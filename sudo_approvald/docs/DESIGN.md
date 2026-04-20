# approvald — Design

A user-controlled privilege-approval daemon, init-agnostic, non-interactive
for v1. This document is the canonical plan; the source tree contains
skeletons consistent with it.

## Problem

Agentic coding tools (Claude Code, etc.) increasingly need to run privileged
commands. The options today are bad:

- **Blanket `NOPASSWD: ALL`** — effectively removes sudo as a security
  boundary for every process running as your uid.
- **Scoped `NOPASSWD: /usr/bin/foo`** — fine for small, stable allowlists,
  but the list keeps growing and each entry is coarse (`systemctl` alone is
  a full escalation path via `systemctl edit`).
- **Interactive password prompt** — interrupts flow, and agents don't have
  a tty to prompt on anyway.
- **`SUDO_ASKPASS` with a stored secret** — works, but doesn't let you see
  or gate *which* command is about to run. Still command-agnostic.

We want: per-command, per-requester approval with a human in the loop, and
the ability to remember decisions so the prompt doesn't fire on every
identical request. Ideally shareable across workspaces (containers, tmux
panes, whatever) on one machine.

## Architecture

```
+-----------------+       +-------------------+       +-----------------+
|  claude-sudo    |       |    approvald      |       |    approve      |
|  (client shim)  |<----->|   (root daemon)   |<----->|  (CLI approver) |
|                 | unix  |                   | unix  |                 |
|  your uid       | sock  |   uid 0           | sock  |  your uid       |
|  in approval    |       |   started ad-hoc  |       |  long-running   |
|  group          |       |                   |       |  (one per host) |
+-----------------+       +-------------------+       +-----------------+
```

Three binaries, each with a narrow job. They communicate via Unix-domain
sockets with length-prefixed JSON frames.

### Sockets

Both created by the daemon on startup, torn down on exit:

```
<socket-dir>/client.sock     0660  root:<client-group>
<socket-dir>/approver.sock   0600  root:root (SO_PEERCRED-checked at accept)
```

`--socket-dir` defaults to `/run/approvald` but can be any writable dir
(useful for rootless testing: `--socket-dir /tmp/approvald-test`, though
the daemon still needs root to exec privileged commands).

### Wire protocol

`uint32` big-endian length prefix, then a JSON object. Boring, debuggable
with `socat UNIX-CONNECT:... -` and `jq`.

#### Client → daemon (one per connection)

```json
{
  "type": "exec",
  "argv": ["/usr/bin/apt", "install", "-y", "nginx"],
  "cwd":  "/home/leon/src/web",
  "env":  {"LANG": "en_US.UTF-8"},
  "requester_hint": "workspace:web",
  "timeout_sec": 300
}
```

Daemon resolves `argv[0]` through its own `PATH` if relative, then
`realpath`s it. The canonical path is what policy matches against.

`requester_hint` is advisory — the daemon derives true identity from the
peer credentials and logs both; a mismatch is a flag.

#### Daemon → client (streaming, multiple frames)

```json
{"type": "status", "state": "queued"}
{"type": "status", "state": "approved", "rule_id": 14}
{"type": "stdout", "data": "Reading package lists...\n"}
{"type": "stderr", "data": "..."}
{"type": "exit",   "code": 0, "duration_ms": 1843}
```

On denial the daemon sends `status denied` then `exit` with code 126
(chosen to match sudo's "command not permitted" convention).

#### Daemon ↔ approver (persistent connection)

```json
// daemon -> approver
{"type": "pending", "id": "req-8f3a",
 "requester": "podman:claude-web-01:1000",
 "argv": ["/usr/bin/apt", "install", "-y", "nginx"],
 "cwd":  "/home/leon/src/web",
 "matched_rule": 7,
 "matched_decision": "ask",
 "flags": []}

// approver -> daemon
{"type": "decision", "id": "req-8f3a", "decision": "allow_once"}
// decision ∈ {allow_once, allow_remember, deny_once, deny_remember}

// approver -> daemon (maintenance)
{"type": "list"}
{"type": "revoke", "rule_id": 14}
{"type": "reload_policy"}
```

If the approver disconnects with pending requests, the daemon keeps them
queued up to `--pending-limit` (default 16) for `--pending-timeout`
(default 5m), then starts failing new ones with `approver_unavailable`.

### Identity resolution

Each client connection gets a real identity derived by the daemon, not
trusted from the wire:

1. `getsockopt(SO_PEERCRED)` → `{uid, gid, pid}`. If `uid` is not in the
   client group (or not the approver uid, for the approver socket),
   reject before reading any frame.
2. Read `/proc/<pid>/cgroup`. If the leaf cgroup contains `docker`,
   `podman`, `libpod`, `machine.slice`, or `lxc`, extract the container
   id/name as `container_id`. Otherwise `container_id = "host"`.
3. Read `/proc/<pid>/cwd` and `/proc/<pid>/cmdline` for display/audit
   only.

Policy requester string: `"{container_id}:{uid}"`, e.g.
`podman:claude-web-01:1000` or `host:1000`.

### Policy file

TOML. Reloaded on `SIGHUP` or on explicit approver request. First-match
wins; write new "remember" rules *above* the final catch-all.

```toml
# Global settings
[settings]
env_allowlist = ["LANG", "LC_ALL", "TERM", "NO_COLOR"]
pending_limit = 16
pending_timeout_sec = 300
default_exec_timeout_sec = 300

# Rules are evaluated top to bottom; first match wins.
[[rule]]
id = 1
requester = "podman:claude-web-*:1000"
command   = "/usr/bin/systemctl"
args      = ["restart", "nginx"]
decision  = "allow"

[[rule]]
id = 2
requester = "*"
command   = "/usr/sbin/nft"
args      = ["list", "**"]       # ** = rest-match
decision  = "allow"

[[rule]]
id = 3
requester = "host:1000"
command   = "/usr/bin/apt"
args      = ["install", "-y", "**"]
decision  = "ask"

# Catch-all at the bottom. Nothing gets out without going through approver.
[[rule]]
id = 99
requester = "*"
command   = "*"
args      = ["**"]
decision  = "ask"
```

Matching rules:

- Requester: fnmatch-style glob, `*` matches any single segment (non-`:`),
  plain `*` by itself matches everything.
- Command: must match the daemon's canonicalized absolute path. `*` on
  its own matches anything. No partial path globs (avoid confusion).
- Args: list of per-position patterns. `*` matches exactly one argv
  element (any value). `**` matches zero or more remaining elements and
  must be last. Literal match otherwise. No shell-string matching.
- Rule IDs: stable, user-assigned or auto-assigned. Needed for
  `revoke` and audit log references.

"Allow and remember" appends a new rule just above the final catch-all
and atomically rewrites the file (write tempfile, fsync, rename,
keeping `.bak.1..N`).

### Dangerous-command flags

Flags annotate requests; they don't block by themselves. Approver
surfaces them prominently. For flagged requests the approver disables
"allow+remember" by default (override with `--allow-remember-flagged`).

Flag engine lives in `internal/flags/`. Pure functions, each returns
zero or more `Flag{Kind, Reason}` values. Unit-testable in isolation.

Flag kinds shipped in v1:

- `reads-credentials` — argv contains any path under `/etc/shadow`,
  `/etc/sudoers{,.d}`, `/root/.ssh`, `/home/*/.ssh`, `/home/*/.aws`,
  `/home/*/.config/gh`, `/home/*/.netrc`, `/home/*/.pgpass`,
  `/run/secrets`, `/run/keys`, `/var/lib/*/secrets`; or argv[0] is one
  of `passwd`, `chpasswd`, `gpg --export-secret-keys`, `getent shadow`.
- `exec-launderer` — argv[0] ∈ `{env, nice, nohup, timeout, stdbuf,
  chrt, taskset, ionice, unshare, nsenter, setpriv, runuser, su, sudo}`.
  These re-exec something else; pattern-matching on them is meaningless.
- `shell` — argv[0] ends in `sh`/`bash`/`zsh`/`fish`/`dash`/`ksh`, or
  argv contains `-c`/`--command`; `find … -exec`; `xargs`; `parallel`;
  `git -c core.sshCommand=` / `-c core.editor=`.
- `editor` — argv[0] ∈ `{vi, vim, nvim, nano, emacs, ed, less, more,
  most}`; `systemctl edit`; `crontab -e`; `visudo`.
- `writes-sensitive` — argv contains `/etc/sudoers*`, `/etc/pam.d/*`,
  `/etc/ssh/*`, `/boot/*`, `/etc/systemd/*`, `/root/*`, `/etc/cron*`,
  any `authorized_keys`; or `dd of=<sensitive>`; or `tee <sensitive>`.
- `network` — `curl`, `wget`, `nc`, `ncat`, `socat` with a remote
  endpoint in argv.
- `untrusted-source` — `dpkg -i`, `apt install ./*.deb`, `pip install`
  with URL/path, `npm install` from git/url, `cargo install --git`.
- `hint-mismatch` — `requester_hint` disagrees with derived identity.

### Subprocess execution (non-interactive, v1)

On approval, daemon:

1. `pipe2(O_CLOEXEC)` for stdout and stderr.
2. `open("/dev/null", O_RDONLY)` for stdin.
3. Build env = `PATH=/usr/sbin:/usr/bin:/sbin:/bin` + (global env_allowlist
   ∩ client-supplied env) + per-rule env_allowlist if any.
4. `fork`.
   - Child: `setsid()`, dup2 stdin/stdout/stderr, `chdir(cwd)` (falling
     back to `/` if the dir isn't accessible — flagged in audit),
     `execve(canonical_argv0, argv, env)`.
   - Parent: close child ends, select/epoll-loop reading stdout/stderr,
     frame as `stdout`/`stderr` messages to client.
5. Timeout goroutine: at `min(request.timeout_sec, settings.default)`,
   `SIGTERM` the process group; after 5s grace, `SIGKILL`.
6. `waitpid`, send `exit {code, duration_ms}`.

Commands that expect stdin will get EOF immediately and fail. That's the
v1 contract — we'll surface their error cleanly but not work around it.

### Audit log

Append-only JSON lines at `--log`. One entry per request lifecycle
(approve + exec together; or just a denial). Include: timestamp, request
id, derived requester, hint, argv, cwd, env (after filtering), flags,
matched rule, decision source (rule vs approver), decision value, exit
code, duration, captured stdout length, captured stderr length.

Stdout/stderr contents are **not** written to the audit log by default
(they can contain secrets). `--log-output` flag enables it for debugging.

### Failure modes

| Condition                          | Behavior                                           |
|------------------------------------|----------------------------------------------------|
| Daemon not running                 | Client exits nonzero with "approvald not running: <sock path>" |
| Approver not connected, rule = ask | Queue request up to pending_limit/timeout, else fail |
| Policy file missing                | Daemon refuses to start                            |
| Policy file unparseable at reload  | Log error, keep previous policy in memory          |
| Subprocess hits timeout            | `exit code = 124`, stderr gets a note              |
| Client disconnects mid-exec        | Daemon SIGTERMs subprocess (its output has no home) |
| Approver disconnects mid-decision  | Treat as `deny_once`, log it                       |

## Implementation order

See `docs/IMPLEMENTATION_ORDER.md`.

## Open questions

- **Approver authentication**: peer-cred uid check (current plan) vs
  token file. Plan sticks with peer-cred; revisit if we need to allow
  the approver to run as a different uid than the daemon's
  `--approver-uid`.
- **Policy file format**: TOML (current plan) vs JSON. TOML reads better
  for humans; the "remember" writer has to be TOML-aware, which is mildly
  annoying but not hard with `github.com/pelletier/go-toml/v2`.
- **Multi-approver**: what if two `approve` processes connect at once?
  v1 plan: daemon accepts only one approver connection at a time,
  subsequent connects are rejected with `approver_already_connected`.
