# Threat Model

Who can do what, and what we're defending against.

## Trust boundaries

- **Daemon (`approvald`)**: fully trusted, runs as root. Correctness of
  the whole system depends on it.
- **Approver (`approve`)**: trusted; its decisions are authoritative.
  Runs as the human's uid. Must be connected to the same physical
  machine (Unix socket, peer-cred).
- **Client (`claude-sudo`)**: **untrusted**. It runs inside an agent's
  context. Everything it sends is advisory. The daemon re-derives
  everything safety-relevant (identity, canonical argv[0], cwd validity).
- **Policy file**: trusted, root-owned, 0600. If an attacker can write
  to it, the game is over — same as `/etc/sudoers`.

## Attacker capabilities we assume

- Runs code as the unprivileged user (your uid).
- Can craft arbitrary frames to the client socket, including fake
  `requester_hint`, spoofed argv, unusual env.
- Can spawn processes inside any container the user controls.
- **Cannot** write to root-owned files, read the approver socket (mode
  0600 root:root), or bypass `SO_PEERCRED`.
- **Cannot** compromise the approver process itself (that's a different
  threat model).

## Defenses

### Against spoofed identity

- `SO_PEERCRED` gives us kernel-attested `{uid, gid, pid}`. The client
  cannot lie about these.
- Container identity comes from `/proc/<pid>/cgroup`, readable by the
  daemon (root) regardless of the client's capabilities. An attacker in
  a container cannot forge a different container's cgroup path.
- `requester_hint` from the client is **never** used for policy matching
  — only for display + mismatch flagging.

### Against argv shenanigans

- `argv[0]` is resolved via the daemon's `PATH`, not the client's.
  `realpath` is applied. Policy matches the canonical absolute path.
- Symlinks into allowlisted binaries are followed *before* matching, so
  `ln -s /bin/bash /tmp/systemctl && claude-sudo /tmp/systemctl restart nginx`
  is rejected — the canonical path is `/bin/bash`, not `/usr/bin/systemctl`.
- `exec-launderer` flag catches `env`, `nice`, `timeout`, etc. that
  would let an attacker shove arbitrary downstream argv past a naive
  allowlist.

### Against env-variable escalation

- Default env is empty except `PATH` (daemon-set, not client-set).
- Client-supplied env is intersected with a per-policy allowlist.
- `LD_PRELOAD`, `LD_LIBRARY_PATH`, `PYTHONPATH`, `PERL5LIB`, `RUBYLIB`,
  `NODE_OPTIONS`, etc. are never forwarded.
- The allowlist is **allowlist-only**, never blocklist — new dangerous
  vars shouldn't require a code change.

### Against time-of-check/time-of-use on argv[0]

- The daemon resolves the path, opens it, stats it, then `fexecve`s the
  open fd (or `execveat(AT_EMPTY_PATH)`). An attacker swapping the
  binary between check and exec sees the old one.

### Against policy file tampering

- File must be 0600, root-owned. Daemon refuses to load otherwise.
- Backup files (`.bak.N`) inherit the same mode.
- Atomic rewrite (tempfile + fsync + rename in the same directory).

### Against denial-of-service via request flooding

- Pending queue capped (`--pending-limit`). Overflow returns
  `approver_unavailable` immediately.
- Per-requester rate limiting is not in v1. Worth revisiting if it
  becomes a problem.

### Against approver impersonation

- Approver socket is 0600 root:root.
- On accept, daemon checks `SO_PEERCRED` uid against `--approver-uid`.
  Anyone else gets rejected immediately.
- Only one approver at a time; second connection is rejected.

## Known residual risks

- **Shared-uid workspaces**: if two workspaces run as the same uid in
  the same container, they are indistinguishable. Mitigation: run each
  workspace in its own container or namespace.
- **Approver decision fatigue**: rubber-stamping "allow+remember" builds
  up a loose policy over time. Mitigation: flagged requests can't be
  remembered by default; audit log lets you retroactively review.
- **Subprocess children after approval**: an approved `apt install`
  fork-execs scripts; we don't re-ask. This is inherent to the "approve
  a command" model. Flagged commands that are known to script heavily
  (`apt`, `pip`, `npm`) get the `untrusted-source` flag when args
  suggest external sources.
- **Agents that pass secrets in argv**: if the agent runs
  `claude-sudo foo --password=hunter2`, the password is in our audit
  log's argv field. Agents should use files/env for secrets. We can't
  fix this from the daemon side.

## Explicitly out of scope for v1

- Protection against a compromised approver process.
- Protection against root compromise (if you're root, you don't need us).
- Protection against kernel exploits or container escapes.
- Protection against physical access.
- Any form of encryption — this is single-host, Unix-socket only.
