# approvald

A user-controlled privilege-approval daemon for agentic tools (Claude Code,
etc.) that need to run privileged commands without either giving them blanket
`NOPASSWD` sudo or interactively typing passwords on every request.

Instead of `sudo`, the agent calls `claude-sudo <cmd>`. The request goes over
a Unix socket to `approvald` (running as root, started on-demand — no init
integration required). The daemon checks the request against a policy file;
if it matches an `ask` rule, the request is forwarded to `approve` (a CLI
TUI running as your user) where you approve or deny it, optionally
remembering the decision. Stdout/stderr stream back to the caller live, exit
code is forwarded.

## Scope (v1)

- Init-agnostic: `approvald` is a plain binary. Launch however you want.
- Non-interactive commands only. Stdin is `/dev/null` in the subprocess.
- Single-host, Unix-domain sockets only.
- Policy file (TOML), reloadable on `SIGHUP`.
- CLI approver first. TUI is a separate binary on the same protocol, later.
- Heuristic flagging of dangerous patterns (credential reads, exec
  launderers, shell invocations, editor escape hatches, sensitive writes).

## Out of scope (v1)

- Interactive / pty-forwarded commands.
- Multi-host / network sockets.
- Integration with polkit, pam, or any existing auth framework.
- init-system units (users can wrap it themselves if they want).

## Layout

```
cmd/approvald/      the daemon (runs as root)
cmd/claude-sudo/    client shim (runs as any user in the approval group)
cmd/approve/        CLI approver (runs as your uid)
internal/proto/     wire protocol types + framing
internal/policy/    policy file parsing, matching, atomic rewrite
internal/flags/     dangerous-pattern heuristics
internal/identity/  peer-cred + cgroup-based requester identification
internal/daemon/    daemon main loop, request lifecycle, subprocess exec
docs/DESIGN.md      full design writeup
scripts/            example start scripts for each tool
```

## Quick build

```
go build -o bin/approvald    ./cmd/approvald
go build -o bin/claude-sudo  ./cmd/claude-sudo
go build -o bin/approve      ./cmd/approve
```

## Quick run

```
# terminal 1, as root
sudo ./bin/approvald \
    --approver-uid 1000 \
    --client-group approval \
    --policy /etc/approvald/policy.toml \
    --socket-dir /run/approvald \
    --log /var/log/approvald.log

# terminal 2, as your user
./bin/approve

# terminal 3 (or inside a Claude Code workspace)
claude-sudo apt install -y nginx
```
