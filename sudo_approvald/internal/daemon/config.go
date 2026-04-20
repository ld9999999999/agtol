// Package daemon implements the main approvald loop: socket setup, request
// acceptance, policy matching, approver coordination, subprocess execution,
// and audit logging.
package daemon

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"os/user"
	"strconv"
)

// Config holds all daemon settings parsed from command-line flags.
type Config struct {
	// ApproverUID is the only uid allowed to connect to the approver socket.
	ApproverUID int

	// ClientGroup is the group name whose members can connect to the client
	// socket. The socket is created with mode 0660 and this group as owner.
	ClientGroup string
	ClientGID   int // resolved from ClientGroup at startup

	// PolicyPath is the path to the TOML policy file. Must be 0600 root:root.
	PolicyPath string

	// SocketDir holds client.sock and approver.sock. Created if missing.
	SocketDir string

	// LogPath is the audit log (JSON lines). Appended to, never rotated.
	LogPath string

	// LogOutput, if true, includes subprocess stdout/stderr in audit entries.
	// Off by default because captured output can contain secrets.
	LogOutput bool

	// Verbose bumps slog level to debug.
	Verbose bool

	// PendingLimit caps the number of requests buffered for the approver.
	// Defaults to the policy file's setting, or 16 if unset there.
	PendingLimit int

	// PendingTimeoutSec is how long a request waits for an approver decision
	// before being auto-denied. Defaults to policy's, or 300 if unset.
	PendingTimeoutSec int
}

// ParseFlags parses os.Args into a Config.
func ParseFlags(args []string) (*Config, error) {
	fs := flag.NewFlagSet("approvald", flag.ContinueOnError)
	var c Config
	var approverUser string
	fs.StringVar(&approverUser, "approver-uid", "", "uid or username of the approver (required)")
	fs.StringVar(&c.ClientGroup, "client-group", "approval", "group allowed to connect to the client socket")
	fs.StringVar(&c.PolicyPath, "policy", "/etc/approvald/policy.toml", "path to policy TOML file")
	fs.StringVar(&c.SocketDir, "socket-dir", "/run/approvald", "directory for client.sock and approver.sock")
	fs.StringVar(&c.LogPath, "log", "/var/log/approvald.log", "audit log path")
	fs.BoolVar(&c.LogOutput, "log-output", false, "include subprocess stdout/stderr in audit log (secrets risk)")
	fs.BoolVar(&c.Verbose, "verbose", false, "increase log verbosity")
	fs.IntVar(&c.PendingLimit, "pending-limit", 0, "max queued requests (0 = use policy or 16)")
	fs.IntVar(&c.PendingTimeoutSec, "pending-timeout", 0, "seconds to wait for approver (0 = use policy or 300)")

	if err := fs.Parse(args); err != nil {
		return nil, err
	}

	if approverUser == "" {
		return nil, errors.New("--approver-uid is required")
	}
	if uid, err := strconv.Atoi(approverUser); err == nil {
		c.ApproverUID = uid
	} else {
		u, err := user.Lookup(approverUser)
		if err != nil {
			return nil, fmt.Errorf("resolve approver user %q: %w", approverUser, err)
		}
		c.ApproverUID, _ = strconv.Atoi(u.Uid)
	}

	g, err := user.LookupGroup(c.ClientGroup)
	if err != nil {
		return nil, fmt.Errorf("resolve client group %q: %w", c.ClientGroup, err)
	}
	c.ClientGID, _ = strconv.Atoi(g.Gid)

	return &c, nil
}

// MustBeRoot exits if the process isn't running as uid 0. The daemon needs
// root to create privileged sockets and exec privileged commands.
func MustBeRoot() {
	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "approvald must run as root")
		os.Exit(1)
	}
}
