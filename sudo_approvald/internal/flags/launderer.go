package flags

import (
	"path/filepath"

	"github.com/leon/approvald/internal/proto"
)

// launderers are argv[0] basenames that re-exec a downstream program,
// rendering a naive command-path allowlist useless.
//
// When one of these is argv[0], the effective command is elsewhere in argv.
// Policy rules should match on the downstream command, not the launderer.
var launderers = map[string]string{
	"env":     "re-execs a program after setting env",
	"nice":    "re-execs a program with adjusted priority",
	"nohup":   "re-execs a program detached from HUP",
	"timeout": "re-execs a program with a time limit",
	"stdbuf":  "re-execs a program with adjusted stdio buffering",
	"chrt":    "re-execs a program with scheduling policy",
	"taskset": "re-execs a program pinned to CPUs",
	"ionice":  "re-execs a program with I/O priority",
	"unshare": "re-execs a program in new namespaces",
	"nsenter": "re-execs a program in existing namespaces",
	"setpriv": "re-execs a program with adjusted privileges",
	"runuser": "re-execs a program as another user",
	"su":      "re-execs a shell as another user",
	"sudo":    "re-execs a program as another user",
}

// CheckExecLaunderer flags argv[0] values that defeat command-path
// allowlists by exec'ing something else.
func CheckExecLaunderer(argv []string) []proto.Flag {
	if len(argv) == 0 {
		return nil
	}
	base := filepath.Base(argv[0])
	if reason, ok := launderers[base]; ok {
		return []proto.Flag{{
			Kind:   KindExecLaunderer,
			Reason: "argv[0] is " + base + ": " + reason,
		}}
	}
	return nil
}
