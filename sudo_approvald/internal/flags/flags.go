// Package flags contains pure-function heuristics that detect potentially
// dangerous command patterns. Each check returns zero or more Flags.
//
// Flags do NOT block execution on their own; they annotate the request so
// the approver can surface them. For flagged requests, the approver disables
// "allow+remember" by default.
//
// Each flag kind lives in its own file for auditability. Add a new kind by:
//   1. Creating <kind>.go with a Check(argv []string) []Flag function.
//   2. Adding it to the `checks` slice in All().
//   3. Writing unit tests covering positive and negative cases.
package flags

import "github.com/leon/approvald/internal/proto"

// Known flag kinds. Keep in sync with docs/DESIGN.md.
const (
	KindReadsCredentials = "reads-credentials"
	KindExecLaunderer    = "exec-launderer"
	KindShell            = "shell"
	KindEditor           = "editor"
	KindWritesSensitive  = "writes-sensitive"
	KindNetwork          = "network"
	KindUntrustedSource  = "untrusted-source"
	KindHintMismatch     = "hint-mismatch"
)

// Check is the function shape each heuristic file exports.
type Check func(argv []string) []proto.Flag

// checks lists every built-in heuristic. Order doesn't matter; results are
// concatenated.
var checks = []Check{
	CheckReadsCredentials,
	CheckExecLaunderer,
	CheckShell,
	CheckEditor,
	CheckWritesSensitive,
	CheckNetwork,
	CheckUntrustedSource,
}

// All runs every built-in heuristic against argv and returns the aggregated
// flags. Does not include hint-mismatch (that requires daemon-level context).
func All(argv []string) []proto.Flag {
	var out []proto.Flag
	for _, c := range checks {
		out = append(out, c(argv)...)
	}
	return out
}
