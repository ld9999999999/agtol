package flags

import (
	"path/filepath"
	"strings"

	"github.com/leon/approvald/internal/proto"
)

var shellBinaries = map[string]bool{
	"sh":   true,
	"bash": true,
	"zsh":  true,
	"fish": true,
	"dash": true,
	"ksh":  true,
	"mksh": true,
	"tcsh": true,
	"csh":  true,
}

// CheckShell flags argv that invokes a shell interpreter or uses a -c style
// escape hatch. Matching on allowlisted argv[0]s becomes meaningless if the
// downstream command is a shell snippet.
func CheckShell(argv []string) []proto.Flag {
	if len(argv) == 0 {
		return nil
	}
	var out []proto.Flag

	base := filepath.Base(argv[0])
	if shellBinaries[base] {
		out = append(out, proto.Flag{
			Kind:   KindShell,
			Reason: "argv[0] is shell interpreter: " + base,
		})
	}

	for _, a := range argv[1:] {
		if a == "-c" || a == "--command" {
			out = append(out, proto.Flag{
				Kind:   KindShell,
				Reason: "argv contains " + a + ": downstream is a shell snippet",
			})
			break
		}
	}

	// find ... -exec / -execdir
	if base == "find" {
		for _, a := range argv[1:] {
			if a == "-exec" || a == "-execdir" {
				out = append(out, proto.Flag{
					Kind:   KindShell,
					Reason: "find -exec runs arbitrary downstream commands",
				})
				break
			}
		}
	}

	// xargs, parallel: downstream invocation.
	if base == "xargs" || base == "parallel" {
		out = append(out, proto.Flag{
			Kind:   KindShell,
			Reason: "argv[0] is " + base + ": runs downstream commands from stdin",
		})
	}

	// git -c core.sshCommand=... / core.editor=... / core.pager=...
	if base == "git" {
		for i, a := range argv[1:] {
			if a == "-c" && i+2 < len(argv) {
				cfg := argv[i+2]
				for _, dangerous := range []string{
					"core.sshcommand=",
					"core.editor=",
					"core.pager=",
					"core.hookspath=",
				} {
					if strings.HasPrefix(strings.ToLower(cfg), dangerous) {
						out = append(out, proto.Flag{
							Kind:   KindShell,
							Reason: "git -c " + cfg + ": redirects git to arbitrary command",
						})
					}
				}
			}
		}
	}

	return dedupe(out)
}
