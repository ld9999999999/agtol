package flags

import (
	"path/filepath"

	"github.com/leon/approvald/internal/proto"
)

// editorEscapeHatches are editors/pagers that can shell out to arbitrary
// commands from within their UI. Running any of them as root is effectively
// a root shell.
var editorEscapeHatches = map[string]bool{
	"vi":    true,
	"vim":   true,
	"nvim":  true,
	"nano":  true,
	"emacs": true,
	"ed":    true,
	"less":  true,
	"more":  true,
	"most":  true,
	"view":  true,
}

// CheckEditor flags invocations of interactive editors or pagers, and
// known subcommands that drop the user into $EDITOR as root.
func CheckEditor(argv []string) []proto.Flag {
	if len(argv) == 0 {
		return nil
	}
	var out []proto.Flag
	base := filepath.Base(argv[0])

	if editorEscapeHatches[base] {
		out = append(out, proto.Flag{
			Kind:   KindEditor,
			Reason: "argv[0] is interactive editor/pager with shell escape: " + base,
		})
	}

	// systemctl edit / cat <unit> + shell -> edit
	// crontab -e, visudo: open editor as root
	if base == "systemctl" && len(argv) >= 2 && argv[1] == "edit" {
		out = append(out, proto.Flag{
			Kind:   KindEditor,
			Reason: "systemctl edit opens $EDITOR as root",
		})
	}
	if base == "crontab" {
		for _, a := range argv[1:] {
			if a == "-e" || a == "--edit" {
				out = append(out, proto.Flag{
					Kind:   KindEditor,
					Reason: "crontab -e opens $EDITOR",
				})
			}
		}
	}
	if base == "visudo" {
		out = append(out, proto.Flag{
			Kind:   KindEditor,
			Reason: "visudo edits /etc/sudoers via $EDITOR",
		})
	}

	return dedupe(out)
}
