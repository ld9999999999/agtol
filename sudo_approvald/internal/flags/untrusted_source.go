package flags

import (
	"path/filepath"
	"strings"

	"github.com/leon/approvald/internal/proto"
)

// CheckUntrustedSource flags package-manager operations that install from
// arbitrary sources (local files, git URLs, HTTP) rather than configured
// repositories.
func CheckUntrustedSource(argv []string) []proto.Flag {
	if len(argv) == 0 {
		return nil
	}
	base := filepath.Base(argv[0])
	var out []proto.Flag

	switch base {
	case "dpkg":
		// dpkg -i <file>.deb, dpkg --install <file>.deb
		for _, a := range argv[1:] {
			if a == "-i" || a == "--install" {
				out = append(out, proto.Flag{
					Kind:   KindUntrustedSource,
					Reason: "dpkg -i installs .deb from arbitrary path",
				})
				break
			}
		}

	case "apt", "apt-get":
		// apt install ./foo.deb or apt install /abs/path.deb
		for _, a := range argv[2:] {
			if strings.HasSuffix(a, ".deb") && (strings.HasPrefix(a, "./") || strings.HasPrefix(a, "/")) {
				out = append(out, proto.Flag{
					Kind:   KindUntrustedSource,
					Reason: "apt installing local .deb: " + a,
				})
			}
		}

	case "pip", "pip3":
		// pip install <url> or pip install <path> or pip install git+...
		for _, a := range argv[1:] {
			if strings.HasPrefix(a, "git+") || strings.HasPrefix(a, "http://") ||
				strings.HasPrefix(a, "https://") || strings.HasPrefix(a, "file://") ||
				strings.HasPrefix(a, "./") || strings.HasPrefix(a, "/") {
				out = append(out, proto.Flag{
					Kind:   KindUntrustedSource,
					Reason: "pip installing from URL/path: " + a,
				})
			}
		}

	case "npm":
		// npm install <url>, npm install git+...
		for _, a := range argv[1:] {
			if strings.HasPrefix(a, "git+") || strings.HasPrefix(a, "http://") ||
				strings.HasPrefix(a, "https://") {
				out = append(out, proto.Flag{
					Kind:   KindUntrustedSource,
					Reason: "npm installing from URL: " + a,
				})
			}
		}

	case "cargo":
		// cargo install --git ...
		for i, a := range argv[1:] {
			if a == "--git" && i+2 < len(argv) {
				out = append(out, proto.Flag{
					Kind:   KindUntrustedSource,
					Reason: "cargo install --git " + argv[i+2],
				})
			}
		}
	}

	return dedupe(out)
}
