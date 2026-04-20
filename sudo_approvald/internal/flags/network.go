package flags

import (
	"path/filepath"
	"strings"

	"github.com/leon/approvald/internal/proto"
)

// CheckNetwork flags argv that initiates network egress with remote
// endpoints specified in argv. Legitimate uses exist (apt repos are also
// network egress, but via apt not curl), so this is a soft flag.
func CheckNetwork(argv []string) []proto.Flag {
	if len(argv) == 0 {
		return nil
	}
	base := filepath.Base(argv[0])
	switch base {
	case "curl", "wget":
		for _, a := range argv[1:] {
			if strings.HasPrefix(a, "http://") || strings.HasPrefix(a, "https://") ||
				strings.HasPrefix(a, "ftp://") || strings.HasPrefix(a, "file://") {
				return []proto.Flag{{
					Kind:   KindNetwork,
					Reason: base + " fetching remote URL: " + a,
				}}
			}
		}
	case "nc", "ncat", "socat":
		// Any invocation of these as root is worth surfacing; args are varied.
		return []proto.Flag{{
			Kind:   KindNetwork,
			Reason: "argv[0] is " + base + ": raw network tool",
		}}
	}
	return nil
}
