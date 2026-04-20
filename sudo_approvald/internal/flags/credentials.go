package flags

import (
	"path/filepath"
	"strings"

	"github.com/leon/approvald/internal/proto"
)

// sensitiveCredentialPaths lists path prefixes that should flag a request
// if they appear anywhere in argv. All paths are absolute and canonical.
//
// The matching is prefix-based after cleaning, so "/root/.ssh" catches
// "/root/.ssh/id_rsa", "/root/.ssh/authorized_keys", etc.
//
// Home-relative paths are handled separately via hasHomeSensitivePrefix.
var sensitiveCredentialPaths = []string{
	"/etc/shadow",
	"/etc/gshadow",
	"/etc/sudoers",
	"/etc/sudoers.d",
	"/root/.ssh",
	"/root/.aws",
	"/root/.config/gh",
	"/root/.netrc",
	"/root/.pgpass",
	"/run/secrets",
	"/run/keys",
	"/var/lib/docker/secrets",
	"/var/lib/kubelet/pods", // often contains mounted secrets
}

// homeSensitiveSuffixes are directory names under /home/<user>/ that
// typically contain credentials.
var homeSensitiveSuffixes = []string{
	".ssh",
	".aws",
	".config/gh",
	".netrc",
	".pgpass",
	".kube",
	".docker/config.json",
}

// credentialReadCommands are argv[0] basenames that inherently read
// credentials, regardless of other args.
var credentialReadCommands = map[string]string{
	"passwd":   "modifies system password database",
	"chpasswd": "modifies system password database",
	"vipw":     "edits /etc/passwd",
	"vigr":     "edits /etc/group",
}

// CheckReadsCredentials returns flags if argv appears to read or modify
// sensitive credential material.
func CheckReadsCredentials(argv []string) []proto.Flag {
	if len(argv) == 0 {
		return nil
	}
	var out []proto.Flag

	base := filepath.Base(argv[0])
	if reason, ok := credentialReadCommands[base]; ok {
		out = append(out, proto.Flag{
			Kind:   KindReadsCredentials,
			Reason: "argv[0] " + base + ": " + reason,
		})
	}

	// Check each arg for a sensitive path reference.
	for _, a := range argv[1:] {
		if !strings.HasPrefix(a, "/") {
			continue
		}
		clean := filepath.Clean(a)
		for _, p := range sensitiveCredentialPaths {
			if clean == p || strings.HasPrefix(clean, p+"/") {
				out = append(out, proto.Flag{
					Kind:   KindReadsCredentials,
					Reason: "argv contains sensitive path: " + clean,
				})
				break
			}
		}
		if hasHomeSensitiveSuffix(clean) {
			out = append(out, proto.Flag{
				Kind:   KindReadsCredentials,
				Reason: "argv contains home credential path: " + clean,
			})
		}
	}

	// TODO(impl): also check for specific dangerous subcommands:
	//   - "getent shadow"
	//   - "gpg --export-secret-keys"
	//   - "openssl ... -in <key>"

	return dedupe(out)
}

// hasHomeSensitiveSuffix checks whether p is under /home/<user>/<sensitive>.
func hasHomeSensitiveSuffix(p string) bool {
	const prefix = "/home/"
	if !strings.HasPrefix(p, prefix) {
		return false
	}
	rest := p[len(prefix):]
	slash := strings.IndexByte(rest, '/')
	if slash < 0 {
		return false
	}
	rel := rest[slash+1:]
	for _, suf := range homeSensitiveSuffixes {
		if rel == suf || strings.HasPrefix(rel, suf+"/") {
			return true
		}
	}
	return false
}

// dedupe removes duplicate flags (same kind+reason).
func dedupe(in []proto.Flag) []proto.Flag {
	if len(in) < 2 {
		return in
	}
	seen := make(map[proto.Flag]struct{}, len(in))
	out := in[:0]
	for _, f := range in {
		if _, ok := seen[f]; ok {
			continue
		}
		seen[f] = struct{}{}
		out = append(out, f)
	}
	return out
}
