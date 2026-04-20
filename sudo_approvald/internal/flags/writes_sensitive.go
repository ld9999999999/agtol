package flags

import (
	"path/filepath"
	"strings"

	"github.com/leon/approvald/internal/proto"
)

var sensitiveWritePaths = []string{
	"/etc/sudoers",
	"/etc/sudoers.d",
	"/etc/pam.d",
	"/etc/ssh",
	"/boot",
	"/etc/systemd",
	"/etc/cron.d",
	"/etc/crontab",
	"/etc/cron.hourly",
	"/etc/cron.daily",
	"/etc/cron.weekly",
	"/etc/cron.monthly",
	"/root",
}

var writeCommands = map[string]bool{
	"cp":      true,
	"mv":      true,
	"install": true,
	"rsync":   true,
	"ln":      true,
}

func CheckWritesSensitive(argv []string) []proto.Flag {
	if len(argv) == 0 {
		return nil
	}
	base := filepath.Base(argv[0])
	var out []proto.Flag

	for _, a := range argv {
		if strings.Contains(a, "authorized_keys") {
			out = append(out, proto.Flag{
				Kind:   KindWritesSensitive,
				Reason: "argv references authorized_keys: " + a,
			})
		}
	}

	switch base {
	case "dd":
		for _, a := range argv[1:] {
			if strings.HasPrefix(a, "of=") {
				target := strings.TrimPrefix(a, "of=")
				if isSensitiveWritePath(target) {
					out = append(out, proto.Flag{
						Kind:   KindWritesSensitive,
						Reason: "dd output to sensitive path: " + target,
					})
				}
			}
		}

	case "tee":
		for _, a := range argv[1:] {
			if strings.HasPrefix(a, "-") {
				continue
			}
			if isSensitiveWritePath(a) {
				out = append(out, proto.Flag{
					Kind:   KindWritesSensitive,
					Reason: "tee writing to sensitive path: " + a,
				})
			}
		}

	default:
		if writeCommands[base] {
			if len(argv) >= 2 {
				target := argv[len(argv)-1]
				if isSensitiveWritePath(target) {
					out = append(out, proto.Flag{
						Kind:   KindWritesSensitive,
						Reason: base + " targeting sensitive path: " + target,
					})
				}
			}
		}
	}

	if base == "systemctl" && len(argv) >= 3 {
		sub := argv[1]
		if sub == "link" || sub == "enable" {
			for _, a := range argv[2:] {
				if strings.HasPrefix(a, "-") {
					continue
				}
				if strings.HasPrefix(a, "/") && !strings.HasPrefix(a, "/etc/") && !strings.HasPrefix(a, "/lib/") && !strings.HasPrefix(a, "/usr/lib/") {
					out = append(out, proto.Flag{
						Kind:   KindWritesSensitive,
						Reason: "systemctl " + sub + " with out-of-tree unit: " + a,
					})
				}
			}
		}
	}

	return dedupe(out)
}

func isSensitiveWritePath(p string) bool {
	clean := filepath.Clean(p)
	for _, prefix := range sensitiveWritePaths {
		if clean == prefix || strings.HasPrefix(clean, prefix+"/") {
			return true
		}
	}
	return false
}
