package policy

import "testing"

func TestMatchArgs(t *testing.T) {
	cases := []struct {
		name    string
		pattern []string
		args    []string
		want    bool
	}{
		{"empty-empty", []string{}, []string{}, true},
		{"empty-non-empty", []string{}, []string{"x"}, false},
		{"literal-match", []string{"install", "-y", "nginx"},
			[]string{"install", "-y", "nginx"}, true},
		{"literal-mismatch-length", []string{"install"},
			[]string{"install", "-y"}, false},
		{"literal-mismatch-value", []string{"install", "nginx"},
			[]string{"install", "apache"}, false},
		{"star-one-element", []string{"list", "*"},
			[]string{"list", "ruleset"}, true},
		{"star-needs-exactly-one", []string{"list", "*"},
			[]string{"list", "ruleset", "inet"}, false},
		{"star-matches-any-value", []string{"list", "*"},
			[]string{"list", "anything_at_all"}, true},
		{"doublestar-at-end", []string{"install", "-y", "**"},
			[]string{"install", "-y", "nginx", "curl"}, true},
		{"doublestar-zero-extra", []string{"install", "-y", "**"},
			[]string{"install", "-y"}, true},
		{"doublestar-zero", []string{"**"}, []string{}, true},
		{"doublestar-one", []string{"**"}, []string{"x"}, true},
		{"doublestar-many", []string{"**"}, []string{"a", "b", "c", "d"}, true},
		{"doublestar-prefix-star", []string{"*", "**"},
			[]string{"anything", "more", "stuff"}, true},
		{"doublestar-prefix-mismatch", []string{"install", "**"},
			[]string{"remove", "nginx"}, false},
		{"single-star-not-double", []string{"*"},
			[]string{"a", "b"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := matchArgs(c.pattern, c.args); got != c.want {
				t.Errorf("got %v, want %v", got, c.want)
			}
		})
	}
}

func TestMatchRequester(t *testing.T) {
	cases := []struct {
		pattern string
		value   string
		want    bool
	}{
		{"*", "host:1000", true},
		{"*", "podman:anything:0", true},
		{"*", "docker:abc123:1000", true},
		{"host:1000", "host:1000", true},
		{"host:1000", "host:1001", false},
		{"host:1000", "podman:1000", false},
		{"podman:claude-web-*:1000", "podman:claude-web-01:1000", true},
		{"podman:claude-web-*:1000", "podman:claude-db-01:1000", false},
		{"podman:*:1000", "podman:anything:1000", true},
		{"podman:*:1000", "podman:anything:2000", false},
		{"podman:abc", "podman:abc:def", false},
		{"docker:*", "docker:abc123", true},
		{"docker:*", "docker:", true},
	}
	for _, c := range cases {
		t.Run(c.pattern+"_vs_"+c.value, func(t *testing.T) {
			if got := matchRequester(c.pattern, c.value); got != c.want {
				t.Errorf("got %v, want %v", got, c.want)
			}
		})
	}
}

func TestMatchCommand(t *testing.T) {
	cases := []struct {
		pattern string
		value   string
		want    bool
	}{
		{"*", "/usr/bin/apt", true},
		{"*", "/anything", true},
		{"/usr/bin/apt", "/usr/bin/apt", true},
		{"/usr/bin/apt", "/usr/bin/dpkg", false},
		{"/usr/bin/apt", "/usr/bin/apt-get", false},
	}
	for _, c := range cases {
		t.Run(c.pattern+"_vs_"+c.value, func(t *testing.T) {
			if got := matchCommand(c.pattern, c.value); got != c.want {
				t.Errorf("got %v, want %v", got, c.want)
			}
		})
	}
}

func TestPolicyMatchIntegration(t *testing.T) {
	p := &Policy{
		Rules: []Rule{
			{ID: 1, Requester: "host:1000", Command: "/usr/bin/apt", Args: []string{"install", "-y", "**"}, Decision: DecisionAllow},
			{ID: 2, Requester: "*", Command: "/usr/sbin/nft", Args: []string{"list", "**"}, Decision: DecisionAllow},
			{ID: 99, Requester: "*", Command: "*", Args: []string{"**"}, Decision: DecisionAsk},
		},
	}

	cases := []struct {
		name     string
		req      Request
		wantRule int
	}{
		{"apt-install", Request{Requester: "host:1000", CanonicalCommand: "/usr/bin/apt", Args: []string{"install", "-y", "nginx"}}, 1},
		{"nft-list", Request{Requester: "host:1000", CanonicalCommand: "/usr/sbin/nft", Args: []string{"list", "ruleset"}}, 2},
		{"catch-all", Request{Requester: "host:1000", CanonicalCommand: "/usr/bin/systemctl", Args: []string{"restart", "nginx"}}, 99},
		{"no-match-different-uid", Request{Requester: "host:2000", CanonicalCommand: "/usr/bin/apt", Args: []string{"install", "-y", "nginx"}}, 99},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rule := p.Match(c.req)
			if rule == nil {
				t.Fatal("expected a match, got nil")
			}
			if rule.ID != c.wantRule {
				t.Errorf("matched rule %d, want %d", rule.ID, c.wantRule)
			}
		})
	}
}

func TestPolicyMatchNoMatch(t *testing.T) {
	p := &Policy{
		Rules: []Rule{
			{ID: 1, Requester: "host:1000", Command: "/usr/bin/apt", Args: []string{"update"}, Decision: DecisionAllow},
		},
	}
	req := Request{Requester: "host:2000", CanonicalCommand: "/usr/bin/apt", Args: []string{"update"}}
	rule := p.Match(req)
	if rule != nil {
		t.Errorf("expected no match, got rule %d", rule.ID)
	}
}
