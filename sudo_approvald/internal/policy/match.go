package policy

import (
	"path/filepath"
	"strings"
)

// Request is what the matcher evaluates. The daemon builds it after
// canonicalizing argv[0] and deriving the trusted requester string.
type Request struct {
	Requester        string
	CanonicalCommand string
	Args             []string
}

// Match walks the rules in order and returns the first matching rule.
// If no rule matches, the returned rule is nil and the caller should apply
// its own default (the design specifies "ask" as the paranoid default).
func (p *Policy) Match(req Request) *Rule {
	for i := range p.Rules {
		r := &p.Rules[i]
		if matchRequester(r.Requester, req.Requester) &&
			matchCommand(r.Command, req.CanonicalCommand) &&
			matchArgs(r.Args, req.Args) {
			return r
		}
	}
	return nil
}

// matchRequester applies an fnmatch-style glob. `*` matches any run of
// characters within a single segment (where segments are separated by `:`).
// A bare `*` matches anything.
func matchRequester(pattern, value string) bool {
	if pattern == "*" {
		return true
	}
	patternParts := strings.Split(pattern, ":")
	valueParts := strings.Split(value, ":")
	if len(patternParts) != len(valueParts) {
		return false
	}
	for i, pp := range patternParts {
		if pp == "*" {
			continue
		}
		matched, err := filepath.Match(pp, valueParts[i])
		if err != nil || !matched {
			return false
		}
	}
	return true
}

// matchCommand is an exact match, with `*` meaning "anything". No partial
// globs — either a full absolute path or `*`.
func matchCommand(pattern, value string) bool {
	if pattern == "*" {
		return true
	}
	return pattern == value
}

// matchArgs applies positional matching:
//
//	literal  — must equal the argv element at that position exactly
//	"*"      — matches exactly one argv element (any value)
//	"**"     — matches zero or more remaining elements; must be last
//
// A pattern with no "**" requires len(pattern) == len(args).
func matchArgs(pattern, args []string) bool {
	if len(pattern) == 0 {
		return len(args) == 0
	}

	last := len(pattern) - 1
	if pattern[last] == "**" {
		prefix := pattern[:last]
		if len(args) < len(prefix) {
			return false
		}
		for i, p := range prefix {
			if p != "*" && p != args[i] {
				return false
			}
		}
		return true
	}

	if len(pattern) != len(args) {
		return false
	}
	for i, p := range pattern {
		if p != "*" && p != args[i] {
			return false
		}
	}
	return true
}
