package policy

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"sync/atomic"
	"syscall"

	"github.com/pelletier/go-toml/v2"
)

const (
	DecisionAllow = "allow"
	DecisionAsk   = "ask"
	DecisionDeny  = "deny"
)

const (
	defaultPendingLimit      = 16
	defaultPendingTimeoutSec = 300
	defaultExecTimeoutSec    = 300
	maxBackups               = 5
)

var validDecisions = map[string]bool{
	DecisionAllow: true,
	DecisionAsk:   true,
	DecisionDeny:  true,
}

func init() {
	_ = validDecisions
}

type Settings struct {
	EnvAllowlist          []string `toml:"env_allowlist"`
	PendingLimit          int      `toml:"pending_limit"`
	PendingTimeoutSec     int      `toml:"pending_timeout_sec"`
	DefaultExecTimeoutSec int      `toml:"default_exec_timeout_sec"`
}

type Rule struct {
	ID           int      `toml:"id"`
	Requester    string   `toml:"requester"`
	Command      string   `toml:"command"`
	Args         []string `toml:"args"`
	Decision     string   `toml:"decision"`
	EnvAllowlist []string `toml:"env_allowlist,omitempty"`
	ExpiresAt    string   `toml:"expires_at,omitempty"`
}

type Policy struct {
	Settings Settings `toml:"settings"`
	Rules    []Rule   `toml:"rule"`
}

type Store struct {
	path string
	cur  atomic.Pointer[Policy]
}

func NewStore(path string) (*Store, error) {
	p, err := loadAndValidate(path)
	if err != nil {
		return nil, err
	}
	s := &Store{path: path}
	s.cur.Store(p)
	return s, nil
}

func (s *Store) Current() *Policy {
	return s.cur.Load()
}

func (s *Store) Reload() error {
	p, err := loadAndValidate(s.path)
	if err != nil {
		return err
	}
	s.cur.Store(p)
	return nil
}

func (s *Store) AppendRuleAndWrite(r Rule) error {
	cur := s.cur.Load()
	newPol := copyPolicy(cur)
	insertIdx := len(newPol.Rules)
	for i, rule := range newPol.Rules {
		if isCatchAll(rule) {
			insertIdx = i
			break
		}
	}
	rules := make([]Rule, 0, len(newPol.Rules)+1)
	rules = append(rules, newPol.Rules[:insertIdx]...)
	rules = append(rules, r)
	rules = append(rules, newPol.Rules[insertIdx:]...)
	newPol.Rules = rules
	if err := s.atomicWrite(newPol); err != nil {
		return err
	}
	s.cur.Store(newPol)
	return nil
}

func (s *Store) RevokeRule(id int) error {
	cur := s.cur.Load()
	newPol := copyPolicy(cur)
	found := false
	for i, rule := range newPol.Rules {
		if rule.ID == id {
			newPol.Rules = append(newPol.Rules[:i], newPol.Rules[i+1:]...)
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("rule %d not found", id)
	}
	if err := s.atomicWrite(newPol); err != nil {
		return err
	}
	s.cur.Store(newPol)
	return nil
}

func (s *Store) NextRuleID() int {
	cur := s.cur.Load()
	maxID := 0
	for _, r := range cur.Rules {
		if r.ID > maxID {
			maxID = r.ID
		}
	}
	return maxID + 1
}

func loadAndValidate(path string) (*Policy, error) {
	var stat syscall.Stat_t
	if err := syscall.Stat(path, &stat); err != nil {
		return nil, fmt.Errorf("stat policy %s: %w", path, err)
	}
	if stat.Mode&0077 != 0 {
		return nil, fmt.Errorf("policy %s: mode %04o must be 0600 (no group/other bits)", path, fs.FileMode(stat.Mode).Perm())
	}
	if os.Getuid() == 0 && stat.Uid != 0 {
		return nil, fmt.Errorf("policy %s: owner uid %d must be 0 (root)", path, stat.Uid)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read policy %s: %w", path, err)
	}

	var p Policy
	if err := toml.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("parse policy %s: %w", path, err)
	}

	ids := make(map[int]bool, len(p.Rules))
	for i, r := range p.Rules {
		if r.ID == 0 {
			return nil, fmt.Errorf("rule %d: id is required", i)
		}
		if ids[r.ID] {
			return nil, fmt.Errorf("duplicate rule id %d", r.ID)
		}
		ids[r.ID] = true
		if !validDecisions[r.Decision] {
			return nil, fmt.Errorf("rule %d: invalid decision %q", r.ID, r.Decision)
		}
		for j, a := range r.Args {
			if a == "**" && j != len(r.Args)-1 {
				return nil, fmt.Errorf("rule %d: ** must be last element in args", r.ID)
			}
		}
	}

	if p.Settings.PendingLimit <= 0 {
		p.Settings.PendingLimit = defaultPendingLimit
	}
	if p.Settings.PendingTimeoutSec <= 0 {
		p.Settings.PendingTimeoutSec = defaultPendingTimeoutSec
	}
	if p.Settings.DefaultExecTimeoutSec <= 0 {
		p.Settings.DefaultExecTimeoutSec = defaultExecTimeoutSec
	}

	return &p, nil
}

func isCatchAll(r Rule) bool {
	if r.Requester != "*" {
		return false
	}
	if r.Command != "*" {
		return false
	}
	if len(r.Args) != 1 || r.Args[0] != "**" {
		return false
	}
	return true
}

func copyPolicy(p *Policy) *Policy {
	cp := *p
	cp.Rules = make([]Rule, len(p.Rules))
	copy(cp.Rules, p.Rules)
	cp.Settings.EnvAllowlist = make([]string, len(p.Settings.EnvAllowlist))
	copy(cp.Settings.EnvAllowlist, p.Settings.EnvAllowlist)
	return &cp
}

func (s *Store) atomicWrite(newPol *Policy) error {
	dir := filepath.Dir(s.path)
	rotateBackups(s.path, maxBackups)

	tmp, err := os.CreateTemp(dir, ".policy.tmp.*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmp.Name()

	data, err := toml.Marshal(newPol)
	if err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("marshal policy: %w", err)
	}

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("write temp policy: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("fsync temp policy: %w", err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("chmod temp policy: %w", err)
	}
	tmp.Close()

	dirF, err := os.Open(dir)
	if err == nil {
		dirF.Sync()
		dirF.Close()
	}

	if err := os.Rename(tmpPath, s.path); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("rename temp to policy: %w", err)
	}

	return nil
}

func rotateBackups(path string, maxKeep int) {
	for i := maxKeep - 1; i >= 1; i-- {
		older := fmt.Sprintf("%s.bak.%d", path, i)
		newer := fmt.Sprintf("%s.bak.%d", path, i+1)
		if i == maxKeep-1 {
			os.Remove(older)
			continue
		}
		os.Rename(older, newer)
	}
	first := path + ".bak.1"
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	os.WriteFile(first, data, 0o600)
}

func sortRulesByID(rules []Rule) []Rule {
	sorted := make([]Rule, len(rules))
	copy(sorted, rules)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].ID < sorted[j].ID
	})
	return sorted
}
