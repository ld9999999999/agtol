package daemon

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/leon/approvald/internal/flags"
	"github.com/leon/approvald/internal/identity"
	"github.com/leon/approvald/internal/policy"
	"github.com/leon/approvald/internal/proto"
)

func (d *Daemon) acceptClients(ctx context.Context) {
	for {
		conn, err := d.clientLn.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			d.logger.Warn("accept client", "err", err)
			continue
		}
		go d.handleClient(ctx, conn)
	}
}

func (d *Daemon) handleClient(ctx context.Context, conn *net.UnixConn) {
	defer conn.Close()
	reqID := newRequestID()
	start := time.Now()

	peer, err := identity.PeerCred(conn)
	if err != nil {
		d.logger.Warn("peer cred", "err", err, "req_id", reqID)
		writeExit(conn, 126, start)
		return
	}
	d.logger.Info("client connected", "req_id", reqID, "peer_uid", peer.UID, "peer_gid", peer.GID, "peer_pid", peer.PID)

	if !d.isMemberOfClientGroup(peer) {
		d.logger.Warn("client not in group", "uid", peer.UID, "gid", peer.GID, "req_id", reqID, "expected_gid", d.cfg.ClientGID)
		writeExit(conn, 126, start)
		return
	}

	raw, err := proto.ReadFrame(conn)
	if err != nil {
		d.logger.Warn("read exec frame", "err", err, "req_id", reqID)
		writeExit(conn, 126, start)
		return
	}
	d.logger.Debug("raw frame received", "req_id", reqID, "bytes", len(raw))

	msg, err := proto.DecodeMessage(raw)
	if err != nil {
		d.logger.Warn("decode exec frame", "err", err, "req_id", reqID)
		writeExit(conn, 126, start)
		return
	}
	execMsg, ok := msg.(*proto.Exec)
	if !ok {
		d.logger.Warn("first frame not exec", "type", fmt.Sprintf("%T", msg), "req_id", reqID)
		writeExit(conn, 126, start)
		return
	}
	d.logger.Info("exec request received",
		"req_id", reqID,
		"argv", execMsg.Argv,
		"cwd", execMsg.Cwd,
		"env_keys", func() []string {
			keys := make([]string, 0, len(execMsg.Env))
			for k := range execMsg.Env {
				keys = append(keys, k)
			}
			return keys
		}(),
		"requester_hint", execMsg.RequesterHint,
		"timeout_sec", execMsg.TimeoutSec,
	)

	canonical, err := canonicalizeArgv0(execMsg.Argv)
	if err != nil {
		d.logger.Error("canonicalize argv0 failed", "req_id", reqID, "err", err)
		writeStatus(conn, "denied", 0, err.Error())
		writeExit(conn, 126, start)
		d.audit.RecordDenied(reqID, peer, execMsg, "canonicalize: "+err.Error())
		return
	}
	d.logger.Info("argv0 canonicalized", "req_id", reqID, "argv0", execMsg.Argv[0], "canonical", canonical)

	requester := identity.Requester(peer)
	d.logger.Info("requester identity", "req_id", reqID, "requester", requester)

	flagSet := flags.All(execMsg.Argv)
	if execMsg.RequesterHint != "" && execMsg.RequesterHint != requester {
		flagSet = append(flagSet, proto.Flag{
			Kind:   flags.KindHintMismatch,
			Reason: fmt.Sprintf("hint=%q derived=%q", execMsg.RequesterHint, requester),
		})
	}
	if len(flagSet) > 0 {
		d.logger.Warn("request flagged", "req_id", reqID, "flags", len(flagSet))
		for _, f := range flagSet {
			d.logger.Info("flag", "req_id", reqID, "kind", f.Kind, "reason", f.Reason)
		}
	}

	pol := d.policy.Current()
	matchReq := policy.Request{
		Requester:        requester,
		CanonicalCommand: canonical,
		Args:             execMsg.Argv[1:],
	}
	rule := pol.Match(matchReq)

	decision := policy.DecisionAsk
	ruleID := 0
	if rule != nil {
		decision = rule.Decision
		ruleID = rule.ID
	}
	d.logger.Info("policy match result", "req_id", reqID, "decision", decision, "rule_id", ruleID)

	if decision == policy.DecisionAllow && len(flagSet) > 0 {
		decision = policy.DecisionAsk
		d.logger.Info("escalating allow to ask due to flags", "req_id", reqID)
	}

	switch decision {
	case policy.DecisionDeny:
		d.logger.Info("sending denied + exit", "req_id", reqID, "rule_id", ruleID, "exit_code", 126)
		writeStatus(conn, "denied", ruleID, "denied by rule")
		writeExit(conn, 126, start)
		d.audit.RecordDenied(reqID, peer, execMsg, "rule")
		return

	case policy.DecisionAllow:
		d.logger.Info("sending approved, starting exec", "req_id", reqID, "rule_id", ruleID)
		writeStatus(conn, "approved", ruleID, "")
		d.executeAndStream(ctx, conn, reqID, peer, execMsg, canonical, start)
		return

	case policy.DecisionAsk:
		d.logger.Info("sending queued, asking approver", "req_id", reqID, "rule_id", ruleID)
		writeStatus(conn, "queued", ruleID, "")
		pending := proto.Pending{
			Type:            proto.TypePending,
			ID:              reqID,
			Requester:       requester,
			RequesterHint:   execMsg.RequesterHint,
			Argv:            execMsg.Argv,
			Cwd:             execMsg.Cwd,
			MatchedRuleID:   ruleID,
			MatchedDecision: decision,
			Flags:           flagSet,
		}
		outcome, err := d.askApprover(ctx, pending)
		if err != nil {
			d.logger.Error("askApprover failed", "req_id", reqID, "err", err)
			writeStatus(conn, "denied", 0, err.Error())
			writeExit(conn, 126, start)
			d.audit.RecordDenied(reqID, peer, execMsg, err.Error())
			return
		}
		d.logger.Info("approver responded", "req_id", reqID, "decision", outcome.decision)
		switch outcome.decision {
		case "allow_once", "allow_remember":
			if outcome.decision == "allow_remember" {
				if len(flagSet) == 0 {
					d.rememberAllow(requester, canonical, execMsg.Argv[1:])
				} else {
					d.logger.Warn("refusing to remember flagged request",
						"req_id", reqID, "flags", len(flagSet))
				}
			}
			d.logger.Info("sending approved (from approver), starting exec", "req_id", reqID)
			writeStatus(conn, "approved", 0, "approver")
			d.executeAndStream(ctx, conn, reqID, peer, execMsg, canonical, start)
		default:
			if outcome.decision == "deny_remember" {
				d.rememberDeny(requester, canonical, execMsg.Argv[1:])
			}
			d.logger.Info("sending denied (from approver) + exit", "req_id", reqID, "decision", outcome.decision)
			writeStatus(conn, "denied", 0, "approver")
			writeExit(conn, 126, start)
			d.audit.RecordDenied(reqID, peer, execMsg, "approver")
		}
	}
}

func (d *Daemon) isMemberOfClientGroup(peer identity.Peer) bool {
	if peer.GID == d.cfg.ClientGID {
		return true
	}
	u, err := user.LookupId(strconv.Itoa(peer.UID))
	if err != nil {
		return false
	}
	groups, err := u.GroupIds()
	if err != nil {
		return false
	}
	target := strconv.Itoa(d.cfg.ClientGID)
	for _, g := range groups {
		if g == target {
			return true
		}
	}
	return false
}

func canonicalizeArgv0(argv []string) (string, error) {
	if len(argv) == 0 {
		return "", fmt.Errorf("empty argv")
	}
	cmd := argv[0]
	if !filepath.IsAbs(cmd) {
		resolved, err := exec.LookPath(cmd)
		if err != nil {
			return "", fmt.Errorf("lookup %q: %w", cmd, err)
		}
		cmd = resolved
	}
	canonical, err := filepath.EvalSymlinks(cmd)
	if err != nil {
		return "", fmt.Errorf("evalsymlinks %q: %w", cmd, err)
	}
	return canonical, nil
}

func newRequestID() string {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return "req-" + hex.EncodeToString(b[:])
}

func writeStatus(w net.Conn, state string, ruleID int, reason string) {
	_ = proto.WriteFrame(w, proto.Status{
		Type:   proto.TypeStatus,
		State:  state,
		RuleID: ruleID,
		Reason: reason,
	})
}

func writeExit(w net.Conn, code int, start time.Time) {
	_ = proto.WriteFrame(w, proto.Exit{
		Type:       proto.TypeExit,
		Code:       code,
		DurationMs: time.Since(start).Milliseconds(),
	})
}

func (d *Daemon) rememberAllow(requester, command string, args []string) {
	id := d.policy.NextRuleID()
	r := policy.Rule{
		ID:        id,
		Requester: requester,
		Command:   command,
		Args:      argsToPattern(args),
		Decision:  policy.DecisionAllow,
	}
	if err := d.policy.AppendRuleAndWrite(r); err != nil {
		d.logger.Error("remember allow", "err", err, "rule_id", id)
	}
}

func (d *Daemon) rememberDeny(requester, command string, args []string) {
	id := d.policy.NextRuleID()
	r := policy.Rule{
		ID:        id,
		Requester: requester,
		Command:   command,
		Args:      argsToPattern(args),
		Decision:  policy.DecisionDeny,
	}
	if err := d.policy.AppendRuleAndWrite(r); err != nil {
		d.logger.Error("remember deny", "err", err, "rule_id", id)
	}
}

func argsToPattern(args []string) []string {
	if len(args) == 0 {
		return []string{"**"}
	}
	patterns := make([]string, len(args))
	for i, a := range args {
		if strings.HasPrefix(a, "-") || strings.HasPrefix(a, "/") {
			patterns[i] = a
		} else {
			patterns[i] = a
		}
	}
	return patterns
}

func init() {
	_ = os.LookupEnv
	_ = strconv.Itoa
}
