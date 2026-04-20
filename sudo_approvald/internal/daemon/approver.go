package daemon

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/leon/approvald/internal/identity"
	"github.com/leon/approvald/internal/proto"
)

func (d *Daemon) acceptApprover(ctx context.Context) {
	for {
		conn, err := d.approverLn.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			d.logger.Warn("accept approver", "err", err)
			continue
		}

		peer, err := identity.PeerCred(conn)
		if err != nil || peer.UID != d.cfg.ApproverUID {
			_ = proto.WriteFrame(conn, proto.Error{
				Type:    proto.TypeError,
				Message: "not authorized as approver",
			})
			conn.Close()
			continue
		}

		d.approverMu.Lock()
		if d.approver != nil {
			d.approverMu.Unlock()
			_ = proto.WriteFrame(conn, proto.Error{
				Type:    proto.TypeError,
				Message: "approver already connected",
			})
			conn.Close()
			continue
		}
		sess := &approverSession{
			conn:      conn,
			decisions: make(chan proto.Decision, 16),
		}
		d.approver = sess
		d.approverMu.Unlock()

		d.logger.Info("approver connected", "uid", peer.UID, "pid", peer.PID)
		go d.handleApprover(ctx, sess)

		d.rebroadcastPending(sess)
	}
}

func (d *Daemon) handleApprover(ctx context.Context, sess *approverSession) {
	defer func() {
		sess.conn.Close()
		d.approverMu.Lock()
		if d.approver == sess {
			d.approver = nil
		}
		d.approverMu.Unlock()
		d.abandonPending("approver disconnected")
		d.logger.Info("approver disconnected")
	}()

	for {
		raw, err := proto.ReadFrame(sess.conn)
		if err != nil {
			return
		}
		msg, err := proto.DecodeMessage(raw)
		if err != nil {
			d.logger.Warn("approver bad frame", "err", err)
			continue
		}
		switch m := msg.(type) {
		case *proto.Decision:
			d.routeDecision(*m)
		case *proto.List:
			d.sendRuleList(sess)
		case *proto.Revoke:
			if err := d.policy.RevokeRule(m.RuleID); err != nil {
				_ = proto.WriteFrame(sess.conn, proto.Error{
					Type: proto.TypeError, Message: err.Error(),
				})
			} else {
				_ = proto.WriteFrame(sess.conn, proto.Ack{Type: proto.TypeAck})
			}
		case *proto.ReloadPolicy:
			if err := d.policy.Reload(); err != nil {
				_ = proto.WriteFrame(sess.conn, proto.Error{
					Type: proto.TypeError, Message: err.Error(),
				})
			} else {
				_ = proto.WriteFrame(sess.conn, proto.Ack{Type: proto.TypeAck})
			}
		default:
			d.logger.Warn("approver sent unexpected message", "type", fmt.Sprintf("%T", msg))
		}
	}
}

func (d *Daemon) askApprover(ctx context.Context, p proto.Pending) (approverOutcome, error) {
	pr := &pendingRequest{
		id:       p.ID,
		pending:  p,
		decision: make(chan approverOutcome, 1),
	}

	d.pendingMu.Lock()
	if len(d.pending) >= d.cfg.PendingLimit {
		d.pendingMu.Unlock()
		return approverOutcome{}, errors.New("pending queue full")
	}
	d.pending[p.ID] = pr
	d.pendingMu.Unlock()

	defer func() {
		d.pendingMu.Lock()
		delete(d.pending, p.ID)
		d.pendingMu.Unlock()
	}()

	if err := d.sendPendingToApprover(p); err != nil {
		d.logger.Info("no approver connected, request queued", "id", p.ID)
	}

	timeout := time.Duration(d.cfg.PendingTimeoutSec) * time.Second
	if timeout <= 0 {
		timeout = 300 * time.Second
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case outcome := <-pr.decision:
		return outcome, nil
	case <-timer.C:
		return approverOutcome{}, errors.New("approver timeout")
	case <-ctx.Done():
		return approverOutcome{}, ctx.Err()
	}
}

func (d *Daemon) sendPendingToApprover(p proto.Pending) error {
	d.approverMu.Lock()
	sess := d.approver
	d.approverMu.Unlock()
	if sess == nil {
		return errors.New("no approver connected")
	}
	return proto.WriteFrame(sess.conn, p)
}

func (d *Daemon) rebroadcastPending(sess *approverSession) {
	d.pendingMu.Lock()
	snapshot := make([]proto.Pending, 0, len(d.pending))
	for _, pr := range d.pending {
		snapshot = append(snapshot, pr.pending)
	}
	d.pendingMu.Unlock()
	for _, p := range snapshot {
		_ = proto.WriteFrame(sess.conn, p)
	}
}

func (d *Daemon) routeDecision(dec proto.Decision) {
	d.pendingMu.Lock()
	pr, ok := d.pending[dec.ID]
	d.pendingMu.Unlock()
	if !ok {
		d.logger.Warn("decision for unknown id", "id", dec.ID)
		return
	}
	select {
	case pr.decision <- approverOutcome{decision: dec.Decision}:
	default:
		d.logger.Warn("decision dropped, channel full", "id", dec.ID)
	}
}

func (d *Daemon) sendRuleList(sess *approverSession) {
	pol := d.policy.Current()
	reply := proto.ListReply{
		Type:  proto.TypeListReply,
		Rules: make([]proto.RuleSummary, 0, len(pol.Rules)),
	}
	for _, r := range pol.Rules {
		reply.Rules = append(reply.Rules, proto.RuleSummary{
			ID:        r.ID,
			Requester: r.Requester,
			Command:   r.Command,
			Args:      r.Args,
			Decision:  r.Decision,
		})
	}
	_ = proto.WriteFrame(sess.conn, reply)
}

func (d *Daemon) abandonPending(reason string) {
	d.pendingMu.Lock()
	defer d.pendingMu.Unlock()
	for _, pr := range d.pending {
		select {
		case pr.decision <- approverOutcome{err: fmt.Errorf("approver gone: %s", reason)}:
		default:
		}
	}
}
