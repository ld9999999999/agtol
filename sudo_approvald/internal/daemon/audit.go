package daemon

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/leon/approvald/internal/identity"
	"github.com/leon/approvald/internal/proto"
)

// AuditLog writes one JSON line per completed request to a file.
//
// The log is append-only. Rotation is external (logrotate). If the file
// can't be opened, audit writes become no-ops and the error is logged
// once — audit failure must not block command execution.
type AuditLog struct {
	mu         sync.Mutex
	f          *os.File
	warnedOnce bool
}

// OpenAuditLog opens path for append; the caller is responsible for close.
func OpenAuditLog(path string) (*AuditLog, error) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open audit log: %w", err)
	}
	return &AuditLog{f: f}, nil
}

// Close closes the underlying file.
func (a *AuditLog) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.f == nil {
		return nil
	}
	err := a.f.Close()
	a.f = nil
	return err
}

type auditEntry struct {
	Timestamp     string      `json:"ts"`
	ReqID         string      `json:"req_id"`
	Event         string      `json:"event"` // denied | exec_failed | exec_completed
	Requester     string      `json:"requester"`
	RequesterHint string      `json:"requester_hint,omitempty"`
	PeerUID       int         `json:"peer_uid"`
	PeerPID       int         `json:"peer_pid"`
	Argv          []string    `json:"argv"`
	Cwd           string      `json:"cwd,omitempty"`
	Flags         []proto.Flag `json:"flags,omitempty"`
	Reason        string      `json:"reason,omitempty"`
	ExitCode      int         `json:"exit_code,omitempty"`
	DurationMs    int64       `json:"duration_ms,omitempty"`
	Error         string      `json:"error,omitempty"`
}

// RecordDenied logs a denied request.
func (a *AuditLog) RecordDenied(id string, peer identity.Peer, req *proto.Exec, reason string) {
	a.write(auditEntry{
		Timestamp:     time.Now().UTC().Format(time.RFC3339Nano),
		ReqID:         id,
		Event:         "denied",
		Requester:     identity.Requester(peer),
		RequesterHint: req.RequesterHint,
		PeerUID:       peer.UID,
		PeerPID:       peer.PID,
		Argv:          req.Argv,
		Cwd:           req.Cwd,
		Reason:        reason,
	})
}

// RecordExecFailed logs a request where exec itself failed before running.
func (a *AuditLog) RecordExecFailed(id string, peer identity.Peer, req *proto.Exec, err error) {
	a.write(auditEntry{
		Timestamp:     time.Now().UTC().Format(time.RFC3339Nano),
		ReqID:         id,
		Event:         "exec_failed",
		Requester:     identity.Requester(peer),
		RequesterHint: req.RequesterHint,
		PeerUID:       peer.UID,
		PeerPID:       peer.PID,
		Argv:          req.Argv,
		Cwd:           req.Cwd,
		Error:         err.Error(),
	})
}

// RecordExecCompleted logs a request that ran to completion (or timeout).
func (a *AuditLog) RecordExecCompleted(id string, peer identity.Peer, req *proto.Exec, exit int, dur time.Duration) {
	a.write(auditEntry{
		Timestamp:     time.Now().UTC().Format(time.RFC3339Nano),
		ReqID:         id,
		Event:         "exec_completed",
		Requester:     identity.Requester(peer),
		RequesterHint: req.RequesterHint,
		PeerUID:       peer.UID,
		PeerPID:       peer.PID,
		Argv:          req.Argv,
		Cwd:           req.Cwd,
		ExitCode:      exit,
		DurationMs:    dur.Milliseconds(),
	})
}

func (a *AuditLog) write(e auditEntry) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.f == nil {
		return
	}
	buf, err := json.Marshal(e)
	if err != nil {
		if !a.warnedOnce {
			fmt.Fprintln(os.Stderr, "audit marshal:", err)
			a.warnedOnce = true
		}
		return
	}
	buf = append(buf, '\n')
	if _, err := a.f.Write(buf); err != nil {
		if !a.warnedOnce {
			fmt.Fprintln(os.Stderr, "audit write:", err)
			a.warnedOnce = true
		}
	}
}
