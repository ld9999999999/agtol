// Package proto defines the wire protocol shared by approvald, claude-sudo,
// and approve.
//
// Frames are length-prefixed JSON: uint32 big-endian length, then payload.
// Max frame size is enforced to prevent OOM on garbage input.
//
// Every message has a "type" field that determines which concrete struct to
// unmarshal into. Use DecodeFrame to read a raw frame and DecodeMessage to
// dispatch it to the right type.
package proto

import (
	"encoding/json"
	"errors"
)

// MaxFrameSize is the largest frame we'll accept or produce.
const MaxFrameSize = 1 << 20 // 1 MiB

// Message types. Add new types here and in DecodeMessage's switch.
const (
	// Client -> daemon
	TypeExec = "exec"

	// Daemon -> client
	TypeStatus = "status"
	TypeStdout = "stdout"
	TypeStderr = "stderr"
	TypeExit   = "exit"

	// Daemon <-> approver
	TypePending      = "pending"
	TypeDecision     = "decision"
	TypeList         = "list"
	TypeListReply    = "list_reply"
	TypeRevoke       = "revoke"
	TypeReloadPolicy = "reload_policy"
	TypeAck          = "ack"
	TypeError        = "error"
)

// Exec is the single request a client sends after connecting.
type Exec struct {
	Type           string            `json:"type"` // TypeExec
	Argv           []string          `json:"argv"`
	Cwd            string            `json:"cwd"`
	Env            map[string]string `json:"env"`
	RequesterHint  string            `json:"requester_hint,omitempty"`
	TimeoutSec     int               `json:"timeout_sec,omitempty"`
}

// Status reports request lifecycle changes to the client.
type Status struct {
	Type    string `json:"type"` // TypeStatus
	State   string `json:"state"` // queued | approved | denied | running
	RuleID  int    `json:"rule_id,omitempty"`
	Reason  string `json:"reason,omitempty"`
}

// Stdout/Stderr stream subprocess output. Data may be chunked arbitrarily;
// clients should not assume line boundaries.
type Stdout struct {
	Type string `json:"type"` // TypeStdout
	Data string `json:"data"`
}

type Stderr struct {
	Type string `json:"type"` // TypeStderr
	Data string `json:"data"`
}

// Exit is the final message on a client connection.
type Exit struct {
	Type       string `json:"type"` // TypeExit
	Code       int    `json:"code"`
	DurationMs int64  `json:"duration_ms"`
}

// Flag annotates a pending request with a dangerous-pattern detection.
type Flag struct {
	Kind   string `json:"kind"`   // e.g. "reads-credentials"
	Reason string `json:"reason"` // human-readable, one line
}

// Pending is sent to the approver when a request matches an "ask" rule.
type Pending struct {
	Type             string   `json:"type"` // TypePending
	ID               string   `json:"id"`
	Requester        string   `json:"requester"`     // derived, trusted
	RequesterHint    string   `json:"requester_hint,omitempty"` // from client, advisory
	Argv             []string `json:"argv"`
	Cwd              string   `json:"cwd"`
	MatchedRuleID    int      `json:"matched_rule_id,omitempty"`
	MatchedDecision  string   `json:"matched_decision"`
	Flags            []Flag   `json:"flags,omitempty"`
}

// Decision is sent from approver to daemon in response to a Pending.
type Decision struct {
	Type     string `json:"type"`     // TypeDecision
	ID       string `json:"id"`
	Decision string `json:"decision"` // allow_once | allow_remember | deny_once | deny_remember
}

// List / ListReply for the approver to query current rules.
type List struct {
	Type string `json:"type"` // TypeList
}

type ListReply struct {
	Type  string       `json:"type"` // TypeListReply
	Rules []RuleSummary `json:"rules"`
}

type RuleSummary struct {
	ID        int      `json:"id"`
	Requester string   `json:"requester"`
	Command   string   `json:"command"`
	Args      []string `json:"args"`
	Decision  string   `json:"decision"`
}

// Revoke asks the daemon to delete a rule by ID.
type Revoke struct {
	Type   string `json:"type"` // TypeRevoke
	RuleID int    `json:"rule_id"`
}

type ReloadPolicy struct {
	Type string `json:"type"` // TypeReloadPolicy
}

type Ack struct {
	Type string `json:"type"` // TypeAck
	ID   string `json:"id,omitempty"`
}

type Error struct {
	Type    string `json:"type"` // TypeError
	Message string `json:"message"`
}

// Envelope extracts just the "type" field for dispatch.
type Envelope struct {
	Type string `json:"type"`
}

// DecodeMessage parses a raw JSON payload into the appropriate concrete type.
// Returns the typed value and a nil error on success.
func DecodeMessage(raw []byte) (any, error) {
	var env Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, err
	}
	switch env.Type {
	case TypeExec:
		var m Exec
		return &m, json.Unmarshal(raw, &m)
	case TypeStatus:
		var m Status
		return &m, json.Unmarshal(raw, &m)
	case TypeStdout:
		var m Stdout
		return &m, json.Unmarshal(raw, &m)
	case TypeStderr:
		var m Stderr
		return &m, json.Unmarshal(raw, &m)
	case TypeExit:
		var m Exit
		return &m, json.Unmarshal(raw, &m)
	case TypePending:
		var m Pending
		return &m, json.Unmarshal(raw, &m)
	case TypeDecision:
		var m Decision
		return &m, json.Unmarshal(raw, &m)
	case TypeList:
		var m List
		return &m, json.Unmarshal(raw, &m)
	case TypeListReply:
		var m ListReply
		return &m, json.Unmarshal(raw, &m)
	case TypeRevoke:
		var m Revoke
		return &m, json.Unmarshal(raw, &m)
	case TypeReloadPolicy:
		var m ReloadPolicy
		return &m, json.Unmarshal(raw, &m)
	case TypeAck:
		var m Ack
		return &m, json.Unmarshal(raw, &m)
	case TypeError:
		var m Error
		return &m, json.Unmarshal(raw, &m)
	default:
		return nil, errors.New("unknown message type: " + env.Type)
	}
}
