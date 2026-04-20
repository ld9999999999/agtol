package proto

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestFrameRoundTrip(t *testing.T) {
	cases := []struct {
		name string
		in   any
	}{
		{"exec", &Exec{Type: TypeExec, Argv: []string{"/bin/echo", "hi"}, Cwd: "/tmp"}},
		{"status", &Status{Type: TypeStatus, State: "approved", RuleID: 7}},
		{"stdout", &Stdout{Type: TypeStdout, Data: "hello\n"}},
		{"stderr", &Stderr{Type: TypeStderr, Data: "error\n"}},
		{"exit", &Exit{Type: TypeExit, Code: 0, DurationMs: 42}},
		{"pending", &Pending{
			Type: TypePending, ID: "req-1",
			Requester: "host:1000",
			Argv:      []string{"/bin/true"},
			Flags: []Flag{
				{Kind: "shell", Reason: "argv[0] is bash"},
			},
		}},
		{"decision", &Decision{Type: TypeDecision, ID: "req-1", Decision: "allow_once"}},
		{"list", &List{Type: TypeList}},
		{"list_reply", &ListReply{Type: TypeListReply, Rules: []RuleSummary{
			{ID: 1, Requester: "*", Command: "/bin/echo", Args: []string{"**"}, Decision: "allow"},
		}}},
		{"revoke", &Revoke{Type: TypeRevoke, RuleID: 5}},
		{"reload", &ReloadPolicy{Type: TypeReloadPolicy}},
		{"ack", &Ack{Type: TypeAck, ID: "req-1"}},
		{"error", &Error{Type: TypeError, Message: "something broke"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := WriteFrame(&buf, tc.in); err != nil {
				t.Fatalf("write: %v", err)
			}
			raw, err := ReadFrame(&buf)
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			out, err := DecodeMessage(raw)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}

			raw2, _ := bytes.NewBuffer(buf.Bytes()).ReadBytes('\n')
			_ = raw2

			if out == nil {
				t.Fatal("nil result")
			}

			var buf2 bytes.Buffer
			if err := WriteFrame(&buf2, out); err != nil {
				t.Fatalf("re-write: %v", err)
			}
			raw3, err := ReadFrame(&buf2)
			if err != nil {
				t.Fatalf("re-read: %v", err)
			}

			var reOut any
			reOut, err = DecodeMessage(raw3)
			if err != nil {
				t.Fatalf("re-decode: %v", err)
			}

			if tc.name == "exec" {
				exec1, ok1 := out.(*Exec)
				exec2, ok2 := reOut.(*Exec)
				if !ok1 || !ok2 {
					t.Fatal("type mismatch after round-trip")
				}
				if exec1.Cwd != exec2.Cwd {
					t.Errorf("cwd mismatch: %q vs %q", exec1.Cwd, exec2.Cwd)
				}
				if len(exec1.Argv) != len(exec2.Argv) {
					t.Errorf("argv length mismatch: %d vs %d", len(exec1.Argv), len(exec2.Argv))
				}
			}
		})
	}
}

func TestFrameTooLarge(t *testing.T) {
	var buf bytes.Buffer
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], MaxFrameSize+1)
	buf.Write(hdr[:])

	_, err := ReadFrame(&buf)
	if err != ErrFrameTooLarge {
		t.Errorf("expected ErrFrameTooLarge, got %v", err)
	}
}

func TestDecodeUnknownType(t *testing.T) {
	_, err := DecodeMessage([]byte(`{"type":"nope"}`))
	if err == nil {
		t.Fatal("expected error on unknown type")
	}
}

func TestDecodeInvalidJSON(t *testing.T) {
	_, err := DecodeMessage([]byte(`not json`))
	if err == nil {
		t.Fatal("expected error on invalid JSON")
	}
}

func TestReadFrameUnexpectedEOF(t *testing.T) {
	var buf bytes.Buffer
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], 100)
	buf.Write(hdr[:])
	buf.Write([]byte("only 7 bytes"))

	_, err := ReadFrame(&buf)
	if err == nil {
		t.Fatal("expected error on truncated frame")
	}
}
