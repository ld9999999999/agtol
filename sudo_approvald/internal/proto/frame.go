package proto

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// ErrFrameTooLarge is returned by ReadFrame when the declared length exceeds
// MaxFrameSize. The connection should be closed when this happens.
var ErrFrameTooLarge = errors.New("proto: frame exceeds MaxFrameSize")

// WriteFrame marshals msg to JSON and writes it as a length-prefixed frame.
func WriteFrame(w io.Writer, msg any) error {
	payload, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("proto: marshal: %w", err)
	}
	if len(payload) > MaxFrameSize {
		return ErrFrameTooLarge
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(payload)))
	if _, err := w.Write(hdr[:]); err != nil {
		return fmt.Errorf("proto: write header: %w", err)
	}
	if _, err := w.Write(payload); err != nil {
		return fmt.Errorf("proto: write payload: %w", err)
	}
	return nil
}

// ReadFrame reads one length-prefixed frame and returns its raw JSON payload.
// The caller typically passes the result to DecodeMessage.
func ReadFrame(r io.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n > MaxFrameSize {
		return nil, ErrFrameTooLarge
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, fmt.Errorf("proto: read payload: %w", err)
	}
	return buf, nil
}
