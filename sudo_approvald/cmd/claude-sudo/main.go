// Command claude-sudo is a drop-in(-ish) replacement for sudo that routes
// the request through approvald rather than asking for a password.
//
// Usage:
//
//	claude-sudo <command> [args...]
//
// Environment:
//
//	APPROVALD_SOCKET  path to client.sock (default /run/approvald/client.sock)
//	APPROVALD_HINT    requester hint string sent to the daemon (advisory)
//
// Exit codes:
//
//	0..N    the underlying command's exit code
//	124     the command timed out inside approvald
//	126     denied, or transport error
package main

import (
	"fmt"
	"net"
	"os"

	"github.com/leon/approvald/internal/proto"
)

const defaultSocket = "/run/approvald/client.sock"

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: claude-sudo <command> [args...]")
		os.Exit(2)
	}

	sock := os.Getenv("APPROVALD_SOCKET")
	if sock == "" {
		sock = defaultSocket
	}

	conn, err := net.Dial("unix", sock)
	if err != nil {
		fmt.Fprintf(os.Stderr, "claude-sudo: approvald not running: %s (%v)\n", sock, err)
		os.Exit(126)
	}
	defer conn.Close()

	cwd, _ := os.Getwd()

	req := proto.Exec{
		Type:          proto.TypeExec,
		Argv:          os.Args[1:],
		Cwd:           cwd,
		Env:           collectEnv(),
		RequesterHint: os.Getenv("APPROVALD_HINT"),
	}
	if err := proto.WriteFrame(conn, req); err != nil {
		fmt.Fprintln(os.Stderr, "claude-sudo: send:", err)
		os.Exit(126)
	}

	// Read frames until Exit.
	for {
		raw, err := proto.ReadFrame(conn)
		if err != nil {
			fmt.Fprintln(os.Stderr, "claude-sudo: lost connection to approvald:", err)
			os.Exit(126)
		}
		msg, err := proto.DecodeMessage(raw)
		if err != nil {
			fmt.Fprintln(os.Stderr, "claude-sudo: decode:", err)
			os.Exit(126)
		}
		switch m := msg.(type) {
		case *proto.Status:
			// Silent by default. A -v flag could surface these to stderr.
			_ = m
		case *proto.Stdout:
			os.Stdout.WriteString(m.Data)
		case *proto.Stderr:
			os.Stderr.WriteString(m.Data)
		case *proto.Exit:
			os.Exit(m.Code)
		case *proto.Error:
			fmt.Fprintln(os.Stderr, "claude-sudo:", m.Message)
			os.Exit(126)
		default:
			fmt.Fprintf(os.Stderr, "claude-sudo: unexpected frame %T\n", m)
			os.Exit(126)
		}
	}
}

// collectEnv gathers the caller's env. The daemon will intersect this with
// its policy allowlist; nothing is guaranteed to be forwarded.
//
// Sensitive variables (LD_PRELOAD, etc.) are never forwarded regardless,
// so there's no harm in sending everything — but we avoid a few obviously
// useless ones to keep the frame small.
func collectEnv() map[string]string {
	out := make(map[string]string, 16)
	for _, kv := range os.Environ() {
		for i := 0; i < len(kv); i++ {
			if kv[i] == '=' {
				k, v := kv[:i], kv[i+1:]
				if skipEnv(k) {
					break
				}
				out[k] = v
				break
			}
		}
	}
	return out
}

func skipEnv(k string) bool {
	switch k {
	case "_", "SHLVL", "PWD", "OLDPWD", "LINES", "COLUMNS":
		return true
	}
	return false
}
