package daemon

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/leon/approvald/internal/identity"
	"github.com/leon/approvald/internal/proto"
)

func (d *Daemon) executeAndStream(
	ctx context.Context,
	conn net.Conn,
	reqID string,
	peer identity.Peer,
	req *proto.Exec,
	canonicalPath string,
	start time.Time,
) {
	timeout := time.Duration(req.TimeoutSec) * time.Second
	if timeout <= 0 {
		pol := d.policy.Current()
		timeout = time.Duration(pol.Settings.DefaultExecTimeoutSec) * time.Second
	}
	pol := d.policy.Current()
	if max := time.Duration(pol.Settings.DefaultExecTimeoutSec) * time.Second; max > 0 && timeout > max {
		timeout = max
	}
	if timeout <= 0 {
		timeout = 300 * time.Second
	}

	d.logger.Info("executeAndStream starting",
		"req_id", reqID,
		"canonical", canonicalPath,
		"argv", req.Argv,
		"timeout", timeout,
	)

	execCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	env := d.buildEnv(req.Env)
	cwd := d.safeCwd(req.Cwd)
	d.logger.Info("exec environment", "req_id", reqID, "cwd", cwd, "env", env)

	stdoutR, stdoutW, err := os.Pipe()
	if err != nil {
		d.logger.Error("stdout pipe failed", "req_id", reqID, "err", err)
		writeStderr(conn, "approvald: stdout pipe: "+err.Error())
		writeExit(conn, 126, start)
		return
	}
	stderrR, stderrW, err := os.Pipe()
	if err != nil {
		d.logger.Error("stderr pipe failed", "req_id", reqID, "err", err)
		stdoutR.Close()
		stdoutW.Close()
		writeStderr(conn, "approvald: stderr pipe: "+err.Error())
		writeExit(conn, 126, start)
		return
	}
	devnullR, _ := os.Open(os.DevNull)

	binFd, err := syscall.Open(canonicalPath, syscall.O_RDONLY|syscall.O_CLOEXEC, 0)
	if err != nil {
		d.logger.Error("open binary failed", "req_id", reqID, "path", canonicalPath, "err", err)
		stdoutR.Close()
		stdoutW.Close()
		stderrR.Close()
		stderrW.Close()
		devnullR.Close()
		writeStderr(conn, "approvald: open binary: "+err.Error())
		writeExit(conn, 126, start)
		d.audit.RecordExecFailed(reqID, peer, req, fmt.Errorf("open %s: %w", canonicalPath, err))
		return
	}

	argv := req.Argv
	if len(argv) == 0 {
		argv = []string{canonicalPath}
	}

	d.logger.Info("forking subprocess", "req_id", reqID, "path", canonicalPath, "argv", argv, "cwd", cwd)
	pid, err := syscall.ForkExec(canonicalPath, argv, &syscall.ProcAttr{
		Dir: cwd,
		Env: env,
		Files: []uintptr{
			devnullR.Fd(),
			stdoutW.Fd(),
			stderrW.Fd(),
		},
		Sys: &syscall.SysProcAttr{
			Setsid: true,
		},
	})
	devnullR.Close()
	stdoutW.Close()
	stderrW.Close()
	syscall.Close(binFd)

	if err != nil {
		d.logger.Error("fork/exec failed", "req_id", reqID, "err", err)
		stdoutR.Close()
		stderrR.Close()
		writeStderr(conn, "approvald: fork/exec: "+err.Error())
		writeExit(conn, 126, start)
		d.audit.RecordExecFailed(reqID, peer, req, err)
		return
	}

	d.logger.Info("subprocess started", "req_id", reqID, "pid", pid)
	writeStatus(conn, "running", 0, "")

	var streamWg sync.WaitGroup
	streamWg.Add(2)
	go func() {
		defer streamWg.Done()
		streamPipe(conn, stdoutR, proto.TypeStdout)
	}()
	go func() {
		defer streamWg.Done()
		streamPipe(conn, stderrR, proto.TypeStderr)
	}()

	waitCh := make(chan error, 1)
	go func() {
		_, werr := syscall.Wait4(pid, nil, 0, nil)
		waitCh <- werr
	}()

	var waitErr error
	var exitCode int
	select {
	case waitErr = <-waitCh:
		if waitErr != nil {
			exitCode = 126
			d.logger.Error("subprocess wait error", "req_id", reqID, "pid", pid, "err", waitErr)
		}
	case <-execCtx.Done():
		d.logger.Warn("subprocess timed out, sending SIGTERM", "req_id", reqID, "pid", pid, "timeout", timeout)
		syscall.Kill(-pid, syscall.SIGTERM)
		time.AfterFunc(5*time.Second, func() {
			d.logger.Warn("sending SIGKILL after grace period", "req_id", reqID, "pid", pid)
			syscall.Kill(-pid, syscall.SIGKILL)
		})
		waitErr = <-waitCh
		exitCode = 124
		writeStderr(conn, "approvald: command timed out after "+timeout.String())
	}

	streamWg.Wait()
	stdoutR.Close()
	stderrR.Close()

	d.logger.Info("sending exit frame", "req_id", reqID, "pid", pid, "exit_code", exitCode, "duration_ms", time.Since(start).Milliseconds())
	writeExit(conn, exitCode, start)
	d.audit.RecordExecCompleted(reqID, peer, req, exitCode, time.Since(start))
}

func streamPipe(conn net.Conn, r io.Reader, msgType string) {
	buf := make([]byte, 16*1024)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			chunk := buf[:n]
			var frame any
			switch msgType {
			case proto.TypeStdout:
				frame = proto.Stdout{Type: proto.TypeStdout, Data: string(chunk)}
			case proto.TypeStderr:
				frame = proto.Stderr{Type: proto.TypeStderr, Data: string(chunk)}
			}
			if err := proto.WriteFrame(conn, frame); err != nil {
				io.Copy(io.Discard, r)
				break
			}
		}
		if err != nil {
			break
		}
	}
}

func writeStderr(conn net.Conn, msg string) {
	_ = proto.WriteFrame(conn, proto.Stderr{
		Type: proto.TypeStderr,
		Data: msg + "\n",
	})
}

func (d *Daemon) buildEnv(clientEnv map[string]string) []string {
	allowlist := d.policy.Current().Settings.EnvAllowlist
	allow := make(map[string]bool, len(allowlist))
	for _, k := range allowlist {
		allow[k] = true
	}

	blocked := map[string]bool{
		"LD_PRELOAD":      true,
		"LD_LIBRARY_PATH": true,
		"PYTHONPATH":      true,
		"PERL5LIB":        true,
		"NODE_OPTIONS":    true,
		"RUBYLIB":         true,
	}

	env := []string{
		"PATH=/usr/sbin:/usr/bin:/sbin:/bin",
	}
	for k, v := range clientEnv {
		if blocked[k] {
			continue
		}
		if allow[k] {
			env = append(env, k+"="+v)
		}
	}
	return env
}

func (d *Daemon) safeCwd(cwd string) string {
	if cwd == "" {
		return "/"
	}
	fi, err := os.Stat(cwd)
	if err != nil || !fi.IsDir() {
		return "/"
	}
	return cwd
}

func init() {
	_ = filepath.IsAbs
	_ = exec.LookPath
}
