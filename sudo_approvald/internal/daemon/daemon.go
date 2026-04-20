package daemon

import (
	"context"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"

	"github.com/leon/approvald/internal/policy"
	"github.com/leon/approvald/internal/proto"
)

type Daemon struct {
	cfg    *Config
	logger *slog.Logger
	policy *policy.Store
	audit  *AuditLog

	clientLn   *net.UnixListener
	approverLn *net.UnixListener

	approverMu sync.Mutex
	approver   *approverSession

	pendingMu sync.Mutex
	pending   map[string]*pendingRequest

	shutdownOnce sync.Once
	cancel       context.CancelFunc

	clientPath   string
	approverPath string
}

type approverSession struct {
	conn      net.Conn
	decisions chan proto.Decision
}

type pendingRequest struct {
	id       string
	pending  proto.Pending
	decision chan approverOutcome
}

type approverOutcome struct {
	decision string
	err      error
}

func New(cfg *Config, logger *slog.Logger, store *policy.Store, audit *AuditLog) *Daemon {
	pol := store.Current()
	if cfg.PendingLimit <= 0 {
		cfg.PendingLimit = pol.Settings.PendingLimit
	}
	if cfg.PendingTimeoutSec <= 0 {
		cfg.PendingTimeoutSec = pol.Settings.PendingTimeoutSec
	}

	logger.Info("daemon config resolved",
		"pending_limit", cfg.PendingLimit,
		"pending_timeout_sec", cfg.PendingTimeoutSec,
		"approver_uid", cfg.ApproverUID,
		"client_gid", cfg.ClientGID,
	)

	return &Daemon{
		cfg:     cfg,
		logger:  logger,
		policy:  store,
		audit:   audit,
		pending: make(map[string]*pendingRequest),
	}
}

func (d *Daemon) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	d.cancel = cancel
	defer d.shutdown()

	if err := d.setupSockets(); err != nil {
		return err
	}

	go d.acceptClients(ctx)
	go d.acceptApprover(ctx)

	d.logger.Info("approvald running",
		"client_sock", d.clientPath,
		"approver_sock", d.approverPath,
	)

	<-ctx.Done()
	d.logger.Info("shutting down")
	return nil
}

func (d *Daemon) setupSockets() error {
	if err := os.MkdirAll(d.cfg.SocketDir, 0755); err != nil {
		return err
	}

	d.clientPath = filepath.Join(d.cfg.SocketDir, "client.sock")
	d.approverPath = filepath.Join(d.cfg.SocketDir, "approver.sock")

	for _, p := range []string{d.clientPath, d.approverPath} {
		os.Remove(p)
	}

	clientAddr := &net.UnixAddr{Name: d.clientPath, Net: "unix"}
	clientLn, err := net.ListenUnix("unix", clientAddr)
	if err != nil {
		return err
	}
	d.clientLn = clientLn

	approverAddr := &net.UnixAddr{Name: d.approverPath, Net: "unix"}
	approverLn, err := net.ListenUnix("unix", approverAddr)
	if err != nil {
		clientLn.Close()
		return err
	}
	d.approverLn = approverLn

	if err := os.Chown(d.clientPath, 0, d.cfg.ClientGID); err != nil {
		return err
	}
	if err := os.Chmod(d.clientPath, 0o660); err != nil {
		return err
	}

	if err := os.Chown(d.approverPath, d.cfg.ApproverUID, 0); err != nil {
		return err
	}
	if err := os.Chmod(d.approverPath, 0o600); err != nil {
		return err
	}

	return nil
}

func (d *Daemon) shutdown() {
	d.shutdownOnce.Do(func() {
		d.abandonPending("daemon shutting down")

		if d.clientLn != nil {
			d.clientLn.Close()
		}
		if d.approverLn != nil {
			d.approverLn.Close()
		}

		os.Remove(d.clientPath)
		os.Remove(d.approverPath)
	})
}
