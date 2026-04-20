// Command approvald is the privilege-approval daemon. It listens on two
// Unix sockets (client + approver), matches requests against a policy file,
// asks the approver for anything that needs a decision, and runs approved
// commands as root.
//
// Usage:
//
//	approvald --approver-uid USER --policy PATH [flags]
//
// See docs/DESIGN.md for the full picture.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/leon/approvald/internal/daemon"
	"github.com/leon/approvald/internal/policy"
)

func main() {
	daemon.MustBeRoot()

	cfg, err := daemon.ParseFlags(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, "approvald:", err)
		os.Exit(2)
	}

	level := slog.LevelInfo
	if cfg.Verbose {
		level = slog.LevelDebug
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	store, err := policy.NewStore(cfg.PolicyPath)
	if err != nil {
		logger.Error("load policy", "err", err)
		os.Exit(1)
	}

	audit, err := daemon.OpenAuditLog(cfg.LogPath)
	if err != nil {
		logger.Error("open audit log", "err", err)
		os.Exit(1)
	}
	defer audit.Close()

	d := daemon.New(cfg, logger, store, audit)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Signal handling: SIGHUP reloads policy, SIGTERM/SIGINT shuts down.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGHUP, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		for sig := range sigCh {
			switch sig {
			case syscall.SIGHUP:
				if err := store.Reload(); err != nil {
					logger.Error("reload policy", "err", err)
				} else {
					logger.Info("policy reloaded")
				}
			case syscall.SIGTERM, syscall.SIGINT:
				logger.Info("shutting down", "signal", sig)
				cancel()
				return
			}
		}
	}()

	if err := d.Run(ctx); err != nil {
		logger.Error("daemon exited with error", "err", err)
		os.Exit(1)
	}
}
