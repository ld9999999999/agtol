module github.com/leon/approvald

go 1.26

// Dependencies to add during implementation:
//   github.com/pelletier/go-toml/v2    // policy file parsing + writing
//   golang.org/x/sys/unix              // SO_PEERCRED, setsid, etc.
//   golang.org/x/term                  // raw-mode keystroke reading in `approve`
//
// Stdlib-only is the goal otherwise. `log/slog` for structured logging.

require (
	github.com/pelletier/go-toml/v2 v2.3.0
	golang.org/x/sys v0.43.0
	golang.org/x/term v0.42.0
)
