package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/leon/approvald/internal/proto"
	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

const defaultSocket = "/run/approvald/approver.sock"

const (
	reset      = "\x1b[0m"
	bold       = "\x1b[1m"
	dim        = "\x1b[2m"
	underline  = "\x1b[4m"
	fgRed      = "\x1b[31m"
	fgGreen    = "\x1b[32m"
	fgYellow   = "\x1b[33m"
	fgBlue     = "\x1b[34m"
	fgMagenta  = "\x1b[35m"
	fgCyan     = "\x1b[36m"
	fgWhite    = "\x1b[37m"
	bgGray     = "\x1b[48;5;236m"
	bgDarkGray = "\x1b[48;5;234m"
	bgRed      = "\x1b[41m"
	bgGreen    = "\x1b[42m"
	hideCursor = "\x1b[?25l"
	showCursor = "\x1b[?25h"
)

func termWidth() int {
	w, _, err := term.GetSize(int(os.Stdin.Fd()))
	if err != nil || w < 20 {
		return 80
	}
	return w
}

func padLine(s string, width int) string {
	stripped := stripAnsi(s)
	pad := width - runeWidth(stripped)
	if pad < 0 {
		pad = 0
	}
	return s + strings.Repeat(" ", pad)
}

func runeWidth(s string) int {
	w := 0
	for _, r := range s {
		if r >= 0x1100 {
			w += 2
		} else {
			w++
		}
	}
	return w
}

func stripAnsi(s string) string {
	var out strings.Builder
	i := 0
	for i < len(s) {
		if s[i] == '\x1b' && i+1 < len(s) && s[i+1] == '[' {
			j := i + 2
			for j < len(s) && ((s[j] >= '0' && s[j] <= '9') || s[j] == ';' || s[j] == '?') {
				j++
			}
			if j < len(s) {
				i = j + 1
				continue
			}
		}
		out.WriteByte(s[i])
		i++
	}
	return out.String()
}

func centerLine(s string, width int) string {
	stripped := stripAnsi(s)
	sw := runeWidth(stripped)
	if sw >= width {
		return s
	}
	pad := (width - sw) / 2
	return strings.Repeat(" ", pad) + s
}

func truncLine(s string, width int) string {
	stripped := stripAnsi(s)
	if runeWidth(stripped) <= width {
		return s
	}
	runes := []rune(s)
	ansiExtra := len(s) - runeWidth(s)
	targetRunes := width - 2
	if targetRunes < 0 {
		targetRunes = 0
	}
	result := make([]rune, 0, len(runes))
	visLen := 0
	inEscape := false
	for _, r := range runes {
		if r == '\x1b' {
			inEscape = true
			result = append(result, r)
			continue
		}
		if inEscape {
			result = append(result, r)
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
				inEscape = false
			}
			continue
		}
		visLen++
		if visLen > targetRunes {
			break
		}
		result = append(result, r)
	}
	_ = ansiExtra
	return string(result) + ".."
}

func main() {
	var (
		sockPath             = flag.String("socket", defaultSocket, "path to approvald approver socket")
		allowRememberFlagged = flag.Bool("allow-remember-flagged", false, "allow 'remember' on flagged requests")
	)
	flag.Parse()

	conn, err := net.Dial("unix", *sockPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "approve: cannot connect to %s: %v\n", *sockPath, err)
		os.Exit(1)
	}
	defer conn.Close()

	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		fmt.Fprintln(os.Stderr, "approve: cannot set raw mode:", err)
		fmt.Fprintln(os.Stderr, "approve: falling back to line mode")
		lineLoop(conn, *allowRememberFlagged)
		return
	}
	defer term.Restore(int(os.Stdin.Fd()), oldState)

	rawLoop(conn, *allowRememberFlagged)
}

type ui struct {
	conn                 net.Conn
	allowRememberFlagged bool
	queue                []*proto.Pending
	width                int
	redrawCh             chan struct{}
}

func rawLoop(conn net.Conn, allowRememberFlagged bool) {
	u := &ui{
		conn:                 conn,
		allowRememberFlagged: allowRememberFlagged,
		queue:                nil,
		width:                termWidth(),
		redrawCh:             make(chan struct{}, 1),
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, unix.SIGWINCH)
	go func() {
		for range sigCh {
			u.redrawCh <- struct{}{}
		}
	}()

	frameCh := make(chan any, 32)
	go func() {
		for {
			raw, err := proto.ReadFrame(conn)
			if err != nil {
				frameCh <- err
				return
			}
			msg, err := proto.DecodeMessage(raw)
			if err != nil {
				continue
			}
			frameCh <- msg
		}
	}()

	keyCh := make(chan byte, 16)
	go func() {
		buf := make([]byte, 1)
		for {
			n, err := os.Stdin.Read(buf)
			if err != nil || n == 0 {
				keyCh <- 0
				return
			}
			keyCh <- buf[0]
		}
	}()

	fmt.Print(hideCursor)
	defer fmt.Print(showCursor)

	u.render()

	for {
		select {
		case <-u.redrawCh:
			u.width = termWidth()
			u.render()
		case msg := <-frameCh:
			err, isErr := msg.(error)
			if isErr {
				fmt.Print(showCursor)
				fmt.Fprintf(os.Stderr, "\rapprove: disconnected: %v\r\n", err)
				return
			}
			switch m := msg.(type) {
			case *proto.Pending:
				u.queue = append(u.queue, m)
				u.render()
			case *proto.ListReply:
				u.renderRules(m)
				u.render()
			case *proto.Ack:
			case *proto.Error:
				u.renderError(m.Message)
				u.render()
			}
		case key := <-keyCh:
			if !u.handleKey(key) {
				return
			}
		}
	}
}

func (u *ui) render() {
	if len(u.queue) == 0 {
		u.renderWaiting()
		return
	}
	u.renderPending(u.queue[0])
}

func (u *ui) renderWaiting() {
	w := u.width
	line := bold + fgCyan + " approve " + reset + dim + " waiting for pending requests..." + reset
	fmt.Println(padLine(centerLine(line, w), w))
}

func (u *ui) renderPending(p *proto.Pending) {
	w := u.width

	header := fmt.Sprintf(" %s  %s  (%d queued) ", bold+"APPROVAL REQUIRED"+reset, dim+p.ID+reset, len(u.queue))
	u.printBoxHeader(header)

	u.printField("requester", p.Requester, fgCyan)
	if p.RequesterHint != "" && p.RequesterHint != p.Requester {
		u.printField("     hint", p.RequesterHint+fgRed+" (mismatch)"+reset, fgRed+dim)
	}
	u.printField("      cwd", p.Cwd, reset)
	u.printField("  command", formatArgv(p.Argv), fgYellow+bold)
	if p.MatchedRuleID != 0 {
		u.printField("  matched", fmt.Sprintf("rule %s#%d%s %s→ %s%s%s", fgMagenta, p.MatchedRuleID, reset+dim, reset, bold, p.MatchedDecision, reset), reset)
	}
	if len(p.Flags) > 0 {
		fmt.Println()
		for _, f := range p.Flags {
			line := fmt.Sprintf("  %s⚠ %s%s %s— %s%s", bold+fgRed, f.Kind, reset+fgRed, dim, f.Reason, reset)
			fmt.Println(padLine(truncLine(line, w), w))
		}
	}
	fmt.Println()

	rememberDisabled := len(p.Flags) > 0 && !u.allowRememberFlagged

	fmt.Print(padLine(bgGray+fgWhite, w))
	fmt.Print(padLine(bgGray+bold+fgWhite+"  Key bindings:"+reset+bgGray+fgWhite+dim, w))
	fmt.Print(padLine(bgGray+fgWhite, w))

	keys := bgGray + fgWhite + "  " + fgGreen + "[a]" + reset + bgGray + fgWhite + " allow once   "
	if !rememberDisabled {
		keys += fgGreen + "[A]" + reset + bgGray + fgWhite + " allow+remember   "
	} else {
		keys += dim + fgWhite + "[A] (disabled)         " + reset + bgGray + fgWhite
	}
	keys += fgRed + "[d]" + reset + bgGray + fgWhite + " deny   " + fgRed + "[D]" + reset + bgGray + fgWhite + " deny+remember"
	keys += "   " + fgBlue + "[s]" + reset + bgGray + fgWhite + " skip   " + dim + "[q]" + reset + bgGray + fgWhite + " quit"
	fmt.Print(padLine(truncLine(keys, w), w))
	fmt.Print(padLine(bgGray+fgWhite, w))
	fmt.Println(reset)

	fmt.Print(bold + "> " + reset)
}

func (u *ui) printBoxHeader(s string) {
	w := u.width
	fmt.Println(padLine(bold+fgWhite+s+reset, w))
}

func (u *ui) printField(label, value, valueStyle string) {
	w := u.width
	line := fmt.Sprintf("  %s%s%-10s%s %s", dim, label, "", reset, valueStyle+value+reset)
	fmt.Println(padLine(truncLine(line, w), w))
}

func (u *ui) renderRules(r *proto.ListReply) {
	w := u.width
	header := bold + " Rules " + reset
	fmt.Println(padLine(centerLine(header, w), w))
	for _, rule := range r.Rules {
		args := strings.Join(rule.Args, " ")
		line := fmt.Sprintf("  %s#%d%s  %s%s%s  %s%s %s%s  %s→ %s%s%s",
			fgMagenta, rule.ID, reset,
			fgCyan, rule.Requester, reset,
			fgYellow, rule.Command, args, reset,
			dim, bold, rule.Decision, reset)
		fmt.Println(padLine(truncLine(line, w), w))
	}
	fmt.Println()
}

func (u *ui) renderError(msg string) {
	w := u.width
	line := fmt.Sprintf("  %sERROR:%s %s", bold+fgRed, reset, msg)
	fmt.Println(padLine(truncLine(line, w), w))
}

func (u *ui) handleKey(key byte) bool {
	if key == 0 {
		return false
	}
	if len(u.queue) == 0 {
		if key == 'q' || key == 3 {
			return false
		}
		return true
	}
	p := u.queue[0]
	rememberDisabled := len(p.Flags) > 0 && !u.allowRememberFlagged

	var decision string
	switch key {
	case 'a':
		decision = "allow_once"
	case 'A':
		if rememberDisabled {
			return true
		}
		decision = "allow_remember"
	case 'd':
		decision = "deny_once"
	case 'D':
		decision = "deny_remember"
	case 's':
		u.queue = append(u.queue[1:], u.queue[0])
		u.render()
		return true
	case 'q', 3:
		return false
	default:
		return true
	}

	_ = proto.WriteFrame(u.conn, proto.Decision{
		Type:     proto.TypeDecision,
		ID:       p.ID,
		Decision: decision,
	})
	u.queue = u.queue[1:]
	u.render()
	return true
}

func formatArgv(argv []string) string {
	if len(argv) == 0 {
		return ""
	}
	var b strings.Builder
	for i, a := range argv {
		if i > 0 {
			b.WriteByte(' ')
		}
		if strings.Contains(a, " ") || strings.Contains(a, "'") || strings.Contains(a, "\"") {
			b.WriteByte('"')
			b.WriteString(a)
			b.WriteByte('"')
		} else {
			b.WriteString(a)
		}
	}
	return b.String()
}

func lineLoop(conn net.Conn, allowRememberFlagged bool) {
	for {
		raw, err := proto.ReadFrame(conn)
		if err != nil {
			fmt.Fprintln(os.Stderr, "approve: disconnected:", err)
			return
		}
		msg, err := proto.DecodeMessage(raw)
		if err != nil {
			fmt.Fprintln(os.Stderr, "approve: decode:", err)
			continue
		}
		switch m := msg.(type) {
		case *proto.Pending:
			handlePendingLine(conn, m, allowRememberFlagged)
		case *proto.ListReply:
			printRules(m)
		case *proto.Ack:
		case *proto.Error:
			fmt.Fprintln(os.Stderr, "approve:", m.Message)
		default:
			fmt.Fprintf(os.Stderr, "approve: unexpected frame %T\n", m)
		}
	}
}

func handlePendingLine(conn net.Conn, p *proto.Pending, allowRememberFlagged bool) {
	fmt.Println()
	fmt.Printf("── %s ──────────────────────────────────\n", p.ID)
	fmt.Printf("requester: %s\n", p.Requester)
	if p.RequesterHint != "" && p.RequesterHint != p.Requester {
		fmt.Printf("  (hint:   %s — mismatch)\n", p.RequesterHint)
	}
	fmt.Printf("cwd:       %s\n", p.Cwd)
	fmt.Printf("command:   %v\n", p.Argv)
	if p.MatchedRuleID != 0 {
		fmt.Printf("matched:   rule #%d → %s\n", p.MatchedRuleID, p.MatchedDecision)
	}
	for _, f := range p.Flags {
		fmt.Printf("  ⚠ %s — %s\n", f.Kind, f.Reason)
	}
	rememberDisabled := len(p.Flags) > 0 && !allowRememberFlagged
	if rememberDisabled {
		fmt.Println("[a] allow once  [d] deny  [D] deny+remember  [s] skip  [q] quit")
	} else {
		fmt.Println("[a] allow once  [A] allow+remember  [d] deny  [D] deny+remember  [s] skip  [q] quit")
	}
	fmt.Print("> ")

	var key string
	fmt.Scanln(&key)

	decision := ""
	switch key {
	case "a":
		decision = "allow_once"
	case "A":
		if rememberDisabled {
			fmt.Println("(remember disabled for flagged request; use --allow-remember-flagged to override)")
			return
		}
		decision = "allow_remember"
	case "d":
		decision = "deny_once"
	case "D":
		decision = "deny_remember"
	case "s":
		return
	case "q":
		os.Exit(0)
	default:
		fmt.Println("(unrecognized key)")
		return
	}

	_ = proto.WriteFrame(conn, proto.Decision{
		Type:     proto.TypeDecision,
		ID:       p.ID,
		Decision: decision,
	})
}

func printRules(r *proto.ListReply) {
	fmt.Println("rules:")
	for _, rule := range r.Rules {
		args := strings.Join(rule.Args, " ")
		fmt.Printf("  #%d  %s  %s %s  -> %s\n",
			rule.ID, rule.Requester, rule.Command, args, rule.Decision)
	}
}

func init() {
	_ = syscall.SIGHUP
}
