package identity

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"

	"golang.org/x/sys/unix"
)

type Peer struct {
	UID int
	GID int
	PID int
}

// PeerCred returns the uid/gid/pid of the peer connected on conn.
// Requires conn to be a *net.UnixConn.
func PeerCred(conn net.Conn) (Peer, error) {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return Peer{}, fmt.Errorf("identity: not a Unix conn: %T", conn)
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return Peer{}, fmt.Errorf("identity: syscall conn: %w", err)
	}
	var ucred *unix.Ucred
	err = raw.Control(func(fd uintptr) {
		ucred, err = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	})
	if err != nil {
		return Peer{}, fmt.Errorf("identity: control: %w", err)
	}
	if ucred == nil {
		return Peer{}, fmt.Errorf("identity: SO_PEERCRED returned nil")
	}
	return Peer{
		UID: int(ucred.Uid),
		GID: int(ucred.Gid),
		PID: int(ucred.Pid),
	}, nil
}

var (
	reDockerCgroup  = regexp.MustCompile(`/docker[/-]([0-9a-f]{6,64})`)
	rePodmanCgroup  = regexp.MustCompile(`/libpod-([0-9a-f]{6,64})\.scope`)
	reLXCCgroup     = regexp.MustCompile(`/lxc/([^/]+)`)
	reSystemdDocker = regexp.MustCompile(`docker-([0-9a-f]{6,64})\.scope`)
)

// Container inspects /proc/<pid>/cgroup and returns a short identifier
// for the container runtime + instance, or ("host", true) if the process
// isn't running under a recognized runtime.
func Container(pid int) (string, bool) {
	f, err := os.Open(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return "", false
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.SplitN(line, ":", 3)
		if len(parts) < 3 {
			continue
		}
		path := parts[2]

		if m := reDockerCgroup.FindStringSubmatch(path); m != nil {
			cid := m[1]
			if len(cid) > 12 {
				cid = cid[:12]
			}
			return "docker:" + cid, true
		}
		if m := rePodmanCgroup.FindStringSubmatch(path); m != nil {
			cid := m[1]
			if len(cid) > 12 {
				cid = cid[:12]
			}
			return "podman:" + cid, true
		}
		if m := reLXCCgroup.FindStringSubmatch(path); m != nil {
			return "lxc:" + m[1], true
		}
		if m := reSystemdDocker.FindStringSubmatch(path); m != nil {
			cid := m[1]
			if len(cid) > 12 {
				cid = cid[:12]
			}
			return "docker:" + cid, true
		}
	}

	return "host", true
}

// Requester formats the full policy requester string for a Peer.
func Requester(p Peer) string {
	container, ok := Container(p.PID)
	if !ok || container == "" {
		container = "host"
	}
	return fmt.Sprintf("%s:%d", container, p.UID)
}
