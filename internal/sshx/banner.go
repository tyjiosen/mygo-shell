package sshx

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// bannerTimeout is how long Banner waits for the server to name itself when
// the caller sets no timeout.
const bannerTimeout = 5 * time.Second

// Banner dials addr and reads the identification line the server sends before
// the handshake, as "SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u5". It names the
// server in the dialogs that ask for credentials, before any is given.
func Banner(addr string, timeout time.Duration) (string, error) {
	if addr == "" {
		return "", fmt.Errorf("sshx: address is required")
	}
	if !strings.Contains(addr, ":") {
		addr += ":22"
	}
	if timeout <= 0 {
		timeout = bannerTimeout
	}

	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return "", fmt.Errorf("sshx: dial %s: %w", addr, err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return "", fmt.Errorf("sshx: deadline on %s: %w", addr, err)
	}

	// The line is short; the limit keeps a server that never ends it from
	// filling memory.
	reader := bufio.NewReader(io.LimitReader(conn, 1<<12))
	for {
		line, err := reader.ReadString('\n')
		line = strings.TrimRight(line, "\r\n")
		if strings.HasPrefix(line, "SSH-") {
			return line, nil
		}
		if err != nil {
			if line == "" {
				return "", fmt.Errorf("sshx: read banner from %s: %w", addr, err)
			}
			return "", fmt.Errorf("sshx: no SSH banner from %s: %q", addr, line)
		}
	}
}

// ServerType names the server as the connection dialogs show it, as Xshell
// does: the protocol, then the software behind it.
func ServerType(banner string) string {
	for _, prefix := range []string{"SSH-2.0-", "SSH-1.99-"} {
		if rest, ok := strings.CutPrefix(banner, prefix); ok {
			return "SSH2, " + rest
		}
	}
	if rest, ok := strings.CutPrefix(banner, "SSH-1.5-"); ok {
		return "SSH1, " + rest
	}
	return banner
}
