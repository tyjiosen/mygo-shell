// Package sshx connects a terminal view to a remote SSH shell.
//
// Conn implements io.ReadWriteCloser plus Resize, which is what
// terminal.Options.Conn asks for: bytes read show on screen, bytes written
// go to the remote program, and the view tells the remote PTY its size.
package sshx

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// Config describes how to reach the server.
//
// Authentication takes whichever methods are set, in the order key, agent,
// password: a key is tried before a password when both are configured.
type Config struct {
	Addr string // host or host:port, port 22 when omitted
	User string

	// Password is used as both the password and the answer to
	// keyboard-interactive prompts, which many servers use for 2FA.
	Password string
	// KeyboardInteractive answers a server that asks through
	// keyboard-interactive: the name and instruction of the round, the
	// questions, and whether each echoes (false for a password or a code).
	// It may be asked more than once, as a password and then a one-time code;
	// answers are taken as a list of the same length. It replaces the default
	// answer of Password.
	KeyboardInteractive func(name, instruction string, questions []string, echos []bool) ([]string, error)
	// KeyPath is a PEM or OpenSSH private key file.
	KeyPath       string
	KeyPassphrase string
	// UseAgent offers the keys of a running ssh-agent.
	UseAgent bool

	Timeout  time.Duration
	TermType string

	// KnownHostsPath defaults to ~/.ssh/known_hosts.
	KnownHostsPath string
	HostKeyPolicy  HostKeyPolicy
	// OnUnknownHost decides about servers that are not recorded yet and
	// receives the host and its SHA256 fingerprint. Return true to record
	// and trust it. When nil, HostKeyPolicy decides.
	OnUnknownHost func(host, fingerprint string) bool
}

// Conn is a remote shell session used as a terminal Conn.
type Conn struct {
	client  *ssh.Client
	session *ssh.Session
	stdin   io.WriteCloser
	stdout  io.Reader

	host string
}

// Dial authenticates, verifies the host key, requests a PTY and starts an
// interactive shell.
func Dial(cfg Config) (*Conn, error) {
	if cfg.Addr == "" {
		return nil, errors.New("sshx: address is required")
	}
	if cfg.User == "" {
		return nil, errors.New("sshx: user is required")
	}
	addr := cfg.Addr
	if !strings.Contains(addr, ":") {
		addr += ":22"
	}
	if cfg.TermType == "" {
		cfg.TermType = "xterm-256color"
	}
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 15 * time.Second
	}

	auth, err := authMethods(cfg)
	if err != nil {
		return nil, err
	}

	checkHost, err := hostKeyCallback(cfg.KnownHostsPath, cfg.HostKeyPolicy, cfg.OnUnknownHost)
	if err != nil {
		return nil, err
	}

	client, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            cfg.User,
		Auth:            auth,
		HostKeyCallback: checkHost,
		Timeout:         timeout,
	})
	if err != nil {
		return nil, fmt.Errorf("sshx: dial %s: %w", addr, err)
	}

	session, err := client.NewSession()
	if err != nil {
		client.Close()
		return nil, fmt.Errorf("sshx: session on %s: %w", addr, err)
	}

	modes := ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}
	if err := session.RequestPty(cfg.TermType, 24, 80, modes); err != nil {
		session.Close()
		client.Close()
		return nil, fmt.Errorf("sshx: request pty: %w", err)
	}

	stdin, err := session.StdinPipe()
	if err != nil {
		session.Close()
		client.Close()
		return nil, fmt.Errorf("sshx: stdin pipe: %w", err)
	}

	stdout, err := session.StdoutPipe()
	if err != nil {
		session.Close()
		client.Close()
		return nil, fmt.Errorf("sshx: stdout pipe: %w", err)
	}

	if err := session.Shell(); err != nil {
		session.Close()
		client.Close()
		return nil, fmt.Errorf("sshx: start shell: %w", err)
	}

	return &Conn{
		client:  client,
		session: session,
		stdin:   stdin,
		stdout:  stdout,
		host:    addr,
	}, nil
}

// Host returns the address the connection was made to.
func (c *Conn) Host() string { return c.host }

// Read shows the remote program's output.
func (c *Conn) Read(p []byte) (int, error) {
	return c.stdout.Read(p)
}

// Write sends keystrokes and pastes to the remote program.
func (c *Conn) Write(p []byte) (int, error) {
	return c.stdin.Write(p)
}

// Resize tells the remote PTY the size of the view, in cells.
func (c *Conn) Resize(cols, rows int) error {
	return c.session.WindowChange(rows, cols)
}

// Close ends the session and the connection.
func (c *Conn) Close() error {
	err := c.session.Close()
	if cerr := c.client.Close(); err == nil {
		err = cerr
	}
	return err
}

// KeepAlive asks the server to answer, which reports a connection that went
// silent as broken before the terminal reads notice it. A server that does not
// know the request still answers, if it answers at all.
func (c *Conn) KeepAlive(timeout time.Duration) error {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	// The request itself blocks on a connection that stopped answering, so the
	// wait for its answer runs beside it.
	done := make(chan error, 1)
	go func() {
		_, _, err := c.client.SendRequest("keepalive@openssh.com", true, nil)
		done <- err
	}()

	select {
	case err := <-done:
		if err != nil {
			return fmt.Errorf("sshx: keepalive %s: %w", c.host, err)
		}
		return nil
	case <-time.After(timeout):
		return fmt.Errorf("sshx: keepalive %s: no answer in %s", c.host, timeout)
	}
}

// authMethods collects the configured authentication methods.
func authMethods(cfg Config) ([]ssh.AuthMethod, error) {
	var methods []ssh.AuthMethod

	if cfg.KeyPath != "" {
		signer, err := loadSigner(cfg.KeyPath, cfg.KeyPassphrase)
		if err != nil {
			return nil, err
		}
		methods = append(methods, ssh.PublicKeys(signer))
	}

	if cfg.UseAgent {
		// An absent agent is not an error: it only adds another way in.
		if m, err := agentAuth(); err == nil {
			methods = append(methods, m)
		}
	}

	if cfg.KeyboardInteractive != nil {
		methods = append(methods, ssh.KeyboardInteractive(cfg.KeyboardInteractive))
	}

	if cfg.Password != "" {
		methods = append(methods, ssh.Password(cfg.Password))
		if cfg.KeyboardInteractive == nil {
			// Servers often ask for the password through keyboard-interactive,
			// which is also how one-time codes are requested.
			methods = append(methods, ssh.KeyboardInteractive(
				func(name, instruction string, questions []string, echos []bool) ([]string, error) {
					answers := make([]string, len(questions))
					for i := range answers {
						answers[i] = cfg.Password
					}
					return answers, nil
				}))
		}
	}

	if len(methods) == 0 {
		return nil, errors.New("sshx: no authentication method: set a password, a key, an agent, or a keyboard-interactive answer")
	}
	return methods, nil
}

// loadSigner reads a private key, decrypting it when a passphrase is given.
func loadSigner(path, passphrase string) (ssh.Signer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("sshx: read key %s: %w", path, err)
	}

	if passphrase != "" {
		if signer, err := ssh.ParsePrivateKeyWithPassphrase(data, []byte(passphrase)); err == nil {
			return signer, nil
		}
		// Fall through: the key may be stored without a passphrase.
	}
	signer, err := ssh.ParsePrivateKey(data)
	if err != nil {
		return nil, fmt.Errorf("sshx: parse key %s: %w", path, err)
	}
	return signer, nil
}

// agentAuth offers the keys of ssh-agent over SSH_AUTH_SOCK.
func agentAuth() (ssh.AuthMethod, error) {
	sock := os.Getenv("SSH_AUTH_SOCK")
	if sock == "" {
		return nil, errors.New("sshx: SSH_AUTH_SOCK is not set")
	}
	conn, err := net.Dial("unix", sock)
	if err != nil {
		return nil, fmt.Errorf("sshx: dial agent: %w", err)
	}
	return ssh.PublicKeysCallback(agent.NewClient(conn).Signers), nil
}
