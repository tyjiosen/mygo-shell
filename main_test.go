package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/egoist/mygo/plugins/terminal"
	"github.com/egoist/mygo/ui"
	"golang.org/x/crypto/ssh"

	"github.com/tyjiosen/mygo-shell/internal/session"
	"github.com/tyjiosen/mygo-shell/internal/sshx"
)

// TestTerminalLibrary checks that libghostty-vt can be located and loaded,
// which is the prerequisite for every terminal feature.
func TestTerminalLibrary(t *testing.T) {
	if err := terminal.Load(); err != nil {
		t.Fatalf("load libghostty-vt: %v", err)
	}
	p, err := terminal.LibraryPath()
	if err != nil {
		t.Fatalf("library path: %v", err)
	}
	t.Log("libghostty-vt:", p)
	if themes := terminal.GhosttyThemes(); len(themes) == 0 {
		t.Error("no Ghostty themes available")
	} else {
		t.Logf("ghostty themes: %d", len(themes))
	}
}

// TestRunsCommand runs a program in the terminal and reads back what it wrote,
// proving the emulator and the pseudo-terminal work end to end.
func TestRunsCommand(t *testing.T) {
	term, err := terminal.New(terminal.Options{
		Command: []string{"cmd", "/c", "echo hello-from-terminal"},
	})
	if err != nil {
		t.Fatalf("new terminal: %v", err)
	}
	defer term.Close()

	select {
	case <-term.Done():
	case <-time.After(20 * time.Second):
		t.Fatal("program did not exit")
	}
	time.Sleep(300 * time.Millisecond)

	text := term.Text()
	t.Logf("screen text: %q", text)
	if !strings.Contains(text, "hello-from-terminal") {
		t.Errorf("terminal output missing, got %q", text)
	}
	if code := term.ExitCode(); code != 0 {
		t.Errorf("exit code = %d, want 0", code)
	}
}

// serverConfig builds a connection from the test environment, skipping the
// test when no server is configured.
func serverConfig(t *testing.T, knownHosts string, policy sshx.HostKeyPolicy) sshx.Config {
	t.Helper()
	addr := os.Getenv("SHELL_SSH_ADDR")
	if addr == "" {
		t.Skip("SHELL_SSH_ADDR not set")
	}
	return sshx.Config{
		Addr:           addr,
		User:           os.Getenv("SHELL_SSH_USER"),
		Password:       os.Getenv("SHELL_SSH_PASSWORD"),
		KeyPath:        os.Getenv("SHELL_SSH_KEY"),
		KnownHostsPath: knownHosts,
		HostKeyPolicy:  policy,
	}
}

// TestHostKeyRecordsThenVerifies checks that a first connection records the
// host key, and that a later strict connection accepts the recorded one.
func TestHostKeyRecordsThenVerifies(t *testing.T) {
	knownHosts := filepath.Join(t.TempDir(), "known_hosts")

	cfg := serverConfig(t, knownHosts, sshx.HostKeyTrustOnFirstUse)
	conn, err := sshx.Dial(cfg)
	if err != nil {
		t.Fatalf("first dial with trust on first use: %v", err)
	}
	conn.Close()

	data, err := os.ReadFile(knownHosts)
	if err != nil {
		t.Fatalf("read known_hosts: %v", err)
	}
	if len(bytes.TrimSpace(data)) == 0 {
		t.Fatal("known_hosts is empty after the first connection")
	}
	t.Logf("recorded: %s", bytes.TrimSpace(data))

	strict := serverConfig(t, knownHosts, sshx.HostKeyStrict)
	conn2, err := sshx.Dial(strict)
	if err != nil {
		t.Fatalf("second dial with strict policy: %v", err)
	}
	conn2.Close()
}

// TestHostKeyStrictRefusesUnknown checks that strict mode refuses a server
// that is not recorded yet.
func TestHostKeyStrictRefusesUnknown(t *testing.T) {
	knownHosts := filepath.Join(t.TempDir(), "known_hosts")

	_, err := sshx.Dial(serverConfig(t, knownHosts, sshx.HostKeyStrict))
	if err == nil {
		t.Fatal("strict policy accepted an unknown host")
	}
	if !strings.Contains(err.Error(), "unknown host") {
		t.Errorf("error does not mention the unknown host: %v", err)
	}
	t.Logf("refused as expected: %v", err)
}

// TestSSHShell drives a remote shell through the terminal via Conn, which is
// the whole point of the project.
func TestSSHShell(t *testing.T) {
	knownHosts := filepath.Join(t.TempDir(), "known_hosts")
	cfg := serverConfig(t, knownHosts, sshx.HostKeyTrustOnFirstUse)

	conn, err := sshx.Dial(cfg)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	term, err := terminal.New(terminal.Options{Conn: conn, ResizeByConn: true})
	if err != nil {
		t.Fatalf("new terminal: %v", err)
	}
	defer term.Close()

	// Give the login shell a moment to print its prompt.
	time.Sleep(3 * time.Second)

	const marker = "MYGO_SSH_OK"
	term.Send([]byte("echo " + marker + "\n"))

	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(term.Text(), marker) {
			break
		}
		time.Sleep(300 * time.Millisecond)
	}

	text := term.Text()
	t.Logf("screen text:\n%s", text)
	if !strings.Contains(text, marker) {
		t.Errorf("marker %q not on screen; screen was:\n%s", marker, text)
	}
}

// TestKeyAuthentication installs a throwaway public key using the password,
// then connects with only that key, proving key authentication works alone.
func TestKeyAuthentication(t *testing.T) {
	addr := os.Getenv("SHELL_SSH_ADDR")
	if addr == "" {
		t.Skip("SHELL_SSH_ADDR not set")
	}
	user := os.Getenv("SHELL_SSH_USER")
	password := os.Getenv("SHELL_SSH_PASSWORD")
	if password == "" {
		t.Skip("SHELL_SSH_PASSWORD not set, cannot install the test key")
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("public key: %v", err)
	}
	authorized := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub)))

	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPath := filepath.Join(t.TempDir(), "id_ed25519")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	dialPassword := func() (*ssh.Client, error) {
		return ssh.Dial("tcp", hostPort(addr), &ssh.ClientConfig{
			User:            user,
			Auth:            []ssh.AuthMethod{ssh.Password(password)},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			Timeout:         15 * time.Second,
		})
	}

	client, err := dialPassword()
	if err != nil {
		t.Fatalf("password dial: %v", err)
	}
	sess, err := client.NewSession()
	if err != nil {
		client.Close()
		t.Fatalf("session: %v", err)
	}
	install := fmt.Sprintf(
		"mkdir -p ~/.ssh && chmod 700 ~/.ssh && touch ~/.ssh/authorized_keys && "+
			"(grep -qxF '%s' ~/.ssh/authorized_keys || echo '%s' >> ~/.ssh/authorized_keys) && "+
			"chmod 600 ~/.ssh/authorized_keys",
		authorized, authorized)
	if out, err := sess.CombinedOutput(install); err != nil {
		t.Fatalf("install key: %v: %s", err, out)
	}
	sess.Close()
	client.Close()

	t.Cleanup(func() {
		c, err := dialPassword()
		if err != nil {
			return
		}
		defer c.Close()
		s, err := c.NewSession()
		if err != nil {
			return
		}
		defer s.Close()
		// "|" as the separator keeps the base64 key from being read as a regex.
		s.Run(fmt.Sprintf(`sed -i '\|%s|d' ~/.ssh/authorized_keys`, authorized))
	})

	knownHosts := filepath.Join(t.TempDir(), "known_hosts")
	conn, err := sshx.Dial(sshx.Config{
		Addr:           addr,
		User:           user,
		KeyPath:        keyPath,
		KnownHostsPath: knownHosts,
		HostKeyPolicy:  sshx.HostKeyTrustOnFirstUse,
	})
	if err != nil {
		t.Fatalf("key dial: %v", err)
	}
	defer conn.Close()
	t.Logf("connected to %s using only the generated key", conn.Host())
}

// TestServerType checks that the identification line of a server reads the way
// the connection dialogs show it.
func TestServerType(t *testing.T) {
	cases := map[string]string{
		"SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u5": "SSH2, OpenSSH_8.4p1 Debian-5+deb11u5",
		"SSH-1.99-OpenSSH_3.9p1":                 "SSH2, OpenSSH_3.9p1",
		"SSH-1.5-old":                            "SSH1, old",
		"":                                       "",
	}
	for banner, want := range cases {
		if got := sshx.ServerType(banner); got != want {
			t.Errorf("ServerType(%q) = %q, want %q", banner, got, want)
		}
	}
}

// TestBanner reads the identification line the server sends before the
// handshake, which names it before any credentials are given.
func TestBanner(t *testing.T) {
	addr := os.Getenv("SHELL_SSH_ADDR")
	if addr == "" {
		t.Skip("SHELL_SSH_ADDR not set")
	}
	banner, err := sshx.Banner(addr, 5*time.Second)
	if err != nil {
		t.Fatalf("banner: %v", err)
	}
	if !strings.HasPrefix(banner, "SSH-") {
		t.Errorf("banner = %q, want an identification line", banner)
	}
	t.Logf("banner: %s (%s)", banner, sshx.ServerType(banner))
}

// TestCredentialDialogs checks that the dialogs of a connection build and
// that choosing the public key shows the key it asks for, as Xshell's do.
func TestCredentialDialogs(t *testing.T) {
	a := &app{active: -1}
	a.resetForm()
	a.flow = connectFlow{
		step:   stepUser,
		name:   "wangzha test",
		host:   "120.78.228.198",
		port:   "17878",
		banner: "SSH2, OpenSSH_8.4p1 Debian-5+deb11u5",
		auth:   session.AuthPassword,
	}

	tester := ui.NewTester(a.view, 900, 600)
	if !tester.HasText("SSH 用户名") {
		t.Fatal("the login name dialog is not on screen")
	}
	if !tester.HasText("120.78.228.198:17878 (wangzha test)") {
		t.Error("the dialog does not name the server")
	}
	if !tester.HasText("服务器类型:") || !tester.HasText("SSH2, OpenSSH_8.4p1 Debian-5+deb11u5") {
		t.Error("the dialog does not name the server type")
	}

	// The dialog that follows takes the login name the first one asked for.
	a.flow.user = "root"
	a.flow.step = stepAuth
	tester.Frame()

	if !tester.HasText("SSH 用户身份验证") {
		t.Fatal("the authentication dialog is not on screen")
	}
	if !tester.HasText("登录名:") {
		t.Error("the authentication dialog does not name the login")
	}
	if !tester.HasText("密码(W)") {
		t.Error("the password is not asked for by default")
	}

	if err := tester.Click("公钥(U)"); err != nil {
		t.Fatalf("choose the public key: %v", err)
	}
	if a.flow.auth != session.AuthKey {
		t.Errorf("auth = %q after choosing the public key, want %q", a.flow.auth, session.AuthKey)
	}
	if !tester.HasText("用户密钥(K)") {
		t.Error("the key is not offered after choosing the public key")
	}
	if tester.HasText("密码(W)") {
		t.Error("the password field stayed after choosing the public key")
	}
}

// TestSessionMenu checks that a right click on a session offers the actions
// Xshell shows, and that 属性 opens the pane with the session's properties.
func TestSessionMenu(t *testing.T) {
	a := &app{active: -1}
	a.resetForm()
	a.sessions = []session.Session{{
		ID:       "one",
		Name:     "星炎",
		Protocol: session.ProtocolSSH,
		Host:     "10.0.0.1",
		Port:     22,
		User:     "root",
	}}
	a.selected = "one"

	tester := ui.NewTester(a.view, 900, 600)
	if err := tester.RightClick("星炎"); err != nil {
		t.Fatalf("right click on the session: %v", err)
	}

	menu := tester.Menu()
	t.Logf("menu: %v", menu)
	for _, want := range []string{"打开(O)", "编辑(E)", "删除(D)", "属性(I)"} {
		if !slices.Contains(menu, want) {
			t.Errorf("the menu has no %q", want)
		}
	}

	if err := tester.Click("属性(I)"); err != nil {
		t.Fatalf("choose 属性: %v", err)
	}
	if !a.showProps {
		t.Error("属性 did not show the properties pane")
	}
	if !tester.HasText("10.0.0.1") {
		t.Error("the properties pane does not show the host of the session")
	}
}

// TestTabOpensWhileConnecting checks that a tab shows up before its connection
// does, and turns into the terminal once the connection is there.
func TestTabOpensWhileConnecting(t *testing.T) {
	srv := startTestSSH(t)
	a := &app{active: -1, dials: make(chan dialResult, 4)}
	a.resetForm()

	cfg := sshx.Config{
		Addr:           srv.addr,
		User:           "tester",
		Password:       "secret",
		KnownHostsPath: filepath.Join(t.TempDir(), "known_hosts"),
		HostKeyPolicy:  sshx.HostKeyTrustOnFirstUse,
	}

	start := time.Now()
	item := a.openConnection(cfg, session.Session{ID: "one", Name: "本地测试"}, "本地测试")
	if took := time.Since(start); took > time.Second {
		t.Errorf("opening the tab took %s, it should not wait for the connection", took)
	}
	if len(a.tabs) != 1 || a.tabs[0] != item {
		t.Fatal("the tab did not open at once")
	}
	if !item.connecting || item.term != nil {
		t.Error("the tab does not say that it is connecting")
	}

	tester := ui.NewTester(a.view, 900, 600)
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		tester.Frame()
		if item.term != nil {
			t.Cleanup(func() { item.term.Close() })
			if item.connecting || item.errMsg != "" {
				t.Errorf("the tab connected but still says %q", item.errMsg)
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("the tab never connected: %q", item.errMsg)
}

// TestTerminalFitsItsTab checks that the screen of a connected tab takes the
// room of the tab, which the server is told as the size of its pty.
func TestTerminalFitsItsTab(t *testing.T) {
	srv := startTestSSH(t)
	a := &app{active: -1, dials: make(chan dialResult, 4)}
	a.resetForm()

	cfg := sshx.Config{
		Addr:           srv.addr,
		User:           "tester",
		Password:       "secret",
		KnownHostsPath: filepath.Join(t.TempDir(), "known_hosts"),
		HostKeyPolicy:  sshx.HostKeyTrustOnFirstUse,
	}
	item := a.openConnection(cfg, session.Session{ID: "one", Name: "尺寸"}, "尺寸")
	t.Cleanup(func() {
		if item.term != nil {
			item.term.Close()
		}
	})

	tester := ui.NewTester(a.view, 1000, 600)
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		tester.Frame()
		if size, ok := srv.size(); ok && size[0] > 80 {
			t.Logf("the server was told %d columns and %d rows", size[0], size[1])
			return
		}
		time.Sleep(20 * time.Millisecond)
	}

	size, ok := srv.size()
	t.Fatalf("the server was told %v (asked at all: %v), the tab fits more than 80 columns", size, ok)
}

// TestFailedConnectionShowsInTheTab checks that a connection that does not come
// up says why in its own tab, and marks itself in the bar.
func TestFailedConnectionShowsInTheTab(t *testing.T) {
	// A port nothing listens on: the connection is refused at once.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := listener.Addr().String()
	listener.Close()

	a := &app{active: -1, dials: make(chan dialResult, 4)}
	a.resetForm()
	item := a.openConnection(sshx.Config{Addr: addr, User: "tester", Password: "secret"},
		session.Session{ID: "one", Name: "断线测试"}, "断线测试")

	tester := ui.NewTester(a.view, 900, 600)
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) && item.errMsg == "" {
		tester.Frame()
		time.Sleep(20 * time.Millisecond)
	}

	if item.errMsg == "" {
		t.Fatal("the tab does not say why the connection failed")
	}
	if item.term != nil {
		t.Error("the tab has a terminal after a failed connection")
	}
	if !item.down.Load() {
		t.Error("the tab is not marked down")
	}
	if !tester.HasText("连接失败") {
		t.Errorf("the tab does not show the failure: %v", tester.Texts())
	}
}

// TestDialogDoesNotWaitForTheServer checks that the dialogs open at once, and
// that the server type fills in as the server answers.
func TestDialogDoesNotWaitForTheServer(t *testing.T) {
	srv := startTestSSH(t)
	host, port, err := net.SplitHostPort(srv.addr)
	if err != nil {
		t.Fatalf("split %s: %v", srv.addr, err)
	}
	number, err := strconv.Atoi(port)
	if err != nil {
		t.Fatalf("port %q: %v", port, err)
	}

	a := &app{active: -1, probes: make(chan probeResult, 4)}
	a.resetForm()

	item := session.Session{
		ID:       "one",
		Name:     "本地测试",
		Protocol: session.ProtocolSSH,
		Host:     host,
		Port:     number,
	}
	start := time.Now()
	a.startConnect(item)
	if took := time.Since(start); took > time.Second {
		t.Errorf("the dialogs took %s to open, they should not wait for the server", took)
	}

	tester := ui.NewTester(a.view, 900, 600)
	if !tester.HasText("SSH 用户名") {
		t.Fatal("the login name dialog is not on screen")
	}

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if tester.HasText("SSH2, Go") {
			return
		}
		time.Sleep(20 * time.Millisecond)
		tester.Frame()
	}
	t.Fatalf("the server type never filled in: %v", tester.Texts())
}

// TestNeedsTyping checks that the failures the credential dialogs can fix are
// recognised, while the others show as they are.
func TestNeedsTyping(t *testing.T) {
	// The error a session without credentials gives, which the dialog fixes.
	_, err := sshx.Dial(sshx.Config{Addr: "127.0.0.1:1", User: "root"})
	if err == nil || !needsTyping(err) {
		t.Errorf("a dial without credentials reports %v, which should ask again", err)
	}

	if needsTyping(fmt.Errorf("sshx: dial 10.0.0.1:22: connection refused")) {
		t.Error("a refused connection asks for credentials again")
	}
	if needsTyping(nil) {
		t.Error("no error asks for credentials")
	}
}

// TestNeedsCredentials checks which saved sessions ask for the dialogs before
// connecting.
func TestNeedsCredentials(t *testing.T) {
	a := &app{}

	cases := []struct {
		name  string
		item  session.Session
		needs bool
	}{
		{
			name:  "no login name",
			item:  session.Session{Host: "10.0.0.1", AuthMethod: session.AuthPassword},
			needs: true,
		},
		{
			name:  "key without a key file",
			item:  session.Session{Host: "10.0.0.1", User: "root", AuthMethod: session.AuthKey},
			needs: true,
		},
		{
			name: "key with a key file",
			item: session.Session{
				Host: "10.0.0.1", User: "root",
				AuthMethod: session.AuthKey, KeyPath: `C:\Users\you\.ssh\id_ed25519`,
			},
			needs: false,
		},
		{
			name:  "agent",
			item:  session.Session{Host: "10.0.0.1", User: "root", AuthMethod: session.AuthAgent},
			needs: false,
		},
		{
			// The store of the test is missing, so the password is unknown.
			name:  "password",
			item:  session.Session{Host: "10.0.0.1", User: "root", AuthMethod: session.AuthPassword},
			needs: true,
		},
	}

	for _, c := range cases {
		if got := a.needsCredentials(c.item); got != c.needs {
			t.Errorf("%s: needsCredentials = %v, want %v", c.name, got, c.needs)
		}
	}
}

// TestPlusButton checks that the add button of the session list is there and
// opens the dialog that adds a session.
func TestPlusButton(t *testing.T) {
	a := &app{active: -1, showProps: true}
	a.resetForm()

	tester := ui.NewTester(a.view, 900, 600)
	if err := tester.Click("新建会话"); err != nil {
		t.Fatalf("click the plus of the session list: %v", err)
	}
	if !a.showForm {
		t.Error("the plus did not open the new session dialog")
	}
	if !tester.HasText("主机") {
		t.Error("the new session dialog is not on screen")
	}
}

// TestTabTurnsDownWhenItsSessionEnds checks that the watcher marks the tab of
// a terminal that ended, which the tab bar draws in red.
func TestTabTurnsDownWhenItsSessionEnds(t *testing.T) {
	term, err := terminal.New(terminal.Options{
		Command: []string{"cmd", "/c", "echo bye"},
	})
	if err != nil {
		t.Fatalf("new terminal: %v", err)
	}
	t.Cleanup(func() { term.Close() })

	a := &app{active: -1}
	item := &tab{title: "test", term: term, local: true}
	a.watchSession(item)
	t.Cleanup(item.stop)

	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if item.down.Load() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("the tab stayed up after its terminal ended")
}

// testSSH is an SSH server in the test process, which answers what a session
// asks and lets the test cut the connection under a client.
type testSSH struct {
	addr string

	mu    sync.Mutex
	conns []net.Conn
	sizes [][2]int // the cols and rows the client last asked for
}

// size returns the last size the client asked for, if it asked for one.
func (s *testSSH) size() ([2]int, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.sizes) == 0 {
		return [2]int{}, false
	}
	return s.sizes[len(s.sizes)-1], true
}

// startTestSSH starts the server, which accepts the password "secret".
func startTestSSH(t *testing.T) *testSSH {
	t.Helper()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate host key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("host key: %v", err)
	}

	config := &ssh.ServerConfig{
		PasswordCallback: func(_ ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			if string(password) == "secret" {
				return nil, nil
			}
			return nil, fmt.Errorf("wrong password")
		},
	}
	config.AddHostKey(signer)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	srv := &testSSH{addr: listener.Addr().String()}
	t.Cleanup(func() {
		listener.Close()
		srv.cut()
	})

	go func() {
		for {
			nc, err := listener.Accept()
			if err != nil {
				return
			}
			srv.mu.Lock()
			srv.conns = append(srv.conns, nc)
			srv.mu.Unlock()
			go srv.serve(nc, config)
		}
	}()

	return srv
}

// serve answers one connection: the pty and shell of its session, and the
// keepalive request the tab bar sends.
func (s *testSSH) serve(nc net.Conn, config *ssh.ServerConfig) {
	conn, chans, reqs, err := ssh.NewServerConn(nc, config)
	if err != nil {
		return
	}
	defer conn.Close()

	go func() {
		for req := range reqs {
			if req.WantReply {
				req.Reply(true, nil)
			}
		}
	}()

	for newCh := range chans {
		if newCh.ChannelType() != "session" {
			newCh.Reject(ssh.UnknownChannelType, "only sessions")
			continue
		}
		ch, requests, err := newCh.Accept()
		if err != nil {
			continue
		}
		go func() {
			defer ch.Close()
			for req := range requests {
				if req.Type == "window-change" && len(req.Payload) >= 8 {
					cols := binary.BigEndian.Uint32(req.Payload[:4])
					rows := binary.BigEndian.Uint32(req.Payload[4:8])
					s.mu.Lock()
					s.sizes = append(s.sizes, [2]int{int(cols), int(rows)})
					s.mu.Unlock()
				}
				if req.WantReply {
					req.Reply(true, nil)
				}
			}
		}()
	}
}

// cut closes every connection of the server, as a network that goes away does.
func (s *testSSH) cut() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, nc := range s.conns {
		nc.Close()
	}
	s.conns = nil
}

// TestKeepAliveDetectsADeadConnection checks that the keepalive reports a
// session that stopped answering, which is what turns its tab red.
func TestKeepAliveDetectsADeadConnection(t *testing.T) {
	srv := startTestSSH(t)

	banner, err := sshx.Banner(srv.addr, 5*time.Second)
	if err != nil {
		t.Fatalf("banner: %v", err)
	}
	t.Logf("banner: %s (%s)", banner, sshx.ServerType(banner))

	conn, err := sshx.Dial(sshx.Config{
		Addr:           srv.addr,
		User:           "tester",
		Password:       "secret",
		KnownHostsPath: filepath.Join(t.TempDir(), "known_hosts"),
		HostKeyPolicy:  sshx.HostKeyTrustOnFirstUse,
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	if err := conn.KeepAlive(5 * time.Second); err != nil {
		t.Fatalf("keepalive on a live session: %v", err)
	}

	srv.cut()

	deadline := time.Now().Add(10 * time.Second)
	for {
		if err := conn.KeepAlive(2 * time.Second); err != nil {
			t.Logf("the dead connection reported: %v", err)
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("the keepalive did not notice the connection was cut")
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// hostPort appends the default SSH port when the address has none.
func hostPort(addr string) string {
	if strings.Contains(addr, ":") {
		return addr
	}
	return addr + ":22"
}

// TestSessionStore checks that sessions round-trip through SQLite, that the
// password never leaks into listings, and that a save without a password
// keeps the stored one.
func TestSessionStore(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()

	store, err := session.Open(ctx, filepath.Join(dir, "sessions.db"), filepath.Join(dir, "master.key"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	item := session.Session{
		Name:       "test box",
		Protocol:   session.ProtocolSSH,
		Host:       "47.115.175.104",
		Port:       22,
		User:       "root",
		AuthMethod: session.AuthPassword,
		Password:   "s3cret-value",
	}
	if err := store.Save(ctx, &item); err != nil {
		t.Fatalf("save: %v", err)
	}

	list, err := store.List(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("got %d sessions, want 1", len(list))
	}
	if list[0].Password != "" {
		t.Error("password leaked into List")
	}
	if !list[0].HasPassword {
		t.Error("HasPassword is false after saving a password")
	}

	password, err := store.Password(ctx, item.ID)
	if err != nil {
		t.Fatalf("password: %v", err)
	}
	if password != "s3cret-value" {
		t.Errorf("password = %q, want the saved one", password)
	}

	// Saving without a password must not erase the stored one.
	if err := store.Save(ctx, &session.Session{ID: item.ID, Name: "renamed"}); err != nil {
		t.Fatalf("save without password: %v", err)
	}
	password, err = store.Password(ctx, item.ID)
	if err != nil {
		t.Fatalf("password after update: %v", err)
	}
	if password != "s3cret-value" {
		t.Errorf("password was wiped by a save without one: %q", password)
	}

	renamed, err := store.Get(ctx, item.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if renamed.Name != "renamed" {
		t.Errorf("name = %q after update", renamed.Name)
	}

	if err := store.Delete(ctx, item.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	list, err = store.List(ctx)
	if err != nil {
		t.Fatalf("list after delete: %v", err)
	}
	if len(list) != 0 {
		t.Errorf("got %d sessions after delete, want 0", len(list))
	}
}
