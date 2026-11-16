package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/egoist/mygo/ui"

	"github.com/tyjiosen/mygo-shell/internal/session"
	"github.com/tyjiosen/mygo-shell/internal/sshx"
)

// probeTimeout is how long the dialogs wait for the server to name itself.
const probeTimeout = 5 * time.Second

// authKeyboard is the keyboard-interactive method, which the dialog lists as
// Xshell does, without driving it yet.
const authKeyboard = "keyboard"

// connStep is the stage of the credential dialogs, which ask the login name
// and then the way to authenticate, one after the other.
type connStep int

const (
	stepIdle connStep = iota
	stepUser
	stepAuth
)

// probeResult is what the goroutine asking a server to name itself reports,
// which the frame that draws the dialogs takes.
type probeResult struct {
	gen    int    // the connection it answers, which may be gone already
	banner string // the server type, when the server answered
	errMsg string // why it did not
}

// connectFlow holds the state of the dialogs that gather the credentials of
// one connection.
type connectFlow struct {
	step connStep
	// gen marks the connection the flow belongs to: the answers of the servers
	// of other ones are dropped.
	gen int

	saved string // the session the credentials belong to
	name  string // its name, shown beside the address
	host  string
	port  string
	// banner is the server type the dialogs show, as the server named itself.
	banner string

	user         string
	rememberUser bool

	auth           string   // session.AuthPassword or session.AuthKey
	keyPath        string   // the private key the dialog offers
	keys           []string // the private keys found in ~/.ssh
	secret         string   // the password, or the passphrase of the key
	rememberSecret bool

	errMsg string
}

// addr is where the flow connects, with the port filled in.
func (f connectFlow) addr() string {
	port := f.port
	if port == "" {
		port = "22"
	}
	return net.JoinHostPort(f.host, port)
}

// remote names the server as the dialogs show it: its address, then the name
// of the session.
func (f connectFlow) remote() string {
	if f.name != "" && f.name != f.host {
		return fmt.Sprintf("%s (%s)", f.addr(), f.name)
	}
	return f.addr()
}

// needsCredentials reports whether opening a session asks the dialogs, which
// it does while the login name or the secret it needs is not saved.
func (a *app) needsCredentials(item session.Session) bool {
	if item.User == "" {
		return true
	}
	switch item.AuthMethod {
	case session.AuthKey:
		// A key session with no key to offer has nothing to try.
		return item.KeyPath == ""
	case session.AuthAgent:
		return false
	}
	if a.store == nil {
		return true
	}
	secret, err := a.store.Password(context.Background(), item.ID)
	return err != nil || secret == ""
}

// authErrors are the ways the server says the credentials it was given do not
// get in, which the dialogs can ask for again.
var authErrors = []string{
	"unable to authenticate",
	"no authentication method",
	"no supported methods remain",
	"parse key",
	"read key",
}

// needsTyping reports whether an error is one the credential dialogs can fix,
// as a password the server no longer takes or a key that is not there.
func needsTyping(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	for _, want := range authErrors {
		if strings.Contains(msg, want) {
			return true
		}
	}
	return false
}

// startConnect begins the connection of a session: the server is probed for
// the type the dialogs show, then the login name and the way to authenticate
// are asked, as Xshell asks them.
func (a *app) startConnect(item session.Session) {
	port := item.Port
	if port == 0 {
		port = 22
	}
	f := connectFlow{
		saved:   item.ID,
		name:    item.Name,
		host:    item.Host,
		port:    strconv.Itoa(port),
		user:    item.User,
		auth:    item.AuthMethod,
		keyPath: item.KeyPath,
		// Remembering the name is the default, as Xshell has it.
		rememberUser: true,
		keys:         sshKeys(),
	}
	// The dialog offers a password and a key: a session that signed in with
	// an agent, or with nothing recorded, starts from the password.
	if f.auth != session.AuthKey {
		f.auth = session.AuthPassword
	}

	// A saved login name needs no dialog of its own: only the way to
	// authenticate it is asked.
	f.step = stepUser
	if f.user != "" {
		f.step = stepAuth
	}

	// A session added now has no login name yet: the dialog asks for it at
	// once, and the server names itself beside it as the answer comes.
	a.probeGen++
	f.gen = a.probeGen
	a.flow = f
	a.errMsg = ""
	a.askServer(f.addr(), f.gen)
	a.invalidate()
}

// askServer asks a server to name itself for the dialog that is already up,
// which fills the server type as the answer comes. No dialog waits on the
// network for it.
func (a *app) askServer(addr string, gen int) {
	if a.probes == nil {
		return
	}

	go func() {
		result := probeResult{gen: gen}
		if banner, err := sshx.Banner(addr, probeTimeout); err != nil {
			result.errMsg = err.Error()
		} else {
			result.banner = sshx.ServerType(banner)
		}

		// A full queue only means the view is behind: the next frame asks
		// again for nothing, so the stale answer is dropped rather than waited
		// for.
		select {
		case a.probes <- result:
		default:
		}
		a.invalidate()
	}()
}

// takeProbe applies the answer of the server the dialogs asked, if it came
// since the last frame.
func (a *app) takeProbe() {
	for {
		select {
		case result := <-a.probes:
			// An answer for a connection the dialogs left behind, or for
			// one they no longer show.
			if a.flow.step == stepIdle || result.gen != a.flow.gen {
				continue
			}
			a.flow.banner = result.banner
			a.flow.errMsg = result.errMsg
		default:
			return
		}
	}
}

// connectNow dials with what the dialogs gathered. A failure keeps them open
// with the reason, so the password can be typed again.
func (a *app) connectNow() {
	f := &a.flow
	if f.user == "" {
		f.errMsg = "请输入登录的用户名"
		a.invalidate()
		return
	}

	port, err := strconv.Atoi(f.port)
	if err != nil || port <= 0 {
		port = 22
	}
	cfg := sshx.Config{
		Addr:           net.JoinHostPort(f.host, strconv.Itoa(port)),
		User:           f.user,
		KnownHostsPath: os.Getenv("SHELL_SSH_KNOWN_HOSTS"),
		// TODO: ask the user about a fingerprint that is not recorded yet
		// instead of trusting it silently.
		HostKeyPolicy: sshx.HostKeyTrustOnFirstUse,
	}
	switch f.auth {
	case session.AuthKey:
		if f.keyPath == "" {
			f.errMsg = "请选择用户密钥"
			a.invalidate()
			return
		}
		cfg.KeyPath = f.keyPath
		cfg.KeyPassphrase = f.secret
	case session.AuthAgent:
		cfg.UseAgent = true
	default:
		cfg.Password = f.secret
	}

	item := a.saveFlow()

	title := item.Name
	if title == "" {
		title = item.Host
	}

	// The tab opens at once: the frame that takes the connection shows the
	// terminal in it, or says why it did not come up.
	a.flow = connectFlow{}
	a.openConnection(cfg, item, title)
}

// saveFlow stores what the dialogs gathered, so the next connection asks less,
// and reports the session the tab is opened for.
func (a *app) saveFlow() session.Session {
	f := &a.flow

	port, err := strconv.Atoi(f.port)
	if err != nil || port <= 0 {
		port = 22
	}
	item := session.Session{
		ID:         f.saved,
		Name:       f.name,
		Protocol:   session.ProtocolSSH,
		Host:       f.host,
		Port:       port,
		User:       f.user,
		AuthMethod: f.auth,
		KeyPath:    f.keyPath,
	}
	if item.Name == "" {
		item.Name = item.Host
	}

	if a.store == nil || f.saved == "" {
		return item
	}

	// What the boxes did not tick stays out of the store.
	stored := item
	if !f.rememberUser {
		stored.User = ""
	}
	if f.rememberSecret {
		stored.Password = f.secret
	}
	if err := a.store.Save(context.Background(), &stored); err != nil {
		a.errMsg = err.Error()
		return item
	}
	a.selected = stored.ID
	a.reloadSessions()
	return item
}

// sshKeys lists the private keys in the user's ~/.ssh, which the dialog offers
// to sign in with.
func sshKeys() []string {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	dir := filepath.Join(home, ".ssh")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}

	var keys []string
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || strings.HasSuffix(name, ".pub") {
			continue
		}
		path := filepath.Join(dir, name)
		if isPrivateKey(path) {
			keys = append(keys, path)
		}
	}
	return keys
}

// isPrivateKey reports whether a file starts like a private key.
func isPrivateKey(path string) bool {
	file, err := os.Open(path)
	if err != nil {
		return false
	}
	defer file.Close()

	head := make([]byte, 64)
	n, err := file.Read(head)
	if n == 0 && err != nil {
		return false
	}
	return strings.Contains(string(head[:n]), "PRIVATE KEY")
}

// connectDialogs draws the dialogs asking for the credentials of a connection.
func (a *app) connectDialogs(c *ui.Context, t *ui.Theme) {
	a.takeProbe()

	switch a.flow.step {
	case stepUser:
		a.userDialog(c, t)
	case stepAuth:
		a.authDialog(c, t)
	}
}

// connPanel draws one of the connection dialogs, titled and naming the server,
// with body for what it asks.
func (a *app) connPanel(c *ui.Context, t *ui.Theme, title string, body func()) {
	ui.Overlay(c, func() {
		ui.Column(c).Absolute().Left(280).Top(70).Width(440).
			Background(t.Background).Border(1, t.Border).Padding(16).Gap(10).
			Children(func() {
				ui.Text(c, title).Bold().FontSize(15)
				a.connFacts(c, t)
				body()
			})
	})
}

// connFacts names the server above the fields of a dialog.
func (a *app) connFacts(c *ui.Context, t *ui.Theme) {
	row := func(label, value string) {
		ui.Row(c).Gap(8).Children(func() {
			ui.Text(c, label).Width(76).FontSize(12).TextColor(t.TextMuted)
			ui.Text(c, value).FontSize(12).Bold()
		})
	}

	row("远程主机:", a.flow.remote())
	if a.flow.step == stepAuth && a.flow.user != "" {
		row("登录名:", a.flow.user)
	}
	switch {
	case a.flow.banner != "":
		row("服务器类型:", a.flow.banner)
	case a.flow.errMsg == "":
		// The server is still being asked: the dialog does not wait for it.
		row("服务器类型:", "探测中…")
	}

	ui.Column(c).Height(1).Background(t.Border)
}

// connCancel drops the dialogs without a connection, leaving the tab of a
// failed attempt as it is.
func (a *app) connCancel() {
	a.flow = connectFlow{}
	a.retry = nil
	a.invalidate()
}

// userDialog asks for the login name, as Xshell's SSH 用户名 dialog does.
func (a *app) userDialog(c *ui.Context, t *ui.Theme) {
	a.connPanel(c, t, "SSH 用户名", func() {
		ui.Text(c, "请输入登录的用户名(E):").FontSize(12)
		ui.TextInput(c, &a.flow.user).FillWidth()
		ui.Checkbox(c, &a.flow.rememberUser, "记住用户名(R)")

		a.connError(c, t)

		ui.Row(c).Gap(8).Children(func() {
			if ui.PrimaryButton(c, "确定").Width(90).Clicked() {
				a.confirmUser()
			}
			if ui.Button(c, "取消").Width(90).Clicked() {
				a.connCancel()
			}
		})
	})
}

// confirmUser takes the login name and goes on to the authentication.
func (a *app) confirmUser() {
	a.flow.user = strings.TrimSpace(a.flow.user)
	if a.flow.user == "" {
		a.flow.errMsg = "请输入登录的用户名"
		a.invalidate()
		return
	}

	a.flow.errMsg = ""
	a.saveFlow()
	a.flow.step = stepAuth
	a.invalidate()
}

// authDialog asks how to authenticate, as Xshell's SSH 用户身份验证 dialog does.
func (a *app) authDialog(c *ui.Context, t *ui.Theme) {
	// The key the session names stays chosen: one kept outside ~/.ssh joins
	// the keys the dialog found.
	if a.flow.auth == session.AuthKey && len(a.flow.keys) > 0 {
		switch {
		case a.flow.keyPath == "":
			a.flow.keyPath = a.flow.keys[0]
		case !slices.Contains(a.flow.keys, a.flow.keyPath):
			a.flow.keys = append([]string{a.flow.keyPath}, a.flow.keys...)
		}
	}

	a.connPanel(c, t, "SSH 用户身份验证", func() {
		ui.Text(c, "请在下面选择恰当的身份验证方法并提供登录所需的信息。").FontSize(12)

		ui.RadioGroup(c, func() {
			ui.Radio(c, &a.flow.auth, session.AuthPassword, "密码(P)")
			ui.Radio(c, &a.flow.auth, session.AuthKey, "公钥(U)")
			ui.Radio(c, &a.flow.auth, authKeyboard, "键盘交互(I)").Disabled(true)
		})

		switch a.flow.auth {
		case session.AuthKey:
			if len(a.flow.keys) > 0 {
				ui.Combobox(c, &a.flow.keyPath, a.flow.keys).Label("用户密钥(K)")
			} else {
				ui.TextInput(c, &a.flow.keyPath).
					Placeholder(`C:\Users\you\.ssh\id_ed25519`).Label("用户密钥(K)").FillWidth()
			}
			ui.TextInput(c, &a.flow.secret).Password().Label("密码(H)").FillWidth()
		case authKeyboard:
			ui.Text(c, "使用键盘输入用户身份验证。").FontSize(11).TextColor(t.TextMuted)
		default:
			ui.TextInput(c, &a.flow.secret).Password().Label("密码(W)").FillWidth()
		}

		ui.Checkbox(c, &a.flow.rememberSecret, "记住密码(R)")

		a.connError(c, t)

		ui.Row(c).Gap(8).Children(func() {
			if ui.PrimaryButton(c, "确定").Width(90).Clicked() {
				a.connectNow()
			}
			if ui.Button(c, "取消").Width(90).Clicked() {
				a.connCancel()
			}
		})
	})
}

// connError shows why the last attempt did not go through.
func (a *app) connError(c *ui.Context, t *ui.Theme) {
	if a.flow.errMsg != "" {
		ui.Text(c, a.flow.errMsg).TextColor(t.Danger).FontSize(12)
	}
}
