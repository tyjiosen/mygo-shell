package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/egoist/mygo"
	"github.com/egoist/mygo/plugins/terminal"
	"github.com/egoist/mygo/ui"

	"github.com/tyjiosen/mygo-shell/internal/session"
	"github.com/tyjiosen/mygo-shell/internal/sshx"
)

// tab is one terminal in the tab bar, with the connection it reads from when
// it is not a local shell.
type tab struct {
	title string
	// term is nil until the connection of the tab comes up, and stays nil when
	// it does not: errMsg says why.
	term *terminal.Terminal
	conn io.Closer
	// session is the profile the tab was opened for, whose credentials are
	// asked for again when connecting with it failed.
	session session.Session
	// local marks the tab that runs the local shell, which a session picked
	// from the list replaces in place.
	local bool

	// connecting marks a tab whose connection is still coming up. It and
	// errMsg change on the frame that takes the result, so they are the UI's.
	connecting bool
	errMsg     string

	// down marks a session that ended or stopped answering, which the tab bar
	// shows in red until it answers again.
	down atomic.Bool
	// quit stops the goroutine watching the session.
	quit     chan struct{}
	quitOnce sync.Once
}

// dialResult is what the goroutine connecting a tab reports, which the frame
// that shows the tabs takes.
type dialResult struct {
	tab  *tab
	conn io.Closer
	term *terminal.Terminal
	err  error
}

// stop ends the goroutine that watches the session of the tab.
func (t *tab) stop() {
	if t.quit == nil {
		return
	}
	t.quitOnce.Do(func() { close(t.quit) })
}

// setDown sets whether the tab shows as disconnected, reporting a change.
func (t *tab) setDown(down bool) bool {
	return t.down.Swap(down) != down
}

// sessionForm holds the fields of the session dialog.
type sessionForm struct {
	name     string
	host     string
	port     string
	user     string
	password string
	keyPath  string
	auth     string
}

// app is the window state.
type app struct {
	tabs   []*tab
	active int
	win    *mygo.Window

	store    *session.Store
	sessions []session.Session
	selected string // the session shown in the properties pane
	// showProps shows the properties of the selection under the list, which
	// the session menu toggles.
	showProps bool

	showForm bool
	formID   string // empty while creating, set while editing
	form     sessionForm
	errMsg   string

	// flow holds the dialogs that ask for the credentials of a connection,
	// and probes the answers of the servers they ask to name themselves.
	flow     connectFlow
	probes   chan probeResult
	probeGen int

	// asks carries the keyboard-interactive questions the servers ask while
	// tabs connect: keyboard is the round on screen, askQueue the ones behind.
	asks     chan *keyboardAsk
	keyboard *keyboardAsk
	askQueue []*keyboardAsk

	// dials carries the connections the tabs are waiting for, and retry is the
	// tab a connection that failed for want of credentials takes over.
	dials chan dialResult
	retry *tab

	// focused is the tab whose terminal took the keys: a tab that comes to the
	// front takes them over, and a terminal that comes up takes them.
	focused *tab

	// Deleting asks first: the password of the session goes with it.
	pendingDelete     string
	pendingDeleteName string
	showDeleteConfirm bool

	// A second click on the same session within doubleClickWindow opens it;
	// a single click only shows its properties.
	lastClickID string
	lastClickAt time.Time
}

// doubleClickWindow is how close two clicks must be to open a session.
const doubleClickWindow = 450 * time.Millisecond

// connCheckInterval is how often the sessions behind the tabs are asked
// whether they still answer, and keepAliveTimeout how long one may take.
const (
	connCheckInterval = 5 * time.Second
	keepAliveTimeout  = 4 * time.Second
)

// pinger is a connection that tells whether it still answers, as the SSH
// connection does.
type pinger interface {
	KeepAlive(time.Duration) error
}

// sidebarWidth keeps the session list narrow, leaving the window to the
// terminal, which is where the work happens.
const sidebarWidth float32 = 160

// blackTheme is the terminal look of a classic SSH client: black background,
// light grey text, and the palette of a dark theme.
func blackTheme() *terminal.Theme {
	theme := terminal.DarkTheme()
	theme.Background = ui.RGB(0, 0, 0)
	theme.Foreground = ui.RGB(204, 204, 204)
	return theme
}

// Icons of the session list, drawn in the color of the text around them.
var (
	iconServer = ui.MustParseSVG([]byte(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16">` +
		`<rect x="2" y="2.4" width="12" height="4.6" rx="1" fill="none" stroke="currentColor" stroke-width="1.2"/>` +
		`<rect x="2" y="9" width="12" height="4.6" rx="1" fill="none" stroke="currentColor" stroke-width="1.2"/>` +
		`<circle cx="4.6" cy="4.7" r="0.8" fill="currentColor"/>` +
		`<circle cx="4.6" cy="11.3" r="0.8" fill="currentColor"/></svg>`))

	iconTerminal = ui.MustParseSVG([]byte(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16">` +
		`<rect x="1.6" y="2.4" width="12.8" height="11.2" rx="1.6" fill="none" stroke="currentColor" stroke-width="1.2"/>` +
		`<path d="M4.4 6.8l1.9 1.9-1.9 1.9" fill="none" stroke="currentColor" stroke-width="1.2" stroke-linecap="round" stroke-linejoin="round"/>` +
		`<path d="M8.4 10.8h3.4" fill="none" stroke="currentColor" stroke-width="1.2" stroke-linecap="round"/></svg>`))

	iconClose = ui.MustParseSVG([]byte(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16">` +
		`<path d="M4.2 4.2l7.6 7.6M11.8 4.2l-7.6 7.6" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/></svg>`))

	// The dot of a tab, green while its session answers and red once it does
	// not: the color comes from the element, the shape from here.
	iconDot = ui.MustParseSVG([]byte(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16">` +
		`<circle cx="8" cy="8" r="5.4" fill="currentColor"/></svg>`))

	// iconPlus is the plus of the buttons that add a session or a tab, drawn
	// rather than typed: a font's plus sits above the middle of its line.
	iconPlus = ui.MustParseSVG([]byte(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16">` +
		`<path d="M8 3.6v8.8M3.6 8h8.8" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>`))
)

// truncate shortens a label to n runes, marking the cut.
func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}

// plusButton draws the button of a toolbar that adds something: a bare patch
// that lights up under the pointer, with the plus in the middle of it.
func plusButton(c *ui.Context, t *ui.Theme, label string, onClick func()) {
	button := ui.Row(c).Padding(7).Radius(6).Border(1, t.Border).AlignItems(ui.Center)
	if button.Hovered() {
		button = button.Background(t.SurfaceHover).BorderColor(t.TextMuted)
	}
	button.Children(func() {
		ui.Icon(c, iconPlus).Width(11).Height(11).TextColor(t.TextMuted)
	})
	if button.Clicked() {
		onClick()
	}
	button.Label(label)
}

// resetForm clears the form for a new session.
func (a *app) resetForm() {
	a.form = sessionForm{
		port: "22",
		auth: session.AuthPassword,
	}
	a.formID = ""
	a.errMsg = ""
}

// openNew shows the form empty.
func (a *app) openNew() {
	a.resetForm()
	a.showForm = true
	a.invalidate()
}

// openEdit shows the form filled with a saved session. The password stays in
// the store: leaving the field empty keeps it.
func (a *app) openEdit(item session.Session) {
	port := item.Port
	if port == 0 {
		port = 22
	}
	auth := item.AuthMethod
	if auth == "" {
		auth = session.AuthPassword
	}

	a.form = sessionForm{
		name:    item.Name,
		host:    item.Host,
		port:    strconv.Itoa(port),
		user:    item.User,
		keyPath: item.KeyPath,
		auth:    auth,
	}
	a.formID = item.ID
	a.errMsg = ""
	a.showForm = true
	a.invalidate()
}

// deleteSession removes a saved session.
func (a *app) deleteSession(id string) {
	if a.store == nil {
		a.errMsg = "会话库不可用"
		return
	}
	if err := a.store.Delete(context.Background(), id); err != nil {
		a.errMsg = err.Error()
		a.invalidate()
		return
	}

	if a.selected == id {
		a.selected = ""
	}
	if a.formID == id && a.showForm {
		a.showForm = false
		a.resetForm()
	}
	a.reloadSessions()
	a.invalidate()
}

// reloadSessions reads the saved sessions from the store.
func (a *app) reloadSessions() {
	if a.store == nil {
		return
	}
	list, err := a.store.List(context.Background())
	if err != nil {
		a.errMsg = err.Error()
		return
	}
	a.sessions = list

	// Keep the properties pane filled.
	if a.selected == "" && len(list) > 0 {
		a.selected = list[0].ID
	}
}

// terminalOptions is how every terminal of the app behaves, local or remote:
// the mouse works as it does in Xshell, where a selection is copied when it
// ends and a secondary click pastes.
func terminalOptions() terminal.Options {
	return terminal.Options{
		Theme:        blackTheme(),
		CopyOnSelect: terminal.CopyOnSelectClipboard,
		RightClick:   terminal.RightClickPaste,
	}
}

// addLocalTab opens the user's shell in a new tab.
func (a *app) addLocalTab() {
	term, err := terminal.New(terminalOptions())
	if err != nil {
		log.Printf("local terminal: %v", err)
		return
	}
	a.tabs = append(a.tabs, &tab{title: "本地", term: term, local: true})
	a.active = len(a.tabs) - 1
	a.watchSession(a.tabs[a.active])
	a.invalidate()
}

// watchSession keeps the state of a tab current: the tab turns red when its
// session ends or stops answering, and green again once it answers.
func (a *app) watchSession(t *tab) {
	t.quit = make(chan struct{})
	go func() {
		ended := t.term.Done()
		ticker := time.NewTicker(connCheckInterval)
		defer ticker.Stop()

		for {
			select {
			case <-t.quit:
				return
			case <-ended:
				// The shell exited, or the connection went away under it.
				if t.setDown(true) {
					log.Printf("session %q ended", t.title)
					a.invalidate()
				}
				return
			case <-ticker.C:
				down := a.sessionDown(t)
				if t.setDown(down) {
					if down {
						log.Printf("session %q stopped answering", t.title)
					} else {
						log.Printf("session %q answers again", t.title)
					}
					a.invalidate()
				}
			}
		}
	}()
}

// sessionDown asks the session of a tab whether it stopped answering.
func (a *app) sessionDown(t *tab) bool {
	p, ok := t.conn.(pinger)
	if !ok {
		return false
	}
	return p.KeepAlive(keepAliveTimeout) != nil
}

// configFor builds the connection settings of a saved session, decrypting its
// stored secret.
func (a *app) configFor(item session.Session) sshx.Config {
	secret := item.Password
	if secret == "" && a.store != nil {
		if stored, err := a.store.Password(context.Background(), item.ID); err == nil {
			secret = stored
		}
	}

	port := item.Port
	if port == 0 {
		port = 22
	}

	cfg := sshx.Config{
		Addr:           net.JoinHostPort(item.Host, strconv.Itoa(port)),
		User:           item.User,
		KeyPath:        item.KeyPath,
		KnownHostsPath: os.Getenv("SHELL_SSH_KNOWN_HOSTS"),
		// TODO: ask the user about a fingerprint that is not recorded yet
		// instead of trusting it silently.
		HostKeyPolicy: sshx.HostKeyTrustOnFirstUse,
	}
	switch item.AuthMethod {
	case session.AuthKey:
		// The stored secret of a key session unlocks the key itself.
		cfg.KeyPassphrase = secret
	case session.AuthAgent:
		cfg.UseAgent = true
	default:
		cfg.Password = secret
	}
	return cfg
}

// clickSession highlights a session on a single click, which shows its
// properties, and opens it on a double click.
func (a *app) clickSession(item session.Session) {
	now := time.Now()
	double := a.lastClickID == item.ID && now.Sub(a.lastClickAt) < doubleClickWindow

	a.lastClickID = item.ID
	a.lastClickAt = now
	a.selected = item.ID

	if !double {
		a.invalidate()
		return
	}

	// Do not let a third click open it again.
	a.lastClickID = ""
	a.openSession(item)
}

// openSession connects to a saved session, asking first for the credentials it
// does not have yet. The tab opens at once, saying that it is connecting.
func (a *app) openSession(item session.Session) {
	if a.needsCredentials(item) {
		a.startConnect(item)
		return
	}
	a.openConnection(a.configFor(item), item, item.Name)
}

// openConnection shows a tab at once and connects it in the background, so
// that a slow server holds up nothing: the tab says the connection is coming
// up, and the reason when it does not come up.
func (a *app) openConnection(cfg sshx.Config, item session.Session, title string) *tab {
	tab := &tab{title: title, session: item, connecting: true}
	a.placeTab(tab)
	a.errMsg = ""
	a.dial(tab, cfg)
	a.invalidate()
	return tab
}

// placeTab puts a new tab where the next one belongs: in place of the local
// shell in front, which the session takes over, or in place of a tab whose
// connection failed for want of credentials, or at the end.
func (a *app) placeTab(item *tab) {
	if index := a.indexTab(a.retry); index >= 0 {
		a.tabs[index] = item
		a.active = index
		a.retry = nil
		return
	}
	a.retry = nil

	if index := a.active; index >= 0 && index < len(a.tabs) && a.tabs[index].local {
		a.dropTab(index)
		a.tabs[index] = item
		return
	}

	a.tabs = append(a.tabs, item)
	a.active = len(a.tabs) - 1
}

// indexTab returns where a tab is in the bar, or -1 once it is gone.
func (a *app) indexTab(want *tab) int {
	if want == nil {
		return -1
	}
	for i, item := range a.tabs {
		if item == want {
			return i
		}
	}
	return -1
}

// dial connects a tab in the background, and hands the session it makes to the
// frame that shows the tab.
func (a *app) dial(tab *tab, cfg sshx.Config) {
	if a.dials == nil {
		return
	}

	go func() {
		result := dialResult{tab: tab}

		conn, err := sshx.Dial(cfg)
		switch {
		case err != nil:
			result.err = err
		default:
			// The view resizes the screen and tells Conn the size it fits.
			// ResizeByConn would leave the screen at 80×24 until the far end
			// resized it, which a shell never does.
			opts := terminalOptions()
			opts.Conn = conn
			term, terr := terminal.New(opts)
			if terr != nil {
				conn.Close()
				result.err = terr
				break
			}
			result.conn, result.term = conn, term
		}

		select {
		case a.dials <- result:
		default:
		}
		a.invalidate()
	}()
}

// takeDials applies the connections that came up since the last frame.
func (a *app) takeDials() {
	for {
		select {
		case result := <-a.dials:
			a.applyDial(result)
		default:
			return
		}
	}
}

// applyDial shows the terminal of a tab that connected, or says why it did
// not, asking for the credentials again when they were the reason.
func (a *app) applyDial(result dialResult) {
	tab := result.tab
	tab.connecting = false

	// The tab went away while its connection was coming up.
	if a.indexTab(tab) < 0 {
		if result.term != nil {
			result.term.Close()
		}
		if result.conn != nil {
			result.conn.Close()
		}
		return
	}

	if result.err != nil {
		tab.errMsg = result.err.Error()
		tab.setDown(true)
		if needsTyping(result.err) && tab.session.Host != "" {
			a.retry = tab
			a.startConnect(tab.session)
		}
		return
	}

	tab.term = result.term
	tab.conn = result.conn
	tab.errMsg = ""
	tab.setDown(false)
	a.watchSession(tab)
}

// saveForm stores the fields of the dialog, reporting the session it wrote.
func (a *app) saveForm() (session.Session, bool) {
	if a.store == nil {
		a.errMsg = "会话库不可用"
		return session.Session{}, false
	}
	if a.form.host == "" {
		a.errMsg = "主机不能为空"
		return session.Session{}, false
	}

	port, err := strconv.Atoi(a.form.port)
	if err != nil || port <= 0 {
		port = 22
	}

	item := session.Session{
		ID:         a.formID,
		Name:       a.form.name,
		Protocol:   session.ProtocolSSH,
		Host:       a.form.host,
		Port:       port,
		User:       a.form.user,
		AuthMethod: a.form.auth,
		KeyPath:    a.form.keyPath,
		Password:   a.form.password,
	}
	if item.Name == "" {
		item.Name = item.Host
	}

	if err := a.store.Save(context.Background(), &item); err != nil {
		a.errMsg = err.Error()
		return session.Session{}, false
	}

	a.formID = item.ID
	a.selected = item.ID
	a.reloadSessions()
	return item, true
}

// createSession saves a new session and starts its connection, which asks for
// the login name and the way to authenticate.
func (a *app) createSession() {
	item, ok := a.saveForm()
	if !ok {
		a.invalidate()
		return
	}

	a.showForm = false
	a.resetForm()
	a.startConnect(item)
}

// saveAndConnect stores the form of a session and opens it.
func (a *app) saveAndConnect() {
	item, ok := a.saveForm()
	if !ok {
		a.invalidate()
		return
	}

	a.showForm = false
	a.resetForm()
	a.openSession(item)
}

// saveFormOnly stores the form and closes the dialog.
func (a *app) saveFormOnly() {
	if _, ok := a.saveForm(); !ok {
		a.invalidate()
		return
	}

	a.showForm = false
	a.resetForm()
	a.invalidate()
}

// closeTab closes a tab and picks a neighbour, opening a local shell when the
// last one goes away.
func (a *app) closeTab(index int) {
	if index < 0 || index >= len(a.tabs) {
		return
	}

	a.dropTab(index)
	a.tabs = append(a.tabs[:index], a.tabs[index+1:]...)

	// The tabs after the one that went away move down one place, and the tab
	// in front goes on being the one in front.
	if index < a.active {
		a.active--
	}
	if a.active >= len(a.tabs) {
		a.active = len(a.tabs) - 1
	}
	if len(a.tabs) == 0 {
		a.addLocalTab()
		return
	}
	a.invalidate()
}

// dropTab ends the session of the tab at index, which may still be connecting,
// leaving its place in the bar to be taken or removed.
func (a *app) dropTab(index int) {
	t := a.tabs[index]
	t.stop()
	if t == a.retry {
		a.retry = nil
	}
	if t.term != nil {
		t.term.Close()
	}
	if t.conn != nil {
		t.conn.Close()
	}
}

// invalidate asks for the next frame after state the view reads changed.
func (a *app) invalidate() {
	if a.win != nil {
		a.win.Invalidate()
	}
}

// view draws the sidebar, the tab bar and the active terminal.
func (a *app) view(c *ui.Context) {
	t := c.Theme()
	a.takeDials()

	ui.Row(c).Fill().Children(func() {
		a.sidebar(c, t)
		a.content(c, t)
	})

	if a.showForm {
		a.formOverlay(c, t)
	}
	a.connectDialogs(c, t)
	a.deleteConfirm(c)
}

// sidebar stacks the session manager above the properties of the selection,
// as Xshell lays them out.
func (a *app) sidebar(c *ui.Context, t *ui.Theme) {
	// A fixed, narrow column: the terminal keeps the rest of the window.
	// FillHeight rather than Fill, which would also take the width.
	ui.Column(c).Width(sidebarWidth).FillHeight().Background(t.Surface).Children(func() {
		// Title bar of the session manager: the one action that has no row to
		// start from. Editing and deleting a saved session go through its
		// menu and the properties pane.
		ui.Row(c).Padding(6).Gap(4).AlignItems(ui.Center).Children(func() {
			ui.Text(c, "会话").Bold().FontSize(12)
			plusButton(c, t, "新建会话", a.openNew)
		})

		ui.Column(c).Height(1).Background(t.Border)

		ui.Row(c).Padding(6).Children(func() {
			ui.Text(c, "▾ 所有会话").FontSize(11).TextColor(t.TextMuted)
		})

		// The session list takes every remaining pixel of the column.
		ui.Column(c).Fill().Padding(2).Children(func() {
			if len(a.sessions) == 0 {
				ui.Text(c, "还没有会话").FontSize(12).TextColor(t.TextMuted).Padding(6)
			}
			for _, item := range a.sessions {
				a.sessionRow(c, t, item)
			}
		})

		if a.showProps {
			ui.Column(c).Height(1).Background(t.Border)
			a.properties(c, t)
		}
	})
}

// sessionRow draws one line of the session list: an icon and the name, with a
// tip holding the connection details once the pointer rests on it. A single
// click selects it, a double click opens it.
func (a *app) sessionRow(c *ui.Context, t *ui.Theme, item session.Session) {
	row := ui.Row(c).Gap(6).Padding(5).FillWidth()
	if item.ID == a.selected {
		row = row.Background(t.Selection)
	}

	row.Children(func() {
		icon := iconServer
		if item.Protocol == session.ProtocolLocal {
			icon = iconTerminal
		}
		ui.Icon(c, icon).Width(14).Height(14).TextColor(t.TextMuted)
		ui.Text(c, item.Name).FontSize(12)
	})

	switch {
	case row.DoubleClicked():
		a.selected = item.ID
		a.openSession(item)
	case row.Clicked():
		a.selected = item.ID
		a.invalidate()
	}

	a.sessionMenu(row, item)

	ui.TooltipBase(c, row, func(tip ui.Element) {
		host := item.Host
		if host == "" {
			host = "本机"
		}
		user := item.User
		if user == "" {
			user = "-"
		}

		tip.Padding(8).Radius(6).Background(t.Background).Border(1, t.Border)
		tip.Children(func() {
			ui.Text(c, item.Name).FontSize(12).Bold()
			ui.Text(c, fmt.Sprintf("%s@%s:%d", user, host, item.Port)).FontSize(11).TextColor(t.TextMuted)
			ui.Text(c, fmt.Sprintf("%s · %s", strings.ToUpper(string(item.Protocol)), item.AuthMethod)).
				FontSize(11).TextColor(t.TextMuted)
		})
	})
}

// sessionMenu gives a session the menu of the actions on it, as Xshell shows
// on a right click: open, edit, delete, and the pane with its properties.
func (a *app) sessionMenu(row ui.Element, item session.Session) {
	row.PopoverMenu(func(m *ui.Menu) {
		// The menu acts on the session it opened on, which the list and the
		// properties pane then show.
		if a.selected != item.ID {
			a.selected = item.ID
			a.invalidate()
		}

		if m.Item("打开(O)").Chosen() {
			a.openSession(item)
		}
		if m.Item("编辑(E)").Chosen() {
			a.openEdit(item)
		}
		if m.Item("删除(D)").Danger().Chosen() {
			a.pendingDelete = item.ID
			a.pendingDeleteName = item.Name
			a.showDeleteConfirm = true
			a.invalidate()
		}

		m.Separator()

		if m.Item("属性(I)").Chosen() {
			a.showProps = true
			a.invalidate()
		}

		m.Separator()

		// The last two apply to the list rather than the session, as Xshell
		// keeps them at the bottom of the same menu.
		if m.Item("新建会话(N)").Chosen() {
			a.openNew()
		}
		if m.Item("显示属性窗格(H)").Checked(a.showProps).Chosen() {
			a.showProps = !a.showProps
			a.invalidate()
		}
	})
}

// properties shows the fields of the selected session. The actions on it are
// the ones its menu and the list offer, which leaves this pane to read.
func (a *app) properties(c *ui.Context, t *ui.Theme) {
	var sel *session.Session
	for i := range a.sessions {
		if a.sessions[i].ID == a.selected {
			sel = &a.sessions[i]
			break
		}
	}

	// The pane takes the room its fields need, leaving the rest to the list.
	ui.Column(c).Padding(8).Gap(4).Children(func() {
		ui.Text(c, "属性").Bold().FontSize(12)

		row := func(label, value string) {
			ui.Row(c).Gap(8).Children(func() {
				ui.Text(c, label).Width(50).FontSize(12).TextColor(t.TextMuted)
				ui.Text(c, value).FontSize(12)
			})
		}

		if sel == nil {
			ui.Text(c, "未选择会话").FontSize(12).TextColor(t.TextMuted)
			return
		}

		row("名称", sel.Name)
		row("主机", sel.Host)
		row("端口", strconv.Itoa(sel.Port))
		row("协议", strings.ToUpper(string(sel.Protocol)))
		row("用户名", sel.User)
	})
}

// content draws the tab bar and the terminal of the active tab. Terminals of
// other tabs keep running without a view; one terminal can only be in one.
func (a *app) content(c *ui.Context, t *ui.Theme) {
	ui.Column(c).Fill().Children(func() {
		// The tab bar: a tab is one block, its status dot, its title and its
		// close button sharing the background of the block, as a browser draws
		// them.
		ui.Row(c).Gap(4).Padding(5).AlignItems(ui.Center).Background(t.Surface).Children(func() {
			for i, item := range a.tabs {
				a.tabItem(c, t, i, item)
			}

			plusButton(c, t, "新建标签", a.addLocalTab)
			if a.errMsg != "" {
				ui.Text(c, a.errMsg).TextColor(t.Danger).FontSize(11)
			}
		})

		// A hairline keeps the bar apart from the black terminal below it.
		ui.Column(c).Height(1).Background(t.Border)

		if a.active >= 0 && a.active < len(a.tabs) {
			item := a.tabs[a.active]
			if item.term != nil {
				view := terminal.View(c, item.term).Fill()
				// The terminal of the tab in front takes the keys, as Xshell
				// puts the cursor in the tab it opens or switches to. AutoFocus
				// does not: the view is the same element for every tab, so it
				// is born once, and the focus stays on whatever was clicked
				// last, as the button that opened the tab.
				if a.focused != item {
					a.focused = item
					view.Focus()
				}
			} else {
				// There is nothing to type into yet: the terminal takes the
				// keys as it comes up.
				a.focused = nil
				a.idlePane(c, t, item)
			}
		}
	})
}

// idlePane fills the room of a tab that has no terminal yet: the connection
// coming up, or the reason it did not come up.
func (a *app) idlePane(c *ui.Context, t *ui.Theme, item *tab) {
	ui.Column(c).Fill().Background(ui.RGB(0, 0, 0)).Padding(18).Gap(6).Children(func() {
		switch {
		case item.connecting:
			ui.Text(c, "正在连接 "+item.title+"…").FontSize(12).TextColor(t.TextMuted)
		case item.errMsg != "":
			ui.Text(c, "连接失败").FontSize(13).Bold().TextColor(t.Danger)
			ui.Text(c, item.errMsg).FontSize(12).TextColor(t.TextMuted)
		default:
			ui.Text(c, "没有会话").FontSize(12).TextColor(t.TextMuted)
		}
	})
}

// tabItem draws one tab: one block holding the terminal icon, the title and
// the close button, standing out while it is the tab in front.
func (a *app) tabItem(c *ui.Context, t *ui.Theme, index int, item *tab) {
	active := index == a.active
	down := item.down.Load()

	block := ui.Row(c).Gap(6).Padding(9, 6).Radius(6).AlignItems(ui.Center)
	switch {
	case active:
		block = block.Background(t.Background)
	case block.Hovered():
		block = block.Background(t.SurfaceHover)
	}

	textColor := t.TextMuted
	if active {
		textColor = t.Text
	}

	block.Children(func() {
		// The dot tells a session that still answers from one that stopped, as
		// Xshell marks the tab of a lost connection. A local shell has no
		// connection to watch, so it stays grey until the shell itself ends,
		// and a connection coming up shows in amber.
		dotColor := t.TextMuted
		switch {
		case down:
			dotColor = t.Danger
		case item.connecting:
			dotColor = t.Warning
		case !item.local:
			dotColor = t.Success
		}
		ui.Icon(c, iconDot).Width(9).Height(9).TextColor(dotColor)

		label := ui.Text(c, fmt.Sprintf("%d %s", index+1, truncate(item.title, 14))).
			FontSize(12).TextColor(textColor).SingleLine()
		if active {
			label.FontWeight(600)
		}

		// The close button belongs to the block: bare, in the color of the
		// label, taking a patch of its own only while the pointer rests on it.
		close := ui.Row(c).Padding(3).Radius(4).AlignItems(ui.Center)
		if close.Hovered() {
			close = close.Background(t.SurfacePressed)
		}
		close.Children(func() {
			ui.Icon(c, iconClose).Width(9).Height(9).TextColor(textColor)
		})
		if close.Clicked() {
			a.closeTab(index)
		}
	})

	if active {
		// An accent line under the block marks the tab in front.
		block.DrawOver(func(p *ui.Painter, r ui.Rect) {
			in, h := float32(9), float32(2)
			p.Fill(ui.Rect{X: r.X + in, Y: r.Y + r.H - h - 1, W: r.W - 2*in, H: h}, t.Accent, h/2)
		})
	}

	if down {
		ended := "连接已断开"
		switch {
		case item.errMsg != "" && item.term == nil:
			ended = "连接失败"
		case item.local:
			ended = "本地 Shell 已退出"
		}
		ui.TooltipBase(c, block, func(tip ui.Element) {
			tip.Padding(8).Radius(6).Background(t.Background).Border(1, t.Border)
			tip.Children(func() {
				ui.Text(c, ended).FontSize(12).TextColor(t.Danger)
			})
		})
	}

	if block.Clicked() {
		a.active = index
		a.invalidate()
	}
}

// formOverlay draws the session dialog above the window. A new session asks
// only where it goes: the login name and the way to authenticate come from the
// dialogs that follow, as Xshell asks them.
func (a *app) formOverlay(c *ui.Context, t *ui.Theme) {
	editing := a.formID != ""

	ui.Overlay(c, func() {
		ui.Column(c).Absolute().Left(290).Top(60).Width(400).
			Background(t.Background).Border(1, t.Border).Padding(16).Gap(8).
			Children(func() {
				title := "新建会话"
				if editing {
					title = "编辑会话"
				}
				ui.Text(c, title).Bold().FontSize(15)

				ui.TextInput(c, &a.form.name).Placeholder("例如 测试服务器").Label("名称").FillWidth()
				ui.TextInput(c, &a.form.host).Placeholder("47.115.175.104").Label("主机").FillWidth()
				ui.TextInput(c, &a.form.port).Placeholder("22").Label("端口").FillWidth()

				if editing {
					formCredentials(c, a)
				}

				if a.errMsg != "" {
					ui.Text(c, a.errMsg).TextColor(t.Danger).FontSize(12)
				}

				ui.Row(c).Gap(8).Children(func() {
					if editing {
						if ui.PrimaryButton(c, "保存").Clicked() {
							a.saveFormOnly()
						}
						if ui.Button(c, "保存并连接").Clicked() {
							a.saveAndConnect()
						}
					} else if ui.PrimaryButton(c, "确定").Clicked() {
						a.createSession()
					}

					if ui.Button(c, "取消").Clicked() {
						a.showForm = false
						a.resetForm()
						a.invalidate()
					}
				})
			})
	})
}

// formCredentials draws the login of a saved session: its name and the way to
// authenticate, which the connection dialogs ask a new session for.
func formCredentials(c *ui.Context, a *app) {
	ui.TextInput(c, &a.form.user).Placeholder("root").Label("用户名").FillWidth()

	ui.Row(c).Gap(6).Children(func() {
		if a.form.auth == session.AuthPassword {
			ui.PrimaryButton(c, "密码").Width(100)
			if ui.Button(c, "密钥").Width(100).Clicked() {
				a.form.auth = session.AuthKey
				a.invalidate()
			}
			return
		}
		if ui.Button(c, "密码").Width(100).Clicked() {
			a.form.auth = session.AuthPassword
			a.invalidate()
		}
		ui.PrimaryButton(c, "密钥").Width(100)
	})

	if a.form.auth == session.AuthKey {
		ui.TextInput(c, &a.form.keyPath).Placeholder(`C:\Users\you\.ssh\id_ed25519`).Label("私钥路径").FillWidth()
		return
	}
	ui.TextInput(c, &a.form.password).Placeholder("留空则保留已存密码").Label("密码").FillWidth()
}

// deleteConfirm asks before deleting a session, because its stored password
// goes with it and cannot be recovered.
func (a *app) deleteConfirm(c *ui.Context) {
	if a.pendingDelete == "" {
		return
	}
	// The dialog was closed without a choice, as by Escape.
	if !a.showDeleteConfirm {
		a.pendingDelete = ""
		a.pendingDeleteName = ""
		return
	}

	open := a.showDeleteConfirm
	choice := ui.AlertDialog(c, &open, "删除会话",
		fmt.Sprintf("确定删除「%s」？保存的密码会一起删除，无法恢复。", a.pendingDeleteName),
		"取消", "删除")
	a.showDeleteConfirm = open

	switch choice {
	case 1:
		id := a.pendingDelete
		a.pendingDelete = ""
		a.pendingDeleteName = ""
		a.showDeleteConfirm = false
		a.deleteSession(id)
	case 0:
		a.pendingDelete = ""
		a.pendingDeleteName = ""
		a.showDeleteConfirm = false
	}
}

// openStore opens the session database next to the user's config.
func openStore() *session.Store {
	dir, err := os.UserConfigDir()
	if err != nil {
		log.Printf("config dir: %v", err)
		return nil
	}

	base := filepath.Join(dir, "mygo-shell")
	if err := os.MkdirAll(base, 0o700); err != nil {
		log.Printf("create %s: %v", base, err)
		return nil
	}

	store, err := session.Open(context.Background(),
		filepath.Join(base, "sessions.db"),
		filepath.Join(base, "master.key"))
	if err != nil {
		log.Printf("session store: %v", err)
		return nil
	}
	return store
}

// sshConfigFromEnv builds a connection from the environment, which keeps the
// test suite and quick checks out of the UI.
func sshConfigFromEnv() (sshx.Config, bool) {
	addr := os.Getenv("SHELL_SSH_ADDR")
	if addr == "" {
		return sshx.Config{}, false
	}

	policy := sshx.HostKeyStrict
	if os.Getenv("SHELL_SSH_TOFU") == "1" {
		policy = sshx.HostKeyTrustOnFirstUse
	}

	return sshx.Config{
		Addr:           addr,
		User:           os.Getenv("SHELL_SSH_USER"),
		Password:       os.Getenv("SHELL_SSH_PASSWORD"),
		KeyPath:        os.Getenv("SHELL_SSH_KEY"),
		KeyPassphrase:  os.Getenv("SHELL_SSH_KEY_PASSPHRASE"),
		UseAgent:       os.Getenv("SHELL_SSH_AGENT") == "1",
		KnownHostsPath: os.Getenv("SHELL_SSH_KNOWN_HOSTS"),
		HostKeyPolicy:  policy,
	}, true
}

// iconPNG returns the icon the window shows in its title bar and the taskbar:
// the one built beside the executable, or the one in resources while the app
// runs from the source.
func iconPNG() []byte {
	var paths []string
	if exe, err := os.Executable(); err == nil {
		paths = append(paths, filepath.Join(filepath.Dir(exe), "icon.png"))
	}
	paths = append(paths, "icon.png", filepath.Join("resources", "icon.png"))

	for _, path := range paths {
		if png, err := os.ReadFile(path); err == nil {
			return png
		}
	}
	return nil
}

func main() {
	mygo.App.WhenReady(func() {
		a := &app{
			active:    -1,
			showProps: true,
			probes:    make(chan probeResult, 4),
			dials:     make(chan dialResult, 4),
			asks:      make(chan *keyboardAsk, 4),
		}
		a.resetForm()

		a.win = mygo.NewWindow(mygo.WindowOptions{
			Title:     "mygo-shell",
			Width:     1100,
			Height:    700,
			MinWidth:  720,
			MinHeight: 420,
			// A new key: the old one remembered a window too short to use.
			StateKey: "main-v2",
			Content:  ui.View(a.view),
		})
		// A window takes the icon it is given: Windows draws its own default
		// one otherwise, whatever the executable carries.
		if png := iconPNG(); png != nil {
			if err := a.win.SetIcon(png); err != nil {
				log.Printf("window icon: %v", err)
			}
		}
		a.win.OnClosed(func() {
			for _, t := range a.tabs {
				t.stop()
				if t.term != nil {
					t.term.Close()
				}
				if t.conn != nil {
					t.conn.Close()
				}
			}
			if a.store != nil {
				a.store.Close()
			}
		})

		a.store = openStore()
		a.reloadSessions()

		if cfg, ok := sshConfigFromEnv(); ok {
			a.openConnection(cfg, session.Session{
				Protocol: session.ProtocolSSH,
				Host:     cfg.Addr,
			}, cfg.Addr)
		} else {
			a.addLocalTab()
		}
	})

	if err := mygo.App.Run(); err != nil {
		log.Fatal(err)
	}
}
