# mygo-shell

A Xshell-style desktop terminal in Go: SSH sessions and local shells in one tabbed window.
纯 Go、无 cgo、一个 exe 直接运行。

界面用 [MyGo](https://github.com/egoist/mygo) 的原生 UI 画，终端仿真用 [Ghostty](https://github.com/ghostty-org/ghostty) 的 VT 核心（libghostty-vt）。

## 功能

- **多标签**：本地 shell 与 SSH 会话共用标签栏。标签左端的状态点表示连接状态 —— 绿=正常、琥珀=连接中、红=已断开或连接失败、灰=本地 shell
- **会话管理**：SQLite 会话库；密码和私钥口令用 AES-256-GCM 加密后落盘（`sessions.db` + `master.key`）
- **仿 Xshell 的连接流程**
  1. 「新建会话」只填名称/主机/端口
  2. 后台探测服务器标识，显示为 `SSH2, OpenSSH_8.4p1 Debian-5+deb11u5` 这样的服务器类型
  3. 「SSH 用户名」：可勾选记住用户名
  4. 「SSH 用户身份验证」：可选密码或公钥（自动列出 `~/.ssh` 下的私钥）并记住密码
- **连接不阻塞界面**：点确定立刻出现新标签并显示「正在连接…」，失败原因直接写在标签里；若是凭据问题，会自动重新弹出身份验证并复用同一个标签
- **断线检测**：终端结束事件加每 5 秒一次的 `keepalive@openssh.com` 探测，探测恢复应答后状态点自动变回绿色
- **会话操作**：右键菜单（打开 / 编辑 / 删除 / 属性）、属性窗格、双击打开

## 构建

需要 Go 1.27+。版本固定在 `mise.toml`，装了 [mise](https://mise.jdx.dev) 可以直接 `mise install`。

```bash
# 开发运行
go run .

# 生产构建，产物在 build/<platform>/
go tool mygo build -skip-installer

# 全平台
go tool mygo build -platform windows/amd64,darwin/universal,linux/amd64 -skip-installer -skip-dmg
```

Windows 的产物是 `build/windows-amd64/mygo-shell.exe` 加上同目录的 `ghostty-vt.dll`、`Sqlitecore.dll`、`icon.png`，整个目录可以直接分发（不需要目标机器再下载任何东西）。macOS 的签名与 dmg 必须在 macOS 上做。

## 关于 libghostty-vt

终端仿真核心是本地动态库。`go tool mygo build` 会把它打进产物；只用 `go run` / `go test` 时不会，首次运行会从 GitHub Releases 下载并缓存到 `%LOCALAPPDATA%\mygo\natives\<sha256>\ghostty-vt.dll`。网络受限时可以用 `MYGO_GHOSTTY_VT` 指向已有的 dll。

## 可选：用环境变量直接连一台

```bash
SHELL_SSH_ADDR=10.0.0.1:22
SHELL_SSH_USER=root
SHELL_SSH_PASSWORD=secret
SHELL_SSH_KEY=C:\Users\you\.ssh\id_ed25519
SHELL_SSH_KEY_PASSPHRASE=...
SHELL_SSH_AGENT=1
SHELL_SSH_KNOWN_HOSTS=...
```

设置了 `SHELL_SSH_ADDR` 时启动直接连它，不写会话库。

## 已知限制

- 暂不支持键盘交互（Keyboard Interactive）认证，只开该方式的服务器（部分 PAM / 2FA 配置）目前连不上
- 主机密钥采用 TOFU（首次连接直接信任并记录），不会先展示指纹让人核对
- GSSAPI、PKCS#11、CAPI 认证未实现
- 单窗口，没有标签拖拽、分屏和会话分组

## 目录结构

```
main.go             界面：会话列表、标签栏、终端面板、连接状态
connect.go          仿 Xshell 的两步凭据弹窗
internal/sshx       SSH 连接：密码/公钥/agent、keepalive、服务器标识探测
internal/session    会话库（SQLite）
internal/vault      主密钥与密码加解密
```

## 依赖

- [MyGo](https://github.com/egoist/mygo)：原生 UI、窗口与打包
- [Ghostty](https://github.com/ghostty-org/ghostty) 的 libghostty-vt：终端仿真核心
- [golang.org/x/crypto](https://pkg.go.dev/golang.org/x/crypto/ssh)：SSH

## License

MIT
