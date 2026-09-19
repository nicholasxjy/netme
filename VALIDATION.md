# 验证记录

## 当前版本

界面已改为 btop 风格的原生 TUI：终端背景、细线框、紧凑对齐，无 GUI 色块 / 卡片 / 模拟按钮。保留下载 / 上传、硬件接口、链路信息、Internal / Router / External、滚动、固定和公网查询确认。

公网请求优先使用环境代理，其次使用 macOS 系统手动代理；没有代理才直连。启用现有 ureq 的 `socks-proxy` 特性，支持 HTTP CONNECT / SOCKS。配置代理失败时不自动直连，避免暴露真实出口。

## 本地结果

环境：Darwin arm64，普通用户，Rust / Cargo 1.98.1。

| 检查 | 实际结果 |
| --- | --- |
| LSP 检查改动的 Rust 文件和 PTY 脚本 | 无错误 / 警告 |
| `cargo fmt --check` | 通过 |
| `cargo clippy --locked --all-targets -- -D warnings` | 通过，无警告 |
| `cargo test --locked` | 16 通过；2 个显式实时测试默认忽略 |
| `cargo test --locked live_loopback_smoke -- --ignored --nocapture` | 1 通过；真实接口计数和本地 TCP 回环流量 |
| `cargo test --locked live_public_ip_proxy_smoke -- --ignored --nocapture` | 1 通过；经本机已配置代理使用 HTTPS 成功获取公网 IPv4，未打印地址或代理凭证 |
| `cargo build --locked` | 通过 |
| `python3 tests/tty_smoke.py target/debug/netme` | 8 场景通过：滚动 / 固定 / 取消查询、btop 配色、紧凑、窄屏、过小窗口、Ctrl-C、SIGTERM、SIGHUP；核对退出和 termios 恢复 |

## 回归覆盖

- 72×24、80×24、120×24：七个接口和所有原有字段完整显示；宽屏表格与横向网络路径，窄屏双行接口与纵向路径。
- 140×50、52×20、44×16 和更小窗口：滚动、ASCII / NO_COLOR、空列表、IPv6、确认弹窗，无绘制异常。
- 所有界面单元格背景保持 `Color::Reset`，不出现块状 GUI 边缘。PTY 断言存在彩色文字序列、没有 RGB 填充背景序列。
- 环境代理优先级、系统代理解析、SOCKS5h 配置、无效端口和 PAC 拒绝。
- 本地 HTTP 模拟代理返回 IPv6：验证 IPv6 出口请求可以经 IPv4 代理发送，不解析目标域名。
- 本地 HTTPS CONNECT 模拟代理：验证 CONNECT 目标与 407 拒绝处理。
- 断开的代理不会向目标直连；错误消息不包含代理凭证。
- 公网查询缓存与网络代次绑定；IPv4 成功立即显示，不等待 IPv6；显示 proxy / direct 来源，失败和过期状态不会伪装成成功。

测试过程中修正了模拟服务器的协议预期：HTTP 代理请求使用绝对 URI，HTTPS 才使用 CONNECT。修正夹具后两条路径分别验证，完整检查通过。

## 验证边界

- macOS 实机采样、PTY、HTTP 代理 HTTPS 公网 IPv4 查询已验证。Linux 解析器通过测试，未执行 Linux 实机或远端 CI。
- 真实公网 IPv6、真实 SOCKS 服务及带认证代理未做在线烟测；IPv6-over-IPv4-proxy 与协议失败通过本地模拟验证。
- 默认单元测试与 PTY 不访问公网；只有本轮显式执行的 `live_public_ip_proxy_smoke` 联系了 ipify。
- PAC / 自动代理发现不执行；需提供 `HTTPS_PROXY` / `ALL_PROXY`。已配置代理优先，不按 NO_PROXY 绕行。
- Wi-Fi 信息依赖系统可见性；未知字段不猜测。SIGKILL / 断电无法恢复终端。
