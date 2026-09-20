# netme

macOS / Linux 网络监控 TUI。参考 btop：沿用终端背景、细线框分区、紧凑列对齐，下载蓝色、上传绿色。没有 GUI 填充卡片、模拟按钮或特殊字体要求。

界面内容和监控功能保持不变：

- 顶部 **DOWNLOAD / UPLOAD**：默认出口实时速率。
- **interfaces**：Ethernet Adapter、Thunderbolt、Wi-Fi 的下载 / 上传、链路带宽和类型 / 频段。
- 底部 **Internal / Router / External**：本地地址、默认网关、公网出口；External 标明 `proxy` / `direct`。

不显示历史曲线、进程、socket 或额外诊断面板，不启动 `nettop` / `ss`。仅展示本机硬件接口，不写死设备或地址；回环、桥接、VPN 不列为硬件行。

## 运行

```sh
cargo install --path . --locked
netme
netme --interval 2   # 1–60 秒，默认 1 秒
netme --ascii       # ASCII 字符和边框
NO_COLOR=1 netme    # 无颜色
netme --help
```

建议 **80×24**：宽屏使用紧凑网卡表与横向网络路径；窄屏使用双行网卡与纵向路径。**72×24** 也可完整展示七个接口。最小 **44×16**；更矮的列表可滚动，IPv6 自动折行。布局利用终端宽度，不再模拟居中的 GUI 窗口。

Linux 需要 `iproute2`，Wi-Fi 链路信息可选 `iw`。macOS 使用系统自带网络工具；无需 sudo。

| 按键 | 操作 |
| --- | --- |
| `↑` / `↓`、`k` / `j` | 移动选择 / 滚动网卡 |
| `Home` / `End`、`PageUp` / `PageDown` | 首尾 / 翻页 |
| `Space` | 固定 / 恢复显示，边框显示 pinned；后台采样继续 |
| `p` | 查询 External IP；`y` / Enter 确认，`n` / Esc 取消 |
| `q` / `Ctrl-C` | 退出 |

## 公网 IP 与代理

保留确认查询：启动不访问公网，按 `p` 确认后通过 HTTPS 查询 `api.ipify.org` / `api6.ipify.org`。

代理选择顺序：

1. 第一个非空环境变量：`https_proxy`、`HTTPS_PROXY`、`all_proxy`、`ALL_PROXY`、`http_proxy`、`HTTP_PROXY`。
2. 没有环境代理时，macOS 读取 `scutil --proxy` 的有效 HTTPS、HTTP、SOCKS 手动代理设置。
3. **仅在没有代理配置时直连**。代理无效或请求失败时显示 `proxy failed`，不会暗中绕过代理暴露真实出口。PAC / 自动代理发现不能直接执行，需提供显式代理环境变量。

支持 HTTP CONNECT 与 SOCKS 代理（`socks5h://` 使用远端 DNS）。例如：

```sh
HTTPS_PROXY=http://127.0.0.1:7890 netme
ALL_PROXY=socks5h://127.0.0.1:7890 netme
```

- 查询的是代理 / 当前连接的公网出口，不是所有进程的公网 IP；已配置代理优先，不按 `NO_PROXY` 绕行。
- 代理可以是 IPv4 地址，同时查询其 IPv6 出口；不会错误地把代理的地址族限制为被查询的地址族。
- 保留 TLS 验证，禁用重定向，每次请求最多 5 秒，响应限制 64 字节并校验 IP 地址族。不在界面或错误消息中显示代理凭证。
- 成功结果缓存 60 秒。网络代次或代理配置变化使缓存失效；失败不复用缓存，可按 `p` 再次确认立即重试，没有自动重试。IPv4 成功立即可见，不必等 IPv6 完成。
- 未查询 / 网络变化后显示 `p: query`，查询中显示 `…`，失败显示 `proxy failed` / `unavailable`。启动后立即确认查询时，会先等待首份网络采样，避免把结果误判为旧网络数据。

## 计量口径

- 网卡累计计数来自 `sysinfo`，以单调时钟的实际间隔计算速率。首次采样、计数重置、接口身份变化显示 `—`，不伪造零值。单位 B/s、KB/s、MB/s 使用十进制。
- 顶部取 IPv4 默认出口，其次 IPv6 默认出口，再次在线硬件接口；不重复叠加物理网卡和隧道流量。
- 链路带宽与 Wi-Fi 频段只使用系统报告值；断开接口显示 `0.00 b/s`，未知保持未知。元数据约 5 秒刷新，Wi-Fi 链路信息约 30 秒刷新，连接变化提前刷新。
- Internal / Router 属于默认出口；不知道网关时不猜测。VPN 默认出口可能与可见硬件不同。
- 采样与请求在工作线程运行，不阻塞界面。正常退出、错误、panic、SIGTERM/INT/HUP/QUIT 恢复终端；SIGKILL 无法清理。

## 验证

```sh
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
cargo test --locked live_loopback_smoke -- --ignored --nocapture
cargo build --locked
python3 tests/tty_smoke.py target/debug/netme
# 可选：真实代理 HTTPS 查询，会联系 ipify（不打印返回的 IP）
cargo test --locked live_public_ip_proxy_smoke -- --ignored --nocapture
```

默认测试不访问公网；代理测试使用本地模拟 CONNECT 服务，验证 IPv4 代理承载 IPv6 查询、没有目标 DNS 请求、失败不回退直连、错误不泄露凭证。布局测试覆盖线框与无填充背景、所有原有字段、紧凑 / 宽屏、滚动、ASCII / NO_COLOR、IPv6 和确认弹窗。

本地实际结果见 [VALIDATION.md](VALIDATION.md)。
