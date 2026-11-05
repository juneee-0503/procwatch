# 服务器防御

防御模块监视针对本机的攻击:登录爆破、Web 攻击、网络洪水和扫描、主机失陷迹象。它把分散的发现串成攻击链,再按配置报警。

默认随 procwatch 运行,不需要配置。不配置时发现只留在本机,不发送到任何地方,也不打开端口。

## 能发现什么

| 规则 | 严重度 | 阶段 | 依据 |
|---|---|---|---|
| `ssh-bruteforce` | 高 | 尝试 | 一分钟内同一来源 10 次失败 |
| `ssh-distributed` | 高 | 尝试 | 十分钟内 20 个来源攻击同一用户 |
| `ssh-user-enumeration` | 中 | 侦察 | 同一来源尝试 5 个以上用户名 |
| `login-after-failures` | 严重 | 立足 | 一小时内失败 5 次以上后登录成功,慢速猜测也算 |
| `login-new-source` | 中 | 立足 | 用户从没见过的地址登录 |
| `root-password-login` | 高 | 立足 | root 用密码远程登录 |
| `privilege-guessing` | 高 | 提权 | 五分钟内 3 次 sudo 或 su 失败 |
| `sudo-root-shell` | 低 | 提权 | 用 sudo 打开 root shell |
| `account-created`、`uid0-created` | 中、严重 | 持久化 | 日志显示创建了账户 |
| `added-to-admin-group` | 高 | 提权 | 用户加入 sudo、wheel、docker 等组 |
| `web-sql-injection` | 中/高 | 尝试/立足 | URL 中的注入特征 |
| `web-path-traversal` | 中/高 | 尝试/立足 | 路径穿越、读取敏感文件 |
| `web-command-injection` | 中/高 | 尝试/立足 | 命令注入、Log4Shell |
| `web-xss`、`web-template-injection` | 中/高 | 尝试/立足 | 脚本和模板注入 |
| `web-scanner`、`web-probe`、`web-scan` | 低/中 | 侦察 | 攻击工具 UA、敏感路径、大量 4xx |
| `webshell-access` | 严重 | 执行 | 向上传目录的脚本 POST 并成功 |
| `http-flood` | 高 | 影响 | 一分钟 600 次请求 |
| `port-scan` | 中 | 侦察 | 一分钟内探测 15 个端口,包括已关闭的端口 |
| `syn-flood`、`syn-rate` | 高 | 影响 | 半开连接或 SYN 速率过高 |
| `syn-cookies-active`、`accept-queue-overflow` | 高 | 影响 | 内核计数器显示积压已满 |
| `connection-flood` | 高 | 影响 | 单一来源占用 200 个连接 |
| `reverse-shell` | 严重 | 执行 | shell 或解释器的输入输出是远程 TCP 连接 |
| `fileless-execution` | 严重 | 执行 | 进程从 memfd 运行,磁盘上没有文件 |
| `deleted-binary-running` | 高 | 执行 | 运行已删除的临时目录程序 |
| `hidden-process`、`hidden-module` | 严重 | 持久化 | 两种内核视图不一致,是常见 rootkit 手法 |
| `kernel-module-loaded` | 中 | 持久化 | 新加载了内核模块 |
| `uid0-account`、`account-appeared` | 严重、高 | 提权、持久化 | `/etc/passwd` 的变化 |
| `ssh-key-changed` | 高 | 持久化 | `authorized_keys` 变化 |
| `ld-preload-changed`、`ld-preload-active` | 严重 | 持久化 | `/etc/ld.so.preload` |
| `sudoers-changed`、`pam-changed`、`sshd-config-changed` | 高 | 持久化 | 权限和登录配置 |
| `cron-changed`、`service-changed`、`shell-startup-changed` | 中 | 持久化 | 计划任务、服务、启动脚本 |
| `unusual-load` | 中 | 影响 | 指标明显高于这台机器在这个时段的常态 |

**严重度在攻击成功时升级。** Web 攻击被拒绝是中等,服务器返回 2xx 时升级为高,并进入“立足”阶段。

## 攻击链

分散的告警容易被忽略。防御模块把同一来源的发现串成一条攻击,经过的阶段越多越严重:

```text
侦察 → 尝试 → 立足 → 执行 → 提权 → 持久化 → 影响
```

攻击进入立足及之后的阶段时至少为高,进入两个这样的阶段就是严重。攻击安静一小时后结束。

没有来源地址的主机发现,比如新增 SSH 密钥,会并入最近的攻击。**这个关联只基于时间**,可能是巧合,界面和报警都会说明。

## 自学习基线

`unusual-load` 没有手动阈值。procwatch 为每个指标学习一周 168 个小时各自的常态,周一凌晨 3 点和周一下午 3 点是两条基线。

- 每个小时至少 120 个读数后才开始判断。
- 高出常态 6 个标准差,并持续 12 个读数才报告,短暂波动不算。
- 异常读数不进入学习,长时间攻击不会被学成常态。
- 只判断偏高,目前学习 `net.rx`、`net.tx`、`disk.iops`、`cpu.run_queue`。

一周的每个小时都学到需要至少一周。在这之前,没学过的时段不会有 `unusual-load`。

## 配置

`defense.yml` 放在设置文件旁边。文件不能被其他用户写入,否则模块拒绝运行。

```yaml
auth_logs: [/var/log/auth.log]     # 默认:auth.log、secure,都没有时读 journald
web_logs: [/var/log/nginx/access.log]
allow: [10.0.0.0/8, 192.0.2.10]    # 这些来源永不报告,也永不封禁
quiet_seconds: 600                 # 同一发现在这段时间内不重复

thresholds:
  ssh_failures: 10
  ssh_window_seconds: 60
  ssh_failures_before_login: 5
  ssh_users_per_source: 5
  ssh_sources_per_user: 20
  sudo_failures: 3
  http_per_minute: 600
  http_errors_per_minute: 60
  half_open: 256
  connections_per_source: 200
  syncookies_per_second: 100
  listen_drops_per_second: 100
  scan_ports: 15
  syns_per_second: 2000

alarms:
  - { type: webhook, url: "https://oapi.dingtalk.com/robot/send?access_token=…", format: dingtalk }
  - { type: syslog, min_severity: medium }
  - { type: file, path: /var/log/procwatch/alarms.jsonl }
  - { type: command, argv: [/usr/local/bin/page-oncall] }

exporter:
  listen: "127.0.0.1:9187"
  token: ""                        # 非回环地址必须设置
```

```bash
procwatch --defense-check
```

配置有错时,防御模块显示为不可用,并给出原因,而不是用默认值悄悄运行。按 `M` 或运行 `--modules` 查看。

## 报警

`format` 可以是 `json`、`slack`、`dingtalk`、`feishu`、`wecom`。`min_severity` 默认为 `high`。

```bash
procwatch --alarm-test
```

- 投递在独立线程中,慢的 webhook 不影响检测。
- 每个目的地每分钟最多 12 条,严重级 24 条。超出的计数,附在下一条里。
- 失败重试 3 次,仍失败时显示在界面上。
- webhook 地址通过标准输入交给 curl,不出现在命令行里,其他本地用户用 `ps` 看不到其中的 token。
- `command` 不经过 shell 运行,报警以 JSON 从标准输入传入。

报警内容含主机名、来源地址和日志片段,发到你配置的目的地。

## 自动封禁

代理策略里的 `ban` 步骤用 nftables 封禁来源地址。只在 `mode: enforce` 下执行,审计模式写 `would ban`。

```yaml
mode: audit
playbooks:
  - id: stop-brute-force
    when: { rule: [ssh-bruteforce, login-after-failures] }
    do: [ban]
    ban_seconds: 3600
```

为防止误封:

- 每次封禁都有期限,最长一周,重启后失效,代理正常退出时全部解除。
- 永不封禁回环地址、链路本地地址、`allow` 列表、当前登录用户的来源、默认网关。
- 每小时最多封禁 256 个地址。

手动解除:

```bash
sudo procwatch --unban-all
```

**日志可以伪造。** 本机任何用户都能用 `logger -t sshd` 写入假的登录失败,借此诬陷某个地址。开启 `ban` 前请把管理地址加入 `allow`。

## 指标历史和 Prometheus

`history` 模块把每分钟的最小、平均、最大值写入数据目录,保留 30 天。

```bash
procwatch --history
```

```bash
procwatch --history net.rx --hours 6
```

配置 `exporter.listen` 后,`/metrics` 输出 Prometheus 格式,`/health` 用于存活检查。监听非回环地址时必须设置 `token`,请求带 `Authorization: Bearer <token>`。Grafana 接上就能看图。

## 平台支持

| 来源 | Linux | macOS | Windows |
|---|---|---|---|
| 登录日志 | 文件或 journald | 只有配置的文件 | 无,RDP 爆破未覆盖 |
| Web 日志 | 有 | 有 | 有 |
| 半开连接、连接洪水、内核计数器 | 有 | 无 | 无 |
| SYN 捕获 | 有,需 root | 无 | 无 |
| 文件完整性 | 有 | 部分 | 无 |
| 反弹 shell、无文件执行、隐藏进程和模块 | 有 | 无 | 无 |

需要 root 才能读 `/var/log/auth.log`、抓 SYN、读所有进程的文件描述符。权限不足时,对应来源看不到东西,按 `M` 可以查看。

## 局限

- **进程检查每 30 秒一次。** 比这更短的反弹 shell 看不到。这是目前最大的短板,解决办法是 eBPF。
- **只看 URL。** POST 正文、请求头的攻击看不到。这不是 WAF,也不是 Suricata。
- **反向代理后的来源是代理。** 需要把真实客户端地址放在日志行首。
- **只抓 SYN。** UDP 洪水、ICMP 洪水只能靠 `unusual-load` 间接发现。
- **Rootkit 检测不是证明。** 只能发现这两种视图不一致的手法,更深的 rootkit 能骗过两边。
- **特征是可以绕过的。** Web 规则是常见攻击的字符串匹配,不是语义分析。

## 验证状态

| 项目 | 状态 |
|---|---|
| 解析、检测、关联、基线、报警格式、封禁保护 | 单元测试 |
| 模拟攻击经代理、报警、日志、`/metrics` 全流程 | macOS 本机,用日志文件模拟 |
| 真实的 shell 经 socket 驱动、关闭端口扫描、隐藏进程扫描 | Linux 自测,待 CI |
| `nft` 实际封禁 | **未运行过** |
| 真实攻击流量、真实 webhook | **未验证** |
| 长时间运行下的误报率 | **未知**,这决定规则能不能用,需要在真实服务器上观察 |
