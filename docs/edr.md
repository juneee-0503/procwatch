# EDR 代理

`--agent` 把检测、响应、拦截和日志放进一个长期运行的进程:发现检测后按剧本处置,全部动作写入防篡改日志,进程死亡后自动重启。

它不是商业 EDR 的替代品。下面的[局限](#局限)写明了差距,部署前请先读。

## 快速开始

先写策略,默认的审计模式只记录,不动任何进程。

```yaml
# agent.yml
mode: audit
activity: true
enforce: blocking.yml      # 可选:同时应用拦截策略,路径相对本文件
playbooks:
  - id: note-high
    when: { min_severity: high }
    do: [collect]
  - id: stop-miners
    when: { rule: ["*miner*"] }
    do: [collect, suspend, kill]
    cooldown_seconds: 600
```

```bash
procwatch --agent-check agent.yml
```

```bash
sudo procwatch --agent agent.yml --output /var/log/procwatch/agent.jsonl
```

观察一段时间,确认日志里的 `would kill` 都是你想处置的进程,再改为 `mode: enforce`。检测可能误报,而错杀进程的代价通常高于晚一点告警。

## 策略字段

| 字段 | 默认 | 含义 |
|---|---|---|
| `mode` | `audit` | `audit` 只记录,`enforce` 真实处置 |
| `activity` | `false` | 同时采集文件、注册表、网络活动,写入日志 |
| `enforce` | 无 | 同时应用的[拦截策略](enforcement.md) |
| `playbooks` | 必填 | 剧本列表 |

剧本字段:

| 字段 | 默认 | 含义 |
|---|---|---|
| `id` | 必填 | 唯一名称 |
| `when.rule` | 任意 | 检测或[防御发现](defense.md)的规则 ID 或名称,支持 `*` 和 `?` |
| `when.min_severity` | 无 | `info`、`low`、`medium`、`high`、`critical` |
| `do` | 必填 | 步骤,按顺序执行 |
| `cooldown_seconds` | 300 | 同一进程在这段时间内只处置一次 |
| `ban_seconds` | 3600 | `ban` 的时长,最长一周 |

步骤:

| 步骤 | 动作 |
|---|---|
| `collect` | 把进程名、路径、SHA-256、父进程、命令行写入日志。审计模式也会执行 |
| `suspend` | 挂起进程 |
| `kill` | 强制结束进程 |
| `ban` | 用 nftables 封禁来源地址,见[服务器防御](defense.md#自动封禁) |

未知字段和未知步骤都会让策略被拒绝。

## 安全限制

以下限制没有覆盖开关:

- `when` 不能为空。
- `suspend`、`kill` 和 `ban` 必须指定规则,或者 `min_severity` 至少为 `high`。
- 这些步骤的规则模式不能只有通配符。
- 代理不处置自身、自己的父进程链、init、Windows 内核进程,以及[拦截策略](enforcement.md)列出的系统必需文件。遇到时日志写 `refused`。
- 处置前用 PID 和启动时间核对进程。PID 已被复用时跳过,日志写明原因。
- 已被抑制的检测不触发剧本。

## 日志

日志是 JSON Lines,每行含 `seq`、`time`、`event`、`prev`、`hash`。`hash` 覆盖上一行的哈希和本行内容,所以修改或删除任何一行都会破坏后面的链。

```bash
procwatch --agent-verify /var/log/procwatch/agent.jsonl
```

退出码 0 表示完整,并打印条目数和最新哈希;退出码 1 表示已被改动,并指出第一个错误的行。代理启动时也会校验,日志已损坏时拒绝追加,需要把它移走。

`event` 是字符串,内容是下面这些 JSON:

| `kind` | 含义 |
|---|---|
| `agent started` | 启动,含模式、策略和实际生效的加固措施 |
| `agent stopped` | 停止及原因 |
| `detection` | 检测,同一规则和进程一小时记一次 |
| `threat` | 防御模块的发现 |
| `incident` | 攻击链进入新阶段 |
| `collected` | `collect` 步骤的结果 |
| `response` | `suspend`、`kill` 的结果,或 `would …`、`refused` |
| `blocking` | 拦截策略的决策 |
| `activity` | 一秒内的活动事件 |
| `tamper` | 程序或策略文件被改动 |
| `activity capture unavailable` | 活动采集没有启动及原因 |

**哈希链不能防止重写整个文件。** 能写这个文件的人可以从头重建一条链。要防住这一点,需要把日志或最新哈希送到另一台机器:

```bash
procwatch --agent-verify /var/log/procwatch/agent.jsonl
```

定期把输出的 head 记录到别处,或者用日志转发器发送这个文件。

## 防篡改

| 措施 | 平台 | 能防 | 不能防 |
|---|---|---|---|
| 禁止 dump 和 ptrace(`PR_SET_DUMPABLE`) | Linux | 同用户进程调试、注入 | root 可以用内核模块绕过 |
| 拒绝调试器附加(`PT_DENY_ATTACH`) | macOS | 普通调试器 | root、禁用 SIP 的系统 |
| 进程 DACL 只给 SYSTEM 完全权限 | Windows | 普通用户,以及未启用 SeDebugPrivilege 的管理员 | 启用 SeDebugPrivilege 的管理员 |
| 驱动去掉终止权限(`ObRegisterCallbacks`) | Windows,需加载驱动 | 管理员结束进程 | 能加载驱动或卸载本驱动的人。[驱动从未运行过](../driver/windows/README.md) |
| 每 30 秒校验程序和策略的 SHA-256 | 全部 | 发现文件被替换,写入 `tamper` | 文件已替换但进程先被结束 |
| 代理进程死亡后重启 | 全部 | 进程崩溃或被结束 | 守护进程本身被结束 |
| 日志哈希链 | 全部 | 发现行被修改、删除 | 整个文件重写 |

策略文件变化后,代理继续使用内存里的旧策略,并记录 `tamper`。

Windows 上真正的保护需要 Protected Process Light,这要求微软签发的反恶意软件证书,自己无法做到。

### 让服务管理器负责重启

`--agent` 的守护进程只负责重启工作进程。如果守护进程本身被结束,需要由操作系统把它拉起来。

Linux 的 systemd:

```ini
[Unit]
Description=procwatch agent
After=network.target

[Service]
ExecStart=/usr/local/bin/procwatch --agent /etc/procwatch/agent.yml --output /var/log/procwatch/agent.jsonl
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

macOS 用 LaunchDaemon 的 `KeepAlive`,Windows 用任务计划或服务包装器。

## 局限

- **只看本机。** 没有管理端、没有跨主机关联。
- **响应是事后的。** 检测靠采样和事件,`kill` 发生在进程已经运行之后。要事前阻止,用[拦截策略](enforcement.md)。
- **不读内存。** 没有内存扫描、注入检测和无文件恶意代码检测,这是项目边界。
- **不上传文件。** 没有云端信誉和沙箱。
- **root 或管理员可以停掉它。** 防篡改提高了难度并留下痕迹,但不是对抗内核权限的边界。
- **检测规则数量有限。** 商业 EDR 的价值很大一部分在规则和情报。

## 验证状态

| 项目 | 状态 |
|---|---|
| 策略解析、限制、冷却、日志哈希链、守护重启 | 单元测试 |
| 代理实际运行和审计输出 | macOS 本机实测 |
| Linux、Windows 上的运行 | 待 CI 或真机 |
| 真实恶意程序下的处置 | 未验证 |
| Windows 驱动的保护 | 未运行过 |
