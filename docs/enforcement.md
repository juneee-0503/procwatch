# 拦截与策略

procwatch 可以按策略阻止操作。这是一项能造成实际影响的功能,所以它默认关闭、默认只审计,并且设计上不可能留下持久状态。

## 能阻止什么

| 操作 | Linux | Windows | macOS |
|---|---|---|---|
| 执行程序 `on: exec` | **事前阻止** | 需要内核驱动 | 需要 Endpoint Security |
| 打开文件 `on: open` | **事前阻止** | 需要内核驱动 | 需要 Endpoint Security |
| 联网 `on: connect` | 未实现 | **事前阻止** | 未实现 |
| 写注册表 | 不适用 | 需要内核驱动 | 不适用 |
| 启动后终止 `on: start` | 事后 | 事后 | 事后 |

**事前阻止**:操作在发生前被拒绝。Linux 上内核挂起 `open`/`exec` 等待 procwatch 的回答,被拒绝时调用方得到 `EPERM`。Windows 上由 Windows 筛选平台(WFP)在连接授权阶段拒绝。

**事后终止**:进程已经运行了,procwatch 发现后把它结束。这是响应,不是预防:轮询间隔为 250 ms,更短命的进程会在被发现前结束,已经执行的代码也无法撤销。

平台做不到的规则会让启动失败,不会被静默忽略。

## 工作流程

**1. 写策略**,从 `rules/policy/example.yml` 开始:

```yaml
mode: audit            # audit(默认)或 enforce
expires_minutes: 60    # 到期自动结束;0 表示直到手动停止

rules:
  - id: no-exec-from-tmp
    on: exec           # exec | open | connect | start
    action: block      # block | kill
    path: ["/tmp/*", "/var/tmp/*", "/dev/shm/*"]
    except: ["/tmp/our-installer/*"]
    process: ["*"]     # 可选,按进程名过滤
    note: 说明文字
```

**2. 检查**。这一步不做任何改变:

```bash
procwatch --enforce-check policy.yml
```

**3. 审计运行**。`mode: audit` 时操作全部放行,只记录“本来会阻止什么”:

```bash
sudo procwatch --enforce policy.yml --output decisions.jsonl
```

**4. 阅读记录**,确认没有误伤后再把 `mode` 改成 `enforce`。

**5. 停止**:`ctrl+c`、`kill`,或等待到期。所有拦截立刻消失。

## 规则字段

| 字段 | 必需 | 说明 |
|---|---|---|
| `id` | 是 | 唯一标识,出现在决策记录里 |
| `on` | 是 | `exec`、`open`、`connect`、`start` |
| `action` | 是 | `block`(配合 exec/open/connect)或 `kill`(只配合 start) |
| `path` | 是 | 路径模式列表。`*` 匹配任意字符,**包括 `/`**,`?` 匹配一个字符 |
| `except` | 否 | 例外的路径模式 |
| `process` | 否 | 只对这些进程名生效 |
| `note` | 否 | 说明 |

策略文件不能被其他用户写入,否则启动时拒绝。未知字段会导致策略被拒绝,防止拼写错误让规则悄悄失效。Windows 上路径不区分大小写。Windows 的 `connect` 规则必须是一个具体的可执行文件路径,不能用通配符,因为 WFP 按文件标识匹配。

路径是解析后的真实路径。macOS 上 `/tmp` 的真实路径是 `/private/tmp`。

## 决策记录

每行一个 JSON:

```json
{"time":"…","rule":"no-exec-from-tmp","outcome":"blocked","on":"exec","pid":1234,"process":"sh","path":"/tmp/x"}
```

`outcome` 取值:`blocked`、`killed`、`would block`、`would kill`。

## 安全设计

拦截写错的后果可能是系统无法登录,所以下面这些不是可选项。

**拒绝危险规则,没有绕过开关。** 内置一份系统必需文件清单(`/bin/sh`、`libc`、`/etc/passwd`、`sshd`、`lsass.exe`、`svchost.exe`、procwatch 自身等)。规则只要会匹配其中之一,整个策略就被拒绝。所以 `*`、`/usr/*`、`*.so.6`、`*.exe` 都不能用。

**进程退出后不留任何状态。** Linux 的 fanotify 组随进程关闭,内核放行所有等待者。Windows 使用动态 WFP 会话,进程退出(包括崩溃)时系统自动删除过滤器。不写防火墙规则,不改配置文件,重启后什么都不剩。

**默认到期。** 默认 60 分钟后自动结束,防止忘记关闭。

**防止挂死。** fanotify 权限事件没有超时:处理线程卡住,所有打开文件的进程都会卡住。看门狗在单次回答超过 3 秒时让 procwatch 退出,释放全部等待者。系统保持可用,优先于策略继续生效。

**procwatch 不拦截自己**,也不终止自身、父进程链、init 和 Windows 内核进程。`on: start` 不影响 procwatch 启动前已经存在的进程。

**不接入 TUI。** 拦截只能通过命令行显式启动,界面里没有可以误按的开关。

## 已知局限

- **fanotify 只覆盖真实文件系统**,跳过 proc、sysfs 等虚拟文件系统。
- **`on: exec` 拦截的是 execve。** 脚本经解释器运行(`sh /tmp/x.sh`)时,被执行的是 `sh`,需要 `on: open` 规则才能拦住读取。动态库加载也不算 exec。
- **`on: open` 无法区分读和写。** 打开被拒绝时读写都失败。
- **进程名来自 `/proc/<pid>/comm`**,最长 15 字节,且可被进程自己修改。不要把 `process` 当作安全边界。
- **拦截不是防篡改。** root 可以结束 procwatch,这在设计上是允许的。
- **性能:** `on: open` 让系统里每次打开文件都经过 procwatch,在高负载机器上开销明显。优先用 `on: exec`。
- **Windows 过滤器按文件标识匹配。** 文件被替换或复制到别处后不再匹配。

## 验证状态

| 能力 | 状态 |
|---|---|
| 规则校验、模式匹配 | 单元测试 |
| 事后终止 | macOS 真机、Linux CI 实测(50 ms);Windows 的测试修复后待 CI |
| Linux 执行拦截 | CI 实测通过:审计模式放行并记录;强制模式匹配程序被拒、其他程序照常运行;结束后恢复 |
| Windows 网络拦截 | CI 实测通过:curl 连接在过滤器生效期间失败,结束后恢复 |

## Windows 文件和注册表拦截

这部分需要驱动,源码在 [`driver/windows/`](../driver/windows/README.md)。**驱动从未被加载运行过**,只有在 CI 的 WDK 步骤通过时才算编译过。

| 规则 | 说明 |
|---|---|
| `on: open` | 阻止打开文件用于写入或删除 |
| `on: registry` | 阻止修改键和值 |

```yaml
mode: enforce
rules:
  - { id: guard-tools, on: open, action: block, path: ['C:\\Tools\\*'] }
  - { id: guard-run, on: registry, action: block, path: ['HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run*'] }
```

驱动没有加载时,这些规则会让策略启动失败,而不是静默不生效。

驱动的限制:

- 路径只支持末尾的 `*`。
- 不支持 `process` 和 `except`。
- 注册表根只支持 `HKLM` 和 `HKU`。`HKCU` 因用户而异,请写成 `HKU\\<SID>\\…`。
- 不阻止读取和程序启动。程序启动用 `on: start` + `kill`。
- 决策写入内核调试日志,不会回到 `--enforce` 的输出。

要在正式环境使用,需要 EV 代码签名证书、微软认证签名和微软分配的 altitude。这些只能由项目所有者申请。

macOS 的文件拦截仍然没有实现,需要 Apple 授权的 Endpoint Security。
