# 活动采集

活动采集回答“这个进程具体做了什么”,按操作记录文件、注册表和网络行为,并带上执行者。它不需要内核驱动,使用各系统公开的观测接口。

## 使用

- **界面**:按 `` ` `` 到 Activity 页,`c` 开始或停止。
- **流式**:`procwatch --monitor --activity`。

采集默认关闭,因为它有实际开销。

## 各平台能力

| 能力 | Windows | Linux | macOS |
|---|---|---|---|
| 来源 | ETW Kernel-File、Kernel-Registry、Kernel-Network | fanotify | fs_usage |
| 权限 | 管理员 | root | root |
| 文件 | 打开、创建、读、写、删除、重命名 | 打开、写、写后关闭;5.9 起含创建、删除、移动 | 写、创建、重命名、删除、属性 |
| 注册表 | 创建键、删除键、写值、删值 | 不适用 | 不适用 |
| 网络 | 连接、接受、断开 | 连接(采样差分) | 连接(采样差分) |
| 验证状态 | CI 实测 | CI 实测(部分,见下) | 待验证,`fs_usage` 从未以 root 运行 |

## 与 Procmon 的差距

| 能力 | Procmon | procwatch |
|---|---|---|
| 文件、注册表操作 | 有 | 有(Windows ETW) |
| 返回状态 | 全部 | 文件操作和注册表操作,显示在 Result 列 |
| 注册表读取 | 有 | 有,需在 `capture.yml` 开启 |
| 调用栈 | 有,带 PDB 符号 | 有,需开启;符号只到导出函数 |
| 开机早期 | 有 | 有,`--boot-log`,待真实重启验证 |
| 过滤 | 界面配置 | `capture.yml` |

## 过滤配置

`capture.yml` 放在设置文件旁边(macOS 和 Linux 上通常是 `~/.config/procwatch/`),活动采集开始时读取。

```yaml
registry_reads: false   # 注册表读取,数量远大于写入
stacks: false           # Windows 事件的调用栈
rules:
  - { action: include, path: ["*\\Temp\\*"] }
  - { action: exclude, class: [file], op: [read], path: ["*\\Windows\\*"] }
  - { action: exclude, process: ["SearchIndexer.exe"] }
```

规则按顺序匹配,第一条命中的决定结果,没有命中时保留。一条规则的所有条件都要满足,每个条件内列出的是任选其一。

| 字段 | 含义 |
|---|---|
| `action` | `include` 或 `exclude`,必填 |
| `class` | `file`、`registry`、`network` |
| `op` | 操作名,如 `read`、`open`、`set value` |
| `path` | 目标路径,支持 `*` 和 `?` |
| `process` | 进程名,支持 `*` 和 `?` |

未知字段会报错。文件有错误时采集不会启动,以免在没有过滤的情况下产生大量数据。用下面的命令检查:

```bash
procwatch --capture-check
```

路径和操作的过滤在采集端进行,节省内存。进程名的过滤要等名称解析后才能进行,所以 `process` 规则不减少采集端的工作量。

## 返回状态

Windows 上,文件操作要等到完成事件才能知道结果。procwatch 把操作保留最多 2 秒等待结果,超时后不带结果显示,Result 列为空。

成功和失败分开合并,同一路径上的失败不会被成功淹没。失败在界面上以警告色显示,ECS 输出写入 `event.outcome` 和 `event.reason`。

## 调用栈

设置 `stacks: true` 后,Windows 内核在每个事件发生时记录调用栈。在活动页按 `Enter` 查看,进程详情的 Stack 标签也会显示最近捕获到的调用栈。

地址这样解析:

| 显示 | 含义 |
|---|---|
| `ntdll.dll!NtCreateFile+0x14` | 导出函数加偏移 |
| `app.exe+0x1a20` | 模块内,前面没有导出函数 |
| `<unbacked>!0x7ff…` | 不属于任何已加载文件的代码,常见于注入或 JIT,值得留意 |
| `kernel!0xffff…` | 内核地址 |

函数名来自磁盘上 DLL 的导出表,**没有读取目标进程内存**。所以内部函数只能显示到最近的导出函数,名称可能并不准确。要得到准确的内部函数名需要 PDB 符号服务器,目前没有实现。

调用栈有开销:每个事件多几十到几百字节,解析时要枚举模块。进程很快退出时可能取不到模块列表,此时显示为 `<unbacked>`,不代表可疑。

procwatch **不提供** Windows 上空闲线程的实时调用栈。那需要读取目标进程内存,超出项目边界。

## 开机早期事件

Windows 上用 ETW AutoLogger,在内核启动时开始记录,早于服务和登录。

```bash
procwatch --boot-log enable
```

重启后登录,然后读取:

```bash
procwatch --boot-log read
```

记录内容:文件的创建、打开、删除、重命名,注册表操作,进程启动。文件读写太多,没有记录。

记录会一直进行,直到 `read` 停止它,或文件达到 512 MB。日志在 `%SystemRoot%\System32\LogFiles\WMI\`。不再需要时要关闭:

```bash
procwatch --boot-log disable
```

CI 无法重启,所以只验证了配置的写入和删除,以及用同类会话产生日志后的读取。真实重启尚未验证。

Linux 上用 systemd 单元提前启动 `procwatch --monitor --activity` 可得到类似效果,早于该单元的事件看不到。

## 可靠性

ETW 是有损的:事件产生得比回调处理得快时,内核缓冲区满了就丢弃。procwatch 把缓冲区增大到 256 KB × 最多 256 个,并报告丢失数量,`--selftest` 和 `--boot-log status` 都会显示。

这不等于驱动级可靠。驱动在操作发生时同步运行,不会丢事件;ETW 不行。

## 数据量控制

采集可能每秒产生几万条事件,所以有明确的处理规则,而且**丢失是可见的**:

1. 250 ms 内相同的(进程、操作、目标)合并成一条,显示 `×n`,字节数累加。
2. 每秒超过 2 万条新事件时丢弃多余部分。Linux 内核队列溢出也计入。
3. 丢弃总数显示在 Activity 页、采集健康页和保存到案件的证据说明里。
4. 内存里保留最新 20 万条。

CI 测量:Windows Server 虚拟机 2 分钟压力下保留 20 万条,丢弃 6250 条,消息处理占主线程 1%,内存约 89 MB。

## 与其他功能的联动

- **时间线**:被深度追踪的进程的文件操作进入时间线,可用于行为序列规则。其余只在 Activity 页,否则时间线会被淹没。
- **PW-022**:向自启动注册表位置写入时产生检测,并指出写入的进程。
- **证据**:`e` 把内容存为 `activity.jsonl`,带哈希和来源说明,有丢弃时登记为不完整。

## 每进程流量

| 平台 | 来源 | 权限 | 范围 |
|---|---|---|---|
| Windows | ETW Kernel-Network | 管理员 | TCP、UDP;**回环流量未被计入**(CI 观察到,原因待确认) |
| Linux | sock_diag | 无需 root | **仅 TCP**;只能归属到有权读取 `/proc/<pid>/fd` 的进程;套接字关闭后最后一段数据不再计入 |
| macOS | nettop | 无需 root | TCP、UDP,含回环。4 MiB 回环测得 4.0 / 4.0 MiB(真机) |

Processes 页的 Network 列显示速率(接收加发送),启动后首个样本只作基准。

## Windows 句柄枚举

详情页的 Open 列表和 `f` 查找在 Windows 上由原生句柄枚举提供,不再依赖 handle.exe。

工作方式:读取系统句柄表,把句柄复制到 procwatch 进程,查询类型和名称。**不读取目标进程内存。**

- 其他用户的进程需要管理员权限,受保护进程无法打开。
- 命名管道不查询名称,因为这类调用可能永久挂起且无法取消。
- 枚举运行在带看门狗的线程里。卡住时放弃该线程,从下一个句柄继续;最多放弃 8 次。
- 进程句柄显示为 `process N`,可用来发现谁持有 lsass 之类进程的句柄。

CI 测量:本进程 21 个具名对象 6 ms,全系统 1024 个打开的文件 175 ms。
