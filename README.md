# procwatch — 跨平台 TUI 进程监视器(Rust)

面向 Windows / macOS 的终端进程监视工具,风格类似 Process Hacker /
Process Explorer 的精简终端版。附带一个 Linux 后端作为"自检用的第三平台",
方便在任何开发机上先把整体架构跑通。

## 文档

完整文档在 [docs/](docs/README.md):[快速开始](docs/getting-started.md)、[用户指南](docs/user-guide.md)、[命令行参考](docs/cli.md)、[系统指标](docs/metrics.md)、[模块与微内核](docs/modules.md)、[活动采集](docs/activity-capture.md)、[拦截与策略](docs/enforcement.md)、[检测](docs/detection.md)、[调查与证据](docs/investigation.md)、[与专业工具对比](docs/comparison.md)、[故障排查](docs/troubleshooting.md)、[架构](docs/architecture.md)、[开发](docs/development.md)。

## 构建状态

macOS(aarch64)上 `cargo build` / `cargo test` / `cargo clippy --all-targets` 零警告,并在真实终端中
逐屏驱动验证。Linux 与 Windows 在 GitHub Actions 上实际运行:clippy、单元测试、解析器模糊测试、`--selftest`、
`--soak 2` 和规则校验全部通过(提交 `1160a9e`,CI 运行 41842370540)。这两个平台只在 CI 的无界面环境里跑过,
尚未在真实系统上交互使用;Windows 上是 Windows Server 虚拟机,不是桌面系统。

## 界面

```
 procwatch  1 Processes  2 Performance  3 Network  4 Activity        CPU 8%  Memory 25 GB / 48 GB  ● 1.5s
 /  Search processes…                             View All processes ▾   Sort CPU ↓   1015 processes
  Name                          PID  User       CPU ↓    Memory  Threads      Disk   CPU time
  rustrover                   10216  analyst     6.8%    2.9 GB      177  5.3 KB/s   51:03.05
  ▸ RustRover  8 processes           analyst     6.7%    3.3 GB      360
── Overview  Performance  Threads  Open files  Network  Modules  Environment ─────── rustrover 10216
 Parent       launchd 1                         CPU          6.8%  avg 5.1%
 ...
 ↑↓ select  enter actions  / search  v view  s sort  space multi-select  d details  ?  help  q quit
```

- **不用 F 键**:所有功能都是字母键或方向键,底部提示栏只显示当前场景可用的按键。
- **Enter / 右键 = 操作菜单**:结束、强制退出、结束进程树、挂起/恢复、优先级(很高/高/普通/低/很低)、
  发送信号、复制(PID/名称/路径/命令行)、在访达中显示、只看此应用/此用户。破坏性操作会弹出说明后果的确认框。
- **详情面板**:选中即在列表下方显示,不用切换屏幕;`i` 或双击打开全屏详情。

## 功能

| 功能 | 说明 |
|---|---|
| 三种视图(`v`) | 全部进程 / 进程树 / 按应用分组(helper 进程归入所属 .app,汇总 CPU、内存、线程) |
| 搜索(`/`) | 名称、PID、路径、参数、用户;`:8080` 筛选使用该端口的进程;树视图保留匹配项的父进程 |
| 查找占用(`f`) | 输入端口或文件路径片段,列出正在使用它的进程,回车跳转 |
| 多选(空格) | 选中多个进程或整个应用组后批量操作,`ctrl+a` 全选 |
| 结束进程 | `del` 结束(先确认),`X` 强制退出;结束后 3 秒仍在运行会提示强制退出 |
| 详情面板 | 概览(含代码签名)、性能曲线、线程、打开的文件、网络连接、模块、环境变量 |
| Performance 页 | CPU 历史 + 每核迷你曲线、内存/交换、网络收发、磁盘读写 |
| Network 页 | 全系统 TCP/UDP 连接(含进程名)+ 网卡流量;回车跳到对应进程 |
| Activity 页 | 进程启动/退出日志(时间、父进程、运行时长、命令行) |
| 列 | 18 种可选列(名称、PID、用户、状态、CPU、CPU 迷你曲线、内存、线程、磁盘、CPU 时间、启动时间、优先级、命令行等),窄窗口自动隐藏次要列 |
| 选项(`o`) | 刷新间隔、默认视图、详情面板、结束前确认、新进程高亮、列;自动保存 |
| **自动研判**(视图 `v` → Suspicious) | 每次刷新为每个进程打 0–100 风险分并列出理由:签名无效 / 未签名、运行中可执行文件被删除、位于临时或用户可写目录、隐藏文件名、冒充系统进程名、Office/浏览器/Web 服务器拉起 shell、反弹 shell / 编码 PowerShell / 下载即执行等命令行、可被外网访问的监听、未签名程序连接公网地址、root 从可写目录运行、周期性回连(beaconing)。分数含义是"先看这个",不是"这是恶意程序"。进程表新增 Risk、Signed 列;签名与哈希由 4 个后台线程缓存计算,`R` 清空缓存重算 |
| **IOC 扫描**(Case 页 `I`) | 读取指标文件(默认为设置目录下的 `iocs.txt`),自动识别 MD5/SHA-1/SHA-256、IP、域名(匹配子域名)、路径、`"引号文本"`,支持 `hxxp`、`[.]` 等去武装写法和 `#` 注释;与进程可执行文件哈希、路径、命令行、网络连接、反向解析主机名、持久化项、事件日志逐一比对。结果页 `enter` 跳到进程,`m` 把命中记录为发现,`r` 重新扫描。命令行:`procwatch --sweep iocs.txt [--json]`,有命中时退出码 1 |
| **周期性回连检测** | 按"进程 + 远端地址:端口"统计重复连接的时间间隔,至少 5 次、平均间隔 ≥ 2 秒且间隔足够规律时标记为 "every ~Ns",并计入风险分;容忍采样间隔带来的抖动 |
| **远端主机视图**(Network 页 `h`) | 按远端地址汇总:反向解析名、端口、涉及的进程、当前连接数、累计建立次数、首次/最后出现时间、回连规律;连接表新增 Age 列(连接已存在多久) |
| **持久化分析**(Persistence 页) | macOS:LaunchAgents/LaunchDaemons、cron、第三方内核扩展、系统扩展、shell 启动文件;Linux:systemd 单元、cron、autostart、内核模块、`/etc/ld.so.preload`、`/etc/rc.local`、profile.d;Windows:Run/RunOnce 注册表键、启动文件夹、服务、计划任务、驱动。本轮新增:hosts 文件、`authorized_keys`(标记 `command=`)、sudoers(标记 NOPASSWD)、macOS 登录项(需 `sudo` 运行,否则提示)、StartupItems、SecurityAgent 插件、emond 规则;Linux root 的 crontab 与 authorized_keys、init.d、udev `RUN+=`;Windows Winlogon、IFEO、AppInit_DLLs、WMI 事件订阅。每项附目标可执行文件的 SHA-256、签名状态、修改时间,并标记可疑原因(未签名/签名无效、位于临时或用户可写目录、目标文件缺失、7 天内被修改、隐藏文件名、内联脚本或下载执行)。`c` 切换到"基线以来的变化" |
| **文件分析** | 对任意文件计算 MD5/SHA-1/SHA-256、按魔数识别类型、大小与创建/修改/访问时间、权限与属主、数字签名(完整校验含资源)及证书信息、macOS 下载来源(quarantine 属性与 WhereFroms);**深度分析**:Mach-O / Fat / ELF / PE 头(架构、PE 链接时间戳、ASLR/DEP/CFG)、整体熵值(提示加壳/加密)、字符串指标(URL、IP、邮箱、可疑 API/命令关键字)、macOS 权限声明(entitlements,高风险项标红)。报告可用 ↑↓/PgUp/PgDn 滚动 |
| **文件变更监控** | 监视下载目录、临时目录和自启动目录(可在设置文件用 `watch = 路径` 自定义),创建/修改/重命名/删除事件进入时间线 |
| **DNS 分析**(Network 页 `d`) | DNS 服务器、正在使用 DNS 套接字的进程、远端地址反向解析(后台缓存,连接表增加 Remote host 列)、Windows DNS 客户端缓存 |
| **事件日志**(Logs 页) | macOS 统一日志 / journalctl / Windows 事件日志(System、Application、Security),可选时间窗口(5 分钟–24 小时)与"重要/全部",重复消息合并计数 |
| **时间线分析**(Timeline 页) | 进程启动/退出、网络连接建立/关闭、文件变更、告警、行为追踪、事件日志、案件操作合并为一条按时间排序的时间线,支持 `source:` 等字段过滤;`tree:PID` 只看某进程及其全部后代的事件(选中事件按 `t` 自动填入),`e` 导出 CSV |
| **内存分析**(详情 → Memory) | 地址空间按区域类型统计(虚拟/常驻/数量)、可写可执行(W+X)区域计数、异常模块(已删除、来自临时目录、未签名);Windows 通过 VirtualQueryEx 统计已提交区域(映像/映射/私有)、W+X 区域与私有可执行区域。**不读取、不导出任何内存内容**(见下文"为什么不做内存转储") |
| **证据采集**(Case 页) | 案件目录 + 只追加的取证链日志(custody.log);一键采集系统快照(系统信息、进程、连接、时间线、文件变更、告警、持久化项、事件日志);进程证据包(进程属性、模块、句柄、线程、环境变量、签名、内存报告、可执行文件哈希,可选复制可执行文件,副本设为只读);`s` 生成 SHA-256 清单(含 `sha256sum -c` 格式),`v` 重新校验并报告被修改/缺失/新增的文件 |
| **应急处置** | 结束进程(已有);文件隔离:移入案件 quarantine 目录、去除全部权限、记录原路径/哈希/权限,可在 Case 页 `R` 原样恢复;网络隔离:`i` 生成 pf / nftables / Windows 防火墙的隔离脚本与恢复脚本(可保留一个管理 IP),**只生成、不执行**,由人工审阅后以管理员身份运行 |
| **报告系统** | 任意页面按 `m` 记录发现(可用 `high:` / `low:` 前缀设定级别),`a` 分析笔记,`C` 调查结论;`e` 导出 report.md / report.json / report.html,包含结论、发现、笔记、可疑持久化项、网络连接、告警、时间线、证据清单及哈希、完整取证链 |
| **统一事件过滤** | 所有页面(进程、网络、文件、活动、追踪、告警、变化)使用同一套语法:自由文本,或 `pid:` `ppid:` `name:` `user:` `path:` `cmd:` `port:` `ip:` `state:` `proto:` `kind:` `type:` `fd:` `rule:` 字段过滤;多个条件取交集,前缀 `-` 表示排除(如 `-name:mdworker`),`:443` 等同 `port:443` |
| **进程关系**(详情 → Relations) | 完整祖先链、直接子进程(含其下后代数量)、兄弟进程、同一可执行文件的其他实例,以及通过本机 TCP 互相通信的进程(按连接端点配对) |
| **调用栈**(详情 → Stack) | 按需采样约 1 秒:macOS 使用系统 `sample` 工具显示每个线程的调用图与最热函数;Linux 显示各线程的等待点(wchan)及内核栈(需 root);Windows 暂不支持 |
| **句柄**(详情 → Handles) | 进程打开的文件描述符 / 句柄列表,底部按类型统计(REG、DIR、IPv4、PIPE…) |
| **数字签名详情** | 概览中显示签名状态并真正校验(macOS 直接调用 Security.framework;列表中跳过资源校验以保证速度,文件分析中做完整校验),附标识符、Team ID、签名时间、证书链;Windows 显示颁发者、指纹、有效期、时间戳 |
| **网络连接** | 本地 IP / 端口、远端 IP / 端口分列,连接状态、协议、所属进程;监听端口标注"network(可被外部访问)/ local";顶部汇总已建立连接数、远端地址数、监听数 |
| **文件系统**(Files 页) | 全系统所有进程打开的文件一览(按需扫描,`r` 重新扫描),可按路径、类型、进程过滤,回车跳到进程 |
| **行为追踪**(`T`) | 选中进程按 `T`(或操作菜单"Trace behavior"):跟踪该进程及其后续派生的全部子进程,时间线记录子进程启动/退出(含命令行与父进程)、网络连接建立/关闭、监听端口、文件打开/关闭、CPU 峰值与内存增长;侧栏汇总远端地址、监听端口、文件目录分布、峰值资源与 CPU 时间;`c` 按类型筛选,`e` 导出 Markdown + JSON 报告;所有被追踪进程退出后自动停止 |
| **告警规则**(Alerts 页) | 用自然语言写规则:`cpu > 80% for 10s`、`mem > 2GB name=chrome`、`growth > 20MB/min`、`start ssh`、`exit nginx`、`listen`、`connect :25`;每个进程每次越线只告警一次,恢复后重新布防;标题栏显示未读数,可选桌面通知;规则保存在设置文件中 |
| **基线对比**(Persistence 页 `c`) | 按 `b` 把当前状态(正在运行的程序 + 监听端口)保存为基线;之后列出新增程序、新开端口、已停止的程序、已关闭的端口,并标出端口是否可被网络访问(非回环地址)。替换基线前确认,旧基线保留为 `baseline.prev.json` |
| **命令行模式** | `procwatch --snapshot base.json` 保存基线;`procwatch --diff base.json [--json]` 对比当前状态,有变化时退出码为 1,适合 cron / CI 定期检查 |
| **内存泄漏检测** | "Mem trend" 列对约 30 秒的内存历史做最小二乘拟合,显示每分钟增长量,持续增长标红 |
| 其他 | `e` 导出 CSV,`p` 暂停,点击表头排序,新进程绿色高亮 |
| **导出进程内存转储** | ❌ 故意不实现,见下文 |
| 进程注入 / API 挂钩 / 内存读写 | ❌ 不实现,超出监视工具范畴 |

### 各平台数据来源

| 数据 | macOS | Linux | Windows |
|---|---|---|---|
| 线程数 / 优先级 / CPU 时间 | `proc_pidinfo(PROC_PIDTASKINFO)` | `/proc/<pid>/stat` | Toolhelp32 + `GetProcessTimes` |
| 内存 | 物理占用 footprint(`proc_pid_rusage`,与活动监视器一致) | RSS | 工作集 |
| 谁在用某文件 | 全系统 `lsof -F` | `/proc/*/fd` | 不支持(需 handle.exe),端口可查 |
| nice | `getpriority` | `/proc/<pid>/stat` | 优先级类映射 |
| 线程列表 | `PROC_PIDLISTTHREADS` + `PROC_PIDTHREADINFO` | `/proc/<pid>/task` | Toolhelp32 线程快照 |
| 打开文件 | `lsof -F` | `/proc/<pid>/fd` | 仅句柄数(逐句柄枚举需 Sysinternals handle.exe) |
| 环境变量 | sysinfo(KERN_PROCARGS2) | `/proc/<pid>/environ` | sysinfo(PEB) |
| 模块 / 签名 | `vmmap` / `codesign` | `/proc/<pid>/maps` / — | PowerShell `Get-Process -Module` / `Get-AuthenticodeSignature` |

读取其他用户的进程通常需要提升权限,读不到的字段显示为 `-`,属性页里会写明原因。

### 为什么不做内存转储

Process Hacker、Process Explorer 甚至 Windows 任务管理器本身都有"创建
内存转储文件"这个按钮,技术上这是完全合法的系统功能(调试崩溃用的),
但它也是从 `lsass.exe` 提取明文凭据的经典攻击手法(Mimikatz 等工具就是
对着 `lsass.exe` 调用同一个 `MiniDumpWriteDump`)。考虑到这个双重用途
风险和具体的滥用场景已经相当成熟和知名,我选择不在这个项目里提供
"一键转储任意进程内存"的现成功能。如果你出于合法的调试目的确实需要这个
能力,Windows 任务管理器("创建转储文件")和 Process Explorer 本身已经
提供,不需要靠这个工具重新实现。

### 挂起/恢复/终止不是"黑客技巧"

- **结束进程**:"结束进程"发送 SIGTERM(Windows 为 `taskkill`,即任务管理器的"结束任务"),进程可以先保存;3 秒后仍未退出会提示可强制退出。"强制退出"发送 SIGKILL(Windows `TerminateProcess`)。
- **信号**:Unix 下通过 `kill(2)` 发送标准 POSIX 信号(SIGTERM/SIGKILL/SIGHUP/SIGINT/SIGQUIT/SIGSTOP/SIGCONT/SIGUSR1/SIGUSR2),与 `kill(1)`、活动监视器相同。Windows 下 "End task" 走 `taskkill`(发 WM_CLOSE,进程可保存后退出),"Terminate" 走 `TerminateProcess`,等价于任务管理器"结束任务"。
- **挂起/恢复**:macOS 用标准 POSIX 信号 `SIGSTOP`/`SIGCONT`(`kill -STOP`/`kill -CONT`,这是 shell 内建行为)。Windows 用的 `NtSuspendProcess`/`NtResumeProcess` 是半文档化的 NT 原生 API,但这正是微软官方 Sysinternals 工具包里 `pssuspend.exe`(微软自己签名、公开分发的工具)使用的同一套机制,不是什么地下技巧。

### GPU 限制(如实说明,不打马虎眼)

Windows 和 macOS 都**不对第三方应用提供稳定公开的"按进程"GPU 占用率
API**:
- **Windows**:有"GPU Engine"性能计数器,按引擎(不是严格按进程语义)
  上报利用率,覆盖率因厂商/驱动而异。本项目对所有引擎的利用率求和,
  当作"系统整体 GPU 占用率"展示,标注清楚不是按进程的数字。
- **macOS**:没有任何公开 API。活动监视器的 GPU 列用的是苹果内部私有
  框架。唯一公开途径是 `powermetrics`,但它要求 `sudo` 且是系统整体
  采样——让一个 TUI 工具为了画个 GPU 条天天要求提权,这个代价我认为
  不值得,所以 macOS 下 GPU 面板会诚实显示"不可用"并给出手动查看方法,
  而不是伪造一个看起来很真但其实瞎编的数字。

## 项目结构

微内核加插件模块。结构、依赖规则和新增模块的方法见 [docs/architecture.md](docs/architecture.md) 和 [docs/modules.md](docs/modules.md)。

```
src/
├── kernel/        微内核:总线、生命周期、看门狗、数据模型、配置、告警
├── common/        路径、命令运行器、文本、节奏控制
├── process/       进程、检查、深度追踪、句柄
├── network/       连接、DNS、流量
├── files/         文件监视、分析、内容规则
├── host/          自启动项、日志、工件
├── performance/   系统指标、服务、GPU
├── activity/      操作级采集
├── detection/     检测引擎
├── forensics/     案件、证据、历史、导出
├── response/      拦截
├── engine/        模块注册、到界面的桥接
├── app/  ui/  cli/
```

## 构建

```bash
cargo build --release
./target/release/procwatch                       # 交互界面
./target/release/procwatch --snapshot base.json  # 保存基线
./target/release/procwatch --diff base.json      # 对比;有变化时退出码 1
./target/release/procwatch --sweep iocs.txt     # IOC 扫描;有命中时退出码 1
./target/release/procwatch --scan ~/Downloads   # YARA 子集内容扫描
./target/release/procwatch --offline procwatch-case-…  --artifacts ./copied-evidence   # 离线分析
./target/release/procwatch --check-rules        # 校验 Sigma 规则
./target/release/procwatch --selftest           # 测量捕获率、PID 复用保护等质量指标
./target/release/procwatch --soak 10            # 10 分钟无界面稳定性测试
./target/release/procwatch --monitor --output events.jsonl   # 无界面持续采集,输出 ECS JSON 行
./target/release/procwatch --coverage           # 规则覆盖的 MITRE ATT&CK 技术
./target/release/procwatch --enforce-check rules/policy/example.yml   # 检查拦截策略,不做改变
./target/release/procwatch --replay             # 回放本机记录的事件历史
./target/release/procwatch --run -- ./sample    # 仅限隔离分析虚拟机:启动并从第一条指令开始追踪
./target/release/procwatch --case procwatch-case-20261102-101500   # 继续已有案件
```

设置文件:macOS/Linux 为 `~/.config/procwatch/config`(遵循 `XDG_CONFIG_HOME`),Windows 为
`%APPDATA%\procwatch\config`。查看其他用户的进程详情需要管理员权限(`sudo`)。

## 按键

| 键 | 作用 |
|---|---|
| `↑↓` `PgUp` `PgDn` `Home` `End` | 移动 |
| `1`–`9`、`0`、`` ` `` | Processes / Performance / Network / Files / Persistence / Timeline / Logs / Trace / Alerts / Case / Activity |
| `m` | 把当前选中项记录为调查发现 |
| 操作菜单 → Investigate | 分析可执行文件 / 采集进程证据(可复制可执行文件)/ 记录发现 / 隔离可执行文件 |
| Files 页 | `a` 分析选中文件,`A` 输入路径分析,`Q` 隔离,`w` 切换"打开的文件 / 文件变更" |
| Persistence 页 | `enter` 分析目标文件,`Q` 隔离目标,`c` 基线变化,`r` 重新扫描 |
| Logs 页 | `w` 时间窗口,`a` 重要/全部,`r` 重新读取 |
| Network 页 | `d` DNS 视图,`h` 远端主机视图 |
| Timeline 页 | `t` 只看选中事件所属进程树,`e` 导出 CSV |
| Processes 页 | `R` 清空签名/哈希缓存并重算 |
| Case 页 | `n` 新案件,`c` 采集,`s` 封存清单,`v` 校验,`a` 笔记,`C` 结论,`i` 隔离脚本,`I` IOC 扫描,`e` 导出报告,`tab` 切换发现/隔离列表,`R` 恢复隔离文件,`del` 删除发现 |
| Files 页 | `r` 重新扫描,`enter` 跳到进程 |
| `T` | 追踪选中进程的行为(Trace 页:`x` 停止,`c` 筛选类型,`e` 导出报告,`enter` 跳到进程) |
| Alerts 页 | `a` 新建规则,`tab` 切换告警/规则列表,`space` 启用/停用,`del` 删除,`c` 清空告警 |
| `enter`(或右键) | 操作菜单 |
| `/` | 搜索(`:端口` 按端口筛选),`esc` 清除 |
| `f` | 查找占用某端口或文件的进程 |
| `v` / `t` | 切换视图 / 直接切到进程树 |
| `←` `→` | 折叠 / 展开树节点或应用组 |
| `s` / `r` | 选择排序列 / 反向;也可点击表头 |
| `空格` / `ctrl+a` / `esc` | 多选 / 全选 / 取消选择 |
| `del` / `X` | 结束进程 / 强制退出 |
| `d` / `tab` / `i` | 显示隐藏详情面板 / 切换详情标签 / 全屏详情(全屏中 `1`–`9` 切换标签:概览、关系、性能、线程、调用栈、句柄、网络、模块、环境变量;`r` 刷新/重新采样,`esc` 返回) |
| `z` | 冻结列表顺序(数值继续实时更新);另外移动选择后 4 秒内顺序自动保持,视图栏显示 "order held" |
| `p` | 暂停全部刷新 |
| `e` | 导出 CSV |
| `o` | 选项 |
| `?` | 帮助 |
| `q` | 退出(全屏详情中为返回) |

鼠标:点击选择,双击打开详情,右键打开操作菜单,点击表头排序,点击视图名称切换视图,滚轮滚动。

## 架构要点(性能与健壮性)

- **UI 线程永不阻塞**:采样、网络表、GPU、深度检查、进程操作、全系统文件查找都在后台线程。
- **增量刷新**:每次只刷新 CPU/内存/磁盘 I/O;路径、命令行、用户只在进程首次出现时读取。
- **详情按需读取**:选中停留 300ms 后才读取;耗时的模块列表(vmmap/PowerShell)只在打开"模块"标签时读取。
- 缓存以 `pid + 启动时间` 为键,PID 复用不会串数据;只格式化可见行;列宽按显示宽度计算,中文不错位。
- 外部命令都有超时;信号与优先级直接走系统调用;拒绝对 procwatch 自身发信号。
- panic / 出错 / Ctrl+C 都会恢复终端;设置文件先写临时文件再改名。
- **后台线程隔离**:所有工作线程都包在 `catch_unwind` 中,线程 panic 只在状态栏报错,不会破坏终端或退出程序;采样线程出错后继续下一轮。
- 外部命令输出有上限(日志最多 96 MB,超出时注明),控制字符被清理,不会污染终端。
- 持久化扫描并行补全签名/哈希并复用进程缓存;macOS 签名快速校验走 Security.framework(跳过资源校验),扫描从约 40 秒降到约 6 秒。
- procwatch 自己启动的辅助命令(codesign、log 等)不进入时间线,也不参与研判,避免自我噪声。
- 无读权限的文件(如 `/usr/bin/sudo`)签名状态显示为"未知"而不是误报"无效"。

## 调查模型与检测引擎(本轮)

- **统一实体模型**(`model.rs`):进程实例以 `PID + 启动时间` 标识(PID 复用不串),文件、网络端点、持久化项、用户、规则、证据、主机都是实体;时间线事件带稳定 ID(`T-xxxxxxxx`)、主体与关系。
- **调查图谱**(任意页面 `l`):以选中项为中心展示父子进程、可执行文件、用户、连接端点、打开的文件、启动它的持久化项、检测、证据;`enter` 继续展开,`←` 返回,`t` 查看该实体的全部时间线事件,`g` 跳到所在页面。
- **检测引擎**(9 Detect 页):16 条内置主机规则(PW-001…016)与 Sigma 规则统一输出检测,每条含规则 ID、严重度、置信度、ATT&CK 技术、匹配到的证据、首次/最后出现时间。优先级(Risk 列)= 最强命中的严重度×置信度,再为其他独立命中少量加分,**不再简单相加**,多个弱信号不会盖过一个强信号。
- **误报抑制**:`S` 按过滤条件(如 `path:"/Applications/My Tool.app"`)抑制某条规则并写明原因,保存在设置目录的 `suppressions.txt`,记入取证链;被抑制的命中仍保留(`u` 显示),但不计入优先级。
- **Sigma 子集**(`sigma.rs`):支持 logsource、选择器、通配符、`contains/startswith/endswith/all/exists/cidr/gt/gte/lt/lte/windash` 修饰符和 `and/or/not/1 of/all of` 条件;不支持的写法(`re`、聚合、关联规则)会被拒绝并说明原因,不会被静默误判。统一字段映射层把进程、连接、文件变更、系统日志、EVTX(Sysmon 1/3/11、Security 4688 等)映射为 Sigma 字段。内置 14 条规则;自定义规则放在设置目录的 `sigma/`,或用 `--sigma DIR` 指定,`--check-rules` 校验。
- **执行痕迹**(Logs 页 `x`):Windows Prefetch(17/23/26/30/31,含 Win10+ 的 Xpress-Huffman 压缩)、ShimCache、BAM、Defender 检测记录;任意系统可解析 .evtx;macOS/Linux 读取 shell 历史。每类都注明时间戳含义、局限和能支持的结论(例如 ShimCache 的时间是文件修改时间,不能证明执行过)。`A` 导入从其他机器复制来的文件夹。
- **时间线**:区分事件时间(操作系统记录)与观测时间(`~` 标记,真实时间最多早一个刷新周期);持久化定义文件写入时间、检测、执行痕迹也进入时间线;`b` 按阶段加书签(初始异常 / 可疑执行 / 持久化 / 网络 / 处置 / 恢复验证),进入报告的「关键事件」;`c` 查看**活动簇**:同一进程树在 2 分钟内出现多种行为(执行 + 网络 + 文件/持久化/检测),文件与持久化只通过明确路径关联加入。
- **采集健康度**(任意页面 `H`):列出每个数据源是可用、部分、拒绝访问、缺失还是未加载,以及受影响的规则——「没有检测到」只代表「没有观测到」。
- **证据可信度**:取证链日志改为哈希链(每条记录含 `chain=`,篡改、删除或重排任一条都会使其后全部失效);`evidence.json` 证据登记表记录编号、类别(原始 / 副本 / 派生 / 报告)、来源、方法、工具版本、状态(完整 / 部分 / 失败)和缺失原因;封存时写入 `seal.json`(含链头哈希),校验时同时检查清单、链和报告是否被事后修改。链头哈希显示在 Case 页和报告中,应记录在案件之外——拥有写权限的人仍可整体重写本地文件,这一点无法单靠本地文件解决。
- **自动调查摘要**:报告新增「调查摘要」,按活动簇用固定规则生成(观察到什么、哪些检测、哪些证据、结论措辞),每一行都附事件 ID。
- **离线分析**:`procwatch --offline CASE [--iocs FILE] [--sigma DIR] [--artifacts DIR]... [--json]` 在不接触原主机的情况下,对案件中已采集的数据和导入的 .evtx/.pf/历史文件重新运行主机规则、Sigma 与 IOC 匹配;结果作为派生证据写回案件,有中等以上命中时退出码为 1。

- **注册表 hive 解析**(`regf.rs`):只读解析离线 hive 文件(任意系统上可用),据此读取 **Amcache.hve**(InventoryApplicationFile:完整路径、SHA-1、发布者、版本、链接时间)以及离线 **SYSTEM** hive 中的 ShimCache 与 BAM(自动选择 `Select\Current` 指向的 ControlSet)。在 Logs 页 `A` 导入或 `--offline --artifacts DIR` 中自动识别。解析结果已与独立实现 regipy 交叉验证(由测试生成的 hive)。
- **内容规则(YARA 子集)**(`yara.rs`):文本串(`ascii` `wide` `nocase` `fullword`)、十六进制串(`??`、半字节通配、跳转 `[n-m]`)、条件(`and/or/not`、`$a at N`、`$a in (a..b)`、`#a`、`any/all/N of (…)`、`filesize`、`uint8/16/32`)。正则、模块(`pe.` 等)、`for` 循环会被拒绝并说明原因。规则的 `meta` 中 `severity` / `confidence` 决定检测的严重度与置信度。内置 6 条规则;自定义规则放在设置目录的 `yara/`。只扫描磁盘上的文件,**不读取进程内存**。
  - 文件分析报告中显示命中的规则及位置;Case 页 `Y` 扫描所有运行中进程的可执行文件(多线程,本机 747 个可执行文件约 1.5 秒),命中进入检测并计入进程优先级;`procwatch --scan PATH... [--yara DIR] [--json]` 命令行扫描;`--offline` 会扫描案件中复制的文件。
  - 用真实 YARA 4.5.4 对同一组样本交叉验证,结果一致。procwatch 自身(包含规则文本)会被自动跳过,避免自我误报。
- **某一时刻的系统状态**(Timeline 页 `s`):以选中事件的时间为准,重建当时在运行的进程、打开的连接、已定义的自启动项,并单独列出「此后才新增或修改的自启动项」。每一行标注「观测」(procwatch 当时在采样)或「推断」(早于 procwatch 启动,仅凭时间戳);早于 procwatch 启动的连接、启动前就已结束的进程会明确说明无法得知。

已知局限:Windows 部分(Prefetch/BAM/ShimCache/Defender/Amcache 实时采集、EVTX 通道读取)只通过了类型检查和用合成数据做的单元测试,**未在 Windows 真机运行过**;Xpress-Huffman 解码器和 hive 解析都与独立实现交叉验证过,但未用真实 Windows 文件测试;hive 的事务日志(.LOG1/.LOG2)不会回放,早期(2017 年前)Amcache 格式不支持。USN Journal、MFT、SRUM 需要 NTFS / ESE 解析,本轮未实现;TUI 内的离线案件回放未实现(离线分析通过 `--offline` 命令行完成)。

## 进程中心深度追踪(本轮)

- **深度追踪(Deep Trace)**:对选中进程按 `D`(或操作菜单 → Investigate → Deep trace)开启事件驱动的生命周期追踪,并自动跟随它创建的所有子孙进程。
  - macOS 使用 kqueue 进程通知(fork / exec / exit,无需特殊授权),在 fork 发生时立即列出并监视新子进程;Linux 每 50 ms 轮询 `/proc` 子进程;Windows 每 100 ms 进程快照。事件带毫秒时间戳并注明采集方式。
  - 对被追踪进程每 3 秒快照打开的文件、每 20 秒快照加载的模块,差异成为「文件打开/关闭」「模块加载」事件;监视目录中的文件变更若当时正被某个被追踪进程打开,会归属到该进程。
  - **自动调查**:优先级 ≥ 45 的进程会被自动纳入深度追踪(最多 16 个根进程)。
  - 实测(`--selftest`,本机 3 次运行):1.5 秒采样只捕获到存活 0/50/300/2000 ms 子进程中的 0/0/1/4 个,深度追踪 4/4/4/4;事件顺序(spawn ≤ exec ≤ exit)零违规。
- **进程调查工作台**(任意页面 `W`,或操作菜单):以一个进程实例为对象,汇总关联进程、文件事件、网络事件、模块、规则命中、自启动项计数,并分页显示:
  1. **Summary** 自动行为摘要:每一句都标明依据(observed 观测 / rule 规则 / inferred 推断)并引用事件 ID,末尾列出「此视图看不到什么」。
  2. **Replay 行为回放**:按时间逐条回放(←/→、PgUp/PgDn),右侧显示该时刻运行中的子进程、打开的连接、已接触文件数、检测——只重建已记录的事件,不会重新运行程序。
  3. **Network** 进程级通信画像:每个远端的连接/关闭次数、当前连接、平均连接时长、首次/最后、周期性回连;注明操作系统不提供进程级字节数,因此不显示流量。
  4. **Files** 文件活动热力图(目录 × 时间)。
  5. **Modules** 模块可信性:磁盘上是否仍存在(系统库在共享缓存中会单独说明)、是否位于可写目录、签名、是否在首次检查后才加载、是否为可执行文件的静态依赖(否则标注「运行时加载」)。
  6. **Family** 祖先与全部子孙进程(含已退出)。
  - `e` 导出 **Quick Analysis Report**(Markdown + JSON)到案件,作为派生证据登记。
- **深化的二进制结构分析**:PE 节区(权限、熵)、导入表(库与函数)、导出数、可写可执行节、加壳节名、入口点异常、运行时解析导入;按导入组合提示能力(进程注入、挂钩、截屏、服务安装、下载等)。Mach-O 段/节、链接库、rpath、加密标志、代码签名命令;ELF 节区、DT_NEEDED、可写可执行段、可执行栈。链接库列表与 `otool -L` 在 5 个系统程序上逐一比对一致。
- **可靠的处置**:每个进程操作都带上进程启动时间,执行前重新核对——PID 已被复用时拒绝执行并说明;结果逐个记录(完成 / 已退出 / PID 被复用而跳过 / 失败及原因),全部写入取证链。终止后自动验证进程是否真的消失;30 分钟内同一可执行文件再次运行会产生 **PW-017 Relaunched after termination** 检测,并列出指向它的自启动项作为「候选」(不是已证实的原因)。
- **质量指标**:`procwatch --selftest [--json]` 在本机用无害负载测量短生命周期进程捕获率、事件顺序、PID 复用保护、文件事件延迟(本机 12 ms)和自身开销(本机约 5% CPU、16 MB);采集健康度(`H`)显示当前平台的实际验证状态。

平台验证状态:macOS 已在真实系统上交互与自动测试;Linux 与 Windows 仅编译通过并通过单元测试,深度追踪的 Linux/Windows 实现尚未在真机运行。

## 可信度、底层能力与特色功能(本轮)

### 可信度
- **持续集成**:`.github/workflows/ci.yml` 在 Linux、macOS、Windows 三个平台上执行:`clippy -D warnings`、全部单元测试、解析器模糊测试、`--selftest`、`--soak 2`、规则校验。三平台实测结果见下表(提交 `1160a9e`,CI 虚拟机上的单次运行,不代表所有环境)。

  | | macOS | Linux | Windows |
  |---|---|---|---|
  | 单元测试(另有 5 个模糊测试) | 98 | 96 | 93 |
  | 深度追踪方式 | kqueue | procfs 轮询(20 ms) | ETW 或 ToolHelp(100 ms) |
  | 抓到最短命进程 | 0 ms 档 4/4 | 0 ms 档 1/4(上一轮 0/4),50 ms 档 4/4 | ~30 ms 档 4/4(同档采样 0/4) |
  | 事件顺序错误 | 0 | 0 | 0 |
  | PID 复用保护 | 全部正确 | 全部正确 | 全部正确 |
  | 文件变化通知延迟 | 18 ms | <1 ms | <1 ms |
  | soak 2 分钟:最终内存 / 预热后增长 | 41.5 MB / +1.7 MB | 22.8 MB / +2.0 MB | 31.4 MB / +2.4 MB |
  | soak 消息处理占比 | 1% | 0% | 9% |
  | soak 单次快照处理最长 | 32.6 ms | 14.9 ms | **2222 ms** |

  测试数量不同是因为部分测试只在对应平台编译(Unix 进程测试、Mach-O、codesign 等)。延迟 `<1 ms` 是取整后显示 0 的结果。
- **解析器模糊测试**(`src/fuzz.rs`):对所有读取不可信数据的解析器(PE/Mach-O/ELF、Prefetch/Xpress、ShimCache、注册表 hive、EVTX、YARA/Sigma 规则、IOC、shell 历史、base64)做确定性变异测试,要求不崩溃、单个输入 2 秒内完成。已发现并修复两个真实问题:YARA 转义序列遇到多字节 UTF-8 时崩溃;universal Mach-O 的 slice 指回自身时无限递归。运行:`cargo test --release fuzz_ -- --ignored`(`PW_FUZZ_ITERATIONS` 控制次数)。
- **长时间稳定性**:`procwatch --soak MINUTES` 无界面运行完整流水线(采样、检测、深度追踪、时间线重建、离屏渲染所有页面),在无害的进程更替负载下记录内存、CPU 和缓冲区大小;内存持续增长、后台线程崩溃、消息处理占用超过运行时间 80% 或超过结束时间仍未退出,都判为失败;输出里列出各类消息的数量和耗时。本机 3 分钟:常驻内存约 60–70 MB,预热后增长 ≤10 MB(深度追踪缓冲区填充至上限前)。

### 底层能力
- **持久事件历史**:所有观测到的事件(进程启动/退出、网络、文件、深度追踪、模块/文件快照差异、检测、自启动项变化,以及每 10 分钟一次的进程表快照)按天写入 JSON Lines,位于用户数据目录(macOS `~/Library/Application Support/procwatch/events`,Linux `~/.local/share/procwatch/events`,Windows `%LOCALAPPDATA%\\procwatch\\events`),上限 256 MB / 14 天,设置文件 `history = off` 可关闭。案件采集时会把本次会话的历史复制为 `evidence/events.jsonl`。
- **回放**:`procwatch --replay [历史目录|案件目录|events.jsonl] [--from 时间] [--to 时间]` 在不接触现场系统的情况下打开记录,时间线、调查工作台与行为回放、图谱、某一时刻状态、检测全部可用;结束进程、隔离、采集等会作用于现场的操作在回放中被禁用。
- **按程序建立行为基线**:按 SHA-256 记住每个程序在本机的连接目的地、子程序、非系统模块、监听端口;运行 ≥3 次且累计观察 ≥1 小时后基线成立,此后出现从未有过的行为即报 **PW-018**(低严重度,注明"在 N 次运行中首次出现")。目的地很多的程序(浏览器等)和回环地址不报新目的地。
- **自启动项实时监控**:自启动目录有变化时 3 秒后自动重扫(另外启动 30 秒后首扫、之后每 15 分钟),新增/修改/删除进入时间线并报 **PW-019**;若当时有被深度追踪的进程打开着该配置文件,则标出写入者。
- **更真实的事件来源**:
  - Windows 深度追踪优先使用 ETW Microsoft-Windows-Kernel-Process(需管理员),否则每 100 ms 快照。
  - 文件操作归属到进程:Linux 以 root 运行时使用 fanotify;macOS 以 root 运行时对被追踪进程运行 `fs_usage`。普通权限下仍按打开文件快照推断,并在采集健康度中说明。
  - DNS 查询与连接关联:有 Sysmon(事件 22)时,把连接的地址对应到"哪个进程查询了哪个域名",优先同一进程;否则主机名来自反向解析并明确标注。

### 特色功能
- **启动并追踪**:`procwatch --run -- 程序 [参数…]` —— 程序在第一条指令前被挂起,深度追踪同步挂接后才放行(Unix:fork 后 SIGSTOP 再 exec;Windows:CREATE_SUSPENDED),程序输出写入案件日志并登记为证据,退出状态记入取证链。启动前有确认界面:**只应在可重置的隔离分析虚拟机中使用**,procwatch 观察程序,但不隔离它。
- **行为序列规则**(`rules/behavior/*.yml`,用户规则放在设置目录的 `behavior/`):多步骤、带时间窗口和范围(同一进程树 / 同一进程 / 任意)、可捕获字段并在后续步骤引用、可计数去重。内置 7 条:写入后执行、写入脚本后由解释器执行、下载工具后从临时目录运行、移除隔离属性后运行程序、新增自启动项且其程序随后外连、短时间内大量侦察命令、shell 启动后外连。均已用无害负载实测触发。
- **可信发布者**:在 Detect 页对检测按 `T`,只对弱信号(未签名、可写目录、外连、监听、基线新行为)信任该发布者;签名无效、攻击模式、Sigma/YARA/行为规则永不被这样屏蔽。
- **签名信任链**:文件报告显示 macOS Gatekeeper/公证结论;Windows 显示签名类型(嵌入 / 目录)与证书链及吊销状态。
- **标准格式导出**(Case 页 `X`):STIX 2.1 bundle(已用官方 `stix2` 库和模式校验器验证)、MISP 事件、ECS 字段的时间线 JSON Lines。
- **命令面板**:`:` 或 `ctrl+k`,按名称模糊搜索并执行任何操作。

### 代码审查修复

一次针对主线程阻塞、不可信输入、子进程和资源上限的审查修复了以下问题,均有回归测试或已在三平台类型检查:

- **安全**:Windows 验签把可执行文件路径放进 PowerShell 单引号字符串时只转义了 `'`,而 PowerShell 也把 `‘ ’ ‚ ‛` 当作单引号,攻击者可用文件名注入命令;现在全部转义。隔离脚本的管理地址必须是合法 IP/CIDR。隔离区恢复不再信任记录文件:校验路径在隔离区内、哈希一致、原路径为绝对路径。
- **崩溃**:路径首字符为多字节字符时的字节切片 panic;过短的 `sha256` 字段导致的 panic。
- **卡死**:孙进程继承管道时 `run_command` 的超时会失效;主线程同步运行 PowerShell 取 DNS 信息(最坏约 35 秒);健康页每次绘制都启动 `journalctl`;主线程读取可执行文件(最多 32 MB)。这些都已移到后台。
- **数据**:内容相同的两个文件进入隔离区时记录互相覆盖,第一个无法恢复;`write_atomic` 未落盘且临时文件名固定;事件历史的 256 MB 上限只在启动时检查,长期运行不会清理;自启动项写入者记录满后丢弃的是最新而非最旧的;规则捕获的路径含 `{}`(Windows 常见的 GUID 目录)时永远匹配不上。
- **性能与积压**:规则引擎按步骤分桶,事件只接触等待该类型的序列;证据链追加不再重新哈希整个日志;界面绘制时缓存链校验结果;sysinfo 改为两阶段刷新,读不到的受保护进程最多重试 3 次;界面处理不过来时采样线程暂停,不再堆积快照;文件事件每秒上限 2000 条,丢弃数量显示在采集健康页。

第二轮审查针对上一轮未覆盖的模块:

- **进程操作**:`start_time` 读不到时不再盲目执行动作,PID 复用保护没有缺口;Windows 上被拒绝访问的受保护进程不再被误报为已退出;拒绝向 init 或 Windows 内核进程发信号。
- **规则解析**:Sigma/YARA 条件限制嵌套深度和长度(栈溢出无法捕获),十六进制模式的回溯有步数上限。
- **不可信文件**:`--scan` 不跟随子目录符号链接;哈希、YARA 和格式分析都拒绝 FIFO 和设备文件;工件解析拒绝超过 1 GB 的文件;畸形 `authorized_keys` 不再让整个持久化扫描崩溃。
- **数据准确性**:socket 表读取失败时保留上次结果,不再产生"全部关闭、全部新建"的假事件;Linux 僵尸进程不再被误报为 exec;告警状态按进程实例记录,删除规则后不再错位。
- **证据**:重新采集时旧文件移到 `evidence/earlier/`,不再被覆盖;重复复制同一文件不再失败。
- **其他**:Windows `--run` 的参数引号遵循 `CommandLineToArgvW` 规则;ETW 事件循环在高负载下不再饥饿;启动失败时不留下停止状态的子进程。

新增测试:所有页面和浮层在 1×1 到 200×60 的终端下渲染、两万次随机导航按键、构造的恶意规则。这两项 UI 测试没有发现崩溃。

### 对比专业工具后新增

- **Linux 内核进程事件**:以 root 运行时用 netlink proc connector 取得精确的 fork/exec/exit,失败时回退轮询;`--selftest` 和采集健康页显示实际方式。
- **安全上下文**(进程详情):Linux 的 capabilities、seccomp、no-new-privs、setuid、容器和独立命名空间;Windows 的完整性级别、提权状态和进程承载的服务。
- **新检测**:PW-020 通过环境变量预加载库(检查进程时触发);PW-021 从 memfd 运行、磁盘上没有文件。
- **自启动项**:Windows 增加 LSA 包、BootExecute、Netsh 助手、打印监视器;macOS 增加 periodic 脚本和 at 作业。
- **`--monitor`**:无界面运行完整流水线,持续输出 ECS JSON 行,读取端关闭时正常退出。
- **`--coverage`**:列出各引擎规则覆盖的 ATT&CK 技术。它只说明规则关注什么,不代表检出率。

### 进程活动、句柄与流量

**Activity 页**(按 `` ` ``,`c` 开始或停止采集)按 Process Monitor 的方式列出带进程的文件、注册表和网络操作,使用通用过滤语法,如 `source:registry name:powershell`。`--monitor --activity` 把同样的事件以 ECS JSON 行输出。

| 能力 | Windows | Linux | macOS |
|---|---|---|---|
| 文件操作 | ETW Kernel-File(管理员):打开、创建、读、写、删除、重命名 | fanotify(root):打开、写、关闭;5.9 起含创建、删除、移动 | fs_usage(root) |
| 注册表 | ETW Kernel-Registry:创建键、删除键、写值、删值 | 不适用 | 不适用 |
| 网络操作 | ETW Kernel-Network:连接、接受、断开 | 采样差分 | 采样差分 |
| 每进程流量(Net 列) | ETW,TCP 和 UDP(管理员) | sock_diag,**仅 TCP** | nettop |
| 句柄与打开的文件 | 原生句柄表枚举 | /proc | lsof |

与 Procmon 的差别,使用前应当知道:

- 这些来源都不用内核驱动,所以拿不到驱动才有的返回状态、调用栈和进程启动前的事件。
- 注册表**只记录写操作**:读取量比写入高几个数量级。
- 相同操作在 250 ms 内合并,显示为 `×n`;每秒超过 2 万条的部分被丢弃,丢弃数显示在页面和采集健康页,不会悄悄丢失。
- 缓冲区保留最近 20 万条。开启采集有实际开销,默认关闭。
- 只有被深度追踪的进程的文件操作进入时间线,其余只在 Activity 页。
- Linux 流量只统计 TCP,且只能归属到有权读取 `/proc/<pid>/fd` 的进程;已关闭的套接字只计入最后一次采样时的数字。
- 句柄枚举只把句柄复制到本进程查询,不读目标进程内存;其他用户的进程需要管理员权限,受保护进程无法打开。命名管道不查询名称,因为这类调用可能永久挂起。

向自启动注册表位置写入时触发 PW-022,并且能指出是哪个进程写的。

### 拦截

`--enforce POLICY` 按策略阻止操作:Linux 上事前阻止执行和打开文件(fanotify 权限事件),Windows 上事前阻止程序联网(WFP),三平台都能在进程启动后结束它。默认只审计;会匹配系统必需文件的规则直接拒绝;procwatch 退出后所有拦截自动消失。Windows 的文件和注册表拦截需要内核驱动,没有实现。详见 [docs/enforcement.md](docs/enforcement.md)。

与专业工具相比仍然没有的:Windows 文件和注册表拦截、调用栈、完整的 YARA 语法。内存取证和在线信誉查询是有意不做的。

### 仍未完成 / 未验证
- Windows 上 sysinfo 的进程列表刷新不稳定:同样的代码在不同 CI 运行里平均 70 ms 到 1.2 秒,最长约 5 秒,原因未定位。它在模块线程里,不影响界面。
- Windows 上 soak 早先多次跑不到终点。为消息循环加上时间预算、优化 `cluster` 后跑通,但两项改动是一起上线的,没有单独验证究竟是哪一项解决了问题。
- Linux 的精确进程事件(netlink)需要 root 或 CAP_NET_ADMIN。CI 以 root 实测 0 ms 档为 4/4,普通用户回退轮询时为 0–1/4。
- Windows 上自测输出没有标明实际用的是 ETW 还是 ToolHelp;~30 ms 进程 4/4 被抓到说明很可能是 ETW,但这是推断。
- Windows 的 `--run`、Amcache/BAM/Prefetch 实时采集,以及 Linux 的 fanotify,仅通过类型检查和单元测试,CI 没有运行这些路径。
- macOS 的 `fs_usage` 归属需要 root,本轮只测了输出解析,没有以 root 实际运行。
- Endpoint Security 需要苹果签发的授权,未接入;macOS 上 DNS 查询日志的域名被系统脱敏,无法做进程级 DNS 关联。

## 已知的简化之处

- 线程 / 打开文件 / 模块 / 环境变量是快照,详情底部显示获取时间,按 `r` 刷新。
- 按应用分组在 macOS 上依据 `.app` 包路径,其他平台按进程名。
- 基线对比按"可执行文件路径 + 用户"识别程序,短暂运行的命令(如脚本里的 `grep`)也会算作新程序;使用随机端口的程序每次都可能出现新端口。
- 文件变更事件来自操作系统的文件通知接口,不包含"是哪个进程改的"。
- 网络隔离脚本只生成不执行;执行后 DNS、更新和远程管理都会中断,直到运行恢复脚本。
- 行为追踪基于采样(进程与连接每次刷新,文件约每 2 秒),比采样间隔更短的活动可能捕获不到;报告中已注明。Windows 上追踪不含文件事件。
- 风险分基于启发式规则,会有误报与漏报;请把它当作排查顺序,而不是结论。
- 周期性回连基于采样到的连接建立时间,间隔短于采样周期或使用长连接的程序不会被识别。
- macOS 登录项需要以 root 运行才能读取(普通用户运行时会提示,不会弹出密码框)。
- macOS 上很多空闲进程被 sysinfo 报告为运行状态。
- 磁盘 I/O 为进程级读写字节数,包含缓存命中。
