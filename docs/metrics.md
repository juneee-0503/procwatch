# 系统指标

Performance 页(`2`)按 `m` 在三个视图间切换:曲线、系统指标、服务与关键进程。`↑↓` 滚动。

命令行取一次读数:

```bash
procwatch --metrics
```

```bash
procwatch --metrics --json
```

`--monitor` 每 30 秒把指标写入事件流。

## 平台支持

| 指标 | Linux | macOS | Windows |
|---|---|---|---|
| 负载、可用内存、swap | 支持 | 支持 | 支持(无负载均值) |
| 上下文切换、中断 | 支持 | **不支持** | 支持 |
| 运行队列 | 支持 | **不支持** | 支持 |
| 阻塞进程数 | 支持 | 不支持 | 不支持 |
| 缺页、换入换出 | 支持 | 部分 | 支持 |
| 压力(PSI) | 需内核支持 | **不支持** | **不支持** |
| 磁盘吞吐、IOPS | 支持 | 合计,不分读写 | 支持 |
| 磁盘队列深度、繁忙度、延迟 | 支持 | **不支持** | 支持 |
| 网络吞吐、错误、丢包 | 支持 | 无接收丢包 | 支持 |
| TCP 重传 | 支持 | 支持 | 支持(IPv4) |
| 连接数 | 支持 | 支持 | 支持 |
| 温度 | 取决于硬件 | 取决于机型 | 取决于固件 |
| 功耗 | RAPL 需 root,或电池 | 仅电池 | 仅电池放电 |
| 服务 | systemd | launchd | Windows 服务 |

macOS 上切换和队列深度没有公开接口,这是系统限制。Windows 计数器名称会本地化,非英文系统上可能读不到,界面会说明。

更新频率:Linux 2 秒,macOS 5 秒,Windows 15 秒(读取计数器要启动 PowerShell)。Windows 和 Linux 的指标目前只在 CI 里验证过解析和运行,数值没有和其他工具逐项对比过。

## 如何判断

下面的阈值是经验起点,用于界面着色,不是绝对标准。先看这台机器平时的水平。

### CPU 与调度

| 指标 | 含义 | 关注什么 |
|---|---|---|
| Load | 等待 CPU 的平均任务数(Linux 还含等磁盘) | 除以核数,长期 >1 表示排队 |
| Run queue | 此刻可运行的任务数 | 持续超过核数说明 CPU 不够 |
| Blocked | 卡在磁盘 I/O 的任务数 | 持续非零说明磁盘慢 |
| Context switches | 每秒切换次数 | 看变化。突然翻倍常见于锁竞争或线程过多 |
| CPU pressure | 10 秒内有任务等 CPU 的时间占比 | >10% 已影响延迟 |

CPU 不高但 Load 高,通常是磁盘问题,不是 CPU 问题。

### 内存

| 指标 | 含义 | 关注什么 |
|---|---|---|
| Available | 不换页就能用的内存 | 比“空闲”可靠,缓存可回收 |
| Swap used | 已用交换区 | 占用本身不一定是问题 |
| Swap in/out | 每秒换入换出页数 | **持续换出才是内存不足的信号** |
| Major faults | 需要读盘的缺页 | 持续偏高说明内存紧张 |
| Memory pressure | 因内存等待的时间占比 | >5% 已有影响 |

### 磁盘

| 指标 | 含义 | 关注什么 |
|---|---|---|
| IOPS | 每秒请求数 | 与设备能力比 |
| Queue | 平均排队加处理中的请求数 | HDD 超过 2、SSD 超过 32 要留意 |
| Busy | 设备忙碌时间占比 | SSD 上 100% 不一定饱和,要结合 await |
| Await | 每个请求平均耗时 | SSD 几毫秒内,HDD 十几毫秒内 |
| I/O pressure | 因磁盘等待的时间占比 | >10% 已有影响 |

Queue 和 Await 一起高,说明磁盘是瓶颈。

### 网络

| 指标 | 含义 | 关注什么 |
|---|---|---|
| in / out | 每接口吞吐 | 对比链路速率 |
| errors | 硬件或校验错误 | 累计值在涨就查网卡、网线、驱动 |
| drops | 丢包 | 涨说明缓冲不足或过载,行变红表示正在增长 |
| TCP retransmits | 重传段数 | 持续出现说明路径丢包 |
| Closing | 关闭中的连接 | 大量堆积常见于短连接风暴 |

Network 页和 Activity 页可以进一步定位到进程。

### 温度与功耗

温度取自系统能读到的传感器。功耗在 Linux 上来自 RAPL(只含 CPU 封装,不是整机)或电池;macOS 接电时显示 0 W 是因为电池不放电,不代表整机不耗电。

## 关键进程与服务

服务视图上半部分列出这个系统的关键进程,比如 Linux 的 `systemd`、`sshd`,macOS 的 `launchd`、`WindowServer`,Windows 的 `lsass.exe`、`services.exe`。显示实例数、CPU 和内存。“not running”不一定是故障,不是每台机器都运行所有这些进程。

下半部分是服务,失败的排在最前面,每 60 秒刷新。可以用 `/` 过滤,例如 `state:failed`。

- **Linux**:`failed` 来自 systemd。
- **macOS**:没有运行且上次退出码非零的算失败。很多按需启动的任务属于正常状态,所以这里的“失败”需要判断。
- **Windows**:设为自动启动却没有运行的算失败,其中有一些是按触发器启动的服务,同样需要判断。

## 统一指标名

告警规则和 `--monitor` 使用这些名称,单位已归一化:

| 名称 | 单位 | 标签 |
|---|---|---|
| `cpu.context_switches` `cpu.interrupts` | /s | |
| `cpu.run_queue` `cpu.blocked` | 个 | |
| `cpu.pressure` `memory.pressure` `disk.pressure` | % | |
| `memory.available` `memory.swap_used` | 字节 | |
| `memory.page_faults` `memory.swap_in` `memory.swap_out` | /s | |
| `disk.read` `disk.write` | 字节/s | `device` |
| `disk.iops` | /s | `device` |
| `disk.queue_depth` | 个 | `device` |
| `disk.busy` | % | `device` |
| `disk.await` | ms | `device` |
| `net.rx` `net.tx` | 字节/s | `interface` |
| `net.errors` `net.drops` | /s | `interface` |
| `net.tcp_retransmits` | /s | |
| `sensor.temperature` | °C | `sensor` |
| `sensor.power` | W | `sensor` |

平台不支持的指标不会出现,不会以 0 出现。

## 指标字典

全部指标的名称、单位、类型和平台差异在 `src/kernel/dictionary.rs`,用下面的命令列出:

```bash
procwatch --dictionary
```

| 类型 | 含义 | 降采样 |
|---|---|---|
| Gauge | 某一刻的值 | 平均 |
| Rate | 已换算成速率的计数器 | 平均 |
| Counter | 累计值,只有差值有意义 | 取最新 |

计数器回绕或重置(进程重启、网卡重置)时,那一次没有速率,不会产生假峰值。

每个指标最多 256 条序列,超出时淘汰最久没出现的。所有样本都带 `host`,所有报警都带 `host` 和 `instance`。

在容器里,`/proc` 可能反映宿主视角,cgroup 限额会让 CPU 使用率的分母不同。启动时会检测环境并写入自检日志。
