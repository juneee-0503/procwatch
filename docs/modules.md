# 模块与微内核

procwatch 由一个小内核和一组可插拔模块组成。内核只管调度和通信,所有采集都在模块里,每个模块又把“怎么采”交给按平台分开的探头。

```text
纵向:每个模块一组探头
                ┌─ probes/linux.rs
横向:模块  ────┼─ probes/macos.rs      模块定义“要采什么”
                └─ probes/windows.rs    探头实现“怎么采”

┌──────┬───────┬───────────┬─────┬─────┬─────┬─────┬────────┐
│process│network│performance│ gpu │files│logs │trace│activity│
└──┬───┴───┬───┴─────┬─────┴──┬──┴──┬──┴──┬──┴──┬──┴───┬────┘
───┴───────┴── 事件总线 ──────┴─────┴─────┴─────┴──────┴────
│ 内核:注册 生命周期 调度 看门狗 数据模型 配置 告警           │
```

## 查看和控制模块

**界面**:任何页面按 `M`。`↑↓` 选择,`空格` 启用或停用,选中项下方列出它在本系统上的能力。停用立刻生效,选择写入 `modules.conf`,下次启动继续有效。

**命令行**:

```bash
procwatch --modules
```

```bash
procwatch --module-disable gpu
```

```bash
procwatch --module-enable gpu
```

`--modules --json` 输出结构化列表,不启动任何采集。

### 模块列表

| 名称 | 职责 | 停用后 |
|---|---|---|
| `process` | 进程表、系统总量 | 进程列表和依赖它的功能不再更新 |
| `network` | 连接、每进程流量 | Network 页清空 |
| `performance` | 调度、内存、磁盘、传感器、服务 | 系统指标显示收集中 |
| `gpu` | 系统 GPU 负载 | 不显示 GPU |
| `files` | 监视目录的文件变更 | 文件变更不再记录 |
| `logs` | 系统日志,按需读取 | Logs 页提示模块未运行 |
| `trace` | 事件驱动的进程追踪 | 深度追踪不可用 |
| `activity` | 文件、注册表、网络操作 | Activity 页无法采集 |

### 模块状态

| 状态 | 含义 | 处理 |
|---|---|---|
| running | 正常 | |
| disabled | 被配置关闭 | 按 `空格` 启用 |
| unavailable | 这里跑不了,比如缺权限。**不算故障,不会重启** | 看原因 |
| restarting | 崩溃或卡死,等待自动重启 | 通常无需处理 |
| failed | 5 分钟内崩溃超过 6 次,不再重启 | 看错误,修好后按 `空格` |

## 能力声明

每个模块启动时声明自己在这个系统上支持什么,分三档:

- **supported**:完整支持。
- **partial**:可用但有限制,并说明限制是什么。
- **not supported**:这个系统没有,并说明原因。

界面显示“n/a”和原因,不显示 0、不报错。0 表示“测量结果是零”,不支持的东西不能写成 0。

## 内核的稳定性保证

监护程序自己不能死机,所以内核做这些事:

| 情况 | 内核的处理 |
|---|---|
| 模块 panic | 捕获,隔 1、2、4…最多 30 秒后用工厂重建实例 |
| 模块卡死 | 超过其声明的时限后废弃该线程,启动新实例。线程无法强杀,但旧实例的运行编号已失效,它发布的内容一律丢弃 |
| 反复崩溃 | 5 分钟内超过 6 次后停止重启,标记 failed,等待人工处理 |
| 订阅者处理不过来 | 该订阅者丢事件并计数,发布者绝不阻塞 |
| 配置写错 | 跳过并报告,不影响启动 |

模块之间不直接调用,只通过总线通信。这一点和“内核不含采集逻辑”都由测试强制(`src/architecture.rs`)。

## 配置文件

`modules.conf` 在设置文件旁边:

```text
# 关闭的模块
disabled = gpu, logs

# 系统指标告警
alert = cpu.run_queue > 16 for 30s
alert = disk.queue_depth{device=sda} >= 32 for 10s
alert = memory.available < 500000000
```

写错的行会被跳过,并显示在 `--modules` 和界面状态里。

## 指标告警

告警规则写在统一指标上,所以同一条规则在所有平台上含义相同。不支持的指标不产生数据,对应规则不会触发。

```text
指标名[{标签=值}] 比较符 数值 [for N秒]
```

比较符:`>`、`>=`、`<`、`<=`。带 `for` 时条件要持续这么久才触发。一次异常只触发一次,恢复时再通知一次。触发的告警出现在 Detect 页。

指标名见 [系统指标](metrics.md)。

## 新增一个模块

以“电池健康”为例,不需要改内核。

**1. 定义事件和探头接口**,在 `src/host/battery/mod.rs`:

```rust
pub const REPORT: &str = "battery.report";

pub struct Health { pub wear_percent: f64 }

pub trait Probe: Send {
    fn capabilities(&self) -> Vec<Capability>;
    fn read(&mut self) -> Option<Health>;
}
```

**2. 每个平台一个探头**:`probes/linux.rs`、`probes/macos.rs`、`probes/windows.rs`。平台不支持时在 `capabilities` 里声明 `Capability::no(...)`,不要返回假数据。

**3. 实现模块**:

```rust
impl Module for BatteryModule {
    fn capabilities(&self) -> Vec<Capability> { self.probe.capabilities() }
    fn interval(&self) -> Option<Duration> { Some(Duration::from_secs(60)) }
    fn tick(&mut self, ctx: &Context) {
        if let Some(h) = self.probe.read() {
            ctx.samples(vec![Sample::new("battery.wear", h.wear_percent, Unit::Percent)]);
            ctx.publish(REPORT, h);
        }
    }
}
```

**4. 注册**,在 `src/engine/mod.rs` 加一行:

```rust
r.add("battery", "battery health", || Box::new(BatteryModule::new()));
```

**5. 接到界面**(可选):在 `engine/bridge.rs` 把事件转成 `WorkerMsg`。只发 `Sample` 的话不用这一步,告警和 `--monitor` 已经能用。

**6. 把模块文件加入** `src/architecture.rs` 的检查列表。

### 模块的规矩

- 不直接调用其他模块,需要的东西订阅事件。
- `start` 返回 `Err` 表示这里跑不了,不要 panic。
- 重活放在 `tick` 或 `on_event` 里,并声明合理的 `watchdog`。超时会被替换。
- 持有的线程要能在 `Context::current()` 变为 false 或发送失败时退出。

## 目前的边界

- 模块是编译进程序的,不是运行时加载的动态库。Rust 没有稳定 ABI,动态插件要另外设计接口。
- 隔离单位是线程,不是进程。panic 和卡死能隔离;内存破坏、栈溢出、`abort` 不能。Rust 安全代码基本不会出现前者,而 `unsafe` 的平台调用是剩余风险。
- 持久化扫描、文件分析等一次性工作仍由 `engine/jobs.rs` 运行,没有做成模块。
- 模块文件之间不互相调用,但领域库之间仍有依赖,比如 `files` 用 `process` 的签名检查。依赖表见 `src/architecture.rs`。
