# 开发

## 本地检查

```bash
cargo test --release --locked
cargo clippy --release --locked --all-targets -- -D warnings
```

跨平台代码要检查三个目标:

```bash
cargo clippy --release --locked --all-targets --target x86_64-unknown-linux-gnu -- -D warnings
```

```bash
cargo clippy --release --locked --all-targets --target x86_64-pc-windows-msvc -- -D warnings
```

CI 使用最新 stable,会比本地更新的 lint 和弃用警告更早报错。需要时并排安装同版本工具链,不影响默认工具链:

```bash
rustup toolchain install 1.99.1 --profile minimal -c clippy --no-self-update
```

## 模糊测试

```bash
PW_FUZZ_ITERATIONS=3000 cargo test --release --locked fuzz_ -- --ignored
```

确定性变异,覆盖所有读取不可信数据的解析器。

## CI

`.github/workflows/ci.yml` 在 Linux、macOS、Windows 上运行:构建、clippy、单元测试、模糊测试、`--selftest`、`--soak 2`、规则校验。Linux 额外以 root 运行 `--selftest` 和 `--soak 1`,覆盖 netlink、fanotify 和拦截。Windows runner 本身是管理员。

平台相关代码本地无法运行时,让 `--selftest` 用已知工作负载报告实际看到了什么,这比断言更有用:断言失败只说明错了,输出能说明错在哪。

## 约定

- 把解析和平台调用分开。解析逻辑放在跨平台代码里,这样任何机器都能测试。
- 测试不碰真实配置:设置 `XDG_CONFIG_HOME` 和 `XDG_DATA_HOME`,不在真实的自启动目录里创建文件。
- 新增后台来源必须考虑:数据量上限、丢失如何显示、线程崩溃如何处理、特权不足时说什么。
- 主线程不做阻塞工作。

## 新增模块

见[模块与微内核](modules.md)。

## 新增检测规则

- 主机规则:加到 `triage.rs` 的 `RULES`,并同步 [检测文档](detection.md)。
- Sigma、序列、内容规则:加到 `rules/` 下对应文件。`--check-rules` 和单元测试会校验。

## 测试策略

| 层 | 工具 |
|---|---|
| 单元 | 平台差异隔离在探头后;`/proc` 解析用 `tests/fixtures` 的固定样本 |
| 属性 | proptest:报警状态机、决策、规则解析 |
| 故障注入 | 模块 panic、卡死、持续返回错误,验证看门狗、退避、熔断 |
| 模糊 | 所有解析不可信输入的代码,`src/fuzz.rs` |
| 基准 | `cargo test --release bench_ -- --ignored`,有性能下限 |
| 验收 | `tests/acceptance.sh` |
| 真实内核 | CI 的 `ebpf` 作业 |
| 供应链 | `cargo deny`,配置在 `deny.toml` |

合并要求 Linux 和 Windows 的 build、clippy、test 全过。这需要在 GitHub 的分支保护里把这些作业设为必需,CI 文件本身做不到。

## 约定

最低 Rust 版本 1.95(`Cargo.toml` 的 `rust-version`,yara-x 要求)。许可证 MIT。

内核禁止 `unwrap`、`expect`、`panic!` 和索引访问,由 `src/kernel/mod.rs` 的 clippy 规则强制。

`unsafe` 只用于平台调用,集中在这些文件:

| 文件 | 用途 |
|---|---|
| `src/defense/ebpf/loader.rs` | `bpf`、`perf_event_open`、`mmap` |
| `src/defense/sniff.rs`、`src/network/pcap.rs` | 原始套接字 |
| `src/response/enforce.rs` | fanotify、WFP |
| `src/response/tamper.rs`、`src/response/agent.rs` | prctl、DACL、`chattr` |
| `src/response/driver.rs` | 过滤器通信端口 |
| `src/cli/service.rs` | 信号、服务控制 |
| `src/common/etw.rs`、`src/files/symbols.rs` | ETW、ToolHelp |
| `src/process/` 下的探头 | 平台进程 API |
