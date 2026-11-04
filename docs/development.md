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

## 新增检测规则

- 主机规则:加到 `triage.rs` 的 `RULES`,并同步 [检测文档](detection.md)。
- Sigma、序列、内容规则:加到 `rules/` 下对应文件。`--check-rules` 和单元测试会校验。
