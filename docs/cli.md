# 命令行参考

## 退出码约定

| 退出码 | 含义 |
|---|---|
| 0 | 成功,没有发现 |
| 1 | 有发现或校验失败(适合脚本判断) |
| 2 | 用法或运行错误 |
| 3 | `--soak` 看门狗触发,或 `--enforce` 的处理线程卡住 |

## 交互

| 命令 | 说明 |
|---|---|
| `procwatch` | 启动界面 |
| `procwatch --case DIR` | 继续已有案件 |
| `procwatch --sigma DIR` | 使用指定的 Sigma 规则目录 |
| `procwatch --replay [PATH] [--from WHEN] [--to WHEN]` | 回放记录的事件历史 |
| `procwatch --run -- PROGRAM [ARGS…]` | **仅限可重置的隔离虚拟机。** 真实运行程序,从第一条指令开始追踪 |

## 基线与扫描

| 命令 | 说明 |
|---|---|
| `--snapshot FILE` | 保存基线,`-` 输出到 stdout |
| `--diff FILE [--json]` | 与基线比较,有变化时退出码 1 |
| `--sweep FILE [--json]` | IOC 扫描,有命中时退出码 1 |
| `--scan PATH… [--yara DIR] [--json]` | YARA 子集内容扫描。不跟随子目录中的符号链接,跳过 FIFO 和设备文件 |
| `--offline CASE [--iocs F] [--sigma D] [--yara D] [--artifacts D] [--json]` | 离线分析案件 |
| `--check-rules [DIR]` | 校验 Sigma 规则 |
| `--coverage [--json]` | 列出规则覆盖的 ATT&CK 技术。说明规则关注什么,不代表检出率 |

## 持续采集

```text
procwatch --monitor [--output FILE] [--minutes N] [--activity]
```

无界面运行完整流水线,把新事件写成 Elastic Common Schema 风格的 JSON 行。

- 进程事件带 `process.hash.sha256`。哈希在后台计算,一个可执行文件的头几条事件可能还没有。
- `--activity` 增加文件、注册表和网络操作,需要特权。无法启动时退出码 2,不会静默降级。
- 读取端关闭(如 `| head`)时正常退出,退出码 0。

示例:

```bash
sudo procwatch --monitor --activity --output /var/log/procwatch.jsonl
procwatch --monitor | jq 'select(.event.category[0]=="network")'
```

## 拦截

```text
procwatch --enforce-check POLICY
procwatch --enforce POLICY [--output FILE] [--minutes N]
```

见[拦截与策略](enforcement.md)。

## 质量测量

| 命令 | 说明 |
|---|---|
| `--selftest [--json]` | 用无害负载测量捕获率、PID 复用保护、文件延迟、活动采集、流量、拦截和句柄枚举 |
| `--soak MINUTES` | 无界面运行完整流水线,报告内存、CPU 和各阶段耗时。内存持续增长、线程崩溃、消息处理跟不上都算失败 |

环境变量 `PW_SELFTEST_URL` 指向一个已知大小的文件时,`--selftest` 会下载它来检验流量统计的准确性。默认不访问网络。
