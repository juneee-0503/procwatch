# 与专业工具对比

这份对比尽量不夸大。procwatch 的优势在于把分散的能力放进一个可审计的调查流程,而不是在单项上超过专门工具。

| 能力 | 专业工具 | procwatch | 差距 |
|---|---|---|---|
| 进程树、详情 | Process Explorer、System Informer | 有,含安全上下文、特权、服务 | 无 GPU 引擎细节、无线程栈符号解析(Windows) |
| 文件和注册表操作 | Procmon | 有,基于 ETW,含返回状态、注册表读取、事件调用栈、开机日志、配置化过滤 | 符号只到导出函数,无 PDB;开机日志待真实重启验证 |
| 句柄 | handle.exe、System Informer | 有 | 不显示命名管道名称 |
| 网络连接 | TCPView | 有 | |
| 抓包 | Wireshark、tcpdump | `--capture-packets` 存 pcap | 无解析和 BPF 过滤,用 Wireshark 打开 |
| 每进程流量 | Nethogs、资源监视器 | 有 | Linux 仅 TCP,Windows 回环未计入 |
| 自启动项 | Autoruns | 有,三平台 | Autoruns 覆盖的类别更多 |
| 系统指标 | iostat、vmstat、PerfMon | 调度、磁盘队列、丢包、温度、服务 | macOS 无切换和队列深度;无长期历史 |
| 进程事件日志 | Sysmon | `--monitor`、`capture.yml` 过滤 | ETW 缓冲区溢出仍会丢事件,但会报告数量;无驱动 |
| 拦截 | EDR | Linux 文件、Windows 网络;Windows 文件和注册表靠驱动 | 驱动只有源码,从未加载,需要微软签名 |
| 自动响应 | EDR | `--agent` 剧本、防篡改日志 | 单机;管理员可停止,无 PPL |
| 内容规则 | YARA | YARA-X,完整语法和模块 | 不含 cuckoo、magic 模块;只扫磁盘文件,不扫内存 |
| 日志规则 | Sigma 工具链 | 子集 | 无聚合 |
| 内存取证 | Volatility | **不做** | 项目边界 |
| 取证流程 | Velociraptor、KAPE | 保管链、证据登记、离线分析 | 无跨主机采集 |
| 跨主机 | EDR、osquery fleet | 无 | 只看本机 |
| 信誉情报 | VirusTotal | **不做** | 项目边界 |

## 什么时候用 procwatch

- 需要在一台机器上快速调查,并保留可校验的证据。
- 需要在三个操作系统上用同一套流程。
- 没有条件安装驱动或代理。

## 什么时候不要用

- **需要防御真实攻击者时不能替代商业 EDR。** 防篡改只提高难度,攻击者拿到 root 仍可结束它,也没有集中管理。
- 需要带 PDB 符号的完整调用栈。
- 需要内存取证。
- 需要管理很多台机器。
