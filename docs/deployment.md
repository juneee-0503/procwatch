# 部署

## Linux

```bash
cargo build --release
```

```bash
sudo deploy/linux/install.sh target/release/procwatch
```

脚本创建 `procwatch` 系统用户,安装程序和 systemd 单元,批准当前程序和配置,然后启动服务。

| 路径 | 内容 | 所有者 |
|---|---|---|
| `/usr/local/bin/procwatch` | 程序 | root,服务账户只读 |
| `/etc/procwatch/` | 配置 | root,服务账户只读 |
| `/var/lib/procwatch/` | 日志和状态 | procwatch |

服务不以 root 运行,只拿需要的能力:

| 能力 | 用途 |
|---|---|
| `CAP_BPF`、`CAP_PERFMON` | eBPF |
| `CAP_NET_RAW` | SYN 捕获 |
| `CAP_DAC_READ_SEARCH` | 读日志和跟踪点 |
| `CAP_SYS_PTRACE` | 读其他进程的文件描述符 |
| `CAP_LINUX_IMMUTABLE` | 日志追加写 |

这份能力集**不含** `CAP_NET_ADMIN` 和 `CAP_KILL`,所以 `ban`、`kill` 这类处置不可用。要启用自动处置,需要在单元里加上它们,这会扩大权限。

沙箱选项逐项开启过,但只在 CI 的虚拟机上跑过。部分系统上 eBPF 可能和某些选项冲突,用下面的命令确认:

```bash
sudo journalctl -u procwatch -n 30
```

## Windows

以管理员运行:

```powershell
.\deploy\windows\install.ps1 -Binary target\release\procwatch.exe
```

服务账户是 `NT SERVICE\procwatch`,失败时自动重启。

## 升级

```bash
sudo deploy/linux/upgrade.sh path/to/new/procwatch
```

脚本先进入维护模式,否则升级会被保护机制当作攻击;替换程序并批准;启动失败时回到旧版本。数据和配置保留。

## 回滚

旧版本在 `/usr/local/bin/procwatch.previous`。配置的上一份已批准副本在数据目录的 `*.good` 文件里。

## 版本化

| 位置 | 版本字段 |
|---|---|
| `defense.yml` | `version` |
| 指标历史 | 每行 `v` |
| 心跳协议 | `v` |
| 报警 JSON | `v` |
| 审计日志 | `v` |
| 查询接口 | `v` |

规则:旧版本的数据能读,新版本的未知字段忽略。

当前版本写的文件里出现未知字段,按写错处理并报错,否则拼错的设置会悄悄不生效。拦截策略和代理策略始终严格,因为错字可能改变拦截范围。

## 排障

```bash
procwatch --diagnose report.txt
```

```bash
procwatch --query health
```

`--query` 问运行中的代理,它只读,只回答 `health` 和 `version`。

procwatch 自己的记录在数据目录的 `audit.jsonl`,和被监控的日志分开,超过 16 MB 轮转。
