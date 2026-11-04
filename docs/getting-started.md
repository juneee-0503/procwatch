# 快速开始

## 构建

需要 Rust stable(CI 使用最新 stable,项目在 1.98 和 1.99 上都能编译)。

```bash
cargo build --release
./target/release/procwatch
```

## 权限

大部分功能不需要特权。以下功能需要 root(macOS、Linux)或管理员(Windows):

| 功能 | 原因 |
|---|---|
| 其他用户的进程详情 | 系统访问控制 |
| 活动采集 | 使用 fanotify、fs_usage、ETW |
| Linux 精确进程事件 | netlink proc connector 需要 CAP_NET_ADMIN |
| 文件操作归属到进程 | 同上 |
| Windows 每进程流量 | 使用 ETW |
| 拦截 | 使用 fanotify 权限事件、WFP |

没有权限时功能会降级,并在采集健康页(`H`)说明缺什么、影响什么。

## 第一次调查

1. 启动后在 Processes 页按 `v` 切换到 Suspicious 视图,只看有风险评分的进程,风险最高的在前。
2. 选中进程按 `W` 打开调查工作区,查看它的事件回放、网络、文件、模块和家族。
3. 按 `D` 对它做深度追踪,此后它的子进程全部被事件驱动地捕获,哪怕只存活几毫秒。
4. 按 `H` 看采集健康页,确认结论背后的数据是否完整。**“没有发现”的可信度取决于这一页。**
5. 按 `9` 看 Detect 页的全部检测结果,按 `6` 看时间线。
6. 按 `0` 到 Case 页,`c` 采集证据,`s` 封存清单,`v` 校验。

## 用活动采集观察一个可疑程序

以管理员或 root 运行:

```bash
sudo ./target/release/procwatch
```

按 `` ` `` 到 Activity 页,按 `c` 开始采集,用 `/` 输入过滤条件,例如 `name:powershell source:registry`。按 `s` 看汇总,按 `e` 保存到案件。

## 试用拦截

```bash
./target/release/procwatch --enforce-check rules/policy/example.yml
```

这一步只显示策略将做什么,不做任何改变。详见[拦截与策略](enforcement.md)。

## 自检

```bash
./target/release/procwatch --selftest
```

约一分钟,使用无害的工作负载测量这台机器上的捕获率、PID 复用保护、活动采集和拦截是否真正生效。以 root 运行能覆盖更多项目。
