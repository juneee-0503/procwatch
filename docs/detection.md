# 检测

procwatch 有四个检测引擎。检测结果汇总在 Detect 页(`9`),每条带严重性、置信度、ATT&CK 技术和证据。

## 优先级

优先级来自最强命中的严重性乘以置信度,再加少量增量,而不是把分数累加。十个低置信度命中不会盖过一个高置信度的严重命中。

## 主机规则

| ID | 名称 | 严重性 | 置信度 | ATT&CK |
|---|---|---|---|---|
| PW-001 | 代码签名无效 | High | High | T1554 |
| PW-002 | 未签名的可执行文件 | Low | Low | |
| PW-003 | 运行中可执行文件已被删除 | High | Medium | T1070.004 |
| PW-004 | 从临时或用户可写目录运行 | Medium | Low | T1204.002 |
| PW-005 | 隐藏文件名 | Low | Medium | T1564.001 |
| PW-006 | 系统进程名出现在系统目录之外 | High | Medium | T1036.005 |
| PW-007 | 文档、浏览器或 Web 服务启动了 shell | High | Medium | T1059 |
| PW-008 | 反弹 shell 命令行 | Critical | High | T1059.004 |
| PW-009 | 编码的 PowerShell 命令 | High | Medium | T1027.010 |
| PW-010 | 下载后立即执行 | High | Medium | T1105 |
| PW-011 | 解码并运行内嵌载荷 | High | Medium | T1140 |
| PW-012 | 脚本化的管理员提权提示 | High | Medium | T1548 |
| PW-013 | 不受信任的程序接受连接 | Medium | Low | T1571 |
| PW-014 | 未签名程序访问互联网 | Low | Low | T1071 |
| PW-015 | 特权进程来自可写目录 | High | Medium | T1574 |
| PW-016 | 规律性重连(信标) | Medium | Medium | T1071.001 |
| PW-017 | 被终止后重新启动 | Medium | Medium | T1543 |
| PW-018 | 行为偏离自身历史 | Low | Medium | |
| PW-019 | 自启动项被添加或修改 | Medium | High | T1547 |
| PW-020 | 通过环境变量预加载库 | High | Medium | T1574.006 |
| PW-021 | 从内存运行,磁盘上没有文件 | High | High | T1620 |
| PW-022 | 写入自启动注册表位置 | Medium | High | T1547.001 |

几点说明:

- PW-020 需要进程的环境变量,只在检查该进程时触发,不是全量扫描。
- PW-021 目前只在 Linux 上触发(可执行路径为 `/memfd:`)。
- PW-022 需要 Windows 上运行活动采集。

## Sigma 规则

内置 14 条,位于 `rules/sigma/procwatch-builtin.yml`。把规则放到设置目录的 `sigma/` 下,或用 `--sigma DIR` 指定。

支持 Sigma 的子集:`selection` 映射和列表、`|contains`、`|startswith`、`|endswith`、`and`/`or`/`not`、括号、`1 of`、`all of`。不支持聚合(`| count()`)。用 `--check-rules` 查看哪些规则不能用、原因是什么。条件最多嵌套 64 层。

## 行为序列规则

内置 7 条,位于 `rules/behavior/procwatch-builtin.yml`,描述“先 A 后 B”:

```yaml
id: pw-seq-001
title: File written, then executed
within: 600s
scope: any            # any | tree | process
steps:
  - event: file_write
    capture: { file: path }
  - event: process_start
    where: { image: "{file}" }
```

事件类型:`process_start`、`process_exit`、`file_write`、`file_open`、`module_load`、`net_connect`、`net_listen`、`persistence_change`、`detection`。条件比较不区分大小写,支持 `|contains`、`|startswith`、`|endswith`,`{name}` 引用捕获的值。`count: 5` 加 `distinct: name` 表示累计不同的值。

## 内容规则

内置 6 条 YARA 风格规则,位于 `rules/yara/procwatch-builtin.yar`,只匹配磁盘上的文件,从不读取进程内存。

这是 YARA 的子集,不是完整实现。条件 4096 词以内,嵌套 64 层以内,十六进制模式的回溯有步数上限,单个文件最多扫描前 64 MB。

## 误报抑制

检测可以按规则、进程、路径抑制,被抑制的命中仍可查看,只是不再计入优先级。

## 覆盖度

```bash
procwatch --coverage
```

列出每个 ATT&CK 技术由哪些规则关注。目前 33 个技术、40 条映射。这说明规则在看什么,不代表能检出,也没有经过红队验证。
