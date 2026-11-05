# 用户指南

按 `?` 随时查看按键帮助,按 `:` 或 `ctrl+k` 打开命令面板,按名称搜索所有操作。

## 页面

| 键 | 页面 | 内容 |
|---|---|---|
| `1` | Processes | 进程表、树、应用分组、可疑视图 |
| `2` | Performance | CPU、内存、磁盘、网络曲线 |
| `3` | Network | 连接、远端主机、DNS(`h`、`d` 切换) |
| `4` | Files | 打开的文件、文件变更(`w` 切换) |
| `5` | Persistence | 自启动项、相对基线的变化 |
| `6` | Timeline | 合并所有来源的事件时间线 |
| `7` | Logs | 系统日志、执行痕迹(`x` 切换) |
| `8` | Trace | 对单个进程的采样式行为追踪 |
| `9` | Detect | 检测结果、告警、告警规则 |
| `0` | Case | 案件、证据、发现、隔离区 |
| `` ` `` | Activity | 操作级活动采集 |

## 通用操作

| 键 | 作用 |
|---|---|
| `↑↓` `PgUp` `PgDn` `Home` `End` | 移动 |
| `/` | 过滤,`esc` 清除 |
| `f` | 查找谁打开了某个文件或端口 |
| `enter` 或右键 | 操作菜单 |
| `H` | 采集健康页 |
| `M` | 模块:状态、能力、启用或停用 |
| `W` | 调查工作区 |
| `D` | 深度追踪 |
| `l` | 选中项的关系图 |
| `m` | 把当前项记录为发现 |
| `p` | 暂停刷新 |
| `o` | 选项 |
| `q` | 退出 |

## 过滤语法

所有列表使用同一种语法,多个条件之间是“与”:

```text
chrome                  任意字段包含
pid:123  port:443       数值字段精确匹配
name:helper user:root   文本字段包含
-name:mdworker          开头的 - 表示排除
path:"/My App/x"        引号保留空格
:8080                   port:8080 的简写
```

常用字段:`pid ppid name user path cmd port ip state proto kind type source rule sev tag cluster entity team basis id`。

## Processes 页

| 键 | 作用 |
|---|---|
| `v` / `t` | 切换视图 / 进程树 |
| `←` `→` | 折叠或展开 |
| `s` / `r` | 选择排序列 / 反向 |
| `space` / `ctrl+a` | 多选 / 全选 |
| `del` / `X` | 结束 / 强制结束,有确认,并校验 PID 没有被复用 |
| `d` / `tab` / `i` | 详情面板 / 切换标签 / 全屏 |
| `z` | 冻结排序 |
| `T` | 行为追踪 |
| `R` | 清空签名和哈希缓存 |
| `e` | 导出 CSV |

可以在选项中打开 Network 列,显示每进程的网络速率。详情面板显示进程的安全上下文:

- **Linux**:用户 ID(含 setuid)、capabilities、seccomp、no-new-privs、容器、独立命名空间。
- **Windows**:完整性级别、是否提权、已启用的特权、进程承载的服务。

## Performance 页

`m` 切换曲线、系统指标、服务与关键进程,`↑↓` 滚动。各项含义和判断方法见[系统指标](metrics.md)。

## Activity 页

| 键 | 作用 |
|---|---|
| `c` | 开始或停止采集 |
| `s` | 汇总:最忙的进程、操作、目标 |
| `e` | 保存到案件(ECS JSON 行) |
| `x` | 清空 |
| `/` | 过滤,如 `source:registry kind:write path:Run` |

详见[活动采集](activity-capture.md)。

## 设置文件

macOS 和 Linux 为 `~/.config/procwatch/config`(遵循 `XDG_CONFIG_HOME`),Windows 为 `%APPDATA%\procwatch\config`。格式是 `key = value`,无法识别的行会被忽略。
