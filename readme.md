# AutoIR_MCP

AutoIR_MCP 是 AutoIR 的 FastMCP 版本，用于通过 VS Code、Cursor 等支持 MCP 的客户端进行 Linux 主机自动化应急响应。项目通过 SSH 连接目标主机，提供用户、进程、网络、文件、后门、日志和 Rootkit 排查工具。

> 工具返回结果用于辅助 AI 分析，应急结论仍需结合现场环境人工复核。

## 功能列表

### 劫持排查

- 检查环境变量是否存在劫持风险
- 检查常见启动环境中的恶意命令

### 用户与权限排查

- 检查 `/home` 下用户目录
- 检查 `/etc/passwd` 中拥有 shell、root 或特殊权限的用户
- 检查 `/etc/shadow` 中空口令用户
- 检查 `/etc/sudoers` 与 `/etc/sudoers.d/*` 中异常 sudo 权限
- 检查用户 `authorized_keys` 免密登录配置
- 检查用户历史命令

### 进程排查

- 检查挖矿脚本和高危命令进程
- 检查异常启动命令和可疑执行路径
- 检查隐藏 PID
- 检查命令名被替换的进程
- 检查 mount 挂载类进程后门

### 网络排查

- 分析本机 IP、监听端口和对外连接
- 检查网卡信息
- 检查 `/etc/hosts` 中非标准解析记录

### 文件与 WebShell 排查

- 基于基线检查 `/usr/bin` 文件权限、属主、链接和文件类型
- 检查 `/tmp` 下可疑文件，并尽量输出权限、属主、大小和时间
- 打包下载 webroot，调用本地 HeMa 扫描疑似 WebShell

### 后门与持久化排查

- 检查 `LD_PRELOAD`、`LD_AOUT_PRELOAD`、`LD_ELF_PRELOAD`、`LD_LIBRARY_PATH`
- 检查 `ld.so.preload`
- 检查 `PROMPT_COMMAND`、alias、cron、启动项和 rc 文件
- 检查 SSH 软链接后门、SSH Server wrapper、inetd/xinetd 后门
- 检查 SUID 类后门

### 日志排查

- 分析 Apache access log 中的恶意请求、状态码、跳转和 User-Agent
- 统计成功登录和失败登录来源 IP

### Rootkit 排查

- 上传并执行 rkhunter 进行 Rootkit 检测

## 容错与安全优化

当前版本增加了以下容错和安全机制：

- SSH 命令执行统一返回 `status`、`result`、`stderr`、`exit_status` 和 `error`，失败时保留错误原因。
- 多个工具增加跨发行版 fallback，例如 `ss` 失败时尝试 `netstat`，`ip` 失败时尝试 `hostname -I`。
- 登录日志优先使用 `last`/`lastb`，不可用时 fallback 到 `/var/log/auth.log` 和 `/var/log/secure`。
- 大日志分析默认只读取最近 `max_lines` 行，避免超大日志拖慢响应。
- WebShell 扫描默认限制文件数量，并对压缩包解压做路径、类型和大小保护。
- SUID 扫描默认排除 `/proc`、`/sys`、`/dev`、`/run`、`/mnt`、`/media` 等目录。
- 空结果会明确返回“未发现明显异常”，减少静默失败。

## 安装与运行

```bash
pip install uv
git clone git@github.com:IHK-ONE/AutoIR_MCP.git
cd AutoIR_MCP
uv sync
uv run python AutoIR_MCP.py
```

## 配置

### SafeLine WAF

编辑 `config/config.json`，配置 SafeLine WAF GET 检测接口：

```json
{
  "SafeLineWAF": {
    "Server": "https://check-safeline.ihk-one.top/?input="
  }
}
```

离线环境可以将该地址替换为本地服务或通过 SSH 隧道暴露的检测接口。该接口应接收待检测内容作为 GET 参数，并在命中时返回 403。

### `/usr/bin` 基线

`config/info_bin.json` 用于 `/usr/bin` 基线对比。需要更新基线时，可准备同版本干净系统并运行：

```bash
AUTOIR_BASELINE_IP=192.168.1.10 \
AUTOIR_BASELINE_PORT=22 \
AUTOIR_BASELINE_USERNAME=root \
AUTOIR_BASELINE_PASSWORD=root \
uv run python DumpFileInfo.py
```

## MCP 使用建议

1. 首次分析先调用 `get_ssh_client` 建立 SSH 连接。
2. 连接成功后优先调用 `check_safeline`，确认 WAF 检测能力是否可用。
3. 按“基础采集 → 专项检测 → 关联验证”推进，避免重复调用已能回答问题的工具。
4. 没有明确证据时，在结论中标注“需人工复核”。

推荐巡检顺序：连接与 WAF → 用户 → 进程 → 网络 → 文件 → 后门 → 日志 → Rootkit。

## 开发命令

```bash
uv sync
python -m py_compile AutoIR_MCP.py functions.py DumpFileInfo.py
uv lock --check
git diff --check
```

当前仓库未配置单元测试或 lint 工具。
