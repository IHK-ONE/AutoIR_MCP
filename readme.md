# AutoIR_MCP

AutoIR_MCP 是 AutoIR 的 FastMCP 版本，用于通过支持 MCP 的客户端对 Linux 主机执行自动化应急响应。工具通过 SSH 连接目标主机，提供用户、进程、网络、文件、后门、持久化、日志和 Rootkit 排查能力。

> 工具结果用于辅助分析，最终结论仍需结合现场环境人工复核。

## 架构

```plain
AutoIR_MCP/
├── AutoIR_MCP.py              # 兼容入口，运行 autoir_mcp.server:mcp
├── autoir_mcp/
│   ├── server.py              # FastMCP app、工具注册、编排工具
│   ├── prompts.py             # MCP instructions、AUTOIR_MCP 艺术字、报告规范
│   ├── functions.py           # SSH 命令、SFTP、fallback、SafeLine、本地规则
│   ├── schemas.py             # 结构化结果辅助
│   ├── session.py             # SSH session 状态模型
│   ├── transport.py           # 传输层兼容导出
│   ├── detectors/             # 后续检测模块拆分位置
│   ├── tools/                 # 后续工具注册拆分位置
│   └── utils/                 # 路径安全、文本截断等工具
├── config/                    # SafeLine、/usr/bin、进程基线
├── extensions/                # HeMa、rkhunter 等本地资产
└── DumpFileInfo.py            # /usr/bin 基线生成工具
```

## 功能清单

### 基础与编排

- `get_ssh_client`：建立 SSH 会话。
- `check_ssh_session`：检查 SSH 会话是否可用。
- `close_ssh_client`：关闭当前 SSH 会话。
- `reset_session`：重置连接和分析缓存。
- `readonly_shell`：优先推荐的只读远程 shell，拒绝明显写入/破坏命令。
- `shell`：通过 MCP 在已连接的 SSH 目标主机执行命令，返回退出码、stdout、stderr、耗时和截断状态；不使用本地 Bash。
- `check_safeline`：检查 SafeLine WAF 检测能力。
- `get_system_info`：采集 hostname、内核、系统版本、时间和 uptime。
- `run_quick_triage`：快速巡检用户、进程、网络、持久化和登录日志。
- `run_full_triage`：全量巡检，支持 WebShell 和 Rootkit 相关步骤。
- `get_triage_summary`：读取最近一次巡检缓存，避免重复运行重命令。

### 用户与权限

- `check_home`
- `check_history`
- `check_passwd`
- `check_shadow`
- `check_sudoers`
- `check_ssh_keys`
- `check_auth_log`

### 进程

- `get_ps`
- `check_mine`
- `check_exec`
- `check_pid`
- `check_exe`
- `check_mount`
- `check_deleted_exe`

### 网络

- `get_localhost`
- `check_network`
- `check_eth`
- `check_hosts`
- `check_dns_config`

### 文件、取证与 WebShell

- `stat_file`
- `hash_file`
- `download_file`
- `upload_file`
- `collect_evidence_bundle`
- `check_bin`
- `check_tmp`
- `check_webshell`

### 后门与持久化

- `check_ld_so_preload`
- `check_env_preload`
- `check_alias`
- `check_cron`
- `check_user_crontabs`
- `check_at_jobs`
- `check_ssh`
- `check_ssh_wrapper`
- `check_inetd`
- `check_xinetd`
- `check_setuid`
- `check_startup`
- `check_profile`
- `check_rc`
- `check_fstab`
- `check_systemd_timers`
- `check_service_execstart`

### 服务与容器

- `list_services`
- `check_enabled_services`
- `check_recent_systemd_changes`
- `check_docker_containers`
- `check_container_mounts`
- `check_container_processes`

### 日志与 Rootkit

- `check_log`
- `check_web_logs_auto`
- `check_login_success`
- `check_login_fail`
- `RookitUpload`

## 容错与安全

- SSH 命令统一返回状态、stdout/stderr、退出码、耗时、超时和截断标记。
- 常见检测提供 fallback，例如 `ss → netstat`、`ip → hostname -I`、`last/lastb → auth.log/secure`。
- SafeLine 不可用时自动降级到本地规则，并要求报告中说明。
- 大日志默认只分析最近 `max_lines` 行。
- WebShell 扫描限制文件数量、单文件大小，并阻断 tar 路径穿越和链接逃逸。
- SFTP 上传/下载返回明确错误。
- 所有工具必须区分“未发现明显异常”和“检测失败”。

## 安装与运行

```bash
uv sync
uv run python AutoIR_MCP.py
```

## MCP 使用流程

1. 调用 `get_ssh_client` 连接目标。
2. 调用 `check_safeline` 和 `get_system_info` 建立上下文。
3. 需要直接执行目标机只读命令时优先调用 `readonly_shell(command, timeout, max_bytes)`；明确需要通用执行时再调用 `shell(command, timeout, max_bytes)`。
4. 快速排查使用 `run_quick_triage`。
5. 全面排查使用 `run_full_triage`。
6. 需要复用最近巡检结果时调用 `get_triage_summary`。
7. 专项问题按工具分组调用对应工具。
8. 工具失败、权限不足、WAF 不可用、输出截断必须写入报告。

## SafeLine 配置

编辑 `config/config.json`：

```json
{
  "SafeLineWAF": {
    "Server": "http://127.0.0.1:5000/?input="
  }
}
```

接口应接收待检测内容作为 GET 参数，命中恶意内容时返回 HTTP 403。离线环境可留空，工具会使用本地规则继续检测。

## `/usr/bin` 基线

准备同版本干净系统后执行：

```bash
AUTOIR_BASELINE_IP=192.168.1.10 \
AUTOIR_BASELINE_PORT=22 \
AUTOIR_BASELINE_USERNAME=root \
AUTOIR_BASELINE_PASSWORD=root \
uv run python DumpFileInfo.py
```

## 统一报告输出

Claude 最终报告必须以 `AUTOIR_MCP` 艺术字开头：

```text
 █████╗ ██╗   ██╗████████╗ ██████╗ ██╗██████╗         ███╗   ███╗ ██████╗██████╗
██╔══██╗██║   ██║╚══██╔══╝██╔═══██╗██║██╔══██╗        ████╗ ████║██╔════╝██╔══██╗
███████║██║   ██║   ██║   ██║   ██║██║██████╔╝        ██╔████╔██║██║     ██████╔╝
██╔══██║██║   ██║   ██║   ██║   ██║██║██╔══██╗        ██║╚██╔╝██║██║     ██╔═══╝
██║  ██║╚██████╔╝   ██║   ╚██████╔╝██║██║  ██║███████╗██║ ╚═╝ ██║╚██████╗██║
╚═╝  ╚═╝ ╚═════╝    ╚═╝    ╚═════╝ ╚═╝╚═╝  ╚═╝╚══════╝╚═╝     ╚═╝ ╚═════╝╚═╝
```

报告结构固定为：摘要 → 检测结果 → 风险分析 → 处置建议 → 后续建议。

检测结果表固定字段：

```markdown
| 检测项 | 关键发现 | 风险 | 依据 |
|---|---|---|---|
```

风险等级只使用：`高`、`中`、`低`、`信息`、`未发现明显异常`。

## 开发命令

```bash
uv sync
python -m py_compile AutoIR_MCP.py functions.py DumpFileInfo.py autoir_mcp/*.py autoir_mcp/**/*.py
uv lock --check
git diff --check
```

当前仓库未配置单元测试或 lint 工具。
