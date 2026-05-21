# AutoIR_MCP

AutoIR_MCP 是一个基于 FastMCP 的 Linux 应急响应 MCP 服务。它通过 SSH 连接目标主机，向 MCP 客户端暴露用户、进程、网络、文件、WebShell、持久化、日志、容器和 Rootkit 排查工具。

> 工具结果用于辅助分析，最终结论仍需结合现场环境人工复核。

## 架构

```plain
AutoIR_MCP/
├── AutoIR_MCP.py              # 启动入口，运行 core.server:mcp
├── core/
│   ├── server.py              # FastMCP app、工具注册、巡检编排和取证工具
│   ├── prompts.py             # MCP instructions、工具分组、执行链模板、报告规范
│   ├── functions.py           # SSH 命令、SFTP、SafeLine、本地规则、IOC/格式化 helper
│   └── session.py             # SSH session 状态模型
├── config.json                # SafeLine 检测接口配置
├── extensions/                # HeMa、rkhunter 等本地资产
├── requirements.txt           # Python 依赖
└── README.md
```

## 安装与运行

```bash
pip install -r requirements.txt
python AutoIR_MCP.py
```

## 推荐 MCP 使用流程

1. `get_ssh_client`：连接目标主机。
2. `check_safeline`、`get_system_info`：建立检测上下文。
3. `run_quick_triage`：快速巡检。
4. `get_triage_summary`：复用最近巡检缓存。
5. `extract_iocs`：汇总 IOC。
6. `generate_timeline`：从巡检缓存或文本中提取事件时间线。
7. `generate_report`：生成规范化报告草稿。
8. 根据发现继续调用专项工具，或使用 `run_full_triage`。

## 工具执行链模板

`get_ir_playbooks` 会返回常用模板，只提供建议流程，不自动执行：

- `quick_linux_ir`：基础连接、SafeLine、系统信息、快速巡检、IOC、时间线、报告。
- `web_intrusion_ir`：Webroot 发现、Web 日志、WebShell、近期文件、IOC、时间线、报告。
- `persistence_ir`：cron、systemd、启动项、shell 初始化、SSH key、持久化摘要、时间线。
- `account_ir`：账户、sudoers、history、SSH key、登录成功/失败统计。

## 功能清单

### 基础、编排与报告

- `get_ssh_client`：建立 SSH 会话。
- `check_ssh_session`：检查 SSH 会话是否可用。
- `close_ssh_client`：关闭当前 SSH 会话。
- `reset_session`：重置连接和分析缓存。
- `shell`：在已连接的 SSH 目标主机执行命令，返回统一执行结果。
- `check_safeline`：检查 SafeLine WAF 检测能力。
- `get_system_info`：采集 hostname、内核、系统版本、时间和 uptime。
- `get_tool_inventory`：返回工具分类、推荐流程和执行链模板。
- `get_ir_playbooks`：返回常用应急响应执行链模板。
- `run_quick_triage`：快速巡检用户、进程、网络、持久化和登录日志。
- `run_full_triage`：全量巡检，支持 WebShell 和 Rootkit 相关步骤。
- `get_triage_summary`：读取最近一次巡检缓存。
- `extract_iocs`：从文本或最近巡检缓存提取 IP、域名、URL、路径和端口。
- `generate_timeline`：从文本或最近巡检缓存提取事件时间线。
- `generate_report`：基于巡检缓存生成规范化报告草稿。

### 文件、取证与 WebShell

- `stat_file`：读取远程文件元数据。
- `hash_file`：计算 md5、sha1 或 sha256。
- `profile_suspicious_file`：快速画像单个可疑文件，包含 stat、hash、file、预览、strings 和风险提示。
- `download_file`：下载远程文件到本地取证目录。
- `upload_file`：上传本地 `extensions/` 或 `downloads/` 内文件到目标主机。
- `collect_evidence_bundle`：采集系统、用户、进程、网络、服务、计划任务和日志摘要。
- `check_bin`：检查 `/usr/bin` 近期修改、权限和属主异常。
- `check_tmp`：列举 `/tmp` 下文件。
- `check_recent_files`：检查指定目录近期变更文件。
- `discover_webroots`：自动发现常见 Web 根目录和配置中的站点目录。
- `check_webshell`：扫描 webroot 中的疑似 WebShell。

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
- `check_listening_ports`
- `check_eth`
- `check_hosts`
- `check_dns_config`

### 后门与持久化

- `check_persistence_summary`
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

### 服务、容器、日志与 Rootkit

- `list_services`
- `check_enabled_services`
- `check_recent_systemd_changes`
- `check_docker_containers`
- `check_container_mounts`
- `check_container_processes`
- `check_log`
- `check_web_logs_auto`
- `check_login_success`
- `check_login_fail`
- `RookitUpload`

## SafeLine 配置

编辑根目录 `config.json`：

```json
{
  "SafeLineWAF": {
    "Server": "https://check.ihk-one.top/"
  }
}
```

接口应接收 `input` GET 参数，命中恶意内容时返回 HTTP 403。离线环境可留空，工具会使用本地规则继续检测。

## 容错与安全

- SSH 命令统一返回状态、stdout/stderr、退出码、超时和截断标记。
- 常见检测提供 fallback，例如 `ss → netstat`、`ip → hostname -I`、`last/lastb → auth.log/secure`。
- SafeLine 不可用时自动降级到本地规则，并要求报告中说明。
- 大日志默认只分析最近 `max_lines` 行。
- WebShell 扫描限制文件数量、单文件大小，并阻断 tar 路径穿越和链接逃逸。
- 可疑文件画像只读取限定头部和限定 strings 片段，不整文件输出。
- 编排和报告层会把工具输出归一为 `status/result/data/error/meta` 结构，直接检测工具仍优先保持简洁可读。
- 所有工具必须区分“未发现明显异常”和“检测失败”。

## 统一报告输出

最终报告必须以 `AUTOIR_MCP` 艺术字开头，并使用固定结构：摘要 → 检测结果表 → IOC 摘要 → 攻击流程分析 → 风险分析 → 处置建议 → 后续建议。

`generate_report` 会基于巡检缓存、IOC 和时间线线索生成攻击流程分析。该分析只做证据化阶段判断，证据不足时必须标注需人工复核，不编造完整攻击链。

检测结果表固定字段：

```markdown
| 检测项 | 关键发现 | 风险 | 依据 |
|---|---|---|---|
```

风险等级只使用：`高`、`中`、`低`、`信息`、`未发现明显异常`。

## 开发命令

```bash
python -m compileall -q AutoIR_MCP.py core
git diff --check
```

当前仓库未配置单元测试或 lint 工具。
