# AutoIR_MCP

AutoIR_MCP 是一个基于 FastMCP 的 Linux 应急响应 MCP 服务。它通过 SSH 连接目标主机，向 MCP 客户端暴露用户、进程、网络、文件、WebShell、持久化、日志、容器和 Rootkit 排查工具。

> 工具结果用于辅助分析，最终结论仍需结合现场环境人工复核。

## 架构

```plain
AutoIR_MCP/
├── AutoIR_MCP.py              # 启动入口，运行 core.server:mcp
├── .github/workflows/         # GitHub Actions 静态检查与单元测试
├── core/
│   ├── server.py              # FastMCP app、工具注册和取证工具
│   ├── prompts.py             # MCP instructions、工具分组和报告规范
│   ├── functions.py           # SSH 命令、SFTP、SafeLine、本地规则、IOC/格式化 helper
│   └── session.py             # SSH session 状态模型
├── config.json                # SafeLine 检测接口配置
├── extensions/                # HeMa、rkhunter、YARA 规则等本地资产
├── tests/                     # 标准库 unittest 回归测试
├── requirements.txt           # Python 依赖
└── README.md
```

## 安装与运行

```bash
pip install -r requirements.txt
python AutoIR_MCP.py
```

需要 Python 3.10+；当前依赖版本区间已在 Python 3.12 下验证。

## 使用原则

AutoIR_MCP 只暴露纯 MCP 工具和工具结果，不提供任何预设排查路径。AI 客户端应根据用户目标、现场上下文和已有工具输出，自行决定调用哪个单个工具，并自行组织 IOC、时间线、攻击链和结论。

## 功能清单

### 基础与报告

- `get_ssh_client`：建立 SSH 会话；支持密码、`key_file`/`passphrase` 私钥以及本机默认密钥/SSH agent 认证；支持 `verify_host_key=True` 与自定义 `known_hosts` 启用主机密钥校验。默认不校验主机密钥并在结果中给出中间人风险警告，实战环境应显式开启校验。
- `check_ssh_session`：检查 SSH 会话是否可用。
- `close_ssh_client`：关闭当前 SSH 会话。
- `reset_session`：重置连接和会话状态。
- `shell`：在已连接的 SSH 目标主机执行命令，返回统一执行结果。
- `check_safeline`：检查 SafeLine WAF 检测能力。
- `get_system_info`：采集 hostname、内核、系统版本、时间和 uptime。
- `get_tool_inventory`：返回工具分类。
- `extract_iocs`：兼容分析工具；从文本提取 IP、域名、URL、路径和端口，支持 `limit` 控制每类数量。
- `generate_timeline`：兼容分析工具；从文本提取事件时间线。
- `analyze_attack_chain`：兼容分析工具；从文本生成攻击阶段表、攻击路径判断、IOC 和时间线数据。
- `generate_report`：兼容报告工具；优先基于结构化 `case`、`findings`、`timeline`、`iocs`、`answers` 渲染规范化报告，`extra_context` 仅作为旧调用兜底，支持 `output_mode='file'` 落盘避免返回截断。

### 文件、取证与 WebShell

- `stat_file`：读取远程文件元数据。
- `hash_file`：计算 md5、sha1 或 sha256。
- `profile_suspicious_file`：快速画像单个可疑文件，包含 stat、hash、file、预览、strings 和风险提示。
- `download_file`：下载远程文件到本地取证目录。
- `upload_file`：上传本地 `extensions/` 或 `downloads/` 内文件到目标主机。
- `collect_evidence_bundle`：采集系统、用户、进程、网络、服务、计划任务和日志摘要。
- `scan_yara`：将单个远程文件下载到独立临时目录，调用本地 `yara -s -w` 扫描；默认规则为 `extensions/yara/index.yar`，支持自定义规则路径和下载大小上限，扫描结束删除样本。
- `check_bin`：检查 `/usr/bin` 近期修改、权限和属主异常。
- `check_tmp`：扫描 `/tmp`、`/var/tmp`、`/dev/shm`、`/run/shm` 中的文件，并标注可执行文件和隐藏文件。
- `check_recent_files`：检查指定目录近期变更文件。
- `check_package_integrity`：使用 `rpm -Va`、`dpkg --verify` 或 `apk audit --system` 校验已安装软件包文件完整性，用于发现被替换的系统命令、库和缺失文件；需要 root，`rpm` 全量校验可能较慢。
- `discover_webroots`：自动发现常见 Web 根目录和配置中的站点目录。
- `check_web_persistence`：检查站点目录与 PHP 配置中的 `.user.ini`、`.htaccess`、`php.ini`，标记 `auto_prepend_file`/`auto_append_file`、`allow_url_include`、非标准扩展路径和 PHP handler 持久化。
- `check_webshell`：扫描 webroot 中的疑似 WebShell。扫描前会先在目标主机执行高信号代码特征与可疑文件名的启发式检查，再打包下载并调用本地 HeMa 扫描器；`hm`/`hm.exe` 按当前平台优先选择，扫描器缺失或失败时仍返回启发式结果并明确标注。扫描完成后会删除本地解压目录，避免反复扫描占满磁盘；崩溃残留目录可通过 `AUTOIR_WEBSHELL_RETENTION_DAYS` 配置自动清理（默认 `0`，保守保留证据）。

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
- `check_memory_maps`：扫描 `/proc/<pid>/maps` 中的可写可执行映射、临时目录映射、`(deleted)` 映射、`memfd:` 映射和匿名可执行映射，并关联进程命令行。

### 网络

- `get_localhost`
- `check_network`
- `check_listening_ports`
- `check_eth`
- `check_hosts`
- `check_dns_config`

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
- `check_pam`
- `check_sshd_config`
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
- `check_login_sessions`
- `check_container_escape`：解析 `docker/podman inspect`，检查 privileged、host PID/IPC/网络/User 命名空间、危险 capability、`seccomp/apparmor=unconfined`、敏感路径挂载、Docker/containerd socket 及其权限。
- `check_kubernetes`：通过 `kubectl get pods -A -o json` 检查 hostNetwork/hostPID/hostIPC、hostPath、特权容器、危险 capability 和 hostPort；未安装 kubectl 或无权限时明确标注。
- `check_auditd`：读取 `auditctl -l`、auditd 状态和 `/var/log/audit/audit.log`，回退 `ausearch`/`journalctl`；解析 EXECVE/PROCTITLE 十六进制命令、临时目录执行、AVC denied、审计规则变更和守护进程异常结束。
- `check_log_integrity`：检查 wtmp/btmp/lastlog/auth.log/secure/audit.log 等文件的大小、权限、属主和时间，执行 `journalctl --verify`、boot 列表和认证日志断层检测，并扫描 logrotate 配置中的可疑命令。
- `check_kernel_modules`
- `check_ebpf`：枚举 `bpftool prog/map/net/cgroup`、`/sys/fs/bpf` pinned 对象和 `unprivileged_bpf_disabled`，并过滤内核日志中的 BPF、Oops、模块校验和 taint 线索。
- `RootkitUpload`（旧名 `RookitUpload` 仍保留为兼容别名）

### 基线与对比

- `baseline_capture`：采集文件哈希（账户、SSH、PAM、sudoers、计划任务、profile、审计规则等）、UID 0/普通用户、空口令账户、SUID/SGID、软件包、服务、监听端口、内核模块和内核版本，保存到本地 `downloads/baselines/<目标IP>/<name>.json`。
- `baseline_diff`：与本地基线对比，输出新增、消失和哈希变化项；支持 `update=True` 在对比后更新基线，并拒绝跨目标主机误对比。

## SafeLine 配置

编辑根目录 `config.json`：

```json
{
  "SafeLineWAF": {
    "Server": "http://check.ihk-one.top/"
  }
}
```

生产环境建议使用 HTTPS；当前临时配置使用 HTTP。接口应接收 `input` GET 参数：HTTP 403 视为命中，2xx/3xx 视为未命中，其他状态码或请求异常视为不可用。可用性检查结果缓存 5 分钟，不可用结果缓存 30 秒，查询频率限制为每分钟 120 次；配置变更后缓存自动清空。离线环境可留空，工具会使用本地规则继续检测；SafeLine 不可用时工具输出会明确标注，而不是当作安全。

## 容错与安全

- SSH 命令统一返回状态、stdout/stderr、退出码、超时和截断标记；并发执行有上限，避免压垮目标 sshd。
- 常见检测提供 fallback，例如 `ss → netstat`、`ip → hostname -I`、`last/lastb → auth.log/secure`、`find -printf → stat`；认证日志支持 `journalctl` 回退。`find` 不可用、权限不足和路径不存在会明确标注，不再表现为“无异常”。
- 临时目录排查覆盖 `/tmp`、`/var/tmp`、`/dev/shm`、`/run/shm`，避免只查磁盘目录而漏掉内存盘驻留样本。
- `check_package_integrity` 使用 `rpm -Va`、`dpkg --verify` 或 `apk audit --system` 校验软件包文件完整性；系统可执行文件/库不一致、软件包文件缺失会重点标注，无包管理器或校验失败时明确标注需人工复核。
- `check_history` 除检查历史文件外，还会扫描下载执行、反弹 shell、编码解码、持久化、历史清理等特征；账户/服务类低信号命中单独标注，避免与高危特征混淆。
- SSH 排查同时覆盖 `authorized_keys`、`authorized_keys2`、`sshrc`、`~/.ssh/rc` 和 `~/.ssh/config` 中的命令触发配置；`check_pam` 和 `check_sshd_config` 进一步覆盖 PAM 外部命令模块、`nullok`、非标准 include、`AuthorizedKeysCommand`、`ForceCommand` 和异常 HostKey/SFTP 路径。
- `check_auth_log` 会把同一 IP 的大量失败与成功登录关联，标记“疑似暴力破解后成功登录”，并汇总无效用户名；`check_login_sessions` 关联 `who`、`last`、sshd 进程父子关系和已建立 SSH 连接，`notty` 与父进程为 1 的 sshd 会话会被标注复核。
- `check_kernel_modules` 解析内核 taint 位（强制加载/卸载、oops、树外、未签名模块），并核对 `lsmod` 模块文件是否位于标准模块目录；已知 rootkit 模块名会重点标注。
- `check_auditd` 优先读取 audit.log，回退 `ausearch` 和 `journalctl`；PROCTITLE/EXECVE 十六进制参数会还原为可读命令，审计未启用、规则为空或日志不可读会明确标注。
- `check_ebpf` 在 `bpftool` 缺失时仍检查 pinned 对象、非特权 BPF 配置和内核日志；`check_memory_maps` 依赖 `/proc` 可读性，非 root 会提示结果不完整。
- `check_log_integrity` 区分“文件为空可能被清空”“全局可写”“登录审计文件缺失”，并检测认证日志超过 24 小时的时间断层；journal 校验失败和 logrotate 可疑命令会重点标注。
- 基线只保存在本地 `downloads/baselines/`，不会上传目标主机；`baseline_diff` 会拒绝与不同目标 IP 的基线对比。
- `scan_yara` 仅下载单个文件，默认 100 MB 上限，样本保存在独立临时目录并在扫描结束删除；本地缺少 yara 或规则文件时明确标注，不会假装未命中。
- `check_log` 会聚合路径穿越、SQL 注入、命令注入、PHP 伪协议、WebShell/上传脚本访问和扫描器 User-Agent，按来源 IP 与特征统计成功请求数，避免逐行刷屏。
- SUID/SGID 检查覆盖 `df` 列出的所有本地挂载点（包括 `/dev/shm`、`/run/shm` 等 tmpfs），同时检查 SUID 与 SGID；常见系统程序标记为“需校验包完整性”，非典型路径和属主非 root 标记为“需人工复核”，避免把 `passwd`、`sudo` 等全部误报为后门。
- 服务枚举在 systemd 之外回退到 OpenRC `rc-status`/`rc-update`、`chkconfig` 和 `service --status-all`；网络连接缺少进程信息时会明确提示非 root 或 hidepid 限制。
- SafeLine 不可用时自动降级到本地规则，工具输出和报告必须明确标注“未经 WAF 检测”。
- 多文件检查采用批量读取，减少 SSH 往返；每个文件保留独立退出码，权限不足不会被误报为“未发现异常”。
- 大日志默认只分析最近 `max_lines` 行。
- WebShell 扫描限制文件数量、单文件大小和下载大小，阻断 tar 路径穿越、链接和设备文件，并在扫描器失败或结果无法解析时报告检测失败。
- 远程打包、扫描和下载使用独立运行目录，失败时会清理临时压缩包；扫描结束（包括异常退出）会删除本地解压目录；并发扫描通过锁串行化。
- SFTP 下载带超时和硬性大小上限，失败时删除不完整文件。
- 可疑文件画像只读取限定头部和限定 strings 片段，不整文件输出。
- 兼容分析工具会把工具输出归一为 `status/result/data/error/meta` 结构；兼容报告工具返回可读报告文本，直接检测工具仍优先保持简洁可读。
- 所有工具必须区分“未发现明显异常”“检测失败”“权限不足”“输出截断”和“需人工复核”。

## AI 客户端分析与兼容报告工具

默认设计是纯工具采证：MCP 工具返回主机证据，IOC、时间线和攻击链由 AI 客户端根据提示词自行组织。用户提供 IP、账号密码、入口说明、靶机信息、CTF 题目或应急响应任务时，AI 客户端不得只根据题面直接回答，必须先调用 `get_ssh_client` 建立 SSH 会话。`generate_report` 是调查结束、交付结论或用户要求总结前必须调用的最终汇总工具，用于把已有工具证据整理为规范化报告。

最终汇总报告会输出 banner、案件背景/摘要、检测结果表、IOC 摘要、时间线摘要、攻击流程分析、风险分析、处置原则和 AI 编排说明。分析只做证据化阶段判断，证据不足时必须标注待检测或需人工复核，不编造完整攻击链。

常用参数语义：

- `generate_report(case=...)`：结构化案件背景，建议包含 `title`、`target`、`system`、`webroot`。
- `generate_report(findings=...)`：结构化检测结论列表，固定字段为 `item`、`finding`、`risk`、`evidence`；检测结果表直接由该 schema 渲染，不再靠长文本猜测。
- `generate_report(timeline=...)`：结构化时间线列表，建议字段为 `time`、`event`、`source`；也可直接传 `generate_timeline` 的工具结果。
- `generate_report(iocs=...)`：结构化 IOC 字典，支持 `ips`、`domains`、`urls`、`paths`、`ports`；也可直接传 `extract_iocs` 的工具结果。
- `generate_report(answers=...)`：专项题目、CTF 或调查问答的结构化答案，支持字典或 `question/answer` 列表。
- `generate_report(output_mode=...)`：默认 `both`，同时返回完整报告、交付预览并写入 `downloads/reports/<timestamp>/report.md`；`inline` 只返回完整 markdown；`preview` 返回短预览；`file` 写入报告文件，并在 `result` 返回可直接展示的短报告、完整报告路径和末尾答案。
- `generate_report(extra_context=...)`：兼容旧调用的兜底摘要字段；不要直接传入大段原始日志，应先 `raw_log -> filter/slice -> structured_events/findings -> report`。
- `generate_report(report_profile=...)`：调查结束前必须调用；`standard`、`executive`、`technical`、`handoff` 仅影响报告表达侧重点。
- `generate_report(focus=...)`：声明关注方向，例如 Web、账户、持久化、挖矿；只影响报告聚焦文本，不代表已确认风险。
- `generate_report(max_findings=..., max_timeline_events=..., max_iocs_per_type=..., evidence_limit=...)`：只控制输出密度，不改变原始证据。
- `generate_report(include_iocs=False)`：只关闭报告里的 IOC 摘要展示。
- `generate_report(include_timeline=False)`：只关闭时间线摘要章节。
- `generate_report(include_next_tools=...)`：兼容参数；无论取值如何，MCP 服务都不预设后续工具、排查路径或固定顺序。
- `extract_iocs`、`generate_timeline`、`analyze_attack_chain` 是中间分析工具；`generate_report` 是最终交付前的汇总工具。
- `extract_iocs(text=...)`、`generate_timeline(text=...)`、`analyze_attack_chain(text=...)`：当前纯工具模式只分析显式传入的 `text`。

检测结果表固定字段：

```markdown
| 检测项 | 关键发现 | 风险 | 依据 |
|---|---|---|---|
```

风险等级只使用：`高`、`中`、`低`、`信息`、`未发现明显异常`。工具失败、权限不足、WAF 不可用、输出截断、待检测和需人工复核必须作为报告事实明确呈现。

## 开发命令

```bash
python -m compileall -q AutoIR_MCP.py core tests
python -m unittest discover -s tests -v
pip install pyflakes
python -m pyflakes core AutoIR_MCP.py tests
git diff --check
```

测试使用标准库 `unittest`，不依赖网络或真实 SSH 目标。
