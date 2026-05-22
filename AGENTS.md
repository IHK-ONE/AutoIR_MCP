# AGENTS.md

AUTOIR_MCP 是一个基于 FastMCP 的 Linux 应急响应 MCP 服务。它通过 SSH 连接目标主机，并向客户端暴露用户、进程、网络、文件、WebShell、持久化、日志、IOC/报告、攻击链分析和 Rootkit 排查等防御型工具。

## 命令

- 安装依赖：`pip install -r requirements.txt`
- 本地运行 MCP 服务：`python AutoIR_MCP.py`
- 检查语法：`python -m compileall -q AutoIR_MCP.py core`
- 检查空白字符/冲突标记：`git diff --check`

## 项目结构

- `AutoIR_MCP.py` 是兼容性启动入口。
- `core/server.py` 定义 FastMCP 应用和工具注册，包括会话控制、`shell`、证据辅助工具、巡检缓存、服务/容器/cron 检查、IOC/报告工具、攻击链分析和编排工具。
- `core/prompts.py` 定义 MCP instructions、工具分类、工作流、执行链模板，以及必需的 AUTOIR_MCP 报告 banner。
- `core/functions.py` 包含 SSH 命令执行、fallback、SFTP、解析器、SafeLine、本地规则、IOC 提取、时间线提取、攻击流程推断、格式化和本地检测辅助函数。
- `core/session.py` 保存 SSH 会话状态和最近一次巡检缓存。
- `config.json` 保存 SafeLine 配置。
- `extensions/` 保存本地扫描器和 Rootkit 检测资产。

## AI 客户端工作流

大多数调查优先使用以下证据优先流程：

1. `get_ssh_client` 连接已授权目标。
2. `check_safeline` 和 `get_system_info` 建立上下文。
3. `run_quick_triage` 执行低成本基线巡检。
4. `get_triage_summary` 复用缓存结果，避免重复扫描。
5. `extract_iocs` 汇总 IP、域名、URL、路径和端口。
6. `generate_timeline` 提取带时间戳的事件。
7. `analyze_attack_chain` 将证据映射到攻击阶段。
8. `generate_report` 生成最终报告草稿。
9. 仅针对证据缺口或可疑阶段运行专项工具。

选择特定场景执行链时使用 `get_ir_playbooks`。Web 入侵、持久化或账户失陷等场景优先使用聚焦 playbook，不要默认运行所有重型工具。

## 面向 AI 的报告参数

- `extract_iocs(limit=...)`：控制每类 IOC 的最大数量。
- `analyze_attack_chain(max_stages=..., evidence_limit=..., include_unobserved=..., max_iocs_per_type=...)`：控制攻击阶段深度、证据密度和 IOC 展示密度。
- `generate_report(report_profile=..., focus=...)`：根据受众选择 `standard`、`executive`、`technical` 或 `handoff`。
- `generate_report(max_summary_chars=..., max_findings=..., max_timeline_events=..., max_iocs_per_type=..., evidence_limit=...)`：让 AI 客户端上下文更简洁、更贴合任务。
- `generate_report(include_timeline=..., include_next_tools=...)`：仅在调用方需要更短交接内容时关闭可选章节。
- `generate_report(include_iocs=False)`：仅隐藏 IOC 摘要章节；证据章节仍可能引用原始工具输出。

除非明确要求，不要在 MCP 服务内部添加外部 LLM/API 调用。服务端应负责准备结构化证据和报告草稿；最终推理与文字组织由 AI 客户端完成。

## 响应风格

报告必须以如下 banner 开头，并放在 `text` 代码块中：

```text
 █████╗ ██╗   ██╗████████╗ ██████╗ ██╗██████╗         ███╗   ███╗ ██████╗██████╗
██╔══██╗██║   ██║╚══██╔══╝██╔═══██╗██║██╔══██╗        ████╗ ████║██╔════╝██╔══██╗
███████║██║   ██║   ██║   ██║   ██║██║██████╔╝        ██╔████╔██║██║     ██████╔╝
██╔══██║██║   ██║   ██║   ██║   ██║██║██╔══██╗        ██║╚██╔╝██║██║     ██╔═══╝
██║  ██║╚██████╔╝   ██║   ╚██████╔╝██║██║  ██║███████╗██║ ╚═╝ ██║╚██████╗██║
╚═╝  ╚═╝ ╚═════╝    ╚═╝    ╚═════╝ ╚═╝╚═╝  ╚═╝╚══════╝╚═╝     ╚═╝ ╚═════╝╚═╝
```

使用标准化结构：摘要、检测结果表、IOC 摘要、时间线摘要、黑客攻击流程分析、风险分析、处置建议和后续工具建议。风险标签只能使用：`高`、`中`、`低`、`信息`、`未发现明显异常`。

## 安全注意事项

- 工具失败、权限错误、WAF 不可用和输出截断都必须作为明确报告事实呈现，不能当作无异常结果。
- 除非证据确凿，不要把采集到的事实写成已确认失陷；不确定项应标记为需要人工复核。
- 黑客攻击流程分析必须基于工具输出、IOC 和时间线事件；不要编造缺失的 kill-chain 阶段。
- 优先使用 `get_ir_playbooks`、`extract_iocs`、`generate_timeline`、`analyze_attack_chain`、`generate_report` 和 `profile_suspicious_file` 进行简洁交接，避免重复执行重型扫描。
- 直接检测工具保持精简。参数和结构化上下文主要添加到分析/报告工具中，不要给每个低层检查器都增加复杂输出。
