# AGENTS.md

AUTOIR_MCP 是一个基于 FastMCP 的 Linux 应急响应 MCP 服务。它通过 SSH 连接目标主机，并向客户端暴露用户、进程、网络、文件、WebShell、持久化、日志、IOC/报告、攻击链分析和 Rootkit 排查等防御型工具。

## 命令

- 安装依赖：`pip install -r requirements.txt`
- 本地运行 MCP 服务：`python AutoIR_MCP.py`
- 检查语法：`python -m compileall -q AutoIR_MCP.py core`
- 检查空白字符/冲突标记：`git diff --check`

## 项目结构

- `AutoIR_MCP.py` 是兼容性启动入口。
- `core/server.py` 定义 FastMCP 应用和工具注册，包括会话控制、`shell`、证据辅助工具、服务/容器/cron 检查、IOC/报告工具和攻击链兼容分析工具。
- `core/prompts.py` 定义 MCP instructions、工具分类和必需的 AUTOIR_MCP 报告 banner。
- `core/functions.py` 包含 SSH 命令执行、fallback、SFTP、解析器、SafeLine、本地规则、IOC 提取、时间线提取、攻击流程推断、格式化和本地检测辅助函数。
- `core/session.py` 保存 SSH 会话状态。
- `config.json` 保存 SafeLine 配置。
- `extensions/` 保存本地扫描器和 Rootkit 检测资产。

## AI 客户端编排原则

AutoIR_MCP 只提供纯 MCP 工具和工具证据，不提供任何预设排查路径。用户提供 IP、账号密码、入口说明、靶机信息、CTF 题目或应急响应任务时，AI 客户端不得只根据题面直接回答，必须先调用 `get_ssh_client` 建立 SSH 会话，再根据用户目标、现场上下文和已有工具输出，自行决定调用哪个单个工具，并自行组织 IOC、时间线、攻击链和结论。

## 面向 AI 的兼容分析参数

默认由 AI 客户端直接基于纯工具输出完成 IOC、时间线和攻击链组织；`generate_report` 是调查结束、交付结论或用户要求总结前必须调用的最终汇总工具。

- `extract_iocs(limit=...)`：控制每类 IOC 的最大数量。
- `extract_iocs(text=...)`、`generate_timeline(text=...)`、`analyze_attack_chain(text=...)`：当前纯工具模式只分析显式传入的 `text`。
- `analyze_attack_chain(max_stages=..., evidence_limit=..., include_unobserved=..., max_iocs_per_type=...)`：控制攻击阶段深度、证据密度和 IOC 展示密度。
- `generate_report(report_profile=..., focus=...)`：根据受众选择 `standard`、`executive`、`technical` 或 `handoff`；`focus` 只表示关注方向。
- `generate_report(max_summary_chars=..., max_findings=..., max_timeline_events=..., max_iocs_per_type=..., evidence_limit=...)`：只控制输出密度，不改变原始证据。
- `generate_report(include_timeline=...)`：仅关闭时间线摘要章节；`include_next_tools` 是兼容参数，不会让 MCP 服务预设后续工具、排查路径或固定顺序。
- `generate_report(include_iocs=False)`：只关闭报告里的 IOC 摘要展示；不会删除摘要中的原始证据文本，时间线、攻击链和风险分析仍会基于原始工具输出识别相关线索。

除非明确要求，不要在 MCP 服务内部添加外部 LLM/API 调用。服务端应负责提供纯工具证据；最终推理由 AI 客户端完成，最终文字交付应调用 `generate_report` 汇总已有证据。

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

报告结构由 AI 客户端基于工具证据自行组织；风险标签只能使用：`高`、`中`、`低`、`信息`、`未发现明显异常`。

## 安全注意事项

- 工具失败、权限错误、WAF 不可用和输出截断都必须作为明确报告事实呈现，不能当作无异常结果。
- 除非证据确凿，不要把采集到的事实写成已确认失陷；不确定项应标记为需要人工复核。
- 黑客攻击流程分析必须基于工具输出、IOC 和时间线事件；不要编造缺失的 kill-chain 阶段。
- 优先使用纯采证工具做简洁交接；`extract_iocs`、`generate_timeline`、`analyze_attack_chain` 作为中间分析工具，`generate_report` 是最终交付前必须调用的汇总工具。
- 直接检测工具保持精简。参数和结构化上下文不要下沉到每个低层检查器，最终组织由 AI 客户端完成。
