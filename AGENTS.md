# AGENTS.md

AUTOIR_MCP is a FastMCP-based Linux incident-response MCP server. It connects to target hosts over SSH and exposes defensive tools for user, process, network, file, WebShell, persistence, log, IOC/reporting, and rootkit checks.

## Commands

- Install dependencies: `pip install -r requirements.txt`
- Run the MCP server locally: `python AutoIR_MCP.py`
- Check syntax: `python -m compileall -q AutoIR_MCP.py core`
- Check whitespace/conflict markers: `git diff --check`

## Project structure

- `AutoIR_MCP.py` is the compatibility entrypoint.
- `core/server.py` defines the FastMCP app and tool registrations, including session controls, `shell`, evidence helpers, triage caching, service/container/cron checks, IOC/report tools, and orchestration tools.
- `core/prompts.py` defines MCP instructions, tool categories, workflow, execution-chain templates, and the required AUTOIR_MCP report banner.
- `core/functions.py` contains SSH command, fallback, SFTP, parser, SafeLine, IOC extraction, formatting, and local detection helpers.
- `config.json` stores SafeLine configuration.
- `extensions/` stores local scanner/rootkit assets.

## Response style

Reports must begin with this banner in a `text` code block:

```text
 █████╗ ██╗   ██╗████████╗ ██████╗ ██╗██████╗         ███╗   ███╗ ██████╗██████╗
██╔══██╗██║   ██║╚══██╔══╝██╔═══██╗██║██╔══██╗        ████╗ ████║██╔════╝██╔══██╗
███████║██║   ██║   ██║   ██║   ██║██║██████╔╝        ██╔████╔██║██║     ██████╔╝
██╔══██║██║   ██║   ██║   ██║   ██║██║██╔══██╗        ██║╚██╔╝██║██║     ██╔═══╝
██║  ██║╚██████╔╝   ██║   ╚██████╔╝██║██║  ██║███████╗██║ ╚═╝ ██║╚██████╗██║
╚═╝  ╚═╝ ╚═════╝    ╚═╝    ╚═════╝ ╚═╝╚═╝  ╚═╝╚══════╝╚═╝     ╚═╝ ╚═════╝╚═╝
```

Use the normalized structure: summary, findings table, IOC summary, hacker attack flow analysis, risk analysis, remediation advice, and suggested next tools. Risk labels: `高`, `中`, `低`, `信息`, `未发现明显异常`.

## Safety notes

- Treat tool failures, permission errors, WAF unavailability, and truncated output as explicit report facts, not as clean results.
- Do not present collected facts as confirmed compromise unless evidence is conclusive; mark uncertain items as requiring manual review.
- Hacker attack flow analysis must be evidence-based from tool output, IOCs, and timeline events; never invent missing kill-chain stages.
- Prefer `get_ir_playbooks`, `extract_iocs`, `generate_timeline`, `profile_suspicious_file`, and `generate_report` for concise investigation handoff instead of repeating heavy scans.
