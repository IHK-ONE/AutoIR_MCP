# AGENTS.md

AUTOIR_MCP is a FastMCP-based Linux incident-response MCP server. It connects to target hosts over SSH and exposes defensive tools for user, process, network, file, WebShell, persistence, log, IOC/reporting, attack-chain analysis, and rootkit checks.

## Commands

- Install dependencies: `pip install -r requirements.txt`
- Run the MCP server locally: `python AutoIR_MCP.py`
- Check syntax: `python -m compileall -q AutoIR_MCP.py core`
- Check whitespace/conflict markers: `git diff --check`

## Project structure

- `AutoIR_MCP.py` is the compatibility entrypoint.
- `core/server.py` defines the FastMCP app and tool registrations, including session controls, `shell`, evidence helpers, triage caching, service/container/cron checks, IOC/report tools, attack-chain analysis, and orchestration tools.
- `core/prompts.py` defines MCP instructions, tool categories, workflow, execution-chain templates, and the required AUTOIR_MCP report banner.
- `core/functions.py` contains SSH command, fallback, SFTP, parser, SafeLine, IOC extraction, timeline extraction, attack-flow inference, formatting, and local detection helpers.
- `core/session.py` stores SSH session state and the latest triage cache.
- `config.json` stores SafeLine configuration.
- `extensions/` stores local scanner/rootkit assets.

## AI client workflow

Prefer this evidence-first flow for most investigations:

1. `get_ssh_client` to connect to the authorized target.
2. `check_safeline` and `get_system_info` to establish context.
3. `run_quick_triage` for low-cost baseline coverage.
4. `get_triage_summary` to reuse cached results instead of rescanning.
5. `extract_iocs` to collect IPs, domains, URLs, paths, and ports.
6. `generate_timeline` to extract timestamped events.
7. `analyze_attack_chain` to map evidence to attack stages.
8. `generate_report` to produce the final report draft.
9. Run focused tools only for gaps or suspicious stages.

Use `get_ir_playbooks` when choosing a scenario-specific chain. Prefer focused playbooks for Web intrusion, persistence, or account compromise instead of running every heavy tool by default.

## AI-oriented reporting parameters

- `extract_iocs(limit=...)`: control the maximum IOC count per type.
- `analyze_attack_chain(max_stages=..., evidence_limit=..., include_unobserved=..., max_iocs_per_type=...)`: control attack-stage depth, evidence density, and IOC display density.
- `generate_report(report_profile=..., focus=...)`: use `standard`, `executive`, `technical`, or `handoff` depending on the audience.
- `generate_report(max_summary_chars=..., max_findings=..., max_timeline_events=..., max_iocs_per_type=..., evidence_limit=...)`: keep AI-client context concise and task-specific.
- `generate_report(include_timeline=..., include_next_tools=...)`: disable optional sections only when a caller needs a shorter handoff.
- `generate_report(include_iocs=False)`: suppress only the IOC summary section; evidence sections may still quote original tool output.

Do not add external LLM/API calls inside the MCP server unless explicitly requested. The server should prepare structured evidence and report drafts; the AI client performs final reasoning and wording.

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

Use the normalized structure: summary, findings table, IOC summary, timeline summary, hacker attack flow analysis, risk analysis, remediation advice, and suggested next tools. Risk labels: `高`, `中`, `低`, `信息`, `未发现明显异常`.

## Safety notes

- Treat tool failures, permission errors, WAF unavailability, and truncated output as explicit report facts, not as clean results.
- Do not present collected facts as confirmed compromise unless evidence is conclusive; mark uncertain items as requiring manual review.
- Hacker attack flow analysis must be evidence-based from tool output, IOCs, and timeline events; never invent missing kill-chain stages.
- Prefer `get_ir_playbooks`, `extract_iocs`, `generate_timeline`, `analyze_attack_chain`, `generate_report`, and `profile_suspicious_file` for concise investigation handoff instead of repeating heavy scans.
- Keep direct detection tools lean. Add parameters and structured context mainly to analysis/reporting tools, not to every low-level checker.
