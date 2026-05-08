# CLAUDE.md

This repository implements AUTOIR_MCP, a FastMCP-based Linux incident-response server that connects to target hosts over SSH and exposes defensive investigation tools.

## Development commands

- Install dependencies: `uv sync`
- Run the MCP server locally: `uv run python AutoIR_MCP.py`
- Check Python syntax: `python -m py_compile AutoIR_MCP.py functions.py DumpFileInfo.py autoir_mcp/*.py autoir_mcp/**/*.py`
- Verify the lockfile is current: `uv lock --check`
- Check whitespace/conflict-marker issues: `git diff --check`

No unit test or lint runner is currently configured.

## Architecture overview

- `AutoIR_MCP.py` is a compatibility entrypoint that imports and runs `autoir_mcp.server:mcp`.
- `autoir_mcp/server.py` owns the FastMCP app, SSH session state, tool registration, and orchestration tools.
- `autoir_mcp/prompts.py` stores MCP instructions, the AUTOIR_MCP banner, and final report rules.
- `autoir_mcp/functions.py` contains command execution, fallback execution, SFTP, parsing, time, local malicious-text detection, and SafeLine WAF helpers.
- `autoir_mcp/schemas.py`, `session.py`, `transport.py`, and `utils/` provide reusable structure for future detector extraction.
- `config/` stores SafeLine configuration and `/usr/bin`/process baselines.
- `extensions/` stores local scanner/rootkit assets used by MCP tools.
- `DumpFileInfo.py` updates `config/info_bin.json` from `AUTOIR_BASELINE_*` SSH environment variables.

## MCP usage flow

1. Establish SSH with `get_ssh_client` before any remote detection.
2. Call `check_safeline` and `get_system_info` after connecting.
3. Prefer `readonly_shell(command, timeout, max_bytes)` for direct target-host commands; use `shell(command, timeout, max_bytes)` only when unrestricted target execution is explicitly needed. Neither uses local Bash.
4. Use `run_quick_triage` for low-cost coverage or `run_full_triage` for broad investigation; use `get_triage_summary` to reuse cached triage output.
5. Use evidence helpers (`stat_file`, `hash_file`, `download_file`, `collect_evidence_bundle`) for forensics workflows.
6. Preserve existing tool names and parameters unless intentionally changing the MCP contract.
7. Tool failures, permission errors, WAF unavailability, and truncated output must be reported explicitly; never treat failures as clean results.

## Response style

Incident-response reports must start with this AUTOIR_MCP banner in a `text` code block:

```text
 █████╗ ██╗   ██╗████████╗ ██████╗ ██╗██████╗         ███╗   ███╗ ██████╗██████╗
██╔══██╗██║   ██║╚══██╔══╝██╔═══██╗██║██╔══██╗        ████╗ ████║██╔════╝██╔══██╗
███████║██║   ██║   ██║   ██║   ██║██║██████╔╝        ██╔████╔██║██║     ██████╔╝
██╔══██║██║   ██║   ██║   ██║   ██║██║██╔══██╗        ██║╚██╔╝██║██║     ██╔═══╝
██║  ██║╚██████╔╝   ██║   ╚██████╔╝██║██║  ██║███████╗██║ ╚═╝ ██║╚██████╗██║
╚═╝  ╚═╝ ╚═════╝    ╚═╝    ╚═════╝ ╚═╝╚═╝  ╚═╝╚══════╝╚═╝     ╚═╝ ╚═════╝╚═╝
```

Use this structure: summary, findings table, risk analysis, remediation advice, and suggested next tools. Risk labels are limited to `高`, `中`, `低`, `信息`, and `未发现明显异常`.
