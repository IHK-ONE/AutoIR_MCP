# AGENTS.md

AUTOIR_MCP is a FastMCP-based Linux incident-response MCP server. It connects to target hosts over SSH and exposes defensive tools for user, process, network, file, persistence, log, and rootkit checks.

## Commands

- Install dependencies: `uv sync`
- Run the MCP server locally: `uv run python AutoIR_MCP.py`
- Check syntax: `python -m py_compile AutoIR_MCP.py functions.py DumpFileInfo.py autoir_mcp/*.py autoir_mcp/**/*.py`
- Verify lockfile: `uv lock --check`
- Check whitespace/conflict markers: `git diff --check`

## Project structure

- `AutoIR_MCP.py` is the compatibility entrypoint.
- `autoir_mcp/server.py` defines the FastMCP app and tool registrations, including session controls, `readonly_shell`/`shell`, evidence helpers, triage caching, service/container/cron checks, and orchestration tools.
- `autoir_mcp/prompts.py` defines MCP instructions and the required AUTOIR_MCP report banner.
- `autoir_mcp/functions.py` contains SSH command, fallback, SFTP, parser, SafeLine, and local detection helpers.
- `config/` stores SafeLine and baseline JSON files.
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

Use the normalized structure: summary, findings table, risk analysis, remediation advice, and suggested next tools. Risk labels: `高`, `中`, `低`, `信息`, `未发现明显异常`.
