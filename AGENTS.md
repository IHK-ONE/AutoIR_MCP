# AGENTS.md

This file provides guidance to Codex-style agents when working in this repository.

## Commands

- Install dependencies: `uv sync`
- Run the MCP server locally: `uv run python AutoIR_MCP.py`
- Check Python syntax: `python -m py_compile AutoIR_MCP.py functions.py DumpFileInfo.py`
- Verify the lockfile is current: `uv lock --check`
- Check whitespace/conflict-marker issues before committing: `git diff --check`

No test runner or lint configuration is currently defined in this repository.

## Project structure

AutoIR_MCP is a FastMCP-based Linux incident-response MCP server. It connects to target hosts over SSH and exposes tools for user, process, network, file, persistence, log, and rootkit checks.

- `AutoIR_MCP.py` defines the FastMCP app, global SSH session state, tool prompts, and most MCP tool implementations.
- `functions.py` contains shared SSH command, SFTP, parsing, timestamp, local shell-detection, and SafeLine WAF helpers.
- `DumpFileInfo.py` updates the `/usr/bin` baseline in `config/info_bin.json` using SSH settings from `AUTOIR_BASELINE_*` environment variables.
- `config/` stores SafeLine configuration and local process/binary baselines.
- `extensions/` stores local scanner/rootkit assets uploaded to target hosts by MCP tools.

## Response style

For incident-response reports or user-facing analysis, begin with this ASCII banner in a `text` code block:

```text
    ___         __        ________  __  ___ ______ ____
   /   | __  __/ /_____  /  _/ __ \/  |/  // ____// __ \
  / /| |/ / / / __/ __ \ / // /_/ / /|_/ // /    / /_/ /
 / ___ / /_/ / /_/ /_/ // // _, _/ /  / // /___ / ____/
/_/  |_\__,_/\__/\____/___/_/ |_/_/  /_/ \____//_/
```

Then use this normalized structure: summary, findings table, risk analysis, remediation advice, and suggested next tools. Use risk labels consistently: `高`, `中`, `低`, `信息`, or `未发现明显异常`.
