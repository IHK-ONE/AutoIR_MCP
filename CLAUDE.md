# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Development commands

- Install dependencies: `uv sync`
- Run the MCP server locally: `uv run python AutoIR_MCP.py`
- Check Python syntax: `python -m py_compile AutoIR_MCP.py functions.py DumpFileInfo.py`
- Verify the lockfile is current: `uv lock --check`
- Check whitespace/conflict-marker issues before committing: `git diff --check`

No test runner or lint configuration is currently defined in this repository.

## Architecture overview

This repository implements an AutoIR incident-response MCP server using FastMCP. The server exposes SSH-based Linux response tools for user, process, network, file, persistence, log, and rootkit checks.

- `AutoIR_MCP.py` owns the FastMCP app, global SSH session state, MCP tool definitions, and orchestration prompt. Most response functionality lives here.
- `functions.py` contains shared helpers for remote command execution, SFTP transfers, `ls -al` parsing, timestamp formatting, local malicious shell detection, and SafeLine WAF checks.
- `DumpFileInfo.py` is a standalone helper for generating/updating the `/usr/bin` baseline in `config/info_bin.json`. It reads SSH target settings from `AUTOIR_BASELINE_IP`, `AUTOIR_BASELINE_PORT`, `AUTOIR_BASELINE_USERNAME`, and `AUTOIR_BASELINE_PASSWORD` when set.
- `config/config.json` stores the SafeLine WAF GET endpoint used by `check_safe_safeline()`.
- `config/info_bin.json` and `config/info_proc.json` are local baselines used by binary and process checks.
- `extensions/` stores local scanner/rootkit assets that are uploaded to target hosts by MCP tools.

## MCP usage flow

The MCP prompt expects callers to establish SSH first with `get_ssh_client`, then call `check_safeline` before deeper analysis. Tool outputs are mostly plain or tab-delimited strings intended for downstream AI analysis, so keep return values concise and explicit about command failures or empty findings.

When modifying tools, preserve existing tool names and parameters unless the caller-facing MCP contract intentionally changes. Prefer adding safe defaults and fallback commands over introducing new dependencies.
