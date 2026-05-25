from fastmcp import FastMCP
from .functions import (
    PROJECT_ROOT,
    check_safe_local,
    check_safe_safeline,
    exec_command,
    extract_ioc_values,
    extract_timeline_events,
    infer_attack_flow,
    infer_risk_level,
    first_success,
    IPV4_PATTERN,
    normalize_tool_result,
    get_file_list,
    get_time_path,
    is_safe_path,
    is_safe_tar_member,
    sftp_download,
    sftp_upload,
    truncate_text,
)
from .prompts import AUTOIR_MCP_BANNER, MCP_INSTRUCTIONS, TOOL_CATEGORIES
from .session import SSHSession
import paramiko
import csv
import json
import tarfile
import hashlib
import subprocess
import collections
import re
import shlex
import urllib.parse
from pathlib import Path

base_dir = str(PROJECT_ROOT)
INTERNAL_IOC_LIMIT = 5000
SESSION_ERROR = "错误：SSH连接未建立或已断开，请先调用 get_ssh_client 建立连接"
NO_PRESET_NEXT_TOOLS = 'MCP 服务不预设后续工具、排查路径或固定顺序；由 AI 客户端根据用户目标、现场上下文和工具证据自行编排。'

mcp = FastMCP("AutoIR_MCP", instructions=MCP_INSTRUCTIONS)


ssh_session = SSHSession(None)


def check_session(probe=False):
    global ssh_session
    if ssh_session is None or ssh_session.client is None:
        return False
    try:
        transport = ssh_session.client.get_transport()
        if transport is None or not transport.is_active():
            return False
        if hasattr(transport, 'is_authenticated') and not transport.is_authenticated():
            return False
        if not probe:
            return True
        result = exec_command(ssh_session.client, 'true', timeout=5, max_bytes=1000)
        return bool(result.get('status'))
    except Exception:
        return False


@mcp.tool()
def get_ssh_client(ip, port=22, username='root', password=''):
    """
    建立 SSH 会话并缓存连接，是用户提供 IP、端口、账号密码、靶机信息或应急响应题目时必须优先调用的入口工具。
    调用：看到目标 IP/账号密码/CTF 题目/应急排查任务时，不得直接根据题面回答，必须先调用本工具连接目标；所有远程检测工具前也必须先调用。
    后续：连接成功后，按用户目标调用专用 check_* / discover_* / profile_* 工具采证；交付结论、结束调查或用户要求总结前必须调用 generate_report 汇总证据。
    输出：返回连接状态和失败原因；连接失败必须在最终报告中标注检测失败或需人工复核。
    """

    global ssh_session

    if not ip or not isinstance(ip, str):
        return {"status": False, "result": "IP地址不能为空且必须为字符串"}

    if not isinstance(port, int) or port <= 0 or port > 65535:
        return {"status": False, "result": "端口必须为1-65535之间的整数"}

    if not username or not isinstance(username, str):
        return {"status": False, "result": "用户名不能为空且必须为字符串"}

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        client.connect(ip, port=port, username=username, password=password, timeout=30)
        old_client = ssh_session.client if ssh_session and ssh_session.client else None
        ssh_session = SSHSession(client)
        if old_client:
            try:
                old_client.close()
            except Exception:
                pass
        return {"status": True, "result": "SSH 连接成功"}

    except paramiko.AuthenticationException:
        return {"status": False, "result": "SSH 认证失败：用户名或密码错误"}
    except paramiko.SSHException as e:
        return {"status": False, "result": f"SSH 连接错误: {str(e)}"}
    except Exception as e:
        return {"status": False, "result": f"SSH 连接失败: {str(e)}"}


@mcp.tool()
def check_ssh_session():
    """
    检查当前 SSH 会话状态。
    调用：需要确认是否已连接目标主机、连接是否仍可用时使用。
    输出：返回 connected 状态和说明。
    """
    connected = check_session(probe=True)
    return {
        "status": connected,
        "connected": connected,
        "result": "SSH 会话可用" if connected else "SSH 会话未建立或已断开",
    }


@mcp.tool()
def close_ssh_client():
    """
    关闭当前 SSH 会话。
    调用：完成排查或需要释放连接时使用。
    输出：返回关闭状态。
    """
    global ssh_session
    try:
        if ssh_session and ssh_session.client:
            ssh_session.client.close()
    except Exception as error:
        ssh_session = SSHSession(None)
        return {"status": False, "result": f"SSH 会话关闭异常: {error}"}
    ssh_session = SSHSession(None)
    return {"status": True, "result": "SSH 会话已关闭"}


@mcp.tool()
def reset_session(close_connection=True):
    """
    重置当前 MCP 会话状态。
    调用：需要清空缓存的用户、进程、网络等状态时使用；默认同时关闭 SSH 连接。
    输出：返回重置状态。
    """
    global ssh_session
    old_client = ssh_session.client if ssh_session else None
    if close_connection and old_client:
        try:
            old_client.close()
        except Exception:
            pass
        ssh_session = SSHSession(None)
        return {"status": True, "result": "会话状态已重置，SSH 连接已关闭"}
    if ssh_session is None:
        ssh_session = SSHSession(old_client)
    else:
        ssh_session.client = old_client
        ssh_session.reset_analysis_state()
    return {"status": True, "result": "会话状态已重置，SSH 连接保持不变"}


@mcp.tool()
def shell(command, timeout=10, max_bytes=200000):
    """
    在已连接的 SSH 目标主机上执行 shell 命令。
    调用：需要 AI 直接通过 MCP 对目标机执行命令时使用，不使用本地 Bash；必须先调用 get_ssh_client。
    输出：返回 exec_command 的统一执行结果。
    """
    if not check_session():
        return {"status": False, "result": SESSION_ERROR}
    if not isinstance(command, str) or not command.strip():
        return {"status": False, "result": "command 不能为空"}
    try:
        timeout = max(1, min(int(timeout), 600))
    except (TypeError, ValueError):
        timeout = 10
    try:
        max_bytes = max(1024, min(int(max_bytes), 5_000_000))
    except (TypeError, ValueError):
        max_bytes = 200000

    return exec_command(ssh_session.client, command.strip(), timeout=timeout, max_bytes=max_bytes)



@mcp.tool()
def check_safeline():
    """
    检测 SafeLine WAF 可用性。
    调用：SSH 连接成功后优先调用一次，用于后续恶意命令/请求辅助判断。
    输出：返回 WAF 存活状态。
    """
    ssh_session.safeline_available = bool(check_safe_safeline('bash -i'))
    if ssh_session.safeline_available:
        return {"status": True, "result": "雷池 WAF 服务存活"}
    return {"status": False, "result": "雷池 WAF 未存活，继续运行"}


@mcp.tool()
def get_tool_inventory():
    """
    获取 MCP 工具清单。
    调用：需要了解可用纯工具和工具分组时使用；不返回任何预设排查路径。
    输出：返回工具分类。
    """
    return {
        "categories": TOOL_CATEGORIES,
    }


def ioc_source_text(text=''):
    return str(text or '')


def clamp_int(value, default, minimum=1, maximum=500):
    try:
        return max(minimum, min(int(value), maximum))
    except (TypeError, ValueError):
        return default


def trim_iocs(iocs, limit):
    limit = clamp_int(limit, 50, minimum=1, maximum=500)
    return {key: (values or [])[:limit] for key, values in (iocs or {}).items()}


def iocs_truncated(iocs, limit, extraction_limit=None):
    limit = clamp_int(limit, 50, minimum=1, maximum=500)
    extraction_limit = clamp_int(extraction_limit, 0, minimum=0, maximum=INTERNAL_IOC_LIMIT) if extraction_limit else None
    return any(
        len(values or []) > limit or (extraction_limit and len(values or []) >= extraction_limit)
        for values in (iocs or {}).values()
    )


def format_ioc_lines(iocs, limit=50, extraction_limit=None):
    lines = []
    labels = {
        'ips': 'IP',
        'domains': '域名',
        'urls': 'URL',
        'paths': '路径',
        'ports': '端口',
    }
    limit = clamp_int(limit, 50, minimum=1, maximum=500)
    extraction_limit = clamp_int(extraction_limit, 0, minimum=0, maximum=INTERNAL_IOC_LIMIT) if extraction_limit else None
    for key, label in labels.items():
        all_values = iocs.get(key) or []
        values = all_values[:limit]
        hidden = len(all_values) - limit
        if hidden > 0 and extraction_limit and len(all_values) >= extraction_limit:
            suffix = f'（另有 {hidden} 条已提取未展示；提取达到上限，实际数量可能更多）'
        elif hidden > 0:
            suffix = f'（另有 {hidden} 条未展示）'
        else:
            suffix = ''
        lines.append(f'- {label}: {", ".join(values) + suffix if values else "未提取到"}')
    return '\n'.join(lines)


def format_timeline_lines(events, limit=10):
    if not events:
        return '未提取到常见时间格式的事件线索'
    limit = clamp_int(limit, 10, minimum=1, maximum=100)
    rows = ['| 时间 | 事件 | 来源 |', '|---|---|---|']
    for item in events[:limit]:
        event = item['event'].replace('|', '/')
        source_name = item['source'].replace('|', '/')
        rows.append(f'| {item["time"]} | {event} | {source_name} |')
    if len(events) > limit:
        rows.append(f'| ... | 另有 {len(events) - limit} 条时间线线索未展示 | ... |')
    return '\n'.join(rows)


def summarize_input_sections(content, max_sections=12):
    rows = []
    current = ''
    body = []
    for line in content.splitlines():
        if line.startswith('## '):
            if current:
                rows.append((current, body))
            current = line[3:].strip()
            body = []
        elif current and line.strip():
            body.append(line.strip())
    if current:
        rows.append((current, body))

    findings = []
    for name, lines in rows[:max_sections]:
        section_text = '\n'.join(lines) if lines else '无输出'
        text = next((line for line in lines if not line.startswith('[status=')), section_text)
        risk = infer_risk_level(section_text)
        evidence, _ = truncate_text(text, max_chars=160)
        findings.append(f'| {name} | {evidence.replace("|", "/")} | {risk} | 最近输入材料 |')
    if not findings:
        findings.append('| 输入材料 | 暂无可结构化的工具输出 | 信息 | 证据不足 |')
    return '\n'.join(findings)


@mcp.tool()
def extract_iocs(text='', limit=100):
    """
    从输入文本或最近一次输入材料提取 IOC。
    调用：需要从日志、进程、WebShell 或其他工具输出中汇总 IP、域名、URL、路径和端口时使用。
    输出：返回去重后的 IOC 字段，不做外部情报查询；limit 控制每类 IOC 最大数量。
    """
    source = ioc_source_text(text)
    if not source.strip():
        return normalize_tool_result('extract_iocs', {"status": False, "result": "没有可提取 IOC 的文本；请传入 text 或已有工具输出"})
    limit = clamp_int(limit, 100, minimum=1, maximum=500)
    iocs = extract_ioc_values(source, limit=INTERNAL_IOC_LIMIT)
    visible_iocs = trim_iocs(iocs, limit)
    truncated = iocs_truncated(iocs, limit, extraction_limit=INTERNAL_IOC_LIMIT)
    result = format_ioc_lines(iocs, limit=limit, extraction_limit=INTERNAL_IOC_LIMIT)
    return {
        "status": True,
        "result": result,
        "iocs": visible_iocs,
        "data": {"iocs": visible_iocs},
        "error": "",
        "meta": {"tool": "extract_iocs", "risk": "信息", "empty": not any(iocs.values()), "truncated": truncated, "kind": "dict"},
    }


@mcp.tool()
def generate_timeline(text='', max_events=100):
    """
    从输入文本或最近输入材料生成事件时间线。
    调用：需要复盘入侵过程、梳理日志/文件/登录事件先后顺序时使用。
    输出：返回按原始材料出现顺序整理的 markdown 时间线表。
    """
    source = ioc_source_text(text)
    if not source.strip():
        return normalize_tool_result('generate_timeline', {'status': False, 'result': '没有可提取时间线的文本；请传入 text，或先提供已有工具输出'})
    max_events = clamp_int(max_events, 100, minimum=1, maximum=500)
    events = extract_timeline_events(source, limit=max_events)
    if not events:
        return normalize_tool_result('generate_timeline', '未提取到常见时间格式的事件线索')
    rows = ['| 时间 | 事件 | 来源 |', '|---|---|---|']
    for item in events:
        event = item['event'].replace('|', '/')
        source_name = item['source'].replace('|', '/')
        rows.append(f'| {item["time"]} | {event} | {source_name} |')
    result = '\n'.join(rows)
    normalized = normalize_tool_result('generate_timeline', result)
    normalized['data'] = {'events': events}
    return normalized


@mcp.tool()
def analyze_attack_chain(text='', max_stages=8, evidence_limit=3, include_unobserved=True, max_timeline_events=30, max_iocs_per_type=50):
    """
    基于输入文本或最近输入材料分析攻击链阶段。
    调用：需要让 AI 客户端复盘初始访问、落地执行、提权、持久化、外联和影响动作时使用。
    输出：返回攻击阶段表、路径判断、IOC 和时间线数据；max_iocs_per_type 控制 IOC 展示数量。
    """
    source = ioc_source_text(text)
    if not source.strip():
        return normalize_tool_result('analyze_attack_chain', {'status': False, 'result': '没有可分析攻击链的文本；请传入 text，或先提供已有工具输出'})
    max_stages = clamp_int(max_stages, 8, minimum=1, maximum=8)
    evidence_limit = clamp_int(evidence_limit, 3, minimum=1, maximum=10)
    max_timeline_events = clamp_int(max_timeline_events, 30, minimum=1, maximum=200)
    max_iocs_per_type = clamp_int(max_iocs_per_type, 50, minimum=1, maximum=500)
    ioc_extract_limit = INTERNAL_IOC_LIMIT
    iocs = extract_ioc_values(source, limit=ioc_extract_limit)
    timeline_events = extract_timeline_events(source, limit=max_timeline_events)
    attack_flow = infer_attack_flow(
        source,
        iocs=iocs,
        timeline_events=timeline_events,
        max_items=max_stages,
        evidence_limit=evidence_limit,
        include_unobserved=include_unobserved,
    )
    result = f'''## 攻击路径判断

{attack_flow['summary']}

## 攻击阶段表

{attack_flow['markdown']}

## IOC 摘要

{format_ioc_lines(iocs, limit=max_iocs_per_type, extraction_limit=ioc_extract_limit)}

## 时间线摘要

{format_timeline_lines(timeline_events, limit=min(max_timeline_events, 20))}
'''
    has_evidence = any(stage['status'] == '发现线索' for stage in attack_flow['stages'])
    has_network_iocs = any(iocs.get(key) for key in ('ips', 'domains', 'urls'))
    truncated = iocs_truncated(iocs, max_iocs_per_type, extraction_limit=ioc_extract_limit)
    return {
        'status': True,
        'result': result,
        'data': {
            'iocs': trim_iocs(iocs, max_iocs_per_type),
            'timeline_events': timeline_events,
            'attack_flow': attack_flow,
        },
        'error': '',
        'meta': {
            'tool': 'analyze_attack_chain',
            'risk': '中' if has_evidence or has_network_iocs else '信息' if any(iocs.values()) or timeline_events else '未发现明显异常',
            'empty': not has_evidence and not any(iocs.values()) and not timeline_events,
            'truncated': truncated,
            'kind': 'dict',
        },
    }


@mcp.tool()
def generate_report(extra_context='', include_iocs=True, report_profile='standard', focus='', max_summary_chars=1200, max_findings=12, max_timeline_events=50, max_iocs_per_type=50, evidence_limit=3, include_timeline=True, include_next_tools=False):
    """
    调查结束前必须调用的最终汇总工具，基于 extra_context 或已有输入材料生成规范化结论报告。任务结束时输出必须附加报告正文。
    调用：交付结论、结束调查或用户要求总结前必须调用；可用 report_profile/focus 控制报告画像与关注方向。
    输出：返回包含 banner、案件背景/摘要、检测结果表、IOC、时间线、攻击流程、风险分析、处置原则和 AI 编排说明的报告草稿。
    要求：检测结果表字段固定为 | 检测项 | 关键发现 | 风险 | 依据 |；风险等级只能使用 高 / 中 / 低 / 信息 / 未发现明显异常；证据不足时标注 待检测 或 需人工复核，不得编造完整攻击链。
    """
    content = ioc_source_text(extra_context)
    has_content = bool(content.strip())
    if not has_content:
        content = '未提供 extra_context 或已有工具输出；尚未执行检测或当前上下文没有可汇总证据。'

    profiles = {
        'standard': '标准应急报告',
        'executive': '管理层摘要，突出影响、风险和处置优先级',
        'technical': '技术复盘，突出证据、IOC、时间线和工具依据',
        'handoff': '交接报告，突出已做检查、未决问题和证据缺口',
    }
    report_profile = str(report_profile or 'standard').strip().lower()
    if report_profile not in profiles:
        report_profile = 'standard'
    max_summary_chars = clamp_int(max_summary_chars, 1200, minimum=300, maximum=10000)
    max_findings = clamp_int(max_findings, 12, minimum=1, maximum=50)
    max_timeline_events = clamp_int(max_timeline_events, 50, minimum=1, maximum=200)
    max_iocs_per_type = clamp_int(max_iocs_per_type, 50, minimum=1, maximum=500)
    evidence_limit = clamp_int(evidence_limit, 3, minimum=1, maximum=10)

    findings = summarize_input_sections(content, max_sections=max_findings)
    ioc_extract_limit = INTERNAL_IOC_LIMIT
    iocs = extract_ioc_values(content, limit=ioc_extract_limit)
    timeline_events = extract_timeline_events(content, limit=max_timeline_events)
    attack_flow = infer_attack_flow(content, iocs=iocs, timeline_events=timeline_events, evidence_limit=evidence_limit)
    ioc_text = format_ioc_lines(iocs, limit=max_iocs_per_type, extraction_limit=ioc_extract_limit) if include_iocs else '未启用 IOC 摘要展示'
    timeline_text = format_timeline_lines(timeline_events, limit=min(max_timeline_events, 15)) if include_timeline else '未启用时间线摘要'
    next_tools = NO_PRESET_NEXT_TOOLS
    has_attack_flow = any(stage['status'] == '发现线索' for stage in attack_flow['stages'])
    if not has_content:
        risk_note = '未提供可汇总的工具证据，不能判断是否存在入侵、WebShell、持久化或影响动作；所有结论均应标注为待检测或需人工复核。'
    elif any(iocs.values()) or '[!]' in content or has_attack_flow:
        risk_note = '发现可疑线索，需结合原始日志和业务上下文人工复核。'
    else:
        risk_note = '当前摘要未提取到明确 IOC 或攻击阶段证据，仍需结合工具失败、权限不足和截断情况复核。'
    summary, truncated = truncate_text(content, max_chars=max_summary_chars)
    truncated_note = '；报告摘要已截断' if truncated else ''
    focus_line = f'- 关注方向：{focus}' if str(focus or '').strip() else '- 关注方向：未指定，按通用 Linux 应急响应组织。'
    background_line = '- 案件背景：来自用户输入、题目信息、目标信息或已执行 MCP 工具输出。' if has_content else '- 案件背景：未提供可汇总材料；任务背景、目标信息和工具证据均待补充。'
    evidence_status = '已提供输入材料，以下结论仅基于当前材料。' if has_content else '待检测：未提供 extra_context 或可汇总工具输出。'

    return f'''```text
{AUTOIR_MCP_BANNER}
```

## 案件背景

{background_line}
{focus_line}
- 报告画像：{report_profile}（{profiles[report_profile]}）
- 证据状态：{evidence_status}

## 摘要

- 材料来源：extra_context / 工具输出{truncated_note}
- 关键摘要：

```text
{summary}
```

## 检测结果表

| 检测项 | 关键发现 | 风险 | 依据 |
|---|---|---|---|
{findings}

## 检测状态说明

- 未发现明显异常：仅表示当前材料未见明确异常，不代表目标绝对安全。
- 检测失败 / 权限不足 / 输出截断：必须按工具原始结果呈现，不能归类为无异常。
- 待检测 / 需人工复核：表示当前证据不足，不能编造结论。

## IOC 摘要

{ioc_text}

## 时间线摘要

{timeline_text}

## 攻击流程分析

{attack_flow['markdown']}

### 攻击路径判断

{attack_flow['summary']}

## 风险分析

{risk_note}

## 处置原则

- 仅将工具输出作为证据来源，不能把单条线索直接写成已确认失陷。
- 风险定性必须结合原始日志、业务上下文、权限边界和时间线交叉验证。
- 报告中标注“需人工复核”的阶段必须回看原始证据后再定性。

## AI 编排说明

{next_tools}
'''


def command_format(check, command):
    return 'env -i /usr/bin/' + command if check else command


def quote_remote_path(path):
    return shlex.quote(str(path))


def detect_malicious_text(content, use_safeline=True):
    malicious_local = check_safe_local(content)
    if not use_safeline or not ssh_session.safeline_available:
        return malicious_local
    malicious_safeline = check_safe_safeline(content)
    return malicious_local + malicious_safeline


def file_md5(path):
    digest = hashlib.md5()
    with open(path, 'rb') as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def empty_result(message='未发现明显异常'):
    return message


def command_failure(result, action='命令执行失败'):
    detail = result.get('error') or result.get('stderr') or result.get('result') or '无错误详情'
    return f'{action}: {detail}'


def count_ips_from_lines(lines):
    counts = {}
    for line in lines:
        ip_match = IPV4_PATTERN.search(line)
        if ip_match:
            ip = ip_match.group()
            counts[ip] = counts.get(ip, 0) + 1
    return counts


def format_ip_counts(counts, label):
    if not counts:
        return ''
    return '\n'.join(f'ip: {ip}\tcount: {count}\t[!] {label}' for ip, count in counts.items())


def check_export(filename, data):
    try:
        export_list = re.findall(r'export (.*)=(.*)', data)
        for key, value in export_list:
            if key in ('PATH', 'LD_PRELOAD', 'LD_AOUT_PRELOAD', 'LD_ELF_PRELOAD', 'LD_LIBRARY_PATH',
                       'PROMPT_COMMAND') and value != '"$PATH:${snap_bin_path}"':
                ssh_session.hijack_output.append(f'filename: {filename}\texport {key}={value}\t[!] 环境变量劫持')
    except (TypeError, ValueError):
        pass


def process_files(file_list, base_path=''):
    for file in file_list:
        path = f'{base_path}{file}' if base_path else file
        command = command_format(ssh_session.hijack, f'cat {quote_remote_path(path)}')
        result = exec_command(ssh_session.client, command)

        if result['status'] and result['result']:
            check_export(path, result['result'])


@mcp.tool()
def check_hijack():
    """
    检查 shell 初始化文件中的环境变量劫持。
    调用：怀疑 PATH、LD_PRELOAD、PROMPT_COMMAND 等被篡改时使用。
    输出：返回可疑文件、变量和值。
    """

    if not check_session():
        return SESSION_ERROR

    ssh_session.hijack = False
    ssh_session.hijack_output = []

    common_files = ['/root/.bashrc', '/root/.tcshrc', '/root/.bash_profile', '/root/.cshrc', '/etc/bashrc',
                    '/etc/profile', '/etc/csh.login', '/etc/csh.cshrc']
    home_files = ['.bashrc', '.bash_profile', '.tcshrc', '.cshrc']

    result = exec_command(ssh_session.client, 'ls -al .')
    if result['status'] and result['result'][:5] != 'total':
        result = exec_command(ssh_session.client, 'env -i /usr/bin/ls -al .')
        if result['status'] and result['result'][:5] == 'total':
            ssh_session.hijack = True

    process_files(common_files)

    profile_d_files = []
    profile_d_command = command_format(ssh_session.hijack, 'ls -al /etc/profile.d/')
    profile_d_result = exec_command(ssh_session.client, profile_d_command)
    if profile_d_result['status'] and profile_d_result['result']:
        profile_d_files = [file['filename'] for file in get_file_list(profile_d_result['result']).values()]
    process_files(profile_d_files, '/etc/profile.d/')

    home_dir_command = command_format(ssh_session.hijack, 'ls -al /home')
    home_dir_result = exec_command(ssh_session.client, home_dir_command)
    if home_dir_result['status'] and home_dir_result['result']:
        ssh_session.user_list = [file['filename'] for file in get_file_list(home_dir_result['result']).values()]
        process_files([f'/home/{user}/{f}' for user in ssh_session.user_list for f in home_files])

    return '\n'.join(ssh_session.hijack_output)


def extract_users_from_output(output):
    return [line.strip().split()[-1] for line in output.splitlines() if line.strip()]


def get_group():
    result = exec_command(ssh_session.client, f'cat /etc/group')
    if result['status'] and result['result']:
        for line in result['result'].splitlines():
            parts = line.strip().split(':')
            if len(parts) >= 4:
                group_name, _, _, users = parts
                ssh_session.group_list[group_name] = [user.strip() for user in users.split(',') if user.strip()]


def load_home_users(force=False):
    if ssh_session.user_list and not force:
        return ssh_session.user_list
    result = exec_command(ssh_session.client, 'ls -al /home')
    if result['status'] and result['result']:
        ssh_session.user_list = [file['filename'] for file in get_file_list(result['result']).values()]
    return ssh_session.user_list


@mcp.tool()
def check_home():
    """
    枚举 /home 用户目录。
    调用：用户排查的基础步骤，可为 history、ssh key、rc 文件检测提供用户列表。
    输出：返回发现的用户目录名。
    """

    if not check_session():
        return SESSION_ERROR

    return '\n'.join(load_home_users())


@mcp.tool()
def check_history():
    """
    检查 root 与普通用户的 bash_history 是否存在。
    调用：发现可疑用户或需追踪操作痕迹时使用。
    输出：返回存在历史记录的路径。
    """

    if not check_session():
        return SESSION_ERROR
    output = []

    if not ssh_session.user_list:
        load_home_users()

    result = exec_command(ssh_session.client, f'cat /root/.bash_history')
    if result['status'] and result['result']:
        output.append(f'[!] 存在 bash_history: /root/.bash_history')

    for user in ssh_session.user_list:
        result = exec_command(ssh_session.client, f'cat /home/{user}/.bash_history')
        if result['status'] and result['result']:
            output.append(f'[!] 存在 bash_history: /home/{user}/.bash_history')

    return '\n'.join(output)


@mcp.tool()
def check_passwd():
    """
    分析 /etc/passwd 中可登录、UID/GID 异常的账户。
    调用：排查恶意用户、隐藏特权账户或异常 shell 权限时使用。
    输出：返回用户、shell 和异常原因。
    """

    if not check_session():
        return SESSION_ERROR

    result = exec_command(ssh_session.client, f'cat /etc/passwd')
    output = []

    if result['status'] and result['result']:
        for line in result['result'].splitlines():
            parts = line.strip().split(':')
            if len(parts) >= 7:
                user_name, _, user_uid, user_gid, _, _, user_shell = parts

                issues = []
                if ('nologin' not in user_shell) and (user_name != 'root'):
                    if "sh" in user_shell:
                        issues.append('拥有 shell 权限 [拥有系统 shell]')
                    else:
                        issues.append('拥有 shell 权限 [请检测 shell]')
                if user_uid == '0' and user_name != 'root':
                    issues.append('root 标识用户')
                if user_gid == '0' and user_name != 'root':
                    issues.append('特权用户')

                if issues:
                    output.append(f'user: {user_name}\t"shell: {user_shell}\t[!] {"、".join(issues)}')

    return '\n'.join(output)


@mcp.tool()
def check_ssh_keys():
    """
    检查 root 与普通用户的 authorized_keys。
    调用：排查 SSH 免密后门或未知公钥时使用；必要时先调用 check_home。
    输出：返回密钥文件路径和提取到的 key 注释用户。
    """

    if not check_session():
        return SESSION_ERROR

    output = []

    if not ssh_session.user_list:
        load_home_users()

    result = exec_command(ssh_session.client, f'cat /root/.ssh/authorized_keys')
    if result['status'] and result['result']:
        users = ', '.join(extract_users_from_output(result['result']))
        output.append(f'/root/.ssh/authorized_keys\tuser list{users}\t[!] 存在 SSH authorized_keys')

    result = exec_command(ssh_session.client, f'find /root/.ssh/ -type f 2>/dev/null')
    if result['status'] and result['result']:
        output.append(f'{result["result"]}\t[!] 存在 SSH authorized_keys')

    for user in ssh_session.user_list:
        result = exec_command(ssh_session.client, f'cat /home/{user}/.ssh/authorized_keys')
        if result['status'] and result['result']:
            users = ', '.join(extract_users_from_output(result['result']))
            output.append(f'/home/{user}/.ssh/authorized_keys\tuser list：{users}\t[!] 存在 SSH authorized_keys')

    for user in ssh_session.user_list:
        result = exec_command(ssh_session.client, f'find /home/{user}/.ssh/ -type f 2>/dev/null')
        if result['status'] and result['result']:
            output.append(f'{result["result"]}\t[!] 存在 SSH authorized_keys')

    return '\n'.join(output)


@mcp.tool()
def check_shadow():
    """
    检查 /etc/shadow 空口令账户。
    调用：排查弱口令、无密码登录或异常账户时使用。
    输出：返回空口令用户名。
    """

    if not check_session():
        return SESSION_ERROR

    result = exec_command(ssh_session.client, f'cat /etc/shadow')
    output = []

    if result['status'] and result['result']:
        for line in result['result'].splitlines():
            parts = line.strip().split(':')
            if len(parts) >= 2:
                user_name, hashcode = parts[0], parts[1]
                if not hashcode:
                    output.append(f'user: {user_name}\t[!] 空口令账户')

    return '\n'.join(output)


@mcp.tool()
def check_sudoers():
    """
    检查 sudoers 中高权限用户和组。
    调用：排查提权风险、异常 sudo 授权或管理员组滥用时使用。
    输出：返回可 sudo 的用户/组及组成员。
    """

    if not check_session():
        return SESSION_ERROR

    output = []
    result = first_success(ssh_session.client, [
        'cat /etc/sudoers /etc/sudoers.d/* 2>/dev/null',
        'cat /etc/sudoers 2>/dev/null',
    ])

    if not result['status']:
        return command_failure(result, 'sudoers 读取失败')
    if not result['result']:
        return empty_result()

    get_group()
    for line in result['result'].splitlines():
        line = line.strip()
        if ('ALL=(ALL)' in line or 'ALL=(root)' in line) and not line.startswith('#'):
            parts = line.split()
            if len(parts) > 0:
                user_or_group = parts[0]

                if user_or_group.startswith('%'):
                    group_name = user_or_group[1:]
                    users_in_group = ssh_session.group_list.get(group_name, [])
                    tmp = f'group: {group_name}\tuser: {", ".join(users_in_group)}'
                    output.append(f'{tmp}\t[!] sudo 权限组异常')
                else:
                    tmp = f'{"user: " + user_or_group}'
                    output.append(f'{tmp}\t[!] sudo 权限组异常')

    return '\n'.join(output) or empty_result()


privilege_escalation = ['aa-exec', 'aoss', 'apt-get', 'apt', 'ash', 'at', 'awk',
                        'aws', 'bash', 'batcat', 'bconsole', 'bundle', 'bundler', 'busctl', 'busybox', 'byebug', 'c89',
                        'c99', 'cabal', 'capsh', 'cdist', 'certbot', 'check_by_ssh', 'choom', 'cobc', 'composer',
                        'cowsay', 'cowthink', 'cpan', 'cpio', 'cpulimit', 'crash', 'csh', 'csvtool', 'dash', 'dc',
                        'debugfs', 'distcc', 'dmesg', 'docker', 'dotnet', 'dpkg', 'dstat', 'dvips', 'easy_install',
                        'eb', 'ed', 'elvish', 'emacs', 'enscript', 'env', 'ex', 'expect', 'facter', 'find', 'fish',
                        'flock', 'ftp', 'gawk', 'gcc', 'gcloud', 'gdb', 'gem', 'genie', 'ghc', 'ghci', 'gimp', 'ginsh',
                        'git', 'grc', 'gtester', 'hping3', 'iftop', 'ionice', 'irb', 'ispell', 'jjs', 'joe',
                        'journalctl', 'jrunscript', 'jtag', 'julia', 'knife', 'ksh', 'latex', 'latexmk', 'ld.so',
                        'less', 'lftp', 'loginctl', 'logsave', 'ltrace', 'lua', 'lualatex', 'luatex', 'mail', 'make',
                        'man', 'mawk', 'minicom', 'more', 'msfconsole', 'msgfilter', 'multitime', 'mysql', 'nano',
                        'nawk', 'ncdu', 'ncftp', 'neofetch', 'nice', 'nmap', 'node', 'nohup', 'npm', 'nroff', 'nsenter',
                        'octave', 'openvpn', 'pandoc', 'pdb', 'pdflatex', 'pdftex', 'perf', 'perl', 'perlbug', 'pexec',
                        'pg', 'php', 'pic', 'pico', 'pip', 'posh', 'pry', 'psftp', 'psql', 'puppet', 'pwsh', 'python',
                        'rake', 'rc', 'rlwrap', 'rpm', 'rpmdb', 'rpmquery', 'rpmverify', 'rsync', 'rtorrent', 'ruby',
                        'run-mailcap', 'run-parts', 'runscript', 'rview', 'rvim', 'sash', 'scanmem', 'scp', 'screen',
                        'script', 'scrot', 'sed', 'service', 'setarch', 'setlock', 'sftp', 'sg', 'slsh', 'smbclient',
                        'socat', 'softlimit', 'split', 'sqlite3', 'sqlmap', 'ssh-agent', 'ssh', 'sshpass',
                        'start-stop-daemon', 'stdbuf', 'strace', 'tar', 'task', 'taskset', 'tasksh', 'tclsh', 'tdbtool',
                        'telnet', 'tex', 'time', 'timedatectl', 'timeout', 'tmate', 'tmux', 'top', 'torify', 'torsocks',
                        'tshark', 'unshare', 'vagrant', 'valgrind', 'vi', 'view', 'vim', 'vimdiff', 'volatility',
                        'watch', 'wget', 'wish', 'xargs', 'xdg-user-dir', 'xdotool', 'xelatex', 'xetex', 'yarn', 'yash',
                        'zathura', 'zip', 'zsh', 'zypper']


def parse_ps_output(output):
    processes = {}
    for line in output.splitlines()[1:]:
        try:
            parts = re.split(r'\s+', line.strip())
            if len(parts) < 11:
                continue

            pid = int(parts[1])
            command = ' '.join(parts[10:])
            exe = command.split()[0]
            if ':' in exe:
                exe = exe.split(':')[0]
            elif '/' in exe:
                exe = Path(exe).name
            elif '(' in exe:
                exe = exe[1:-1]

            processes[pid] = {
                'user': parts[0],
                'cpu': float(parts[2]),
                'mem': float(parts[3]),
                'tty': parts[6],
                'time': parts[9],
                'command': command,
                'exe': exe}
        except (IndexError, ValueError):
            continue
    return processes


def load_processes():
    ssh_session.ps = {}
    result = exec_command(ssh_session.client, 'ps -aux')
    if result['status'] and result['result']:
        ssh_session.ps = parse_ps_output(result['result'])
    return len(ssh_session.ps)


@mcp.tool()
def get_ps():
    """
    采集进程快照。
    调用：进程类检测前优先调用；后续 check_mine、check_exec、check_pid、check_exe 复用该快照。
    输出：返回采集到的进程数量。
    """

    if not check_session():
        return SESSION_ERROR

    return f"已获取 {load_processes()} 个进程信息"


@mcp.tool()
def check_mine():
    """
    检测高 CPU/内存占用进程。
    调用：怀疑挖矿、资源异常或主机卡顿时使用；会自动补采进程快照。
    输出：返回超过阈值的 PID、资源占用和命令。
    """

    if not check_session():
        return SESSION_ERROR

    if not ssh_session.ps:
        load_processes()

    output = ''
    for pid, proc in ssh_session.ps.items():
        cpu, mem, command = proc['cpu'], proc['mem'], proc['command']
        if cpu > 50.0 or mem > 50.0:
            output += f'PID: {pid}\tCPU: {cpu}\tMEM: {mem}\tCOMMAND: {command}\t[!] "疑似挖矿脚本，cpu/mem 占用超过 50%", "red"\n'
    return output or empty_result()


@mcp.tool()
def check_exec():
    """
    检测可疑命令执行进程。
    调用：排查反弹 shell、相对路径执行、root 可提权命令或 WAF 命中特征时使用。
    输出：返回 PID、TTY、命令和可疑原因。
    """

    if not check_session():
        return SESSION_ERROR

    if not ssh_session.ps:
        load_processes()

    output = ''
    root_command = []

    for pid, proc in ssh_session.ps.items():
        user, tty, command, exe = proc['user'], proc['tty'], proc['command'], proc['exe']
        reasons = []

        if 'ttyS' not in tty and tty != '?':
            reasons.append('tty 虚拟终端执行命令')
        if './' in command:
            reasons.append('通过相对路径运行命令')
        if user == 'root' and exe not in root_command:
            root_command.append(exe)
        if detect_malicious_text(command):
            reasons.append('疑似命令执行')
        if reasons:
            output += f'PID: {pid}\tTTY: {tty}\tCOMMAND: {command}\t[!] {", ".join(reasons)}\n'

    for command in root_command:
        if command.startswith('[') or command.endswith(']'):
            continue
        for check in privilege_escalation:
            if check == command:
                output += f'"command: " {command}\t[!] 疑似可 root 提权\n'
                break

    return output or empty_result()


@mcp.tool()
def check_pid():
    """
    检测疑似隐藏 PID。
    调用：怀疑 rootkit、进程隐藏或 ps 输出不可信时使用。
    输出：返回 /proc 存在但进程快照缺失的 PID。
    """

    if not check_session():
        return SESSION_ERROR

    if not ssh_session.ps:
        load_processes()

    output = ''

    result_pid = exec_command(ssh_session.client, 'ls /proc')
    result_self = exec_command(ssh_session.client, 'ls -al /proc/self')

    if result_pid['status'] and result_self['status']:
        try:
            current_pid = re.findall(r'(\d+)', result_pid['result'])  # 确定所有 pid
            self_pid = re.search(r'-> (\d+)', result_self['result']).group(1)  # 匹配 self 的 pid

            for pid in current_pid:
                if int(pid) not in ssh_session.ps and (int(pid) not in range(int(self_pid) - 2, int(self_pid) + 2)):
                    output += f'PID: {pid}\t path:/proc/{pid}\t[!] 隐藏 pid\n'
        except (AttributeError, ValueError):
            pass

    return output or empty_result()


@mcp.tool()
def check_exe():
    """
    检测进程名与真实可执行文件不一致。
    调用：怀疑进程伪装、命令替换或二进制劫持时使用。
    输出：返回 PID、真实 exe 和 ps 中显示的 exe。
    """

    if not check_session():
        return SESSION_ERROR

    output = ''
    if ssh_session.ps.keys():

        result = exec_command(ssh_session.client, f'ls -al /proc/*/exe 2>/dev/null')
        if result['status'] and result['result']:
            try:
                group = re.findall(r'.*/proc/(\d+)/exe -> (.*)', result['result'])
                for item in group:
                    pid = item[0]
                    true_exe = Path(item[1]).name  # exe 真实指向命令
                    if int(pid) in ssh_session.ps:
                        exe = ssh_session.ps[int(pid)]['exe']

                        if true_exe != exe:
                            output += f'PID: {pid}\ttrue_exe: {true_exe}\texe: {exe}\t[!] 进程名与真实可执行文件不一致，需结合上下文复核\n'
            except ValueError:
                pass

    return output or empty_result()


@mcp.tool()
def check_mount():
    """
    检查 /proc 挂载异常。
    调用：怀疑通过 mount 隐藏进程或伪装文件系统时使用。
    输出：返回可疑 /proc/<pid> 挂载项。
    """

    if not check_session():
        return SESSION_ERROR

    output = ''

    result = exec_command(ssh_session.client, f'cat /proc/mounts')
    if not result['status']:
        return command_failure(result, '挂载信息读取失败')
    if not result['result']:
        return empty_result()

    try:
        for pid in re.findall(r'/proc/(\d+)', result['result']):
            output += f'path: /proc/{pid}\t[!] mount 挂载后门\n'
    except re.error:
        pass

    return output or empty_result()


@mcp.tool()
def get_localhost():
    """
    采集本机 IPv4 地址。
    调用：网络连接分析前使用，用于区分本地地址和远程外联。
    输出：返回本地 IP 列表。
    """

    if not check_session():
        return SESSION_ERROR

    ssh_session.ip_list = ["127.0.0.1", "localhost", "0.0.0.0"]
    result = first_success(ssh_session.client, ['ip -4 addr show', 'hostname -I'])

    if not result['status']:
        return command_failure(result, '本地 IP 获取失败')
    if not result['result']:
        return f"本地IP列表: {', '.join(ssh_session.ip_list)}"

    for line in result['result'].splitlines():
        line = line.strip()
        if "inet" in line:
            try:
                ip = re.split(r'\s+', line)[1].split('/')[0]
                if ip not in ssh_session.ip_list:
                    ssh_session.ip_list.append(ip)
            except (IndexError, ValueError):
                pass
        else:
            for ip in line.split():
                if re.fullmatch(r'\d{1,3}(?:\.\d{1,3}){3}', ip) and ip not in ssh_session.ip_list:
                    ssh_session.ip_list.append(ip)

    return f"本地IP列表: {', '.join(ssh_session.ip_list)}"


def parse_socket_line(line):
    line = line.strip()
    if not line or line.lower().startswith(('netid', 'proto', 'active')):
        return None
    parts = re.split(r'\s+', line)
    if len(parts) < 5 or parts[0] not in ('tcp', 'udp', 'tcp6', 'udp6'):
        return None
    if len(parts) >= 6 and parts[1].upper() in {'LISTEN', 'UNCONN', 'ESTAB', 'ESTABLISHED', 'TIME-WAIT'}:
        state = parts[1]
        local = parts[4]
        remote = parts[5]
    else:
        state = next((part for part in parts if part.upper() in {'LISTEN', 'UNCONN', 'ESTABLISHED'}), '')
        local = parts[3]
        remote = parts[4]
    process = parts[-1] if '/' in parts[-1] or 'users:' in parts[-1] else ''
    return {
        'proto': parts[0],
        'local': local,
        'remote': remote,
        'state': state,
        'process': process,
    }


@mcp.tool()
def check_network():
    """
    分析 ss -anutp 网络连接。
    调用：排查异常外联、监听端口或后门通信时使用；可结合已采集的本机地址判断远程连接。
    输出：返回本地地址、远程地址、进程和连接类型。
    """
    if not check_session():
        return SESSION_ERROR

    output = []

    result = first_success(ssh_session.client, ['ss -anutp', 'netstat -anutp 2>/dev/null'])
    if not result.get('status'):
        return command_failure(result, '网络连接获取失败')
    if not result.get('result'):
        return empty_result()

    for line in result['result'].splitlines()[1:]:
        try:
            socket = parse_socket_line(line)
            if not socket:
                continue
            local = socket['local']
            remote = socket['remote']
            process = socket['process'] or '-'
            local_addr, local_port = local.rsplit(':', 1)
            remote_addr, remote_port = remote.rsplit(':', 1)

            if remote_addr not in ssh_session.ip_list and remote_port != "*":
                output.append(f'local :{local}\tremote :{remote}\tpid :{process}\t[!] 发现远程连接')
            elif local_port and local_port != "*":
                output.append(f'local :{local}\tremote :{remote}\tpid :{process}\t[!] 发现开启端口')
        except (IndexError, ValueError):
            pass

    return '\n'.join(output) or empty_result()


@mcp.tool()
def check_listening_ports():
    """
    汇总监听端口。
    调用：需要快速确认目标主机暴露服务、监听地址和关联进程时使用。
    输出：返回协议、本地监听地址、状态和进程线索。
    """
    if not check_session():
        return SESSION_ERROR

    result = first_success(ssh_session.client, ['ss -lntup', 'netstat -lntup 2>/dev/null'])
    if not result.get('status'):
        return command_failure(result, '监听端口获取失败')
    if not result.get('result'):
        return empty_result('未发现监听端口')

    output = []
    for line in result['result'].splitlines():
        socket = parse_socket_line(line)
        if not socket:
            continue
        output.append(
            f'proto: {socket["proto"]}\tlocal: {socket["local"]}\tstate: {socket["state"] or "-"}'
            f'\tprocess: {socket["process"] or "-"}\t[i] 监听端口'
        )

    return '\n'.join(output) or empty_result('未发现监听端口')


@mcp.tool()
def check_eth():
    """
    枚举网卡设备。
    调用：排查异常网卡、虚拟网卡或多网段资产时使用。
    输出：返回网卡名称列表。
    """

    if not check_session():
        return SESSION_ERROR

    result = exec_command(ssh_session.client, 'ls /sys/class/net')

    if result.get('status'):
        output = [f'网卡: {line.strip()}\t[!] "网卡检测"' for line in result['result'].splitlines()]
        return '\n'.join(output)
    return ''


@mcp.tool()
def check_hosts():
    """
    检查 /etc/hosts 非本机解析项。
    调用：排查 hosts 劫持、恶意域名解析或异常内网映射时使用。
    输出：返回可疑 IP 与域名。
    """

    if not check_session():
        return SESSION_ERROR

    output = ''
    standard_hosts = {'127.0.0.1', '127.0.1.1', '::1', 'ff02::1', 'ff02::2'}

    result = exec_command(ssh_session.client, f'cat /etc/hosts')
    if not result['status']:
        return command_failure(result, 'hosts 读取失败')
    if not result['result']:
        return empty_result()

    for line in result['result'].splitlines():
        line = line.strip()
        try:
            parts = re.split(r'\s+', line.strip())
            if parts and not parts[0].startswith('#'):
                ip, *domains = parts
                if ip in standard_hosts or not domains:
                    continue
                if ip and ip not in ssh_session.ip_list:
                    ssh_session.ip_list.append(ip)
                    output += f'ip: {ip}\tdomain: {"、".join(domains)}\t[!] 非本机 hosts 解析\n'
        except (IndexError, ValueError):
            pass

    return output or empty_result()


@mcp.tool()
def check_bin():
    """
    采集 /usr/bin 关键文件线索。
    调用：怀疑系统命令被替换、权限异常或新增可疑命令时使用。
    输出：返回近期修改、非 root 属主、异常权限和软链信息，供结合上下文复核。
    """

    if not check_session():
        return SESSION_ERROR

    result = exec_command(ssh_session.client, 'ls -alt /usr/bin')
    if not result['status']:
        return command_failure(result, '/usr/bin 文件列表读取失败')
    if not result['result']:
        return empty_result()

    files = list(get_file_list(result['result']).values())
    recent_files = []
    suspicious_files = []
    symlink_files = []

    for file in files:
        filename = file['filename']
        owner = file['owner']
        group = file['group']
        perm = file['perm']
        time = file['time']
        link = ''

        if ' -> ' in filename:
            filename, link = filename.split(' -> ', 1)

        if len(recent_files) < 10:
            recent_files.append(f'file: {filename}\ttime: {time}\t[i] /usr/bin 近期修改文件')

        reasons = []
        if owner != 'root' or group != 'root':
            reasons.append('非 root 属主/属组')
        if len(perm) > 8 and perm[8] == 'w':
            reasons.append('other 可写权限')
        if len(perm) > 3 and perm[3] in {'s', 'S'}:
            reasons.append('setuid 权限')
        if len(perm) > 6 and perm[6] in {'s', 'S'}:
            reasons.append('setgid 权限')

        if reasons:
            suspicious_files.append(
                f'file: {filename}\tperm: {perm}\towner: {owner}\tgroup: {group}\t[!] {", ".join(reasons)}，需结合上下文复核'
            )
        if link:
            symlink_files.append(f'file: {filename}\tlink: {link}\t[i] /usr/bin 软链条目')

    output = []
    output.extend(recent_files)
    output.extend(suspicious_files[:50])
    if len(suspicious_files) > 50:
        output.append(f'[i] 还有 {len(suspicious_files) - 50} 条权限/属主线索未展示')
    output.extend(symlink_files[:30])
    if len(symlink_files) > 30:
        output.append(f'[i] 还有 {len(symlink_files) - 30} 条软链线索未展示')

    return '\n'.join(output) or empty_result()


@mcp.tool()
def check_tmp():
    """
    列举 /tmp 下文件。
    调用：排查临时目录落地文件、脚本或恶意样本时使用。
    输出：返回 /tmp 可疑文件路径。
    """

    if not check_session():
        return SESSION_ERROR

    result = first_success(ssh_session.client, [
        "find /tmp -type f -printf '%p\t%u:%g\t%m\t%s bytes\t%TY-%Tm-%Td %TH:%TM\n' 2>/dev/null",
        'find /tmp -type f 2>/dev/null',
    ])
    if not result['status']:
        return command_failure(result, '/tmp 文件扫描失败')
    if not result['result']:
        return empty_result()

    output = ''.join(f'file path: {item.strip()}\t[!] /tmp 目录下可疑文件\n' for item in result['result'].splitlines())
    return output or empty_result()


@mcp.tool()
def check_recent_files(path='/tmp', days=7, max_results=200):
    """
    检查指定目录近期变更文件。
    调用：排查 /tmp、webroot、用户目录中近期落地的脚本、样本、隐藏 shell、免杀马或异常文件时使用。
    输出：返回文件路径、属主、权限、大小和修改时间。
    """
    if not check_session():
        return SESSION_ERROR

    if not isinstance(path, str) or not path.strip() or not path.strip().startswith('/'):
        return "path 必须是目标主机上的绝对路径"
    try:
        days = max(1, min(int(days), 365))
    except (TypeError, ValueError):
        days = 7
    try:
        max_results = max(1, min(int(max_results), 1000))
    except (TypeError, ValueError):
        max_results = 200

    quoted_path = quote_remote_path(path.strip())
    command = (
        f"find {quoted_path} -type f -mtime -{days} "
        f"-printf '%TY-%Tm-%Td %TH:%TM\t%u:%g\t%m\t%s bytes\t%p\\n' 2>/dev/null "
        f"| head -n {max_results}"
    )
    result = exec_command(ssh_session.client, command, timeout=30, max_bytes=300000)
    if not result['status']:
        return command_failure(result, '近期文件扫描失败')
    if not result['result']:
        return empty_result(f'最近 {days} 天未发现变更文件')
    return '\n'.join(f'{line}\t[i] 近期变更文件' for line in result['result'].splitlines())


@mcp.tool()
def discover_webroots(max_results=50):
    """
    自动发现常见 Web 根目录。
    调用：用户要求 WebShell 查杀、Web 入侵排查、隐藏 shell 路径、免杀马路径或不知道站点目录时使用，后续可接 check_webshell 或 check_recent_files。
    输出：返回 webroot 路径、来源、存在状态和浅层文件数量。
    """
    if not check_session():
        return SESSION_ERROR
    try:
        max_results = max(1, min(int(max_results), 200))
    except (TypeError, ValueError):
        max_results = 50

    command = r'''for p in /var/www/html /usr/share/nginx/html /www/wwwroot /home/wwwroot /data/wwwroot /srv/www /opt/lampp/htdocs; do [ -d "$p" ] && printf 'common\t%s\n' "$p"; done
for f in /etc/nginx/nginx.conf /etc/nginx/conf.d/*.conf /etc/apache2/sites-enabled/* /etc/apache2/sites-available/* /etc/httpd/conf/*.conf /etc/httpd/conf.d/*.conf /www/server/panel/vhost/nginx/*.conf /www/server/panel/vhost/apache/*.conf; do
  [ -f "$f" ] || continue
  awk '
    $1 == "root" {gsub(";", "", $2); gsub("\"", "", $2); if ($2 ~ /^\//) printf "config:%s\t%s\n", FILENAME, $2}
    $1 == "DocumentRoot" {gsub("\"", "", $2); if ($2 ~ /^\//) printf "config:%s\t%s\n", FILENAME, $2}
  ' "$f" 2>/dev/null
done'''
    result = exec_command(ssh_session.client, command, timeout=30, max_bytes=200000)
    if not result['status'] and not result['result']:
        return command_failure(result, 'Web 目录发现失败')

    roots = []
    seen = set()
    for line in result.get('result', '').splitlines():
        parts = line.split('\t', 1)
        if len(parts) != 2:
            continue
        source, path = parts[0].strip(), parts[1].strip().rstrip(';')
        if not path.startswith('/') or path in seen:
            continue
        seen.add(path)
        roots.append((source, path))
        if len(roots) >= max_results:
            break

    if not roots:
        return empty_result('未发现常见 Web 根目录')

    output = []
    for source, path in roots:
        quoted = quote_remote_path(path)
        info = exec_command(
            ssh_session.client,
            f"if [ -d {quoted} ]; then count=$(find {quoted} -maxdepth 2 -type f 2>/dev/null | head -n 1001 | wc -l); stat -c '%U:%G\t%A\t%s bytes\t%y' {quoted} 2>/dev/null | sed \"s/^/$count files(max depth 2)\t/\"; else echo 'missing'; fi",
            timeout=15,
            max_bytes=4000,
        )
        detail = info.get('result', '').strip() if info.get('status') else '状态获取失败'
        output.append(f'source: {source}\tpath: {path}\t{detail}\t[i] Web 根目录候选')
    return '\n'.join(output)


@mcp.tool()
def check_webshell(path='/var/www/html', max_files=20000):
    """
    扫描 webroot 中的疑似 WebShell。
    调用：用户要求 WebShell 查杀、Web 入侵排查、查找黑客 shell、隐藏 shell 或免杀马时使用；传入站点目录，工具会打包下载并调用本地扫描器分析。
    输出：返回疑似文件路径、MD5 或扫描器错误。
    """

    if not check_session():
        return SESSION_ERROR

    output = ''
    try:
        max_files = max(1, min(int(max_files), 100000))
    except (TypeError, ValueError):
        max_files = 20000
    path = path.strip() or '/var/www/html'
    quoted_path = quote_remote_path(path)

    count_result = first_success(
        ssh_session.client,
        [
            f"find {quoted_path} -type f -printf '.\\n' 2>/dev/null | head -n {max_files + 1} | wc -l",
            f"find {quoted_path} -type f 2>/dev/null | head -n {max_files + 1} | wc -l",
        ],
        timeout=30,
        max_bytes=1000,
    )
    if not count_result['status']:
        return command_failure(count_result, 'webroot 文件计数失败')
    try:
        file_count = int(count_result['result'].splitlines()[0].strip())
    except (IndexError, ValueError):
        return command_failure(count_result, 'webroot 文件计数失败')
    if file_count == 0:
        return empty_result('webroot 目录未发现文件')
    if file_count > max_files:
        return f'webroot 文件数量超过限制 {max_files}，请缩小扫描目录或提高 max_files'

    if file_count:
        size_result = exec_command(ssh_session.client, f"du -sb {quoted_path} 2>/dev/null | awk '{{print $1}}'", timeout=20, max_bytes=1000)
        if size_result['status'] and size_result['result']:
            try:
                if int(size_result['result'].splitlines()[0]) > 500 * 1024 * 1024:
                    return 'webroot 总大小超过 500MB，请缩小扫描目录'
            except (IndexError, ValueError):
                pass
        remote_archive = f'/tmp/autoir_webroot_{get_time_path()}.tar.gz'
        quoted_remote_archive = quote_remote_path(remote_archive)
        tar_result = exec_command(ssh_session.client, f'cd {quoted_path} && tar -zcf {quoted_remote_archive} .')
        if not tar_result['status'] and tar_result.get('stderr'):
            return command_failure(tar_result, 'webroot 打包失败')
        local_path = Path(base_dir) / 'downloads' / get_time_path()
        local_path.mkdir(parents=True, exist_ok=True)
        archive_path = local_path / 'webroot.tar.gz'
        try:
            sftp_download(ssh_session.client, remote_archive, str(archive_path))
        finally:
            exec_command(ssh_session.client, f'rm -f {quoted_remote_archive}', timeout=5, max_bytes=1000)
        if not archive_path.exists():
            return 'webroot 下载失败：未生成本地压缩包'

        with tarfile.open(archive_path, 'r:gz') as tar:
            member_count = 0
            for member in tar:
                member_count += 1
                if member_count > max_files:
                    return output + f'压缩包成员数量超过限制 {max_files}，已停止解压'
                if not is_safe_tar_member(local_path, member):
                    server_path = path.rstrip('/') + '/' + member.name.replace('\\', '/')
                    output += f'file path: {server_path}\t[!] 路径/类型/大小异常已拦截\n'
                    continue
                tar.extract(member, local_path)

        scanner_path = Path(base_dir) / 'extensions' / 'HeMa' / 'hm.exe'
        try:
            result = subprocess.run([str(scanner_path), 'scan', str(local_path)], capture_output=True, text=True,
                                    encoding='utf-8', errors='ignore', timeout=300)
        except subprocess.TimeoutExpired:
            return output + '扫描器执行超时'
        except OSError as error:
            return output + f'扫描器执行失败: {error}'

        count = 0
        for line in result.stdout.splitlines():
            if "总计" in line:
                count = int(line.replace(' ', '').split('|')[-2])
        if count:
            result_path = Path(base_dir) / 'extensions' / 'HeMa' / 'result.csv'
            with open(result_path, 'r', encoding='utf-8', errors='ignore') as csvfile:
                csv_reader = csv.reader(csvfile, delimiter=',')
                next(csv_reader, None)  # 跳过表头
                for row in csv_reader:
                    suggestion, file_path = row[1], row[2]
                    file_path = Path(file_path)
                    server_path = str(file_path).replace(str(local_path), path.strip()).replace('\\', '/')
                    output += f'file path: {server_path}\tmd5: {file_md5(file_path)}\t[!] 疑似 webshell 文件\n'
    return output or empty_result('未发现疑似 webshell')


def get_files(directory):
    file_list = []
    result = exec_command(ssh_session.client, f'ls -al {quote_remote_path(directory)}')
    if result and result.get('status') and result.get('result'):
        for file in get_file_list(result['result']).values():
            filename = file['filename']
            if '->' in filename:
                filename = filename.split(' -> ')[0]
            file_list.append(filename)
    return file_list


def check_malicious_content(file_path):
    output = ''
    result = exec_command(ssh_session.client, f'cat {quote_remote_path(file_path)}')
    if result['status'] and result['result']:
        for line in result['result'].splitlines():
            if not line.startswith('#'):
                malicious = detect_malicious_text(line.strip())
                if malicious:
                    output += f'file: {file_path}\tcontent: {malicious}\t[!] 恶意命令执行\n'
    return output


@mcp.tool()
def check_ld_so_preload():
    """
    检查 /etc/ld.so.preload 后门。
    调用：怀疑动态库预加载、命令劫持或持久化时使用。
    输出：返回非注释预加载库路径。
    """

    if not check_session():
        return SESSION_ERROR

    output = ''

    result = exec_command(ssh_session.client, f'cat /etc/ld.so.preload')
    if result['status'] and result['result']:
        for line in result['result'].splitlines():
            line = line.strip()
            if line and not line.startswith('#'):
                output += f'{line}\t[!] ld.so.preload 后门！\n'
    elif result.get('exit_status') not in (0, 1):
        return command_failure(result, 'ld.so.preload 读取失败')

    return output or empty_result()


@mcp.tool()
def check_cron():
    """
    扫描 cron 计划任务中的可疑命令。
    调用：排查定时持久化、反弹任务或恶意下载执行时使用。
    输出：返回可疑任务文件和命中内容。
    """

    if not check_session():
        return SESSION_ERROR

    output = ''

    cron_dirs = ['/var/spool/cron', '/etc/cron.d', '/etc/cron.daily', '/etc/cron.weekly', '/etc/cron.hourly', '/etc/cron.monthly']

    for cron_dir in cron_dirs:
        for file in get_files(cron_dir):
            output += check_malicious_content(f'{cron_dir}/{file}')

    return output or empty_result()


@mcp.tool()
def check_ssh():
    """
    检查 /usr/sbin/sshd 是否被软链接劫持。
    调用：怀疑 SSH 后门、sshd 被替换或异常端口服务时使用。
    输出：返回 sshd 链接信息和风险提示。
    """

    if not check_session():
        return SESSION_ERROR

    output = ''

    result = exec_command(ssh_session.client, 'ls -al /usr/sbin/sshd')
    if result['status'] and result['result'] and '>' in result['result']:
        output += f'content: {result["result"]}\t[!] /usr/sbin/sshd 已被劫持\n'

    return output or empty_result()


@mcp.tool()
def check_ssh_wrapper():
    """
    检查 sshd 二进制中的可疑字符串。
    调用：怀疑 SSH wrapper 后门或 sshd 被脚本/恶意逻辑包装时使用。
    输出：返回命中的可疑内容。
    """

    if not check_session():
        return SESSION_ERROR

    output = ''

    result = exec_command(ssh_session.client, 'strings /usr/sbin/sshd')
    if result['status'] and result['result']:
        for line in result['result'].splitlines():
            malicious = detect_malicious_text(line.strip())
            if malicious:
                if '\033' in malicious:
                    output += f'file: {"/usr/sbin/sshd"}\tcontent: {malicious}\t[!] 恶意 shell 命令\n'
                else:
                    output += f'file: {"/usr/sbin/sshd"}\tcontent: {malicious}\t[!] ssh wrapper 劫持\n'

    return output or empty_result()


@mcp.tool()
def check_inetd():
    """
    检查 /etc/inetd.conf 中的可疑后门配置。
    调用：排查 inetd 持久化或网络服务触发命令执行时使用。
    输出：返回可疑配置内容。
    """

    if not check_session():
        return SESSION_ERROR

    output = check_malicious_content('/etc/inetd.conf')
    return output or empty_result()


@mcp.tool()
def check_xinetd():
    """
    检查 xinetd 配置中的可疑后门。
    调用：排查 xinetd 服务持久化、反弹 shell 或异常执行路径时使用。
    输出：返回可疑配置文件和命中内容。
    """

    if not check_session():
        return SESSION_ERROR

    output = ''

    for file in get_files('/etc/xinetd.conf/'):
        output += check_malicious_content(f'/etc/xinetd.conf/{file}')

    return output or empty_result()


@mcp.tool()
def check_setuid():
    """
    查找 SUID 文件。
    调用：排查本地提权后门或异常 SUID 程序时使用。
    输出：返回发现的 SUID 文件路径。
    """

    if not check_session():
        return SESSION_ERROR

    output = ''

    command = r"find / -xdev \( -path /proc -o -path /sys -o -path /dev -o -path /run -o -path /mnt -o -path /media \) -prune -o -type f -perm -4000 -print 2>/dev/null"
    result = exec_command(ssh_session.client, command)
    if not result['status']:
        return command_failure(result, 'SUID 文件扫描失败')
    if not result['result']:
        return empty_result()

    for line in result['result'].splitlines():
        output += f'command {line.strip()}\t[!] SUID 后门\n'

    return output or empty_result()


@mcp.tool()
def check_startup():
    """
    扫描系统启动项中的可疑命令。
    调用：排查 init、rc.local、systemd 等启动持久化时使用。
    输出：返回可疑启动项文件和命中内容。
    """

    if not check_session():
        return SESSION_ERROR

    output = ''

    init_paths = ['/etc/init.d', '/etc/rc.d', '/etc/systemd/system', '/usr/local/etc/rc.d']
    init_files = ['/etc/rc.local', '/usr/local/etc/rc.local', '/etc/conf.d/local.start', '/etc/inittab']

    for path in init_paths:
        for file in get_files(path):
            output += check_malicious_content(f'{path}/{file}')

    for file in init_files:
        output += check_malicious_content(f'{file}')

    return output or empty_result()


@mcp.tool()
def check_profile():
    """
    扫描 /etc/profile.d 脚本。
    调用：排查登录即触发的持久化、环境变量注入或命令劫持时使用。
    输出：返回可疑脚本和命中内容。
    """

    if not check_session():
        return SESSION_ERROR

    output = ''

    for file in get_files('/etc/profile.d'):
        output += check_malicious_content(f'/etc/profile.d/{file}')

    return output or empty_result()


@mcp.tool()
def check_rc():
    """
    扫描系统与用户 shell 初始化脚本。
    调用：排查 .bashrc、profile、cshrc 等登录持久化或环境劫持时使用。
    输出：返回可疑脚本和命中内容。
    """

    if not check_session():
        return SESSION_ERROR

    output = ''

    init_paths = ['/root/.bashrc', '/root/.tcshrc', '/root/.bash_profile', '/root/.cshrc', '/etc/bashrc',
                  '/etc/profile', '/etc/csh.login', '/etc/csh.cshrc']
    init_files = ['.bashrc', '.bash_profile', '.tcshrc', '.cshrc']

    for path in init_paths:
        output += check_malicious_content(path)

    for user in load_home_users():
        for file in init_files:
            output += check_malicious_content(f'/home/{user}/{file}')

    return output or empty_result()


pattern = re.compile(
    r'(?P<ip>\S+) \S+ \S+ '
    r'\[(?P<time>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+) (?P<protocol>\S+)" '
    r'(?P<status>\d{3}) (?P<size>\d+) '
    r'"(?P<referer>[^"]*)" '
    r'"(?P<user_agent>[^"]*)"'
)


@mcp.tool()
def check_log(path='/var/log/apache2/access.log', max_lines=5000):
    """
    分析 Apache access.log。
    调用：排查 Web 攻击、恶意 URI、异常状态码和 User-Agent 时使用；path 可指定日志路径。
    输出：返回恶意请求和访问统计。
    """

    if not check_session():
        return SESSION_ERROR

    try:
        max_lines = max(1, min(int(max_lines), 50000))
    except (TypeError, ValueError):
        max_lines = 5000

    output = [f'仅分析最近 {max_lines} 行日志']

    result = exec_command(ssh_session.client, f'tail -n {int(max_lines)} {quote_remote_path(path)} 2>/dev/null')
    if not result['status']:
        return command_failure(result, '日志读取失败')
    if not result['result']:
        return empty_result('日志为空或无可读内容')

    checked_lines = set()
    for line in result['result'].splitlines():
        stripped = line.strip()
        if stripped in checked_lines:
            continue
        checked_lines.add(stripped)
        if detect_malicious_text(stripped, use_safeline=False):
            output.append(f'url: {urllib.parse.unquote(stripped)}\t[!] 恶意请求')

    request_success = []
    request_jump = []
    request_others = []
    user_agents = set()
    for match in pattern.finditer(result['result']):
        request = match.groupdict()
        status = request['status']
        user_agents.add(request['user_agent'])
        if status == '200' and len(request['path']) != 1:
            request_success.append(request)
        elif status == '302':
            request_jump.append(request)
        else:
            request_others.append(request)

    output.append('成功访问 IP 统计')
    output.extend(f'\tip: {ip}\tcount: {count}' for ip, count in collections.Counter(request['ip'] for request in request_success).items())

    output.append('\n跳转访问 IP 统计')
    output.extend(f'\tip: {ip}\tcount: {count}' for ip, count in collections.Counter(request['ip'] for request in request_jump).items())

    output.append('\n失败访问 IP 统计')
    output.extend(f'\tip: {ip}\tcount: {count}' for ip, count in collections.Counter(request['ip'] for request in request_others).items())

    output.append('\n访问 User-Agent 统计')
    output.extend(f'\tUser-Agent: {user_agent}' for user_agent in sorted(user_agents))

    output.append('\n成功访问 请求统计')
    output.extend(f'\tip: {request["ip"]}\turi: {request["path"]}\tuser agent: {request["user_agent"]}' for request in request_success)

    output.append('\n跳转访问 请求统计')
    output.extend(f'\tip: {request["ip"]}\turi: {request["path"]}\tuser agent: {request["user_agent"]}' for request in request_jump)

    return '\n'.join(output)


@mcp.tool()
def check_login_success():
    """
    统计成功登录来源。
    调用：排查异常 SSH 登录、凭证泄露或未知远程登录时使用。
    输出：返回登录 IP 和次数。
    """

    if not check_session():
        return SESSION_ERROR

    result = first_success(ssh_session.client, [
        'last',
        "grep -h 'Accepted' /var/log/auth.log /var/log/secure 2>/dev/null",
    ])

    if not result['status']:
        return command_failure(result, '成功登录日志读取失败')
    if not result['result']:
        return empty_result('未发现成功登录 IP')

    output = format_ip_counts(count_ips_from_lines(result['result'].splitlines()), '成功登入 IP')
    return output or empty_result('未发现成功登录 IP')


@mcp.tool()
def check_login_fail():
    """
    统计失败登录来源。
    调用：排查爆破、撞库或异常登录尝试时使用。
    输出：返回失败登录 IP 和次数。
    """

    if not check_session():
        return SESSION_ERROR

    result = first_success(ssh_session.client, [
        'lastb',
        "grep -h -E 'Failed password|authentication failure|Invalid user' /var/log/auth.log /var/log/secure 2>/dev/null",
    ])

    if not result['status']:
        return command_failure(result, '失败登录日志读取失败')
    if not result['result']:
        return empty_result('未发现失败登录 IP')

    output = format_ip_counts(count_ips_from_lines(result['result'].splitlines()), '爆破登入 IP')
    return output or empty_result('未发现失败登录 IP')


@mcp.tool()
def RookitUpload(install=False):
    """
    上传 rkhunter；默认不安装。
    调用：需要 rootkit 深度检测时使用；只有明确 install=True 时才会在目标机执行安装脚本。
    输出：返回上传状态、人工安装命令或显式安装结果。
    """

    if not check_session():
        return SESSION_ERROR

    local_rkhunter = Path(base_dir) / 'extensions' / 'rkhunter.gz'
    remote_archive = f'/tmp/autoir_rkhunter_{get_time_path()}.tar.gz'
    quoted_archive = quote_remote_path(remote_archive)
    upload_result = sftp_upload(ssh_session.client, str(local_rkhunter), remote_archive)
    if not upload_result.get('status'):
        return f'上传失败: {upload_result.get("error") or "本地 rkhunter.gz 不存在或 SFTP 失败"}'

    install_command = f'cd /tmp && tar -xf {quoted_archive} && cd /tmp/rkhunter-1.4.6 && bash installer.sh --install'
    if not install:
        return {
            "status": True,
            "result": "rkhunter 已上传，默认未安装；如需修改目标系统，请人工确认后执行安装命令或调用 install=True",
            "remote_archive": remote_archive,
            "manual_install_command": install_command,
        }

    result = exec_command(ssh_session.client, install_command, timeout=120, max_bytes=120000)

    if result['status'] and result['result']:
        if "complete" in result['result'].lower():
            return '[success] rkhunter rootkit 检测工具上传安装成功，需要用户手动执行命令 rkhunter --check'

    return command_failure(result, 'rkhunter 安装失败')


@mcp.tool()
def get_system_info():
    """
    采集基础系统信息。
    调用：SSH 连接成功后优先调用，用于报告目标主机上下文。
    输出：返回 hostname、系统版本、内核、时间和运行时长。
    """
    if not check_session():
        return SESSION_ERROR

    command = "printf 'hostname: '; hostname; printf 'kernel: '; uname -a; printf 'date: '; date; printf 'uptime: '; uptime; printf 'os-release:\n'; cat /etc/os-release 2>/dev/null"
    result = exec_command(ssh_session.client, command, timeout=10, max_bytes=20000)
    if not result['status']:
        return command_failure(result, '系统信息采集失败')
    return result['result'] or empty_result('系统信息为空')


@mcp.tool()
def check_alias():
    """
    扫描 alias 后门。
    调用：怀疑 shell 命令被 alias 劫持或登录持久化时使用。
    输出：返回可疑 alias 定义和来源文件。
    """
    if not check_session():
        return SESSION_ERROR

    paths = ['/root/.bashrc', '/root/.bash_profile', '/root/.profile', '/etc/bashrc', '/etc/profile']
    for user in load_home_users():
        paths.extend([f'/home/{user}/.bashrc', f'/home/{user}/.bash_profile', f'/home/{user}/.profile'])

    output = []
    dangerous = re.compile(r'\b(curl|wget|nc|ncat|socat|bash\s+-i|/dev/tcp|python\s+-c|perl\s+-e|chmod\s+\+s|ssh|scp)\b', re.I)
    for path in paths:
        result = exec_command(ssh_session.client, f"grep -nE '^alias[[:space:]]+' {quote_remote_path(path)} 2>/dev/null")
        if result['status'] and result['result']:
            for line in result['result'].splitlines():
                label = '可疑 alias 后门' if dangerous.search(line) else 'alias 定义需复核'
                output.append(f'file: {path}\tcontent: {line}\t[!] {label}')
    return '\n'.join(output) or empty_result()


@mcp.tool()
def check_env_preload():
    """
    检查环境变量预加载和命令注入。
    调用：排查 LD_PRELOAD、LD_LIBRARY_PATH、PROMPT_COMMAND 等登录持久化或劫持。
    输出：返回变量来源、变量名和值。
    """
    if not check_session():
        return SESSION_ERROR

    names = 'LD_PRELOAD|LD_AOUT_PRELOAD|LD_ELF_PRELOAD|LD_LIBRARY_PATH|PROMPT_COMMAND|BASH_ENV|ENV'
    paths = ['/root/.bashrc', '/root/.bash_profile', '/root/.profile', '/etc/bashrc', '/etc/profile', '/etc/environment']
    for file in get_files('/etc/profile.d'):
        paths.append(f'/etc/profile.d/{file}')
    for user in load_home_users():
        paths.extend([f'/home/{user}/.bashrc', f'/home/{user}/.bash_profile', f'/home/{user}/.profile'])

    output = []
    for path in paths:
        result = exec_command(ssh_session.client, f"grep -nE '({names})' {quote_remote_path(path)} 2>/dev/null")
        if result['status'] and result['result']:
            for line in result['result'].splitlines():
                if line.strip().startswith('#'):
                    continue
                output.append(f'file: {path}\tcontent: {line}\t[!] 环境变量持久化/劫持')
    return '\n'.join(output) or empty_result()


@mcp.tool()
def check_fstab():
    """
    检查 /etc/fstab 异常挂载项。
    调用：排查启动挂载持久化、远程挂载或伪装文件系统时使用。
    输出：返回可疑挂载项。
    """
    if not check_session():
        return SESSION_ERROR

    result = exec_command(ssh_session.client, 'cat /etc/fstab 2>/dev/null')
    if not result['status']:
        return command_failure(result, 'fstab 读取失败')
    output = []
    suspicious = re.compile(r'(curl|wget|/dev/tcp|sshfs|nfs|cifs|tmpfs|fuse|overlay|auto|x-systemd)', re.I)
    for line in result['result'].splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith('#'):
            continue
        if suspicious.search(stripped):
            output.append(f'file: /etc/fstab\tcontent: {stripped}\t[!] 异常挂载项需复核')
    return '\n'.join(output) or empty_result()


@mcp.tool()
def check_systemd_timers():
    """
    检查 systemd timer 持久化。
    调用：排查定时任务持久化或异常服务触发器时使用。
    输出：返回 timer 列表和可疑文件内容。
    """
    if not check_session():
        return SESSION_ERROR

    result = first_success(ssh_session.client, [
        "systemctl list-timers --all --no-pager 2>/dev/null",
        "find /etc/systemd/system /usr/lib/systemd/system /lib/systemd/system -name '*.timer' -type f 2>/dev/null",
    ], timeout=20, max_bytes=80000)
    if not result['status']:
        return command_failure(result, 'systemd timer 检查失败')
    return result['result'] or empty_result()


@mcp.tool()
def check_service_execstart():
    """
    检查 systemd 服务 ExecStart 高危命令。
    调用：排查 systemd 服务持久化、反弹 shell 或下载执行时使用。
    输出：返回可疑服务文件和 ExecStart 内容。
    """
    if not check_session():
        return SESSION_ERROR

    command = r"grep -RInE 'Exec(Start|StartPre|StartPost)=.*(bash -i|/dev/tcp|curl|wget|nc |ncat|socat|python -c|perl -e|chmod \+s)' /etc/systemd/system /usr/lib/systemd/system /lib/systemd/system 2>/dev/null"
    result = exec_command(ssh_session.client, command, timeout=30, max_bytes=120000)
    if result['status'] and result['result']:
        return '\n'.join(f'{line}\t[!] systemd 高危启动命令' for line in result['result'].splitlines())
    if result.get('exit_status') in (0, 1):
        return empty_result()
    return command_failure(result, 'systemd 服务检查失败')


@mcp.tool()
def check_deleted_exe():
    """
    检查已删除但仍在运行的可执行文件。
    调用：排查无文件落地进程、进程隐藏或恶意进程自删除时使用。
    输出：返回 PID 和 deleted exe 指向。
    """
    if not check_session():
        return SESSION_ERROR

    result = exec_command(ssh_session.client, "ls -al /proc/*/exe 2>/dev/null | grep 'deleted'", timeout=20)
    if result['status'] and result['result']:
        return '\n'.join(f'{line}\t[!] deleted exe 进程' for line in result['result'].splitlines())
    if result.get('exit_status') in (0, 1):
        return empty_result()
    return command_failure(result, 'deleted exe 检查失败')


@mcp.tool()
def check_dns_config():
    """
    检查 DNS 配置。
    调用：排查 DNS 劫持、异常解析或未知 nameserver 时使用。
    输出：返回 resolv.conf 内容和可疑 nameserver。
    """
    if not check_session():
        return SESSION_ERROR

    result = exec_command(ssh_session.client, 'cat /etc/resolv.conf 2>/dev/null')
    if not result['status']:
        return command_failure(result, 'DNS 配置读取失败')
    output = []
    for line in result['result'].splitlines():
        stripped = line.strip()
        if stripped.startswith('nameserver'):
            ip = stripped.split()[-1]
            risk = '公共/外部 DNS 需复核' if not (ip.startswith('127.') or ip.startswith('10.') or ip.startswith('172.16.') or ip.startswith('172.17.') or ip.startswith('172.18.') or ip.startswith('172.19.') or ip.startswith('192.168.')) else 'DNS 配置'
            output.append(f'file: /etc/resolv.conf\tcontent: {stripped}\t[!] {risk}')
    return '\n'.join(output) or empty_result()


@mcp.tool()
def check_auth_log(max_lines=5000):
    """
    分析 SSH/auth 日志。
    调用：排查暴力破解、成功登录、无效用户和认证异常时使用。
    输出：返回关键认证事件统计。
    """
    if not check_session():
        return SESSION_ERROR

    try:
        max_lines = max(1, min(int(max_lines), 50000))
    except (TypeError, ValueError):
        max_lines = 5000
    command = f"tail -n {max_lines} /var/log/auth.log /var/log/secure 2>/dev/null"
    result = exec_command(ssh_session.client, command, timeout=20, max_bytes=200000)
    if not result['status']:
        return command_failure(result, 'auth 日志读取失败')
    lines = result['result'].splitlines()
    failed = [line for line in lines if re.search(r'Failed password|authentication failure|Invalid user', line, re.I)]
    accepted = [line for line in lines if re.search(r'Accepted (password|publickey)', line, re.I)]
    output = []
    failed_counts = count_ips_from_lines(failed)
    accepted_counts = count_ips_from_lines(accepted)
    if failed_counts:
        output.append('失败登录统计\n' + format_ip_counts(failed_counts, '失败登录来源'))
    if accepted_counts:
        output.append('成功登录统计\n' + format_ip_counts(accepted_counts, '成功登录来源'))
    for line in failed[:20] + accepted[:20]:
        output.append(f'event: {line}')
    return '\n'.join(output) or empty_result('未发现认证异常事件')


@mcp.tool()
def check_web_logs_auto(max_lines=3000):
    """
    自动发现并分析常见 Web 访问日志。
    调用：不知道 Apache/Nginx/httpd 日志路径时使用。
    输出：返回已发现日志路径和分析摘要。
    """
    if not check_session():
        return SESSION_ERROR

    result = exec_command(ssh_session.client, "find /var/log -maxdepth 3 -type f \\( -name 'access.log' -o -name '*access*.log' -o -name 'access_log' \\) 2>/dev/null", timeout=20)
    if not result['status']:
        return command_failure(result, 'Web 日志发现失败')
    paths = [line.strip() for line in result['result'].splitlines() if line.strip()][:5]
    if not paths:
        return empty_result('未发现常见 Web access 日志')
    output = [f'发现日志: {path}' for path in paths]
    for path in paths:
        output.append(f'--- {path} ---')
        output.append(check_log(path=path, max_lines=max_lines))
    return '\n'.join(output)


def safe_local_subdir(relative_dir):
    base = Path(base_dir) / 'downloads'
    target = (Path(base_dir) / relative_dir).resolve()
    if not is_safe_path(base, target):
        target = base / 'evidence'
    target.mkdir(parents=True, exist_ok=True)
    return target


def is_allowed_upload_source(path):
    allowed_roots = (Path(base_dir) / 'extensions', Path(base_dir) / 'downloads')
    return any(is_safe_path(root, path) for root in allowed_roots)


@mcp.tool()
def stat_file(path):
    """
    获取目标主机文件元数据。
    调用：取证前确认文件权限、大小、时间和类型时使用。
    输出：返回 stat 信息，失败时 fallback 到 ls -al。
    """
    if not check_session():
        return SESSION_ERROR
    if not isinstance(path, str) or not path.strip():
        return "path 不能为空"
    quoted = quote_remote_path(path.strip())
    result = first_success(ssh_session.client, [
        f"stat {quoted} 2>/dev/null",
        f"ls -al {quoted} 2>/dev/null",
    ])
    if not result['status']:
        return command_failure(result, '文件元数据读取失败')
    return result['result'] or empty_result('文件不存在或无可读元数据')


@mcp.tool()
def hash_file(path, algorithm='sha256'):
    """
    计算目标主机文件哈希。
    调用：文件取证、样本确认或完整性校验时使用。
    输出：返回 md5/sha1/sha256 哈希。
    """
    if not check_session():
        return SESSION_ERROR
    algorithms = {'sha256': 'sha256sum', 'sha1': 'sha1sum', 'md5': 'md5sum'}
    algorithm = str(algorithm).lower().strip()
    if algorithm not in algorithms:
        return "algorithm 仅支持 sha256、sha1、md5"
    quoted = quote_remote_path(path.strip())
    result = exec_command(ssh_session.client, f"{algorithms[algorithm]} {quoted} 2>/dev/null")
    if not result['status']:
        return command_failure(result, '文件哈希计算失败')
    return result['result'] or empty_result('文件哈希为空')


@mcp.tool()
def profile_suspicious_file(path, max_preview_lines=40, max_strings=80):
    """
    快速画像目标主机上的可疑文件。
    调用：需要对单个文件做 stat、hash、类型、预览和字符串片段分析时使用。
    输出：返回文件元数据、sha256、file 类型、头部预览、strings 片段和风险提示。
    """
    if not check_session():
        return {"status": False, "result": SESSION_ERROR}
    if not isinstance(path, str) or not path.strip():
        return {"status": False, "result": "path 不能为空"}
    try:
        max_preview_lines = max(1, min(int(max_preview_lines), 200))
    except (TypeError, ValueError):
        max_preview_lines = 40
    try:
        max_strings = max(1, min(int(max_strings), 300))
    except (TypeError, ValueError):
        max_strings = 80

    path = path.strip()
    quoted = quote_remote_path(path)
    stat_result = exec_command(
        ssh_session.client,
        f"stat -c '%F\t%A\t%a\t%U:%G\t%s\t%y\t%n' {quoted} 2>/dev/null",
        timeout=10,
        max_bytes=8000,
    )
    if not stat_result['status']:
        return {"status": False, "path": path, "result": command_failure(stat_result, '文件元数据读取失败')}

    fields = stat_result.get('result', '').split('\t')
    file_type = fields[0] if len(fields) > 0 else ''
    permissions = fields[1] if len(fields) > 1 else ''
    mode = fields[2] if len(fields) > 2 else ''
    owner = fields[3] if len(fields) > 3 else ''
    size = fields[4] if len(fields) > 4 else ''
    mtime = fields[5] if len(fields) > 5 else ''

    sha256_result = exec_command(ssh_session.client, f"sha256sum {quoted} 2>/dev/null", timeout=20, max_bytes=4000)
    type_result = exec_command(ssh_session.client, f"file -b {quoted} 2>/dev/null", timeout=10, max_bytes=4000)
    preview_result = exec_command(ssh_session.client, f"head -n {max_preview_lines} {quoted} 2>/dev/null", timeout=10, max_bytes=12000)
    strings_result = exec_command(ssh_session.client, f"strings -a {quoted} 2>/dev/null | head -n {max_strings}", timeout=20, max_bytes=20000)

    lower_path = path.lower()
    reasons = []
    if 'directory' in file_type.lower():
        reasons.append('目标是目录')
    if permissions and any(flag in permissions for flag in ('x', 's', 'S')):
        reasons.append('包含执行权限或 SUID/SGID 标记')
    if permissions and permissions.endswith('w'):
        reasons.append('other 可写')
    if lower_path.endswith(('.php', '.jsp', '.jspx', '.asp', '.aspx', '.war', '.py', '.pl', '.sh')):
        reasons.append('脚本或 Web 可执行扩展')
    if any(token in lower_path for token in ('/tmp/', '/dev/shm/', '/var/tmp/', '/uploads/', '/upload/')):
        reasons.append('位于高频落地目录')
    if size == '0':
        reasons.append('空文件')

    sha256 = sha256_result.get('result', '').split()[0] if sha256_result.get('status') and sha256_result.get('result') else ''
    preview, preview_truncated = truncate_text(preview_result.get('result', ''), max_chars=4000)
    string_snippets, strings_truncated = truncate_text(strings_result.get('result', ''), max_chars=8000)

    return {
        "status": True,
        "path": path,
        "metadata": {
            "type": file_type,
            "permissions": permissions,
            "mode": mode,
            "owner": owner,
            "size": size,
            "mtime": mtime,
        },
        "sha256": sha256,
        "file": type_result.get('result', '') if type_result.get('status') else 'file 命令不可用或失败',
        "preview": preview,
        "strings": string_snippets,
        "risk_notes": reasons or ['未发现明显文件画像风险点，仍需结合上下文复核'],
        "truncated": preview_truncated or strings_truncated,
    }


@mcp.tool()
def download_file(remote_path, local_dir='downloads/evidence', max_bytes=100 * 1024 * 1024):
    """
    下载目标主机文件到本地取证目录。
    调用：需要保存可疑文件、日志或配置用于后续分析时使用；默认拒绝超过 max_bytes 的文件。
    输出：返回本地路径、远程路径和下载状态。
    """
    if not check_session():
        return {"status": False, "result": SESSION_ERROR}
    if not isinstance(remote_path, str) or not remote_path.strip():
        return {"status": False, "result": "remote_path 不能为空"}
    try:
        max_bytes = max(1024, min(int(max_bytes), 2 * 1024 * 1024 * 1024))
    except (TypeError, ValueError):
        max_bytes = 100 * 1024 * 1024
    remote_path = remote_path.strip()
    quoted_remote = quote_remote_path(remote_path)
    stat_result = exec_command(ssh_session.client, f"stat -c '%s\t%n\t%s bytes\t%U:%G\t%A\t%y' {quoted_remote} 2>/dev/null", timeout=10, max_bytes=4000)
    if not stat_result.get('status'):
        return {"status": False, "remote_path": remote_path, "result": command_failure(stat_result, '远程文件元数据读取失败')}
    try:
        remote_size = int(stat_result.get('result', '').split('\t', 1)[0])
    except (IndexError, ValueError):
        return {"status": False, "remote_path": remote_path, "result": "远程文件大小解析失败"}
    if remote_size > max_bytes:
        return {"status": False, "remote_path": remote_path, "size": remote_size, "max_bytes": max_bytes, "result": "远程文件超过下载大小限制"}
    target_dir = safe_local_subdir(local_dir) / get_time_path()
    target_dir.mkdir(parents=True, exist_ok=True)
    local_path = target_dir / Path(remote_path).name
    result = sftp_download(ssh_session.client, remote_path, str(local_path))
    return {
        "status": result.get('status'),
        "remote_path": remote_path,
        "local_path": str(local_path) if result.get('status') else "",
        "stat": stat_result.get('result', ''),
        "error": result.get('error', ''),
    }


@mcp.tool()
def upload_file(local_path, remote_path):
    """
    上传本地文件到目标主机。
    调用：需要传输取证工具或用户明确要求上传文件时使用。
    输出：返回上传状态和错误原因。
    """
    if not check_session():
        return {"status": False, "result": SESSION_ERROR}
    local = Path(local_path).expanduser().resolve()
    if not local.is_file():
        return {"status": False, "result": f"本地文件不存在: {local}"}
    if not is_allowed_upload_source(local):
        return {"status": False, "result": "local_path 仅允许位于项目 extensions/ 或 downloads/ 目录内"}
    if not isinstance(remote_path, str) or not remote_path.strip():
        return {"status": False, "result": "remote_path 不能为空"}
    result = sftp_upload(ssh_session.client, str(local), remote_path.strip())
    return {
        "status": result.get('status'),
        "local_path": str(local),
        "remote_path": remote_path.strip(),
        "error": result.get('error', ''),
    }


@mcp.tool()
def collect_evidence_bundle(include_logs=True, include_files=False):
    """
    采集本地证据快照目录。
    调用：需要保存系统、用户、进程、网络、服务、计划任务和关键日志摘要用于复盘时使用。
    输出：返回本地 bundle 目录和生成的文件列表。
    """
    if not check_session():
        return {"status": False, "result": SESSION_ERROR}
    bundle_dir = Path(base_dir) / 'downloads' / 'evidence_bundle' / get_time_path()
    bundle_dir.mkdir(parents=True, exist_ok=True)
    commands = {
        'system.txt': "hostname; uname -a; date; uptime; cat /etc/os-release 2>/dev/null",
        'users.txt': "cat /etc/passwd; printf '\n--- sudoers ---\n'; cat /etc/sudoers /etc/sudoers.d/* 2>/dev/null",
        'processes.txt': "ps auxww; printf '\n--- deleted exe ---\n'; ls -al /proc/*/exe 2>/dev/null | grep deleted || true",
        'network.txt': "ip addr; ss -anutp 2>/dev/null || netstat -anutp 2>/dev/null; cat /etc/hosts; cat /etc/resolv.conf 2>/dev/null",
        'services.txt': "systemctl list-units --type=service --all --no-pager 2>/dev/null; systemctl list-unit-files --type=service --state=enabled --no-pager 2>/dev/null",
        'scheduled.txt': "crontab -l 2>/dev/null; ls -al /var/spool/cron /var/spool/cron/crontabs 2>/dev/null; atq 2>/dev/null",
        'startup.txt': "find /etc/systemd/system /usr/lib/systemd/system /lib/systemd/system -maxdepth 2 -type f 2>/dev/null | head -500; cat /etc/rc.local /etc/profile 2>/dev/null",
    }
    if include_logs:
        commands['logs.txt'] = "tail -n 1000 /var/log/auth.log /var/log/secure /var/log/syslog /var/log/messages 2>/dev/null"
    if include_files:
        commands['tmp_files.txt'] = "find /tmp -type f -printf '%p\t%u:%g\t%m\t%s bytes\t%TY-%Tm-%Td %TH:%TM\n' 2>/dev/null | head -1000"
    written = []
    for filename, command in commands.items():
        result = exec_command(ssh_session.client, command, timeout=30, max_bytes=500000)
        path = bundle_dir / filename
        path.write_text(result.get('result', '') or result.get('error', ''), encoding='utf-8', errors='ignore')
        written.append(str(path))
    return {"status": True, "bundle_dir": str(bundle_dir), "files": written}


@mcp.tool()
def list_services():
    """
    枚举系统服务。
    调用：排查异常服务、未知服务或服务状态时使用。
    输出：返回 service 列表。
    """
    if not check_session():
        return SESSION_ERROR
    result = first_success(ssh_session.client, [
        'systemctl list-units --type=service --all --no-pager 2>/dev/null',
        'service --status-all 2>/dev/null',
    ], timeout=20, max_bytes=200000)
    if not result['status']:
        return command_failure(result, '服务列表获取失败')
    return result['result'] or empty_result('未发现服务列表')


@mcp.tool()
def check_enabled_services():
    """
    检查开机自启服务。
    调用：排查持久化服务或异常 enabled 服务时使用。
    输出：返回 enabled service 列表。
    """
    if not check_session():
        return SESSION_ERROR
    result = exec_command(ssh_session.client, 'systemctl list-unit-files --type=service --state=enabled --no-pager 2>/dev/null', timeout=20, max_bytes=200000)
    if not result['status']:
        return command_failure(result, '开机自启服务获取失败')
    return result['result'] or empty_result('未发现 enabled 服务')


@mcp.tool()
def check_recent_systemd_changes(days=7):
    """
    检查近期变更的 systemd 单元文件。
    调用：排查近期新增或修改的服务、timer、socket 持久化时使用。
    输出：返回最近修改的 systemd 文件。
    """
    if not check_session():
        return SESSION_ERROR
    try:
        days = max(1, min(int(days), 365))
    except (TypeError, ValueError):
        days = 7
    command = f"find /etc/systemd/system /usr/lib/systemd/system /lib/systemd/system -type f -mtime -{days} -printf '%TY-%Tm-%Td %TH:%TM\t%p\n' 2>/dev/null"
    result = exec_command(ssh_session.client, command, timeout=30, max_bytes=200000)
    if result['status'] and result['result']:
        return result['result']
    if result.get('exit_status') in (0, 1):
        return empty_result(f'最近 {days} 天未发现 systemd 文件变更')
    return command_failure(result, 'systemd 近期变更检查失败')


def container_runtime():
    result = first_success(ssh_session.client, ['command -v docker', 'command -v podman'])
    if result['status'] and result['result']:
        path = result['result'].splitlines()[0].strip()
        return 'podman' if path.endswith('podman') else 'docker'
    return ''


def container_ids(runtime):
    result = exec_command(ssh_session.client, f"{runtime} ps -aq --no-trunc 2>/dev/null", timeout=20)
    if not result['status'] or not result['result']:
        return []
    return [line.strip() for line in result['result'].splitlines() if line.strip()]


@mcp.tool()
def check_docker_containers():
    """
    检查 Docker/Podman 容器列表。
    调用：排查容器中隐藏的恶意服务、进程或异常镜像时使用。
    输出：返回容器列表或不可用原因。
    """
    if not check_session():
        return SESSION_ERROR
    runtime = container_runtime()
    if not runtime:
        return empty_result('未发现 docker/podman 命令')
    result = exec_command(ssh_session.client, f'{runtime} ps -a --no-trunc 2>&1', timeout=30, max_bytes=200000)
    if not result['status']:
        return command_failure(result, f'{runtime} 容器列表获取失败，可能无权限或 daemon 不可访问')
    return result['result'] or empty_result('未发现容器')


@mcp.tool()
def check_container_mounts():
    """
    检查容器挂载。
    调用：排查宿主机敏感目录挂载、逃逸风险或恶意持久化时使用。
    输出：返回容器挂载摘要。
    """
    if not check_session():
        return SESSION_ERROR
    runtime = container_runtime()
    if not runtime:
        return empty_result('未发现 docker/podman 命令')
    ids = container_ids(runtime)
    if not ids:
        return empty_result('未发现容器')
    quoted_ids = ' '.join(shlex.quote(cid) for cid in ids[:50])
    result = exec_command(
        ssh_session.client,
        f"{runtime} inspect --format '{{{{.Name}}}} {{{{json .Mounts}}}}' {quoted_ids} 2>/dev/null",
        timeout=30,
        max_bytes=500000,
    )
    if result['status'] and result['result']:
        return result['result']
    return empty_result('未发现容器挂载信息')


@mcp.tool()
def check_container_processes():
    """
    检查容器内进程。
    调用：排查容器内挖矿、反弹 shell 或异常服务时使用。
    输出：返回容器 top 进程摘要。
    """
    if not check_session():
        return SESSION_ERROR
    runtime = container_runtime()
    if not runtime:
        return empty_result('未发现 docker/podman 命令')
    ids = container_ids(runtime)
    if not ids:
        return empty_result('未发现容器')
    quoted_ids = ' '.join(shlex.quote(cid) for cid in ids[:50])
    command = f'for cid in {quoted_ids}; do echo "## $cid"; {runtime} top "$cid" 2>/dev/null; done'
    result = exec_command(ssh_session.client, command, timeout=60, max_bytes=500000)
    if result['status'] and result['result']:
        return result['result']
    return empty_result('未发现容器进程信息')


@mcp.tool()
def check_user_crontabs():
    """
    检查用户级 crontab。
    调用：排查用户级计划任务、反弹 shell 或定时下载执行时使用。
    输出：返回每个用户的 crontab 和 spool 文件线索。
    """
    if not check_session():
        return SESSION_ERROR
    command = """awk -F: '$7 !~ /(nologin|false)$/ {print $1}' /etc/passwd 2>/dev/null | head -n 200 | while IFS= read -r user; do crontab=$(crontab -l -u "$user" 2>/dev/null); if [ -n "$crontab" ]; then printf '## user: %s\n%s\n\n' "$user" "$crontab"; fi; done"""
    result = exec_command(ssh_session.client, command, timeout=60, max_bytes=300000)
    output = []
    if result['status'] and result['result']:
        output.append(result['result'])
    spool = exec_command(ssh_session.client, 'find /var/spool/cron /var/spool/cron/crontabs -maxdepth 2 -type f -printf "%p\t%u:%g\t%m\t%s bytes\n" 2>/dev/null', timeout=20)
    if spool['status'] and spool['result']:
        output.append('## cron spool files\n' + spool['result'])
    return '\n\n'.join(output) or empty_result('未发现用户级 crontab')


@mcp.tool()
def check_at_jobs():
    """
    检查 at 计划任务。
    调用：排查一次性定时执行任务或隐藏持久化时使用。
    输出：返回 atq 列表和任务内容。
    """
    if not check_session():
        return SESSION_ERROR
    result = exec_command(ssh_session.client, 'atq 2>/dev/null', timeout=10)
    if not result['status'] or not result['result']:
        if result.get('exit_status') in (0, 1, None):
            return empty_result('未发现 at 任务或 at 不可用')
        return command_failure(result, 'atq 查询失败')
    output = ['## atq', result['result']]
    for line in result['result'].splitlines()[:50]:
        job_id = line.split()[0] if line.split() else ''
        if job_id.isdigit():
            job = exec_command(ssh_session.client, f'at -c {shlex.quote(job_id)} 2>/dev/null', timeout=10, max_bytes=50000)
            if job['status'] and job['result']:
                output.append(f'## at job {job_id}\n{job["result"]}')
    return '\n\n'.join(output)



if __name__ == "__main__":
    mcp.run()
