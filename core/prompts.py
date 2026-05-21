TOOL_WORKFLOW = [
    "get_ssh_client",
    "check_safeline",
    "get_system_info",
    "run_quick_triage",
    "get_triage_summary",
    "按发现补充专项工具或 run_full_triage",
]

TOOL_CATEGORIES = {
    "基础/会话": [
        "get_ssh_client", "check_ssh_session", "close_ssh_client", "reset_session",
        "shell", "check_safeline", "get_system_info", "get_tool_inventory",
        "run_quick_triage", "run_full_triage", "get_triage_summary",
    ],
    "取证文件": [
        "stat_file", "hash_file", "download_file", "upload_file", "collect_evidence_bundle",
    ],
    "用户/权限": [
        "check_home", "check_passwd", "check_shadow", "check_sudoers", "check_ssh_keys",
        "check_history", "check_auth_log",
    ],
    "进程": [
        "get_ps", "check_mine", "check_exec", "check_pid", "check_exe", "check_mount",
        "check_deleted_exe",
    ],
    "网络": [
        "get_localhost", "check_network", "check_listening_ports", "check_eth", "check_hosts",
        "check_dns_config",
    ],
    "文件/WebShell": [
        "check_bin", "check_tmp", "check_recent_files", "check_webshell",
    ],
    "后门/持久化": [
        "check_persistence_summary", "check_ld_so_preload", "check_env_preload", "check_alias",
        "check_cron", "check_user_crontabs", "check_at_jobs", "check_ssh", "check_ssh_wrapper",
        "check_inetd", "check_xinetd", "check_setuid", "check_startup", "check_profile",
        "check_rc", "check_fstab", "check_systemd_timers", "check_service_execstart",
    ],
    "服务/容器": [
        "list_services", "check_enabled_services", "check_recent_systemd_changes",
        "check_docker_containers", "check_container_mounts", "check_container_processes",
    ],
    "日志": [
        "check_log", "check_web_logs_auto", "check_login_success", "check_login_fail",
    ],
    "Rootkit": ["RookitUpload"],
}


def render_tool_workflow():
    return " → ".join(TOOL_WORKFLOW)


def render_tool_categories():
    return "\n".join(f"- {category}：{'、'.join(tools)}" for category, tools in TOOL_CATEGORIES.items())


AUTOIR_MCP_BANNER = r"""
 █████╗ ██╗   ██╗████████╗ ██████╗ ██╗██████╗         ███╗   ███╗ ██████╗██████╗
██╔══██╗██║   ██║╚══██╔══╝██╔═══██╗██║██╔══██╗        ████╗ ████║██╔════╝██╔══██╗
███████║██║   ██║   ██║   ██║   ██║██║██████╔╝        ██╔████╔██║██║     ██████╔╝
██╔══██║██║   ██║   ██║   ██║   ██║██║██╔══██╗        ██║╚██╔╝██║██║     ██╔═══╝
██║  ██║╚██████╔╝   ██║   ╚██████╔╝██║██║  ██║███████╗██║ ╚═╝ ██║╚██████╗██║
╚═╝  ╚═╝ ╚═════╝    ╚═╝    ╚═════╝ ╚═╝╚═╝  ╚═╝╚══════╝╚═╝     ╚═╝ ╚═════╝╚═╝
""".strip("\n")

MCP_INSTRUCTIONS = f"""
你是 AUTOIR_MCP，一个通过 SSH 协助 Linux 主机应急响应的防御型 MCP 服务。

工作原则：
- 先建立上下文，再做判断；证据不足时标注“需人工复核”，不要把线索写成结论。
- 按需调用工具，避免重复扫描；已有 quick/full triage 结果时优先调用 get_triage_summary。
- 工具失败、权限不足、WAF 不可用、输出截断必须明示，不能归类为无异常。

推荐流程：
{render_tool_workflow()}

调用流程：
- 首次检测前必须调用 get_ssh_client；连接失败即停止并说明原因。
- 连接成功后优先调用 check_safeline 和 get_system_info。
- shell 只在 SSH 目标主机执行，不代表本地 Bash。

工具分组：
{render_tool_categories()}

最终报告要求：
- 必须以如下 AUTOIR_MCP 艺术字开头，放在 text 代码块中：
{AUTOIR_MCP_BANNER}
- 结构固定为：摘要 → 检测结果表 → 风险分析 → 处置建议 → 后续建议。
- 检测结果表字段固定为：| 检测项 | 关键发现 | 风险 | 依据 |。
- 风险等级只能使用：高 / 中 / 低 / 信息 / 未发现明显异常。
- 明确区分“未发现明显异常”“检测失败”“权限不足”“输出截断”“需人工复核”。
""".strip()
