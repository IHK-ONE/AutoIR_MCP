RISK_LEVELS = ("高", "中", "低", "信息", "未发现明显异常")


def tool_result(tool, ok=True, summary="未发现明显异常", findings=None, errors=None, metadata=None):
    return {
        "tool": tool,
        "ok": bool(ok),
        "summary": summary,
        "findings": findings or [],
        "errors": errors or [],
        "metadata": metadata or {},
    }


def finding(title, risk="信息", target="", evidence="", recommendation=""):
    if risk not in RISK_LEVELS:
        risk = "信息"
    return {
        "title": title,
        "risk": risk,
        "target": target,
        "evidence": evidence,
        "recommendation": recommendation,
    }


def format_tool_output(tool, content, empty_message="未发现明显异常"):
    if content is None:
        content = ""
    if isinstance(content, str):
        stripped = content.strip()
        return stripped or f"[EMPTY] {tool}: {empty_message}"
    return content
