def truncate_text(value, max_chars=4000):
    value = value or ""
    if len(value) <= max_chars:
        return value, False
    return value[:max_chars] + "\n[TRUNCATED] output exceeded limit", True
