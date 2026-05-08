from pathlib import Path


def is_safe_path(base_dir, candidate):
    try:
        Path(candidate).resolve().relative_to(Path(base_dir).resolve())
        return True
    except (OSError, ValueError):
        return False


def is_safe_tar_member(destination, member, max_member_size=20 * 1024 * 1024):
    if member.issym() or member.islnk() or member.isdev() or member.size > max_member_size:
        return False
    if Path(member.name).is_absolute() or ".." in Path(member.name).parts:
        return False
    return is_safe_path(destination, Path(destination) / member.name)
