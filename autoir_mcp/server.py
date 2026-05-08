from fastmcp import FastMCP
from .functions import *
from .prompts import MCP_INSTRUCTIONS
from .schemas import format_tool_output
from .session import SSHSession
from .utils.path_safety import is_safe_path, is_safe_tar_member
import paramiko
import os
import csv
import json
import urllib
import tarfile
import hashlib
import subprocess
import collections
import re
import shlex
import urllib.parse
from pathlib import Path

base_dir = str(Path(__file__).resolve().parents[1])

mcp = FastMCP("AutoIR_MCP", instructions=MCP_INSTRUCTIONS)


ssh_session = SSHSession(0)


def check_session():
    global ssh_session
    if ssh_session is None or ssh_session.client is None:
        return False
    try:
        ssh_session.client.exec_command('echo test', timeout=5)
        return True
    except Exception:
        return False


READONLY_DENIED_PATTERNS = (
    r'(^|\s)(rm|mv|cp|chmod|chown|kill|pkill|reboot|shutdown|halt|poweroff|mkfs|dd)\b',
    r'(^|\s)(apt|yum|dnf|apk|pip|npm|gem)\s+(install|remove|erase|upgrade|update)\b',
    r'\b(systemctl|service)\s+(start|stop|restart|reload|enable|disable)\b',
    r'(^|[^<])>>?\s*\S+',
    r'\|\s*(sh|bash|python|perl)\b',
    r'\b(curl|wget)\b.*\|',
)

READONLY_ALLOWED_PREFIXES = (
    'cat ', 'grep ', 'egrep ', 'fgrep ', 'awk ', 'sed ', 'head ', 'tail ', 'ls ', 'find ', 'stat ',
    'file ', 'strings ', 'ps ', 'ss ', 'netstat ', 'lsof ', 'ip ', 'hostname', 'uname', 'date',
    'uptime', 'who', 'w', 'last', 'lastb', 'systemctl ', 'journalctl ', 'crontab ', 'atq',
    'docker ps', 'docker inspect', 'docker top', 'podman ps', 'podman inspect', 'podman top'
)


def validate_readonly_command(command):
    normalized = command.strip()
    lower = normalized.lower()
    for pattern in READONLY_DENIED_PATTERNS:
        if re.search(pattern, lower):
            return normalized, f"readonly_shell 拒绝非只读命令: {command}"
    if not lower.startswith(READONLY_ALLOWED_PREFIXES):
        return normalized, f"readonly_shell 仅允许常见只读命令: {command}"
    return normalized, ''


@mcp.tool()
def get_ssh_client(ip, port=22, username='root', password=''):
    """
    建立 SSH 会话并缓存连接。
    调用：所有远程检测工具前必须先调用；参数为 ip、port、username、password。
    输出：返回连接状态和失败原因。
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
        ssh_session = SSHSession(client)
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
    connected = check_session()
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
    调用：需要清空缓存的用户、进程、网络、巡检摘要等状态时使用；默认同时关闭 SSH 连接。
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
    ssh_session = SSHSession(old_client)
    return {"status": True, "result": "会话状态已重置，SSH 连接保持不变"}


@mcp.tool()
def shell(command, timeout=10, max_bytes=200000):
    """
    在已连接的 SSH 目标主机上执行 shell 命令。
    调用：需要 AI 直接通过 MCP 对目标机执行命令时使用，不使用本地 Bash；必须先调用 get_ssh_client。
    输出：返回远程命令、退出码、stdout、stderr、耗时和截断状态。
    """
    if not check_session():
        return {"status": False, "result": "错误：SSH连接未建立或已断开，请先调用 get_ssh_client 建立连接"}
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

    result = exec_command(ssh_session.client, command.strip(), timeout=timeout, max_bytes=max_bytes)
    return {
        "status": result.get("status"),
        "command": result.get("command"),
        "exit_status": result.get("exit_status"),
        "stdout": result.get("stdout", ""),
        "stderr": result.get("stderr", ""),
        "error": result.get("error", ""),
        "duration_ms": result.get("duration_ms"),
        "timeout": result.get("timeout"),
        "truncated": result.get("truncated"),
    }


@mcp.tool()
def readonly_shell(command, timeout=10, max_bytes=200000):
    """
    在 SSH 目标主机上执行取证友好的只读命令。
    调用：AI 默认需要直接查看目标机信息时优先使用；它不是安全沙箱，只用于减少误操作。
    输出：同 shell，但会拒绝明显写入、破坏或交互类命令。
    """
    if not isinstance(command, str) or not command.strip():
        return {"status": False, "result": "command 不能为空"}
    normalized, error = validate_readonly_command(command)
    if error:
        return {"status": False, "result": error}
    return shell(normalized, timeout=timeout, max_bytes=max_bytes)


@mcp.tool()
def check_safeline():
    """
    检测 SafeLine WAF 可用性。
    调用：SSH 连接成功后优先调用一次，用于后续恶意命令/请求辅助判断。
    输出：返回 WAF 存活状态。
    """
    ssh_session.safeline_server = check_safe_safeline('bash -i')
    if ssh_session.safeline_server:
        return '雷池 WAF 服务存活。。。'
    else:
        return '雷池 WAF 未存活，继续运行。。。'


def command_format(check, command):
    return 'env -i /usr/bin/' + command if check else command


def quote_remote_path(path):
    return shlex.quote(str(path))


def detect_malicious_text(content):
    malicious_local = check_safe_local(content)
    malicious_safeline = check_safe_safeline(content) if ssh_session.safeline_server else ''
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
        ip_match = re.search(r'\b\d{1,3}(?:\.\d{1,3}){3}\b', line)
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
                ssh_session.hijack_list.append(f'[+] 环境变量劫持: {key}')
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
        return "错误：SSH连接未建立或已断开，请先调用 get_ssh_client 建立连接"

    # 常规目录环境变量排查
    common_files = ['/root/.bashrc', '/root/.tcshrc', '/root/.bash_profile', '/root/.cshrc', '/etc/bashrc',
                    '/etc/profile', '/etc/csh.login', '/etc/csh.cshrc']
    home_files = ['.bashrc', '.bash_profile', '.tcshrc', '.cshrc']

    # 检查是否被劫持
    result = exec_command(ssh_session.client, 'ls -al .')
    if result['status'] and result['result'][:5] != 'total':
        result = exec_command(ssh_session.client, 'env -i /usr/bin/ls -al .')
        if result['status'] and result['result'][:5] == 'total':
            ssh_session.hijack = True

    # 处理常规文件
    process_files(common_files)

    # 处理 /etc/profile.d/ 目录下的文件
    profile_d_files = []
    profile_d_command = command_format(ssh_session.hijack, 'ls -al /etc/profile.d/')
    profile_d_result = exec_command(ssh_session.client, profile_d_command)
    if profile_d_result['status'] and profile_d_result['result']:
        profile_d_files = [file['filename'] for file in get_file_list(profile_d_result['result']).values()]
    process_files(profile_d_files, '/etc/profile.d/')

    # 处理 HOME 目录下的用户文件
    home_dir_command = command_format(ssh_session.hijack, 'ls -al /home')
    home_dir_result = exec_command(ssh_session.client, home_dir_command)
    if home_dir_result['status'] and home_dir_result['result']:
        ssh_session.user_list = [file['filename'] for file in get_file_list(home_dir_result['result']).values()]
        process_files([f'/home/{user}/{f}' for user in ssh_session.user_list for f in home_files])

    return '\n'.join(ssh_session.hijack_output)


def extract_users_from_output(output):
    """ ssh_key 用户名提取 """
    return [line.strip().split()[-1] for line in output.splitlines() if line.strip()]


def get_group():
    result = exec_command(ssh_session.client, f'cat /etc/group')
    if result['status'] and result['result']:
        for line in result['result'].splitlines():
            parts = line.strip().split(':')
            # 组名:密码:占位符 GID:组内用户
            if len(parts) >= 4:
                group_name, _, _, users = parts
                ssh_session.group_list[group_name] = [user.strip() for user in users.split(',') if user.strip()]


def load_home_users():
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
        return "错误：SSH连接未建立或已断开，请先调用 get_ssh_client 建立连接"

    return '\n'.join(load_home_users())


def check_home_nomcp():
    if not check_session():
        return "错误：SSH连接未建立或已断开，请先调用 get_ssh_client 建立连接"

    return '\n'.join(load_home_users())


@mcp.tool()
def check_history():
    """
    检查 root 与普通用户的 bash_history 是否存在。
    调用：发现可疑用户或需追踪操作痕迹时使用。
    输出：返回存在历史记录的路径。
    """

    if not check_session():
        return "错误：SSH连接未建立或已断开，请先调用 get_ssh_client 建立连接"
    output = []

    if not ssh_session.user_list:
        check_home_nomcp()

    # 检查 root 用户的 bash_history
    result = exec_command(ssh_session.client, f'cat /root/.bash_history')
    if result['status'] and result['result']:
        output.append(f'[!] 存在 bash_history: /root/.bash_history')

    # 检查其他用户的 bash_history
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
        return "错误：SSH连接未建立或已断开，请先调用 get_ssh_client 建立连接"

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
        return "错误：SSH连接未建立或已断开，请先调用 get_ssh_client 建立连接"

    output = []

    if not ssh_session.user_list:
        check_home_nomcp()

    # 检查 root 用户的 authorized_keys
    result = exec_command(ssh_session.client, f'cat /root/.ssh/authorized_keys')
    if result['status'] and result['result']:
        users = ', '.join(extract_users_from_output(result['result']))
        output.append(f'/root/.ssh/authorized_keys\tuser list{users}\t[!] 存在 SSH authorized_keys')

    result = exec_command(ssh_session.client, f'find /root/.ssh/ -type f 2>/dev/null')
    if result['status'] and result['result']:
        output.append(f'{result["result"]}\t[!] 存在 SSH authorized_keys')

    # 检查其他用户的 authorized_keys
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
        return "错误：SSH连接未建立或已断开，请先调用 get_ssh_client 建立连接"

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
        return "错误：SSH连接未建立或已断开，请先调用 get_ssh_client 建立连接"

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


check_proc = json.load(open(os.path.join(base_dir, 'config', 'info_proc.json'), encoding='utf-8'))
privilege_escalation = ['aa-exec', 'ansible-playbook', 'ansible-test', 'aoss', 'apt-get', 'apt', 'ash', 'at', 'awk',
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
        return "错误：SSH连接未建立或已断开，请先调用 get_ssh_client 建立连接"

    return f"已获取 {load_processes()} 个进程信息"


def get_ps_nomcp():
    if not check_session():
        return "错误：SSH连接未建立或已断开，请先调用 get_ssh_client 建立连接"

    return f"已获取 {load_processes()} 个进程信息"


@mcp.tool()
def check_mine():
    """
    检测高 CPU/内存占用进程。
    调用：怀疑挖矿、资源异常或主机卡顿时使用；会自动补采进程快照。
    输出：返回超过阈值的 PID、资源占用和命令。
    """

    if not check_session():
        return "错误：SSH连接未建立或已断开，请先调用 get_ssh_client 建立连接"

    if not ssh_session.ps:
        get_ps_nomcp()

    output = ''
    for pid, proc in ssh_session.ps.items():
        cpu, mem, command = proc['cpu'], proc['mem'], proc['command']
        if cpu > 50.0 or mem > 50.0:
            output += f'PID: {pid}\tCPU: {cpu}\tMEM: {mem}\tCOMMAND: {command}\t[!] "疑似挖矿脚本，cpu/mem 占用超过 50%", "red"\n'
    return output


@mcp.tool()
def check_exec():
    """
    检测可疑命令执行进程。
    调用：排查反弹 shell、相对路径执行、root 可提权命令或 WAF 命中特征时使用。
    输出：返回 PID、TTY、命令和可疑原因。
    """

    if not check_session():
        return "错误：SSH连接未建立或已断开，请先调用 get_ssh_client 建立连接"

    if not ssh_session.ps:
        get_ps_nomcp()

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
            if check in command:
                output += f'"command: " {command}\t[!] 疑似可 root 提权\n'
                break

    return output


@mcp.tool()
def check_pid():
    """
    检测疑似隐藏 PID。
    调用：怀疑 rootkit、进程隐藏或 ps 输出不可信时使用。
    输出：返回 /proc 存在但进程快照缺失的 PID。
    """

    if not check_session():
        return "错误：SSH连接未建立或已断开，请先调用 get_ssh_client 建立连接"

    if not ssh_session.ps:
        get_ps_nomcp()

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

    return output


@mcp.tool()
def check_exe():
    """
    检测进程名与真实可执行文件不一致。
    调用：怀疑进程伪装、命令替换或二进制劫持时使用。
    输出：返回 PID、真实 exe 和 ps 中显示的 exe。
    """

    if not check_session():
        return "错误：SSH连接未建立或已断开，请先调用 get_ssh_client 建立连接"

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

                        if (true_exe != exe) and (((true_exe in check_proc) and (exe not in check_proc[true_exe])) or (
                                true_exe not in check_proc)):
                            output += f'PID: {pid}\ttrue_exe: {true_exe}\texe: {exe}\t[!]"命令被替换\n'
            except ValueError:
                pass

    return output


@mcp.tool()
def check_mount():
    """
    检查 /proc 挂载异常。
    调用：怀疑通过 mount 隐藏进程或伪装文件系统时使用。
    输出：返回可疑 /proc/<pid> 挂载项。
    """

    if not check_session():
        return "错误：SSH连接未建立或已断开，请先调用 get_ssh_client 建立连接"

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
        return "错误：SSH连接未建立或已断开，请先调用 get_ssh_client 建立连接"

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


@mcp.tool()
def check_network():
    """
    分析 ss -anutp 网络连接。
    调用：排查异常外联、监听端口或后门通信时使用；建议先调用 get_localhost。
    输出：返回本地地址、远程地址、进程和连接类型。
    """
    if not check_session():
        return "错误：SSH连接未建立或已断开，请先调用 get_ssh_client 建立连接"

    output = []

    result = first_success(ssh_session.client, ['ss -anutp', 'netstat -anutp 2>/dev/null'])
    if not result.get('status'):
        return command_failure(result, '网络连接获取失败')
    if not result.get('result'):
        return empty_result()

    for line in result['result'].splitlines()[1:]:
        try:
            parts = re.split(r'\s+', line.strip())
            if not parts:
                continue
            if parts[0] in ('tcp', 'udp', 'tcp6', 'udp6') and len(parts) >= 5:
                local, remote, pid_program = parts[3], parts[4], parts[-1]
            elif len(parts) >= 6:
                local, remote, pid_program = parts[4], parts[5], parts[-1]
            else:
                continue

            local_addr, local_port = local.rsplit(':', 1)
            remote_addr, remote_port = remote.rsplit(':', 1)

            if remote_addr not in ssh_session.ip_list and remote_port != "*":
                output.append(f'local :{local}\tremote :{remote}\tpid :{pid_program}\t[!] 发现远程连接')
            elif local_port and local_port != "*":
                output.append(f'local :{local}\tremote :{remote}\tpid :{pid_program}\t[!] 发现开启端口')
        except (IndexError, ValueError):
            pass

    return '\n'.join(output) or empty_result()


@mcp.tool()
def check_eth():
    """
    枚举网卡设备。
    调用：排查异常网卡、虚拟网卡或多网段资产时使用。
    输出：返回网卡名称列表。
    """

    if not check_session():
        return "错误：SSH连接未建立或已断开，请先调用 get_ssh_client 建立连接"

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
        return "错误：SSH连接未建立或已断开，请先调用 get_ssh_client 建立连接"

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


check_bin_json = json.load(open(os.path.join(base_dir, 'config', 'info_bin.json'), encoding='utf-8'))


@mcp.tool()
def check_bin():
    """
    校验 /usr/bin 基线。
    调用：怀疑系统命令被替换、权限异常或新增可疑命令时使用。
    输出：返回权限/属主/链接/类型异常以及最近修改命令。
    """

    if not check_session():
        return "错误：SSH连接未建立或已断开，请先调用 get_ssh_client 建立连接"

    output = ''

    result = exec_command(ssh_session.client, 'ls -alt /usr/bin')
    if result['status'] and result['result']:
        current_bin = []
        for file in get_file_list(result['result']).values():
            filename = file['filename']
            owner = file['owner']
            group = file['group']
            perm = file['perm']
            time = file['time']
            link = ''
            current_bin.append([filename, time])

            if '->' in filename:
                link = filename.split(' -> ')[1]
                filename = filename.split(' -> ')[0]

            check_out = []
            if filename in check_bin_json:
                baseline = check_bin_json[filename]
                if baseline.get('perm') is None or baseline.get('owner') is None or baseline.get('group') is None:
                    check_out.append('基线缺字段')
                if baseline.get('perm') is not None and perm != baseline.get('perm'):
                    check_out.append('权限异常')
                if baseline.get('owner') is not None and baseline.get('group') is not None:
                    if owner != baseline.get('owner') or group != baseline.get('group'):
                        check_out.append('所属异常')
                if baseline.get('link') is not None and link != baseline.get('link'):
                    check_out.append('恶意链接')
            else:
                check_out.append("不常见命令")

            if check_out:
                output += f"file: {filename}\tperm: {perm}\towner: {owner}\tgroup: {group}\t[!] {', '.join(check_out)}\n"

        # '/usr/bin 最近修改'
        output += ''.join(
            [f'file: {item[0]}\ttime: {item[1]}\t[!] 最近修改的命令\n' for item in current_bin[:5]])

    # 文件类型排查
    result = exec_command(ssh_session.client, 'find /usr/bin -type f -exec file {} + 2>/dev/null')
    if result['status'] and result['result']:
        for line in result['result'].splitlines():
            if ':' in line:
                file_path, file_type = line.split(':', 1)
                file_type = file_type.split(',')[0].strip()
                if 'ELF' in file_type:
                    file_type = 'ELF'
                if Path(file_path).name in check_bin_json:
                    if check_bin_json[Path(file_path).name].get('type') != file_type:
                        output += f'file path: {file_path}\tfile type: {file_type}\t[!] 文件类型错误\n'

    return output or empty_result()


@mcp.tool()
def check_tmp():
    """
    列举 /tmp 下文件。
    调用：排查临时目录落地文件、脚本或恶意样本时使用。
    输出：返回 /tmp 可疑文件路径。
    """

    if not check_session():
        return "错误：SSH连接未建立或已断开，请先调用 get_ssh_client 建立连接"

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
def check_webshell(path='/var/www/html', max_files=20000):
    """
    扫描 webroot 中的疑似 WebShell。
    调用：传入站点目录，工具会打包下载并调用本地扫描器分析。
    输出：返回疑似文件路径、MD5 或扫描器错误。
    """

    if not check_session():
        return "错误：SSH连接未建立或已断开，请先调用 get_ssh_client 建立连接"

    output = ''
    try:
        max_files = max(1, min(int(max_files), 100000))
    except (TypeError, ValueError):
        max_files = 20000
    path = path.strip() or '/var/www/html'
    quoted_path = quote_remote_path(path)

    result = exec_command(ssh_session.client, f'find {quoted_path} -type f 2>/dev/null')
    if not result['status']:
        return command_failure(result, 'webroot 文件枚举失败')
    if not result['result']:
        return empty_result('webroot 目录未发现文件')

    file_count = len(result['result'].splitlines())
    if file_count > max_files:
        return f'webroot 文件数量 {file_count} 超过限制 {max_files}，请缩小扫描目录或提高 max_files'

    if result['status'] and result['result']:
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
        return "错误：SSH连接未建立或已断开，请先调用 get_ssh_client 建立连接"

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
        return "错误：SSH连接未建立或已断开，请先调用 get_ssh_client 建立连接"

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
        return "错误：SSH连接未建立或已断开，请先调用 get_ssh_client 建立连接"

    output = ''

    result = exec_command(ssh_session.client, 'ls -al /usr/sbin/sshd')
    if result['status'] and result['result'] and '>' in result['result']:
        output += f'content: {result["result"]}\t[!] /usr/sbin/sshd 已被劫持\n'

    return output


@mcp.tool()
def check_ssh_wrapper():
    """
    检查 sshd 二进制中的可疑字符串。
    调用：怀疑 SSH wrapper 后门或 sshd 被脚本/恶意逻辑包装时使用。
    输出：返回命中的可疑内容。
    """

    if not check_session():
        return "错误：SSH连接未建立或已断开，请先调用 get_ssh_client 建立连接"

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

    return output


@mcp.tool()
def check_inetd():
    """
    检查 /etc/inetd.conf 中的可疑后门配置。
    调用：排查 inetd 持久化或网络服务触发命令执行时使用。
    输出：返回可疑配置内容。
    """

    if not check_session():
        return "错误：SSH连接未建立或已断开，请先调用 get_ssh_client 建立连接"

    output = check_malicious_content('/etc/inetd.conf')
    return output


@mcp.tool()
def check_xinetd():
    """
    检查 xinetd 配置中的可疑后门。
    调用：排查 xinetd 服务持久化、反弹 shell 或异常执行路径时使用。
    输出：返回可疑配置文件和命中内容。
    """

    if not check_session():
        return "错误：SSH连接未建立或已断开，请先调用 get_ssh_client 建立连接"

    output = ''

    for file in get_files('/etc/xinetd.conf/'):
        output += check_malicious_content(f'/etc/xinetd.conf/{file}')

    return output


@mcp.tool()
def check_setuid():
    """
    查找 SUID 文件。
    调用：排查本地提权后门或异常 SUID 程序时使用。
    输出：返回发现的 SUID 文件路径。
    """

    if not check_session():
        return "错误：SSH连接未建立或已断开，请先调用 get_ssh_client 建立连接"

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
        return "错误：SSH连接未建立或已断开，请先调用 get_ssh_client 建立连接"

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
        return "错误：SSH连接未建立或已断开，请先调用 get_ssh_client 建立连接"

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
        return "错误：SSH连接未建立或已断开，请先调用 get_ssh_client 建立连接"

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
        return "错误：SSH连接未建立或已断开，请先调用 get_ssh_client 建立连接"

    try:
        max_lines = max(1, min(int(max_lines), 50000))
    except (TypeError, ValueError):
        max_lines = 5000

    output = f'仅分析最近 {max_lines} 行日志\n'
    ssh_session.request_success = {}
    ssh_session.request_jump = {}
    ssh_session.request_others = {}
    ssh_session.user_agents = []

    result = exec_command(ssh_session.client, f'tail -n {int(max_lines)} {quote_remote_path(path)} 2>/dev/null')
    if not result['status']:
        return command_failure(result, '日志读取失败')
    if not result['result']:
        return empty_result('日志为空或无可读内容')

    if result['status'] and result['result']:
        access_log = result['result'].splitlines()
        checked_lines = set()
        for line in access_log:
            stripped = line.strip()
            if stripped in checked_lines:
                continue
            checked_lines.add(stripped)
            malicious = detect_malicious_text(stripped)
            if malicious:
                output += f'url: {urllib.parse.unquote(stripped)}\t[!] 恶意请求\n'

        for num, match in enumerate(pattern.finditer(result['result'])):
            request = match.groupdict()
            status = request['status']
            user_agent = request['user_agent']

            if status == '200' and len(request['path']) != 1:
                ssh_session.request_success[num] = request
            elif status == '302':
                ssh_session.request_jump[num] = request
            else:
                ssh_session.request_others[num] = request

            if user_agent not in ssh_session.user_agents:
                ssh_session.user_agents.append(user_agent)

        output += '成功访问 IP 统计\n'
        for ip, count in collections.Counter(
                [request['ip'] for request in ssh_session.request_success.values()]).items():
            output += f'\tip: {ip}\tcount: {count}\n'

        output += '\n跳转访问 IP 统计\n'
        for ip, count in collections.Counter([request['ip'] for request in ssh_session.request_jump.values()]).items():
            output += f'\tip: {ip}\tcount: {count}\n'

        output += '\n失败访问 IP 统计\n'
        for ip, count in collections.Counter(
                [request['ip'] for request in ssh_session.request_others.values()]).items():
            output += f'\tip: {ip}\tcount: {count}\n'

        output += '\n访问 User-Agent 统计\n'
        for user_agent in sorted(ssh_session.user_agents):
            output += f'\tUser-Agent: {user_agent}\n'

        output += '\n成功访问 请求统计\n'
        for request in ssh_session.request_success.values():
            output += f'\tip: {request["ip"]}\turi: {request["path"]}\tuser agent: {request["user_agent"]}\n'

        output += '\n跳转访问 请求统计\n'
        for request in ssh_session.request_jump.values():
            output += f'\tip: {request["ip"]}\turi: {request["path"]}\tuser agent: {request["user_agent"]}\n'

    return output


@mcp.tool()
def check_login_success():
    """
    统计成功登录来源。
    调用：排查异常 SSH 登录、凭证泄露或未知远程登录时使用。
    输出：返回登录 IP 和次数。
    """

    if not check_session():
        return "错误：SSH连接未建立或已断开，请先调用 get_ssh_client 建立连接"

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
        return "错误：SSH连接未建立或已断开，请先调用 get_ssh_client 建立连接"

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
def RookitUpload():
    """
    上传并安装 rkhunter。
    调用：需要 rootkit 深度检测时使用；安装后需用户手动执行 rkhunter --check。
    输出：返回上传安装状态。
    """

    if not check_session():
        return "错误：SSH连接未建立或已断开，请先调用 get_ssh_client 建立连接"

    local_rkhunter = Path(base_dir) / 'extensions' / 'rkhunter.gz'
    upload_result = sftp_upload(ssh_session.client, str(local_rkhunter), '/tmp/rkhunter.gz')
    if not upload_result.get('status'):
        return f'上传失败: {upload_result.get("error") or "本地 rkhunter.gz 不存在或 SFTP 失败"}'

    result = exec_command(ssh_session.client, 'cd /tmp && tar -xf /tmp/rkhunter.gz && cd /tmp/rkhunter-1.4.6 && bash installer.sh --install', timeout=120, max_bytes=120000)

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
        return "错误：SSH连接未建立或已断开，请先调用 get_ssh_client 建立连接"

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
        return "错误：SSH连接未建立或已断开，请先调用 get_ssh_client 建立连接"

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
        return "错误：SSH连接未建立或已断开，请先调用 get_ssh_client 建立连接"

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
        return "错误：SSH连接未建立或已断开，请先调用 get_ssh_client 建立连接"

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
        return "错误：SSH连接未建立或已断开，请先调用 get_ssh_client 建立连接"

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
        return "错误：SSH连接未建立或已断开，请先调用 get_ssh_client 建立连接"

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
        return "错误：SSH连接未建立或已断开，请先调用 get_ssh_client 建立连接"

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
        return "错误：SSH连接未建立或已断开，请先调用 get_ssh_client 建立连接"

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
        return "错误：SSH连接未建立或已断开，请先调用 get_ssh_client 建立连接"

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
        return "错误：SSH连接未建立或已断开，请先调用 get_ssh_client 建立连接"

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


@mcp.tool()
def stat_file(path):
    """
    获取目标主机文件元数据。
    调用：取证前确认文件权限、大小、时间和类型时使用。
    输出：返回 stat 信息，失败时 fallback 到 ls -al。
    """
    if not check_session():
        return "错误：SSH连接未建立或已断开，请先调用 get_ssh_client 建立连接"
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
        return "错误：SSH连接未建立或已断开，请先调用 get_ssh_client 建立连接"
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
def download_file(remote_path, local_dir='downloads/evidence'):
    """
    下载目标主机文件到本地取证目录。
    调用：需要保存可疑文件、日志或配置用于后续分析时使用。
    输出：返回本地路径、远程路径和下载状态。
    """
    if not check_session():
        return {"status": False, "result": "错误：SSH连接未建立或已断开，请先调用 get_ssh_client 建立连接"}
    if not isinstance(remote_path, str) or not remote_path.strip():
        return {"status": False, "result": "remote_path 不能为空"}
    stat_result = exec_command(ssh_session.client, f"stat -c '%n\t%s bytes\t%U:%G\t%A\t%y' {quote_remote_path(remote_path)} 2>/dev/null")
    target_dir = safe_local_subdir(local_dir) / get_time_path()
    target_dir.mkdir(parents=True, exist_ok=True)
    local_path = target_dir / Path(remote_path.strip()).name
    result = sftp_download(ssh_session.client, remote_path.strip(), str(local_path))
    return {
        "status": result.get('status'),
        "remote_path": remote_path.strip(),
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
        return {"status": False, "result": "错误：SSH连接未建立或已断开，请先调用 get_ssh_client 建立连接"}
    local = Path(local_path).expanduser().resolve()
    if not local.is_file():
        return {"status": False, "result": f"本地文件不存在: {local}"}
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
        return {"status": False, "result": "错误：SSH连接未建立或已断开，请先调用 get_ssh_client 建立连接"}
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
        return "错误：SSH连接未建立或已断开，请先调用 get_ssh_client 建立连接"
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
        return "错误：SSH连接未建立或已断开，请先调用 get_ssh_client 建立连接"
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
        return "错误：SSH连接未建立或已断开，请先调用 get_ssh_client 建立连接"
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
        return "错误：SSH连接未建立或已断开，请先调用 get_ssh_client 建立连接"
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
        return "错误：SSH连接未建立或已断开，请先调用 get_ssh_client 建立连接"
    runtime = container_runtime()
    if not runtime:
        return empty_result('未发现 docker/podman 命令')
    ids = container_ids(runtime)
    if not ids:
        return empty_result('未发现容器')
    output = []
    for cid in ids[:50]:
        result = exec_command(ssh_session.client, f"{runtime} inspect --format '{{{{.Name}}}} {{{{json .Mounts}}}}' {shlex.quote(cid)} 2>/dev/null", timeout=20, max_bytes=50000)
        if result['status'] and result['result']:
            output.append(result['result'])
    return '\n'.join(output) or empty_result('未发现容器挂载信息')


@mcp.tool()
def check_container_processes():
    """
    检查容器内进程。
    调用：排查容器内挖矿、反弹 shell 或异常服务时使用。
    输出：返回容器 top 进程摘要。
    """
    if not check_session():
        return "错误：SSH连接未建立或已断开，请先调用 get_ssh_client 建立连接"
    runtime = container_runtime()
    if not runtime:
        return empty_result('未发现 docker/podman 命令')
    ids = container_ids(runtime)
    if not ids:
        return empty_result('未发现容器')
    output = []
    for cid in ids[:50]:
        result = exec_command(ssh_session.client, f"{runtime} top {shlex.quote(cid)} 2>/dev/null", timeout=20, max_bytes=50000)
        if result['status'] and result['result']:
            output.append(f'## {cid}\n{result["result"]}')
    return '\n\n'.join(output) or empty_result('未发现容器进程信息')


@mcp.tool()
def check_user_crontabs():
    """
    检查用户级 crontab。
    调用：排查用户级计划任务、反弹 shell 或定时下载执行时使用。
    输出：返回每个用户的 crontab 和 spool 文件线索。
    """
    if not check_session():
        return "错误：SSH连接未建立或已断开，请先调用 get_ssh_client 建立连接"
    passwd = exec_command(ssh_session.client, 'cat /etc/passwd 2>/dev/null')
    if not passwd['status']:
        return command_failure(passwd, 'passwd 读取失败')
    users = []
    for line in passwd['result'].splitlines():
        parts = line.split(':')
        if len(parts) >= 7 and parts[6] not in ('/usr/sbin/nologin', '/sbin/nologin', '/bin/false'):
            users.append(parts[0])
    output = []
    for user in users[:200]:
        quoted_user = shlex.quote(user)
        result = exec_command(ssh_session.client, f'crontab -l -u {quoted_user} 2>/dev/null', timeout=10, max_bytes=50000)
        if result['status'] and result['result']:
            output.append(f'## user: {user}\n{result["result"]}')
    spool = exec_command(ssh_session.client, 'find /var/spool/cron /var/spool/cron/crontabs -type f -maxdepth 2 -printf "%p\t%u:%g\t%m\t%s bytes\n" 2>/dev/null', timeout=20)
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
        return "错误：SSH连接未建立或已断开，请先调用 get_ssh_client 建立连接"
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


@mcp.tool()
def get_triage_summary():
    """
    获取最近一次 quick/full triage 结果缓存。
    调用：需要复用最近巡检结果、避免重复执行重命令时使用。
    输出：返回缓存摘要或提示先运行巡检。
    """
    if not getattr(ssh_session, 'last_triage_summary', ''):
        return '暂无巡检缓存，请先运行 run_quick_triage 或 run_full_triage'
    return f'巡检类型: {getattr(ssh_session, "last_triage_type", "unknown")}\n\n{ssh_session.last_triage_summary}'


def run_tool_sequence(tools):
    results = []
    for func in tools:
        tool_name = func.__name__
        try:
            value = func()
            text = format_tool_output(tool_name, value)
            if not isinstance(text, str):
                text = json.dumps(text, ensure_ascii=False)
            results.append(f'## {tool_name}\n{text}')
        except Exception as error:
            results.append(f'## {tool_name}\n[ERROR] {error}')
    return '\n\n'.join(results)


@mcp.tool()
def run_quick_triage():
    """
    执行快速应急巡检。
    调用：需要低耗时覆盖用户、进程、网络、持久化和登录日志时使用；必须先建立 SSH。
    输出：返回各检测工具摘要，单项失败不影响后续检测。
    """
    if not check_session():
        return "错误：SSH连接未建立或已断开，请先调用 get_ssh_client 建立连接"
    tools = (
        check_safeline, get_system_info, check_hijack, check_home, check_passwd, check_shadow,
        check_sudoers, check_ssh_keys, check_history, get_ps, check_mine, check_exec,
        check_deleted_exe, get_localhost, check_network, check_hosts, check_dns_config,
        check_ld_so_preload, check_env_preload, check_alias, check_cron, check_user_crontabs,
        check_at_jobs, check_startup, list_services, check_enabled_services, check_docker_containers,
        check_login_success, check_login_fail,
    )
    result = run_tool_sequence(tools)
    ssh_session.last_triage_type = 'quick'
    ssh_session.last_triage_summary = result
    return result


@mcp.tool()
def run_full_triage(webroot='/var/www/html', include_webshell=True, include_rootkit=False):
    """
    执行全量应急巡检。
    调用：需要全面排查用户、进程、网络、文件、持久化、日志和 rootkit 线索时使用；必须先建立 SSH。
    输出：返回各检测工具摘要，单项失败不影响后续检测。
    """
    if not check_session():
        return "错误：SSH连接未建立或已断开，请先调用 get_ssh_client 建立连接"
    output = [run_quick_triage()]
    extra_tools = (
        check_pid, check_exe, check_mount, check_eth, check_bin, check_tmp, check_ssh,
        check_ssh_wrapper, check_inetd, check_xinetd, check_setuid, check_profile, check_rc,
        check_fstab, check_systemd_timers, check_service_execstart, check_recent_systemd_changes,
        check_container_mounts, check_container_processes, check_auth_log, check_web_logs_auto,
    )
    output.append(run_tool_sequence(extra_tools))
    if include_webshell:
        try:
            output.append(f'## check_webshell\n{check_webshell(path=webroot)}')
        except Exception as error:
            output.append(f'## check_webshell\n[ERROR] {error}')
    if include_rootkit:
        try:
            output.append(f'## RookitUpload\n{RookitUpload()}')
        except Exception as error:
            output.append(f'## RookitUpload\n[ERROR] {error}')
    result = '\n\n'.join(output)
    ssh_session.last_triage_type = 'full'
    ssh_session.last_triage_summary = result
    return result


if __name__ == "__main__":
    mcp.run()
