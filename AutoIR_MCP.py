from fastmcp import FastMCP
from functions import *
import paramiko
import os
import csv
import json
import urllib
import tarfile
import hashlib
import subprocess
import collections
import urllib.parse
from pathlib import Path

# 获取当前脚本所在目录
base_dir = os.path.dirname(os.path.abspath(__file__))

mcp = FastMCP("AutoIR_MCP", instructions="""
    ** 工具概述 **
        远程应急响应工具集，可对目标服务器进行快速排查与分析。

    ** 会话规则【关键】 **
        1. 第一次操作必须先调用 get_ssh_client 建立 SSH 连接
        2. 连接成功后，立即调用 check_safeline 记录雷池 WAF 状态
        3. 若任意工具返回连接错误，请重新执行 get_ssh_client
        4. 相同的连接参数会自动复用，请勿重复创建

    ** 任务选择逻辑 **
        - 用户给出目标或问题：拆解需求 → 推断潜在攻击链 → 依序调用最相关的工具，可并行协同分析
        - 用户未指定需求：按模块顺序完整巡检
            1. HijackAnalysis 环境变量劫持
            2. UserAnalysis 恶意用户
            3. ProcAnalysis 恶意进程
            4. NetworkAnalysis 网络异常
            5. FileAnalysis 可疑文件
            6. BackdoorAnalysis 持久化后门
            7. LogAnalysis 日志事件
            8. Rookit Rootkit

    ** 工具目录 **
        # UserAnalysis
        1. /home 用户目录排查
        2. /etc/passwd 高权限与交互式 shell 用户
        3. /etc/shadow 空口令用户
        4. sudoers 异常授权
        5. authorized_keys 免密登录

        # ProcAnalysis
        1. 挖矿进程
        2. 恶意命令执行
        3. 隐藏 PID
        4. 命令替换
        5. 异常挂载

        # NetworkAnalysis
        1. 对外连接
        2. 网卡列表
        3. hosts 记录

        # FileAnalysis
        1. /usr/bin 可执行文件
        2. /tmp 临时目录
        3. Webroot WebShell

        # BackdoorAnalysis
        1. LD_PRELOAD 系列变量
        2. PROMPT_COMMAND
        3. cron 计划任务
        4. alias 命令别名
        5. SSH 软链接与 wrapper
        6. /etc/inetd.conf
        7. /etc/xinetd.conf
        8. setuid 程序
        9. 系统启动项

        # LogAnalysis
        1. Apache 访问日志
        2. 登录成功/失败统计

        # Rookit
        1. rkhunter 检测

    ** 输出格式【必遵守】 **
        1. Markdown 表格呈现检测结果
        2. 紧随其后输出 "## 风险分析" 段落
        3. 追加 "## 建议措施" 段落，明确行动项

        示例：
        | 检测项 | 检测结果 | 风险等级 |
        |-------|---------|---------|
        | ...   | ...     | 高/中/低 |

        ## 风险分析
        详细说明风险来源与影响

        ## 建议措施
        1. 立即处置：...
        2. 加固措施：...
        3. 监控建议：...
""")


class SSHSession:
    """ SSH 链接对象管理，用于每次链接实例化数据 """

    def __init__(self, client):
        self.client = client

        # Hijack Analysis 模块 - 环境变量劫持排查
        self.hijack = False
        self.hijack_output = []
        self.hijack_list = []

        # User Analysis 模块 - 用户排查
        self.user_list = []
        self.group_list = {}

        # ProcAnalysis - 恶意进程排查
        self.ps = {}

        # NetAnalysis - 网络分析
        self.ip_list = ["127.0.0.1", "localhost", "0.0.0.0"]

        # FileAnalysis - 文件分析
        self.path = ''

        # LogAnalysis - 日志分析
        self.request_success = {}
        self.request_jump = {}
        self.request_others = {}
        self.user_agents = []

        # safeline 检测
        self.safeline_server = False


ssh_session = SSHSession(0)


def check_session():
    """ ssh_session 存活判断 """
    global ssh_session
    if ssh_session is None or ssh_session.client is None:
        return False
    try:
        ssh_session.client.exec_command('echo test', timeout=5)
        return True
    except Exception:
        return False


@mcp.tool()
def get_ssh_client(ip, port=22, username='root', password=''):
    """
    SSH 初始化连接工具
    用户必须在会话第一次使用时调用 SSH 初始化连接工具，才能使用其他远程排查工具。
    如果链接失败，则返回对话原因，并结束对话，链接成功则继续调用 check_safeline 。

    参数：
        ip：目标服务器IP地址
        port：SSH 登入端口 默认 22
        username：用户登入名，默认 root
        password：登入密码

    返回：
        # 当前连接状态，返回格式
        | 连接状态 | 返回内容 |
        |---------|---------|
        | ...     | ...     |
    """
    global ssh_session
    
    # 输入验证
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
def check_safeline():
    """
    在一次连接会话开始前，必须调用其检测是否存在雷池 safeline 存活服务，无论服务是否存活，提示完后继续运行。
    """
    ssh_session.safeline_server = check_safe_safeline('bash -i')
    if ssh_session.safeline_server:
        return '雷池 WAF 服务存活。。。'
    else:
        return '雷池 WAF 未存活，继续运行。。。'

#########################################
#
#  Hijack Analysis 模块 - 环境变量劫持排查
#
#########################################


def command_format(check, command):
    return 'env -i /usr/bin/' + command if check else command


def check_export(filename, data):
    try:
        export_list = re.findall(r'export (.*)=(.*)', data)
        for key, value in export_list:
            if key in ('PATH', 'LD_PRELOAD', 'LD_AOUT_PRELOAD', 'LD_ELF_PRELOAD', 'LD_LIBRARY_PATH', 'PROMPT_COMMAND') and value != '"$PATH:${snap_bin_path}"':
                ssh_session.hijack_list.append(f'[+] 环境变量劫持: {key}')
            ssh_session.hijack_output.append(f'filename: {filename}\texport {key}={value}\t[!] 环境变量劫持')
    except:
        pass


def process_files(file_list, base_path=''):
    for file in file_list:
        path = f'{base_path}{file}' if base_path else file
        command = command_format(ssh_session.hijack, f'cat {path}')
        result = exec_command(ssh_session.client, command)

        if result['status'] and result['result']:
            check_export(path, result['result'])


@mcp.tool()
def check_hijack():
    """
    系统环境变量劫持排查，检测系统环境变量是否被劫持。
    当检测到环境变量劫持且进行多项目排查时，继续进行排查可能会造成排查卡顿报错，需提前询问用户是否自愿继续排查。

    返回：
        ## 检测状态
        - 是否发现劫持：[是/否]

        ## 劫持详情（如有）
        | 文件路径 | 劫持变量 | 劫持内容 |
        |---------|---------|---------|
        | ...     | ...     | ...     |

        ## 风险分析
        [对发现的劫持进行安全分析]

        ## 建议措施
        [给出具体的修复建议]

        **重要提示**：如检测到劫持，继续排查可能导致系统卡顿，请询问用户是否继续。
    """

    if not check_session():
        return "错误：SSH连接未建立或已断开，请先调用 get_ssh_client 建立连接"

    # 常规目录环境变量排查
    common_files = ['/root/.bashrc', '/root/.tcshrc', '/root/.bash_profile', '/root/.cshrc', '/etc/bashrc', '/etc/profile', '/etc/csh.login', '/etc/csh.cshrc']
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
        hijack_user_list = [file['filename'] for file in get_file_list(home_dir_result['result']).values()]
        process_files([f'/home/{user}/{f}' for user in hijack_user_list for f in home_files])

    return '\n'.join(ssh_session.hijack_output)


#################################################################
#
#  User Analysis 模块 - 用户排查
#    1. 排查 home 下用户
#    2. 排查 /etc/passwd 下，拥有 shell 权限、root 权限、特殊权限的用户
#    3. 排查 /etc/shadow 下，空口令用户（无密码登录用户）
#    4. 排查 sudo 中权限异常用户
#    5. 排查 拥有 authorized_keys 免密登录用户
#
##################################################################


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


@mcp.tool()
def check_home():
    """
    home 目录用户排查，用于排查是否存在隐藏用户。

    返回（如有）：
        | 用户名 | / |
        |---------|-----------------|
        | ...     | home 目录存在用户 |

        # 风险分析
        [对发现的用户进行安全分析] 判断用户名是否可能是恶意的用户，例如 hack、H4ck、flag 等与黑客相关的词或变形

        # 建议措施
        [给出具体的修复建议]
    """

    if not check_session():
        return "错误：SSH连接未建立或已断开，请先调用 get_ssh_client 建立连接"

    result = exec_command(ssh_session.client, 'ls -al /home')
    if result['status'] and result['result']:
        ssh_session.user_list = [file['filename'] for file in list(get_file_list(result['result']).values())]
    return '\n'.join(ssh_session.user_list)

def check_home_nomcp():
    if not check_session():
        return "错误：SSH连接未建立或已断开，请先调用 get_ssh_client 建立连接"

    result = exec_command(ssh_session.client, 'ls -al /home')
    if result['status'] and result['result']:
        ssh_session.user_list = [file['filename'] for file in list(get_file_list(result['result']).values())]
    return '\n'.join(ssh_session.user_list)

@mcp.tool()
def check_history():
    """
    bash_history 排查，用于排查是否存在命令执行历史记录，黑客可能并未清理恶意执行的命令。

    返回（如有）：
        | bash_history 路径 | / |
        |---------|-----------------|
        | ...     | 存在历史命令记录文件 |

        # 建议措施
        [给出具体的修复建议]
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
    /etc/passwd 异常用户排查，排查用户是否拥有系统 shell，以及是否是 root 或 特权用户。

    返回（如有）：
        |  用户名 | 排查结果 |
        |---------|-----------------|
        | ...     | 用户拥有 shell / root用户 / 特权用户 |

        # 风险分析
        [对发现的用户及其权限进行安全分析] 判断用户其权限是否正常，例如：正常服务或用户为 nologin，且用户所在组不在 root 组中。

        # 建议措施
        [给出具体的修复建议]
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
    SSH authorized_keys 排查，排查是否存在恶意的 ssh 密钥后门。

    返回（如有）：
        | authorized_keys 路径 | / |
        |---------------------|--------------------|
        | ...                 | 存在 SSH 私钥登入文件 |

        # 风险分析
        [对发现的 SSH 私钥文件路径进行安全分析]，默认情况下不存在 SSH 私钥。

        # 建议措施
        [给出具体的修复建议]
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
    /etc/shadow 异常用户排查，排查是否存在空口令账户。

    返回（如有）：
        | 用户名 | / |
        |---------|-----------------|
        | ...     | 空口令账户 |

        # 风险分析
        [对发现的空口令账户进行安全分析]

        # 建议措施
        [给出具体的修复建议]
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
    sudo 用户权限排查，出现用户含有 ALL=(ALL) / ALL=(root)。

    返回（如有）：
        | 用户名 | / |
        |---------|-----------------|
        | ...     | sudo 权限组异常 |

        # 风险分析
        [对发现的异常用户组进行安全分析]

        # 建议措施
        [给出具体的修复建议]
    """

    if not check_session():
        return "错误：SSH连接未建立或已断开，请先调用 get_ssh_client 建立连接"

    result = exec_command(ssh_session.client, f'cat /etc/sudoers')
    output = []

    if result['status'] and result['result']:
        get_group()

        for line in result['result'].splitlines():
            line = line.strip()
            if ('ALL=(ALL)' in line or 'ALL=(root)' in line) and not line.startswith('#'):
                parts = line.split()
                if len(parts) > 0:
                    user_or_group = parts[0]

                    if user_or_group.startswith('%'):  # 组
                        group_name = user_or_group[1:]
                        users_in_group = ssh_session.group_list.get(group_name, [])
                        tmp = f'group: {group_name}\tuser: {", ".join(users_in_group)}'
                        output.append(f'{tmp}\t[!] sudo 权限组异常')
                    else:
                        tmp = f'{"user: " + user_or_group}'
                        output.append(f'{tmp}\t[!] sudo 权限组异常')

    return '\n'.join(output)


######################################
#
#  ProcAnalysis - 恶意进程排查
#    1.排查 恶意挖矿脚本
#    2.排查 恶意启动，恶意命令执行的进程
#    3.排查 隐藏pid
#    4.排查 被恶意替换命令名称的进程
#    5.排查 被恶意 mount 挂载的进程
#
#######################################

check_proc = json.load(open(os.path.join(base_dir, 'config\info_proc.json'), encoding='utf-8'))
privilege_escalation = ['aa-exec', 'ansible-playbook', 'ansible-test', 'aoss', 'apt-get', 'apt', 'ash', 'at', 'awk','aws', 'bash', 'batcat', 'bconsole', 'bundle', 'bundler', 'busctl', 'busybox', 'byebug', 'c89', 'c99', 'cabal', 'capsh', 'cdist', 'certbot', 'check_by_ssh', 'choom', 'cobc', 'composer', 'cowsay', 'cowthink', 'cpan', 'cpio', 'cpulimit', 'crash', 'csh', 'csvtool', 'dash', 'dc', 'debugfs', 'distcc', 'dmesg', 'docker', 'dotnet', 'dpkg', 'dstat', 'dvips', 'easy_install', 'eb', 'ed', 'elvish', 'emacs', 'enscript', 'env', 'ex', 'expect', 'facter', 'find', 'fish', 'flock', 'ftp', 'gawk', 'gcc', 'gcloud', 'gdb', 'gem', 'genie', 'ghc', 'ghci', 'gimp', 'ginsh', 'git', 'grc', 'gtester', 'hping3', 'iftop', 'ionice', 'irb', 'ispell', 'jjs', 'joe', 'journalctl', 'jrunscript', 'jtag', 'julia', 'knife', 'ksh', 'latex', 'latexmk', 'ld.so', 'less', 'lftp', 'loginctl', 'logsave', 'ltrace', 'lua', 'lualatex', 'luatex', 'mail', 'make', 'man', 'mawk', 'minicom', 'more', 'msfconsole', 'msgfilter', 'multitime', 'mysql', 'nano', 'nawk', 'ncdu', 'ncftp', 'neofetch', 'nice', 'nmap', 'node', 'nohup', 'npm', 'nroff', 'nsenter', 'octave', 'openvpn', 'pandoc', 'pdb', 'pdflatex', 'pdftex', 'perf', 'perl', 'perlbug', 'pexec', 'pg', 'php', 'pic', 'pico', 'pip', 'posh', 'pry', 'psftp', 'psql', 'puppet', 'pwsh', 'python', 'rake', 'rc', 'rlwrap', 'rpm', 'rpmdb', 'rpmquery', 'rpmverify', 'rsync', 'rtorrent', 'ruby', 'run-mailcap', 'run-parts', 'runscript', 'rview', 'rvim', 'sash', 'scanmem', 'scp', 'screen', 'script', 'scrot', 'sed', 'service', 'setarch', 'setlock', 'sftp', 'sg', 'slsh', 'smbclient', 'socat', 'softlimit', 'split', 'sqlite3', 'sqlmap', 'ssh-agent', 'ssh', 'sshpass', 'start-stop-daemon', 'stdbuf', 'strace', 'tar', 'task', 'taskset', 'tasksh', 'tclsh', 'tdbtool', 'telnet', 'tex', 'time', 'timedatectl', 'timeout', 'tmate', 'tmux', 'top', 'torify', 'torsocks', 'tshark', 'unshare', 'vagrant', 'valgrind', 'vi', 'view', 'vim', 'vimdiff', 'volatility', 'watch', 'wget', 'wish', 'xargs', 'xdg-user-dir', 'xdotool', 'xelatex', 'xetex', 'yarn', 'yash', 'zathura', 'zip', 'zsh', 'zypper']


def get_ps():
    """
    获取系统进程列表。
    """

    if not check_session():
        return "错误：SSH连接未建立或已断开，请先调用 get_ssh_client 建立连接"

    result = exec_command(ssh_session.client, 'ps -aux')

    if result['status'] and result['result']:
        for line in result['result'].splitlines()[1:]:
            try:
                parts = re.split(r'\s+', line.strip())
                if len(parts) >= 11:
                    pid = int(parts[1])
                    command = ' '.join(parts[10:])

                    exe = command.split()[0]
                    if ':' in exe:
                        exe = exe.split(':')[0]
                    elif '/' in exe:
                        exe = Path(exe).name
                    elif '(' in exe:
                        exe = exe[1:-1]

                    ssh_session.ps[pid] = {
                        'user': parts[0],
                        'cpu': float(parts[2]),
                        'mem': float(parts[3]),
                        'tty': parts[6],
                        'time': parts[9],
                        'command': ' '.join(parts[10:]),
                        'exe': exe}
            except:
                pass

    return f"已获取 {len(ssh_session.ps)} 个进程信息"

def get_ps_nomcp():
    if not check_session():
        return "错误：SSH连接未建立或已断开，请先调用 get_ssh_client 建立连接"

    result = exec_command(ssh_session.client, 'ps -aux')

    if result['status'] and result['result']:
        for line in result['result'].splitlines()[1:]:
            try:
                parts = re.split(r'\s+', line.strip())
                if len(parts) >= 11:
                    pid = int(parts[1])
                    command = ' '.join(parts[10:])

                    exe = command.split()[0]
                    if ':' in exe:
                        exe = exe.split(':')[0]
                    elif '/' in exe:
                        exe = Path(exe).name
                    elif '(' in exe:
                        exe = exe[1:-1]

                    ssh_session.ps[pid] = {
                        'user': parts[0],
                        'cpu': float(parts[2]),
                        'mem': float(parts[3]),
                        'tty': parts[6],
                        'time': parts[9],
                        'command': ' '.join(parts[10:]),
                        'exe': exe}
            except:
                pass

    return f"已获取 {len(ssh_session.ps)} 个进程信息"

@mcp.tool()
def check_mine():
    """
    挖矿脚本排查，判断逻辑：cpu / mem 超过 50%。

    返回（如有）：
        | PID | CPU | MEM | COMMAND |
        |-----|-----|-----|---------|
        | ... | ... | ... | ...     |

        # 建议措施
        [给出具体的修复建议]
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
    排查恶意执行的命令，例如虚拟命令、相对路径执行的文件、root 权限执行文件。

    返回（如有）：
        | 进程信息 | 排查结果          |
        |---------|-----------------|
        | ...     | ...             |

        # 风险分析
        [对发现的恶意进程进行安全分析]

        # 建议措施
        [给出具体的修复建议]
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
        if check_safe_local(command) or (ssh_session.safeline_server and check_safe_safeline(command)):
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
    隐藏的 PID 进程，黑客可能通过隐藏 PID 从而进行持久化攻击。

    返回（如有）：
        | PID | PATH |  / |
        |-----|---|---------------|
        | ... |---| 隐藏的 pid 进程 |

        # 风险分析
        [对发现的隐藏进程进行安全分析]

        # 建议措施
        [给出具体的修复建议]
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
        except:
            pass

    return output


@mcp.tool()
def check_exe():
    """
    命令替换排查 可能会有部分误判，黑客可能会通过替换执行命令，导致运行的进程和实际的运行文件并不相同，从而进行持久化攻击。

    返回（如有）：
        | PID | 正确的exe | 伪造的 exe |
        |-----|----------|----------|
        | ... | ...      | ...      |

        # 风险分析
        [对发现的替换的命令行安全分析]

        # 建议措施
        [给出具体的修复建议]
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
            except:
                pass

    return output


@mcp.tool()
def check_mount():
    """
    mount 挂载后门排查，黑客可能会通过 mount 进行挂载，隐藏 PID 以及进程，从而进行持久化攻击。

    返回：
        | path | / |
        |---------|---------------|
        | ...     | mount 挂载后门 |

        # 风险分析
        [对发现的 mount 挂载后门进行安全分析]

        # 建议措施
        [给出具体的修复建议]
    """

    if not check_session():
        return "错误：SSH连接未建立或已断开，请先调用 get_ssh_client 建立连接"

    output = ''

    result = exec_command(ssh_session.client, f'cat /proc/mounts')
    if result['status'] and result['result']:
        try:
            for pid in re.findall(r'/proc/(\d+)', result['result']):
                output += f'path: /proc/{pid}\t[!] mount 挂载后门\n'
        except:
            pass

    return output


######################################
#
# NetAnalysis - 网络分析
#
######################################


@mcp.tool()
def get_localhost():
    """ 获取远程服务器的本地 ip 地址 """

    if not check_session():
        return "错误：SSH连接未建立或已断开，请先调用 get_ssh_client 建立连接"

    result = exec_command(ssh_session.client, 'ip -4 addr show')

    if result['status'] and result['result']:
        for line in result['result'].splitlines():
            line = line.strip()
            if "inet" in line:
                try:
                    ip = re.split(r'\s+', line)[1].split('/')[0]
                    ssh_session.ip_list.append(ip)
                except:
                    pass

    return f"本地IP列表: {', '.join(ssh_session.ip_list)}"


@mcp.tool()
def check_network():
    """
    ss 排查，排查是否有恶意远程的连接。有些恶意外联使用同一网段本地测试，故保留同一网段的外连链接。

    返回（如有）：
        | Local | Remote | 排查结果 |
        |-------|-----------------|
        | ...   | ...    |...     |

        # 风险分析
        [对发现的外联远程和本地地址进行安全分析]

        # 建议措施
        [给出具体的修复建议]
    """

    if not check_session():
        return "错误：SSH连接未建立或已断开，请先调用 get_ssh_client 建立连接"

    output = []

    result = exec_command(ssh_session.client, 'ss -anutp')
    if result.get('status') and result.get('result'):
        for line in result['result'].splitlines()[1:]:
            try:
                parts = re.split(r'\s+', line.strip())
                if len(parts) >= 6:
                    local, remote, pid_program = parts[4], parts[5], parts[-1]
                    local_addr, local_port = local.rsplit(':', 1)
                    remote_addr, remote_port = remote.rsplit(':', 1)

                    if remote_addr not in ssh_session.ip_list and remote_port != "*":
                        output.append(
                            f'local :{local}\tremote :{remote}\tpid :{pid_program}\t[!] 发现远程连接')
                    elif local_port and local_port != "*":
                        output.append(
                            f'local :{local}\tremote :{remote}\tpid :{pid_program}\t[!] 发现开启端口')

            except:
                pass

    return '\n'.join(output)


@mcp.tool()
def check_eth():
    """
    网卡排查，建议用户进行 tcpdump -i any 或者使用 tcpdump -i 网卡 -w output.pcap 捕获流量，进一步分析。

    返回（如有）：
        | 网卡名称 | 网卡信息|
        |---------|-----------------|
        | ...     | ...             |
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
    hosts 排查，排查 DNS 是否被劫持，仅排除非本地 ipv4 的 hosts。

    返回（如有）：
        | ip | domain | \ |
        |---------|-----------------|
        | ...|... | 恶意 ip 解析域名|

        # 风险分析
        [对发现的可疑 ip 与域名进行安全分析]

        # 建议措施
        [给出具体的修复建议]"""

    if not check_session():
        return "错误：SSH连接未建立或已断开，请先调用 get_ssh_client 建立连接"

    output = ''

    result = exec_command(ssh_session.client, f'cat /etc/hosts')
    if result['status'] and result['result']:
        for line in result['result'].splitlines():
            line = line.strip()
            try:
                parts = re.split(r'\s+', line.strip())
                if parts and not parts[0].startswith('#'):
                    ip, *domains = parts
                    if ip and ip not in ssh_session.ip_list:
                        ssh_session.ip_list.append(ip)
                        output += f'ip: {ip}\tdomain: {"、".join(domains)}\t[!] 恶意 ip 解析域名\n'
            except:
                pass

    return output


#####################################
#
#  FileAnalysis - 恶意文件检测
#    1./usr/bin 检测
#    2.系统可执行文件扫描
#    3./tmp 临时目录文件扫描
#    4.用户目录文件扫描
#    5.可疑隐藏文件扫描
#    6.web root webshell 扫描
#
#################################

check_bin_json = json.load(open(os.path.join(base_dir, 'config\info_bin.json'), encoding='utf-8'))


def is_safe_path(basedir, path):
    try:
        parts = re.split(r'[\\/]+', path)
        for part in parts:
            if part.strip() == '.':
                return False
    except:
        return True
    return True


@mcp.tool()
def check_bin():
    """
    /usr/bin 排查，检测服务器的 bin 目录下命令是否被替换，排查并不准确，建议下载对应系统并参考 readme.md 使用 DumpFileInfo.py 进行 dump。

    返回：
        返回内容请构造列表并格式化输出给用户

        # 风险分析
        [对发现的可疑被替换文件进行安全分析]

        # 建议措施
        [给出具体的修复建议]
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
                if perm != check_bin_json[filename]['perm']:
                    check_out.append('权限异常')
                if owner != check_bin_json[filename]['owner'] or group != check_bin_json[filename]['group']:
                    check_out.append('所属异常')
                if link != check_bin_json[filename]['link']:
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

    return output


@mcp.tool()
def check_tmp():
    """
    /tmp 目录排查，tmp 目录可能存在黑客的残留文件。

    返回（如有）：
        | 文件路径 | / |
        |---------|-----------------|
        | ...     | tmp 目录文件文件 |

        # 风险分析
        [对发现的 tmp 目录文件名进行安全分析]

        # 建议措施
        [给出具体的修复建议]
    """

    if not check_session():
        return "错误：SSH连接未建立或已断开，请先调用 get_ssh_client 建立连接"

    output = ''
    result = exec_command(ssh_session.client, 'find /tmp -type f 2>/dev/null')
    if result['status'] and result['result']:
        output = ''.join(
            [f'file path: {item.strip()}\t[!] /tmp 目录下可疑文件\n' for item in result['result'].splitlines()])
    return output


@mcp.tool()
def check_webshell(path='/var/www/html'):
    """
    webroot webshell分析，通过对 web 服务进行 dump 到本地，并使用 exetension 扩展的河马查杀，对 web 服务代码进行 webshell 排查。

    参数：
        path：web 服务工作目录，默认为 /var/www/html

    返回（如有）：
        | 文件路径 | \ |
        |---------|-----------------|
        | ...     | 疑似 webshell 文件 |

        # 风险分析
        [对发现的 webroot 文件进行安全分析]

        # 建议措施
        [给出具体的修复建议]
    """

    if not check_session():
        return "错误：SSH连接未建立或已断开，请先调用 get_ssh_client 建立连接"

    output = ''
    if path.strip():
        path = path.strip()

    result = exec_command(ssh_session.client, f'find {path} -type f 2>/dev/null')
    if result['status'] and result['result']:
        exec_command(ssh_session.client, f'cd {path} && tar -zcvf /tmp/webroot.tar.gz .*')
        local_path = f'downloads\\{get_time_path()}'
        os.makedirs(local_path, exist_ok=True)
        sftp_download(ssh_session.client, '/tmp/webroot.tar.gz', f'{local_path}/webroot.tar.gz')

        with tarfile.open(f'{local_path}/webroot.tar.gz', 'r:gz') as tar:
            for member in tar.getmembers():
                member_path = os.path.join(local_path, member.name)
                if is_safe_path(local_path, member_path):
                    tar.extract(member, local_path)
                else:
                    server_path = path + '/' + member.name.replace('\\', '/')
                    output += f'file path: {server_path}\t[!] 路径遍历已拦截\n'
        result = subprocess.run([f'extensions\\HeMa\\hm.exe', 'scan', f'{local_path}'], capture_output=True, text=True, encoding='utf-8', errors='ignore')

        count = 0
        for line in result.stdout.splitlines():
            if "总计" in line:
                count = int(line.replace(' ', '').split('|')[-2])
        if count:
            with open(f"extensions\\HeMa\\result.csv", 'r', encoding='utf-8', errors='ignore') as csvfile:
                csv_reader = csv.reader(csvfile, delimiter=',')
                next(csv_reader, None)  # 跳过表头
                for row in csv_reader:
                    suggestion, file_path = row[1], row[2]
                    server_path = file_path.replace(local_path, path.strip()).replace('\\', '/')
                    output += f'file path: {server_path}\tmd5: {hashlib.md5(open(file_path, "rb").read()).hexdigest()}\t[!] 疑似 webshell 文件\n'
    return output





def get_files(directory):
    file_list = []
    result = exec_command(ssh_session.client, f'ls -al {directory}')
    if result and result.get('status') and result.get('result'):
        for file in get_file_list(result['result']).values():
            filename = file['filename']
            if '->' in filename:
                filename = filename.split(' -> ')[0]
            file_list.append(filename)
    return file_list


def check_malicious_content(file_path):
    output = ''
    result = exec_command(ssh_session.client, f'cat {file_path}')
    if result['status'] and result['result']:
        for line in result['result'].splitlines():
            if not line.startswith('#'):
                malicious_a = check_safe_local(line.strip())
                malicious_b = ''
                if ssh_session.safeline_server:
                    malicious_b = check_safe_safeline(line.strip())
                if malicious_a or malicious_b:
                    output += f'file: {file_path}\tcontent: {malicious_a + malicious_b}\t[!] 恶意命令执行\n'
    return output


@mcp.tool()
def check_ld_so_preload():
    """
    /etc/ld.so.preload 后门排查，黑客可能通过写入 ld.so.preload 进行持久化攻击。

    返回：
        # 风险分析
        [对发现的 ld.so.preload 后门进行安全分析]

        # 建议措施
        [给出具体的修复建议]
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

    return output


@mcp.tool()
def check_cron():
    """
    计划任务后门排查，黑客可能会通过写入计划任务从而进行持久化攻击，排查基于雷池 WAF 拦截，可能并不准确，建议重点关注包含 bash 片段。

    返回（如有）：
        | 文件路径 | 恶意内容 |
        |---------|--------|
        | ...     | ...    |

        # 风险分析
        [对发现的计划任务后门进行安全分析]

        # 建议措施
        [给出具体的修复建议]
    """

    if not check_session():
        return "错误：SSH连接未建立或已断开，请先调用 get_ssh_client 建立连接"

    output = ''

    cron_dirs = ['/var/spool/cron', '/etc/cron.d', '/etc/cron.daily', '/etc/cron.weekly', '/etc/cron.hourly', '/etc/cron.monthly']

    for cron_dir in cron_dirs:
        for file in get_files(cron_dir):
            output += check_malicious_content(f'{cron_dir}/{file}')

    return output


@mcp.tool()
def check_ssh():
    """
    /usr/sbin/sshd 软连接后门排查，黑客可能通过 sshd 软连接创建后门。

    返回（如有）：
        # 风险分析
        [对发现的劫持进行安全分析]

        # 建议措施
        [给出具体的修复建议]
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
    /usr/sbin/sshd ssh wrapper 后门，排查排查基于雷池 WAF 拦截，可能并不准确，建议重点关注包含 bash 片段。

    返回（如有）：
        | 文件路径 | 恶意内容 |
        |---------|--------|
        | ...     | ...    |

        # 风险分析
        [对发现的后门进行安全分析]

        # 建议措施
        [给出具体的修复建议]
    """

    if not check_session():
        return "错误：SSH连接未建立或已断开，请先调用 get_ssh_client 建立连接"

    output = ''

    result = exec_command(ssh_session.client, 'strings /usr/sbin/sshd')
    if result['status'] and result['result']:
        for line in result['result'].splitlines():
            malicious_a = check_safe_local(line.strip())
            malicious_b = ''
            if ssh_session.safeline_server:
                malicious_b = check_safe_safeline(line.strip())
            if malicious_a or malicious_b:
                if '\033' in malicious_a + malicious_b:
                    output += f'file: {"/usr/sbin/sshd"}\tcontent: {malicious_a + malicious_b}\t[!] 恶意 shell 命令\n'
                else:
                    output += f'file: {"/usr/sbin/sshd"}\tcontent: {malicious_a + malicious_b}\t[!] ssh wrapper 劫持\n'

    return output


@mcp.tool()
def check_inetd():
    """
    /etc/inetd.conf 后门排查

    返回（如有）：
        | 文件路径 | 恶意内容 |
        |---------|--------|
        | ...     | ...    |

        # 风险分析
        [对发现的 inetd.conf 后门进行安全分析]

        # 建议措施
        [给出具体的修复建议]
    """

    if not check_session():
        return "错误：SSH连接未建立或已断开，请先调用 get_ssh_client 建立连接"

    output = check_malicious_content('/etc/inetd.conf')
    return output


@mcp.tool()
def check_xinetd():
    """xinetd 后门排查

    返回（如有）：
        | 文件路径 | 恶意内容 |
        |---------|--------|
        | ...     | ...    |

        # 风险分析
        [对发现的 xinetd 后门进行安全分析]

        # 建议措施
        [给出具体的修复建议]
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
    SUID 后门排查（当前正在运行的程序中），黑客可能通过此方法进行 SUID 提权，获取 root 用户权限，或者进行了持久化攻击。

    返回（如有）：
        | SUID 命令 | 恶意内容 |
        |---------|--------|
        | ...     | ...    |

        # 风险分析
        [对发现的 SUID 进行安全分析]

        # 建议措施
        [给出具体的修复建议]
    """

    if not check_session():
        return "错误：SSH连接未建立或已断开，请先调用 get_ssh_client 建立连接"

    output = ''

    result = exec_command(ssh_session.client, "find / ! -path '/proc/*' -type f -perm -4000 2>/dev/null")
    if result['status'] and result['result']:
        for line in result['result'].splitlines():
            output += f'command {line.strip()}\t[!] SUID 后门\n'

    return output


@mcp.tool()
def check_startup():
    """
    系统启动项排查，排查基于雷池 WAF 拦截，可能并不准确，建议重点关注包含 bash 片段。

    返回（如有）：
        | 文件路径 | 恶意内容 |
        |---------|--------|
        | ...     | ...    |

        # 风险分析
        [对发现的启动项进行安全分析]

        # 建议措施
        [给出具体的修复建议]
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

    return output


@mcp.tool()
def check_profile():
    """
    /etc/profile.d 后门排查，排查基于雷池 WAF 拦截，可能并不准确，建议重点关注包含 bash 片段。

    返回（如有）：
        | 文件路径 | 恶意内容 |
        |---------|--------|
        | ...     | ...    |

        # 风险分析
        [对发现的 profiled.d 后门进行安全分析]

        # 建议措施
        [给出具体的修复建议]
    """

    if not check_session():
        return "错误：SSH连接未建立或已断开，请先调用 get_ssh_client 建立连接"

    output = ''

    for file in get_files('/etc/profile.d'):
        output += check_malicious_content(f'/etc/profile.d/{file}')

    return output


@mcp.tool()
def check_rc():
    """
    bashrc 等初始化 shell 脚本排查，排查基于雷池 WAF 拦截，可能并不准确，建议重点关注包含 bash 片段。

    返回（如有）：
        | 文件路径 | 恶意内容 |
        |---------|--------|
        | ...     | ...    |

        # 风险分析
        [对发现的 bashrc 等初始化 shell 脚本后门进行安全分析]

        # 建议措施
        [给出具体的修复建议]
    """

    if not check_session():
        return "错误：SSH连接未建立或已断开，请先调用 get_ssh_client 建立连接"

    output = ''

    init_paths = ['/root/.bashrc', '/root/.tcshrc', '/root/.bash_profile', '/root/.cshrc', '/etc/bashrc',
                  '/etc/profile', '/etc/csh.login', '/etc/csh.cshrc']
    init_files = ['.bashrc', '.bash_profile', '.tcshrc', '.cshrc']

    for path in init_paths:
        output += check_malicious_content(path)

    user_list = []
    home_dir_result = exec_command(ssh_session.client, 'ls -al /home')
    if home_dir_result['status'] and home_dir_result['result']:
        user_list = [file['filename'] for file in get_file_list(home_dir_result['result']).values()]

    for user in user_list:
        for file in init_files:
            output += check_malicious_content(f'/home/{user}/{file}')

    return output


###############################
#
# LogAnalysis - 日志分析
#
###############################

pattern = re.compile(
    r'(?P<ip>\S+) \S+ \S+ '
    r'\[(?P<time>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+) (?P<protocol>\S+)" '
    r'(?P<status>\d{3}) (?P<size>\d+) '
    r'"(?P<referer>[^"]*)" '
    r'"(?P<user_agent>[^"]*)"'
)


@mcp.tool()
def check_log(path='/var/log/apache2/access.log'):
    """
    apache2 日志分析（其他日志可能会产生报错），通过转发请求给雷池，判断内容是否恶意。

    参数：
        path：apache2 日志路径，默认为 /var/log/apache2/access.log

    返回（如有）：
        根据排查结果，进行构造多个列表，清晰直观的给用户 apache2 日志分析的结果

        # 风险分析
        [对发现的恶意请求内容进行安全分析]

        # 建议措施
        [给出具体的修复建议]
    """

    if not check_session():
        return "错误：SSH连接未建立或已断开，请先调用 get_ssh_client 建立连接"

    output = ''

    result = exec_command(ssh_session.client, f'cat {path}')
    if result['status'] and result['result']:
        access_log = result['result'].splitlines()
        for line in access_log:
            result_a = check_safe_local(line.strip())
            result_b = check_safe_safeline(line.strip())
            if result_a or result_b:
                output += f'url: {urllib.parse.unquote(line.strip())}\t[!] 恶意请求\n'


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
    服务器远程登入成功日志排查

    返回（如有）：
        | 登入 IP | 尝试登入次数 |
        |---------|-----------|
        | ...     | ...       |

        # 风险分析
        [对发现的恶意登入（成功）进行安全分析]

        # 建议措施
        [给出具体的修复建议]
    """

    if not check_session():
        return "错误：SSH连接未建立或已断开，请先调用 get_ssh_client 建立连接"

    output = ''
    login_success = {}

    result = exec_command(ssh_session.client, 'last')

    if result['status'] and result['result']:
        for line in result['result'].splitlines():
            line = line.strip()
            try:
                parts = re.split(r'\s+', line)
                if len(parts) >= 3:
                    ip = parts[2]
                    if ip in login_success:
                        login_success[ip] += 1
                    else:
                        login_success[ip] = 1
            except:
                pass

    for ip, count in login_success.items():
        if '.' in ip:
            output += f'ip: {ip}\tcount: {count}\t[!] 爆破登入 IP\n'

    return output


@mcp.tool()
def check_login_fail():
    """
    服务器远程登入失败日志排查

    返回（如有）：
        | 登入 IP | 尝试登入次数 |
        |---------|-----------|
        | ...     | ...       |

        # 风险分析
        [对发现的恶意登入（失败）进行安全分析]

        # 建议措施
        [给出具体的修复建议]
    """

    if not check_session():
        return "错误：SSH连接未建立或已断开，请先调用 get_ssh_client 建立连接"

    output = ''
    login_fail = {}

    result = exec_command(ssh_session.client, 'lastb')
    if result['status'] and result['result']:
        for line in result['result'].splitlines():
            line = line.strip()
            try:
                parts = re.split(r'\s+', line)
                if len(parts) >= 3:
                    ip = parts[2]
                    if ip in login_fail:
                        login_fail[ip] += 1
                    else:
                        login_fail[ip] = 1
            except:
                pass

    for ip, count in login_fail.items():
        if '.' in ip:
            output += f'ip: {ip}\tcount: {count}\t[!] 爆破登入 IP\n'

    return output


@mcp.tool()
def RookitUpload():
    """
    rookit 检测，通过 Rookit 上传并执行检测，上传并安装后，需要用户手动执行（信息过多，直接执行便于查看）
    """

    if not check_session():
        return "错误：SSH连接未建立或已断开，请先调用 get_ssh_client 建立连接"

    sftp_upload(ssh_session.client, 'extensions/rkhunter.gz', '/tmp/rkhunter.gz')
    result = exec_command(ssh_session.client,'cd /tmp && tar -xf /tmp/rkhunter.gz && cd /tmp/rkhunter-1.4.6 && bash installer.sh --install')

    if result['status'] and result['result']:
        if "complete" in result['result']:
            return f'[success] rkhunter rookit检测工具上传安装成功，需要用户手动执行命令 rkhunter --check'

    return '上传失败'


if __name__ == "__main__":
    mcp.run()
