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
    # 系统角色说明
    你是“AutoIR_MCP”，一个具备多模块自动化应急响应能力的智能助手。  

    ## 操作规则（必须遵守）
    1. **首次操作必须执行** `get_ssh_client(ip, username, password)`  
       - 建立 SSH 连接并缓存连接句柄。
       - 若连接失败，返回错误提示。
    2. **连接成功后立即执行** `check_safeline`  
       - 检查雷池（SafeLine WAF）是否运行。
    3. **若任意工具执行时报连接错误** → 自动或提示重新执行 `get_ssh_client`。
    4. 相同连接参数会自动复用，请勿重复创建连接。

    ## 模块结构（按逻辑依赖顺序执行）
    每个模块可单独调用，也可按顺序全量巡检，巡检要求每个模块内巡检子工具。
    | 模块 | 工具函数 | 功能描述 |
    |------|-----------|-----------|
    | 1 | ijackAnalysis | 检查环境变量劫持 |
    | 2 | UserAnalysis | 用户与授权异常 |
    | 3 | ProcAnalysis | 恶意或隐藏进程 |
    | 4 | NetworkAnalysis | 网络异常与外联行为 |
    | 5 | FileAnalysis | 可疑文件与 WebShell |
    | 6 | BackdoorAnalysis | 后门与持久化机制 |
    | 7 | LogAnalysis | 登录与访问日志分析 |
    | 8 | Rookit | Rootkit 检测 |

    ## 调用逻辑（决策树）
    - 用户明确提到 “SSH 连接”、“目标主机” → 调用 `get_ssh_client`
    - 用户提到 “WAF”、“雷池” → 调用 `check_safeline`
    - 用户提到 “后门”、“计划任务”、“LD_PRELOAD” → 调用 `BackdoorAnalysis` 内的子工具
    - 用户提到 “用户”、“sudo”、“shadow” → 调用 `UserAnalysis` 内的子工具
    - 用户提到 “挖矿”、“异常进程”、“命令执行” → 调用 `ProcAnalysis` 内的子工具
    - 用户提到 “网络连接”、“外联”、“hosts” → 调用 `NetworkAnalysis` 内的子工具
    - 用户提到 “文件”、“webshell”、“/tmp” → 调用 `FileAnalysis` 内的子工具
    - 用户提到 “日志”、“登录记录”、“访问日志” → 调用 `LogAnalysis` 内的子工具
    - 用户提到 “rootkit”、“内核劫持” → 调用 `Rookit` 内的子工具

    ## 决策逻辑（必须遵守）
    若用户未指定模块，自行决策，优先对用户提出的内容进行问题分解，调用最可能需要的工具.
    如果存在可疑内容，但没分析出需要的结果时，应当检查是否有工具最有能进行进一步分析，进行多工具调用（禁止重复调用一个工具两次）。
    如果分析出对应问题的结果，则停止调用，给出分析结果，避免冗杂分析。
    若用户未提出任何需求，仅提供 SSH 连接信息，则按上述模块顺序全量执行巡检。

    ## 输出要求（强制格式）
    检测报告必须使用以下模板格式输出（可根据代码输出结果进行增加删减列表的标题和内容，仅要求是列表）：
    | 检测项 | 检测结果 | 风险等级 |
    |--------|-----------|-----------|
    | 示例：LD_PRELOAD 环境变量 | 检测到恶意注入路径 `/usr/lib/.libhack.so` | 高 |

    ### ## 风险分析，要求 AI 根据结果结合问题分析，请勿直接根据提供的工具提供的案例进行风险分析。
    描述检测项的危害来源、利用方式及潜在影响。

    ### ## 建议措施，要求 AI 根据结果结合问题分析，请勿直接根据提供的工具提供的案例进行风险分析。
    示例：
    1. **立即处置：** 指出可执行的快速修复操作。  
    2. **加固措施：** 提供安全策略或配置加固方法。  
    3. **监控建议：** 建议后续监控指标或检测策略。

    ## 输出风格
    - 使用简明、专业的安全分析语言；
    - 输出内容 **以检测表格 + 分析说明** 为主；
    - 若模块无异常，仍需返回结构化表格并标明“未发现异常”。
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
    用于建立与目标主机的 SSH 会话，其他远程排查工具依赖此连接。
    第一次使用前必须调用本函数，连接成功后将自动调用 check_safeline。
    若连接失败，返回失败原因并终止后续分析。

    参数：
        ip：目标服务器 IP 地址
        port：SSH 登入端口（默认 22）
        username：登入用户名（默认 root）
        password：登入密码

    返回：
        | 连接状态 | 返回内容 |
        |-----------|-----------|
        | 成功/失败 | 详细说明 |
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
    雷池 WAF 存活检测工具
    在每次连接建立后应立即调用，用于检测目标主机是否运行雷池（SafeLine）WAF 服务。
    无论检测结果如何，必须提示状态，再继续执行后续分析流程。
    """
    ssh_session.safeline_server = check_safe_safeline('bash -i')
    if ssh_session.safeline_server:
        return '雷池 WAF 服务存活。。。'
    else:
        return '雷池 WAF 未存活，继续运行。。。'


def command_format(check, command):
    return 'env -i /usr/bin/' + command if check else command


def check_export(filename, data):
    try:
        export_list = re.findall(r'export (.*)=(.*)', data)
        for key, value in export_list:
            if key in ('PATH', 'LD_PRELOAD', 'LD_AOUT_PRELOAD', 'LD_ELF_PRELOAD', 'LD_LIBRARY_PATH',
                       'PROMPT_COMMAND') and value != '"$PATH:${snap_bin_path}"':
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
    """"
    环境变量劫持排查工具（HijackAnalysis 模块子工具）

    原理：
        遍历系统及用户 shell 初始化脚本（如 .bashrc、/etc/profile 等），
        检查是否存在异常 export 或环境变量注入，用于识别环境变量是否被恶意修改或利用。

    返回：
        ## 检测状态
        - 是否发现可疑劫持：[是 / 否]

        ## 劫持详情（如有）
        | 文件路径 | 劫持变量 | 劫持内容 |
        |-----------|-----------|-----------|
        | ...       | ...       | ...       |
    
        # AI 自主分析判断，以下为参考示例：
        
        ## 智能分析
        - 该文件路径是否可能存在此变量名称
        - 是否存在恶意劫持（如变量名、路径或内容中包含恶意特征：LD_PRELOAD、/tmp/、wget、curl、python、反弹 shell 等）
        - 劫持内容是否可被用于命令注入、持久化、环境污染或后门执行
        - 若无明显恶意行为，应分析是否为系统自定义变量或合法初始化脚本

        ## 建议措施
        - 若 AI 判断存在恶意行为，应自动生成针对性的修复建议；
        - 若判断为正常行为，仅提示「未发现明显异常」；
        - 建议示例：
            1. 删除或还原被篡改文件；
            2. 检查启动项与 PATH 是否包含异常路径；
            3. 验证关键命令完整性（md5sum /usr/bin/ls 等）；
            4. 重新加载或重启相关进程验证修复结果。

    注意：
        - 检测到可疑内容时，继续排查可能造成系统卡顿；
        - 应提示用户确认后再执行多模块分析。
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
        hijack_user_list = [file['filename'] for file in get_file_list(home_dir_result['result']).values()]
        process_files([f'/home/{user}/{f}' for user in hijack_user_list for f in home_files])

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


@mcp.tool()
def check_home():
    """
    Home 目录用户排查工具（UserAnalysis 模块子工具）

    原理：
        通过列举 /home 目录下的所有用户目录，检测是否存在异常命名用户、
        隐藏用户目录或未登记账户，以判断系统是否被潜在入侵或滥用。

    调用说明：
        - 多工具调用，根据 建议措施 输出的推荐工具进行调用；

    返回：
        ## 检测结果
        - 列出 /home 下的所有用户目录；
        - 标识可能存在的可疑账户（由 AI 自主判断是否恶意）。
        - AI 应基于检测结果判断用户是否可能为恶意账户，并给出优先级排序。

        | 用户名 | 状态说明 |
        |---------|----------|
        | user1   | 正常用户 |
        | hack123 | 可疑用户名，疑似黑客账户 |
        | .hidden | 隐藏用户目录，需进一步核查 |

        # AI 自主分析判断，以下为参考示例：

        ## 智能分析
        - 用户名是否存在黑客特征词（如 hack、H4ck、flag、test、tmp、backdoor 等）；
        - 是否存在隐藏用户目录（以 . 开头）；
        - 是否存在随机无意义命名（如 zxc123、tmpuser、xxoo）；
        - 结合用户数量与命名规律，判断是否存在异常账户添加行为；
        - 若发现异常，应分析其可能来源（如渗透后添加账户、恶意脚本自动创建等）。

        ## 建议措施，根据用户需求 AI 自行决策。
        - 删除或禁用未授权用户账户；
        - 核查 `/etc/passwd`、`/etc/shadow`、 `/etc/sudoers` 是否有对应条目，且权限是否异常，即调用 check_passwd、check_shadow、check_sudoer 排查；
        - 检查登录日志 `/var/log/secure`、`/var/log/auth.log` 及 `lastlog` 记录，即调用 check_login_success、check_login_fail 排查；
        - 若发现可疑账户，立即审计其目录文件（特别是 .ssh、.bash_history）,即调用 check_ssh_keys、check_history 排查；
        - 若为合法运维账户，应登记并设置强密码策略。
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
    bash_history 文件存在性排查工具（UserAnalysis 模块子工具）

    原理：
        检查 root 用户及 /home 下所有用户是否存在 .bash_history 文件，
        用于判断是否存在命令历史记录文件，供后续分析或审计使用。

    调用说明：
        - 可结合 check_home 输出的用户列表批量检查；
        - 当前功能仅检测文件是否存在，不分析具体命令内容。

    返回：
        ## 检测结果
        - 列出所有存在的 bash_history 文件路径；
        - 可由 AI 或后续工具对历史记录内容进一步分析。

        | 用户 | bash_history 路径 | 状态说明 |
        |------|-----------------|----------|
        | root | /root/.bash_history | 存在 |
        | user1 | /home/user1/.bash_history | 存在 |

        # AI 自主分析判断，以下为参考示例：

        ## 智能分析
            - 若文件存在，AI 可提示该用户可能有操作记录；
            - 无文件则提示“无历史记录文件”；
            - 不重复调用的情况下结合其他模块（如 check_home、check_hijack）可进一步判断用户是否异常。

        ## 建议措施
            - 如需要审计历史命令，可使用其他工具或手动查看文件内容；
            - 清理或备份历史记录文件视运维策略而定；
            - 结合用户权限和登录日志分析是否存在异常操作。
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
    /etc/passwd 用户权限排查工具（UserAnalysis 模块子工具）

    原理：
        解析 /etc/passwd 文件，检测用户是否拥有系统 shell，
        是否是 root 或特权用户，并判断其权限是否符合安全规范。

    调用说明：
        - 可结合 check_home 输出的用户列表和 check_sudoer 检查进一步分析用户权限风险；
        - AI 根据检测结果自主判断用户是否异常，并给出风险分析和建议措施。

    返回：
        ## 检测结果
        - 列出存在异常 shell 权限、root UID 或特权组的用户；
        - 输出示例：

        | 用户名 | shell | 异常权限说明 | 风险等级 |
        |--------|-------|--------------|----------|
        | testuser | /bin/bash | 拥有系统 shell | 中 |
        | hacker  | /bin/sh   | root 标识用户 | 高 |
        | svc     | /bin/bash | 特权用户 | 中 |

        # AI 自主分析判断，以下为参考示例：
        
        ## 智能分析
            - 用户是否存在异常 shell 权限（如非 nologin 却可登录）；
            - 用户是否为 root UID 或特权组成员；
            - 是否可能为未授权用户、渗透痕迹或误配置账户；
            - 若权限正常且为系统或服务用户，则标记为低风险。

        ## 建议措施
            - 禁用或修改异常 shell 用户，设置为 nologin 或指定安全 shell；
            - 审查 root 或特权用户，确认其合法性；
            - 核查 sudo 权限（可调用 check_sudoer）；
            - 对可疑用户进行登录日志和历史操作审计（结合 check_history）。
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
    SSH authorized_keys 排查工具（UserAnalysis 模块子工具）

    原理：
        检查 root 用户及 /home 下所有用户的 ~/.ssh/authorized_keys 文件，
        用于判断是否存在潜在的 SSH 后门或未授权密钥。

    调用说明：
        - 可结合 check_home 输出的用户列表批量检查；
        - AI 根据检测结果自主判断是否存在异常或可疑密钥，并输出风险等级。

    返回：
        ## 检测结果
        - 列出所有存在的 authorized_keys 文件路径及用户；
        - 标识可能存在的可疑密钥。

        | 用户 | authorized_keys 路径 | 检测结果 | 风险等级 |
        |------|---------------------|-----------|----------|
        | root | /root/.ssh/authorized_keys | 存在 SSH 密钥 | 高 |
        | user1 | /home/user1/.ssh/authorized_keys | 存在 SSH 密钥 | 中 |

        # AI 自主分析判断，以下为参考示例：

        ## 智能分析
            - 是否存在非预期的 SSH 密钥；
            - 密钥是否属于未知来源用户；
            - 是否可能用于远程后门或横向渗透；
            - 若所有密钥均属于合法运维账户，则标记为低风险。

        ## 建议措施
            - 审查 authorized_keys 文件中密钥来源和用途；
            - 删除或禁用非授权密钥；
            - 对重要用户启用多因素认证或强密码策略；
            - 可结合 check_home、check_history、check_passwd 等模块综合判断主机安全状态。
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
    /etc/shadow 空口令账户排查工具（UserAnalysis 模块子工具）

    原理：
        检查 /etc/shadow 文件中是否存在空密码账户，
        用于判断系统是否存在未授权或弱口令用户。

    调用说明：
        - 可结合 check_home、check_passwd 等模块综合分析用户安全状态；
        - AI 根据检测结果自主判断风险等级。

    返回：
        ## 检测结果
        - 列出存在空口令的用户账户；
        - 示例：

        | 用户名 | 状态说明 | 风险等级 |
        |--------|---------|----------|
        | testuser | 空口令账户 | 高 |
        | demo    | 空口令账户 | 中 |

        # AI 自主分析判断，以下为参考示例：

        ## 智能分析
            - 空口令账户可能被未经授权使用；
            - 高风险用户可能为渗透痕迹或临时创建账户；
            - 若为空口令的账户为系统或服务用户，可标记为中/低风险。

        ## 建议措施
            - 禁用或修改空口令账户，设置强密码；
            - 核查对应用户权限和登录日志；
            - 可结合 check_passwd、check_sudoer、check_login_success/fail 进一步分析；
            - 若为空口令的账户非必要，建议删除或禁用。
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
    sudo 权限排查工具（UserAnalysis 模块子工具）

    原理：
        检查 /etc/sudoers 文件及相关组成员，识别具有 ALL=(ALL) 或 ALL=(root) 权限的用户或组，
        用于判断系统是否存在高权限异常用户或滥用 sudo 权限。

    调用说明：
        - 可结合 check_passwd、check_shadow、check_home 等模块综合分析用户安全状态；
        - AI 根据检测结果自主判断风险等级。

    返回：
        ## 检测结果
        - 列出所有异常 sudo 权限的用户或组及其成员；
        - 示例：

        | 类型 | 用户/组 | 成员列表 | 风险等级 |
        |------|---------|----------|----------|
        | user | alice   | -        | 高 |
        | group | admin  | bob, tom | 高 |

        # AI 自主分析判断，以下为参考示例：

        ## 智能分析
            - 用户或组是否拥有过高 sudo 权限；
            - 是否存在未授权账户或服务用户被误赋 sudo 权限；
            - 高风险用户可能被用于提权或渗透活动；
            - 合法运维账户应标记为低风险。

        ## 建议措施
            - 移除或限制非必要 sudo 权限；
            - 审查组成员及权限来源；
            - 可结合 check_passwd、check_shadow、check_home、check_login_success/fail 进一步分析账户安全；
            - 对高风险账户进行密码审计或多因素认证。
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


check_proc = json.load(open(os.path.join(base_dir, 'config\info_proc.json'), encoding='utf-8'))
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


@mcp.tool()
def get_ps():
    """
    系统进程列表获取工具（ProcAnalysis 模块基础）

    原理：
        通过执行 `ps -aux` 获取目标主机所有运行进程。
        提取 PID、用户、CPU/内存占用、TTY、运行时间、完整命令和可执行文件名，
        为后续恶意进程检测、挖矿、命令替换和异常挂载分析提供基础数据。

    调用说明：
        - 数据存储在 ssh_session.ps 字典中，格式：
            { PID: {'user': ..., 'cpu': ..., 'mem': ..., 'tty': ..., 'time': ..., 'command': ..., 'exe': ...} }
        - 可结合 ProcAnalysis 模块的其他工具进行：
            1. check_mine：恶意挖矿脚本检测
            2. check_exec: 恶意执行排查
            3. check_pid: PID 隐藏排查
            4. check_exe：命令名称被替换检测
            5. check_mount：异常 mount 挂载检测

    返回：
        - 获取成功时，返回已获取进程数量；
        - 示例：
            "已获取 153 个进程信息"

        智能分析（可选）：
            - AI 可根据进程 CPU/内存占用、命令特征、路径信息判断进程风险等级；
            - 为 ProcAnalysis 其他模块提供基础数据。
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
    挖矿进程排查工具（ProcAnalysis 模块子工具）

    原理：
        遍历系统进程列表，检测 CPU 或内存占用超过 50% 的进程，
        判断其是否可能为恶意挖矿脚本或高负载异常进程。

    调用说明：
        - 推荐先调用 get_ps 获取最新进程列表；
        - 可结合 ProcAnalysis 其他模块进行综合分析；
        - AI 根据进程占用和命令特征自主判断风险等级。

    返回：
        ## 检测结果
        - 列出疑似挖矿的进程：

        | PID  | 用户 | CPU(%) | MEM(%) | COMMAND | 风险等级 |
        |------|------|--------|--------|---------|----------|
        | 1234 | root | 78.5   | 65.2   | ./xmrig | 高       |
        | 5678 | alice| 52.3   | 51.0   | python3 miner.py | 高 |

        # AI 自主分析判断，以下为参考示例：
        
        ## 智能分析
            - CPU/内存占用高且命令可疑者，AI 自动标记为高风险；
            - 若命令为常见系统服务或运维脚本，可标记为低/中风险；
            - 可结合历史记录或 ps 输出路径进一步分析进程来源。

        ## 建议措施
            - 立即终止高风险进程；
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
    恶意命令执行排查工具（ProcAnalysis 模块子工具）

    原理：
        遍历已获取的系统进程列表，识别疑似通过非常规方式执行的命令，
        包括虚拟终端执行、相对路径执行、root 权限执行的可疑命令，以及基于安全策略或 WAF 判断的可疑命令执行痕迹。

    调用说明：
        - 推荐先调用 get_ps 获取最新进程列表；
        - 可结合 check_mine、check_hijack、check_history、check_startup 等模块进行综合分析；

    返回：
        - 列出疑似由非常规方式执行或具有可疑执行特征的进程信息，示例输出：
        | 进程 PID | 用户 | TTY | COMMAND | 可疑原因 |
        |----------|------|-----|---------|----------|
        | 1234     | root | ?   | ./run   | 通过相对路径运行, 疑似命令执行 |

        # AI 自主分析判断，以下为参考示例：

        智能分析：
            - AI 应基于 tty、命令是否包含相对路径（"./"）、执行用户（如 root）与命令特征判断可疑程度；

        建议措施：
            - 对高风险项建议立即审计对应可执行文件的路径与文件内容；
            - 若确认恶意，终止该进程并隔离可执行文件以便取证；
            - 检查该命令的启动来源（cron、systemd、init 脚本、用户 shell 等）并清除持久化项；
            - 将可疑条目与 check_history、check_hijack、check_startup 模块输出关联分析以定位入侵痕迹。
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
    隐藏 PID 进程排查工具（ProcAnalysis 模块子工具）

    原理：
        列举 /proc 下的进程 ID，并与已获取的进程列表（ssh_session.ps）比对。
        若 /proc 中存在但 ssh_session.ps 中不存在的 PID，可能表示进程被隐藏或被内核/工具以非常规方式运行，
        需要进一步核查 /proc/<pid>/cmdline、/proc/<pid>/exe 等信息以判断可疑程度。

    调用说明：
        - 执行前应先调用 get_ps 获取并填充 ssh_session.ps（进程快照）；
        - 本工具会尝试读取 /proc/<pid>/cmdline（若可读）以获取命令行信息用于分析。

    返回：
        - 以 Markdown 表格返回发现的可疑 PID 列表（若无则返回“未发现隐藏 PID”）：

        | PID | CMDLINE | 说明 |
        |-----|---------|------|
        | 1234 | /usr/bin/... | /proc/1234 存在但未出现在 ps -aux 输出中 |

        # AI 自主分析判断，以下为参考示例：
        智能分析：
            - AI 可基于 cmdline、exe 路径、进程用户（若可获）判断是否为隐藏或内核模块伪装进程；
            - 若无法读取 cmdline（权限或已被清空），应提高可疑等级并建议进一步取证（lsof、gdb、dump 等）。

        建议措施：
            - 对可疑 PID 进行取证（cat /proc/<pid>/cmdline, readlink /proc/<pid>/exe, ls -l /proc/<pid>）；
            - 若确认恶意，先采集证据（拷贝可执行文件、进程内存转储），再终止进程并隔离样本；
            - 检查启动项、内核模块与异常挂载，结合 check_hijack、check_mount、check_startup 等模块综合分析。
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
    命令替换排查工具（ProcAnalysis 模块子工具）

    原理：
        检查 /proc/*/exe 的实际指向与 ps 快照中记录的 exe 字段是否一致。
        黑客可能通过替换可执行文件、软连接或伪造路径使运行中的进程名与实际可执行文件不一致，
        以达到隐藏、持久化或提权目的。

    调用说明：
        - 先调用 get_ps 获取进程快照；
        - 本工具会读取 /proc/*/exe 的指向并与 ssh_session.ps 中的 exe 比较；
        - 可结合 check_hijack、check_mount、check_history、check_mine 等模块进行进一步分析。

    返回：
        - 若发现疑似替换的进程，返回 Markdown 表格：
            | PID | true_exe | observed_exe | 说明 |
            |-----|----------|--------------|------|
            | 1234 | sshd | sˢʰᴅ | 命令被替换，实际 exe 与 ps 中不一致 |

        # AI 自主分析判断，以下为参考示例：
        智能分析：
            - 若 true_exe 与 ps 中 exe 不一致且不在已知映射（check_proc）中，则提升可疑等级；
            - 若 true_exe 为系统或常见二进制但 observed_exe 为可疑路径（如 /tmp、/var/tmp、/dev/shm），则视为高风险；
            - 若无法读取 /proc/<pid>/exe（权限或已被清空），建议提升可疑等级并取证。

        建议措施：
            - 对可疑项采集证据（readlink /proc/<pid>/exe, cat /proc/<pid>/cmdline, ls -l /proc/<pid>）；
            - 若确认恶意，隔离并备份可执行文件，终止进程并进一步检查启动项与持久化机制；
            - 结合 check_hijack、check_mount、check_startup 等模块定位替换来源并清除持久化。
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
    mount 挂载后门排查工具（ProcAnalysis 模块子工具）

    原理：
        读取 /proc/mounts 或系统 mount 输出，解析所有挂载项。
        识别可能被滥用用于隐藏进程、伪装文件或持久化的挂载类型/路径，例如：
        - 将 /proc/<pid> 或 /proc/<数字> 作为挂载点（可能用于隐藏进程）
        - tmpfs、/dev/shm、/tmp、/var/tmp、/run 等可写临时目录被可疑挂载或绑定
        - fuse、overlay、aufs、loop 等非常规文件系统或 loop 设备挂载到可疑位置
        - bind 挂载源为 /proc/<pid> 或非常规路径

    调用说明：
        - 可结合 check_pid、check_exe、check_hijack、check_startup 等模块进行深入分析；
        - 本工具只检测挂载信息并标注可疑项，若发现可疑项建议进一步采集（readlink /proc/...、ls -l、查看启动项等）。

    返回：
        - 以 Markdown 表格列出可疑挂载（若无则返回“未发现可疑挂载”）：

        |挂载点 | 文件系统 | 源 (source) | 挂载选项 | 说明 |
        |--------|----------|-------------|----------|------|
        | /proc/1234 | proc | proc | rw,nosuid,... | /proc/1234 被挂载，可能用于隐藏 PID |

        # AI 自主分析判断，以下为参考示例：
        智能分析：
            - 若挂载点匹配 `/proc/\d+` 或源为 `/proc/\d+`，标记为高危（可能用于隐藏或伪装进程）；
            - 若文件系统为 tmpfs 且挂载点在 /tmp、/var/tmp、/dev/shm、/run 且非标准用途，标记为中/高风险；
            - 若为 fuse/overlay/loop/aufs 且挂载点或源位于可疑目录（/tmp、/var/tmp、/dev/shm、/proc/...），提升风险等级；
            - 对每个发现项，AI 应建议后续采集命令以便进一步取证（例如 readlink/cat/ls -l）。

        建议措施：
            - 对可疑挂载先采集证据（cat /proc/mounts, mount | grep <path>, readlink /proc/<pid>/exe, ls -l <path> 等）；
            - 若确认恶意：卸载该挂载（umount <path>），隔离并备份相关可疑文件与目录，然后终止相关进程并追溯启动来源；
            - 检查启动项、cron、systemd 单元及网页后门等持久化方式（可调用 check_startup、check_cron、check_webshell）；
            - 在修复后持续监控相同挂载点与相似行为。

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


@mcp.tool()
def get_localhost():
    """
    本地 IP 获取工具（NetAnalysis 模块子工具）

    原理：
        通过执行 `ip -4 addr show` 命令获取目标主机的 IPv4 地址列表，
        提取每个网卡的 IP，用于网络巡检、异常通信检测或后续扫描分析。

    调用说明：
        - 获取的 IP 地址会存储在 ssh_session.ip_list 列表中，可供其他模块使用；
        - 可结合 check_network、check_open_ports、check_remote_connection 等模块进一步分析。

    返回：
        - 成功时返回获取到的 IP 列表，例如：
            "本地IP列表: 192.168.1.10, 10.0.0.5"
        - 若未获取到 IP，返回提示信息。

        # AI 自主分析判断，以下为参考示例：
        智能分析：
            - 自动过滤无效或回环地址（127.0.0.1）；
            - 可提示用户判断是否存在异常网卡或私有 IP 未登记在资产列表中；
            - 可结合历史扫描结果判断是否存在多网段异常通信。

        建议措施：
            - 对发现的 IP 地址与资产登记表比对，确认是否属于合法网卡；
            - 对异常 IP 或未知网段，建议进一步排查网卡配置、路由表及防火墙策略；
            - 可结合 check_network、check_remote_connection 模块检查可疑通信。
    """

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
    网络连接排查工具（ss 分析）（NetAnalysis 模块子工具）

    原理：
        通过执行 `ss -anutp` 命令获取系统所有 TCP/UDP 连接信息，
        提取本地地址、本地端口、远程地址、远程端口以及对应进程信息，
        用于发现异常外联或开放端口，辅助恶意连接分析。

    调用说明：
        - 先调用 get_localhost 获取本地 IP；
        - 可结合 check_remote_connection、check_open_ports 等模块进行综合分析；
        - 输出结果可用于判断是否存在异常外联或未授权的服务端口。

    返回：
        - 列出可疑的远程连接或开放端口：

        | Local Address | Remote Address | PID/Program | 排查结果 |
        |---------------|----------------|-------------|---------|
        | 192.168.1.10:22 | 203.0.113.5:445 | 1234/sshd | 可疑远程连接 |
        | 192.168.1.10:8080 | 0.0.0.0:* | 5678/python | 可疑开放端口 |

        # AI 自主分析判断，以下为参考示例：
        智能分析：
            - 若远程地址不在本地 IP 列表中且端口合法，则标记为高风险外联；
            - 若本地端口被异常监听，可能存在未授权服务或后门程序；
            - 可结合历史网络连接数据，判断是否为新建异常连接。

        建议措施：
            - 对高风险远程连接，建议使用 netstat 或 tcpdump 进一步抓包分析；
            - 关闭未授权的开放端口，或限制访问源 IP；
            - 审查对应进程及执行文件，结合 check_exec 模块分析是否存在恶意执行；
            - 若发现可疑远程通信，可配合 check_firewall、check_routes 模块进行排查。
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
    网卡排查工具（NetworkAnalysis 模块子工具）

    原理：
        通过列举 /sys/class/net 下的网卡设备，获取系统可用网络接口信息。
        可结合 tcpdump 或其他流量分析工具，进一步分析异常网络流量或恶意外联。

    调用说明：
        - 建议在 SSH 连接建立后执行；
        - 可结合 check_network、check_localhost 工具进一步分析网络状态；
        - 检测结果可用于判断是否存在异常网卡、虚拟网卡或被恶意配置的网络接口。

    返回：
        ## 网卡列表
        | 网卡名称 | 网卡信息 |
        |---------|-----------|
        | ...     | ...       |
        
        # AI 自主分析判断，以下为参考示例：
        智能分析：
            - 可判断网卡是否为虚拟网卡（如 docker0、virbr0 等）；
            - 可检查是否存在未知或异常网卡名称；
            - 可用于结合 ss/tcpdump 分析外联流量或监听端口异常情况。

        建议措施：
            - 对未知或异常网卡，检查其创建原因及配置；
            - 可配合 tcpdump -i 网卡 -w output.pcap 进行流量捕获分析；
            - 检查系统是否存在网络后门或流量转发规则异常。

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
    hosts 文件排查工具（NetworkAnalysis 模块子工具）

    原理：
        读取 /etc/hosts 文件，检测是否存在非本地 IPv4 的条目。
        可用于发现 DNS 劫持、恶意域名解析或本地伪造 hosts 条目。

    调用说明：
        - 可结合 get_localhost 工具判断本地 IP；
        - 可结合 check_network 分析与外部通信情况。

    返回：
        ## hosts 条目列表
        | IP | 域名 | 检测结果 |
        |----|------|----------|
        | ...| ...  | 恶意 ip 解析域名 |

        # AI 自主分析判断，以下为参考示例：
        智能分析：
            - 若 IP 非本地地址，且域名非正常业务域名，则标记为可疑；
            - 检查是否存在重复或被篡改的 hosts 条目；
            - 可结合历史 hosts 文件版本分析是否为近期注入。

        建议措施：
            - 对可疑条目进行还原或删除；
            - 检查是否存在脚本或程序自动修改 hosts 文件；
            - 审核系统是否存在 DNS 劫持或网络后门行为。
    """

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
    /usr/bin 检测（FileAnalysis 模块子工具）

    原理：
        检查 /usr/bin 下命令的权限、所有者、符号链接与文件类型，识别被替换或篡改的系统命令。

    调用说明：
        - 可结合 get_ps、check_exec 分析是否有异常命令被执行；
        - 依赖：get_file_list、check_bin_json（基准信息）。

    返回：
        | 文件名 | 权限 | 所有者 | 所属组 | 检测结果 |
        |--------|------|--------|--------|----------|

        # AI 自主分析判断，以下为参考示例：
        智能分析：
            - 权限/所有者/链接与基准不符或文件类型异常时标记为可疑；
            - 列出最近修改的文件供取证。

        建议措施：
            - 备份可疑文件，恢复官方二进制，或使用 DumpFileInfo.py 深度比对；
            - 审计可执行文件的启动来源（cron、systemd、web 等）。
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
    /tmp 临时目录扫描（FileAnalysis 模块子工具）

    原理：
        列举 /tmp 下所有文件，检测可执行、可写或异常修改的文件，识别黑客残留文件或潜在恶意脚本。

    调用说明：
        - 可结合 check_exe、check_mount 判断是否为挂载伪装或被执行的二进制文件；
        - 可结合 check_user_files、check_hidden_files 做进一步分析。

    返回：
        | 文件路径 | 检测结果 |
        |----------|----------|
        | ...      | tmp 目录下可疑文件 |

        # AI 自主分析判断，以下为参考示例：
        智能分析：
            - 位于 /tmp 的 ELF 文件或脚本高度可疑；
            - 可执行且权限异常的文件风险等级更高；
            - 可结合进程信息判断文件是否正在被利用。

        建议措施：
            - 备份可疑文件，隔离或删除；
            - 检查相关进程、crontab、systemd 启动项；
            - 限制 /tmp 执行权限和可写权限，监控频繁写入行为。
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
    webroot WebShell 扫描工具（FileAnalysis 模块子工具）

    原理：
        将指定 webroot 目录打包下载到本地，使用本地扩展的扫描器（例如河马扩展）
        对代码进行静态签名/规则扫描，识别常见 WebShell 特征（eval、base64_decode、system 等）。

    调用说明：
        - 参数 path 默认为 /var/www/html，可传入自定义 webroot；
        - 本工具会：
            1. 在远端打包目标目录到 /tmp/webroot_<ts>.tar.gz；
            2. 将包下载到本地 extensions 扫描目录下并解包；
            3. 调用本地扫描器（若存在）进行扫描，并解析扫描结果；
        - 依赖：sftp_download、is_safe_path、get_time_path 等辅助函数，以及本地扫描器路径（extensions/HeMa/hm.exe 或可配置的 scanner）。

    返回：
        - 若发现可疑文件，返回按行的结构化输出（每行为一项，便于拼接成表格）：
            示例行格式：
            file path: /var/www/html/shell.php\tmd5: <md5>\t[!] 疑似 webshell 文件
        - 若无可疑项，返回 "未发现疑似 webshell" 或相应错误说明。

        # AI 自主分析判断，以下为参考示例：
        智能分析：
            - 将扫描器返回的命中条目映射为疑似 webshell；
            - 若文件体积小、修改频繁或包含高危函数（eval/system/passthru/etc），提高风险等级；
            - 若无法使用本地扫描器，返回打包并下载路径以便离线分析。

        建议措施：
            - 立即备份并隔离可疑文件，停止对应站点以防继续利用；
            - 恢复或替换受影响文件，修补上传点并修正文件权限；
            - 结合 access log（check_log）核查恶意请求来源并做网络防护。
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
        result = subprocess.run([f'extensions\\HeMa\\hm.exe', 'scan', f'{local_path}'], capture_output=True, text=True,
                                encoding='utf-8', errors='ignore')

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
    /etc/ld.so.preload 后门排查工具（BackdoorAnalysis 模块子工具）

    原理：
        读取 /etc/ld.so.preload 中的库路径，检查是否存在可疑共享库被预加载。
        恶意库放入 ld.so.preload 可使任意二进制在加载时注入恶意代码，属于高危持久化后门。

    调用说明：
        - 本工具会读取 /etc/ld.so.preload（忽略注释行），对每个非空路径：
            1. 检查文件是否存在；
            2. 尝试获取文件的 owner/group/perm；
            3. 尝试计算 md5sum（若有权限）；
        - 可结合 check_exe、check_startup、check_bin 等模块进行进一步关联分析。

    返回：
        - 若发现内容，返回 Markdown 表格：
            | path | 存在 | owner:group | perm | md5 | 说明 |
            |------|------|-------------|------|-----|------|
            | /tmp/lib.so | 否/是 | root:root | 0755 | <md5> | 可疑（位于 /tmp） |

        - 若 /etc/ld.so.preload 不存在或为空，返回 "未发现 ld.so.preload 内容"。

        # AI 自主分析判断，以下为参考示例：
        智能分析：
            - 若路径位于可写临时目录（/tmp、/var/tmp、/dev/shm 等）或非常规目录，标记为高风险；
            - 若文件不存在但被引用，提示可能为已删除的持久化痕迹或误配置；
            - 若文件存在且 md5 与已知白名单不匹配，提升为可疑/高风险。

        建议措施：
            1. 立即审查并备份 /etc/ld.so.preload 与被列出的库文件（若存在）做取证；
            2. 若确认为恶意，先停止受影响服务、隔离可疑库并从 ld.so.preload 中移除对应条目；
            3. 检查启动项、cron、systemd、web 上传点等，排查持久化来源（可调用 check_startup、check_cron、check_webshell）；
            4. 修复后验证系统二进制完整性并持续监控相同文件/路径变更。
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
    计划任务后门排查工具（BackdoorAnalysis 模块子工具）

    原理：
        扫描系统常见的计划任务目录与用户 crontab，读取任务内容并检测可疑命令片段（如包含 bash 片段、wget/curl、python -c、base64 解码、反弹 shell 模式等）。
        计划任务常被用于持久化，包含可疑命令或非常规可执行路径的条目应提高警惕。

    调用说明：
        - 依赖：exec_command 获取远端文件列表与文件内容；（如环境中存在 check_malicious_content，可优先调用）
        - 检查目标：
            1. /var/spool/cron 下的用户 crontab 文件
            2. /etc/cron.d、/etc/cron.daily、/etc/cron.weekly、/etc/cron.hourly、/etc/cron.monthly 下的任务文件
            3. 使用 crontab -l 检查当前用户或 root 的 crontab（如有权限）

    返回：
        - 若发现可疑条目，返回 Markdown 表格：
          | 路径 | 可疑内容摘要 | 说明 |
          |------|--------------|------|
          | /etc/cron.d/pwn | wget http://... | 包含远程拉取脚本，疑似后门 |

        - 若未发现可疑条目，返回： "未发现可疑计划任务"

        # AI 自主分析判断，以下为参考示例：
        智能分析：
            - 可疑判断依据包括（但不限于）：出现 wget/curl、nc/python -c/bash -i、base64 解码、反弹 shell 命令、执行 /tmp、/dev/shm、/var/tmp 下二进制或脚本、调用未在白名单内的二进制。
            - 若系统启用了雷池 WAF（ssh_session.safeline_server），可结合 WAF 规则对命令做二次校验（若可用）。

        建议措施：
            - 立即备份可疑 crontab/任务文件并记录原始内容用于取证；
            - 若确认恶意，删除或注释对应任务，终止相关进程并隔离可疑文件；
            - 检查任务所调用文件的路径与权限，并结合 check_webshell、check_bin、check_tmp、check_startup 进一步排查持久化来源；
            - 建议在修复后持续监控 crontab 变更并限制只有受控用户可写 crontab。
    """

    if not check_session():
        return "错误：SSH连接未建立或已断开，请先调用 get_ssh_client 建立连接"

    output = ''

    cron_dirs = ['/var/spool/cron', '/etc/cron.d', '/etc/cron.daily', '/etc/cron.weekly', '/etc/cron.hourly',
                 '/etc/cron.monthly']

    for cron_dir in cron_dirs:
        for file in get_files(cron_dir):
            output += check_malicious_content(f'{cron_dir}/{file}')

    return output


@mcp.tool()
def check_ssh():
    """
    /usr/sbin/sshd 软连接/劫持排查工具（BackdoorAnalysis 模块子工具）

    原理：
        检查 /usr/sbin/sshd 是否为符号链接或被替换（指向非常规路径、临时目录或非系统二进制），
        并尝试获取其目标路径、权限、属主与 md5（若有权限）。恶意替换 sshd 可导致后门持久化或任意远程登入。

    调用说明：
        - 本工具会：
            1. 使用 ls -l 或 readlink 检查 /usr/sbin/sshd 是否为符号链接并获取目标；
            2. 若目标存在，尝试 stat 获取 owner:group 与权限，并尝试 md5sum；
            3. 根据目标路径是否在可疑目录（/tmp、/var/tmp、/dev/shm 等）或非标准系统路径判断风险。
        - 可结合 check_exe、check_bin、check_startup 等模块进一步核查替换来源与启动项。

    返回：
        - 若发现可疑情形，返回 Markdown 表格：
            | path | is_symlink | target | exists | owner:group | perm | md5 | 说明 |
            |------|------------|--------|--------|-------------|------|-----|------|
        - 若未发现可疑项，返回 "未发现 /usr/sbin/sshd 劫持迹象"。
        
        # AI 自主分析判断，以下为参考示例：
        智能分析：
            - 若 /usr/sbin/sshd 指向 /tmp、/var/tmp、/dev/shm、用户家目录或非标准系统库路径，标为高风险；
            - 若为符号链接但目标不存在，提示可能为已删除的持久化痕迹或误配置；
            - 若 md5 与系统标准不符或无法比对，建议采集样本离线比对。

        建议措施：
            - 若确认被替换：立即备份可疑文件并记录（用作取证），在评估风险后停止相关服务并隔离样本；
            - 从信任来源恢复 sshd，移除异常链接与持久化项，审查启动项（systemd/crontab）与上传点；
            - 部署文件完整性监控，持续监控 /usr/sbin/sshd 与相关二进制的变更。
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
    /usr/sbin/sshd wrapper 后门排查工具（BackdoorAnalysis 模块子工具）

    原理：
        检查常见 sshd 可执行文件路径（如 /usr/sbin/sshd、/usr/bin/sshd、/usr/local/sbin/sshd 等），
        判断是否为二进制（ELF）或脚本（Wrapper），并根据文件类型、目标指向、文件所在路径与文件内容特征（如包含 #!/bin/bash、exec、bash -c、反弹命令片段等）判断是否为可疑 ssh wrapper 后门。

    调用说明：
        - 本工具会对一组常见路径做逐一检测：存在性、readlink（解析符号链接）、file 类型、首若干字节（判断是否脚本/包含 bash 片段）、md5（若可读）；
        - 可结合 check_ssh（/usr/sbin/sshd 劫持检测）、check_startup、check_bin 等模块做深入关联分析。

    返回：
        - 若发现可疑项，返回 Markdown 表格：
          | path | exists | type | target | md5 | 说明 |
          |------|--------|------|--------|-----|------|

        - 若未发现可疑项，返回："未发现 sshd wrapper 可疑项"。

        # AI 自主分析判断，以下为参考示例：
        智能分析：
            - 以脚本（以 #! /bin/bash 或可读文本）或指向临时/用户目录（/tmp、/var/tmp、/dev/shm、/home）为高危信号；
            - 若 file 判定为 ELF，但 target 被符号链接到非常规路径亦为可疑；
            - 若文件 md5 与已知基线不符（若基线可用），应提升风险等级。

        建议措施：
            - 对可疑文件采集证据（readlink, stat, md5sum, head -c）、备份并离线分析；
            - 若确认为后门：停止服务、隔离可执行文件、恢复可信二进制并排查持久化来源（systemd/crontab/web 等）；
            - 部署文件完整性校验与变更告警，限制 /usr/sbin/sshd 写权限仅限管理员。
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
    /etc/inetd.conf 后门排查工具（BackdoorAnalysis 模块子工具）

    原理：
        读取 /etc/inetd.conf 并解析非注释行，检测可能被滥用用于后门的服务配置或可疑命令。
        inetd 配置可直接启动网络服务或执行程序，恶意条目可能用于隐蔽持久化与反弹 shell。

    调用说明：
        - 会尝试读取 /etc/inetd.conf，并对每条非注释配置行做静态特征匹配；
        - 若全局存在 check_malicious_content 函数，会优先使用其结果作为判断依据（兼容已有实现）。

    返回：
        - 若发现可疑条目，返回 Markdown 表格：
          | 路径 | 行号 | 配置片段 | 可疑理由 |
          |------|------|----------|----------|
        - 若未发现可疑项，返回 "未发现可疑 inetd.conf 条目"；
        - 若无法读取文件，返回对应错误提示。

        # AI 自主分析判断，以下为参考示例：
        智能分析：
            - 可疑特征示例：包含 /bin/sh /bin/bash、/tmp/、wget/curl、nc/netcat、base64 解码、直接执行 shell 的 service/exec 字段、指向用户目录或非标准二进制；
            - 若配置启动了交互 shell 或执行脚本，应提升为高风险；
            - 若条目被注释但近期有变更记录，应进一步结合日志和版本控制核查。

        建议措施：
            - 备份 /etc/inetd.conf 并记录原始内容以便取证；
            - 对可疑条目进行注释或移除，并重启 inetd/xinetd 服务以生效（视系统而定）；
            - 审查被调用的程序路径（结合 check_bin、check_exe）与相关用户权限；
            - 若确认恶意，建议结合 check_log、check_history 做横向溯源与入侵面排查。
    """

    if not check_session():
        return "错误：SSH连接未建立或已断开，请先调用 get_ssh_client 建立连接"

    output = check_malicious_content('/etc/inetd.conf')
    return output


@mcp.tool()
def check_xinetd():
    """
    xinetd 配置后门排查工具（BackdoorAnalysis 模块）

    原理：
        读取 /etc/xinetd.conf 及 /etc/xinetd.d/ 下的服务配置文件，解析非注释行并检测可疑命令或可执行路径。
        xinetd 配置可直接启动网络服务或执行程序，恶意条目可能用于隐蔽持久化与反弹 shell。

    调用说明：
        - 建议在 SSH 连接建立后执行；
        - 会检查：
            1. /etc/xinetd.conf（若存在）
            2. /etc/xinetd.d/ 目录下所有文件
        - 若存在全局函数 check_malicious_content，会优先调用以保持兼容。

    返回：
        - 若发现可疑条目，返回 Markdown 表格：
          | 路径 | 行号 | 配置片段 | 可疑理由 |
          |------|------|----------|----------|
        - 若未发现可疑项，返回："未发现可疑 xinetd 条目"
        - 若无法读取文件，会返回相应错误提示

    智能分析（启发式）：
        - 可疑特征包括：包含 /tmp、/var/tmp、/dev/shm、wget/curl/nc/python -c/base64 等；
        - 包含 shell metacharacters、直接执行 shell 的配置、或指向用户家目录与可写临时目录的条目提高风险等级。

    建议措施：
        - 备份并核查可疑配置，注释或移除恶意条目并重启 xinetd；
        - 审计被调用程序路径（结合 check_bin、check_exec、check_startup）及对应权限；
        - 若确认恶意，采集证据后清除持久化并加强变更监控。
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
    SUID 后门排查工具（BackdoorAnalysis 模块子工具）

    原理：
        查找系统上带 SUID 位的文件（权限位包含 s），这些文件在被滥用或被替换时可能用于提权或持久化。
        本工具会列出所有可发现的 SUID 文件，并尝试获取其路径、属主:属组、权限与 md5（若可读），
        并对位于异常位置或最近修改的可疑项进行标注。

    调用说明：
        - 会执行基于 find 的搜索，但会排除 /proc、/sys、/dev、网络挂载点等非常规路径以减少误判；
        - 可结合 check_bin、check_exe、check_startup 等模块进一步分析可疑 SUID 文件的来源与使用情况。

    返回：
        - 若发现 SUID 文件，返回 Markdown 表格：
          | path | owner:group | perm | md5 | 说明 |
          |------|-------------|------|-----|------|
        - 若未发现或无权限读取，返回相应提示信息。

        # AI 自主分析判断，以下为参考示例：
        智能分析：
            - 若 SUID 文件位于 /tmp、/var/tmp、/dev/shm、用户目录或非常规路径，标为高风险；
            - 若文件 MD5 与已知白名单不符或无法读取 MD5，建议采集文件做离线比对；
            - 若文件最近修改时间异常或属主非 root，则提高警戒等级。

        建议措施：
            1. 立即备份并取证（备份文件、记录权限/属主/MD5）；
            2. 若确认为恶意或非必要，移除 SUID 位或替换为可信版本，并排查创建来源（启动项、脚本、安装包等）；
            3. 对关键主机启用文件完整性监控，并限制普通用户对可执行文件目录的写入权限；
            4. 修复后持续监控并结合其它模块（check_exec / check_startup / check_cron）排查横向影响。
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
    系统启动项排查工具（BackdoorAnalysis 模块子工具）

    原理：
        排查系统启动项文件和目录中可能存在的恶意内容，包括 init 脚本、rc.local、systemd 服务等。
        可重点关注包含 bash 片段或异常命令的启动项，以发现潜在后门或持久化攻击。

    调用说明：
        - 会自动扫描常见启动目录与启动文件；
        - 可结合 check_malicious_content、check_exec、check_bin 进一步分析。

    返回：
        - 若发现可疑启动项，返回 Markdown 表格：
          | 文件路径 | 恶意内容 |
          |---------|----------|
        - 若未发现可疑内容，返回空字符串。

        # AI 自主分析判断，以下为参考示例：
        智能分析：
            - 检测包含 bash 片段或异常命令的启动项；
            - 若启动项文件不属于系统默认文件或被非 root 修改，标注为高风险；
            - 可结合历史修改时间和文件 MD5 分析文件来源。

        建议措施：
            1. 对发现的可疑启动项进行备份与取证；
            2. 核实是否为合法脚本或服务，删除或恢复为安全版本；
            3. 检查启动项是否被恶意修改，排查对应文件的创建来源；
            4. 建议开启文件完整性监控，限制普通用户对启动项目录写入权限。
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
    /etc/profile.d 后门排查工具（BackdoorAnalysis 模块子工具）

    原理：
        读取 /etc/profile.d/ 下的所有脚本文件，检查是否包含可疑命令片段或环境变量注入（如含有 bash 片段、LD_PRELOAD、wget/curl、base64 解码、反弹 shell 等）。
        这些文件会在 shell 启动时被加载，常被滥用于持久化与命令劫持。

    调用说明：
        - 会检查 /etc/profile.d 目录下的每个文件（若目录不存在或不可读会返回相应信息）；
        - 若全局存在 check_malicious_content 函数，优先使用其结果（兼容你现有实现）；否则使用内置启发式规则判断可疑性。

    返回：
        - 若发现可疑项，返回 Markdown 表格：
            | 路径 | 可疑摘要 | 说明 |
            |------|----------|------|
        - 若未发现可疑项，返回： "未发现可疑 /etc/profile.d 条目"
        - 若目录不存在或无法读取，返回相应错误提示。

        # AI 自主分析判断，以下为参考示例：
        智能分析：
            - 依据可疑关键词（wget/curl, base64, python -c, nc, /tmp, LD_PRELOAD, export PATH=带可疑路径 等）进行判定；
            - 若文件包含 export 对 PATH/LD_PRELOAD 的异常修改或以可写临时目录为路径，提升为高风险；
            - 若文件被非 root 修改或最近被修改，也应提高优先级（如权限允许会尝试读取 stat 时间）。

        建议措施：
            1. 备份并取证可疑文件，记录原始内容与元数据；
            2. 若确认为恶意，移除或还原被篡改文件，检查持久化来源（crontab、systemd、web 上传点等）；
            3. 修复后在受影响主机启用文件变更监控，并限制普通用户对 /etc/profile.d 的写权限；
            4. 如需深度分析，可结合 check_history、check_startup、check_webshell、check_bin 等模块进行链式排查。
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
    Shell 初始化脚本排查（BackdoorAnalysis 模块子工具）

    原理：
        检查系统与用户的 shell 初始化脚本（例如 .bashrc、.bash_profile、/etc/profile、/etc/bashrc 等），
        识别包含可疑命令片段、环境变量注入（如 LD_PRELOAD、异常 PATH）、远程拉取或反弹命令的脚本。
        这些文件在用户登录或启动交互 shell 时会被加载，常被滥用于持久化与命令劫持。

    调用说明：
        - 会检查系统级初始化脚本与 /home 下每个用户的常见初始化脚本；
        - 优先使用全局辅助函数 `check_malicious_content`（若存在），否则使用内置启发式规则判断可疑性；
        - 发现可疑项时返回结构化 Markdown 表格，便于拼接最终报告。

    返回：
        - 若发现可疑项，返回 Markdown 表格：
            | 路径 | 可疑摘要 | 说明 |
            |------|---------|------|
        - 若未发现可疑项，返回："未发现可疑初始化脚本"
        - 若权限或命令执行失败，会返回相应错误说明。

        # AI 自主分析判断，以下为参考示例：
        智能分析：
            - 可疑特征包括（但不限于）：LD_PRELOAD、export PATH 包含 /tmp、wget/curl、base64 解码、python -c、nc/netcat、bash -i、反弹/反向连接片段、调用 /tmp/* 可执行文件等；
            - 若文件为可写或最近修改，则提升风险等级；
            - 若发现可疑项，建议结合 check_history、check_startup、check_webshell 做链式排查。

        建议措施：
            1. 备份并取证可疑脚本，记录元数据（owner/perm/mtime）；
            2. 如确认恶意，移除或还原脚本，修复上传点并修复权限；
            3. 对受影响账户进行凭证轮换，并开启文件完整性与变更告警。
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
    Apache2 日志分析工具（FileAnalysis 模块子工具）

    原理：
       - 读取 Apache2 日志文件（默认为 /var/log/apache2/access.log）；
       - 对每条访问记录调用本地和远程雷池 WAF 检测；
       - 对访问状态码、跳转、User-Agent 进行统计；
        - 对疑似恶意请求生成直观列表输出。

    参数：
        path: str, apache2 日志路径，默认 /var/log/apache2/access.log

    返回：
        - 如果检测到恶意请求，返回 Markdown 或结构化文本：
        1. 恶意请求列表
        2. 成功访问 IP 统计
        3. 跳转访问 IP 统计
        4. 失败访问 IP 统计
        5. User-Agent 统计
        6. 成功请求详情
        7. 跳转请求详情
        - 如果未检测到恶意内容，返回 "未发现可疑请求"
        - 如果 SSH 未连接，返回相应错误提示

        # AI 自主分析判断，以下为参考示例：
        建议措施：
            1. 对高频恶意请求的 IP 进行封禁；
            2. 分析可疑 URI、User-Agent，防止 Webshell 或注入攻击；
            3. 结合 Web 应用防火墙或日志监控进行实时告警。
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
    远程登录成功日志排查（LogAnalysis 模块子工具）

    原理：
        - 优先使用 `last` 命令枚举最近的登录记录（交互式会话）；
        - 兼容性不足时，尝试从常见认证日志文件（/var/log/auth.log 或 /var/log/secure）提取 "Accepted" 类似的成功登录条目；
        - 汇总按 IP 与用户名的成功登录次数，并给出最近一次出现时间（若可解析）。

    调用说明：
        - 本工具会尽量兼容不同 Linux 发行版和日志格式；
        - 如果目标主机存在日志轮转或权限受限，部分信息可能不可读（会在输出中标注）。

    返回（优先为 Markdown 表格）：
        | 用户名 | 登录 IP | 成功次数 | 最近一次登录 |
        |--------|--------:|---------:|--------------:|
        | root   | 1.2.3.4 | 12       | 2025-10-12 08:23:45 |

        # AI 自主分析判断，以下为参考示例：
        智能分析：
            - 高频次或来自异常国家/网段的登录 IP 应标记为可疑；
            - 若出现大量不同 IP 的短时间成功登录，可能为凭证泄露或被滥用；
            - 若某些用户（如 root 或运维账号）在非工作时间频繁登录，需进一步核查。

        建议措施：
            1. 立即核实高频或未知 IP 的合法性；对确认为恶意的 IP 进行封禁；
            2. 对相关账户进行凭证轮换（特别是 root / 管理账号）并启用多因素认证；
            3. 检查对应时间段的命令历史与 web 日志（可调用 check_history、check_log）以判断后续行为；
            4. 加强登录审计与告警（基于 fail2ban、WAF、IDS/IPS 等），限制不必要的远程访问端口。
    """

    if not check_session():
        return "错误：SSH连接未建立或已断开，请先调用 get_ssh_client 建立连接"

    output = ''
    login_success = {}

    result = exec_command(ssh_session.client, 'last')

    if result['status'] and result['result']:
        for line in result['result'].splitlines():
            line = line.strip()
            # 匹配 IPv4
            ip_match = re.search(r'\b\d{1,3}(?:\.\d{1,3}){3}\b', line)
            if not ip_match:
                continue
            ip = ip_match.group()
            user = line.split()[0]
            login_success[user] = ip
            login_success[ip] = login_success.get(ip, 0) + 1

    for ip, count in login_success.items():
        if '.' in ip:
            output += f'ip: {ip}\tcount: {count}\t[!] 爆破登入 IP\n'

    return output


@mcp.tool()
def check_login_fail():
    """
    失败登录排查（LogAnalysis 模块子工具）

    原理：
        - 优先解析认证日志（/var/log/auth.log 或 /var/log/secure）中典型的失败登录行（如 "Failed password" / "authentication failure"）；
        - 若可用，使用 lastb 作为补充来源；
        - 汇总按 IP 和用户名的失败尝试次数，并记录最近一次出现时间。

    调用说明：
        - 兼容多种 Linux 发行版日志位置与常见失败登录格式；
        - 若日志受限或不可读，会在输出中标注并尽量使用可访问的数据源。

    返回（Markdown）：
        | IP | 用户名 | 失败次数 | 最近一次出现 |
        |----|--------|---------:|---------------:|

        # AI 自主分析判断，以下为参考示例：
        智能分析：
            - 失败次数极高（例如 > 100）或单 IP 失败对多个用户名发生，视为高危（疑似暴力破解）；
            - 若某 IP 在短时间内对单账号尝试多次，也视为高危。

        建议措施：
            1. 对高风险 IP 临时封禁并进一步追踪（配合 firewall / WAF / fail2ban）；
            2. 对被试账号进行凭证重置并启用 MFA；
            3. 限制 SSH 访问（白名单、端口变更、密钥登录），开启登录告警与速率限制；
            4. 如有大量尝试，结合 check_login_success、check_history 做横向溯源。
    """

    if not check_session():
        return "错误：SSH连接未建立或已断开，请先调用 get_ssh_client 建立连接"

    output = ''
    login_fail = {}

    result = exec_command(ssh_session.client, 'lastb')

    if result['status'] and result['result']:
        for line in result['result'].splitlines():
            line = line.strip()
            
            ip_match = re.search(r'\b\d{1,3}(?:\.\d{1,3}){3}\b', line)
            if not ip_match:
                continue
            ip = ip_match.group()
            user = line.split()[0]
            login_fail[user] = ip
            
            login_fail[ip] = login_fail.get(ip, 0) + 1

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
    result = exec_command(ssh_session.client,
                          'cd /tmp && tar -xf /tmp/rkhunter.gz && cd /tmp/rkhunter-1.4.6 && bash installer.sh --install')

    if result['status'] and result['result']:
        if "complete" in result['result']:
            return f'[success] rkhunter rookit检测工具上传安装成功，需要用户手动执行命令 rkhunter --check'

    return '上传失败'


if __name__ == "__main__":
    mcp.run()
