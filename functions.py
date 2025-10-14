import os.path
from datetime import datetime
import re
import json
import requests

# 读取 config 配置文件，读取雷池服务器的链接地址
base_dir = os.path.dirname(os.path.abspath(__file__))
config_path = os.path.join(base_dir, 'config', 'config.json')

try:
    with open(config_path, encoding='utf-8') as f:
        config_data = json.load(f)
    server = config_data['SafeLineWAF']['Server']
except (FileNotFoundError, KeyError, json.JSONDecodeError) as e:
    server = ""


def exec_command(client, command):
    """命令执行函数"""
    stdin, stdout, stderr = client.exec_command(command)
    stdout_output = stdout.read().decode().strip()
    stderr_output = stderr.read().decode().strip()

    result = {'status': False, 'result': stderr_output}
    if stdout_output:
        result.update({'status': True, 'result': stdout_output})

    return result


def sftp_download(client, origin_path, download_path):
    """SFTP 传输函数"""
    sftp = None
    try:
        sftp = client.open_sftp()
        sftp.get(origin_path, download_path)
    except Exception:
        return ''
    finally:
        if sftp:
            sftp.close()


def sftp_upload(client, local_path, server_path):
    """SFTP 传输函数"""
    sftp = None
    try:
        sftp = client.open_sftp()
        sftp.put(local_path, server_path)
    except Exception:
        return ''
    finally:
        if sftp:
            sftp.close()


def get_file_list(files):
    """ 将 ls -al 的数据转换为列表 """

    file_list = {}
    files = files.splitlines()[1:]

    for i in range(len(files)):
        file = files[i].strip()
        parts = re.split(r'\s+', file.strip())
        perm = parts[0].strip('.').strip('+')  # 文件权限
        link = parts[1]  # 硬链接数
        owner = parts[2]  # 文件拥有者
        group = parts[3]  # 所在用户组
        size = parts[4]  # 文件大小
        time = get_time(parts[5:8])  # 文件时间
        filename = ' '.join(_ for _ in parts[8:])  # 文件名
        if filename not in ['.', '..']:
            file_list[i] = {'perm': perm, 'link': link, 'owner': owner, 'group': group, 'size': size, 'time': time, 'filename': filename}

    return file_list


def get_time(time):
    """时间转换，用于本地时间戳的判断"""

    month_map = {
        'Jan': '01', 'Feb': '02', 'Mar': '03', 'Apr': '04',
        'May': '05', 'Jun': '06', 'Jul': '07', 'Aug': '08',
        'Sep': '09', 'Oct': '10', 'Nov': '11', 'Dec': '12'
    }

    month = month_map[time[0]]
    day = time[1]

    if ":" in time[2]:
        return f"{datetime.now().year}年{month}月{day}日 {time[2]}"
    return f"{time[2]}年{month}月{day}日"


def get_time_path():
    """返回 %Y_%m_%d_%H_%M_%S 时间戳"""
    return datetime.now().strftime("%Y_%m_%d_%H_%M_%S")


def check_safe_local(content):
    # 检测恶意 shell
    # Author：咚咚呛
    # Github：https://github.com/grayddq/GScan

    try:
        if (('bash' in content) and (('/dev/tcp/' in content) or ('telnet ' in content) or ('nc ' in content) or (('exec ' in content) and ('socket' in content)) or ('curl ' in content) or ('wget ' in content) or ('lynx ' in content) or ('bash -i' in content))) or (".decode('base64')" in content) or ("exec(base64.b64decode" in content):
            return content
        elif ('/dev/tcp/' in content) and (('exec ' in content) or ('ksh -c' in content)):
            return content
        elif ('exec ' in content) and (('socket.' in content) or (".decode('base64')" in content)):
            return content

        elif (('wget ' in content) or ('curl ' in content)) and ((' -O ' in content) or (' -s ' in content)) and (' http' in content) and (('php ' in content) or ('perl' in content) or ('python ' in content) or ('sh ' in content) or ('bash ' in content)):
            return content
        return ''
    except Exception:
        return ''


def check_safe_safeline(content):
    """雷池 WAF 拦截检测"""
    try:
        response = requests.get(server + content, timeout=3)
        if response.status_code == 403:
            return content
        return ''
    except Exception:
        return ''
