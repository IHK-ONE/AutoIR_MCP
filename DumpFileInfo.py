from functions import *
import paramiko
import json
from pathlib import Path

'''
# 当 check_bin 误判率过高，使用该脚本，原理是提取相同版本号系统的 bin 目录文件信息，逐个对比，判断是否不同
  1. 创建一个应急服务器的基础镜像（手动下载一个全新的镜像，确保版本号相同）
  2. 开启镜像 SSH 服务
  3. 填入信息后运行该脚本，提取正确的 /usr/bin 文件信息
  4.将提取的 /usr/bin 信息将 config 的 info_bin.json 内容替换
'''

IP = '192.168.*.*'
PORT = 22
USERNAME = 'root'
PASSWORD = 'root'

client = paramiko.SSHClient()
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
client.connect(IP, PORT, USERNAME, PASSWORD)
result_dict = json.load(open('config/info_bin.json', 'r'))


def update_bin_info():
    result = exec_command(client, 'ls -al /usr/bin')
    for file in get_file_list(result['result']).values():
        filename, file_link = (file['filename'].split(' -> ') + [''])[:2]

        result_dict[filename] = {
            'perm': file['perm'],
            'owner': file['owner'],
            'group': file['group'],
            'link': file_link
        }


def update_file_types():
    result = exec_command(client, 'find /usr/bin -type f -exec file {} +')
    if result['status'] and result['result']:
        for line in result['result'].splitlines():
            file_path, file_type = line.split(':', 1)
            file_type = file_type.split(',')[0].strip()
            result_dict[Path(file_path).name]['type'] = 'ELF' if 'ELF' in file_type else file_type


update_bin_info()
update_file_types()
json.dump(result_dict, open('config/info_bin.json', 'w'))
print('data/info_bin.json 更新完毕，重新运行 AutoIR_MCP.py 即可')