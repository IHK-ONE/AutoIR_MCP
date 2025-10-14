```plain
[!] 项目停止更新
切勿直接用于生产环境，该项目已经集成应急响应的 MCP 功能，提示词并未优化完善。
```

AutoIR 的 FastMCP 版本，可以使用 Vscode / cursor 进行 AI 自动化应急响应

环境配置基本与 AutoIR_Remote 配置相同，详细跳转 [https://github.com/IHK-ONE/AutoIR_Remote](https://github.com/IHK-ONE/AutoIR_Remote)

# 功能列表
```plain
# 劫持排查
  1. 排查环境是否被劫持，以及劫持环境变量
  
# 恶意用户排查
  1. 排查 home 下用户
  2. 排查 /etc/passwd 下，拥有 shell 权限、root 权限、特殊权限的用户
  3. 排查 /etc/shadow 下，空口令用户（无密码登录用户）
  4. 排查 sudo 中权限异常用户
  5. 排查 拥有 authorized_keys 免密登录用户

# ProcAnalysis 恶意进程排查
  1. 排查 恶意挖矿脚本
  2. 排查 恶意启动，恶意命令执行的进程
  3. 排查 隐藏pid检
  4. 排查 被恶意替换命令名称的进程
  5. 排查 被恶意 mount 挂载的进程

# NetworkAnalysis 网络排查
  1. 分析网络对外连接
  2. 检测存在的网卡
  3. hosts 排查
  
# FileAnalysis 恶意文件检测
  1. /usr/bin 排查
  2. /tmp 排查
  3. webroot webshell
 
# BackdoorAnalysis 后门排查
  1. LD_PRELOAD后门检测
  2. LD_AOUT_PRELOAD后门检测
  3. LD_ELF_PRELOAD后门检测
  4. LD_LIBRARY_PATH后门检测
  5. ld.so.preload后门检测
  6. PROMPT_COMMAND后门检测
  7. cron后门检测
  8. alias后门
  9. ssh后门 ln -sf /usr/sbin/sshd /tmp/su; /tmp/su -oPort=5555;
  10. SSH Server wrapper 后门，替换/user/sbin/sshd 为脚本文件
  11. /etc/inetd.conf 后门
  12. /etc/xinetd.conf/后门
  13. setuid类后门
  14. /etc/fstab类后门（待写）
  13. 系统启动项后门检测

# LogAnalysis
  1. apache2 日志排查信息统计（并未制作 IIS Nginx Ruoyi 等服务日志审计，一般情况下 应急响应出题使用 Apache 居多）
  2. 登入成功和登入失败信息统计
  
# Rookit 排查
  1. 使用 rkhunter 实现
```

# MCP 导入
```plain
uv init autoir-mcp
uv pip install -r requirements.txt
```

初始化后，可以直接在 Vscode 与 Cursor 中让 AI 加载 MCP

![](https://cdn.nlark.com/yuque/0/2025/png/35229002/1760464295921-21ef314e-a9ca-49cc-b1ff-ee3b7e5798eb.png)

配置完后直接询问即可

![](https://cdn.nlark.com/yuque/0/2025/png/35229002/1760463837550-179de7da-0429-4a72-9886-8b222a97101f.png)

