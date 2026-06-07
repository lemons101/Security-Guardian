# 给云端 OpenClaw 的部署 Prompt

把下面这段发给云端 OpenClaw / 龙虾执行。

云端固定部署目录：

```text
/root/projects/Security-Guardian
```

```text
你是云端 OpenClaw 运维助手。

请在当前云服务器上部署 Security Guardian 审计控制台，方式要和之前 Morning-Newspaper-Assistant 项目类似：从 GitHub 拉取项目，在服务器本地启动一个 dashboard 服务，并给出公网访问链接。

GitHub 仓库：
https://github.com/lemons101/Security-Guardian

目标端口：
8511

目标访问路径：
/dashboard.html

期望最终访问地址：
http://101.47.152.44:8511/dashboard.html

请按以下步骤执行：

1. 先确认当前目录：

   pwd
   ls /root/projects

2. 确保项目根目录存在：

   mkdir -p /root/projects

3. 部署 Security Guardian 到固定目录：

   /root/projects/Security-Guardian

4. 如果目录不存在，请克隆仓库：

   git clone https://github.com/lemons101/Security-Guardian /root/projects/Security-Guardian

5. 如果目录已存在，请进入目录并更新：

   cd /root/projects/Security-Guardian
   git pull

6. 进入部署目录：

   cd /root/projects/Security-Guardian

7. 检查启动脚本：

   ls -la run_dashboard.sh

8. 如果脚本没有执行权限，请添加：

   chmod +x run_dashboard.sh

9. 启动服务：

   ./run_dashboard.sh

10. 服务应监听：

   127.0.0.1:8511

11. 检查本地访问是否正常：

   http://127.0.0.1:8511/dashboard.html

12. 检查云服务器安全组、防火墙或端口转发是否允许 TCP 8511。

13. 如果 8511 未放行，请提醒我需要在云服务器安全组中开放 TCP 8511。

14. 如果服务正常，请输出最终访问链接：

   http://101.47.152.44:8511/dashboard.html

如果当前终端会被服务占用，请保持该服务运行，不要关闭窗口。

如果需要后台运行，可以在确认无误后再使用类似方式：

   nohup ./run_dashboard.sh > security-guardian.log 2>&1 &

不要擅自使用后台运行，除非我明确要求。

旧版路径说明：
不要使用本地路径 D:\Openclaw。
不要把项目部署到 Morning-Newspaper-Assistant 目录里面。

以下为本次部署固定值：

   部署目录：/root/projects/Security-Guardian
   端口：8511
   访问路径：/dashboard.html

请不要执行下面这些旧的路径探测步骤：

   pwd
   find
   dir

安全要求：

- 不要读取真实 API Key。
- 不要读取真实 SSH 私钥。
- 不要读取真实客户数据。
- 不要修改现有 OpenClaw 生产配置。
- 不要停止已有的 Morning-Newspaper-Assistant 服务。
- 如果 8511 端口被占用，请停止操作并报告，不要擅自换端口。

部署完成后，请输出：

1. 当前目录
2. /root/projects 是否存在
3. /root/projects/Security-Guardian 是否存在
4. git clone / git pull 是否成功
5. Python 是否可用
6. 服务是否已启动
7. 8511 是否监听
8. 最终访问链接
```
