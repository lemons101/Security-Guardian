# 给云端 OpenClaw 的分步部署 Prompt

不要一次性全发。按顺序一段一段发给云端 OpenClaw / 龙虾。

## 第 1 步：确认目录

```text
你是云端 OpenClaw 运维助手。

请先确认云服务器上的项目目录是否存在：

/root/projects

请执行：

pwd
ls -la /root/projects

如果 /root/projects 不存在，请创建：

mkdir -p /root/projects

执行完后告诉我：
1. 当前目录是什么
2. /root/projects 是否存在
3. /root/projects 下面现在有哪些项目
```

## 第 2 步：拉取 Security Guardian

```text
请把 Security Guardian 部署到固定目录：

/root/projects/Security-Guardian

GitHub 仓库：
https://github.com/lemons101/Security-Guardian

如果目录不存在，请执行：

git clone https://github.com/lemons101/Security-Guardian /root/projects/Security-Guardian

如果目录已存在，请执行：

cd /root/projects/Security-Guardian
git pull

执行完后告诉我：
1. 是 clone 还是 pull
2. 是否成功
3. 当前最新 commit 是什么
```

## 第 3 步：启动服务

```text
请进入项目目录并启动 Security Guardian：

cd /root/projects/Security-Guardian
chmod +x run_dashboard.sh
./run_dashboard.sh

服务应监听：

127.0.0.1:8511

注意：
- 不要停止已有的 Morning-Newspaper-Assistant 服务
- 不要修改 OpenClaw 生产配置
- 如果 8511 端口被占用，请停止并告诉我，不要擅自换端口

启动后告诉我服务是否正常运行。
```

## 第 4 步：验证访问

```text
请验证 Security Guardian 是否可以访问。

本地验证地址：

http://127.0.0.1:8511/dashboard.html

公网目标地址：

http://101.47.152.44:8511/dashboard.html

请检查：
1. 8511 是否正在监听
2. 本地访问是否成功
3. 云服务器安全组或防火墙是否放行 TCP 8511
4. 公网链接是否可访问

最后请输出最终访问链接。
```

## 第 5 步：安全边界确认

```text
请确认本次部署没有执行以下危险动作：

1. 没有读取真实 API Key
2. 没有读取真实 SSH 私钥
3. 没有读取真实客户数据
4. 没有修改 OpenClaw 生产配置
5. 没有停止已有服务

如果都没有，请回复：安全边界确认通过。
```
