# 给云端 OpenClaw 的 Security Guardian 执行 Prompt

把下面分步骤交给云端 OpenClaw / 龙虾执行即可。

## 第 1 步：部署项目

```text
请把 Security Guardian 部署到云服务器：

目标目录：/root/projects/Security-Guardian
GitHub 仓库：https://github.com/lemons101/Security-Guardian
固定端口：8511

如果目录不存在，请 clone。
如果目录已存在，请进入目录后 git pull。
```

## 第 2 步：启动服务

```text
请启动 Security Guardian。

要求：
1. 进入 /root/projects/Security-Guardian
2. 确认云服务器已安装并登录 Claude Code CLI
3. 确认下面命令可用：

claude -p "请只回复 ok"

4. 如果 Claude Code 调用命令不是 claude -p，请设置 CLAUDE_CODE_COMMAND
5. 确认 run_dashboard.sh 可执行
6. 使用真实 OpenClaw 目录启动：

OPENCLAW_ROOT=/root/projects/OpenClaw ./run_dashboard.sh

如果真实 OpenClaw 不在 /root/projects/OpenClaw，请先定位真实目录，再替换 OPENCLAW_ROOT。

服务应监听：
0.0.0.0:8511
```

## 第 3 步：执行 Security Guardian Skill

```text
请在云服务器本机依次调用以下接口：

curl -X POST http://127.0.0.1:8511/claude-code/analyze-cloud
curl -X POST http://127.0.0.1:8511/claude-code/enable-monitoring
curl -X POST http://127.0.0.1:8511/guardian/seal-control-plane
curl -X POST http://127.0.0.1:8511/guardian/isolate-skill
curl -X POST http://127.0.0.1:8511/guardian/rotate-secrets
curl -X POST http://127.0.0.1:8511/guardian/apply-governance
curl -X POST http://127.0.0.1:8511/guardian/final-audit

注意：
这些接口只生成检测报告、告警规则建议、治理建议和最终复检结论。
不要修改 OpenClaw 生产配置。
不要读取或输出真实密钥明文。
```

## 第 4 步：验证页面

```text
请验证页面是否可访问：

http://101.47.152.44:8511/dashboard.html

请检查：
1. 8511 是否监听在 0.0.0.0
2. OPENCLAW_ROOT 是否指向真实 OpenClaw 目录
3. 页面是否显示 Claude 调用成功
4. 页面是否显示扫描文件数
5. 页面是否显示 Claude Code 风险发现
6. 页面是否生成建议治理动作
7. 页面是否生成最终复检结论
```

## 第 5 步：输出结果

```text
请最终输出：

1. Security Guardian 是否部署成功
2. 服务是否启动成功
3. 最终访问链接
4. OPENCLAW_ROOT 实际路径
5. 扫描文件数
6. Claude Code 是否调用成功
7. high / critical 风险数量
8. 最终复检结论
9. 审计报告路径

请不要声称已经完成生产治理，除非你确实修改并验证了 OpenClaw 生产配置。
```
