# OpenClaw Security Guardian

第 20 章《企业级数字员工的安全审计与生产治理》实战项目。

这个项目不是攻击靶场，也不是一键修复器。它面向已经部署在云服务器上的 OpenClaw，做三件事：

1. 读取真实 OpenClaw 日志、配置快照和运行证据。
2. 调用 Claude Code CLI 生成安全审计报告，指出风险位置、证据、影响和建议。
3. 在页面中展示风险发现、告警规则建议、治理建议和最终复检结论。

Security Guardian **不会自动修改 OpenClaw 生产配置**，也不会读取或展示真实密钥明文。所有疑似密钥字段会脱敏。

## 启动

前置要求：

- 云服务器已安装并登录 Claude Code CLI。
- 默认调用命令为 `claude -p <prompt>`。
- 如果你的 Claude Code 调用方式不同，可以设置 `CLAUDE_CODE_COMMAND`。

例如：

```bash
export CLAUDE_CODE_COMMAND="claude -p"
```

云服务器推荐路径：

```bash
cd /root/projects/Security-Guardian
chmod +x run_dashboard.sh
OPENCLAW_ROOT=/root/projects/OpenClaw ./run_dashboard.sh
```

如果真实 OpenClaw 不在 `/root/projects/OpenClaw`，把 `OPENCLAW_ROOT` 改成实际目录。

默认监听：

```text
0.0.0.0:8511
```

公网访问：

```text
http://101.47.152.44:8511/dashboard.html
```

Windows 本地：

```powershell
cd "D:\Openclaw\Security Guardian"
.\run_dashboard.cmd
```

本地访问：

```text
http://127.0.0.1:8511/dashboard.html
```

## 页面流程

1. **执行真实检测**  
   扫描 `OPENCLAW_ROOT` 下的日志、配置、Skill 记录和审计材料，生成 `security_audit_bundle.json`、Markdown 报告和 JSON 报告。

2. **生成告警规则**  
   根据真实风险发现生成告警规则建议。这里不是说监控系统已经被改好，而是输出可落地的规则清单。

3. **控制面建议**  
   如果检测到公网监听、弱鉴权或 WebSocket 风险，输出控制面收敛建议和需要复核的证据。

4. **Skill 建议**  
   如果检测到未签名 Skill、敏感路径访问或可疑出站，输出最小权限、签名校验和出站白名单建议。

5. **密钥建议**  
   如果检测到 Token、API Key 或 Authorization 进入日志，输出吊销、轮换、短期凭证和日志脱敏建议。

6. **治理策略建议**  
   输出 denyList、Token 熔断、审计日志和人工审批建议。

7. **最终复检**  
   根据扫描覆盖范围和风险发现数量给出上线前判断。存在 high / critical 风险时，结论会是暂缓上线。

## 生成文件

执行真实检测后会生成：

```text
openclaw_security_console/runtime/security_audit_bundle.json
openclaw_security_console/runtime/claude_code_audit_prompt.md
openclaw_security_console/runtime/security_audit_report.md
openclaw_security_console/runtime/security_audit_report.json
```

## 检测范围

程序会优先使用：

```text
OPENCLAW_ROOT
```

如果未设置，会尝试查找：

```text
/root/projects/OpenClaw
/root/projects/openclaw
/root/projects/Openclaw
/root/projects
```

扫描文件类型包括：

```text
.log .txt .json .jsonl .yml .yaml .toml .conf .md
```

会跳过：

```text
.git node_modules .venv venv __pycache__ site-packages
```

## 安全边界

- 只做只读检测和报告生成。
- 不自动修改 OpenClaw 配置。
- 不读取真实 SSH 私钥内容作为报告正文。
- 不展示真实 API Key / Token 明文。
- 审计页面不建议长期裸露公网，生产环境请加 IP 白名单、Basic Auth、VPN 或企业 SSO。

## 课程结论

学员最终拿到的不是“已完成生产治理的 OpenClaw”，而是：

- 一份真实证据驱动的 Claude Code 审计报告
- 一份真实 Claude Code 调用 Prompt
- 一组可转成工单的告警规则建议
- 一组按风险类型拆开的治理建议
- 一个上线前复检结论
- `checklists/OpenClaw生产上线安全核查表.md`

## 配套文档

- `lesson20-lab.md`：课堂实验手册，给学员按步骤执行。
- `lesson20_architecture.md`：课程 framework、系统逻辑和设计边界。
- `checklists/OpenClaw生产上线安全核查表.md`：上线前人工复核清单。
