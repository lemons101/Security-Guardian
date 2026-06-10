# 第 20 节课程 Framework：Security Guardian 云端 OpenClaw 安全自审计

## 1. 课程定位

本项目服务于第 20 节《企业级数字员工的安全审计与生产治理》。

课程目标不是做攻击演示，也不是让学员一键修复 OpenClaw，而是让学员完成一次真实的生产前安全自审计：

```text
云端 OpenClaw
  -> 收集真实日志、配置、Skill 记录和运行证据
  -> 调用 Claude Code 做一次性安全审计
  -> 生成风险报告、告警建议、治理建议和最终复检结论
```

学员最终要理解的是：

- 数字员工上线前要看真实证据，而不是凭感觉判断安全
- Claude Code 可以作为审计分析器，但不能替代生产配置变更
- “建议已生成”和“生产已治理”必须严格区分
- high / critical 风险存在时，应暂缓上线或进入人工处置

## 2. 课堂角色

| 角色 | 作用 | 边界 |
|---|---|---|
| OpenClaw / 龙虾 | 执行部署、启动服务、调用本机接口 | 不伪造审计结果 |
| Security Guardian | 读取真实证据、脱敏、生成审计包、展示报告 | 不自动修改生产配置 |
| Claude Code CLI | 审查审计包，输出结构化风险报告 | 不直接读取密钥，不执行修复命令 |
| 学员 | 观察报告、理解风险、判断上线前条件 | 不需要手动登录服务器 |

## 3. 系统架构

```text
/root/projects/OpenClaw
 真实日志 / 配置 / Skill 记录
        |
        v
Security Guardian
  - 扫描 OPENCLAW_ROOT
  - 脱敏疑似密钥
  - 生成 security_audit_bundle.json
        |
        v
Claude Code CLI
  claude -p "<audit prompt>"
        |
        v
Security Guardian Console
  - Claude Code 风险发现
  - 告警规则建议
  - 治理建议
  - 最终复检结论
```

默认访问地址：

```text
http://101.47.152.44:8511/dashboard.html
```

## 4. 核心流程

### Step 1：部署项目

OpenClaw 将仓库部署到：

```text
/root/projects/Security-Guardian
```

仓库地址：

```text
https://github.com/lemons101/Security-Guardian.git
```

### Step 2：确认 Claude Code 可用

云服务器必须能执行：

```bash
claude -p "请只回复 ok"
```

如果 Claude Code CLI 不可用，审计不能继续。系统会生成 `CC-CALL-FAILED`，而不是伪造 Claude 审计成功。

### Step 3：指定真实 OpenClaw 目录

启动服务时设置：

```bash
OPENCLAW_ROOT=/root/projects/OpenClaw ./run_dashboard.sh
```

如果真实目录不同，应替换为实际路径。

### Step 4：执行真实检测

调用：

```bash
curl -X POST http://127.0.0.1:8511/claude-code/analyze-cloud
```

系统会生成：

```text
openclaw_security_console/runtime/security_audit_bundle.json
openclaw_security_console/runtime/claude_code_audit_prompt.md
openclaw_security_console/runtime/security_audit_report.md
openclaw_security_console/runtime/security_audit_report.json
```

### Step 5：生成建议

依次调用：

```bash
curl -X POST http://127.0.0.1:8511/claude-code/enable-monitoring
curl -X POST http://127.0.0.1:8511/guardian/seal-control-plane
curl -X POST http://127.0.0.1:8511/guardian/isolate-skill
curl -X POST http://127.0.0.1:8511/guardian/rotate-secrets
curl -X POST http://127.0.0.1:8511/guardian/apply-governance
```

这些接口只生成建议，不代表真实生产配置已经被修改。

### Step 6：最终复检

调用：

```bash
curl -X POST http://127.0.0.1:8511/guardian/final-audit
```

复检判断逻辑：

- Claude 调用失败：不能通过
- 未定位真实 OpenClaw：审计范围不足
- 扫描文件数为 0：审计范围不足
- 存在 high / critical：暂缓上线
- 只剩 medium：进入人工复核
- 未发现高危证据：可进入上线前人工复核

## 5. 页面模块

| 模块 | 展示内容 |
|---|---|
| 云端 OpenClaw 状态 | Claude 调用状态、OPENCLAW_ROOT、扫描文件数、端口和配置摘要 |
| Claude Code 风险发现 | 风险编号、等级、位置、证据、影响、建议 |
| 告警规则 | 由 high / critical 风险转换出的告警建议 |
| 建议治理动作 | 控制面、Skill、密钥、denyList、Token 熔断等建议 |
| 最终复检 | 根据真实审计结果给出上线前判断 |

## 6. 风险检测范围

Security Guardian 会扫描 `OPENCLAW_ROOT` 下的常见审计材料：

```text
.log .txt .json .jsonl .yml .yaml .toml .conf .md
```

会跳过：

```text
.git node_modules .venv venv __pycache__ site-packages
```

内置预检关注：

- 控制面公网监听
- Token / API Key 进入日志
- 未签名或社区来源 Skill
- 敏感路径读取
- 可疑网络出站
- Token 用量异常
- denyList 缺失
- 审计日志关闭

最终风险判断以 Claude Code 返回的结构化报告为准。

## 7. 安全边界

项目坚持四条边界：

1. 只读检测，不主动修改 OpenClaw 生产配置。
2. 疑似密钥字段脱敏，不展示真实密钥明文。
3. Claude Code 失败时明确失败，不伪造审计报告。
4. 所有“治理”都以建议和复核证据形式呈现。

## 8. 课堂交付物

学员最终应拿到：

- Security Guardian 页面链接
- Claude Code 调用状态
- 扫描文件数和 OpenClaw 根目录
- `security_audit_bundle.json`
- `claude_code_audit_prompt.md`
- `security_audit_report.md`
- `security_audit_report.json`
- 告警规则建议
- 建议治理动作
- 最终复检结论

## 9. 配套文件

建议 GitHub 仓库保留以下核心文档：

| 文件 | 用途 |
|---|---|
| `README.md` | 项目说明和启动方式 |
| `lesson20-lab.md` | 学员实验手册 |
| `课程Framework设计说明.md` | 课程设计与系统逻辑 |
| `checklists/OpenClaw生产上线安全核查表.md` | 上线前人工复核清单 |

其他过程稿不再保留，避免项目结构臃肿。
