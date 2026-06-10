# 第 20 节 实验手册：Security Guardian 云端 OpenClaw 安全自审计

> 配套课程：AI 业务流架构师 · 第 20 节《企业级数字员工的安全审计与生产治理》
> 预计耗时：40-60 分钟
> 操作方式：全程发给云端 OpenClaw / 龙虾执行
> 前置条件：OpenClaw 已部署 + Claude Code CLI 可用 + 8511 端口可访问

---

## 0. 开始前确认

| # | 物料 | 备注 |
|---|---|---|
| 1 | 云端 OpenClaw / 龙虾 | 能执行部署和本机 `curl` |
| 2 | Claude Code CLI | `claude -p "请只回复 ok"` 能返回 |
| 3 | OpenClaw 真实目录 | 推荐 `/root/projects/OpenClaw` |
| 4 | Security Guardian 仓库 | `https://github.com/lemons101/Security-Guardian.git` |
| 5 | 访问端口 | 固定 `8511` |

> 本实验只做真实检测和建议输出，不自动修改 OpenClaw 生产配置。

---

## 1. 实验链路

```text
OpenClaw 真实日志 / 配置 / Skill 记录
  -> Security Guardian 生成脱敏审计包
  -> Claude Code CLI 一次性审计
  -> 页面展示风险、告警建议、治理建议、最终复检
```

关键边界：

- Claude Code 必须真实调用成功
- `OPENCLAW_ROOT` 必须指向真实 OpenClaw
- 页面里的勾表示“报告或建议已生成”，不表示生产已经治理

---

## 2. 部署项目（发给龙虾）

```text
请帮我部署 Security Guardian。

仓库地址：
https://github.com/lemons101/Security-Guardian.git

部署目录：
/root/projects/Security-Guardian

请完成：
1. 如果目录不存在就 clone
2. 如果目录已存在就 git pull
3. 确认 README.md、run_dashboard.sh、openclaw_security_console/app.py 都存在

完成后告诉我：
1. clone / pull 是否成功
2. 当前 commit hash
3. 项目目录是否正确
```

---

## 3. 检查 Claude Code（发给龙虾）

```text
请检查 Claude Code CLI 是否可用。

执行：
claude -p "请只回复 ok"

要求：
1. 如果返回 ok，继续
2. 如果命令不存在、未登录或报错，请停止并返回完整错误
3. 不要伪造 Claude 调用成功

完成后告诉我：
1. Claude Code CLI 是否可用
2. 测试命令返回内容
```

如果云端不是 `claude -p`，先设置：

```bash
export CLAUDE_CODE_COMMAND="你的 Claude Code 一次性调用命令"
```

---

## 4. 定位 OpenClaw 目录（发给龙虾）

```text
请定位真实 OpenClaw 项目目录。

优先检查：
/root/projects/OpenClaw
/root/projects/openclaw
/root/projects/Openclaw

要求：
1. 不要把 /root/projects/Security-Guardian 当成 OpenClaw
2. 找到后告诉我 OPENCLAW_ROOT 应该设置为什么
3. 如果找不到，请停止并说明原因
```

---

## 5. 启动服务（发给龙虾）

发送前把 `OPENCLAW_ROOT` 替换为第 4 步真实路径。

```text
请启动 Security Guardian。

执行：
cd /root/projects/Security-Guardian
chmod +x run_dashboard.sh
OPENCLAW_ROOT=/root/projects/OpenClaw ./run_dashboard.sh

要求：
1. 服务监听 0.0.0.0:8511
2. 如果 8511 被占用，请停止并报告
3. 不要停止已有 OpenClaw 生产服务

完成后告诉我：
1. 服务是否启动成功
2. 是否监听 0.0.0.0:8511
3. OPENCLAW_ROOT 实际值
4. 页面链接是否为 http://101.47.152.44:8511/dashboard.html
```

---

## 6. 执行真实检测（发给龙虾）

```text
请执行 Security Guardian 真实检测，并调用 Claude Code 审计。

执行：
curl -X POST http://127.0.0.1:8511/claude-code/analyze-cloud

完成后检查：
1. Claude 调用是否成功
2. OPENCLAW_ROOT 是否正确
3. 扫描文件数是否大于 0
4. 是否生成 security_audit_bundle.json
5. 是否生成 claude_code_audit_prompt.md
6. 是否生成 security_audit_report.md
7. 是否生成 security_audit_report.json
8. 是否出现 CC-CALL-FAILED

完成后告诉我：
1. Claude Code 是否调用成功
2. 扫描文件数
3. 风险发现总数
4. high / critical 风险数量
5. 审计报告路径
```

> 如果出现 `CC-CALL-FAILED`，先修 Claude 调用链路，不要继续解释审计结论。

---

## 7. 生成建议（发给龙虾）

```text
请按顺序生成 Security Guardian 建议。

依次执行：
curl -X POST http://127.0.0.1:8511/claude-code/enable-monitoring
curl -X POST http://127.0.0.1:8511/guardian/seal-control-plane
curl -X POST http://127.0.0.1:8511/guardian/isolate-skill
curl -X POST http://127.0.0.1:8511/guardian/rotate-secrets
curl -X POST http://127.0.0.1:8511/guardian/apply-governance

注意：
这些接口只生成告警规则建议、控制面建议、Skill 建议、密钥建议和治理策略建议。
不要自动修改 OpenClaw 生产配置。

完成后告诉我：
1. 生成了哪些建议
2. 建议分别对应哪些风险
3. 是否有 high / critical 风险需要人工处理
```

---

## 8. 最终复检（发给龙虾）

```text
请执行最终复检。

执行：
curl -X POST http://127.0.0.1:8511/guardian/final-audit

复检规则：
1. Claude 调用失败：不能通过
2. OPENCLAW_ROOT 未定位：审计范围不足
3. 扫描文件数为 0：审计范围不足
4. 存在 critical / high 风险：暂缓上线
5. 只剩 medium 风险：进入人工复核

完成后告诉我：
1. 最终复检结论
2. critical / high / medium 风险数量
3. 是否允许进入上线前人工复核
4. 页面访问链接
```

---

## 9. 查看页面

打开：

```text
http://101.47.152.44:8511/dashboard.html
```

重点看：

| 区域 | 看什么 |
|---|---|
| 云端 OpenClaw 状态 | Claude 调用、OPENCLAW_ROOT、扫描文件数 |
| Claude Code 风险发现 | 风险等级、位置、证据、建议 |
| 告警规则 | high / critical 是否转成告警建议 |
| 建议治理动作 | 控制面、Skill、密钥、治理策略 |
| 最终复检 | 是否还有上线阻断项 |

生成文件：

```text
openclaw_security_console/runtime/security_audit_bundle.json
openclaw_security_console/runtime/claude_code_audit_prompt.md
openclaw_security_console/runtime/security_audit_report.md
openclaw_security_console/runtime/security_audit_report.json
```

---

## 10. 验收检查清单

- [ ] Security Guardian 已部署到 `/root/projects/Security-Guardian`
- [ ] Claude Code CLI 可用
- [ ] `OPENCLAW_ROOT` 指向真实 OpenClaw
- [ ] 服务监听 `0.0.0.0:8511`
- [ ] 页面可以访问
- [ ] Claude 调用成功
- [ ] 扫描文件数大于 0
- [ ] 审计包、Prompt、Markdown 报告、JSON 报告均已生成
- [ ] 页面显示风险发现
- [ ] 页面显示建议治理动作
- [ ] 页面显示最终复检结论
- [ ] 没有把“建议已生成”说成“生产已治理”

---

## 11. 常见问题速查

| 现象 | 原因 | 你发什么 |
|---|---|---|
| `CC-CALL-FAILED` | Claude CLI 不可用或返回非 JSON | 「请执行 `claude -p "请只回复 ok"` 并返回完整报错」 |
| Claude 调用失败 | 命令不匹配 | 「请设置正确的 `CLAUDE_CODE_COMMAND`」 |
| `OPENCLAW_ROOT` 待检测 | 路径没设置或设置错 | 「请重新定位真实 OpenClaw 目录」 |
| 扫描文件数为 0 | 指到了空目录或日志不在范围内 | 「请列出 OPENCLAW_ROOT 下的日志和配置文件」 |
| 页面打不开 | 8511 未监听或安全组未放行 | 「请检查 8511 监听和云安全组」 |
| 页面有建议但没修复 | 正常，本项目只生成建议 | 「请不要声称已治理，除非真实修改并复核」 |

---

## 12. 本节课带走什么

- 会让 OpenClaw 收集真实审计材料
- 会让 Claude Code 生成结构化安全报告
- 会区分“建议已生成”和“生产已治理”
- 会用证据决定是否暂缓上线
