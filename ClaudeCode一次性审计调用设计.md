# Claude Code 一次性审计调用设计

## 为什么用 steer one-shot

本项目不需要多轮对话。OpenClaw 只需要把一次审计所需的材料整理成审计包，然后让 Claude Code 一次性输出结构化报告。

这样更适合云端执行官 Skill：

- 输入明确
- 输出稳定
- 容易记录审计证据
- 不需要用户手动聊天
- 便于转成报告和工单

## 输入

Security Guardian 会生成：

```text
openclaw_security_console/runtime/security_audit_bundle.json
openclaw_security_console/runtime/claude_code_audit_prompt.md
```

审计包包含：

- OpenClaw 根目录
- 开放端口摘要
- 配置快照
- 脱敏后的日志证据
- 已命中的风险模式
- Claude Code 审计约束

审计约束：

```text
只审查审计包内容
不要读取真实密钥
不要执行修复动作
输出风险位置、证据、影响、建议和上线前判断
```

## 推荐 Prompt

```text
请读取 security_audit_bundle.json，对当前 OpenClaw 做上线前安全审计。

要求：
1. 只基于审计包中的真实证据判断。
2. 不要假设生产配置已经被修复。
3. 不要输出真实密钥明文。
4. 每个风险必须包含编号、等级、位置、证据、影响、建议。
5. 如果审计范围不足，请明确指出缺少哪些日志或配置。
6. 最后输出是否存在 high / critical 上线阻断项。
```

## 实际调用方式

默认命令：

```bash
claude -p "<prompt>"
```

如果云端 OpenClaw 的 Claude Code 调用方式不同，可以设置：

```bash
export CLAUDE_CODE_COMMAND="claude -p"
```

Security Guardian 会记录：

- Claude 调用是否成功
- 调用 Prompt 文件路径
- Claude 原始输出摘要
- JSON 解析错误或 CLI 错误

如果 Claude Code 没有成功调用，系统会生成 `CC-CALL-FAILED` 风险项，不会假装已经完成 Claude 审计。

## 输出结构

```json
{
  "summary": {
    "overallRisk": "CRITICAL",
    "findingCount": 3,
    "scannedFiles": 42
  },
  "findings": [
    {
      "id": "CC-001",
      "severity": "critical",
      "location": "config/openclaw.yml",
      "evidence": "已脱敏证据",
      "risk": "风险影响",
      "recommendation": "建议动作"
    }
  ],
  "recommendedOrder": [
    "优先处理 critical/high 风险发现",
    "处理后重新执行 Security Guardian 复检"
  ]
}
```

## 和 Security Guardian 的关系

Claude Code 负责审计判断。

Security Guardian 负责：

- 收集真实证据
- 脱敏
- 生成审计包
- 展示 Claude Code 风险发现
- 把风险拆成告警规则建议和治理建议
- 做最终复检结论

Security Guardian 不负责自动修改生产配置。
