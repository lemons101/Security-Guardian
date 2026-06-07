# Claude Code 一次性审计调用设计

## 1. 为什么不用多轮对话

安全审计任务不适合做成聊天式多轮问答。

更合适的方式是一次性任务调用：

```text
OpenClaw 收集审计材料
  ↓
生成 security_audit_bundle.json
  ↓
通过 ACP 或 steer 交给 Claude Code
  ↓
Claude Code 生成 security_audit_report.md / .json
  ↓
OpenClaw 读取报告并展示
```

这样有几个好处：

- 输入边界清楚
- 输出格式稳定
- 可审计、可复跑
- 不需要人工连续对话
- 更适合放进生产治理流水线

## 2. OpenClaw 需要准备什么

OpenClaw 先生成一个审计包：

```text
runtime/security_audit_bundle.json
```

内容包含脱敏后的材料：

```json
{
  "target": "openclaw-prod-01",
  "runtime": "OpenClaw + Claude Code",
  "config_snapshot": {
    "websocket_bind": "0.0.0.0:7070",
    "require_auth": false,
    "check_origin": false,
    "token_budget_enabled": false
  },
  "skills": [
    {
      "name": "reconcile-plus",
      "source": "community-market",
      "signed": false,
      "requested_paths": ["secrets", "finance"],
      "network_egress": true
    }
  ],
  "logs": [
    {
      "time": "2026-06-07 08:14:01",
      "source": "openclaw-control",
      "level": "critical",
      "message": "Access token observed in websocket query string"
    }
  ],
  "token_usage": {
    "last_20_minutes": 184000,
    "daily_limit_enabled": false
  }
}
```

注意：

- 不放真实 API Key
- 不放真实 SSH 私钥
- 不放客户明文数据
- 只放风险证据和脱敏摘要

## 3. steer 调用方式

如果 OpenClaw 环境支持 steer，可以把 Claude Code 当成一次性审计执行器。

任务指令可以是：

```text
你是 OpenClaw 生产安全审计员。

请读取 runtime/security_audit_bundle.json，对当前 OpenClaw 数字员工进行上线前安全审计。

请输出两个文件：

1. runtime/security_audit_report.md
2. runtime/security_audit_report.json

报告必须包含：
- 风险编号
- 风险等级
- 具体位置
- 日志证据
- 影响说明
- 修复建议
- 验证方式
- 是否允许上线

不要读取审计包之外的文件。
不要输出真实密钥。
不要执行修复动作，只生成审计报告。
```

这个任务只需要一次调用，不需要后续对话。

## 4. ACP 调用方式

如果走 ACP，可以把请求建模成一次 agent task。

请求结构可以是：

```json
{
  "task": "openclaw_security_audit",
  "mode": "one_shot",
  "input_files": [
    "runtime/security_audit_bundle.json"
  ],
  "output_files": [
    "runtime/security_audit_report.md",
    "runtime/security_audit_report.json"
  ],
  "instructions": "审查 OpenClaw 审计包，输出风险位置、证据、影响、建议和上线结论。",
  "constraints": [
    "只读取 input_files",
    "不读取真实密钥",
    "不执行修复动作",
    "不访问公网"
  ]
}
```

Claude Code 返回后，OpenClaw 只需要读取输出文件并展示。

## 5. 输出 JSON 建议格式

```json
{
  "target": "openclaw-prod-01",
  "overall_risk": "critical",
  "allow_launch": false,
  "findings": [
    {
      "id": "CC-001",
      "severity": "critical",
      "location": "control_plane.websocket_bind",
      "evidence": "websocket_bind=0.0.0.0:7070",
      "impact": "控制面可能被远程接管",
      "recommendation": "启用强鉴权、Origin 校验，并限制控制面入口",
      "verification": "未授权请求应返回 401/403"
    }
  ],
  "next_actions": [
    "吊销旧 Token",
    "隔离社区 Skill",
    "启用 denyList",
    "启用 Token 熔断"
  ]
}
```

## 6. 推荐方案

本课程项目建议采用：

```text
steer one-shot
```

而不是聊天式多轮对话。

ACP 可以作为进阶企业集成方案，但本章实战默认使用 steer，因为：

- 调用链更短
- 更容易解释
- 更容易本地演示
- 不需要额外协议服务
- 输出文件路径清楚，方便页面读取

Claude Code 的职责是：

```text
读审计包 → 生成报告 → 写入文件
```

OpenClaw 的职责是：

```text
收集证据 → 调用 Claude Code → 展示报告 → 执行治理动作
```
