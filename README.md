# OpenClaw Claude Code 安全自审计服务

这是第 20 章《企业级数字员工的安全审计与生产治理》的实战项目。

项目模拟一台已经部署在云服务器上的 OpenClaw。OpenClaw 会收集自己的运行日志、配置快照、Skill 权限、Token 用量和治理状态，然后通过 **steer one-shot** 调用 Claude Code 进行安全自审计。Claude Code 输出风险报告，Security Guardian 根据报告执行治理动作，最终生成上线前安全审计结论。

## 一、项目目标

本项目训练的是：

- OpenClaw 如何收集自己的安全审计材料
- Claude Code 如何基于日志和配置快照定位风险
- 如何输出风险位置、证据、影响和修复建议
- 如何启用监控告警
- 如何执行控制面封堵、Skill 隔离、密钥轮换、denyList 和 Token 熔断
- 如何完成最终越权审计并判断是否允许上线

它不是攻击工具，也不是从零搭建 OpenClaw 的工程。

## 二、核心流程

```text
云服务器上的 OpenClaw
  ↓ 收集日志、配置快照、Skill 记录、Token 用量
生成 security_audit_bundle.json
  ↓ steer one-shot
Claude Code 审查审计包
  ↓ 输出
security_audit_report.md / security_audit_report.json
  ↓
Security Guardian 展示报告并执行治理动作
  ↓
最终越权审计与上线结论
```

## 三、启动方式

推荐使用和前面课程一致的 dashboard 启动脚本：

Linux 云服务器：

```bash
cd /root/projects/Security-Guardian
chmod +x run_dashboard.sh
./run_dashboard.sh
```

云服务器脚本默认监听：

```text
0.0.0.0:8511
```

这意味着只要云安全组 / 防火墙放行 TCP `8511`，公网即可访问：

```text
http://101.47.152.44:8511/dashboard.html
```

Windows 本地：

```powershell
cd "D:\Openclaw\Security Guardian"
.\run_dashboard.cmd
```

本机访问：

```text
http://127.0.0.1:8511/dashboard.html
```

如果部署在云服务器，并且已经开放或转发 `8511` 端口，访问形式为：

```text
http://101.47.152.44:8511/dashboard.html
```

如果不使用 dashboard 脚本，也可以运行：

```powershell
.\run-conda-env1.bat
```

或：

```powershell
.\run-local.bat
```

## 四、课堂操作顺序

页面中按顺序执行：

1. **分析云端日志**  
   OpenClaw 生成审计包，并通过 steer one-shot 交给 Claude Code。页面会生成并展示审计报告。

2. **启用监控告警**  
   将 Token 泄露、Skill 外传、Token 用量异常转成持续监控告警。

3. **封堵控制台**  
   启用强鉴权、Origin 校验、会话过期和敏感操作保护。

4. **隔离 Skill**  
   将社区 Skill 放入最小权限沙盒，禁止读取密钥和财务原始库，默认拒绝网络出站。

5. **密钥轮换**  
   吊销疑似泄露的旧 Token 和旧业务 API Key，签发短期凭证。

6. **denyList / 熔断**  
   配置高危命令黑名单、敏感文件黑名单、每日 Token 上限和单任务 Token 上限。

7. **最终越权审计**  
   验证 OpenClaw 是否还能越权读取、外传、关闭安全策略、使用旧 Token 或超额消耗 Token。

## 五、Claude Code 调用方式

本项目默认采用：

```text
steer one-shot
```

含义是：OpenClaw 不和 Claude Code 多轮聊天，而是把审计包作为一次性任务交给 Claude Code。

点击 **分析云端日志** 后，会生成：

```text
openclaw_security_console/runtime/security_audit_bundle.json
openclaw_security_console/runtime/security_audit_report.md
openclaw_security_console/runtime/security_audit_report.json
```

当前版本为了课堂稳定性，Claude Code 输出由本地逻辑模拟。真实接入时，只需要把 `openclaw_security_console/app.py` 中的模拟审计逻辑替换成实际的 steer / Claude Code 调用即可。

## 六、目录说明

```text
Security Guardian/
├── README.md
├── run_dashboard.cmd
├── run-conda-env1.bat
├── run-local.bat
├── openclaw_security_console/
│   ├── app.py
│   ├── data/
│   └── skills/
├── openclaw-audit-sample/
│   ├── openclaw运行快照.yml
│   └── ClaudeCode审计请求模板.md
├── checklists/
│   └── OpenClaw生产上线安全核查表.md
├── 课堂运行脚本.md
├── 项目设计说明.md
├── ClaudeCode一次性审计调用设计.md
└── 云端访问部署说明.md
```

## 七、云服务器部署说明

如果要给外界访问，推荐用固定端口：

```text
8511
```

启动：

```powershell
.\run_dashboard.cmd
```

访问：

```text
http://服务器IP:8511/dashboard.html
```

如果使用 Nginx 或云平台端口转发，可以把外部域名或公网链接转发到：

```text
127.0.0.1:8511
```

更详细说明见：

```text
云端访问部署说明.md
```

## 八、最终交付物

课程结束后，学员应能拿到：

- Claude Code 云端日志审计报告
- Claude Code 监控告警
- OpenClaw 治理动作记录
- 最终越权审计结果
- `OpenClaw生产上线安全核查表.md`

## 九、安全边界

当前项目使用模拟日志和模拟数据。

真实接入 OpenClaw 时，请注意：

- 不要把真实 API Key 直接交给 Claude Code
- 不要把真实 SSH 私钥交给 Claude Code
- 不要展示客户明文数据
- 审计包应使用脱敏日志和配置快照
- 页面不应长期裸露公网
- 生产环境建议加 IP 白名单、Basic Auth、VPN 或企业 SSO

## 十、一句话总结

本项目演示的是：

> OpenClaw 在云服务器上调用 Claude Code 对自己做安全自审计，Claude Code 输出风险报告，Security Guardian 执行治理，最终判断数字员工是否可以进入受控无人值守运行。
