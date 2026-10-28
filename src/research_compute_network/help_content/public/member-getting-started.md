---
slug: member-getting-started
title: 成员安装、连接与 Agent 接续
summary: GitHub Setup、HTTPS 入组、一次批准后自动配置 Agent；断网保留原申请编号。
audience: public
order: 18
category: workflow
section: 按流程使用
keywords: [安装, HTTPS, join, 配对, Agent, 自检, 离线, 恢复]
related_slugs: [member-task-package, getting-started]
source_refs:
  - document: docs/member-onboarding-guide.md
    section: 三步开始
    kind: public
  - document: docs/member-onboarding-guide.md
    section: Agent 申请与原编号续接
    kind: public
last_reviewed: 2026-10-28
---

# 三步开始

1. 从 [GitHub Releases](https://github.com/Patr1ck2005/rcn/releases) 获取同批 **RCN-Member-Setup.exe** 与 SHA-256，核对后在当前 Windows 用户下安装。Python 和依赖已包含，无需克隆源码或配置开发环境。
2. 在客户端“加入课题组”填写所属组的 HTTPS 中心链接、姓名、设备和 Agent 类型／名称。本组拟用入口是 `https://rcn.my1ab.fyi`，alpha.6 公网 HTTPS 验收仍为 pending；其他部署使用操作员自己的入口。
3. 通过本人联系渠道让管理员核对姓名、设备与配对码，由私有管理入口明确关联已有成员或新建成员。批准一次后，客户端自动保存个人登录、登记独立 Agent 凭据、生成配置并执行一次自检。自检通过后复制说明给本机 Agent。

仅提交任务不要求贡献电脑，也不要求安装 COMSOL。贡献计算在安装后单独进入“贡献计算”，使用自己的邀请并确认时间、资源与接活意愿。重装或登录不会自动恢复已暂停的机器。

# Agent 申请与恢复

安装后，未登录的 Agent 也可调用稳定入口；把示例中心替换为所属组的实际 HTTPS 入口：

```powershell
$rcnAgent = Join-Path $env:LOCALAPPDATA 'ResearchComputeNetwork/member-client/bin/RCN-Agent.exe'
$centerUrl = 'https://compute.example.org'
& $rcnAgent join --center $centerUrl --name '你的姓名' --device-name '你的电脑名称' --agent codex --label '我的 Codex' --wait 120
& $rcnAgent join --status --wait 120
```

替换姓名、设备与 Agent；类型支持 `codex`、`claude`、`dsh`、`generic`。待批准每 5 秒轮询，`--wait 120` 最多等 120 秒；只写 `--wait` 默认 300 秒，上限 3600 秒。超时退出码为 3，只结束本次等待，不取消申请。

响应未知、断网或重启后，`join --status` 读取本机原 `pairing_id`；可加 `--pairing-id '<原 pairing_id>'` 指定原申请。不要用新编号解决未知结果。待批准有效期为 24 小时；拒绝、过期或撤销后不能重放恢复，先与管理员核对。配对码只用于人工核对，秘密保存在当前 Windows 用户的 DPAPI，不能用配对码登录。

退出个人登录会持久暂停自动接续；普通状态查询不重新登录，明确恢复或 `join --status` 才继续。自检中断会续做，失败可显式重试，成功报告复用，不在每轮状态查询重新检查整套安装。

# 给 Agent 的第一步

读取导出的接续说明和 `rcn-agent-access.json`。按照其中的 `command_prefix` 调用命令，不猜测安装路径、不把凭据放进命令参数。

- `context`：当前安装入口、公开帮助目录和本机原操作编号。
- `doctor`：按需检查连接、身份和提交能力；不会创建科学任务。
- `help list`：列出本版本可用的离线帮助。
- `help read member-task-package`：按项目合同准备任务包。
- `capabilities`：核对本人实际可用的 Profile 与提交策略。

接续文件可以引用到项目已有的 `AGENTS.md` 或 `CLAUDE.md`，不要覆盖原项目规则。通用 Agent 只需要能够运行本机命令并读取 JSON。升级后沿用稳定入口和原操作编号。

# 提交和回收

让项目 Agent 读取[任务包准备指南](member-task-package)，按项目科学合同生成 ZIP。模型文件本身不等于完整任务；缺少扫描、求解或导出要求时先补齐定义，不能猜测。

客户端依次提供选择任务包、预览、确认上传、进度与下载。中断后继续原操作，不以新建 Job 代替恢复。结果下载与哈希核验完成后，科学导入和判断仍由项目 Agent 完成。

# 有问题时直接在客户端处理

未登录、断网或中心暂时不可用时，也可进入“连接诊断”和“帮助与文档”。点击“重新检查”，按失败阶段的说明处理。点击“复制给 Agent”或导出诊断，即可交给本机 Agent；不需要重复截图或发送 token。

“恢复本机连接”只处理客户端自己的受管连接，不关闭其他软件、不恢复机器接活。SSH 组件缺失时，Windows 可能要求联网、管理员确认或重启；取消后保留原操作，稍后继续。客户端不会自动重启电脑。

个人登录已撤销时，先与管理员核对原身份，按确认重新申请；网络重试不能恢复被撤销的身份。连接 ZIP、手动凭据与 SSH 仅用于高级恢复；旧用户升级保留原身份与通道，不按同名合并或删除原状态重建。看到端口占用、用户身份不符或安装文件变化时，遵循具体提示，不关闭所有进程、不递归放开磁盘权限。

# 升级与卸载

用新 Setup 升级，保留个人身份、任务记录、结果和明确暂停。卸载会先等待正在进行的传输及相关计算排空；完整退网另行撤销授权。移除某个 Agent 的本机登录与撤销中心凭据是不同操作，界面会分别说明结果。

发行哈希用于核对文件完整性，不是机构签名。公网 HTTPS 是本轮必须验收项，当前仍为 pending；陌生 Windows、UAC、重启及真实成员科学试算仍延期。源码、发行物、部署与真实成员验收分别记录。
