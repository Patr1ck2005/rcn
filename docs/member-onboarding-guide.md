# 成员安装、连接与 Agent 接续

更新：2026-10-28。本文维护公开预览版成员安装与接入操作；[成员概览](member-guide.md)说明使用边界，[运行环境与适配器](adapters-and-runtimes.md)说明操作员需另行准备的批准与科学执行条件，[任务包指南](member-task-package-guide.zh.md)维护任务准备细节。

## 三步开始

1. **双击 Setup 安装。** 使用管理员提供的同批 `RCN-Member-Setup.exe` 与校验信息，沿默认位置、当前 Windows 用户完成安装。Python、依赖和帮助已包含，无需另装开发环境或先运行 CMD／“准备连接”脚本；此处不选择机器邀请。安装完成打开“Research Compute Network”桌面入口。
2. **导入本人私密连接包。** 在“连接与 Agent 配置”选择管理员私发的个人连接 ZIP，核对预览中的成员、计算中心和连接方式，勾选本人确认，再点击“确认并接入中心”。客户端安全保存连接与登录。组内受管 SSH 和 HTTPS 均走这条流程；已有个人 HTTPS 登录资料时，也可展开高级入口登录。
3. **选择 Agent 并生成配置。** 连接后核对当前个人身份，选择 Codex、Claude Code、DSH 或“其他 Agent”，填写便于识别的名称，点击生成配置。客户端自动登记该实例独立受限凭据，无需找管理员索取第二份 token。复制接入说明给本机 Agent，或下载 ZIP，按说明引用到项目现有规则中。

仅提交任务不要求贡献电脑，也不要求本机安装 COMSOL。机器贡献在安装、登录之后另行选择，见下方“可选：贡献计算与暂停”。

Setup 是无个人秘密的通用软件；个人连接包只私发本人，可能包含个人凭据、受限连接密钥和主机校验资料。不要把连接包或解包内容放进群公告、Git、截图或 Agent 对话。Agent 接续使用生成的无凭据配置和说明，不需要读取私密包明文。文件哈希用于核对完整性，不等于机构代码签名。

## 导入状态与原编号恢复

导入首先只展示归属预览；确认后才核验连接并保存个人登录。客户端显示等待确认、校验、保存、完成或失败状态，并保留原 `import_id`。不要把“已选文件”当作连接完成。

- 连接确认仍在执行时等待原操作，不重复点击或切换另一份身份。
- 响应丢失、页面重开或网络中断后，使用“恢复同一导入”读取原记录；结果未知时先读回，不重新建立另一份导入。
- 原记录明确失败时，按错误码处理后选择“按原编号重试导入”；读回的是中断的校验／保存阶段时，可在确认归属后“继续原导入”。
- 显示“需要恢复本机状态”时，保留原编号、身份和任务目录，运行自检并把脱敏报告交给本机 Agent 或管理员。不要删除状态文件来解除冲突。

连接包属于另一成员、中心信任或本机目录身份不一致时，先核对原资料。已有任务、Agent 根目录和结果不通过更换用户 ID 或机器 ID 迁移。连接成功只证明本人身份与通道已核验，具体任务仍受项目、固定 Profile、科学合同和资源门槛约束。

## 给本机 Agent 的接续

先读取导出的 `AGENT_ACCESS.md`、对应 Agent 的接入说明和 `rcn-agent-access.json`。按 JSON 中的 `command_prefix` 调用；该前缀包含此 Agent 专属 `--state-root`，不要自行换成桌面登录根或另一实例。引用可加入现有 `AGENTS.md`、`CLAUDE.md` 或 Agent 的项目说明，保留原有科学规则。

安装版提供稳定的用户入口 `<客户端状态根>/bin/RCN-Agent.exe`，默认状态根为 `%LOCALAPPDATA%\ResearchComputeNetwork\member-client`。它读取本机 `active-version.json` 并核验所选安装文件，升级后仍沿用该入口。开发／旧版配置可能返回 Python 模块前缀，按实际导出值使用；不要硬编码某个版本目录或别人的用户名。

Agent 的起步顺序：

| 命令（追加在实际 `command_prefix` 后） | 目的与结果 |
| --- | --- |
| `help list --format json` | 列出当前安装版公开帮助；不需要中心连接或个人登录。 |
| `help read member-getting-started --format markdown` | 离线阅读安装、连接与恢复说明。 |
| `help read member-task-package --format markdown` | 离线阅读任务包准备要求。 |
| `context` | 读取当前入口、公开帮助和本机原操作编号，建立接续上下文。 |
| `doctor` | 按需检查本机身份、安装、连接和提交能力，返回脱敏分阶段报告。失败或未登录可返回非零退出码，仍须读取 JSON。 |
| `capabilities` | 在线核对本人允许的 Profile、提交策略和额度；缓存身份不等于在线授权。 |
| `status` | 核对当前登录和中心连接；离线时保留未知状态。 |

下面仅用于定位默认安装的公开帮助；执行当前 Agent 的任务时，仍使用导出前缀中的专属状态根：

```powershell
$clientRoot = Join-Path $env:LOCALAPPDATA 'ResearchComputeNetwork\member-client'
$rcnAgent = Join-Path $clientRoot 'bin\RCN-Agent.exe'
& $rcnAgent help list --format json
& $rcnAgent help read member-getting-started --format markdown
```

`doctor`、`context` 和任务操作不创建第二套控制面或通用远端 shell。公开帮助直接读取安装包，受保护手册仍需中心连接与相应角色。Agent 应保留一次检查的结果，复制／导出时复用它；不要为维持在场反复运行诊断。

配置中的凭据仅供这台电脑的当前 Windows 用户使用。每个 Agent 共享本人的授权与限额，但有独立可撤销凭据。在“停用此 Agent”确认撤销中心凭据，只停用该实例；“移除此 Agent 的本机登录”是另一个操作，不能当作中心撤销。结果未知时刷新原 Agent 状态，不生成另一实例来绕过确认。

## 准备、提交与回收任务

把项目目录和[任务包指南](member-task-package-guide.zh.md)交给本机 Agent。已有编译请求和对应输入时，Agent 可离线打包；只有 MPH 时，先由项目侧补齐扫描、Study、求解和输出合同，不由客户端猜测。

任务包的真实命令入口是安装版解释器中的 `research_compute_network.cli`：

```powershell
$clientRoot = Join-Path $env:LOCALAPPDATA 'ResearchComputeNetwork\member-client'
$active = Get-Content -LiteralPath (Join-Path $clientRoot 'active-version.json') -Raw | ConvertFrom-Json
$memberPython = $active.python_path
if (-not $memberPython) {
    $memberPython = Join-Path (Split-Path -Parent $active.pythonw_path) 'python.exe'
}
& $memberPython -B -m research_compute_network.cli submission-package-build --help
& $memberPython -B -m research_compute_network.cli submission-package-build compiled-request.json --input-root prepared-inputs --output member-task.zip
```

上例的请求和输入必须已由来源项目准备；使用正确绝对路径或在准备目录运行。`prepared-inputs` 是包含 `inputs` 的父目录，具体目录形态及三个输入的当前合同只在[任务包指南](member-task-package-guide.zh.md#项目侧要交付什么)维护。打包不上传、不创建 Job、不启动 COMSOL。`RCN-Agent.exe` 提供的命令以其 `--help` 为准，任务包构建不追加到它的 Agent 子命令后。

成员在“提交任务”选择任务 ZIP，核对归属、项目、计算项和输出要求，再确认原预览。Agent 也可按实际前缀调用：

```text
plan --package <任务ZIP的绝对路径>
submit --operation-id <plan返回的原UUID>
watch --operation-id <同一UUID> --timeout-s 60
collect --operation-id <同一UUID>
```

这些行是追加在 `command_prefix` 后的参数，不是独立可执行文件。Agent 依次运行并读取回执，不能把占位符直接作为真实编号。缺少计算单元或耗时依据时向项目负责人核实；仪表盘 ETA 不代替科学申报。

上传、查询、下载沿同一操作 UUID；`watch` 超时仅表示本轮观察结束。传输开始不等于文件收齐；以原回执的完成状态、逐文件 SHA 与本机结果目录为准。下载中断会保留断点，明确暂停保持暂停；所有文件已在本机时，可在中心暂时离线期间继续本地运输核验。正式科学导入、有效性判断及写入研究数据仍归来源项目。

## 离线帮助、诊断与恢复

“帮助与文档”和“连接自检与恢复”在未登录、离线或本机配置无法读取时仍可进入。点击“重新自检”后按失败阶段和下一步提示处理；“复制诊断给 Agent”或“下载诊断 JSON”复用这次已返回的脱敏报告。保留诊断编号和检查时间，不发送原始登录文件或私钥。

| 现象 | 处理方式 |
| --- | --- |
| 安装文件校验失败、稳定入口提示不可用 | 保留状态与结果，使用管理员核验过的同一 Setup 修复安装；入口仍不可用时可直接阅读本指南。不要编辑发行清单或关闭完整性核验。 |
| 本机端口被其他服务占用 | 按诊断核对占用者及原客户端；不杀所有进程、不另起第二实例或自动换端口。 |
| 中心离线、网络暂不可达 | 读离线帮助和本机记录，保留原导入／任务／下载编号，恢复网络后读回原状态。 |
| SSH 组件缺失或本人的受管连接未就绪 | 自检明确给出可恢复项后，按界面确认范围执行本机安全修复。组件供应可能需要网络、UAC 或重启；取消后保留状态，客户端不自动重启电脑。 |
| 个人登录已撤销 | 请管理员提供有效的本人连接包；反复网络重试不能恢复已撤销凭据。 |
| 用户、连接包归属、中心指纹或状态根冲突 | 核对原 Windows 用户、包归属和原安装位置，交给管理员核对。不要覆盖他人的配置、接受未知主机指纹或递归放宽目录权限。 |
| 没有项目提交权或 Profile 不可用 | 由管理员核对本人策略及实际项目／科学执行合同；登录成功不扩展计算权限。 |

`doctor --repair` 是 Agent 可用的显式恢复选项，仅在已读自检且确认对应本机恢复范围后运行；不是自动执行所有 `next_actions`。它不恢复机器接活、不更改他人进程或科学任务。诊断失败不是删除本机状态的理由。

## 可选：贡献计算与暂停

愿意贡献电脑时，安装和登录后进入“贡献计算”，使用管理员单独私发的机器邀请，核对本人机器、COMSOL 环境、工作根、CPU／内存预算、允许时间和接活意愿。机器邀请与个人连接包用途不同，不互换，也不在通用 Setup 安装步骤选择。

需要专用普通执行账户、受管组件或系统更改时，按界面展示的 Windows 确认执行。新 v2 邀请在本人同意、机器身份、固定 runtime 与通道就绪后自动准入，科学验收独立异步；旧 v1／手工节点保留原门禁与已签署策略。首次入网和科学验收由操作员核对，不能由“安装完成”推定。

可以先只提交任务，日后再贡献。本人暂停、计算时间与资源预算仍由机主控制；重登录、重装或升级不自动解除明确暂停。共享机保留至少四分之一的调度线程预算，不能把它描述为操作系统 CPU 时间隔离。不要为修复个人连接而开启计算贡献或更改正在运行的研究任务。

## 升级、卸载与验收边界

使用同批新 Setup 升级，继续原 Windows 用户和状态根。稳定 Agent 入口跟随经核验的当前版本，保留原身份、Agent 实例、任务记录、结果与明确暂停。升级后先核对原操作状态，不重新规划已受理任务。

通过 Windows 的程序卸载入口卸载。程序先等待相关传输与计算排空；未排空或软件目录身份无法确认时保留安装并提示稍后重试。卸载保留个人身份、任务历史与结果，不等于撤销中心凭据、删除科研数据或完整退网。退出成员关系、撤销某个 Agent、停止机器贡献分别按对应授权处理，历史任务证据保留。

源码测试、安装产物核验和真实成员使用是不同证据。公开预览未宣称已经通过独立外部成员的干净 Windows 安装、UAC、重启／升级／卸载、换网、外部 HTTPS 或科学试算与回收验收。具体发行内容与已验证范围见[本版变更说明](releases/0.15.0a5.md)。
