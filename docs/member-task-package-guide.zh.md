# 成员任务包：Agent 操作与可视化核对

更新：2026-10-23。本文是成员侧 Agent 与项目负责人的操作入口。**平台优先提供清楚的可视化预览、进度和结果；准备、打包及常规操作优先由 Agent 执行。** 成员可以直接使用界面确认与观察，无需手工操作命令行。打包本身不需要管理员权限、个人 token、联网或启动 COMSOL。

## 先判断你手里有什么

| 你手里的文件 | 下一步 |
| --- | --- |
| 项目负责人已给你的 RCN 任务 ZIP | 打开客户端 → **提交任务 → 选择任务包**；直接从“提交与恢复”开始。 |
| 已编译的任务请求 JSON 和对应输入目录 | 让本机 Agent 按“安装版命令入口”运行打包器，再在客户端核对生成的 ZIP。 |
| 只有 COMSOL 的 MPH 模型 | 先由项目侧准备计算定义与已编译请求。打包器不能从一个模型猜出扫描参数、Study、求解方式和需要导出的物理量。 |

**当前客户端的“选择任务包”用于导入 ZIP，不能在那里制作 ZIP。** 打包命令已随客户端安装，但不注册到系统 PATH。Agent 使用安装版解释器调用，不需要另外装 Python，也不需要让成员寻找一个 GUI 打包器。

## Agent 的最短操作路径

成员把本指南和自己的项目目录交给本机 Agent。Agent 先读该项目自己的规则、现行科学合同与已登记来源适配器说明；已编译请求只做核对和打包，不再修改模板、扫描或导出定义。适配器与科学 runtime 由项目负责人另行提供，参见[集成指南](adapters-and-runtimes.md)。

1. 核对是否已有项目侧编译的请求、三个输入、正确提交成员和 project；只有 MPH 时先准备科学定义与来源适配。
2. 从本人客户端的 `active-version.json` 定位安装版 Python，先读取打包命令的 `--help`。
3. 用请求 JSON、**包含 `inputs` 子目录的父目录**和新 ZIP 路径运行打包器；不要把 `inputs` 自己当成输入根。
4. 核对打包成功回执和 ZIP 清单；在客户端导入，查看本人、项目、计算项及导出要求的可视化预览。
5. 在本轮提交授权内确认提交，并沿原操作编号上传、查询和下载核验。界面用于观察与核对，Agent 保留原编号和回执。

打包本身不会上传、创建 Job 或改变计算接活开关。Agent 遇到失败按“常见问题”定位，保留错误和原操作，不重装、不重签身份、不用新编号重复已受理的提交。

## 项目侧要交付什么

已编译请求由该科学项目的 Workbench 或已登记来源适配器准备，必须已经明确提交成员、project、固定执行 Profile、原子计算项、输入清单和输出合同。项目负责人同时交付请求引用的原始输入，不能在编译后悄悄替换模型或扫描文件。

一种可用的目录形态是：

```text
准备好的任务/
  compiled-request.json
  prepared-inputs/             ← 第三步选择这个目录
    inputs/
      project.yaml
      template.mph
      scan.yaml               ← 实际文件名由请求声明，也可以是 JSON
```

请求 JSON 可以是 `PartitionRequest`，也可以是包含 `request` 字段的规划文档，保存为 **UTF-8 无 BOM**。它不是随便取名的参数文件，也不是客户端导出的登录或机器配置。

当前 COMSOL 任务包固定包含**三个输入文件**：`inputs/project.yaml`、`inputs/template.mph` 和唯一一个直接位于 `inputs/` 的扫描配置。ZIP 根目录还会由工具自动生成 `submission-package.json`。不要手工修改这个清单或套一层外目录再压缩。

输入内容和逐文件 SHA-256 必须与请求一致。当前客户端接受的 ZIP 最大 16 GiB，未压缩输入总量最大 64 GiB；容量上限不表示可以添加未声明文件。工具生成的是数据包，不能附带要远端执行的 Python、PowerShell、批处理、EXE 或个人凭据。

不同几何结构可使用同一套执行环境；能否执行取决于已支持的科学流程、模型接口、求解与导出合同，以及实际计算机的许可和资源。新科学流程先在项目侧适配一次，已有项目批准范围内的正常 Job 无需逐次人工审批。提交电脑无需本地 COMSOL；计算节点须已部署并验收对应的受控 runtime、求解器与许可；公开源码和安装器本身不提供科学执行环境。

## 安装版命令入口

项目侧已有 RCN 命令的环境中可以运行：

```powershell
rcn submission-package-build compiled-request.json --input-root prepared-inputs --output member-task.zip
```

成员 Setup 的嵌入式解释器不注册到全局 PATH。成员侧 Agent 在本人 PowerShell 中找到当前安装入口，再调用同一个打包命令：

```powershell
$clientRoot = Join-Path $env:LOCALAPPDATA 'ResearchComputeNetwork\member-client'
$active = Get-Content -LiteralPath (Join-Path $clientRoot 'active-version.json') -Raw | ConvertFrom-Json
$memberPython = Join-Path (Split-Path -Parent $active.pythonw_path) 'python.exe'
& $memberPython -B -m research_compute_network.cli submission-package-build --help
& $memberPython -B -m research_compute_network.cli submission-package-build compiled-request.json --input-root prepared-inputs --output member-task.zip
```

这些路径中的请求和输入由项目侧准备；先切换到对应准备目录，或使用完整路径。`active-version.json` 中记录的是该用户当前版本的 `pythonw_path`，打包使用同目录的 `python.exe`，不会启动第二个成员后台。不要硬编码别人的用户目录、旧版本目录或管理员 venv。

首次核对所选解释器的发布身份、对应发行清单和 `--help`，之后同版本路径可以复用；不要为每个小操作重装软件或重新采集全机诊断。

## 提交与恢复

成员客户端：**提交任务 → 选择任务包 → 校验预览 → 生成提交预览 → 确认提交 → 上传／继续上传 → 查看计算 → 下载并核验结果**。

预览必须显示你自己的身份和正确项目。缺少分包或耗时信息时填写真实单元数或申报信息，工具不自动猜测耗时。下载的自动恢复、暂停与重试沿用原操作状态；明确暂停后由本人恢复。响应中断、上传中断或重新打开客户端后继续原操作，不重新生成 Job；确实想重新计算时再使用“明确重算”。

下载校验完成后，文件保存在客户端显示的本机目录。正式导入研究数据集与物理分析仍由来源项目负责。

## Agent 使用本机客户端接口

Agent 可以通过同一客户端接口操作，不必模拟每一次页面点击。中心登录仍由本机客户端管理，
无需读取或重新打印保存的个人 token。先以带 CookieJar 的 HTTP 会话请求本机
`http://127.0.0.1:18765/local/v1/capabilities`，这次准备请求不发送 `Origin` 头，核对 `mode=member-client` 并保留返回的会话 cookie；
再读取 `/local/v1/session`，核对本人身份、连接和可执行操作状态。请求固定回环地址，保留客户端的同源边界。

| 本机接口 | Agent 要做什么 |
| --- | --- |
| `POST /local/v1/packages` | 上传 ZIP 原始字节，使用 `Content-Type: application/zip` 和编码后的 `X-RCN-Filename`；取得 `package_id` 与预览。 |
| `PUT /local/v1/operations/{uuid}` | 使用返回的 `package_id` 规划；仅在已确认需要时提供真实 `requested_unit_count` 或 `estimated_seconds_per_item`。 |
| `POST /local/v1/operations/{uuid}/confirm` | 在本轮授权内确认同一规划，取得原 Job。 |
| `POST /local/v1/operations/{uuid}/upload` | 上传或继续原上传，不换任务编号。 |
| `GET /local/v1/operations/{uuid}` | 核对原状态及进度；没有新事件时由程序等待，不用模型不断查询。 |
| `POST /local/v1/operations/{uuid}/collect` | 启动或续接下载与逐文件核验。 |

导入相同 ZIP 时若返回既有 `operation_id`，直接续接它。首次新规划在调用前保存 UUID，响应丢失时
查原记录，不能再生成一份 UUID。查询所有本机历史可用 `GET /local/v1/operations`。
客户端重启会换本机会话 cookie，重新执行只读会话准备，然后继续原提交编号；不重签个人 token。
上传与下载在后台执行，POST 成功仅表示已受理。程序通过原操作的 GET 等待
`upload.state == "complete"` 或 `collection.state == "complete"`，失败时保留错误及原编号；
下载完成后的本机结果目录在 `collection.directory`。不能把上传／下载已启动当成已经完成。
这些步骤与可视化页面使用同一个协议，不另开一套提交或科学执行链路。

## 常见问题

| 看到的问题 | 怎样处理 |
| --- | --- |
| 找不到 RCN 当前安装入口 | 用安装客户端的同一个 Windows 账户运行；先核对 `active-version.json`。不要改用另一用户或全局 Python。 |
| 只有 MPH，没有已编译请求 | 请项目负责人先准备该模型的计算定义和请求；不把文件名改成 JSON。 |
| 找不到 `inputs/project.yaml` 或模型 | 第三步选 `inputs` 的父目录，检查文件名与请求声明。 |
| SHA-256／文件大小不匹配 | 输入在编译后发生变化；由项目侧用当前正确输入重新编译请求。不要手改清单里的哈希。 |
| ZIP 归属其他成员／项目不对 | 项目侧为正确提交成员和已授权 project 准备请求；不共享别人的包和 token。 |
| 原位置已有不同 ZIP | 换一个新的输出文件名，保留旧包；工具不覆盖另一份任务。同内容重复打包可复用原包。 |
| 不支持的 Profile、仿真流程或输入数量 | 按当前三个输入和支持的执行流程准备；新流程先做项目侧适配。 |

## 后续入口

[成员使用指南](member-guide.md)说明个人连接与可选机器贡献；[集成指南](adapters-and-runtimes.md)说明项目适配器与科学 runtime；[安全约定](security.md)说明凭据、受控执行和机主授权。本文的公开任务包指南随成员端安装，中心离线时仍可阅读；受保护内容继续由中心按当前身份授权。
