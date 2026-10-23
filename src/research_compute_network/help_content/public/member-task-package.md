---
slug: member-task-package
title: 任务包怎么准备
summary: 本机 Agent 调用安装版打包器，成员在客户端核对任务预览、进度和结果。
audience: public
order: 19
category: workflow
section: 按流程使用
keywords: [任务包, ZIP, 打包, Agent, 成员客户端, 提交, MPH, runtime]
related_slugs: [getting-started]
source_refs:
  - document: docs/member-task-package-guide.zh.md
    section: Agent 的最短操作路径
    kind: public
  - document: docs/member-task-package-guide.zh.md
    section: 安装版命令入口
    kind: public
last_reviewed: 2026-10-23
process_steps:
  - label: 项目侧准备
    detail: Agent 按项目科学合同编译请求，准备模型、项目配置与扫描配置。
  - label: 安装版打包
    detail: 调用现有 RCN 打包器生成绑定成员、项目和输入哈希的 ZIP。
  - label: 可视化核对
    detail: 客户端导入 ZIP，核对项目、计算项和导出要求，再按授权确认。
  - label: 原任务续接
    detail: 上传、查询与下载沿同一提交编号，逐文件核验结果。
---

## 从已经有的文件开始

已有 RCN 任务 ZIP：在客户端“提交任务”中选择它，查看预览后确认。

已有项目编译的任务请求 JSON 和输入目录：让本机 Agent 调用打包器。只有 MPH 模型时，先由项目侧定义要算什么、扫描哪些参数和导出哪些物理量，再编译请求。

**“选择任务包”是导入入口。打包器是已随客户端安装的命令；日常操作优先由 Agent 执行，界面用于清楚展示任务、进度和结果。**

## 把这段交给本机 Agent

先读取本项目规则、现行科学合同和来源适配器入口。核对已编译请求及三个输入，不猜测科学参数、Study、耗时或输出要求。使用当前成员安装版本，生成 ZIP 后在客户端核对本人、project、执行 Profile 和工作量；在已有授权内提交，断线继续原提交编号。

项目环境已有 RCN 命令时，入口是：

```powershell
rcn submission-package-build compiled-request.json --input-root prepared-inputs --output member-task.zip
```

成员 Setup 不把 `rcn` 加入全局 PATH。Agent 在本人 PowerShell 中这样定位当前安装版：

```powershell
$clientRoot = Join-Path $env:LOCALAPPDATA 'ResearchComputeNetwork\member-client'
$active = Get-Content -LiteralPath (Join-Path $clientRoot 'active-version.json') -Raw | ConvertFrom-Json
$memberPython = Join-Path (Split-Path -Parent $active.pythonw_path) 'python.exe'
& $memberPython -B -m research_compute_network.cli submission-package-build --help
& $memberPython -B -m research_compute_network.cli submission-package-build compiled-request.json --input-root prepared-inputs --output member-task.zip
```

请求和输入路径由来源项目提供，使用完整路径或先进入对应目录。JSON 保存为 UTF-8 无 BOM。使用本人当前版本的解释器，打包本身无需个人 token、联网或本机 COMSOL。

## 输入根与生成包

`prepared-inputs` 是包含 `inputs` 子目录的父目录。当前兼容的 COMSOL 包要求 `inputs/project.yaml`、`inputs/template.mph` 和唯一一个直接位于 `inputs/` 的扫描配置，均须与请求的哈希一致。

工具在 ZIP 根目录生成 `submission-package.json`。不要手工压缩一个 MPH 当作任务 ZIP，也不要给输出 ZIP 再套外目录。不同几何可以复用运行环境，但科学流程和求解／导出接口仍要受当前执行流程支持。

## 提交、观察与恢复

客户端显示任务包预览、原提交与 Job、计算进度和下载校验结果。Agent 保留原提交编号，上传中断继续上传、下载中断继续核验；明确重新计算时才创建新编号。

缺少分包信息时填写真实计算单元数，不自动猜耗时。结果正式导入与物理分析留在来源项目。成员职责见[开始使用](/help/getting-started)，操作正文见文档来源中的“成员任务包”指南。
