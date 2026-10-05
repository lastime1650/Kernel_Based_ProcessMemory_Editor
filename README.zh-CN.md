# Kernel Based Process Memory Editor

[한국어](README.md) · [English](README.en.md) · [简体中文](README.zh-CN.md) · [Español](README.es.md)

本项目将 Windows 内核驱动 **SampleKernel1** 与本地网页工作区 **Kernel Studio** 结合，用于进程内存分析与编辑。通过浏览器搜索内存、编辑字节和结构体、转储映像、分析 PE、管理线程与寄存器，并查看或恢复修改。

![Kernel Studio 仪表盘](docs/images/01-dashboard.jpg)

> 四种语言支持的是**仓库文档**。原程序界面仍为韩语；导入的程序源码及原有韩语文档未修改。源码驱动版本为 v2.3，API 为 v3.0.0；截图环境中已加载的驱动是 v2.2。

## 主要功能

- 通过内核 IOCTL 查询进程和内存映射，读取、写入、分配、释放、修改保护属性及复制内存。
- 数值、字符串、AOB、结构体的 New/Next/Unknown 扫描，SQLite 候选存储，分页或全部候选浏览及 CSV 导出。
- ReClass 风格字节编辑、嵌套指针、Watch/数值冻结、Wide View（Beta）。
- 最大 16GiB 转储、MEM_IMAGE 集合、进度、取消、继续与哈希校验。
- PE 导入/导出、可选 PDB 符号、汇编、控制流图与保守的 C 伪代码。
- 指令补丁校验、Undo/Redo、结构体/类、项目工作区、修改日志与采样时间线。
- 线程上下文、优先级、CPU 掩码、硬件断点、DLL 加载及单参数函数调用。

## 快速开始

需要 Windows x64 和 64 位 Python。本地验证使用 Python 3.14.5。请先按[构建与驱动加载说明](docs/zh-CN/GUIDE.md#构建与驱动加载)准备兼容的已签名驱动。网页服务器不会自动安装或加载驱动。

```powershell
git clone https://github.com/lastime1650/Kernel_Based_ProcessMemory_Editor.git
cd Kernel_Based_ProcessMemory_Editor
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r kernel_control_panel\requirements.txt
cd kernel_control_panel
..\.venv\Scripts\python.exe -m uvicorn server:app --host 127.0.0.1 --port 8005
```

打开[本地界面](http://127.0.0.1:8005/)，依次执行 **选择目标 → 内存扫描 → New → Next → 保存地址 → Hex/Watch/分析**。若 8005 已有服务器，请使用该服务或选择其他端口。原有 `python server.py` 和 `start_panel.bat` 默认使用 **8000**。

## 文档

| 内容 | 链接 |
|---|---|
| 安装、构建、使用流程、API 与故障排查 | [中文指南](docs/zh-CN/GUIDE.md) |
| 所有源码文件及职责 | [源码地图](docs/SOURCE_MAP.md) |
| 完整 HTTP 路由与 IOCTL | [API / ABI 列表](docs/reference/API_ABI.md) |
| 验证依据与限制 | [验证记录](docs/VALIDATION.md) |
| 贡献、支持、安全与许可证状态 | [贡献](CONTRIBUTING.md) · [支持](SUPPORT.md) · [安全](SECURITY.md) · [许可证状态](LICENSE_STATUS.md) |
| 修改记录 | [CHANGELOG](CHANGELOG.md) |

## 验证与发布范围

2026-10-05–06，在副本上通过了 **314 项回归测试**、x64 **Release/Debug 构建**、**DIA 工具构建**及针对已加载驱动的 **7 项只读诊断**。这不代表重新加载 v2.3 后的全部真实写入测试。CI 在 Windows 上执行现有模拟回归测试。

37 个 ABI 标识符中，网页工作区连接 34 个；两个事件操作及线程终止不在界面中提供。PID 搜索和返回列表存在上限，运行中内存读取与补丁并非原子操作。详细限制请参阅指南。

包含全部源码、测试、静态界面和项目配置。IDE 缓存、构建产物、用户 DLL/PDB、扫描数据库、转储、运行日志及生成报告保留在本地副本，不公开提交。源码哈希与文件覆盖情况见[源码地图](docs/SOURCE_MAP.md)。

**使用范围：**仅用于自己拥有或获准分析的测试进程。API 没有认证层，请使用 loopback 绑定。仓库不提供公开发布签名包或安装器，尚未指定开源许可证。
