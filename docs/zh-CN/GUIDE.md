# 安装与使用指南

[中文概览](../../README.zh-CN.md) · [한국어](../ko/GUIDE.md) · [English](../en/GUIDE.md) · [Español](../es/GUIDE.md)

**驱动 2.6.0.1 · Kernel Studio 3.2.2 · Windows x64 · ManualV4 ABI v3 / 2104 字节**

> [!IMPORTANT]
> 配套使用更新后的驱动和面板。仪表盘显示的是设备中**已加载的版本**，不是磁盘 `.sys` 的版本。构建成功与驱动加载成功是两项检查。

## 1. 准备与构建

使用 Windows x64、64 位 Python、Visual Studio 2022 C++ 工具和匹配的 Windows SDK/WDK。开发验证使用 Python 3.14.5 与 VS 2022 Professional。ARM64 配置不代表已支持 ARM64。界面为韩语，下文保留韩语控件名称以便定位。

在仓库根目录的 Developer PowerShell 中运行：

```powershell
msbuild SampleKernel1.sln /t:Rebuild /m /p:Configuration=Release /p:Platform=x64 /p:SignMode=Off
msbuild SampleKernel1.sln /t:Rebuild /m /p:Configuration=Debug /p:Platform=x64 /p:SignMode=Off
```

输出为 `x64\Release\SampleKernel1.sys` 和 `x64\Debug\SampleKernel1.sys`。`SignMode=Off` 生成未签名文件，不会使 Windows 自动接受驱动。请使用适合测试系统的签名与部署配置；源码仓库不是认证安装包。

替换已加载驱动时，先关闭客户端，并根据需要恢复冻结、补丁及断点，再进行常规驱动更新。控制设备为 `\\.\MyDriver`。

## 2. 启动 Kernel Studio

```powershell
cd kernel_control_panel
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python kernel_studio.py
```

打开 [http://127.0.0.1:8005/](http://127.0.0.1:8005/)。`kernel_studio.py` 和 `server.py` 默认均为 **8005**。可用 `python kernel_studio.py --port 8006` 指定其他端口。服务器仅绑定本机回环地址；设备和管理状态属于单个进程，应只运行一个 worker。源码服务器用 Ctrl+C 停止。

打包时，在构建环境安装 PyInstaller，然后从此目录运行 `tools\build_release.cmd`。输出位于 `dist/3.2.2/KernelStudio`；版本目录已存在则建立带时间戳的新子目录。关闭旧面板后运行新的 `KernelStudio.exe`。

> [!NOTE]
> `/api/build` 描述正在运行的面板，`/api/status` 返回实际连接的驱动信息。替换文件不会更新仍在运行的面板或仍已加载的驱动。

## 3. 选择目标、读取与缩小范围

打开 **대상 프로세스 선택**（选择目标），按名称/PID 搜索，或直接输入 PID。选择时重新检查存活与创建身份。发现机制按 4 的步长探测 PID 范围，不是完整系统枚举。默认范围为 4–65,536，也可扩大范围。

在 **메모리 스캔**（内存扫描）选择类型、条件与范围。运行 **New**，在自己的测试程序中改变数值，然后用新值或 Increased 等条件运行 **Next**。**Live** 更新显示值，不改变 Next 的基线。

可将结果传给 **메모리 편집**（内存编辑）、Watch、结构体或反汇编。类型写入、冻结、分配、释放、保护和线程操作会改变真实目标。应用修改时应预览字节，并检查回读与恢复状态。

> [!TIP]
> 书签记住的是地址，不是进程的寿命。昨天的地址，今天使用前也要重新确认目标。

## 4. 正确解读 ManualV4

在 **ManualV4** 选择目标，输入绝对磁盘路径，例如 `C:\DLLs\Example.dll`，然后提交 **커널 매핑 요청**。面板在发出内核请求前验证进程身份。刷新页面或任务列表不会再次提交映射请求。

| 结果 | 解读 |
|---|---|
| `state: mapped` 且内核成功响应通过验证 | 按当前请求契约完成映射 |
| 正数 `failcode` | `manual_map_protocol.h` 中的确切失败分支 |
| `failmessage` | 分支处观测到的 API/验证详情、实际值与 NTSTATUS |
| 响应缺失 / 无效 | 结果不确定，诊断为 `null`，不会自动重试 |

v3 数据包为 **2104 字节**。`failcode` 偏移 **1076**，`failmessage[1024]` 偏移 **1080**。输入诊断全零；成功返回代码 0 和空消息。即使清理改变最终状态，也保留首次代码/消息。消息为 ASCII/ANSI，NUL 结束，尾部填零；超长时标记 `[truncated]`。

遇到 **119**，检查节名/RVA、请求地址/大小/保护属性及 `ZwProtectVirtualMemory` 状态。调用前字段还包含：

- `pre_page`：首个区域的状态、类型、保护属性，以及对页对齐请求的覆盖范围。
- `pre_dynamic`：动态代码策略 Flags 与解码位。
- `pre_protection`：保护级别、类型、Audit 和 Signer。

> [!IMPORTANT]
> 新增的策略/页面查询只读，不改变保护参数或策略。`UNAVAILABLE` 表示无法得到有效查询结果。首个区域不一定代表全部请求范围，观测也不是原子快照。

> [!WARNING]
> HTTP 200、任务查询或 IOCTL 传输成功不等于映射成功。请检查已验证的任务状态、NTSTATUS 与诊断。`ACCESS_DENIED` 是返回状态，不是已证实的内部策略原因。失败 API 的输出字段可能仍保留初始化值。

API/ABI 详情见[参考](../reference/API_ABI.md)，当前韩语功能说明见[面板指南](../../kernel_control_panel/README_ko.md)。

## 5. 保存位置、符号与限制

打包应用将 assets、symbols、workspaces 和 dumps 保存在可执行文件旁的 `data/` 下。`KERNEL_STUDIO_DATA_DIR` 可修改根目录。源码运行保留源码模式位置；旧数据不会自动复制到新软件包。

PDB 分析使用 `native/pdb_symbols.exe` 与 Microsoft DIA x64 运行库。辅助程序通过 `native/build_pdb_symbols.cmd` 构建，默认路径为 VS 2022 Professional。其他安装需调整构建路径，并用 `KERNEL_STUDIO_DIA_DLL` 指定不同的 DIA 运行库。PDB GUID/Age 必须与映像匹配。

普通传输上限为 1MiB；驱动读取分块不超过 4KiB。大范围转储可达 16GiB，流式写入磁盘。零填充缺口记录在清单中，不能视为原始字节。映像转储保持映射 RVA 布局，不重建磁盘 PE。取消等待当前请求结束；同一服务器会话内的恢复检查进程身份与部分文件完整性。

## 6. 测试与故障排查

在仓库根目录构建合成样例，再运行面板测试：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File samples/build_fixture.ps1
cd kernel_control_panel
python -m unittest discover -p 'test*.py' -v
node test_manual_v4_ui.js
python native/manual_map/run_selftest.py
```

完整 discovery 需要样例与 DIA 辅助程序。原生 harness 使用当前映射器与模拟 DDI，不打开真实驱动或目标。`test_driver_readonly.py` 可显式对已加载驱动运行七个只读诊断；`test_driver_all_ioctl.py` 的范围相同，并非完整真实 IOCTL 测试。见[样例说明](../../samples/README.md)与[验证范围](../VALIDATION.md)。

| 症状 | 检查项目 |
|---|---|
| 设备连接失败 | 已加载服务、签名接受情况、管理员权限与 `\\.\MyDriver` |
| 面板看起来旧 | 实际运行的文件/源码目录、`/api/build`，再刷新浏览器 |
| 进程未显示 | 扩大发现范围或输入 PID |
| ManualV4 数据包不匹配 | 更新后的驱动和面板、v3 / 2104 字节 ABI |
| 映射被拒绝 | NTSTATUS、failcode、failmessage 与有效的调用前观测 |
| `pre_*: UNAVAILABLE` | 查询状态、返回长度和内容验证；不能假设策略为零 |
| PDB 不可用 | 辅助程序、DIA、GUID/Age 与运行库路径 |

公开问题请使用合成复现，不上传私人转储或用户 DLL/PDB。许可证信息见 [LICENSE_STATUS.md](../../LICENSE_STATUS.md)。
