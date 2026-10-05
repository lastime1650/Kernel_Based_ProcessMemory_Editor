# 검증 기록 / Validation / 验证记录 / Validación

날짜 / Dates / 日期 / Fechas: **2026-10-05–06 (Asia/Seoul)**

## 결과 / Results / 结果 / Resultados

| 항목 / Check / 检查 / Comprobación | 결과 / Result / 结果 / Resultado | 범위 / Scope / 范围 / Alcance |
|---|---|---|
| Existing unittest discovery | PASS: 314 tests | 모의 회귀 / Mocked regression / 模拟回归 / Regresión simulada |
| x64 Release MSBuild | PASS | 별도 복사본 / Separate copy / 独立副本 / Copia separada |
| x64 Debug MSBuild | PASS | 별도 복사본 / Separate copy / 独立副本 / Copia separada |
| DIA `pdb_symbols.cpp` build | PASS | VS 2022 Professional |
| Repository-local fixture regressions | PASS: 314 tests / 5.150s | DIA helper + newly built samples/PanelHello.dll and matching PDB |
| Loaded driver diagnostics | PASS: 7/7 | v2.2 읽기 전용 / v2.2 read-only / v2.2 只读 / v2.2 solo lectura |
| Imported source integrity | PASS: 79/79 SHA-256 | 최초 스냅샷 일치 / Matches initial snapshot / 匹配初始快照 / Coincide con original |
| Source-derived reference | 74 route decorators, 37 IOCTL IDs | `server.py`, `studio_api.py`, `driver_bridge.py` |
| UI observation | 4 screenshots | `http://127.0.0.1:8005/`, no selected target |

## 환경 / Environment / 环境 / Entorno

Windows x64; Python 3.14.5; Visual Studio 2022 Professional; SDK 10.0.26100.0; WDK 10.0.26100.6584.

| Package | Installed version |
|---|---|
| fastapi | 0.142.2 |
| uvicorn | 0.54.0 |
| psutil | 7.2.2 |
| capstone | 5.0.9 |
| keystone-engine | 0.9.2 |
| numpy | 2.5.3 |

## 재현 / Reproduce / 复现 / Reproducir

```powershell
cd kernel_control_panel
powershell -NoProfile -ExecutionPolicy Bypass -File ../samples/build_fixture.ps1
python -m unittest discover -p 'test*.py' -v
python test_driver_readonly.py
```

```text
Ran 314 tests in 5.150s
OK

PASS: driver_status
PASS: process_info
PASS: process_extended
PASS: process_handles
PASS: process_token
PASS: process_threads
PASS: thread_info
```

```powershell
msbuild SampleKernel1.sln /m /p:Configuration=Release /p:Platform=x64
msbuild SampleKernel1.sln /m /p:Configuration=Debug /p:Platform=x64
cd kernel_control_panel/native
.uild_pdb_symbols.cmd
```

## 검증 한계

원본에 쓰지 않고 별도 복사본에서 시험했습니다. 빌드에서 생성한 로컬 테스트 서명은 공개 배포 인증이 아닙니다. 실행 중인 드라이버를 재로드하거나 대상 메모리·레지스터·스레드를 변경하는 실전 시험은 하지 않았습니다. 소스 버전 2.3과 로드 버전 2.2를 구분하세요. ARM64와 모든 Windows 빌드의 동작은 검증하지 않았습니다. 캡처는 실제 로컬 웹 UI이며 대상을 선택하기 전의 사용 도구 화면입니다. 원본의 생성 보고서는 실행 기록이므로 공개 추적에서 제외했습니다. 새 GitHub CI의 결과는 실제 실행 후 별도로 확인해야 합니다.

## Validation limits

Tests ran on the separate copy, without writes to the original. Local build test signing is not public-release certification. The running driver was not reloaded, and no live mutation tests of target memory, registers or threads were performed. Source v2.3 differs from loaded v2.2. ARM64 and every Windows build were not validated. Screenshots show actual local UI controls before target selection. Original generated reports are runtime records excluded from public tracking. The new GitHub CI result must be verified after its actual run.

## 验证限制

测试在独立副本执行，未写入原目录。本地测试签名不是公开发布认证。未重载运行驱动，也未对目标内存、寄存器或线程进行真实修改测试。源码 v2.3 与加载 v2.2 不同。未验证 ARM64 或所有 Windows 构建。截图为选定目标前的真实本地工具界面。原生成报告属于运行记录，不公开追踪。新 GitHub CI 需实际运行后另行确认。

## Límites de validación

Las pruebas se ejecutaron en la copia sin escribir en el original. La firma local de prueba no certifica distribución pública. No se recargó el controlador ni se modificaron memoria, registros o hilos reales. Distinga código v2.3 de controlador cargado v2.2. No se verificó ARM64 ni cada compilación de Windows. Las capturas muestran controles reales antes de seleccionar destino. Los informes originales generados son registros de ejecución excluidos. El resultado del nuevo CI debe confirmarse tras ejecutarlo.

## 깨끗한 체크아웃 / Clean checkout / 干净检出 / Checkout limpio

원본 테스트는 로컬 DLL/PDB 예제에 의존합니다. 공개 저장소의 [samples](../samples/README.md)에 보조 소스와 재현 빌드를 추가했습니다. 전체 시험 전에 DIA 도구와 예제를 빌드하세요. 초기 CI에서는 이 외부 예제 의존성이 누락되어 실패했고, 예제 빌드를 추가해 해결했습니다. [GitHub CI 실행 기록](https://github.com/lastime1650/Kernel_Based_ProcessMemory_Editor/actions/workflows/regression.yml)에서 원격 결과를 확인할 수 있습니다.

Original tests depend on a local DLL/PDB fixture. The public repository adds support source and a reproducible build in [samples](../samples/README.md). Build the DIA helper and fixture before full discovery. Initial CI failed because the external fixture was missing; the added fixture build resolves that dependency. Remote results are recorded in [GitHub CI](https://github.com/lastime1650/Kernel_Based_ProcessMemory_Editor/actions/workflows/regression.yml).

原测试依赖本地 DLL/PDB 样例。公开仓库的 [samples](../samples/README.md) 新增辅助源码及可重现构建。完整测试前需构建 DIA 工具和样例。初次 CI 因外部样例缺失失败，新增样例构建解决了依赖。远程结果见 [GitHub CI](https://github.com/lastime1650/Kernel_Based_ProcessMemory_Editor/actions/workflows/regression.yml)。

Las pruebas originales dependen de un DLL/PDB local. El repositorio añade código auxiliar y compilación reproducible en [samples](../samples/README.md). Compile el auxiliar DIA y el ejemplo antes de ejecutar todas las pruebas. El CI inicial falló por la ausencia del ejemplo externo; su compilación añadida resuelve la dependencia. Consulte los resultados remotos en [GitHub CI](https://github.com/lastime1650/Kernel_Based_ProcessMemory_Editor/actions/workflows/regression.yml).
