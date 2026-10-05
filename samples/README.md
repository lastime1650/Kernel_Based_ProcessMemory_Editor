# 테스트 예제 / Test fixture / 测试样例 / Ejemplo de prueba

## 한국어

`PanelHello.cpp`는 원본 테스트가 기대하는 예제 DLL/PDB를 재현하는 보조 소스입니다. 원본 프로젝트에는 없고, 로컬 예제 소스에서 별도로 가져왔습니다. 저장소 루트에서 `powershell -NoProfile -ExecutionPolicy Bypass -File samples/build_fixture.ps1`을 실행하세요. Visual Studio 2022 C++ 도구가 필요합니다. x64 DLL과 일치하는 PDB를 `samples/`에 생성하므로 원본 테스트의 외부 절대 경로를 사용하지 않습니다. 생성 바이너리는 Git에서 제외합니다.

회귀 시험은 PE, export, unwind, 실제 DIA/PDB 기호와 `InternalFormat`, `HelloWorld(void*)`, 데이터 export `g_HelloResult`를 검사합니다. 대상 접근은 모의 구현이며 CI는 DLL을 대상에 로드하거나 함수를 실행하지 않습니다.

## English

`PanelHello.cpp` reproduces the DLL/PDB fixture expected by the original tests. It is an added support source imported separately from the local example, not part of the original project. From the repository root run `powershell -NoProfile -ExecutionPolicy Bypass -File samples/build_fixture.ps1` with Visual Studio 2022 C++ tools installed. It generates an x64 DLL and matching PDB under `samples/`, avoiding the tests' external absolute-path fallback. Generated binaries are ignored by Git.

Regressions inspect PE, exports, unwind, real DIA/PDB symbols, `InternalFormat`, `HelloWorld(void*)`, and data export `g_HelloResult`. Target access is mocked; CI neither loads the DLL into a target nor executes its functions.

## 简体中文

`PanelHello.cpp` 重建原测试所需的 DLL/PDB 样例。它是从本地示例单独导入的辅助源码，不属于原项目。在仓库根目录运行 `powershell -NoProfile -ExecutionPolicy Bypass -File samples/build_fixture.ps1`，需要 Visual Studio 2022 C++ 工具。脚本在 `samples/` 生成 x64 DLL 和匹配 PDB，从而避免测试使用外部绝对路径。生成的二进制文件不加入 Git。

回归测试检查 PE、导出、unwind、实际 DIA/PDB 符号、`InternalFormat`、`HelloWorld(void*)` 和数据导出 `g_HelloResult`。目标访问采用模拟实现；CI 不向目标加载 DLL，也不执行其中函数。

## Español

`PanelHello.cpp` reproduce el DLL/PDB que esperan las pruebas originales. Es código auxiliar importado del ejemplo local por separado; no pertenece al proyecto original. Desde la raíz ejecute `powershell -NoProfile -ExecutionPolicy Bypass -File samples/build_fixture.ps1` con las herramientas C++ de Visual Studio 2022 instaladas. Genera un DLL x64 y su PDB en `samples/`, evitando la ruta absoluta externa de las pruebas. Git excluye los binarios generados.

Las regresiones inspeccionan PE, exportaciones, unwind, símbolos DIA/PDB reales, `InternalFormat`, `HelloWorld(void*)` y `g_HelloResult`. El acceso al destino es simulado; CI no carga el DLL en un proceso ni ejecuta sus funciones.
