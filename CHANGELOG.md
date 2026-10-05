# 변경 기록 / Changelog / 修改记录 / Registro de cambios

## 2026-10-06 — All-in-one README expansion

- 한국어: 네 언어 README를 전체 구현 설명서로 확장했습니다. 7개 설계도, 79개 Studio 동작, 기본 UI 정의 76개, 세션 action, 37개 IOCTL, 45개 ABI 구조/337개 필드, 네이티브 보조 구조, 요청 모델과 전체 74개 경로를 본문에 넣었습니다. 누락된 PUT 자산 업로드 경로를 API 목록에 추가했습니다. 원본 소스는 변경하지 않았습니다.
- English: Expanded all four READMEs with seven diagrams, 79 Studio operations, 76 base UI tools, session actions, 37 IOCTLs, 45 ABI layouts/337 fields, native support structures, request models and all 74 routes. Restored the omitted PUT asset-upload route in the reference. Original source remains unchanged.
- 简体中文：四语 README 扩展为完整实现文档，包含 7 图、79 Studio 操作、76 基础 UI、会话 action、37 IOCTL、45 ABI/337 字段、原生辅助结构、请求模型及全部 74 路由。补入遗漏 PUT 上传，原源码未改。
- Español: Ampliación de cuatro README: siete diagramas, 79 operaciones, 76 herramientas UI, acciones de sesión, 37 IOCTL, 45 estructuras ABI/337 campos, estructuras nativas, modelos y 74 rutas. Se añadió PUT de archivos omitido; código original intacto.

## 2026-10-06 — Source import and documentation

### 한국어

- 기존 저장소 이력을 유지하며 SampleKernel1 소스·테스트·UI를 바이트 변경 없이 가져왔습니다.
- 네 언어 README와 설치·사용·API·문제 해결 안내, 실제 웹 UI 캡처, 소스/ABI 목록을 추가했습니다.
- Git 제외 규칙, 기여·지원·보안·라이선스 상태, 이슈/PR 템플릿과 Windows 회귀 CI를 추가했습니다.
- 복사본의 314개 회귀 시험, x64 Release/Debug, DIA 도구 빌드와 로드된 v2.2의 읽기 전용 진단 7개를 확인했습니다. 소스 v2.3의 전체 실전 변경 시험은 수행하지 않았습니다.

### English

- Preserved existing Git history and imported sources, tests and UI without byte changes.
- Added four-language READMEs/guides, actual UI screenshots and source/ABI inventories.
- Added Git exclusions, contribution/support/security/license notices, issue/PR templates and Windows regression CI.
- Verified 314 regressions, x64 Release/Debug, DIA helper compilation and 7 read-only diagnostics on loaded v2.2. Full live mutation coverage of source v2.3 was not run.

### 简体中文

- 保留 Git 历史，按原字节导入源码、测试及界面。
- 添加四语 README/指南、真实界面截图、源码/ABI 列表。
- 添加 Git 排除、贡献/支持/安全/许可证说明、问题/PR 模板及 Windows 回归 CI。
- 验证 314 项回归、x64 Release/Debug、DIA 工具及已加载 v2.2 的 7 项只读诊断；未运行源码 v2.3 的全部真实修改测试。

### Español

- Se conservó el historial Git y se importaron código, pruebas e interfaz sin cambiar bytes.
- Se añadieron README/guías en cuatro idiomas, capturas reales e inventarios del código/ABI.
- Se añadieron exclusiones Git, documentos comunitarios, plantillas de incidencias/PR y CI de regresión en Windows.
- Se verificaron 314 regresiones, x64 Release/Debug, auxiliar DIA y 7 diagnósticos de lectura en v2.2 cargado. No se probó toda la modificación real de v2.3.
