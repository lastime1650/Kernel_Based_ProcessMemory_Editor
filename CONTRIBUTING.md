# 기여 / Contributing / 贡献 / Contribuciones

## 한국어

한국어·영어·중국어·스페인어 이슈와 PR을 받습니다. 오류는 OS 빌드, Python/SDK/WDK/드라이버 버전, 기대 결과, 실제 결과, 최소 재현 절차를 포함하세요. 소유한 테스트 프로세스로 재현하고 개인 덤프·PDB·토큰은 제외하세요. 기능 제안은 문제와 예상 흐름을 먼저 설명하세요.

작업 브랜치에서 작은 변경을 만들고 `kernel_control_panel`에서 `python -m unittest discover -p 'test*.py' -v`를 실행하세요. ABI 변경 시 C++ 요청 구조체·Python ctypes·클라이언트·검증을 함께 검토하세요. 읽기 실패, 부분 쓰기, PID/TID 재사용, 반환 버퍼 해제와 복구 원본 보존을 확인하세요. 커널 변경은 별도 테스트 환경에서 빌드·실전 검증하고 검증하지 않은 범위를 PR에 명시하세요. 네 언어의 README·GUIDE를 같은 의미로 유지하세요. 원본 외부 폴더를 수정할 필요는 없습니다.

CI는 모의 회귀 시험이며 드라이버 설치·로드·전체 실전 IOCTL 검증은 수행하지 않습니다. 존중하는 언어로 기술적 근거를 설명하세요. [라이선스 상태](LICENSE_STATUS.md)를 확인하고 제3자 코드는 출처·사용 조건을 명시하세요.

## English

Issues and PRs may be written in Korean, English, Chinese or Spanish. Include OS build, Python/SDK/WDK/driver versions, expected/actual behavior and minimal reproduction. Use owned test processes; omit private dumps, PDBs and tokens. Feature requests should explain the problem and workflow.

Make focused changes on a working branch and run `python -m unittest discover -p 'test*.py' -v` inside `kernel_control_panel`. ABI changes must consider C++ packets, Python ctypes, clients and validation together. Cover read failure, partial writes, PID/TID reuse, returned-buffer release and preservation of recovery originals. Build/test kernel changes in a dedicated environment and disclose unverified scope. Keep the four READMEs and guides semantically aligned. No edits to an external original source folder are required.

CI runs mocked regressions, without driver installation/loading or complete live IOCTL coverage. Communicate respectfully with technical evidence. Review [license status](LICENSE_STATUS.md); identify provenance and usage terms for third-party code.

## 简体中文

可用韩语、英语、中文、西班牙语提交问题和 PR。注明 OS 构建、Python/SDK/WDK/驱动版本、预期/实际结果及最小复现。在自己拥有的测试进程中复现，不提供私人转储、PDB 或令牌。功能建议先说明问题和流程。

在工作分支做小范围修改，在 `kernel_control_panel` 运行 `python -m unittest discover -p 'test*.py' -v`。ABI 修改需同时核对 C++ 包、Python ctypes、客户端和验证。检查读取失败、部分写入、PID/TID 重用、返回缓冲区释放及恢复原件保留。内核修改应在专用环境构建和实测，并说明未验证范围。保持四种 README 和指南语义一致，无需修改外部原始目录。

CI 仅执行模拟回归，不安装/加载驱动，也不覆盖全部真实 IOCTL。尊重他人，用技术依据沟通。查看[许可证状态](LICENSE_STATUS.md)，注明第三方代码来源及使用条件。

## Español

Se aceptan incidencias y PR en coreano, inglés, chino o español. Incluya compilación OS, versiones Python/SDK/WDK/controlador, resultado esperado/real y reproducción mínima. Use procesos de prueba propios y omita volcados privados, PDB y tokens. Explique el problema y flujo al proponer funciones.

Realice cambios acotados en una rama y ejecute `python -m unittest discover -p 'test*.py' -v` en `kernel_control_panel`. Los cambios ABI requieren revisar paquetes C++, ctypes Python, clientes y validación juntos. Compruebe fallos de lectura, escrituras parciales, reutilización PID/TID, liberación de buffers y conservación de originales para recuperación. Compile/pruebe cambios del kernel en un entorno dedicado e indique lo no verificado. Mantenga coherentes los cuatro README y guías. No es necesario editar el directorio original externo.

CI ejecuta regresiones simuladas; no instala/carga el controlador ni cubre todos los IOCTL reales. Dialogue con respeto y evidencia técnica. Revise el [estado de licencia](LICENSE_STATUS.md) e indique procedencia y condiciones del código de terceros.
