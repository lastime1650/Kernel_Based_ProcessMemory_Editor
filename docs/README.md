# 📚 문서 · Documentation

**Driver 2.6.0.1 · Kernel Studio 3.2.2 · ManualV4 protocol v3**

| 지금 찾는 것 | 바로 가기 |
|---|---|
| 프로젝트 소개, 화면, 설치·빌드 시작 | [프로젝트 README](../README.md) |
| 코드에서 실제 구현 찾기 | [🧭 Source map](SOURCE_MAP.md) |
| 요청 경로, IOCTL 번호, 구조체 계약 | [🔌 HTTP API / IOCTL ABI](reference/API_ABI.md) |
| 무엇을 검증했고 어떻게 재현하는가 | [🧪 Validation](VALIDATION.md) |
| 변경 내용 | [📋 Changelog](../CHANGELOG.md) |
| 공개 소스와 현재 원본의 파일별 대조 | [🔎 SHA-256 manifest](reference/SOURCE_SHA256.tsv) |

> [!TIP]
> 처음이라면 README → 기능 안내 → 소스 지도 순서가 편합니다. ABI 표부터 읽어도 되지만, 그건 메뉴판 대신 식재료 명세서로 저녁을 고르는 취향에 가깝습니다. 🍽️

## 언어별 안내

| Language | Overview | Guide |
|---|---|---|
| 한국어 | [README](../README.md) | [GUIDE](ko/GUIDE.md) |
| English | [README](../README.en.md) | [GUIDE](en/GUIDE.md) |
| 简体中文 | [README](../README.zh-CN.md) | [GUIDE](zh-CN/GUIDE.md) |
| Español | [README](../README.es.md) | [GUIDE](es/GUIDE.md) |

## 기능별 구현 안내

- [패널 상세 안내](../kernel_control_panel/README_ko.md)
- [메모리 검색](../kernel_control_panel/MEMORY_SCAN_WORKSPACE.md)
- [디스어셈블리](../kernel_control_panel/DISASSEMBLY_WORKSPACE.md)
- [DLL / PE / PDB 워크벤치](../kernel_control_panel/DLL_WORKBENCH.md)
- [EPROCESS 읽기 워크벤치](../kernel_control_panel/EPROCESS_README.md)
- [재현 가능한 DLL/PDB 시험 예제](../samples/README.md)

> [!IMPORTANT]
> API 계약과 검증 범위는 이 디렉터리의 최신 reference를 기준으로 확인하세요. 로컬에서 빌드한 파일 버전과 현재 로드된 드라이버 버전은 각각 확인해야 합니다.

Translations preserve code identifiers, commands and API names. The shared references describe the current source snapshot; historical entries in the changelog retain their original version and date.
