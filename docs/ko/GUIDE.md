# 설치와 사용 가이드

[한국어 개요](../../README.md) · [English](../en/GUIDE.md) · [简体中文](../zh-CN/GUIDE.md) · [Español](../es/GUIDE.md)

**드라이버 2.6.0.2 · Kernel Studio 3.2.3 · Windows x64 · ManualV4 ABI v3 / 2104바이트**

> [!IMPORTANT]
> 새 드라이버와 패널을 함께 사용하세요. 대시보드는 디스크의 `.sys` 파일이 아니라 장치에 **실제로 로드된 버전**을 표시합니다. 빌드 성공과 드라이버 로드 성공은 별도로 확인해야 합니다.

## 1. 준비와 빌드

Windows x64, 64비트 Python, Visual Studio 2022 C++ 도구와 호환되는 Windows SDK/WDK가 필요합니다. 개발 검증은 Python 3.14.5와 VS 2022 Professional에서 수행했습니다. ARM64 구성이 있다는 사실만으로 ARM64 호환성을 보장하지 않습니다. 프로그램 UI는 한국어입니다.

저장소 루트의 Developer PowerShell에서 실행합니다.

```powershell
msbuild SampleKernel1.sln /t:Rebuild /m /p:Configuration=Release /p:Platform=x64 /p:SignMode=Off
msbuild SampleKernel1.sln /t:Rebuild /m /p:Configuration=Debug /p:Platform=x64 /p:SignMode=Off
```

결과는 `x64\Release\SampleKernel1.sys`, `x64\Debug\SampleKernel1.sys`입니다. `SignMode=Off`는 서명 없이 빌드하는 옵션이며 Windows의 로드 허용 설정을 바꾸지 않습니다. 테스트 시스템에 맞는 서명·배포 절차를 사용해야 합니다. 저장소 자체는 인증된 설치 패키지가 아닙니다.

로드된 드라이버를 교체할 때는 클라이언트를 종료하고 필요한 값 고정·패치·중단점을 복구한 뒤 사용 중인 드라이버 업데이트 절차를 따르세요. 제어 장치는 `\\.\MyDriver`입니다.

## 2. Kernel Studio 실행

```powershell
cd kernel_control_panel
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python kernel_studio.py
```

[http://127.0.0.1:8005/](http://127.0.0.1:8005/)를 엽니다. `kernel_studio.py`와 `server.py` 모두 기본 포트가 **8005**입니다. 변경하려면 `python kernel_studio.py --port 8006`을 사용합니다. 서버는 로컬 루프백에만 연결하며 장치·관리 상태가 프로세스마다 따로 있으므로 worker는 하나만 실행합니다. 소스 서버는 Ctrl+C로 종료합니다.

패널 패키지는 빌드 환경에 PyInstaller를 설치한 뒤 이 폴더에서 `tools\build_release.cmd`를 실행해 만듭니다. `dist/3.2.3/KernelStudio`에 수집하며 버전 폴더가 이미 있으면 시각을 붙인 새 하위 폴더를 만듭니다. 기존 패널을 닫고 새 `KernelStudio.exe`를 실행합니다.

> [!NOTE]
> `/api/build`는 실행 중인 패널 정보를, `/api/status`는 연결된 드라이버 정보를 반환합니다. 파일만 교체하면 이미 실행 중인 패널이나 로드된 드라이버는 바뀌지 않습니다.

## 3. 대상 선택 → 읽기 → 범위 좁히기

**대상 프로세스 선택**을 열어 이름/PID로 검색하거나 PID를 직접 입력합니다. 선택 직전에 실행 상태와 생성 시점을 다시 확인합니다. 목록은 PID를 4 단위로 탐색한 결과이며 시스템 전체 열거가 아닙니다. 기본 범위는 4~65,536이고 더 넓은 범위를 선택할 수 있습니다.

**메모리 스캔**에서 자료형·조건·범위를 정합니다. **New**로 시작하고 본인의 테스트 프로그램에서 값을 바꾼 뒤 새 값이나 Increased 등의 조건으로 **Next**를 실행합니다. **Live**는 표시값을 갱신하지만 Next의 기준값을 바꾸지 않습니다.

결과 주소를 **메모리 편집**, Watch, 구조체 또는 디스어셈블리로 전달할 수 있습니다. 쓰기·값 고정·할당·해제·보호·스레드 도구는 실제 대상을 변경합니다. 적용 전에 바이트를 미리 확인하고 적용 후 재읽기·복구 상태를 살펴보세요.

> [!TIP]
> 북마크는 주소를 기억하지 프로세스의 수명을 기억하지는 않습니다. 어제 저장한 주소를 오늘 사용할 때도 대상부터 확인하세요.

## 4. ManualV4 결과 해석

**ManualV4**에서 대상을 선택하고 **DLL 파일 선택**을 누르면 Windows 기본 파일 선택창이 열립니다. 선택한 DLL의 원래 절대경로를 직접 사용하며 파일 바이트를 로컬 패널에 업로드하거나 `assets`에 복사하지 않습니다. 선택 시 파일 존재 여부와 1바이트~64MiB 크기를 확인하고, 커널 요청 직전에 프로세스 시작 키를 다시 확인합니다. **매핑만 수행**을 선택하면 이미지와 보호 속성까지 준비한 뒤 DLL 진입점 호출을 생략합니다. 새 **ManualV4_Viewer**에서 성공 매핑과 일치하는 PDB를 선택해 시작 주소·프로세스 시작 키·PDB GUID/Age 검증 후 함수 주소와 매개변수를 확인할 수 있습니다. 화면이나 작업 목록 새로 고침은 매핑을 다시 요청하지 않습니다.

| 결과 | 의미 |
|---|---|
| 검증된 커널 성공 응답과 `state: mapped` | 현재 요청 계약에 따라 매핑 완료 |
| 양수 `failcode` | `manual_map_protocol.h`에 정의된 실패 분기 |
| `failmessage` | 분기에서 관찰한 API·조건·실제 값·NTSTATUS |
| 응답 없음 / 유효하지 않음 | 미확인, 진단은 `null`, 자동 재시도 없음 |

v3 패킷은 **2104바이트**입니다. `OnlyMapping` BOOLEAN은 기존 reserved DWORD의 첫 바이트(오프셋 **4**)를 사용하므로 나머지 세 reserved 바이트는 0이어야 하고, 이전 요청의 false 동작과 필드 오프셋은 유지됩니다. `failcode`의 오프셋은 **1076**, `failmessage[1024]`는 **1080**입니다. 입력 진단은 모두 0이고 성공 시 코드 0·빈 메시지를 반환합니다. 정리 중 최종 상태가 바뀌어도 최초 코드·메시지는 유지합니다. 문자열은 ASCII/ANSI, NUL 종결과 제로 tail을 사용하며 공간을 넘으면 `[truncated]`를 표시합니다.

**119**라면 섹션 이름/RVA, 요청 주소·크기·보호 속성과 `ZwProtectVirtualMemory` 상태를 확인합니다. 호출 직전 진단에는 다음 내용도 있습니다.

- `pre_page`: 첫 영역의 상태·타입·보호 속성과 페이지 단위 요청 범위 포함 여부.
- `pre_dynamic`: 동적 코드 정책 Flags와 해석한 비트.
- `pre_protection`: 보호 레벨·타입·Audit·Signer.

> [!IMPORTANT]
> 새 정책·페이지 조회는 읽기 전용이며 보호 인자나 정책을 변경하지 않습니다. `UNAVAILABLE`은 유효한 조회 결과를 얻지 못했다는 뜻입니다. 첫 영역이 요청 전체를 대표하지 않을 수 있고 관찰은 원자적 스냅샷이 아닙니다.

> [!WARNING]
> HTTP 200, 작업 조회 성공 또는 IOCTL 전송 성공이 매핑 성공을 뜻하지는 않습니다. 검증된 작업 상태·NTSTATUS·진단을 확인하세요. `ACCESS_DENIED`는 반환 상태이며 운영체제 내부의 특정 거절 원인이 확정됐다는 뜻이 아닙니다. 실패한 API의 출력 필드는 초기값이 남을 수 있습니다.

상세 API/ABI는 [참조 문서](../reference/API_ABI.md), 현재 기능은 [패널 안내](../../kernel_control_panel/README_ko.md)를 참고하세요.

## 5. 저장 위치·심볼·한계

패키지 실행 시 assets·symbols·workspaces·dumps는 실행 파일 옆 `data/` 아래에 저장됩니다. `KERNEL_STUDIO_DATA_DIR`로 루트를 바꿀 수 있습니다. 소스 실행은 소스 모드의 위치를 유지하며 과거 데이터가 새 패키지로 자동 복사되지는 않습니다.

PDB 분석은 `native/pdb_symbols.exe`와 Microsoft DIA x64 런타임을 사용합니다. 도우미는 `native/build_pdb_symbols.cmd`로 빌드하며 기본 경로는 VS 2022 Professional입니다. 다른 설치 환경에서는 도구 경로를 맞추고 DIA 위치가 다르면 `KERNEL_STUDIO_DIA_DLL`을 지정합니다. PDB GUID/Age는 이미지와 일치해야 합니다.

일반 전송은 1MiB, 드라이버 읽기 조각은 최대 4KiB입니다. 대용량 범위 덤프는 최대 16GiB를 디스크로 이어 씁니다. 0으로 채운 누락 구간은 매니페스트에 기록하며 원본 바이트가 아닙니다. 이미지 덤프는 매핑 RVA 배치를 유지하고 디스크 PE를 복원하지 않습니다. 취소는 현재 요청 완료 후 적용하며 같은 서버 세션에서 이어쓰기를 할 때 대상 식별값과 부분 파일 무결성을 확인합니다.

## 6. 테스트와 문제 확인

저장소 루트에서 합성 예제를 빌드한 뒤 패널 테스트를 실행합니다.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File samples/build_fixture.ps1
cd kernel_control_panel
python -m unittest discover -p 'test*.py' -v
node test_manual_v4_ui.js
python native/manual_map/run_selftest.py
```

전체 discovery에는 예제와 DIA 도우미가 필요합니다. 네이티브 harness는 현재 매핑기와 모의 DDI를 사용하며 실제 드라이버·대상에 접근하지 않습니다. `test_driver_readonly.py`는 로드된 드라이버에 명시적으로 실행하는 읽기 전용 진단 7개이고, `test_driver_all_ioctl.py`도 같은 범위입니다. 전체 IOCTL 실전 검사가 아닙니다. [예제 안내](../../samples/README.md)와 [검증 범위](../VALIDATION.md)를 확인하세요.

| 증상 | 확인할 내용 |
|---|---|
| 장치 연결 실패 | 로드 상태·서명 허용·관리자 권한·`\\.\MyDriver` |
| 이전 패널처럼 보임 | 실행 파일/소스 위치·`/api/build` 확인 후 브라우저 갱신 |
| 목록에 대상 없음 | 탐색 범위를 늘리거나 PID 직접 입력 |
| ManualV4 패킷 불일치 | 새 드라이버·패널, v3 / 2104바이트 ABI |
| 매핑 거절 | NTSTATUS·failcode·failmessage와 유효한 직전 조회 |
| `pre_*: UNAVAILABLE` | 조회 상태·길이·내용 검증; 정책이 0이라고 단정하지 않기 |
| PDB 사용 불가 | 도우미·DIA·GUID/Age·런타임 경로 |

공개 이슈에는 개인 덤프나 사용자 DLL/PDB 대신 합성 재현 자료를 사용하세요. 라이선스 상태는 [LICENSE_STATUS.md](../../LICENSE_STATUS.md)에 있습니다.
