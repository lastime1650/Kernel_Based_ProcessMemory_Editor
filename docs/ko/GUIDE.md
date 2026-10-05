# 설치와 사용 안내

[한국어 시작](../../README.md) · [English](../en/GUIDE.md) · [简体中文](../zh-CN/GUIDE.md) · [Español](../es/GUIDE.md)

## 구성과 요구사항

브라우저 → FastAPI → `KernelOnlyBridge` → `DeviceIoControl` → `SampleKernel1.sys` 순서로 대상에 접근합니다. 장치 경로는 `\\.\MyDriver`입니다. Python은 장치 연결에 `CreateFileW`·`DeviceIoControl`·`CloseHandle`을 사용합니다. 현재 서버의 대상 읽기·검색·메모리 맵은 커널 경로를 이용하며, NumPy 비교와 PE·명령 해석은 반환된 바이트로 유저모드에서 계산합니다. `memory_scanner.py`에는 사용되지 않는 이전 Win32 검색 구현도 남아 있으므로 현재 서버 연결과 구분하세요.

- Windows x64, 64비트 Python, C++ 개발 도구와 Windows SDK/WDK.
- 확인한 환경: Python 3.14.5, Visual Studio 2022 Professional, SDK 10.0.26100.0, WDK 10.0.26100.6584.
- `requirements.txt`: FastAPI, Uvicorn, psutil, Capstone 5, Keystone 0.9.2, NumPy. 패키지 범위는 원본 그대로이며 고정된 재현용 lock 파일은 아닙니다.
- 솔루션은 ARM64 구성을 선언하지만 현재 컨텍스트·원격 호출 구현에 x64 의존성이 있습니다. ARM64 지원을 검증하거나 보장하지 않습니다.
- UI 번역은 추가하지 않았습니다. 아래 번역 설명에서 한국어 메뉴 이름을 그대로 찾을 수 있습니다.

## 빌드와 드라이버 로드

[Microsoft WDK 안내](https://learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk)에 맞는 Visual Studio/SDK/WDK 조합을 준비하고 Developer PowerShell에서 저장소 루트로 이동합니다. 확인된 조합은 위 환경이며 모든 최신 도구 조합을 시험한 것은 아닙니다.

```powershell
msbuild SampleKernel1.sln /m /p:Configuration=Release /p:Platform=x64
msbuild SampleKernel1.sln /m /p:Configuration=Debug /p:Platform=x64
```

```powershell
sc.exe create SampleKernel1 type= kernel start= demand binPath= "C:\Kernel_Based_ProcessMemory_Editor\x64\Release\SampleKernel1.sys"
sc.exe start SampleKernel1
sc.exe query SampleKernel1
```


앞의 `sc.exe` 예시는 **적절히 서명되고 이 테스트 시스템에서 로드가 허용된 드라이버**를 수동 서비스로 등록하는 명령입니다. 관리자 터미널에서 실제 빌드 경로로 바꾸어 실행합니다. 이미 같은 이름의 서비스가 있으면 중복 생성하지 말고 `sc.exe qc SampleKernel1`로 경로를 먼저 확인하세요. Windows의 서명 요구사항은 [공식 안내](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/driver-signing)를 따르세요. 이 저장소는 서명 인증서나 보안 설정 변경 스크립트를 제공하지 않습니다.

원본 INF에는 제조사·장치 ID·DriverVer 등의 템플릿 항목이 있습니다. 패키지를 공개 배포하려면 이를 별도 작업 복사본에서 구성하고 해당 배포 방식에 맞는 검증·서명을 수행해야 합니다. 이 문서는 INF가 완성된 설치 패키지라고 가정하지 않습니다.

드라이버를 교체할 때 웹 서버와 클라이언트를 종료하고 관리 중인 패치·고정·중단점을 먼저 정리하세요. `sc.exe stop SampleKernel1` 후 새 빌드를 준비하고 다시 시작합니다. 서비스 제거가 필요할 때만 `sc.exe delete SampleKernel1`을 사용합니다. 호출 추적 해제나 드라이버 종료가 이미 실행 중인 대상 함수 스레드를 종료하는 것은 아닙니다.

선택 PDB 도구: `kernel_control_panel/native`에서 `build_pdb_symbols.cmd`를 실행합니다. 원본은 VS 2022 Professional 경로를 고정 사용하며 `image_workbench.py`의 `Symbols.dia`도 같은 경로입니다. 다른 에디션·경로에서는 작업 복사본의 두 경로를 맞추세요. PDB의 CodeView GUID와 Age가 대상 이미지와 모두 일치해야 심볼을 적용합니다.

## 서버 실행

[README의 가상환경 설치 명령](../../README.md#빠른-시작)을 실행한 뒤 [8005 UI](http://127.0.0.1:8005/)를 엽니다. `python server.py`와 배치 파일은 8000을 사용합니다. Uvicorn 명령의 `--port 8005`가 이번 안내의 기준입니다. 단일 worker로 실행하세요. 각 worker는 장치 연결과 관리 상태를 따로 가지므로 다중 worker로 일관된 작업 공간을 제공하지 않습니다. 종료는 서버 터미널에서 Ctrl+C를 사용합니다.

## 1. 연결 확인과 대상 선택

![대시보드](../images/01-dashboard.jpg)

대시보드에서 연결과 버전을 확인합니다. 왼쪽 **대상 프로세스 선택**을 열고 이름/PID로 찾거나 PID를 직접 입력합니다. 선택 전 종료 상태와 생성 식별자를 재확인합니다. 기본 PID 범위는 4~65,536이며 262,144 또는 1,048,576까지 확장합니다. 드라이버에 시스템 전체 PID 열거 명령이 없어 4 단위로 PID를 조회하는 방식입니다. 범위 밖 PID는 직접 입력할 수 있으며 목록의 완전성은 보장하지 않습니다.

대상 전환·재선택은 이전 입력·작업 세션을 초기화할 수 있습니다. 이미 적용한 메모리 변경을 자동으로 복원하는 동작은 아닙니다. 복구가 필요한 변경은 전환 전에 복원하세요.

## 2. 메모리 검색과 값 확인

![메모리 스캔](../images/03-memory-scan.jpg)

**메모리 스캔**에서 형식·조건·값을 선택하고 **New**를 실행합니다. 예를 들어 자신이 만든 테스트 프로그램의 32비트 정수 100을 Exact로 검색하고, 프로그램에서 값을 101로 바꾼 뒤 **Next**에 101 또는 Increased를 지정합니다. 초기값을 모르면 숫자/구조체 Unknown을 사용합니다. **Rescan**은 후보를 좁히지 않고 기준을 갱신하며 읽기 실패 후보는 제거합니다. Live 갱신은 Next의 비교 기준을 바꾸지 않습니다.

숫자, UTF-8/UTF-16LE, `DE AD ?? A? ?F` 같은 AOB와 여러 숫자 필드 구조체를 지원합니다. 64비트 정수·주소는 문자열로 유지합니다. 비정렬 값을 찾으려면 정렬 1바이트, 범위는 시작 포함·끝 제외입니다. 선택 주소를 보관하거나 Hex/디스어셈블리/구조체로 보내세요.

새 스캔 작업 공간은 후보를 SQLite에 저장하여 예전 50,000개 후보 제한을 사용하지 않습니다. 검색 예산은 기본 256MiB, 최대 4GiB이며 부분 검색·실패를 표시합니다. 결과 페이지는 50/100/200/500개, 보관 주소는 세션당 256개입니다. **현재 페이지**와 **전체 후보** 필터/정렬을 구분하고 전체 CSV는 완료된 내보내기 작업으로 받습니다. 이전 호환 스캔 API에는 별도의 50,000개 상한이 남아 있습니다.

## 3. 바이트·Watch·구조체·할당

![메모리 편집](../images/02-memory-editor.jpg)

**메모리 편집**에서 16진수 주소를 열고 바이트/숫자를 더블클릭하거나 형식별 편집을 사용합니다. Ctrl+→로 포인터를 펼치고 Ctrl+←로 접으며, 휠로 연속 주소를 탐색합니다. 최근 편집 복원은 현재 바이트 확인 후 수행합니다. **Watch / 값 고정** 또는 스캔 보관 목록의 Freeze는 반복 쓰기입니다. 종료·PID 교체·실패 시 고정을 해제합니다.

**구조체 / 클래스**는 필드·배열·중첩 구조체·포인터를 정의하고 값을 해석합니다. 변경 묶음은 미리보기 → 원본 확인 → 적용 → 다시 읽기 검증 순서로 처리합니다. **프로젝트 작업 공간**은 주소 위치와 뷰 설정을 저장·재연결하고, **변경 기록 / 묶음**은 복구 자료를, **변화 타임라인**은 샘플 간 변화를 보여 줍니다. 타임라인은 모든 순간의 변경을 포착하는 추적기가 아닙니다.

**메모리 할당**은 문자열(ANSI/UTF-16LE, 종료 NULL 포함) 또는 파일 바이트를 입력받아 크기를 자동 계산하고 읽기/쓰기 메모리를 할당합니다. 커널 쓰기 후 다시 읽어 검증하며 NULL을 포함해 최대 1MiB입니다. 기록된 BaseAddress로 해제할 수 있습니다. 이력 초기화는 실제 메모리를 해제하지 않습니다. **메모리 관리**에서 보호 변경·복사·채우기를 수행합니다. Wide View는 Beta 기능입니다. 쓰기·해제·고정·복원 버튼은 대상 메모리를 실제 변경합니다.

## 4. 덤프·모듈·함수

**메모리 / 이미지 덤프**에서 range/image/images 모드를 선택합니다. 범위는 최대 16GiB, 저장은 `dumps/` 또는 `KERNEL_STUDIO_DUMP_DIR`입니다. 취소는 현재 요청 완료 후 적용하고 `.part`를 보존하며, 같은 서버 세션에서 생성 식별자·파일 길이·해시를 검증해 이어 씁니다. 완료 다운로드 기록은 재시작 후 복구하지만 실행 중인 작업은 복구하지 않습니다. Zero 정책의 읽기 실패 구간은 0으로 채우고 manifest에 기록하므로 원본 바이트로 해석하지 마세요.

이미지 덤프는 RVA 배치이며 파일 오프셋은 VA−이미지 기준입니다. 실행 가능한 디스크 EXE 복원 기능은 아닙니다. **모듈 / PE / 주소**는 모듈·PE 헤더·섹션·가져오기/IAT·내보내기·주소 소속을 확인합니다. MEM_IMAGE 외에는 각 커밋 영역 시작의 유효한 PE 헤더를 검사하며 영역 안 모든 바이트를 검색하는 것은 아닙니다.

**DLL / 이미지 함수**에서 이미지를 선택하고 함수를 분석합니다. DLL 요청 성공 후에도 모듈 목록에서 실제 로드를 확인하세요. PDB는 선택 사항이며 없으면 함수 일부가 누락되거나 형식이 추정됩니다. 함수 호출은 드라이버 2.2 이상, x64 대상의 단일 64비트 정수/포인터 인자와 32비트 종료값에 한정됩니다. 시간 초과·통신 실패 후 자동 재실행하지 않으며 기존 CallId를 조회합니다. 추적 해제는 참조 해제이며 스레드 종료/DLL 언로드가 아닙니다.

## 5. 코드·스레드·중단점

![디스어셈블리](../images/04-disassembly.jpg)

**디스어셈블리**에서 주소·분석 크기·x86/x64를 지정합니다. ASM/Graph의 명령을 더블클릭해 Intel 문법 한 줄을 검증하고 대기 목록에 넣습니다. 원래 길이보다 긴 명령은 거부하고 짧으면 NOP으로 채웁니다. **편집 적용** 전에는 대상에 쓰지 않습니다. 주소 Undo/Redo는 이동, 패치 Undo/Redo는 실제 쓰기입니다. 실패 복구는 원본과 현재 바이트가 일치할 때 진행합니다. C 의사코드는 원본 소스·컴파일 가능한 C 복원을 보장하지 않습니다.

패치는 실행 중 스레드에 대해 원자적이지 않고 명령 캐시 동기화를 제공하지 않습니다. 해당 코드를 실행하지 않는 통제된 상태에서 적용하세요. **스레드 / 레지스터**는 PID·TID·생성 시점 확인, 잠시 정지, 요청 필드 변경, 재조회, 정지 횟수 복원을 수행합니다. 일반 레지스터 18개를 지원하며 XMM/YMM은 포함하지 않습니다. 하드웨어 중단점은 실행/쓰기/읽기·쓰기 및 1/2/4/8바이트를 지원하고 제거 실패 복구 자료를 유지합니다.

## API와 제한

`/docs`는 Swagger, `/redoc`은 ReDoc, `/openapi.json`은 스키마입니다. 아래 PID·주소는 예시이므로 실제 자신이 소유한 테스트 대상 값으로 바꾸세요.

```powershell
Invoke-RestMethod http://127.0.0.1:8005/api/status
Invoke-RestMethod http://127.0.0.1:8005/api/studio/capabilities
$requestBody = '{"operation":"read","args":{"pid":1234,"address":"0x140000000","size":64}}'
Invoke-RestMethod http://127.0.0.1:8005/api/studio/execute -Method Post -ContentType application/json -Body $requestBody
```

HTTP 200만으로 성공을 판단하지 말고 `success`, `result_status`, `driver_response`를 확인하세요. 37개 IOCTL과 모든 경로는 [API/ABI 목록](../reference/API_ABI.md)에 있습니다. 큰 덤프와 스캔 작업은 job ID로 조회하고 취소가 완료되는 시점을 확인합니다.

일반 전송 1MiB, 실제 분할 읽기 4KiB, 일반 표 결과 5,000개, 내부 맵 최대 50,000개, 커널 결과 노드 65,536개, 스레드 64개, 핸들 128개입니다. 전체 맵이 필요한 작업은 맵이 잘리면 거부합니다. 스냅샷 16개·맵 8개·패치 64개는 서버 세션 상태입니다. 프로젝트·변경 로그·PDB·업로드 DLL·덤프는 디스크에, 북마크는 브라우저에 저장합니다. 실행 중인 대상의 순차 읽기는 한 시점의 원자 스냅샷이 아닙니다.

## 문제 해결과 시험

| 증상 | 확인 |
|---|---|
| 장치 연결 실패 | 관리자 권한, 서비스 상태, 서명/로드 오류, `\\.\MyDriver` 존재 여부 |
| 주소 사용 오류 | 프로세스 시작 신원, 주소 범위, Guard/NoAccess, 대상 종료·PID 재사용 |
| 프로세스가 목록에 없음 | 조회 범위 확장 또는 PID 직접 입력; 목록은 완전 열거가 아님 |
| 8005 접속 불가 | Uvicorn 포트·터미널 오류; 원본 기본 포트는 8000 |
| 오래된 UI | 새로 고침/브라우저 캐시와 실행 중인 서버의 실제 경로 확인 |
| PDB 실패 | DIA SDK·도구 빌드·경로·GUID/Age 일치 여부 |
| 부분 검색/Quota 오류 | 범위를 좁혀 다시 New; 예산·목록 상한·읽기 실패 확인 |

전체 회귀 시험 중 3개는 DIA 도구 파일의 존재를 검사하므로 시험 전에 `native/build_pdb_symbols.cmd`로 도구를 빌드하세요. CI는 Windows 2022의 실제 VS 2022 설치를 원본이 요구하는 Professional 경로로 연결한 뒤 도구를 빌드합니다. 이는 임시 CI 환경 설정이며 소스를 변경하지 않습니다.

```powershell
cd kernel_control_panel
python -m unittest discover -p 'test*.py' -v
python test_driver_readonly.py
```

첫 명령은 기존 모의 회귀 시험입니다. 두 번째는 실제 로드된 드라이버에 대해 진단 프로세스 자신의 읽기 전용 조회 7개만 수행합니다. `test_driver_all_ioctl.py`도 같은 진단 진입점이며 전체 변경 IOCTL 시험이 아닙니다. [검증 기록](../VALIDATION.md)의 적용 범위를 확인하세요. 공개 이슈에 덤프·개인 PDB·실제 메모리 내용을 올리지 말고 재현용 테스트 데이터를 제공하세요.
