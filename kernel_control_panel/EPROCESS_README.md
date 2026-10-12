# EPROCESS 구조체 보기 (2.4 / 20261010)

현재 PID를 선택하면 `0x825`로 EPROCESS 주소와 프로세스 시작 키를 조회합니다. **EPROCESS 구조체** 메뉴는 네이티브 OS의 아키텍처, NT 버전, 기본 빌드, 제품 종류, 서비스 팩, 공개 릴리스 이름을 로컬 프리셋과 대조합니다. 일치하지 않거나 판별이 모호하면 다른 릴리스로 대체하지 않습니다.

프리셋은 `presets/eprocess/manifest.json`과 30개 JSON에 저장되어 있습니다. Vergilius의 x64 링크 트리에서 발견된 8개 OS 계열을 수집했고, 각 파일에 출처 URL, 다운로드 시각, 원문 해시 및 사실 기반 필드·오프셋·크기·비트 위치를 기록했습니다. 포인터가 가리키는 메모리는 따라가지 않습니다. 값으로 포함된 중첩 구조체는 2단계까지 펼칠 수 있습니다. 실행 중에는 인터넷을 사용하지 않습니다.

현재 호스트는 Windows 11 25H2 / 26200.9457이며, 26200에 연결된 25H2 프리셋은 `sizeof(_EPROCESS)=0x840`입니다. Vergilius는 누적 업데이트(UBR)마다 별도 레이아웃을 보증하지 않으므로 화면에는 실제 UBR과 기본 빌드 일치 범위를 함께 표시합니다. 읽은 `UniqueProcessId`도 선택 PID와 맞는지 검증합니다.

`0x826`은 PID를 다시 조회해 주소와 시작 키를 확인하고, 참조된 동일 EPROCESS에서만 바이트를 읽습니다. 기존 일반 메모리 읽기 API의 사용자 주소 제한을 확장하지 않았습니다. OS별 객체 크기 제한을 커널에 생성해 두었으며, 미지원 빌드·부분 읽기·대상 불일치에서는 해석할 데이터를 반환하지 않습니다. Windows 10 1703보다 오래된 프리셋도 보관하지만, 현재 드라이버가 이미 사용하는 API의 지원 범위 때문에 커널 읽기 크기 목록은 1703 이상입니다.

화면이 보이고 드라이버·PID·프리셋이 유효하면 10ms 목표로 자동 모니터링합니다. 한 번에 한 요청만 진행하며 처리 시간만큼 실제 간격이 늘어날 수 있습니다. 화면은 실제 시작 간격과 왕복 시간을 표시합니다. 다른 메뉴로 이동, 숨김, 선택 해제, 연결 끊김 또는 읽기 실패 시 중단합니다. 값은 관측 표본이며 필드를 잠그는 원자적 스냅샷은 아닙니다. 검색·그룹 펼치기·변경 강조·원본 HEX·일시정지 및 1회 읽기를 지원합니다.

드라이버 로드는 사용자가 직접 수행합니다. 새 드라이버를 로드한 다음 현재 소스의 `start_panel.bat`로 패널을 다시 시작하고 브라우저를 새로 고치면 메뉴를 사용할 수 있습니다. 기존 배포 폴더에 있던 EXE와 드라이버는 이번 변경으로 다시 패키징하지 않았습니다. Frozen EXE를 새로 패키징할 때는 `static` 폴더와 함께 `presets` 폴더를 번들에 포함해야 합니다.

프리셋 갱신 및 커널 크기 목록 재생성:

```powershell
python tools/sync_eprocess_presets.py --help
python tools/sync_eprocess_presets.py --cache-dir C:/Temp/vergilius-eprocess-cache --type-depth 2
python tools/generate_eprocess_bounds.py
```

사이트 자료를 갱신한 뒤에는 생성된 커널 헤더를 포함해 드라이버를 다시 빌드합니다. 프리셋과 헤더의 동기화·무결성·범위 검사는 `test_eprocess_bounds.py`가 수행합니다.

코드 기반 회귀검사 (드라이버 연결이나 로드 없음):

```powershell
python -m unittest test_process_object test_process_object_read test_eprocess_workbench test_eprocess_presets test_eprocess_bounds
```

시험의 데이터 저장 위치는 `KERNEL_STUDIO_DATA_DIR`로 별도 폴더를 지정할 수 있습니다. 커널 및 C++ 클라이언트의 PID/주소/시작 키·크기·부분 응답·참조 균형 검사도 native API를 모의한 별도 회귀검사에서 확인했습니다.
