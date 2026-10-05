# HTTP API / IOCTL ABI

[문서 / Docs / 文档 / Documentación](../README.md)

## 사용 / Usage / 使用 / Uso

한국어: 아래는 소스 데코레이터와 IOCTL 정의에서 추출한 전체 목록입니다. `{action}` 동작의 입력은 연결된 모듈과 [한국어 안내](../ko/GUIDE.md)에 있습니다. 주소·64비트 값은 문자열로 보내고 `success`와 상태값을 확인하세요. `/docs`, `/redoc`, `/openapi.json`에서 실행 중인 서버 스키마를 확인합니다.

English: Complete inventory extracted from source route decorators and IOCTL definitions. Action inputs depend on the linked implementation and [English guide](../en/GUIDE.md). Send addresses/64-bit values as strings; inspect success/status. Runtime schema: `/docs`, `/redoc`, `/openapi.json`.

简体中文：从源码路由装饰器及 IOCTL 定义提取的完整列表。`{action}` 输入参见对应模块和[中文指南](../zh-CN/GUIDE.md)。地址/64 位值用字符串，核对 success/状态。运行模式在 `/docs`、`/redoc`、`/openapi.json`。

Español: Inventario completo extraído de decoradores y definiciones IOCTL. Las entradas de acción dependen de la implementación y [guía española](../es/GUIDE.md). Envíe direcciones/valores de 64 bits como cadenas y compruebe éxito/estado. Esquema: `/docs`, `/redoc`, `/openapi.json`.

## HTTP routes

| Method | Path | Implementation |
|---|---|---|
| GET | `/` | [read_root](../../kernel_control_panel/server.py#L705) |
| POST | `/api/dll/register` | [register_dll](../../kernel_control_panel/server.py#L670) |
| GET | `/api/hwbp/query/{pid}` | [query_hwbp](../../kernel_control_panel/server.py#L651) |
| POST | `/api/hwbp/remove` | [remove_hwbp](../../kernel_control_panel/server.py#L656) |
| POST | `/api/hwbp/set` | [set_hwbp](../../kernel_control_panel/server.py#L644) |
| POST | `/api/memory/alloc` | [alloc_virtual_memory](../../kernel_control_panel/server.py#L354) |
| POST | `/api/memory/copy` | [copy_virtual_memory](../../kernel_control_panel/server.py#L450) |
| POST | `/api/memory/free` | [free_virtual_memory](../../kernel_control_panel/server.py#L358) |
| POST | `/api/memory/inspect` | [inspect_memory_data](../../kernel_control_panel/server.py#L401) |
| GET | `/api/memory/map/{pid}` | [get_memory_map](../../kernel_control_panel/server.py#L455) |
| POST | `/api/memory/pattern_scan` | [pattern_scan](../../kernel_control_panel/server.py#L469) |
| POST | `/api/memory/protect` | [protect_virtual_memory](../../kernel_control_panel/server.py#L363) |
| POST | `/api/memory/read` | [read_virtual_memory](../../kernel_control_panel/server.py#L368) |
| POST | `/api/memory/write` | [write_virtual_memory](../../kernel_control_panel/server.py#L381) |
| POST | `/api/monitor/control` | [monitor_control](../../kernel_control_panel/server.py#L674) |
| GET | `/api/monitor/poll` | [monitor_poll](../../kernel_control_panel/server.py#L678) |
| GET | `/api/process/{pid}` | [get_process_details](../../kernel_control_panel/server.py#L296) |
| GET | `/api/process/{pid}/handles` | [get_process_handles](../../kernel_control_panel/server.py#L312) |
| GET | `/api/process/{pid}/threads` | [get_process_threads](../../kernel_control_panel/server.py#L320) |
| GET | `/api/processes` | [get_process_list](../../kernel_control_panel/server.py#L286) |
| POST | `/api/scan/first` | [scan_first](../../kernel_control_panel/server.py#L489) |
| POST | `/api/scan/next` | [scan_next](../../kernel_control_panel/server.py#L502) |
| POST | `/api/scan/reset` | [scan_reset](../../kernel_control_panel/server.py#L510) |
| GET | `/api/scan/results` | [scan_results](../../kernel_control_panel/server.py#L515) |
| GET | `/api/status` | [get_driver_status](../../kernel_control_panel/server.py#L278) |
| POST | `/api/struct/dissect` | [dissect_memory_structure](../../kernel_control_panel/server.py#L634) |
| POST | `/api/studio/allocation-histories` | [create_allocation_history](../../kernel_control_panel/studio_api.py#L763) |
| DELETE | `/api/studio/allocation-histories/{key}` | [remove_allocation_history](../../kernel_control_panel/studio_api.py#L768) |
| POST | `/api/studio/allocation-histories/{key}/{action}` | [allocation_history_action](../../kernel_control_panel/studio_api.py#L771) |
| GET | `/api/studio/capabilities` | [capabilities](../../kernel_control_panel/studio_api.py#L834) |
| GET | `/api/studio/dump` | [dump](../../kernel_control_panel/studio_api.py#L887) |
| GET | `/api/studio/dumps` | [list_dumps](../../kernel_control_panel/studio_api.py#L905) |
| POST | `/api/studio/dumps` | [start_dump](../../kernel_control_panel/studio_api.py#L898) |
| DELETE | `/api/studio/dumps/{key}` | [delete_dump](../../kernel_control_panel/studio_api.py#L930) |
| GET | `/api/studio/dumps/{key}` | [get_dump](../../kernel_control_panel/studio_api.py#L909) |
| POST | `/api/studio/dumps/{key}/cancel` | [cancel_dump](../../kernel_control_panel/studio_api.py#L916) |
| GET | `/api/studio/dumps/{key}/files/{name}` | [download_dump](../../kernel_control_panel/studio_api.py#L937) |
| POST | `/api/studio/dumps/{key}/resume` | [resume_dump](../../kernel_control_panel/studio_api.py#L923) |
| POST | `/api/studio/editors` | [create_editor](../../kernel_control_panel/studio_api.py#L758) |
| DELETE | `/api/studio/editors/{key}` | [remove_editor](../../kernel_control_panel/studio_api.py#L789) |
| POST | `/api/studio/editors/{key}/{action}` | [editor_action](../../kernel_control_panel/studio_api.py#L792) |
| GET | `/api/studio/events` | [events](../../kernel_control_panel/studio_api.py#L978) |
| POST | `/api/studio/execute` | [execute](../../kernel_control_panel/studio_api.py#L843) |
| GET | `/api/studio/history` | [history](../../kernel_control_panel/studio_api.py#L983) |
| GET | `/api/studio/jobs` | [jobs](../../kernel_control_panel/studio_api.py#L961) |
| POST | `/api/studio/jobs` | [submit](../../kernel_control_panel/studio_api.py#L956) |
| GET | `/api/studio/jobs/{key}` | [job](../../kernel_control_panel/studio_api.py#L965) |
| POST | `/api/studio/jobs/{key}/cancel` | [cancel](../../kernel_control_panel/studio_api.py#L971) |
| GET | `/api/studio/scan-jobs/{key}` | [scan_job](../../kernel_control_panel/studio_api.py#L813) |
| POST | `/api/studio/scan-jobs/{key}/cancel` | [cancel_scan_job](../../kernel_control_panel/studio_api.py#L829) |
| POST | `/api/studio/scans` | [create_scan](../../kernel_control_panel/studio_api.py#L797) |
| DELETE | `/api/studio/scans/{key}` | [remove_scan](../../kernel_control_panel/studio_api.py#L802) |
| GET | `/api/studio/scans/{key}/exports/{export_id}` | [download_scan_export](../../kernel_control_panel/studio_api.py#L818) |
| POST | `/api/studio/scans/{key}/{action}` | [scan_action](../../kernel_control_panel/studio_api.py#L806) |
| GET | `/api/studio/scheduler` | [scheduler_stats](../../kernel_control_panel/studio_api.py#L754) |
| POST | `/api/studio/suite/{action}` | [suite_action](../../kernel_control_panel/studio_api.py#L749) |
| GET | `/api/studio/symbols` | [list_symbols](../../kernel_control_panel/studio_api.py#L847) |
| POST | `/api/studio/symbols` | [add_symbol_path](../../kernel_control_panel/studio_api.py#L850) |
| DELETE | `/api/studio/symbols/{key}` | [delete_symbols](../../kernel_control_panel/studio_api.py#L855) |
| POST | `/api/studio/wide-views` | [create_wide_view](../../kernel_control_panel/studio_api.py#L776) |
| DELETE | `/api/studio/wide-views/{key}` | [remove_wide_view](../../kernel_control_panel/studio_api.py#L781) |
| POST | `/api/studio/wide-views/{key}/{action}` | [wide_view_action](../../kernel_control_panel/studio_api.py#L784) |
| GET | `/api/thread/{tid}/context` | [get_thread_context](../../kernel_control_panel/server.py#L328) |
| POST | `/api/thread/{tid}/context` | [set_thread_context](../../kernel_control_panel/server.py#L332) |
| POST | `/api/thread/{tid}/hide` | [set_thread_hide](../../kernel_control_panel/server.py#L346) |
| POST | `/api/thread/{tid}/resume` | [resume_thread](../../kernel_control_panel/server.py#L342) |
| POST | `/api/thread/{tid}/suspend` | [suspend_thread](../../kernel_control_panel/server.py#L338) |
| POST | `/api/watch/add` | [add_watch_item](../../kernel_control_panel/server.py#L554) |
| POST | `/api/watch/freeze` | [freeze_watch_item](../../kernel_control_panel/server.py#L613) |
| GET | `/api/watch/list` | [get_watch_list](../../kernel_control_panel/server.py#L524) |
| POST | `/api/watch/remove` | [remove_watch_item](../../kernel_control_panel/server.py#L573) |
| POST | `/api/watch/update` | [update_watch_item](../../kernel_control_panel/server.py#L581) |
| WEBSOCKET | `/ws/events` | [websocket_events_endpoint](../../kernel_control_panel/server.py#L682) |

## IOCTL identifiers

`CTL_CODE(FILE_DEVICE_UNKNOWN, function, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)`

한국어: 함수 번호와 전체 IOCTL 코드를 구분하세요. METHOD_BUFFERED 패킷의 전송 성공과 내부 `ResultStatus` 성공은 별개입니다. 반환 목록은 읽기 후 해당 해제 명령으로 정리합니다.

English: Function IDs differ from complete IOCTL codes. Successful buffered transport does not imply successful `ResultStatus`. Returned lists require their matching release operation after copying.

简体中文：函数编号不是完整 IOCTL 码。缓冲传输成功不代表内部 `ResultStatus` 成功。复制返回列表后必须调用对应释放操作。

Español: El ID de función no es el código IOCTL completo. Transporte correcto no implica `ResultStatus` correcto. Libere las listas con la operación correspondiente tras copiarlas.

| Function | Full code | Identifier | Web scope |
|---|---|---|---|
| 0x800 | `0x0022E000` | `IOCTL_HELPER_PROCESS_INFORMATION` | 연결 / Connected / 已连接 / Conectado |
| 0x801 | `0x0022E004` | `IOCTL_HELPER_ALLOC_VIRTUAL_MEMORY` | 연결 / Connected / 已连接 / Conectado |
| 0x802 | `0x0022E008` | `IOCTL_HELPER_FREE_VIRTUAL_MEMORY` | 연결 / Connected / 已连接 / Conectado |
| 0x803 | `0x0022E00C` | `IOCTL_HELPER_COPY_PROCESS_MEMORY` | 연결 / Connected / 已连接 / Conectado |
| 0x804 | `0x0022E010` | `IOCTL_HELPER_SCAN_VALUE_PROCESS` | 연결 / Connected / 已连接 / Conectado |
| 0x805 | `0x0022E014` | `IOCTL_HELPER_READ_PROCESS` | 연결 / Connected / 已连接 / Conectado |
| 0x806 | `0x0022E018` | `IOCTL_HELPER_READ_STRING_PROCESS` | 연결 / Connected / 已连接 / Conectado |
| 0x807 | `0x0022E01C` | `IOCTL_HELPER_READ_PROCESS_INFORMATION` | 연결 / Connected / 已连接 / Conectado |
| 0x808 | `0x0022E020` | `IOCTL_HELPER_FREE_LINKED_LIST` | 연결 / Connected / 已连接 / Conectado |
| 0x809 | `0x0022E024` | `IOCTL_HELPER_FREE_STRING_LIST` | 연결 / Connected / 已连接 / Conectado |
| 0x80A | `0x0022E028` | `IOCTL_HELPER_SET_HARDWARE_BREAKPOINT` | 연결 / Connected / 已连接 / Conectado |
| 0x80B | `0x0022E02C` | `IOCTL_HELPER_QUERY_HARDWARE_BREAKPOINT` | 연결 / Connected / 已连接 / Conectado |
| 0x80C | `0x0022E030` | `IOCTL_HELPER_REMOVE_HARDWARE_BREAKPOINT` | 연결 / Connected / 已连接 / Conectado |
| 0x80D | `0x0022E034` | `IOCTL_HELPER_FREE_HARDWARE_BREAKPOINT_RESULT` | 연결 / Connected / 已连接 / Conectado |
| 0x80E | `0x0022E038` | `IOCTL_HELPER_REGISTER_DLL` | 연결 / Connected / 已连接 / Conectado |
| 0x80F | `0x0022E03C` | `IOCTL_HELPER_WRITE_PROCESS` | 연결 / Connected / 已连接 / Conectado |
| 0x810 | `0x0022E040` | `IOCTL_HELPER_PROTECT_VIRTUAL_MEMORY` | 연결 / Connected / 已连接 / Conectado |
| 0x811 | `0x0022E044` | `IOCTL_HELPER_PATTERN_SCAN` | 연결 / Connected / 已连接 / Conectado |
| 0x812 | `0x0022E048` | `IOCTL_HELPER_ENUMERATE_THREADS` | 연결 / Connected / 已连接 / Conectado |
| 0x813 | `0x0022E04C` | `IOCTL_HELPER_SUSPEND_THREAD` | 연결 / Connected / 已连接 / Conectado |
| 0x814 | `0x0022E050` | `IOCTL_HELPER_RESUME_THREAD` | 연결 / Connected / 已连接 / Conectado |
| 0x815 | `0x0022E054` | `IOCTL_HELPER_GET_THREAD_CONTEXT` | 연결 / Connected / 已连接 / Conectado |
| 0x816 | `0x0022E058` | `IOCTL_HELPER_SET_THREAD_CONTEXT` | 연결 / Connected / 已连接 / Conectado |
| 0x817 | `0x0022E05C` | `IOCTL_HELPER_EVENT_MONITOR_CONTROL` | 비활성 호환 / Inactive compatibility / 非活动兼容 / Compatibilidad inactiva |
| 0x818 | `0x0022E060` | `IOCTL_HELPER_POLL_EVENTS` | 비활성 호환 / Inactive compatibility / 非活动兼容 / Compatibilidad inactiva |
| 0x819 | `0x0022E064` | `IOCTL_HELPER_GET_DRIVER_STATUS` | 연결 / Connected / 已连接 / Conectado |
| 0x81A | `0x0022E068` | `IOCTL_HELPER_QUERY_PROCESS_EXTENDED` | 연결 / Connected / 已连接 / Conectado |
| 0x81B | `0x0022E06C` | `IOCTL_HELPER_QUERY_PROCESS_HANDLES` | 연결 / Connected / 已连接 / Conectado |
| 0x81C | `0x0022E070` | `IOCTL_HELPER_QUERY_PROCESS_TOKEN` | 연결 / Connected / 已连接 / Conectado |
| 0x81D | `0x0022E074` | `IOCTL_HELPER_QUERY_THREAD_INFO` | 연결 / Connected / 已连接 / Conectado |
| 0x81E | `0x0022E078` | `IOCTL_HELPER_SET_THREAD_PRIORITY` | 연결 / Connected / 已连接 / Conectado |
| 0x81F | `0x0022E07C` | `IOCTL_HELPER_SET_THREAD_AFFINITY` | 연결 / Connected / 已连接 / Conectado |
| 0x820 | `0x0022E080` | `IOCTL_HELPER_TERMINATE_THREAD` | UI 제외·커널 존재 / UI excluded; kernel exists / 界面排除；内核存在 / Excluido de UI; existe en kernel |
| 0x821 | `0x0022E084` | `IOCTL_HELPER_SET_THREAD_HIDE_FROM_DEBUGGER` | 연결 / Connected / 已连接 / Conectado |
| 0x822 | `0x0022E088` | `IOCTL_HELPER_CREATE_FUNCTION_CALL` | 연결 / Connected / 已连接 / Conectado |
| 0x823 | `0x0022E08C` | `IOCTL_HELPER_QUERY_FUNCTION_CALL` | 연결 / Connected / 已连接 / Conectado |
| 0x824 | `0x0022E090` | `IOCTL_HELPER_RELEASE_FUNCTION_CALL` | 연결 / Connected / 已连接 / Conectado |

## Function-call packets

| Packet | Bytes | Notes |
|---|---:|---|
| `CREATE_FUNCTION_CALL_REQUEST` | 88 | `StructSize`, `Version=1`, process start key, one uint64 parameter |
| `QUERY_FUNCTION_CALL_REQUEST` | 96 | Existing device-file-owned `CallId`; wait <= 1000ms |
| `RELEASE_FUNCTION_CALL_REQUEST` | 24 | Drops tracking reference; does not terminate thread |

한국어: 구조체 pack=8을 유지하고 예약 필드는 0이어야 합니다. 최대 커널 기록 128개, 장치 파일당 32개입니다. 웹 작업 공간은 별도 30개 활성 추적·128개 이력 상한을 적용합니다. 함수 실행 여부는 `ThreadCreated`로 구분하고 완료 여부는 스레드 신호를 사용합니다. 실패 후 자동 재호출하지 마세요.

English: Preserve pack=8 and zero reserved fields. Kernel limits: 128 records, 32 per device file. Web limits: 30 active tracked calls and 128 history entries. `ThreadCreated` distinguishes execution creation; completion uses thread signaling. Do not automatically recreate after an observation failure.

简体中文：保持 pack=8，保留字段为零。内核最多 128 条记录、每设备文件 32 条；网页最多 30 个活动跟踪和 128 条历史。用 `ThreadCreated` 判断是否已创建执行，完成由线程信号判断。观察失败后不要自动重新创建。

Español: Conserve pack=8 y campos reservados a cero. Límites kernel: 128 registros, 32 por archivo; web: 30 llamadas activas y 128 de historial. `ThreadCreated` indica creación; la finalización usa señalización del hilo. No recree automáticamente ante fallo de observación.
