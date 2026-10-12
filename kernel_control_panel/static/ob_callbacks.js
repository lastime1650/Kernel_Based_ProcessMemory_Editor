/* Global callback controls. Only explicit form/button actions send mutations; polling only reads status. */
(() => {
  'use strict';
  const POLL_MS = 5000, REGISTERING_POLL_MS = 1000, HISTORY_LIMIT = 20;
  const esc = value => String(value ?? '').replace(/[&<>"']/g, char => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  }[char]));
  const states = {
    not_initialized: {title: '초기화되지 않음', tone: 'idle', icon: '○', detail: '커널에서 콜백 등록 초기화가 아직 수행되지 않았습니다.'},
    registering: {title: '등록 진행 중', tone: 'pending', icon: '◌', detail: '커널에서 고도 후보를 확인하며 콜백을 등록하고 있습니다.'},
    registered: {title: '등록 성공', tone: 'registered', icon: '✓', detail: '프로세스와 스레드의 핸들 요청을 관찰하는 콜백이 등록돼 있습니다.'},
    failed: {title: '등록 실패', tone: 'failed', icon: '⚠', detail: '커널에서 콜백 등록에 실패했습니다. 등록 NTSTATUS와 실패 단계를 확인하세요.'},
    unregistered: {title: '등록되지 않음', tone: 'idle', icon: '○', detail: '콜백이 등록되지 않은 상태입니다. 고도 범위를 입력한 뒤 등록할 수 있습니다.'},
    unregistering: {title: '등록 해제 진행 중', tone: 'pending', icon: '◌', detail: '커널에서 콜백 등록과 진행 중인 처리를 정리하고 있습니다.'}
  };
  const stages = {
    none: '없음', resolve_routines: '동적 루틴 확인', format_altitude: '고도 문자열 구성',
    register_callbacks: '콜백 등록', altitude_exhausted: '고도 후보 소진', validate_configuration: '설정 검증',
    create_worker: '등록 작업 생성', cancelled: '등록 취소'
  };
  const tracked = ['state', 'registration_status', 'failure_stage', 'registered_altitude', 'last_attempt_altitude',
    'registration_attempts', 'minimum_altitude', 'maximum_altitude', 'maximum_fraction', 'last_whole', 'last_fraction',
    'register_routine_resolved', 'unregister_routine_resolved', 'callback_version', 'operation_count',
    'process_operations', 'thread_operations', 'pre_operation_enabled', 'post_operation_enabled', 'observe_only', 'dynamic_resolution',
    'handler_address', 'handler_address_valid', 'worker_active', 'registration_generation',
    'last_requested_minimum_altitude', 'last_requested_maximum_altitude', 'last_requested_maximum_fraction'];
  const numericFields = ['maximum_fraction',
    'last_whole', 'last_fraction', 'callback_version', 'operation_count', 'process_operations', 'thread_operations'];
  const booleanFields = ['register_routine_resolved', 'unregister_routine_resolved', 'pre_operation_enabled',
    'post_operation_enabled', 'observe_only', 'dynamic_resolution', 'handler_address_valid', 'worker_active'];
  const stateNames = ['not_initialized', 'registering', 'registered', 'failed', 'unregistered', 'unregistering'];
  let context = null, epoch = 0, serial = 0, timer = null, controller = null;
  let current = null, latest = null, history = [], signature = '';
  let draft = {minimum: '', maximum: '', fraction: '1000'}, mutation = null, commandNotice = null;
  const q = id => context?.root.querySelector('#' + id);
  const active = () => context && (!context.currentPage || context.currentPage() === 'ob_callbacks') && !document.hidden;
  const clone = value => JSON.parse(JSON.stringify(value));
  const now = () => new Date().toISOString();
  const timeText = value => value ? new Date(typeof value === 'number' ? value * 1000 : value).toLocaleString('ko-KR') : '—';
  const boolText = value => value === true ? '예' : value === false ? '아니요' : '알 수 없음';
  const enabled = value => value === true ? '사용' : value === false ? '사용하지 않음' : '알 수 없음';

  function clearTimer() {
    if (timer !== null) clearTimeout(timer);
    timer = null;
  }

  function dispose() {
    stashDraft();
    epoch++;
    serial++;
    clearTimer();
    controller?.abort();
    controller = null;
    document.removeEventListener('visibilitychange', visibilityChanged);
    context = null;
    current = null;
  }

  function reset() {
    dispose(); current = latest = null; history = []; signature = '';
    draft = {minimum: '', maximum: '', fraction: '1000'}; commandNotice = null;
  }

  function stashDraft() {
    if (!q('oc-minimum')) return;
    draft = {minimum: q('oc-minimum').value, maximum: q('oc-maximum').value, fraction: q('oc-fraction').value};
  }

  function rangeValues() {
    const values = [draft.minimum, draft.maximum, draft.fraction].map(value => String(value).trim());
    if (values.some(value => !/^[0-9]+$/.test(value))) return null;
    const [minimum, maximum, fraction] = values.map(Number);
    if (![minimum, maximum, fraction].every(Number.isInteger) || minimum < 0 || maximum > 0xFFFFFFFF ||
      minimum > maximum || fraction < 0 || fraction > 1000) return null;
    return {minimum_altitude: minimum, maximum_altitude: maximum, maximum_fraction: fraction};
  }

  function controls() {
    if (!context) return;
    const busy = mutation !== null || ['registering', 'unregistering'].includes(current?.state) || current?.worker_active === true;
    const queryPending = controller !== null;
    q('oc-refresh').disabled = queryPending || mutation !== null;
    q('oc-export').disabled = queryPending || mutation !== null || !latest;
    for (const id of ['oc-minimum', 'oc-maximum', 'oc-fraction']) q(id).disabled = busy;
    q('oc-register').disabled = busy || queryPending || !rangeValues() || !['unregistered', 'failed'].includes(current?.state);
    q('oc-unregister').disabled = busy || queryPending || current?.state !== 'registered';
    q('oc-input-note').textContent = rangeValues() ? '입력 범위가 유효합니다. 등록하면 드라이버 전역에 적용됩니다.' :
      '정수 시작·끝 범위를 0 ~ 4294967295로 입력하세요. 시작은 끝 이하, 소수부 최대값은 0 ~ 1000입니다.';
    drawCommandNotice();
  }

  function drawCommandNotice() {
    const element = q('oc-command-result');
    if (!element) return;
    element.className = 'oc-command-result' + (commandNotice?.error ? ' oc-command-result--error' : '');
    element.setAttribute('role', commandNotice?.error ? 'alert' : 'status');
    element.setAttribute('aria-live', commandNotice?.error ? 'assertive' : 'polite');
    element.textContent = mutation ? (mutation.action === 'register' ? '등록 요청을 보내는 중입니다…' : '등록 해제 요청을 보내는 중입니다…') : commandNotice?.text || '';
  }

  function banner(title, detail, tone, icon, alert = false) {
    const element = q('oc-status');
    if (!element) return;
    element.className = 'oc-status oc-status--' + tone;
    element.setAttribute('role', alert ? 'alert' : 'status');
    element.setAttribute('aria-live', alert ? 'assertive' : 'polite');
    element.innerHTML = `<span class="oc-status-icon" aria-hidden="true">${esc(icon)}</span><div><strong>${esc(title)}</strong><p>${esc(detail)}</p></div>`;
  }

  function item(label, value) {
    return `<div class="oc-setting"><dt>${esc(label)}</dt><dd>${esc(value ?? '알 수 없음')}</dd></div>`;
  }

  function operations(mask) {
    return `생성 ${mask & 1 ? '사용' : '사용하지 않음'} · 복제 ${mask & 2 ? '사용' : '사용하지 않음'} · 0x${Number(mask).toString(16).toUpperCase()}`;
  }

  function drawCurrent() {
    const element = q('oc-current');
    if (!element) return;
    if (!current) {
      element.innerHTML = '<p class="subtle">현재 드라이버 설정을 확인하지 못했습니다. 이전 표본은 조회 시각과 함께 아래 기록에만 표시합니다.</p>';
      return;
    }
    const data = current;
    element.innerHTML = `
      <h3>현재 드라이버 설정</h3><dl class="oc-settings">
        ${item('등록된 고도', data.registered_altitude || '없음')}
        ${item('마지막 시도 고도', data.last_attempt_altitude || '없음')}
        ${item('등록 시도 횟수', data.registration_attempts)}
        ${item('PRE 핸들러 주소', data.handler_address)}
        ${item('핸들러 주소 유효', boolText(data.handler_address_valid))}
        ${item('등록 작업 실행 중', boolText(data.worker_active))}
        ${item('등록 세대 (Generation)', data.registration_generation)}
        ${item('정수 고도 범위', `${data.minimum_altitude} ~ ${data.maximum_altitude}`)}
        ${item('소수부 카운터 범위', `0 ~ ${data.maximum_fraction} · 0은 정수 문자열`)}
        ${item('마지막 정수 / 소수부', `${data.last_whole} / ${data.last_fraction}`)}
        ${item('등록 NTSTATUS', data.registration_status)}
        ${item('실패 단계', stages[data.failure_stage] || data.failure_stage)}
        ${item('ObRegisterCallbacks 루틴 해결', boolText(data.register_routine_resolved))}
        ${item('ObUnRegisterCallbacks 루틴 해결', boolText(data.unregister_routine_resolved))}
        ${item('콜백 버전', `${data.callback_version} · 0x${Number(data.callback_version).toString(16).toUpperCase().padStart(4, '0')}`)}
        ${item('오브젝트 설정 항목 수', data.operation_count)}
        ${item('프로세스 핸들 요청', operations(data.process_operations))}
        ${item('스레드 핸들 요청', operations(data.thread_operations))}
        ${item('PRE 콜백', enabled(data.pre_operation_enabled))}
        ${item('POST 콜백', enabled(data.post_operation_enabled))}
        ${item('관찰 전용', boolText(data.observe_only))}
        ${item('접근권한 변경', data.observe_only === true ? '없음' : '무변경 여부를 확인할 수 없음')}
        ${item('커널 루틴 동적 해결', boolText(data.dynamic_resolution))}
        ${item('상태 조회 NTSTATUS', data.result_status)}
      </dl><h3 class="oc-history-settings-heading">마지막 등록 요청 기록</h3><dl class="oc-settings">
        ${item('마지막 요청 정수 범위 (이전 기록)', `${data.last_requested_minimum_altitude} ~ ${data.last_requested_maximum_altitude}`)}
        ${item('마지막 요청 소수부 최대값 (이전 기록)', data.last_requested_maximum_fraction)}
      </dl><p class="subtle">마지막 요청 기록은 현재 등록된 설정과 구분됩니다. 해제 상태의 현재 고도·범위 -1과 핸들러 0x0은 등록되지 않았음을 나타냅니다. 고도 후보는 정수 문자열에 이어 소수부 카운터 문자열을 붙이는 순서입니다(예: .9 → .10). 오브젝트 설정 항목 수는 등록 성공 개수가 아닙니다. PRE 기록은 핸들 요청의 관찰값이며 최종 핸들 생성 결과를 뜻하지 않습니다.</p>`;
  }

  function drawHistory() {
    const element = q('oc-history');
    if (!element) return;
    element.innerHTML = history.length ? `<div class="table-wrap"><table><caption class="oc-history-caption">이전 조회 기록 · 최신 ${HISTORY_LIMIT}개까지 메모리에 보관</caption><thead><tr><th>조회 시각</th><th>관측 상태</th><th>변경</th><th>당시 등록 고도 / 시도 횟수</th></tr></thead><tbody>${history.map(entry => `<tr>
      <td>${esc(timeText(entry.observed_at))}</td><td>${esc(entry.label)}</td><td>${esc(entry.change)}</td>
      <td>${esc(entry.snapshot.success === true ? `${entry.snapshot.registered_altitude || '없음'} / ${entry.snapshot.registration_attempts}` : entry.snapshot.error || '조회 실패')}</td>
    </tr>`).join('')}</tbody></table></div>` : '<p class="subtle">아직 조회 기록이 없습니다.</p>';
  }

  function record(response, label) {
    const nextSignature = JSON.stringify(response.success === true ? tracked.map(field => response[field]) : ['query_error', response.error_kind, response.error]);
    const change = !signature ? '첫 조회' : signature === nextSignature ? '동일 상태 / 설정' : '상태 / 설정 변경';
    signature = nextSignature;
    latest = {observed_at: now(), snapshot: clone(response)};
    history.unshift({...latest, label, change});
    history.length = Math.min(history.length, HISTORY_LIMIT);
    q('oc-queried').textContent = `조회 시각 ${timeText(response.queried_at || latest.observed_at)} · 화면을 보는 동안 조회, 등록 진행 중에는 1초 간격`;
    drawHistory();
  }

  function queryError(error) {
    current = null;
    const kind = error.kind || 'read_failed';
    const title = kind === 'unsupported' ? '지원하지 않는 드라이버' : '상태 조회 실패';
    const detail = kind === 'disconnected' ? '드라이버 연결이 없어 등록 상태를 확인할 수 없습니다.' : error.message;
    banner(title, detail, 'query-error', '⚠', true);
    drawCurrent();
    const failed = Object.fromEntries([...tracked, 'state_code', 'result_status', 'registration_status_code',
      'failure_stage_code'].map(field => [field, null]));
    Object.assign(failed, {success: false, state: 'unknown', registered: null, error_kind: kind,
      error: detail, queried_at: error.queried_at || null, error_code: error.code ?? null,
      unsupported: kind === 'unsupported', connected: error.connected ?? null, readonly: true});
    record(failed, title);
  }

  function validStatus(body) {
    const uint32 = value => Number.isInteger(value) && value >= 0 && value <= 0xFFFFFFFF;
    const rangeBoundary = value => value === -1 || uint32(value);
    return body.connected === true && body.unsupported === false && body.readonly === true &&
      Object.hasOwn(states, body.state) && Number.isInteger(body.state_code) &&
      stateNames[body.state_code] === body.state && body.registered === (body.state === 'registered') &&
      typeof body.registration_status === 'string' && /^0x[0-9a-f]{8}$/i.test(body.registration_status) &&
      body.result_status === '0x00000000' && Object.hasOwn(stages, body.failure_stage) &&
      numericFields.every(field => uint32(body[field])) && booleanFields.every(field => typeof body[field] === 'boolean') &&
      ['registration_attempts', 'registration_generation'].every(field => Number.isSafeInteger(body[field]) && body[field] >= 0) &&
      ['minimum_altitude', 'maximum_altitude', 'last_requested_minimum_altitude', 'last_requested_maximum_altitude']
        .every(field => rangeBoundary(body[field])) && uint32(body.last_requested_maximum_fraction) &&
      typeof body.handler_address === 'string' && /^0x[0-9a-f]{1,16}$/i.test(body.handler_address) &&
      (body.state !== 'registered' || (body.handler_address_valid && BigInt(body.handler_address) !== 0n &&
        body.registered_altitude !== '-1' && body.registered_altitude !== '' && body.minimum_altitude >= 0 &&
        body.maximum_altitude >= body.minimum_altitude && body.maximum_fraction <= 1000 &&
        BigInt(body.registration_status) < 0x80000000n)) &&
      ['registered_altitude', 'last_attempt_altitude'].every(field => typeof body[field] === 'string' &&
        body[field].length < 16 && /^(?:-1|[0-9]+(?:\.[0-9]+)?)?$/.test(body[field])) &&
      Number.isFinite(body.queried_at) && body.queried_at >= 0;
  }

  async function refresh() {
    if (!active()) return;
    clearTimer();
    controller?.abort();
    const request = new AbortController();
    controller = request;
    const owner = context, token = epoch, requestSerial = ++serial;
    current = null;
    banner('상태 조회 중', '현재 드라이버의 등록 상태와 설정을 조회합니다.', 'pending', '◌');
    drawCurrent(); controls();
    try {
      const response = await fetch('/api/ob-callbacks/status', {method: 'GET', cache: 'no-store', signal: request.signal});
      let body;
      try { body = await response.json(); }
      catch { throw Error('상태 조회 응답을 읽을 수 없습니다.'); }
      if (!body || typeof body !== 'object' || Array.isArray(body)) {
        const error = Error('드라이버 상태 응답의 형식을 확인하세요.'); error.kind = 'invalid_reply'; throw error;
      }
      if (!response.ok || body.success !== true) {
        const error = Error(typeof body.error === 'string' ? body.error : '드라이버 상태 조회에 실패했습니다.');
        error.kind = body.error_kind || 'read_failed'; error.queried_at = body.queried_at;
        error.code = body.error_code; error.connected = body.connected;
        throw error;
      }
      if (!validStatus(body)) {
        const error = Error('드라이버 상태 응답의 형식을 확인하세요.'); error.kind = 'invalid_reply'; throw error;
      }
      if (context !== owner || token !== epoch || requestSerial !== serial || !active()) return;
      current = clone(body);
      const state = states[current.state];
      banner(state.title, state.detail, state.tone, state.icon, current.state === 'failed');
      drawCurrent(); record(current, state.title);
    } catch (error) {
      if (context === owner && token === epoch && requestSerial === serial && active() && error.name !== 'AbortError') queryError(error);
    } finally {
      if (context === owner && token === epoch && requestSerial === serial) {
        controller = null; controls();
        if (active()) timer = setTimeout(refresh, ['registering', 'unregistering'].includes(current?.state) ? REGISTERING_POLL_MS : POLL_MS);
      }
    }
  }

  async function command(action) {
    stashDraft();
    const range = rangeValues();
    if (!active() || mutation || controller || current?.worker_active ||
      (action === 'register' ? (!range || !['unregistered', 'failed'].includes(current?.state)) : current?.state !== 'registered')) return;
    clearTimer();
    const pending = {action}; mutation = pending; commandNotice = null;
    current = null;
    banner(action === 'register' ? '등록 요청 중' : '등록 해제 요청 중',
      '요청 결과와 실제 드라이버 상태를 확인하는 중입니다.', 'pending', '◌');
    drawCurrent(); controls();
    try {
      // Mutations are never retried or cancelled by navigation. Their completion is followed by a fresh GET.
      const response = await fetch('/api/ob-callbacks/' + action, {method: 'POST', cache: 'no-store',
        headers: {'Content-Type': 'application/json'}, body: JSON.stringify(action === 'register' ? range : {})});
      let body;
      try { body = await response.json(); } catch { throw Error('요청 응답을 읽을 수 없습니다. 현재 상태를 다시 확인하세요.'); }
      if (!response.ok || !body || body.success !== true) throw Error(typeof body?.error === 'string' ? body.error :
        '요청에 실패했습니다. 현재 상태를 다시 확인하세요.');
      if (body.action !== action || body.readonly !== false || body.connected !== true || body.unsupported !== false ||
        body.packet_valid !== true || body.transport_ok !== true ||
        body.accepted !== (action === 'register') || body.completed !== (action === 'unregister') ||
        body.bytes_returned !== 32 || typeof body.result_status !== 'string' || !/^0x[0-9a-f]{8}$/i.test(body.result_status) ||
        BigInt(body.result_status) >= 0x80000000n) {
        throw Error('요청 응답의 형식을 확인할 수 없습니다. 현재 상태를 다시 확인하세요.');
      }
      commandNotice = {error: false, text: action === 'register' ?
        '등록 요청이 수락되었습니다. 현재 드라이버 상태에서 등록 완료 여부를 확인하세요.' :
        '등록 해제 요청이 완료되었습니다. 현재 드라이버 상태를 다시 조회합니다.'};
    } catch (error) {
      commandNotice = {error: true, text: (action === 'register' ? '등록 요청 실패: ' : '등록 해제 요청 실패: ') +
        error.message + ' 자동으로 다시 요청하지 않습니다.'};
    } finally {
      if (mutation === pending) mutation = null;
      if (context) { controls(); if (active()) refresh(); }
    }
  }

  function exportSnapshot() {
    if (!context || !latest || controller) return;
    stashDraft();
    const snapshot = {schema_version: 2, panel: 'ObRegisterCallback Panel', exported_at: now(),
      input_range: rangeValues(), last_control_notice: commandNotice ? clone(commandNotice) : null,
      current: current ? clone(current) : null, latest_query: clone(latest), history: clone(history)};
    context.download(JSON.stringify(snapshot, null, 2), 'ob-callbacks-status-' + Date.now() + '.json', 'application/json');
  }

  function visibilityChanged() {
    if (!context) return;
    if (document.hidden) {
      serial++; clearTimer(); controller?.abort(); controller = null; current = null;
      banner('조회 일시 중지', '화면을 다시 보면 현재 상태를 새로 조회합니다.', 'idle', '○');
      drawCurrent(); controls();
    } else refresh();
  }

  function render(ctx) {
    if (context?.root === ctx.root && q('oc-range-form')) {
      context = ctx; stashDraft(); controls(); refresh(); return;
    }
    dispose(); context = ctx;
    context.root.innerHTML = `<div class="oc-panel">
      <section class="card"><div class="card-head"><div><h2>ObRegisterCallback Panel</h2><p>프로세스 선택 없이 드라이버 전역의 관찰 콜백을 등록·해제하고 현재 상태를 확인합니다.</p></div><span class="chip">드라이버 전역</span></div>
        <p class="subtle">V2 · 상태 조회 0x827 · 등록 요청 0x828 · 등록 해제 0x829</p>
        <div id="oc-status" class="oc-status" role="status" aria-live="polite"></div>
        <div class="actions"><button id="oc-refresh" class="secondary">상태 새로 고침</button><button id="oc-export" class="secondary" disabled>JSON 스냅샷 저장</button></div>
        <p id="oc-queried" class="subtle">아직 현재 상태를 조회하지 않았습니다.</p>
      </section><section class="card"><h2>콜백 등록 범위</h2><p class="subtle">고도 후보는 시작 정수의 문자열, .1, .2, … 순서로 확인합니다. 등록과 해제는 아래 버튼으로 요청합니다.</p>
        <form id="oc-range-form"><div class="oc-range-fields">
          <label for="oc-minimum">정수 시작<input id="oc-minimum" type="text" inputmode="numeric" autocomplete="off" value="${esc(draft.minimum)}" placeholder="0 ~ 4294967295" aria-describedby="oc-input-note"></label>
          <label for="oc-maximum">정수 끝<input id="oc-maximum" type="text" inputmode="numeric" autocomplete="off" value="${esc(draft.maximum)}" placeholder="시작 이상 ~ 4294967295" aria-describedby="oc-input-note"></label>
          <label for="oc-fraction">소수부 최대 카운터<input id="oc-fraction" type="text" inputmode="numeric" autocomplete="off" value="${esc(draft.fraction)}" aria-describedby="oc-input-note"></label>
        </div><p id="oc-input-note" class="subtle"></p><div class="actions"><button id="oc-register" type="submit" disabled>콜백 등록</button><button id="oc-unregister" type="button" class="danger" disabled>등록 해제</button></div>
        <p id="oc-command-result" class="oc-command-result" role="status" aria-live="polite"></p></form>
      </section><section class="card" id="oc-current" aria-label="현재 콜백 설정"></section>
      <section class="card"><h2>최근 조회 기록</h2><p class="subtle">이전 표본의 시각을 함께 표시합니다. 이 기록은 현재 등록 상태를 대신하지 않습니다.</p><div id="oc-history"></div></section>
    </div>`;
    q('oc-refresh').onclick = refresh; q('oc-export').onclick = exportSnapshot;
    for (const id of ['oc-minimum', 'oc-maximum', 'oc-fraction']) q(id).oninput = () => { stashDraft(); controls(); };
    q('oc-range-form').onsubmit = event => { event.preventDefault(); return command('register'); };
    q('oc-register').onclick = event => { event?.preventDefault(); return command('register'); };
    q('oc-unregister').onclick = () => command('unregister');
    banner(document.hidden ? '조회 일시 중지' : '상태 조회 준비', '화면을 보는 동안 현재 상태를 조회합니다.', 'idle', '○');
    drawCurrent(); drawHistory(); controls();
    document.addEventListener('visibilitychange', visibilityChanged);
    refresh();
  }

  window.ObCallbacksPanel = {render, refresh, dispose, reset};
})();
