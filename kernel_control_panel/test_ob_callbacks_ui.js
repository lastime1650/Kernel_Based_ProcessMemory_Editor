/* Offline mock DOM/fetch V2 regression. Never imports the panel server or opens a device. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const source = fs.readFileSync(__dirname + '/static/ob_callbacks.js', 'utf8');
const settle = () => new Promise(resolve => setImmediate(resolve));
const response = (body, ok = true) => ({ok, json: async () => body});
function deferred() {
  let resolve;
  const promise = new Promise(done => { resolve = done; });
  return {promise, resolve};
}
function status(state = 'registered', extra = {}) {
  return {success: true, connected: true, unsupported: false, readonly: true, state,
    state_code: ['not_initialized', 'registering', 'registered', 'failed', 'unregistered', 'unregistering'].indexOf(state),
    registered: state === 'registered', result_status: '0x00000000', registration_status: '0x00000000',
    registration_status_code: 0, failure_stage: 'none', failure_stage_code: 0,
    registered_altitude: state === 'registered' ? '80000.10' : '-1', last_attempt_altitude: '80000.10',
    registration_attempts: 11, minimum_altitude: state === 'unregistered' ? -1 : 80000,
    maximum_altitude: state === 'unregistered' ? -1 : 429999, maximum_fraction: state === 'unregistered' ? 0 : 1000,
    last_whole: 80000, last_fraction: 10, register_routine_resolved: true, unregister_routine_resolved: true,
    callback_version: 256, operation_count: 2, process_operations: 3, thread_operations: 3,
    pre_operation_enabled: true, post_operation_enabled: false, observe_only: true, dynamic_resolution: true,
    handler_address: state === 'registered' ? '0xFFFFF80012345678' : '0x0', handler_address_valid: state === 'registered',
    worker_active: ['registering', 'unregistering'].includes(state), registration_generation: 3,
    last_requested_minimum_altitude: 80000, last_requested_maximum_altitude: 429999, last_requested_maximum_fraction: 1000,
    queried_at: 1791745200, ...extra};
}
function actionReply(action, extra = {}) {
  return {action, success: true, accepted: action === 'register', completed: action === 'unregister',
    transport_ok: true, packet_valid: true, error_code: 0, bytes_returned: 32, result_status: '0x00000000',
    unsupported: false, connected: true, readonly: false, queried_at: 1791745201, ...extra};
}
function queryFailure(kind, error = '모의 조회 오류') {
  return {success: false, state: 'unknown', state_code: null, registered: null, error_kind: kind, error,
    error_code: 50, unsupported: kind === 'unsupported', connected: kind !== 'disconnected', queried_at: 1791745201};
}
function mockRoot() {
  let html = '', elements = new Map();
  return {
    get innerHTML() { return html; },
    set innerHTML(value) {
      html = value; elements = new Map();
      for (const match of value.matchAll(/<\w+\b[^>]*\bid="([^"]+)"[^>]*>/g)) {
        const attributes = {};
        for (const attribute of match[0].matchAll(/([\w-]+)="([^"]*)"/g)) attributes[attribute[1]] = attribute[2];
        elements.set(match[1], {innerHTML: '', textContent: '', value: attributes.value || '', disabled: /\bdisabled\b/.test(match[0]),
          className: attributes.class || '', attributes,
          setAttribute(name, value) { this.attributes[name] = value; },
          getAttribute(name) { return this.attributes[name]; }});
      }
    },
    querySelector(selector) { return elements.get(selector.slice(1)); }
  };
}
function harness() {
  const root = mockRoot(), calls = [], timers = new Map(), listeners = new Map(), downloads = [];
  let timerId = 0, page = 'ob_callbacks', handler = async () => response(status());
  const document = {
    hidden: false,
    addEventListener(name, callback) { listeners.set(name, callback); },
    removeEventListener(name, callback) { if (listeners.get(name) === callback) listeners.delete(name); }
  };
  const sandbox = {window: {}, console, AbortController, document,
    fetch: async (path, options) => { calls.push({path, options}); return handler(path, options); },
    setTimeout(callback, delay) { const id = ++timerId; timers.set(id, {callback, delay}); return id; },
    clearTimeout(id) { timers.delete(id); }};
  vm.runInNewContext(source, sandbox, {filename: 'ob_callbacks.js'});
  const ctx = {root, currentPage: () => page, download: (...args) => downloads.push(args)};
  // Any accidental dependency on selected PID will fail the suite.
  Object.defineProperty(ctx, 'pid', {get() { throw Error('This global page must not access PID'); }});
  return {view: sandbox.window.ObCallbacksPanel, root, calls, timers, listeners, downloads, ctx, document,
    element: id => root.querySelector('#' + id),
    set fetch(value) { handler = value; }, set page(value) { page = value; },
    async render(target = ctx) { this.view.render(target); await settle(); },
    async tick(delay = 5000) {
      assert.equal(timers.size, 1);
      const [id, timer] = timers.entries().next().value;
      assert.equal(timer.delay, delay); timers.delete(id); await timer.callback(); await settle();
    },
    async hide(hidden) { document.hidden = hidden; listeners.get('visibilitychange')?.(); await settle(); },
    posts() { return calls.filter(call => call.options.method === 'POST'); },
    export() { this.element('oc-export').onclick(); return JSON.parse(downloads.at(-1)[0]); }};
}
function inputRange(h, minimum, maximum, fraction = '1000') {
  for (const [id, value] of [['oc-minimum', minimum], ['oc-maximum', maximum], ['oc-fraction', fraction]]) {
    h.element(id).value = value; h.element(id).oninput();
  }
}

async function registeredShowsMeasuredSettingsWithoutPid() {
  const h = harness();
  h.fetch = async () => response(status('registered', {minimum_altitude: 90000, maximum_altitude: 90001,
    maximum_fraction: 7, process_operations: 1, thread_operations: 2, registration_attempts: 37}));
  await h.render();
  assert.match(h.element('oc-status').className, /--registered/);
  assert.match(h.element('oc-status').innerHTML, /등록 성공/);
  assert.equal(h.element('oc-status').getAttribute('role'), 'status');
  const text = h.element('oc-current').innerHTML;
  for (const expected of ['80000.10', '90000 ~ 90001', '0 ~ 7', '>37<', '0x00000000', '0x0100',
    'ObRegisterCallbacks', 'ObUnRegisterCallbacks', '오브젝트 설정 항목 수', 'PRE 콜백', 'POST 콜백',
    '관찰 전용', '접근권한 변경', '커널 루틴 동적 해결']) assert(text.includes(expected), expected);
  assert.match(text, /생성 사용 · 복제 사용하지 않음 · 0x1/);
  assert.match(text, /생성 사용하지 않음 · 복제 사용 · 0x2/);
  assert.doesNotMatch(h.root.innerHTML, /PID 입력|대상을 선택하세요/);
  assert.equal(h.element('oc-export').disabled, false);
  h.view.dispose();
}

async function actualRegistrationFailureUsesRedAlertAndKeepsSettings() {
  const h = harness();
  h.fetch = async () => response(status('failed', {registration_status: '0xC0000022',
    registration_status_code: -1073741790, failure_stage: 'register_callbacks', failure_stage_code: 3}));
  await h.render();
  const banner = h.element('oc-status');
  assert.match(banner.className, /--failed/); assert.match(banner.innerHTML, /등록 실패/);
  assert.match(banner.innerHTML, /⚠/); assert.equal(banner.getAttribute('role'), 'alert');
  assert.equal(banner.getAttribute('aria-live'), 'assertive');
  assert.match(h.element('oc-current').innerHTML, /0xC0000022|콜백 등록/);
  assert.equal(h.export().current.success, true); // Query success is independent of registration failure.
  assert.equal(h.export().current.registered, false);
  h.view.dispose();
}

async function intermediateAndStoppedStatesAreExplicit() {
  const h = harness();
  for (const [state, title, tone] of [['not_initialized', '초기화되지 않음', 'idle'],
    ['registering', '등록 진행 중', 'pending'], ['unregistered', '등록되지 않음', 'idle'],
    ['unregistering', '등록 해제 진행 중', 'pending']]) {
    h.fetch = async () => response(status(state)); await h.render();
    assert.match(h.element('oc-status').innerHTML, new RegExp(title));
    assert.match(h.element('oc-status').className, new RegExp('--' + tone));
    assert.doesNotMatch(h.element('oc-status').innerHTML, /등록 성공|등록 실패/);
  }
  h.view.dispose();
}

async function queryFailuresClearSuccessAndNeverClaimRegistrationFailure() {
  const h = harness(); await h.render();
  for (const kind of ['unsupported', 'disconnected', 'read_failed', 'invalid_reply', 'closing']) {
    h.fetch = async () => response(queryFailure(kind)); await h.view.refresh();
    const banner = h.element('oc-status');
    assert.match(banner.className, /--query-error/); assert.equal(banner.getAttribute('role'), 'alert');
    assert.match(banner.innerHTML, kind === 'unsupported' ? /지원하지 않는 드라이버/ : /상태 조회 실패/);
    assert.doesNotMatch(banner.innerHTML, /등록 성공|등록 실패/);
    assert.doesNotMatch(h.element('oc-current').innerHTML, /80000|0x00000000|<dl/);
    const exported = h.export();
    assert.equal(exported.current, null); assert.equal(exported.latest_query.snapshot.registered, null);
    assert.equal(exported.latest_query.snapshot.minimum_altitude, null);
    assert.equal(exported.latest_query.snapshot.error_code, 50);
    assert.equal(exported.history.at(-1).snapshot.registered, true);
    assert(exported.history.at(-1).observed_at);
  }
  h.view.dispose();
}

async function malformedAndNetworkErrorsCannotLeaveGreen() {
  const h = harness(); await h.render();
  const malformed = [null, [], {}, status('registered', {registered: false}),
    status('registered', {connected: false}), status('registered', {readonly: false}),
    status('registered', {unsupported: true}), status('registered', {state_code: 3}),
    status('registered', {minimum_altitude: -1}), status('registered', {callback_version: '256'}),
    status('registered', {pre_operation_enabled: null}), status('registered', {queried_at: NaN}),
    status('registered', {registration_status: 'success'}), status('registered', {registered_altitude: '<img src=x>'}),
    status('registered', {registered_altitude: '1234567890123456'}),
    status('registered', {state: undefined, state_code: undefined, registered: false})];
  for (const body of malformed) {
    h.fetch = async () => response(body); await h.view.refresh();
    assert.match(h.element('oc-status').className, /--query-error/);
    assert.equal(h.export().current, null);
  }
  for (const handler of [async () => { throw Error('네트워크 오류'); },
    async () => ({ok: true, json: async () => { throw Error('invalid JSON'); }}),
    async () => response(status(), false)]) {
    h.fetch = handler; await h.view.refresh(); assert.match(h.element('oc-status').className, /--query-error/);
  }
  h.view.dispose();
}

async function disposalAbortsAndRejectsLateFetchAndJson() {
  for (const jsonLate of [false, true]) {
    const h = harness(), held = deferred();
    h.fetch = jsonLate ? async () => ({ok: true, json: () => held.promise}) : () => held.promise;
    await h.render(); const signal = h.calls[0].options.signal;
    h.view.dispose(); h.page = 'home'; h.root.innerHTML = '<p>다른 페이지</p>';
    held.resolve(jsonLate ? status() : response(status())); await settle();
    assert.equal(signal.aborted, true); assert.equal(h.root.innerHTML, '<p>다른 페이지</p>');
    assert.equal(h.timers.size, 0); assert.equal(h.listeners.size, 0);
  }
}

async function newestRequestWinsOverIgnoredAbort() {
  const h = harness(), old = deferred(), recent = deferred();
  h.fetch = () => h.calls.length === 1 ? old.promise : recent.promise;
  await h.render(); const newer = h.view.refresh();
  assert.equal(h.calls[0].options.signal.aborted, true);
  recent.resolve(response(status('registered', {registered_altitude: '80001.2'}))); await newer;
  old.resolve(response(queryFailure('disconnected'))); await settle();
  assert.match(h.element('oc-status').innerHTML, /등록 성공/);
  assert.match(h.element('oc-current').innerHTML, /80001.2/);
  assert.equal(h.export().history.length, 1); assert.equal(h.timers.size, 1);
  h.view.dispose();
}

async function renderReentryRejectsPriorPageOwner() {
  const h = harness(), old = deferred(); h.fetch = () => old.promise; await h.render();
  const other = mockRoot(); h.fetch = async () => response(status('failed'));
  await h.render({...h.ctx, root: other});
  old.resolve(response(status())); await settle();
  assert.match(other.querySelector('#oc-status').innerHTML, /등록 실패/);
  assert.equal(h.timers.size, 1); h.view.dispose();
}

async function pollingOnlyRunsWhileVisibleAndUsesGet() {
  const h = harness(); await h.render(); await h.tick(); await h.tick();
  assert.equal(h.calls.length, 3); assert.equal(h.timers.size, 1);
  await h.hide(true); assert.equal(h.timers.size, 0);
  assert.match(h.element('oc-status').innerHTML, /조회 일시 중지/);
  assert.doesNotMatch(h.element('oc-current').innerHTML, /<dl/);
  await h.view.refresh(); assert.equal(h.calls.length, 3);
  await h.hide(false); assert.equal(h.calls.length, 4); assert.equal(h.timers.size, 1);
  h.page = 'home'; await h.tick(); assert.equal(h.calls.length, 4); assert.equal(h.timers.size, 0);
  for (const call of h.calls) {
    assert.equal(call.path, '/api/ob-callbacks/status'); assert.equal(call.options.method, 'GET');
    assert.equal(call.options.cache, 'no-store'); assert.equal(call.options.body, undefined);
  }
  h.view.dispose();
}

async function hiddenOutstandingReplyIsIgnoredUntilFreshQuery() {
  const h = harness(), held = deferred(); h.fetch = () => held.promise; await h.render();
  await h.hide(true); assert.equal(h.calls[0].options.signal.aborted, true);
  held.resolve(response(status())); await settle();
  assert.match(h.element('oc-status').innerHTML, /조회 일시 중지/); assert.equal(h.timers.size, 0);
  h.fetch = async () => response(status('unregistered')); await h.hide(false);
  assert.match(h.element('oc-status').innerHTML, /등록되지 않음/); h.view.dispose();
}

async function boundedHistoryAndJsonExportPreserveMeasuredSettings() {
  const h = harness(); await h.render();
  await h.view.refresh();
  assert.equal(h.export().history[0].change, '동일 상태 / 설정');
  for (let index = 0; index < 28; index++) {
    h.fetch = async () => response(status('registered', {registration_attempts: 100 + index}));
    await h.view.refresh();
  }
  const exported = h.export(), [text, filename, mime] = h.downloads.at(-1);
  assert.equal(exported.panel, 'ObRegisterCallback Panel'); assert.equal(exported.schema_version, 2);
  assert.equal(exported.history.length, 20); assert.equal(exported.current.registration_attempts, 127);
  assert.equal(exported.history[0].change, '상태 / 설정 변경');
  assert.equal(exported.latest_query.snapshot.maximum_altitude, 429999);
  assert.match(filename, /^ob-callbacks-status-\d+\.json$/); assert.equal(mime, 'application/json');
  assert(text.includes('\n')); assert.match(h.element('oc-history').innerHTML, /<caption|조회 시각|최신 20개/);
  h.view.reset(); await h.render(); assert.equal(h.export().history.length, 1); h.view.dispose();
}

async function escapedAccessibleWarningsAndStyles() {
  const h = harness(); h.fetch = async () => response(queryFailure('read_failed', '<script>alert(1)</script>'));
  await h.render();
  for (const id of ['oc-status', 'oc-history']) {
    assert.match(h.element(id).innerHTML, /&lt;script&gt;/);
    assert.doesNotMatch(h.element(id).innerHTML, /<script>|<img/);
  }
  assert.match(h.root.innerHTML, /상태 새로 고침|JSON 스냅샷 저장|aria-label="현재 콜백 설정"/);
  const css = fs.readFileSync(__dirname + '/static/ob_callbacks.css', 'utf8');
  assert.match(css, /\.oc-status--registered\{[^}]*color:var\(--accent\)/);
  assert.match(css, /\.oc-status--failed,\.oc-panel \.oc-status--query-error\{[^}]*color:var\(--bad\)/);
  h.view.dispose();
}

async function actualStudioNavigationAndRefreshRouteGlobalPage() {
  const studio = fs.readFileSync(__dirname + '/static/studio.js', 'utf8');
  const index = fs.readFileSync(__dirname + '/static/index.html', 'utf8');
  assert(index.indexOf('/static/ob_callbacks.js') < index.indexOf('/static/studio.js'));
  assert.match(index, /\/static\/ob_callbacks\.css\?v=20261012/);
  const start = studio.indexOf('const PAGES = ['), end = studio.indexOf('\n];', start) + 3;
  const lines = studio.split(/\r?\n/);
  let renderContext, disposed = 0, refreshed = 0, genericRefreshes = 0, homeRenders = 0;
  const elements = new Map(['page-title', 'breadcrumb', 'tool-search', 'navigation', 'main-content', 'refresh-page']
    .map(id => [id, {value: '', innerHTML: '', textContent: '', querySelectorAll: () => []}]));
  const sandbox = {window: {ObCallbacksPanel: {render: ctx => { renderContext = ctx; },
    dispose: () => disposed++, refresh: () => refreshed++}},
    state: {page: 'ob_callbacks', pid: 0, operations: {}, tablePage: 0, filter: ''},
    $: selector => elements.get(selector.slice(1)), download: () => {}, TOOLS: {}, rememberForm: () => {},
    renderHome: () => homeRenders++, refreshStatus: () => genericRefreshes++};
  vm.runInNewContext(studio.slice(start, end) + '\n' + ['function pageInfo(', 'function navigate(', 'function render(']
    .map(prefix => lines.find(line => line.startsWith(prefix))).join('\n') + '\n' +
    lines.find(line => line.startsWith("$('#refresh-page').onclick=")), sandbox);
  sandbox.render();
  assert.equal(elements.get('page-title').textContent, 'ObRegisterCallback Panel');
  assert.equal(elements.get('breadcrumb').textContent, 'DRIVER / GLOBAL');
  assert.match(elements.get('navigation').innerHTML, /data-page="ob_callbacks"/);
  assert.equal(Object.hasOwn(renderContext, 'pid'), false);
  assert.equal(renderContext.currentPage(), 'ob_callbacks');
  elements.get('refresh-page').onclick(); assert.equal(refreshed, 1); assert.equal(genericRefreshes, 0);
  sandbox.state.pid = 456; sandbox.state.name = 'Existing target'; sandbox.render();
  assert.equal(elements.get('breadcrumb').textContent, 'DRIVER / GLOBAL');
  sandbox.navigate('home'); assert(disposed >= 1); assert.equal(homeRenders, 1);
}

async function initialUnregisteredUsesSentinelsAndNeverAutoRegisters() {
  const h = harness(); h.fetch = async () => response(status('unregistered', {registration_attempts: 0,
    last_attempt_altitude: '-1', last_requested_minimum_altitude: -1, last_requested_maximum_altitude: -1,
    last_requested_maximum_fraction: 0}));
  await h.render(); await h.tick();
  assert.match(h.element('oc-status').innerHTML, /등록되지 않음/);
  assert.equal(h.element('oc-minimum').value, ''); assert.equal(h.element('oc-maximum').value, '');
  assert.equal(h.element('oc-fraction').value, '1000');
  assert.equal(h.element('oc-register').disabled, true); assert.equal(h.element('oc-unregister').disabled, true);
  const current = h.export().current;
  assert.equal(current.minimum_altitude, -1); assert.equal(current.maximum_altitude, -1);
  assert.equal(current.registered_altitude, '-1'); assert.equal(current.handler_address, '0x0');
  assert.equal(current.handler_address_valid, false); assert.equal(h.posts().length, 0);
  assert.match(h.element('oc-current').innerHTML, /마지막 등록 요청 기록|이전 기록/); h.view.dispose();
}

async function rangeValidationAndExactNumericPostContract() {
  const h = harness(); h.fetch = async path => response(path.endsWith('/status') ? status('unregistered') : actionReply('register'));
  await h.render();
  for (const values of [['', '0', '1000'], ['-1', '1', '1'], ['1', '0', '1'], ['0', '4294967296', '1'],
    ['0', '1', '1001'], ['0', '1', '-1'], ['0.5', '1', '1'], ['1e3', '1000', '1'],
    ['0', 'Infinity', '1'], ['0', '1', '1.5'], ['0', '18446744073709551615', '1'], ['0', '1', '']]) {
    inputRange(h, ...values); assert.equal(h.element('oc-register').disabled, true, JSON.stringify(values));
    await h.element('oc-register').onclick(); assert.equal(h.posts().length, 0);
  }
  for (const values of [['0', '0', '0'], ['0', '4294967295', '1000'], ['4294967295', '4294967295', '9'], ['0003', '0004', '0010']]) {
    inputRange(h, ...values); assert.equal(h.element('oc-register').disabled, false);
    await h.element('oc-range-form').onsubmit({preventDefault() {}}); await settle();
    const post = h.posts().at(-1);
    assert.equal(post.path, '/api/ob-callbacks/register'); assert.equal(post.options.headers['Content-Type'], 'application/json');
    assert.deepEqual(JSON.parse(post.options.body), {minimum_altitude: Number(values[0]),
      maximum_altitude: Number(values[1]), maximum_fraction: Number(values[2])});
  }
  assert.equal(h.posts().length, 4); h.view.dispose();
}

async function stateWorkerAndQueryErrorsGateBothActions() {
  for (const [state, worker, register, unregister] of [
    ['not_initialized', false, false, false], ['unregistered', false, true, false], ['failed', false, true, false],
    ['registered', false, false, true], ['registering', true, false, false], ['unregistering', true, false, false],
    ['unregistered', true, false, false], ['registered', true, false, false], ['failed', true, false, false]]) {
    const h = harness(); h.fetch = async () => response(status(state, {worker_active: worker})); await h.render();
    inputRange(h, '1', '2');
    assert.equal(h.element('oc-register').disabled, !register, state + ' register');
    assert.equal(h.element('oc-unregister').disabled, !unregister, state + ' unregister');
    if (!register) await h.element('oc-register').onclick();
    if (!unregister) await h.element('oc-unregister').onclick();
    assert.equal(h.posts().length, 0); h.view.dispose();
  }
  const h = harness(); h.fetch = async () => response(queryFailure('unsupported')); await h.render(); inputRange(h, '0', '1');
  assert.equal(h.element('oc-register').disabled, true); assert.equal(h.element('oc-unregister').disabled, true);
  await h.element('oc-register').onclick(); await h.element('oc-unregister').onclick();
  assert.equal(h.posts().length, 0); h.view.dispose();
}

async function acceptedRegisterNeedsActualCompletionAndLocksDoubleClick() {
  const h = harness(), held = deferred(); let live = status('unregistered');
  h.fetch = path => path.endsWith('/status') ? response(live) : held.promise; await h.render();
  inputRange(h, '4294967295', '4294967295', '1000');
  const first = h.element('oc-register').onclick(); await h.element('oc-register').onclick();
  assert.equal(h.posts().length, 1); assert.equal(h.element('oc-register').disabled, true);
  assert.equal(h.element('oc-minimum').disabled, true); assert.equal(h.element('oc-refresh').disabled, true);
  live = status('registering', {minimum_altitude: 4294967295, maximum_altitude: 4294967295,
    registration_status: '0x00000103', registration_status_code: 259});
  held.resolve(response(actionReply('register'))); await first; await settle();
  assert.match(h.element('oc-command-result').textContent, /수락/);
  assert.match(h.element('oc-status').innerHTML, /등록 진행 중/);
  assert.match(h.element('oc-current').innerHTML, /0x00000103/);
  assert.doesNotMatch(h.element('oc-status').className, /--registered/);
  assert.equal(h.element('oc-register').disabled, true); assert.equal(h.element('oc-unregister').disabled, true);
  live = status('registered', {minimum_altitude: 4294967295, maximum_altitude: 4294967295,
    registered_altitude: '4294967295.1000', handler_address: '0xFFFFFFFFFFFFFFF0'});
  await h.tick(1000);
  assert.match(h.element('oc-status').className, /--registered/);
  assert.match(h.element('oc-current').innerHTML, /0xFFFFFFFFFFFFFFF0|4294967295.1000/);
  assert.equal(h.element('oc-unregister').disabled, false); assert.equal(h.posts().length, 1); h.view.dispose();
}

async function unregisterCompletesThenQueriesClearedLiveFields() {
  const h = harness(); let live = status();
  h.fetch = path => {
    if (path.endsWith('/status')) return response(live);
    live = status('unregistered'); return response(actionReply('unregister'));
  };
  await h.render(); inputRange(h, '7', '8', '12'); await h.element('oc-unregister').onclick(); await settle();
  assert.equal(h.posts().length, 1); assert.equal(h.posts()[0].path, '/api/ob-callbacks/unregister');
  assert.deepEqual(JSON.parse(h.posts()[0].options.body), {});
  assert.match(h.element('oc-command-result').textContent, /해제 요청이 완료/);
  assert.match(h.element('oc-status').innerHTML, /등록되지 않음/);
  const snapshot = h.export();
  assert.equal(snapshot.current.handler_address, '0x0'); assert.equal(snapshot.current.handler_address_valid, false);
  assert.equal(snapshot.current.minimum_altitude, -1); assert.equal(snapshot.current.maximum_altitude, -1);
  assert.equal(snapshot.current.registered_altitude, '-1');
  assert.equal(snapshot.current.last_requested_minimum_altitude, 80000);
  assert.deepEqual(snapshot.input_range, {minimum_altitude: 7, maximum_altitude: 8, maximum_fraction: 12});
  assert.equal(h.element('oc-register').disabled, false); h.view.dispose();
}

async function actionFailureShowsEscapedAlertAndNeverAutoRetries() {
  const h = harness();
  h.fetch = path => response(path.endsWith('/status') ? status('unregistered') :
    actionReply('register', {success: false, accepted: false, error: '<script>busy</script>', error_kind: 'busy'}));
  await h.render(); inputRange(h, '0', '1'); await h.element('oc-register').onclick(); await settle();
  const notice = h.element('oc-command-result');
  assert.equal(notice.getAttribute('role'), 'alert'); assert.match(notice.className, /--error/);
  assert.match(notice.textContent, /등록 요청 실패|자동으로 다시 요청하지 않습니다/);
  assert.match(h.element('oc-status').innerHTML, /등록되지 않음/);
  assert.doesNotMatch(h.element('oc-status').innerHTML, /등록 실패|등록 성공/);
  await h.tick(); await h.view.refresh(); assert.equal(h.posts().length, 1);
  assert.equal(h.export().last_control_notice.error, true); h.view.dispose();
}

async function malformedActionAcknowledgementsAreNotSuccess() {
  const h = harness(); let reply;
  h.fetch = path => path.endsWith('/status') ? response(status('unregistered')) : reply;
  await h.render(); inputRange(h, '1', '1');
  for (const body of [null, [], actionReply('register', {accepted: false}), actionReply('unregister'),
    actionReply('register', {readonly: true}), actionReply('register', {packet_valid: false}),
    actionReply('register', {transport_ok: false}), actionReply('register', {completed: true}),
    actionReply('register', {unsupported: true}), actionReply('register', {bytes_returned: 31}),
    actionReply('register', {result_status: null}), actionReply('register', {result_status: '0xC0000022'})]) {
    reply = response(body); await h.element('oc-register').onclick(); await settle();
    assert.match(h.element('oc-command-result').textContent, /요청 실패/);
    assert.doesNotMatch(h.element('oc-command-result').textContent, /수락되었습니다/);
  }
  reply = {ok: true, json: async () => { throw Error('bad JSON'); }};
  await h.element('oc-register').onclick(); await settle();
  assert.match(h.element('oc-command-result').textContent, /응답을 읽을 수 없습니다/); h.view.dispose();
}

async function globalDraftSurvivesRenderTargetChangesAndNavigation() {
  const h = harness(); h.fetch = async () => response(status('unregistered')); await h.render();
  inputRange(h, '80000', '4294967295', '1000'); const originalInput = h.element('oc-minimum');
  await h.render(); assert.equal(h.element('oc-minimum'), originalInput, 'Unnecessary render must retain input node');
  assert.equal(h.element('oc-minimum').value, '80000');
  h.view.dispose(); h.page = 'home'; h.root.innerHTML = '<p>다른 페이지</p>';
  h.page = 'ob_callbacks'; await h.render();
  assert.equal(h.element('oc-minimum').value, '80000'); assert.equal(h.element('oc-maximum').value, '4294967295');
  assert.equal(h.element('oc-fraction').value, '1000'); assert.equal(h.posts().length, 0);
  h.view.reset(); await h.render(); assert.equal(h.element('oc-minimum').value, ''); h.view.dispose();
}

async function navigationCannotRetryOrForgetPendingMutation() {
  for (const returnBeforeCompletion of [true, false]) {
    const h = harness(), held = deferred(); let live = status('unregistered');
    h.fetch = path => path.endsWith('/status') ? response(live) : held.promise;
    await h.render(); inputRange(h, '0', '0', '0'); const first = h.element('oc-register').onclick();
    h.view.dispose(); h.page = 'home'; h.root.innerHTML = '<p>다른 페이지</p>';
    if (returnBeforeCompletion) {
      h.page = 'ob_callbacks'; await h.render();
      assert.equal(h.element('oc-minimum').value, '0'); assert.equal(h.element('oc-register').disabled, true);
      await h.element('oc-register').onclick(); assert.equal(h.posts().length, 1);
    }
    live = status('registering'); held.resolve(response(actionReply('register'))); await first; await settle();
    if (!returnBeforeCompletion) {
      assert.equal(h.root.innerHTML, '<p>다른 페이지</p>'); assert.equal(h.timers.size, 0);
      h.page = 'ob_callbacks'; await h.render();
    }
    assert.match(h.element('oc-status').innerHTML, /등록 진행 중/);
    assert.equal(h.posts().length, 1); h.view.dispose();
  }
}

async function hiddenPageDoesNotCancelOrRepeatMutation() {
  const h = harness(), held = deferred(); let live = status('unregistered');
  h.fetch = path => path.endsWith('/status') ? response(live) : held.promise;
  await h.render(); inputRange(h, '0', '1'); const first = h.element('oc-register').onclick();
  await h.hide(true); assert.equal(h.posts()[0].options.signal, undefined);
  live = status(); held.resolve(response(actionReply('register'))); await first; await settle();
  assert.match(h.element('oc-status').innerHTML, /조회 일시 중지/); assert.equal(h.timers.size, 0);
  await h.element('oc-register').onclick(); assert.equal(h.posts().length, 1);
  await h.hide(false); assert.match(h.element('oc-status').className, /--registered/);
  assert.equal(h.posts().length, 1); h.view.dispose();
}

async function wideCountersAndHandlerValidityCannotProduceFalseGreen() {
  const h = harness(); h.fetch = async () => response(status('registered', {registration_attempts: 4299262263296,
    registration_generation: 4294967295, handler_address: '0xFFFFFFFFFFFFFFF0'})); await h.render();
  assert.match(h.element('oc-current').innerHTML, /4299262263296|4294967295|0xFFFFFFFFFFFFFFF0/);
  for (const extra of [{registration_attempts: Number.MAX_SAFE_INTEGER + 1}, {handler_address: '0x0'},
    {handler_address_valid: false}, {handler_address: '<img src=x>'}, {minimum_altitude: -1},
    {registered_altitude: '-1'}, {registration_status: '0xC0000022'}]) {
    h.fetch = async () => response(status('registered', extra)); await h.view.refresh();
    assert.match(h.element('oc-status').className, /--query-error/); assert.equal(h.element('oc-unregister').disabled, true);
  }
  h.view.dispose();
}

(async () => {
  const tests = [registeredShowsMeasuredSettingsWithoutPid, actualRegistrationFailureUsesRedAlertAndKeepsSettings,
    intermediateAndStoppedStatesAreExplicit, queryFailuresClearSuccessAndNeverClaimRegistrationFailure,
    malformedAndNetworkErrorsCannotLeaveGreen, disposalAbortsAndRejectsLateFetchAndJson,
    newestRequestWinsOverIgnoredAbort, renderReentryRejectsPriorPageOwner, pollingOnlyRunsWhileVisibleAndUsesGet,
    hiddenOutstandingReplyIsIgnoredUntilFreshQuery, boundedHistoryAndJsonExportPreserveMeasuredSettings,
    escapedAccessibleWarningsAndStyles, actualStudioNavigationAndRefreshRouteGlobalPage,
    initialUnregisteredUsesSentinelsAndNeverAutoRegisters, rangeValidationAndExactNumericPostContract,
    stateWorkerAndQueryErrorsGateBothActions, acceptedRegisterNeedsActualCompletionAndLocksDoubleClick,
    unregisterCompletesThenQueriesClearedLiveFields, actionFailureShowsEscapedAlertAndNeverAutoRetries,
    malformedActionAcknowledgementsAreNotSuccess, globalDraftSurvivesRenderTargetChangesAndNavigation,
    navigationCannotRetryOrForgetPendingMutation, hiddenPageDoesNotCancelOrRepeatMutation,
    wideCountersAndHandlerValidityCannotProduceFalseGreen];
  for (const test of tests) { await test(); console.log('PASS ' + test.name); }
  console.log('PASS ' + tests.length + ' ObRegisterCallback UI mock groups');
})().catch(error => { console.error(error); process.exitCode = 1; });
