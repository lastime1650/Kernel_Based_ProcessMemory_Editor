/* Mock DOM/fetch only: this suite never opens a process or driver. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const source = fs.readFileSync(__dirname + '/static/manual_v4.js', 'utf8');
const settle = () => new Promise(resolve => setImmediate(resolve));
const response = (body, ok = true) => ({ok, json: async () => body});
function deferred() {
  let resolve;
  const promise = new Promise(done => { resolve = done; });
  return {promise, resolve};
}

function harness() {
  let elements = new Map(), html = '', busy = false, timerId = 0;
  let currentPid = 123, startKey = '18446744073709551615', connected = true, jobs = [];
  let fetchHandler = null;
  let picker = {success: true, cancelled: false, path: 'C:\\fixtures\\Picked.dll', display_name: 'Picked.dll', size: 4096};
  const calls = [], timers = new Map(), busyChanges = [];
  const root = {
    get innerHTML() { return html; },
    set innerHTML(value) {
      html = value;
      elements = new Map();
      for (const match of value.matchAll(/<(?:input|button|p|div)\b[^>]*\bid="([^"]+)"[^>]*>/g)) {
        const valueMatch = /\bvalue="([^"]*)"/.exec(match[0]);
        elements.set(match[1], {
          value: valueMatch ? valueMatch[1].replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&') : '',
          innerHTML: '', textContent: '', disabled: false, error: false,
          classList: {toggle(name, enabled) { if (name === 'error') elements.get(match[1]).error = enabled; }}
        });
      }
    },
    querySelector(selector) { return elements.get(selector.slice(1)); }
  };
  const sandbox = {
    window: {}, console,
    fetch: async (path, options = {}) => {
      calls.push({path, options});
      if (fetchHandler) return fetchHandler(path, options);
      if (path === '/api/manual-v4/jobs') return response({success: true, jobs});
      if (path === '/api/manual-v4/select-dll') return response(picker);
      if (path === '/api/manual-v4/map') return response({success: true, id: 'job-1', state: 'queued'});
      throw Error('Unexpected endpoint: ' + path);
    },
    setTimeout: callback => { timers.set(++timerId, callback); return timerId; },
    clearTimeout: id => timers.delete(id)
  };
  vm.runInNewContext(source, sandbox);
  const suite = {
    root, pid: 123, currentPid: () => currentPid,
    identity: () => startKey, connected: () => connected, isBusy: () => busy,
    setBusy: value => { busy = value; busyChanges.push(value); }
  };
  return {
    view: sandbox.window.ManualV4, root, calls, timers, busyChanges, suite,
    element: id => elements.get(id),
    get busy() { return busy; },
    set busy(value) { busy = value; },
    set pid(value) { currentPid = value; },
    set key(value) { startKey = value; },
    set connected(value) { connected = value; },
    set jobs(value) { jobs = value; },
    set fetch(value) { fetchHandler = value; },
    maps: () => calls.filter(call => call.path === '/api/manual-v4/map'),
    setPicker(value) { picker = value; },
    async render() { this.view.render(suite); await settle(); },
    async tick() {
      const [id, callback] = timers.entries().next().value;
      timers.delete(id);
      await callback();
    }
  };
}

async function navigationAndPollingOnlyQuery() {
  const h = harness();
  await h.render();
  assert.match(h.root.innerHTML, /ManualV4/);
  assert.match(h.root.innerHTML, /failcode 0/);
  assert.match(h.root.innerHTML, /id="mv4-select"[^>]*>DLL 파일 선택/);
  assert.match(h.root.innerHTML, /assets 폴더로 복사하지 않습니다/);
  assert.doesNotMatch(h.root.innerHTML, /type="file"|mv4-path|절대 경로 입력|mv4-runtime|data-mv4-action|PDB/);
  assert.equal(h.element('mv4-send').disabled, false);
  assert.equal(h.element('mv4-filename').textContent, '선택된 DLL 없음 · 최대 64MiB');
  await h.tick();
  assert(h.calls.every(call => !call.options.method || call.options.method === 'GET'));
  assert.equal(h.timers.size, 1);
  h.view.dispose();
  assert.equal(h.timers.size, 0);
}

async function identityTargetConnectionAndBusyGate() {
  const h = harness();
  await h.render();
  for (const key of ['', '0', '01', '-1', '1e3', '18446744073709551616']) {
    h.key = key;
    h.view.targetChanged();
    assert.equal(h.element('mv4-send').disabled, true, 'Invalid process key: ' + key);
    await h.element('mv4-send').onclick();
  }
  h.key = '777';
  h.pid = 456;
  h.view.targetChanged();
  assert.equal(h.element('mv4-send').disabled, true);
  await h.element('mv4-send').onclick();
  h.pid = 123;
  h.connected = false;
  h.view.targetChanged();
  assert.equal(h.element('mv4-send').disabled, true);
  await h.element('mv4-send').onclick();
  h.connected = true;
  h.busy = true;
  h.view.targetChanged();
  assert.equal(h.element('mv4-send').disabled, true);
  await h.element('mv4-send').onclick();
  assert.equal(h.maps().length, 0);
  h.busy = false;
  h.view.targetChanged();
  assert.equal(h.element('mv4-send').disabled, false);
  h.view.dispose();
}

async function filePickerValidationAndExactContract() {
  const h = harness();
  await h.render();
  h.setPicker({success: true, cancelled: true});
  await h.element('mv4-select').onclick();
  assert.equal(h.maps().length, 0);
  assert.match(h.element('mv4-status').textContent, /취소/);
  await h.element('mv4-send').onclick();
  assert.equal(h.maps().length, 0);
  assert.equal(h.element('mv4-status').error, true);

  const path = 'C:\\fixtures\\Pícked & Example.dll';
  h.setPicker({success: true, cancelled: false, path, display_name: 'Pícked & Example.dll', size: 4096});
  await h.element('mv4-select').onclick();
  assert.match(h.element('mv4-filename').textContent, /C:\\fixtures\\Pícked & Example\.dll/);
  h.element('mv4-only-mapping').checked = true;
  await h.element('mv4-send').onclick();
  const call = h.maps().at(-1);
  assert.equal(call.path, '/api/manual-v4/map');
  assert.equal(call.options.method, 'POST');
  assert.equal(call.options.headers['Content-Type'], 'application/json');
  assert.deepEqual(JSON.parse(call.options.body), {
    pid: 123, process_start_key: '18446744073709551615', path,
    display_name: 'Pícked & Example.dll', only_mapping: true
  });
  assert.equal(h.busy, false);
  assert.equal(h.timers.size, 1);
  h.view.dispose();
}

async function doubleClickAndDisposeDuringMutation() {
  const h = harness(), held = deferred();
  await h.render();
  await h.element('mv4-select').onclick();
  h.fetch = (path) => path === '/api/manual-v4/map' ? held.promise : response({success: true, jobs: []});
  const first = h.element('mv4-send').onclick();
  const second = h.element('mv4-send').onclick();
  await settle();
  assert.equal(h.maps().length, 1);
  assert.equal(h.busy, true);
  assert.equal(h.element('mv4-select').disabled, true);
  h.view.dispose();
  const html = h.root.innerHTML;
  held.resolve(response({success: true, state: 'queued'}));
  await Promise.all([first, second]);
  assert.equal(h.root.innerHTML, html);
  assert.equal(h.busy, false);
  assert.deepEqual(h.busyChanges, [true, false]);
  assert.equal(h.timers.size, 0);
}

async function resultsKeepPrecisionAndEscapeMarkup() {
  const h = harness();
  h.jobs = [{state: 'mapped', pid: 123, path: 'C:\\<img onerror="bad">.dll',
    mapped_base: '0xfffffffffffffff0', entry_point: '0xfffffffffffffff8', result_status: '0x00000000', failcode: 0, failmessage: '',
    error: '<script>bad()</script>', output: '<img src=x>'},
    {state: 'indeterminate', pid: 123, path: 'C:\\unknown.dll', mapped_base: '0x0', entry_point: '0x0', failcode: null},
    {state: 'failed', pid: 123, path: 'C:\\bad.dll', mapped_base: '0x0', entry_point: '0x0', failcode: 119,
      failmessage: 'ZwProtectVirtualMemory: protect=0x20; NTSTATUS=0xC0000022\n<script>"API"</script>'}];
  await h.render();
  const html = h.element('mv4-jobs').innerHTML;
  assert.match(html, /0xfffffffffffffff0/);
  assert.match(html, /0xfffffffffffffff8/);
  assert.match(html, /매핑 완료/);
  assert.match(html, /failcode\) <code>0<\/code> · SUCCESS/);
  assert.match(html, /failcode\) <code>119<\/code>/);
  assert.match(html, /failcode\) <code>미확인<\/code>/);
  assert.match(html, /결과 확인 불가/);
  assert.match(html, /자동으로 다시 요청하지 않습니다/);
  assert.match(html, /&lt;script&gt;/);
  assert.match(html, /상세 오류 \(failmessage\)/);
  assert.match(html, /white-space:pre-wrap;overflow-wrap:anywhere/);
  assert.match(html, /ZwProtectVirtualMemory: protect=0x20; NTSTATUS=0xC0000022\n&lt;script&gt;&quot;API&quot;&lt;\/script&gt;/);
  assert.match(html, /<pre[^>]+>SUCCESS<\/pre>/);
  assert.match(html, /<pre[^>]+>미확인<\/pre>/);
  assert.doesNotMatch(html, /<script>|<img|<button|data-mv4-action/);
  h.view.dispose();
}

async function staleQueriesCannotOverwriteCurrentView() {
  const h = harness(), old = deferred();
  let count = 0;
  h.fetch = () => ++count === 1 ? old.promise : response({success: true, jobs: [{state: 'mapped', pid: 123, path: 'new.dll'}]});
  h.view.render(h.suite);
  await h.render();
  assert.match(h.element('mv4-jobs').innerHTML, /new\.dll/);
  old.resolve(response({success: true, jobs: [{state: 'failed', pid: 123, path: 'stale.dll'}]}));
  await settle();
  assert.match(h.element('mv4-jobs').innerHTML, /new\.dll/);
  assert.doesNotMatch(h.element('mv4-jobs').innerHTML, /stale\.dll/);
  assert.equal(h.timers.size, 1);
  h.view.dispose();
}

async function failuresNeverRetryMapping() {
  const h = harness();
  await h.render();
  await h.element('mv4-select').onclick();
  h.fetch = path => path === '/api/manual-v4/map' ? response({success: false, detail: '커널 요청 실패'}, false) : response({success: true, jobs: []});
  await h.element('mv4-send').onclick();
  assert.equal(h.maps().length, 1);
  assert.equal(h.element('mv4-status').textContent, '커널 요청 실패');
  assert.equal(h.element('mv4-status').error, true);
  assert.equal(h.busy, false);
  await h.tick();
  assert.equal(h.maps().length, 1);
  h.view.reset();
  await h.render();
  assert.equal(h.element('mv4-filename').textContent, '선택된 DLL 없음 · 최대 64MiB');
  assert.equal(h.maps().length, 1);
  h.view.dispose();
}

function driverVersionGate() {
  const studio = fs.readFileSync(__dirname + '/static/studio.js', 'utf8');
  const gate = /function manualV4Connected\(\)\{[^\n]+\}/.exec(studio);
  assert(gate, 'Studio must apply the ManualV4 driver version gate');
  const sandbox = {state: {status: null}};
  vm.runInNewContext(gate[0], sandbox);
  for (const [major, minor, build, success, expected] of [
    [2, 4, 20261011, true, false], [2, 5, 20261010, true, false],
    [2, 5, 20261012, false, false], [2, 5, 20261011, true, false],
    [2, 5, 20261012, true, false], [2, 6, 20261011, true, false], [2, 6, 20261012, true, true], [3, 0, 20261012, true, true]
  ]) {
    sandbox.state.status = {major_version: major, minor_version: minor, build_number: build, success};
    assert.equal(sandbox.manualV4Connected(), expected, `Driver ${major}.${minor}, build ${build}`);
  }
  assert.equal((studio.match(/connected:manualV4Connected/g) || []).length, 1);
}

(async () => {
  for (const test of [navigationAndPollingOnlyQuery, identityTargetConnectionAndBusyGate,
    filePickerValidationAndExactContract, doubleClickAndDisposeDuringMutation,
    resultsKeepPrecisionAndEscapeMarkup, staleQueriesCannotOverwriteCurrentView,
    failuresNeverRetryMapping, driverVersionGate]) await test();
  console.log('PASS ManualV4 kernel-map UI: 8 mock regression groups');
})().catch(error => { console.error(error); process.exitCode = 1; });
