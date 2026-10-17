'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

const source = fs.readFileSync(__dirname + '/static/apc_normalize.js', 'utf8');
const studio = fs.readFileSync(__dirname + '/static/studio.js', 'utf8');
const index = fs.readFileSync(__dirname + '/static/index.html', 'utf8');
const settle = () => new Promise(resolve => setImmediate(resolve));

class Element {
  constructor(attributes = {}) {
    this.attributes = attributes;
    this.dataset = {};
    this.value = attributes.value || '';
    this.disabled = Object.hasOwn(attributes, 'disabled');
    this.className = attributes.class || '';
    this.textContent = '';
    this.onclick = null;
    this.oninput = null;
    this.onsubmit = null;
    this.children = [];
    for (const [name, value] of Object.entries(attributes)) {
      if (name.startsWith('data-')) this.dataset[name.slice(5).replace(/-([a-z])/g, (_, c) => c.toUpperCase())] = value;
    }
  }
  set innerHTML(value) {
    this.html = value;
    this.children = [];
    for (const match of value.matchAll(/<tr\b([^>]*)>/g)) {
      const attrs = Object.fromEntries([...match[1].matchAll(/([\w-]+)(?:="([^"]*)")?/g)].map(m => [m[1], m[2] ?? '']));
      const child = new Element(attrs);
      child.querySelector = selector => selector === '[data-apcn-apply]' ? child.applyButton : null;
      child.applyButton = new Element({'data-apcn-apply': ''});
      this.children.push(child);
    }
  }
  get innerHTML() { return this.html || ''; }
  querySelector(selector) { return this.children.find(child => selector === '[data-apcn-apply]' && child.dataset.apcnApply !== undefined) || null; }
  querySelectorAll(selector) {
    return selector === '[data-apcn-tid]' ? this.children.filter(child => child.dataset.apcnTid !== undefined) : [];
  }
}

function harness({pid = 4321} = {}) {
  let html = '', page = 'apc_normalize', currentPid = pid;
  const nodes = new Map(), calls = [], pending = [], toasts = [], selected = [];
  const root = {
    set innerHTML(value) {
      html = value;
      nodes.clear();
      for (const match of value.matchAll(/<([\w-]+)\b([^>]*)\bid="([^"]+)"([^>]*)>/g)) {
        const attrs = Object.fromEntries([...`${match[2]} ${match[4]}`.matchAll(/([\w-]+)(?:="([^"]*)")?/g)].map(m => [m[1], m[2] ?? '']));
        nodes.set(match[3], new Element(attrs));
      }
    },
    get innerHTML() { return html; },
    querySelector(selector) { return nodes.get(selector.slice(1)) || null; }
  };
  const sandbox = {window: {}, console};
  vm.createContext(sandbox);
  vm.runInContext(source, sandbox, {filename: 'apc_normalize.js'});
  const ctx = {
    root, pid, currentPid: () => currentPid, currentPage: () => page,
    api: (path, body) => {
      const call = {path, body}; calls.push(call);
      return new Promise((resolve, reject) => pending.push({call, resolve, reject}));
    },
    toast: (text, error) => toasts.push({text, error}),
    openProcess: () => { calls.push({path: 'open-process'}); },
    onSelectThread: tid => selected.push(tid)
  };
  return {
    view: sandbox.window.ApcNormalize, ctx, root, calls, pending, toasts, selected,
    element: id => root.querySelector('#' + id),
    setPage: value => { page = value; }, setPid: value => { currentPid = value; },
    rows: () => root.querySelector('#apcn-thread-rows').querySelectorAll('[data-apcn-tid]'),
    async resolveThreads(threads, extra = {}) {
      const request = pending.shift(); request.resolve({success: true, threads, ...extra}); await settle();
    }
  };
}

async function autoQuerySelectRefreshAndSendExactU64Payload() {
  const h = harness();
  h.view.render(h.ctx);
  assert.equal(h.pending.length, 1, 'navigation immediately fetches threads');
  assert.equal(h.pending[0].call.path, '/api/process/4321/threads?max_threads=64');
  await h.resolveThreads([{thread_id: 7654, start_address: '0x7FF612340000', priority: 8,
    state: 5, wait_reason: 0, context_switches: 92}], {total: 1});
  assert.match(h.element('apcn-thread-status').textContent, /1개 스레드/);
  assert.match(h.root.innerHTML, /스레드 테이블 새로 고침/);
  assert.equal(h.rows().length, 1);
  h.rows()[0].onclick();
  assert.equal(h.element('apcn-tid').value, '7654');
  assert.equal(h.element('apcn-submit').disabled, false);
  assert.equal(h.selected.at(-1), 7654);

  h.element('apcn-refresh').onclick();
  assert.equal(h.pending[0].call.path, '/api/process/4321/threads?max_threads=64');
  await h.resolveThreads([{thread_id: 7654, start_address: '0x7FF612340000', priority: 8,
    state: 5, wait_reason: 0, context_switches: 93}], {total: 1});
  assert.equal(h.rows().length, 1);

  h.element('apcn-address').value = '0x00007FF612341000';
  h.element('apcn-context').value = '18446744073709551614';
  h.element('apcn-buffer1').value = '0';
  h.element('apcn-buffer2').value = '0xFFFFFFFFFFFFFFFF';
  h.element('apcn-form').onsubmit({preventDefault() {}});
  const submitted = h.pending.shift(), call = submitted.call;
  assert.equal(call.path, '/api/apc/normalize');
  assert.deepEqual(JSON.parse(JSON.stringify(call.body)), {
    attached_process_id: 4321, selected_thread_id: 7654,
    normalize_address: '0x7FF612341000', normalize_context: '0xFFFFFFFFFFFFFFFE',
    system_buffer1: '0x0', system_buffer2: '0xFFFFFFFFFFFFFFFF'
  });
  submitted.resolve({success: true, result_status: '0x00000000'});
  await settle();
  assert.match(h.element('apcn-submit-status').textContent, /APC 요청 등록 성공/);
}

async function rejectsInvalidAddressesAndDoesNotSubmit() {
  const h = harness(); h.view.render(h.ctx);
  await h.resolveThreads([{thread_id: 7, start_address: '0x10', priority: 8, state: 5, wait_reason: 0, context_switches: 1}]);
  h.rows()[0].onclick();
  h.element('apcn-address').value = 'not-an-address';
  h.element('apcn-form').onsubmit({preventDefault() {}});
  assert.equal(h.pending.length, 0);
  assert.match(h.element('apcn-submit-status').textContent, /10진수 또는 0x/);
  assert.equal(h.toasts.at(-1).error, true);
}

async function staleRefreshCannotUpdateAfterLeavingPage() {
  const h = harness(); h.view.render(h.ctx);
  const old = h.pending.shift();
  h.setPage('home'); h.view.dispose();
  old.resolve({success: true, threads: [{thread_id: 99}]});
  await settle();
  assert.equal(h.rows().length, 0, 'late response must not populate thread rows after leaving the page');
}

async function integrationRegistersNavigationRendererAndRefresh() {
  assert.match(studio, /\['apc_normalize','APC_NORMALIZE'/);
  assert.match(studio, /window\.ApcNormalize\.render\(/);
  assert.match(studio, /window\.ApcNormalize\?\.refresh\(\)/);
  assert.match(index, /apc_normalize\.js/);
  assert.match(index, /apc_normalize\.css/);
}

(async () => {
  await autoQuerySelectRefreshAndSendExactU64Payload();
  await rejectsInvalidAddressesAndDoesNotSubmit();
  await staleRefreshCannotUpdateAfterLeavingPage();
  await integrationRegistersNavigationRendererAndRefresh();
  console.log('APC_NORMALIZE browser checks passed');
})().catch(error => { console.error(error); process.exitCode = 1; });
