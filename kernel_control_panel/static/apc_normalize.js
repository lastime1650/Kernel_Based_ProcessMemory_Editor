/* APC_NORMALIZE thread picker and request form. */
(() => {
  'use strict';

  const esc = value => String(value ?? '').replace(/[&<>"']/g, ch => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  }[ch]));
  let context = null, epoch = 0, selectedPid = 0, selectedTid = '', threads = [];
  let draft = {normalize_address: '', normalize_context: '0', system_buffer1: '0', system_buffer2: '0'};

  const q = id => context?.root.querySelector('#' + id);
  const current = (ctx, token, pid) => context === ctx && epoch === token &&
    (!ctx.currentPage || ctx.currentPage() === 'apc_normalize') && Number(ctx.currentPid?.() ?? ctx.pid) === pid;

  function dispose() {
    epoch++;
    context = null;
  }

  function render(ctx) {
    context = ctx;
    const token = ++epoch;
    const pid = Number(ctx.pid || 0);
    if (pid !== selectedPid) {
      selectedPid = pid;
      selectedTid = '';
      threads = [];
      draft = {normalize_address: '', normalize_context: '0', system_buffer1: '0', system_buffer2: '0'};
    }

    ctx.root.innerHTML = `<section class="card apcn-card">
      <div class="card-head"><div><h2>프로세스 스레드</h2><p>대상 프로세스의 스레드를 불러옵니다. 행을 선택하면 APC 대상 TID에 적용됩니다.</p></div>
      <span class="chip">${pid ? `Attached Process Id · ${pid}` : '프로세스를 선택하세요'}</span></div>
      <div class="apcn-table-toolbar"><span id="apcn-thread-status" class="subtle" role="status" aria-live="polite">${pid ? '스레드 목록을 불러옵니다…' : '대상 프로세스를 먼저 선택하세요.'}</span>
      <button type="button" id="apcn-refresh" class="secondary small" aria-label="스레드 테이블 새로 고침" ${pid ? '' : 'disabled'}>스레드 테이블 새로 고침</button></div>
      <div class="table-wrap"><table><thead><tr><th>선택</th><th>Thread Id</th><th>시작 주소</th><th>우선순위</th><th>상태</th><th>대기 사유</th><th>컨텍스트 전환</th></tr></thead>
      <tbody id="apcn-thread-rows"><tr><td colspan="7" class="subtle">${pid ? '조회 중…' : '대상 프로세스를 선택하세요.'}</td></tr></tbody></table></div>
    </section>
    <section class="card apcn-card">
      <div class="card-head"><div><h2>APC_NORMALIZE 요청</h2><p>선택한 프로세스와 스레드에 주소와 인자를 전달해 APC 요청을 등록합니다.</p></div></div>
      <div class="apcn-target-fields"><label>Attached Process Id<input id="apcn-pid" value="${pid || ''}" readonly></label>
      <label>Selected Thread Id<input id="apcn-tid" value="${esc(selectedTid)}" readonly></label></div>
      <form id="apcn-form"><div class="fields apcn-address-fields">
        <label>Normalize_Address (PVOID)<input id="apcn-address" name="normalize_address" value="${esc(draft.normalize_address)}" placeholder="0x00007FF612341000" autocomplete="off" spellcheck="false" required></label>
        <label>Normalize_Context (PVOID)<input id="apcn-context" name="normalize_context" value="${esc(draft.normalize_context)}" placeholder="0x0" autocomplete="off" spellcheck="false"></label>
        <label>SystemBuffer 1 (PVOID)<input id="apcn-buffer1" name="system_buffer1" value="${esc(draft.system_buffer1)}" placeholder="0x0" autocomplete="off" spellcheck="false"></label>
        <label>SystemBuffer 2 (PVOID)<input id="apcn-buffer2" name="system_buffer2" value="${esc(draft.system_buffer2)}" placeholder="0x0" autocomplete="off" spellcheck="false"></label>
      </div><div class="actions"><button type="submit" id="apcn-submit" ${pid && selectedTid ? '' : 'disabled'}>커널에 APC 요청</button>
      <span id="apcn-submit-status" class="busy-note" role="status" aria-live="polite"></span></div></form>
    </section>`;

    q('apcn-refresh').onclick = () => refreshThreads(ctx, token, pid);
    q('apcn-form').onsubmit = event => { event.preventDefault(); submit(ctx, token, pid); };
    for (const [id, key] of [['apcn-address', 'normalize_address'], ['apcn-context', 'normalize_context'],
      ['apcn-buffer1', 'system_buffer1'], ['apcn-buffer2', 'system_buffer2']]) {
      q(id).oninput = event => { draft[key] = event.target.value; };
    }
    bindRows(ctx, token, pid);
    renderRows();
    if (pid) void refreshThreads(ctx, token, pid);
    else q('apcn-refresh').onclick = () => ctx.openProcess?.();
  }

  function bindRows(ctx, token, pid) {
    const body = q('apcn-thread-rows');
    for (const row of body.querySelectorAll('[data-apcn-tid]')) {
      const select = () => {
        if (!current(ctx, token, pid)) return;
        selectedTid = row.dataset.apcnTid;
        q('apcn-tid').value = selectedTid;
        q('apcn-submit').disabled = !pid || !selectedTid;
        ctx.onSelectThread?.(Number(selectedTid));
        renderRows();
      };
      row.onclick = select;
      row.onkeydown = event => {
        if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); select(); }
      };
      const apply = row.querySelector('[data-apcn-apply]');
      if (apply) apply.onclick = event => { event.stopPropagation(); select(); };
    }
  }

  function renderRows() {
    const body = q('apcn-thread-rows');
    if (!body) return;
    if (!threads.length) {
      body.innerHTML = `<tr><td colspan="7" class="subtle">${selectedPid ? '표시할 스레드가 없습니다.' : '대상 프로세스를 선택하세요.'}</td></tr>`;
      return;
    }
    body.innerHTML = threads.map(thread => {
      const tid = String(thread.thread_id);
      const selected = tid === selectedTid;
      return `<tr data-apcn-tid="${esc(tid)}" tabindex="0" role="button" aria-selected="${selected}" class="${selected ? 'apcn-selected' : ''}">
        <td><button type="button" class="secondary small" data-apcn-apply>적용</button></td>
        <td class="mono">${esc(tid)}</td><td class="mono">${esc(thread.start_address)}</td>
        <td>${esc(thread.priority)}</td><td>${esc(thread.state)}</td><td>${esc(thread.wait_reason)}</td><td>${esc(thread.context_switches)}</td></tr>`;
    }).join('');
    const ctx = context, token = epoch, pid = selectedPid;
    bindRows(ctx, token, pid);
  }

  async function refreshThreads(ctx = context, token = epoch, pid = selectedPid) {
    if (!ctx || !pid || !current(ctx, token, pid)) return;
    const button = q('apcn-refresh'), status = q('apcn-thread-status');
    if (button) button.disabled = true;
    if (status) { status.className = 'subtle'; status.textContent = '스레드 목록 조회 중…'; }
    try {
      const result = await ctx.api(`/api/process/${pid}/threads?max_threads=64`);
      if (!current(ctx, token, pid)) return;
      if (!result.success) throw Error(result.error || result.result_status || '스레드 목록 조회에 실패했습니다.');
      threads = Array.isArray(result.threads) ? result.threads : [];
      if (!threads.some(thread => String(thread.thread_id) === selectedTid)) {
        selectedTid = '';
        ctx.onSelectThread?.(null);
      }
      q('apcn-tid').value = selectedTid;
      q('apcn-submit').disabled = !selectedTid;
      if (status) { status.className = 'subtle'; status.textContent = `${result.total ?? threads.length}개 스레드${result.truncated ? ' · 반환 상한 적용' : ''}`; }
      renderRows();
    } catch (error) {
      if (!current(ctx, token, pid)) return;
      threads = [];
      selectedTid = '';
      q('apcn-tid').value = '';
      q('apcn-submit').disabled = true;
      ctx.onSelectThread?.(null);
      renderRows();
      if (status) status.textContent = error.message;
      if (status) status.className = 'subtle error';
    } finally {
      if (current(ctx, token, pid) && button) button.disabled = false;
    }
  }

  function parsePointer(value, label, allowZero) {
    const text = String(value ?? '').trim();
    if (!/^(?:0[xX][0-9a-fA-F]+|[0-9]+)$/.test(text)) throw Error(`${label}: 10진수 또는 0x 형식으로 입력하세요.`);
    const parsed = BigInt(text);
    if (parsed < 0n || parsed > 0xFFFFFFFFFFFFFFFFn || (!allowZero && parsed === 0n)) {
      throw Error(`${label}: 유효한 64비트 주소를 입력하세요.`);
    }
    return `0x${parsed.toString(16).toUpperCase()}`;
  }

  async function submit(ctx, token, pid) {
    if (!current(ctx, token, pid)) return;
    if (!selectedTid) return ctx.toast('스레드 테이블에서 대상 행을 먼저 선택하세요.', true);
    const values = {
      normalize_address: q('apcn-address').value,
      normalize_context: q('apcn-context').value,
      system_buffer1: q('apcn-buffer1').value,
      system_buffer2: q('apcn-buffer2').value
    };
    try {
      const payload = {
        attached_process_id: pid,
        selected_thread_id: Number(selectedTid),
        normalize_address: parsePointer(values.normalize_address, 'Normalize_Address', false),
        normalize_context: parsePointer(values.normalize_context || '0', 'Normalize_Context', true),
        system_buffer1: parsePointer(values.system_buffer1 || '0', 'SystemBuffer 1', true),
        system_buffer2: parsePointer(values.system_buffer2 || '0', 'SystemBuffer 2', true)
      };
      draft = {...values};
      const button = q('apcn-submit'), status = q('apcn-submit-status');
      button.disabled = true;
      status.className = 'busy-note';
      status.textContent = '요청 중…';
      const result = await ctx.api('/api/apc/normalize', payload);
      if (!current(ctx, token, pid)) return;
      const ok = result.success === true;
      status.className = ok ? 'busy-note apcn-ok' : 'busy-note error';
      status.textContent = `${ok ? 'APC 요청 등록 성공' : 'APC 요청 실패'} · NTSTATUS ${result.result_status || '알 수 없음'}`;
      ctx.toast(status.textContent, !ok);
    } catch (error) {
      if (!current(ctx, token, pid)) return;
      const status = q('apcn-submit-status');
      status.className = 'busy-note error';
      status.textContent = error.message;
      ctx.toast(error.message, true);
    } finally {
      if (current(ctx, token, pid)) q('apcn-submit').disabled = !selectedTid;
    }
  }

  window.ApcNormalize = {render, refresh: () => refreshThreads(), dispose};
})();
