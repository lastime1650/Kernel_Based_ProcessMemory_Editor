/* Inspect a successfully mapped ManualV4 image through the shared image-analysis pipeline. */
(() => {
  'use strict';

  const PDB_LIMIT = 256 * 1024 * 1024;
  const PAGE_SIZE = 50;
  const esc = value => String(value ?? '').replace(/[&<>"']/g, char => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  }[char]));
  const addressValue = value => /^0x[0-9a-f]+$/i.test(String(value || '')) ? BigInt(value) : null;

  let context = null, generation = 0, jobsSerial = 0, busy = false;
  let jobs = [], selectedId = '', pdbFile = null, pdbId = '', uploadedFile = null;
  let analysis = null, selected = null, detail = null, filter = '', page = 0, error = '', detailView = 'asm';
  const q = id => context?.root.querySelector('#' + id);

  function dispose() {
    generation++;
    jobsSerial++;
    context = null;
    pdbFile = null;
    pdbId = '';
    uploadedFile = null;
  }

  function validJob(job) {
    const base = addressValue(job?.mapped_base);
    return job?.state === 'mapped' && job?.result_status === '0x00000000' &&
      job?.transport_ok === true && job?.packet_valid === true && job?.execution_unknown !== true &&
      Number.isInteger(job?.pid) && job.pid > 0 && typeof job.process_start_key === 'string' &&
      base !== null && base >= 0x10000n && base < 0x800000000000n;
  }

  function currentJob() {
    return jobs.find(job => job.id === selectedId && validJob(job)) || null;
  }

  function active(owner, token) {
    return context === owner && generation === token &&
      owner.root.querySelector('[data-manual-v4-viewer]');
  }

  function validPdb(file) {
    return file && typeof file.name === 'string' && /\.pdb$/i.test(file.name) && file.size > 0 && file.size <= PDB_LIMIT;
  }

  function uploadPdb(file) {
    if (!validPdb(file))
      throw Error('256MiB 이하의 PDB 파일을 선택하세요.');
  }

  function draw() {
    if (!context) return;
    const locked = busy || context.isBusy?.() === true;
    const mapped = jobs.filter(validJob);
    if (!mapped.some(job => job.id === selectedId)) selectedId = mapped[0]?.id || '';
    const job = currentJob();
    context.root.innerHTML = `
      <div data-manual-v4-viewer>
        <section class="card">
          <div class="card-head"><div><h2>ManualV4_Viewer</h2><p>성공한 ManualV4 매핑의 시작 주소를 검증한 뒤 DLL 이미지와 PDB를 분석합니다.</p></div><button id="mv4v-refresh" class="secondary" ${locked ? 'disabled' : ''}>매핑 목록 새로 고침</button></div>
          ${error ? `<div class="notice error">${esc(error)}</div>` : ''}
          ${mapped.length ? `
            <div class="fields">
              <label class="wide">분석할 매핑<select id="mv4v-job" ${locked ? 'disabled' : ''}>${mapped.map(item => `<option value="${esc(item.id)}" ${item.id === selectedId ? 'selected' : ''}>${esc(item.display_name || item.path)} · PID ${item.pid} · ${esc(item.mapped_base)}</option>`).join('')}</select></label>
              <label class="file-pick">PDB 파일 선택<input id="mv4v-pdb" type="file" accept=".pdb" ${locked ? 'disabled' : ''}></label>
            </div>
            <p id="mv4v-pdb-name" class="subtle" aria-live="polite">${pdbFile ? `${esc(pdbFile.name)} · ${pdbFile.size.toLocaleString()} bytes` : 'PDB 파일을 선택하세요 · 최대 256MiB'}</p>
            <div class="actions"><button id="mv4v-analyze" ${locked || !job || !validPdb(pdbFile) ? 'disabled' : ''}>매핑된 DLL 분석</button><span class="hint">PDB GUID·Age, PID 시작 키, 매핑 시작 주소를 분석 요청에서 확인합니다.</span></div>
            ${job ? `<div class="subtle">매핑 DLL ${esc(job.display_name || job.path)} · PID ${job.pid} · 프로세스 시작 키 ${esc(job.process_start_key)}<br>시작 주소 <code>${esc(job.mapped_base)}</code> · 진입점 <code>${esc(job.entry_point || '0x0')}</code> · ${job.only_mapping ? 'DllMain 호출 없이 매핑' : 'DllMain 호출 후 매핑'}</div>` : ''}
          ` : '<div class="empty">분석할 성공 매핑이 없습니다. ManualV4에서 DLL을 먼저 매핑하세요.</div>'}
        </section>
        <section class="card">
          <div class="card-head"><div><h2>매핑 DLL 함수</h2><p>${analysis ? `${esc(analysis.image?.name || 'DLL')} · ${esc(analysis.image?.base || '')} · ${analysis.count.toLocaleString()}개 함수` : 'PDB를 선택하고 매핑된 DLL 분석을 실행하세요.'}</p></div><span class="chip">${analysis?.count?.toLocaleString() || 0}개</span></div>
          ${analysis ? `<div class="result-toolbar"><input id="mv4v-filter" aria-label="함수 검색" placeholder="주소 · 함수명 · 매개변수 검색" value="${esc(filter)}"><button id="mv4v-export" class="secondary small">함수 목록 JSON 저장</button></div><div id="mv4v-table"></div>${analysis.truncated ? '<p class="notice">분석 상한이 적용되어 일부 함수가 생략되었습니다.</p>' : ''}` : '<div id="mv4v-table"><div class="empty">분석 결과가 여기에 표시됩니다.</div></div>'}
          ${analysis?.codeview ? `<p class="subtle">CodeView PDB ${esc(analysis.codeview.pdb_path)} · GUID ${esc(analysis.codeview.guid)} · Age ${analysis.codeview.age}</p>` : ''}
          ${analysis?.forwarders?.length ? `<details><summary>전달 Export ${analysis.forwarders.length}개</summary><pre>${esc(analysis.forwarders.map(row => `${row.name} → ${row.forwarder}`).join('\n'))}</pre></details>` : ''}
          ${analysis?.data_exports?.length ? `<details><summary>실행 코드가 아닌 Export ${analysis.data_exports.length}개</summary><pre>${esc(analysis.data_exports.map(row => `${row.name || 'ordinal_' + row.ordinal} · ${row.rva}`).join('\n'))}</pre></details>` : ''}
        </section>
        <section class="card"><h2>선택 함수 상세</h2><p>${selected ? esc(selected.signature || `${selected.name}(${selected.parameters || '미확인'})`) : '함수 표의 행에서 상세 분석을 선택하세요.'}</p><div id="mv4v-detail"></div></section>
      </div>`;

    if (q('mv4v-refresh')) q('mv4v-refresh').onclick = refreshJobs;
    if (q('mv4v-job')) q('mv4v-job').onchange = event => {
      selectedId = event.target.value;
      pdbFile = null; pdbId = ''; uploadedFile = null;
      analysis = null; selected = null; detail = null; filter = ''; page = 0; error = '';
      draw();
    };
    if (q('mv4v-pdb')) q('mv4v-pdb').onchange = event => {
      pdbFile = event.target.files?.[0] || null;
      pdbId = ''; uploadedFile = null; analysis = null; selected = null; detail = null;
      error = '';
      if (pdbFile) {
        try { uploadPdb(pdbFile); }
        catch (issue) { error = issue.message; }
      }
      draw();
    };
    if (q('mv4v-analyze')) q('mv4v-analyze').onclick = () => run(analyzeMappedDll);
    if (q('mv4v-filter')) q('mv4v-filter').oninput = event => { filter = event.target.value; page = 0; drawTable(); };
    if (q('mv4v-export')) q('mv4v-export').onclick = () => context.download(JSON.stringify(analysis, null, 2), 'manual-v4-image-functions.json', 'application/json');
    drawTable();
    drawDetail();
  }

  async function run(action) {
    if (!context || busy || context.isBusy?.() === true) return;
    const owner = context, token = generation;
    busy = true; error = '';
    owner.setBusy(true);
    draw();
    try { await action(owner, token); }
    catch (issue) { if (active(owner, token)) error = issue.message || String(issue); }
    finally {
      busy = false;
      owner.setBusy(false);
      if (active(owner, token) || context) draw();
    }
  }

  async function refreshJobs() {
    if (!context || busy) return;
    const owner = context, token = generation, serial = ++jobsSerial;
    error = '';
    try {
      const response = await owner.api('/api/manual-v4/jobs?include_all=true');
      if (!active(owner, token) || serial !== jobsSerial) return;
      if (!Array.isArray(response.jobs)) throw Error('ManualV4 작업 목록 응답을 확인하세요.');
      jobs = response.jobs.filter(validJob);
      if (!jobs.some(job => job.id === selectedId)) {
        selectedId = jobs[0]?.id || '';
        pdbFile = null; pdbId = ''; uploadedFile = null;
        analysis = null; selected = null; detail = null;
      }
    } catch (issue) { if (active(owner, token) && serial === jobsSerial) error = issue.message || String(issue); }
    if (active(owner, token) && serial === jobsSerial) draw();
  }

  async function analyzeMappedDll(owner, token) {
    const job = currentJob(), file = pdbFile;
    if (!job) throw Error('성공한 ManualV4 매핑을 선택하세요.');
    if (!file) throw Error('분석할 PDB 파일을 선택하세요.');
    uploadPdb(file);

    const latest = await owner.api('/api/manual-v4/jobs/' + encodeURIComponent(job.id));
    if (!active(owner, token)) return;
    if (!validJob(latest) || latest.process_start_key !== job.process_start_key || latest.mapped_base !== job.mapped_base)
      throw Error('선택한 매핑 작업이 더 이상 유효하지 않습니다. 목록을 새로 고치세요.');

    const catalog = await owner.api('/api/studio/execute', {
      operation: 'image_catalog', args: {pid: job.pid}
    });
    if (!active(owner, token)) return;
    const base = addressValue(job.mapped_base);
    if (!catalog.success || catalog.pid !== job.pid || String(catalog.process_start_key) !== job.process_start_key ||
        !catalog.results?.some(image => addressValue(image.base) === base))
      throw Error('매핑 DLL의 시작 주소가 현재 프로세스 이미지에서 확인되지 않아 분석하지 않았습니다. 프로세스와 매핑 상태를 확인하세요.');

    if (!pdbId || uploadedFile !== file) {
      const response = await fetch(`/api/studio/assets/pdb?filename=${encodeURIComponent(file.name)}`, {
        method: 'PUT', headers: {'Content-Type': 'application/octet-stream'}, body: file
      });
      let symbol;
      try { symbol = await response.json(); }
      catch { throw Error('PDB 업로드 응답을 확인하세요.'); }
      if (!response.ok || !symbol.success || !symbol.id) throw Error(symbol.detail || symbol.error || 'PDB 추가 실패');
      pdbId = symbol.id;
      uploadedFile = file;
    }

    const result = await owner.api('/api/studio/execute', {
      operation: 'image_functions', args: {pid: job.pid, base: job.mapped_base, pdb_id: pdbId}
    });
    if (!active(owner, token)) return;
    if (!result.success) throw Error(result.error || '매핑 DLL 분석에 실패했습니다.');
    if (result.pid !== job.pid || String(result.process_start_key) !== job.process_start_key ||
        addressValue(result.image?.base) !== base || result.pdb_id !== pdbId || !Array.isArray(result.results))
      throw Error('분석 결과의 PID, PDB 또는 매핑 시작 주소가 요청과 일치하지 않습니다.');
    analysis = result; selected = null; detail = null; filter = ''; page = 0;
    owner.toast(`${result.image.name} · 함수 ${result.count.toLocaleString()}개 분석`);
  }

  function drawTable() {
    const host = q('mv4v-table');
    if (!host) return;
    if (!analysis) { host.innerHTML = '<div class="empty">분석 결과가 여기에 표시됩니다.</div>'; return; }
    const rows = analysis.results.filter(row => !filter || JSON.stringify(row).toLowerCase().includes(filter.toLowerCase()));
    const pages = Math.max(1, Math.ceil(rows.length / PAGE_SIZE));
    page = Math.min(page, pages - 1);
    const visible = rows.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE);
    host.innerHTML = `<div class="table-wrap"><table><thead><tr><th>주소</th><th>RVA</th><th>함수명</th><th>매개변수 / 시그니처</th><th>식별 근거</th><th>크기</th><th></th></tr></thead><tbody>${visible.map((row, index) => `<tr class="${row.address === selected?.address ? 'dll-selected' : ''}"><td class="mono">${esc(row.address)}</td><td class="mono">${esc(row.rva)}</td><td>${esc(row.name)}</td><td class="wrap" title="${esc(row.signature)}">${esc(row.parameters || '미확인')}${row.parameter_source === 'pdb' ? ' · PDB' : ''}</td><td>${esc((row.sources || []).join(', '))}</td><td>${row.size || '미확인'}</td><td><button class="secondary small" data-mv4v-function="${index}" ${busy ? 'disabled' : ''}>주소 / 상세</button></td></tr>`).join('') || '<tr><td colspan="7">검색 결과가 없습니다.</td></tr>'}</tbody></table></div><div class="pagination"><span>${rows.length.toLocaleString()}개 · ${page + 1}/${pages}</span><div><button id="mv4v-prev" class="secondary small" ${page ? '' : 'disabled'}>이전</button><button id="mv4v-next" class="secondary small" ${page + 1 < pages ? '' : 'disabled'}>다음</button></div></div><p class="subtle">${esc(analysis.note || '')} ${analysis.truncated ? '· 함수 상한 적용' : ''}</p>`;
    for (const button of host.querySelectorAll('[data-mv4v-function]'))
      button.onclick = () => selectFunction(visible[Number(button.dataset.mv4vFunction)]);
    host.querySelector('#mv4v-prev').onclick = () => { page--; drawTable(); };
    host.querySelector('#mv4v-next').onclick = () => { page++; drawTable(); };
  }

  async function selectFunction(row) {
    selected = row; detail = null;
    await run(async (owner, token) => {
      const job = currentJob();
      if (!job || !analysis) throw Error('분석 결과가 만료되었습니다. 다시 분석하세요.');
      const result = await owner.api('/api/studio/execute', {
        operation: 'image_function_detail', args: {pid: job.pid, analysis_id: analysis.analysis_id, address: row.address}
      });
      if (!active(owner, token)) return;
      if (!result.success || result.function?.address !== row.address) throw Error(result.error || '함수 상세 분석 실패');
      detail = result;
    });
  }

  function drawDetail() {
    const host = q('mv4v-detail');
    if (!host || !detail) return;
    window.FunctionViews.mount(host, detail, {initialView: detailView, onView: view => { detailView = view; }, download: context.download});
  }

  function render(options) {
    dispose();
    context = options;
    jobs = []; selectedId = ''; pdbFile = null; pdbId = ''; uploadedFile = null;
    analysis = null; selected = null; detail = null; filter = ''; page = 0; error = ''; busy = false;
    draw();
    refreshJobs();
  }

  window.ManualV4Viewer = {render, dispose};
})();
