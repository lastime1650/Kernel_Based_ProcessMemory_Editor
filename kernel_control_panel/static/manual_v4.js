/* ManualV4 submits once; navigation and polling only query existing jobs. */
(() => {
  'use strict';

  const esc = value => String(value ?? '').replace(/[&<>"']/g, char => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  }[char]));
  const labels = {
    queued: '대기', running: '실행 중', mapped: '매핑 완료',
    failed: '실패', indeterminate: '결과 확인 불가'
  };
  let context = null, generation = 0, poll = 0, timer = null;
  let submitting = false, selectedFile = null, jobs = [];
  const q = id => context?.root.querySelector('#' + id);

  function stopTimer() {
    if (timer !== null) clearTimeout(timer);
    timer = null;
  }

  function dispose() {
    generation++;
    stopTimer();
    selectedFile = null;
    context = null;
  }

  function reset() {
    dispose();
    jobs = [];
  }

  async function api(path, options = {}) {
    const response = await fetch('/api/manual-v4' + path, options);
    let body;
    try { body = await response.json(); }
    catch { throw Error('서버 응답을 확인하세요'); }
    if (!response.ok || body.success === false) {
      throw Error(typeof body.detail === 'string' ? body.detail : body.error || '요청 실패');
    }
    return body;
  }

  function identity() {
    const value = String(context?.identity() ?? '');
    if (!/^[1-9][0-9]{0,19}$/.test(value)) return '';
    return BigInt(value) <= 18446744073709551615n ? value : '';
  }

  function ready() {
    return context && context.currentPid() === context.pid && context.pid > 0 &&
      identity() !== '' && context.connected();
  }

  function controls() {
    if (!context) return;
    q('mv4-file').disabled = submitting;
    q('mv4-only-mapping').disabled = submitting;
    q('mv4-send').disabled = submitting || context.isBusy?.() === true || !ready();
  }

  function status(value, error = false) {
    if (!q('mv4-status')) return;
    q('mv4-status').textContent = value;
    q('mv4-status').classList.toggle('error', error);
    controls();
  }

  function draw() {
    if (!q('mv4-jobs')) return;
    q('mv4-jobs').innerHTML = jobs.length ? jobs.map(job => `
      <article class="card">
        <strong>${esc(labels[job.state] || job.state)} · PID ${esc(job.pid)}</strong>
        <p style="overflow-wrap:anywhere">DLL ${esc(job.display_name || job.path)}</p>
        <p>${job.only_mapping ? '매핑만 수행 · DllMain 호출 안 함' : 'DllMain 호출 포함'}</p>
        <p>이미지 기준 주소 <code>${esc(job.mapped_base || '0x0')}</code> · 진입점 <code>${esc(job.entry_point || '0x0')}</code></p>
        ${job.result_status ? `<p>커널 상태 <code>${esc(job.result_status)}</code></p>` : ''}
        <p>실패 위치 (failcode) <code>${esc(job.failcode ?? '미확인')}</code>${job.failcode === 0 ? ' · SUCCESS' : ''}</p>
        <p>상세 오류 (failmessage)</p>
        <pre style="white-space:pre-wrap;overflow-wrap:anywhere">${esc(job.failmessage === null || job.failmessage === undefined ? '미확인' : job.failmessage || 'SUCCESS')}</pre>
        ${job.error ? `<p class="error">${esc(job.error)}</p>` : ''}
        ${job.state === 'indeterminate' ? '<p>매핑의 완료 여부를 확인할 수 없습니다. 자동으로 다시 요청하지 않습니다.</p>' : ''}
        ${job.output ? `<details><summary>실행 결과</summary><pre>${esc(job.output)}</pre></details>` : ''}
      </article>`).join('') : '<p>요청한 작업이 없습니다.</p>';
  }

  async function refresh() {
    stopTimer();
    const token = generation, serial = ++poll;
    try {
      const response = await api('/jobs');
      if (!context || token !== generation || serial !== poll) return;
      if (!Array.isArray(response.jobs)) throw Error('작업 목록 응답을 확인하세요');
      jobs = response.jobs;
      draw();
      controls();
    } catch (error) {
      if (context && token === generation && serial === poll) status(error.message, true);
    } finally {
      if (context && token === generation && serial === poll) timer = setTimeout(refresh, 1500);
    }
  }

  function validFile(file) {
    return file && typeof file.name === 'string' && file.name.length > 0 &&
      file.name.length <= 255 && /\.dll$/i.test(file.name) &&
      !/[\\/\x00-\x1f]/.test(file.name) && file.size > 0 && file.size <= (64 * 1024 * 1024);
  }

  async function submit() {
    if (submitting || context?.isBusy?.() === true || !ready()) return;
    const file = selectedFile;
    if (!file) return status('매핑할 DLL 파일을 선택하세요.', true);
    if (!validFile(file)) return status('64MiB 이하의 DLL 파일을 선택하세요.', true);
    const onlyMapping = q('mv4-only-mapping').checked;
    const owner = context, token = generation;
    submitting = true;
    owner.setBusy(true);
    status('DLL 업로드 및 커널 매핑 요청 중…');
    try {
      const query = `pid=${owner.pid}&process_start_key=${encodeURIComponent(identity())}&filename=${encodeURIComponent(file.name)}&only_mapping=${onlyMapping}`;
      const job = await api('/upload-map?' + query, {
        method: 'POST', headers: {'Content-Type': 'application/octet-stream'}, body: file
      });
      if (!context || token !== generation) return;
      status(`요청 접수 · ${file.name} · ${labels[job.state] || job.state}`);
      await refresh();
    } catch (error) {
      if (context && token === generation) status(error.message, true);
    } finally {
      submitting = false;
      owner.setBusy(false);
      if (context && token === generation) controls();
    }
  }

  function render(ctx) {
    dispose();
    context = ctx;
    context.root.innerHTML = `
      <section class="card">
        <h2>ManualV4</h2>
        <p>선택한 DLL 파일을 로컬 패널에 전달한 뒤 선택 프로세스에 커널로 매핑합니다. 대상 PID ${esc(context.pid || '미선택')}</p>
        <div class="fields"><label class="wide">DLL 파일 선택<input id="mv4-file" type="file" accept=".dll,application/x-msdownload"></label></div>
        <p id="mv4-filename" class="subtle" aria-live="polite">선택된 DLL 없음 · 최대 64MiB</p>
        <div class="fields"><label><input id="mv4-only-mapping" type="checkbox"> 매핑만 수행 (DLL 진입 함수 호출 안 함)</label></div>
        <div class="actions"><button id="mv4-send">커널 매핑 요청</button></div>
        <p id="mv4-status" role="status" aria-live="polite"></p>
        <p>failcode 0은 성공, 양수는 커널 실패 위치입니다. 상세 오류에는 실패한 호출과 당시 값이 표시됩니다. 새로 고침은 작업 상태를 조회합니다.</p>
      </section>
      <section><h2>ManualV4 작업</h2><div id="mv4-jobs"></div></section>`;
    q('mv4-file').onchange = () => {
      selectedFile = q('mv4-file').files?.[0] || null;
      q('mv4-filename').textContent = selectedFile
        ? `${selectedFile.name} · ${selectedFile.size.toLocaleString()} bytes`
        : '선택된 DLL 없음 · 최대 64MiB';
      status(selectedFile && !validFile(selectedFile)
        ? '64MiB 이하의 DLL 파일을 선택하세요.'
        : selectedFile ? '선택한 DLL 파일을 확인하고 커널 매핑을 요청하세요.'
          : 'DLL 파일을 선택하세요.', Boolean(selectedFile && !validFile(selectedFile)));
    };
    q('mv4-send').onclick = submit;
    status(ready() ? 'DLL 파일을 선택하고 커널 매핑을 요청하세요' : '프로세스를 선택하고 드라이버 2.6 이상 / 빌드 20261012 연결을 확인하세요');
    draw();
    refresh();
  }

  window.ManualV4 = {render, dispose, reset, targetChanged: controls};
})();
