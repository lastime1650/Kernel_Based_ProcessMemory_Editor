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
  let submitting = false, pathText = '', jobs = [];
  const q = id => context?.root.querySelector('#' + id);

  function stopTimer() {
    if (timer !== null) clearTimeout(timer);
    timer = null;
  }

  function dispose() {
    generation++;
    stopTimer();
    context = null;
  }

  function reset() {
    dispose();
    pathText = '';
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
    q('mv4-path').disabled = submitting;
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
        <p style="overflow-wrap:anywhere">${esc(job.path)}</p>
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

  function validPath(path) {
    return (/^[A-Za-z]:[\\/]/.test(path) || /^\\\\/.test(path) || /^\\\?\?\\/.test(path)) &&
      /\.dll$/i.test(path) && !/[\x00-\x1f]/.test(path);
  }

  async function submit() {
    if (submitting || context?.isBusy?.() === true || !ready()) return;
    const path = q('mv4-path').value.trim();
    if (!validPath(path)) return status('디스크에 있는 DLL의 절대 경로를 입력하세요. 예: C:\\DLLs\\Example.dll', true);
    const owner = context, token = generation;
    const request = {pid: owner.pid, process_start_key: identity(), path};
    pathText = path;
    submitting = true;
    owner.setBusy(true);
    status('커널 매핑 요청 중…');
    try {
      const job = await api('/map', {
        method: 'POST', headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(request)
      });
      if (!context || token !== generation) return;
      status(`요청 접수 · ${labels[job.state] || job.state}`);
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
        <p>선택한 프로세스에 디스크 DLL을 커널로 매핑합니다. 대상 PID ${esc(context.pid || '미선택')}</p>
        <div class="fields"><label class="wide">DLL 절대 경로<input id="mv4-path" type="text" autocomplete="off" spellcheck="false" placeholder="C:\\DLLs\\Example.dll" value="${esc(pathText)}"></label></div>
        <div class="actions"><button id="mv4-send">커널 매핑 요청</button></div>
        <p id="mv4-status" role="status" aria-live="polite"></p>
        <p>failcode 0은 성공, 양수는 커널 실패 위치입니다. 상세 오류에는 실패한 호출과 당시 값이 표시됩니다. 새로 고침은 작업 상태를 조회합니다.</p>
      </section>
      <section><h2>ManualV4 작업</h2><div id="mv4-jobs"></div></section>`;
    q('mv4-path').oninput = () => { pathText = q('mv4-path').value; };
    q('mv4-send').onclick = submit;
    status(ready() ? 'DLL 절대 경로를 입력하고 커널 매핑을 요청하세요' : '프로세스를 선택하고 드라이버 2.6 이상 / 빌드 20261012 연결을 확인하세요');
    draw();
    refresh();
  }

  window.ManualV4 = {render, dispose, reset, targetChanged: controls};
})();
