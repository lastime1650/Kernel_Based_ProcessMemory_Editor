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
  let submitting = false, choosing = false, selectedPath = '', selectedName = '', selectedSize = 0, jobs = [];
  const q = id => context?.root.querySelector('#' + id);

  function stopTimer() {
    if (timer !== null) clearTimeout(timer);
    timer = null;
  }

  function dispose() {
    generation++;
    stopTimer();
    selectedPath = '';
    selectedName = '';
    selectedSize = 0;
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
    const blocked = submitting || choosing || context.isBusy?.() === true;
    q('mv4-select').disabled = blocked;
    q('mv4-only-mapping').disabled = blocked;
    q('mv4-send').disabled = blocked || !ready();
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

  async function chooseFile() {
    if (!context || submitting || choosing || context.isBusy?.() === true) return;
    const token = generation;
    choosing = true;
    status('Windows 파일 선택 창을 여는 중…');
    try {
      const result = await api('/select-dll', {method: 'POST'});
      if (!context || token !== generation) return;
      if (result.cancelled) {
        status(selectedPath ? '기존에 선택한 DLL 경로를 유지합니다.' : 'DLL 파일 선택을 취소했습니다.');
        return;
      }
      if (typeof result.path !== 'string' || !result.path ||
          typeof result.display_name !== 'string' || !Number.isInteger(result.size)) {
        throw Error('선택한 DLL 경로 응답을 확인하세요');
      }
      selectedPath = result.path;
      selectedName = result.display_name;
      selectedSize = result.size;
      q('mv4-filename').textContent = `${selectedPath} · ${selectedSize.toLocaleString()} bytes`;
      status('선택한 DLL의 절대 경로를 사용합니다. 매핑 요청을 실행할 수 있습니다.');
    } catch (error) {
      if (context && token === generation) status(error.message, true);
    } finally {
      choosing = false;
      if (context) controls();
    }
  }

  async function submit() {
    if (submitting || context?.isBusy?.() === true || !ready()) return;
    if (!selectedPath) return status('매핑할 DLL 파일을 선택하세요.', true);
    const onlyMapping = q('mv4-only-mapping').checked;
    const owner = context, token = generation;
    submitting = true;
    owner.setBusy(true);
    status('선택한 DLL 절대 경로로 커널 매핑 요청 중…');
    try {
      const job = await api('/map', {
        method: 'POST', headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({pid: owner.pid, process_start_key: identity(), path: selectedPath,
          display_name: selectedName, only_mapping: onlyMapping})
      });
      if (!context || token !== generation) return;
      status(`요청 접수 · ${selectedName} · ${labels[job.state] || job.state}`);
      await refresh();
    } catch (error) {
      if (context && token === generation) status(error.message, true);
    } finally {
      submitting = false;
      owner.setBusy(false);
      if (context) controls();
    }
  }

  function render(ctx) {
    dispose();
    context = ctx;
    context.root.innerHTML = `
      <section class="card">
        <h2>ManualV4</h2>
        <p>Windows 파일 선택 창에서 고른 DLL의 절대 경로를 그대로 사용해 선택 프로세스에 커널로 매핑합니다. DLL 파일을 패널의 assets 폴더로 복사하지 않습니다. 대상 PID ${esc(context.pid || '미선택')}</p>
        <div class="actions"><button id="mv4-select" class="secondary">DLL 파일 선택</button></div>
        <p id="mv4-filename" class="subtle" aria-live="polite">선택된 DLL 없음 · 최대 64MiB</p>
        <div class="fields"><label><input id="mv4-only-mapping" type="checkbox"> 매핑만 수행 (DLL 진입 함수 호출 안 함)</label></div>
        <div class="actions"><button id="mv4-send">커널 매핑 요청</button></div>
        <p id="mv4-status" role="status" aria-live="polite"></p>
        <p>failcode 0은 성공, 양수는 커널 실패 위치입니다. 상세 오류에는 실패한 호출과 당시 값이 표시됩니다. 새로 고침은 작업 상태를 조회합니다.</p>
      </section>
      <section><h2>ManualV4 작업</h2><div id="mv4-jobs"></div></section>`;
    q('mv4-select').onclick = chooseFile;
    q('mv4-send').onclick = submit;
    status(ready() ? 'DLL 파일을 선택하고 커널 매핑을 요청하세요' : '프로세스를 선택하고 드라이버 2.6 이상 / 빌드 20261012 연결을 확인하세요');
    draw();
    refresh();
  }

  window.ManualV4 = {render, dispose, reset, targetChanged: controls};
})();
