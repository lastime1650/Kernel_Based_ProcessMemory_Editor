/* Loaded-image browser. No native process access; all target actions use the API. */
(() => {
 const contexts=new Map();let timer;
 const escape=v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
 const bytes=n=>`${(Number(n)/1024).toLocaleString(undefined,{maximumFractionDigits:1})} KB`;
 function render(options){
  clearTimeout(timer);
  const {root,pid,api,toast,setBusy}=options;
  if(!pid){root.innerHTML='<section class="card empty"><strong>프로세스를 선택하세요</strong>DLL 로드와 함수 분석은 선택한 대상에서 수행합니다.</section>';return;}
  let c=contexts.get(pid);
  if(!c){c={pid,images:[],symbols:[],base:'',pdb:'',path:'',parameter:'0',wait:'0',filter:'',page:0,imageFilter:'',imagePage:0,calls:[],generation:0};contexts.set(pid,c);}
  const active=()=>root.querySelector(`[data-dll-workbench="${pid}"]`) && options.currentPid()===pid;
  const request=(op,args={})=>api('/api/studio/execute',{operation:op,args:{pid,...args}});
  function remember(){if(!active())return;for(const [id,key] of [['dll-path','path'],['dll-parameter','parameter'],['dll-wait','wait'],['dll-filter','filter']]){const e=root.querySelector('#'+id);if(e)c[key]=e.value;}}
  async function perform(action){if(options.isBusy())return;remember();setBusy(true);for(const b of root.querySelectorAll('button'))b.disabled=true;
   try{await action();}catch(e){toast(e.message,true);c.error=e.message;}finally{setBusy(false);if(active())draw();}
  }
  async function refresh(){
   const [catalog,symbols,status]=await Promise.all([request('image_catalog'),api('/api/studio/symbols'),request('status')]);
   if(!catalog.success)throw Error(catalog.error||'이미지 조회 실패');
   if(c.identity && c.identity!==catalog.process_start_key){c.analysis=null;c.selected=null;c.detail=null;c.base='';c.generation++;}
   c.identity=catalog.process_start_key;c.images=catalog.results;c.discovery=catalog.discovery;c.catalogTruncated=catalog.truncated;c.symbols=symbols.results||[];c.status=status;
   if(!c.images.some(x=>x.base===c.base)){c.base=c.images.find(x=>x.main_image)?.base||c.images[0]?.base||'';c.analysis=null;c.selected=null;c.detail=null;}
   await refreshCalls();c.error='';
  }
  async function analyze(){
   if(!c.base)throw Error('이미지를 선택하세요');
   const generation=++c.generation;const result=await request('image_functions',{base:c.base,pdb_id:c.pdb});
   if(!result.success)throw Error(result.error||'이미지 분석 실패');
   if(generation!==c.generation)return;c.analysis=result;c.selected=null;c.detail=null;c.page=0;c.error='';
   toast(`${result.image.name} · 함수 ${result.count.toLocaleString()}개 식별`);
  }
  async function refreshCalls(){const result=await request('function_calls');if(result.success)c.calls=result.results;}
  async function poll(){
   if(!active())return;
   if(!options.isBusy()){
    for(const call of c.calls.filter(r=>!r.completed&&!r.released&&r.call_id!=='0')){
     try{await request('function_call_query',{id:call.id});}catch{}
    }
    try{await refreshCalls();if(active())drawCalls();}catch{}
   }
   timer=setTimeout(poll,1500);
  }
  async function upload(file,kind){
   if(!file)return;
   const limit=kind==='pdb'?256*1024*1024:64*1024*1024;
   if(!file.name.toLowerCase().endsWith('.'+kind)||file.size>limit)throw Error(`.${kind} 파일과 크기 상한을 확인하세요`);
   const response=await fetch(`/api/studio/assets/${kind}?filename=${encodeURIComponent(file.name)}`,{method:'PUT',headers:{'Content-Type':'application/octet-stream'},body:file});
   const result=await response.json();if(!response.ok||!result.success)throw Error(result.detail||result.error||'파일 추가 실패');
   if(kind==='dll'){c.path=result.path;toast('DLL 파일을 추가했습니다. 로드 요청을 실행하세요');}
   else{c.pdb=result.id;c.symbols=(await api('/api/studio/symbols')).results;c.analysis=null;c.selected=null;c.detail=null;c.generation++;toast('PDB를 추가했습니다. 이미지를 다시 분석하세요');}
  }
  function draw(){
   const version=c.status?`${c.status.major_version}.${c.status.minor_version}`:'확인 중';
   const enabled=c.status?.success&&(c.status.major_version>2||c.status.major_version===2&&c.status.minor_version>=2);
   root.innerHTML=`<div data-dll-workbench="${pid}">
    <section class="card"><div class="card-head"><div><h2>DLL 로드와 이미지 함수</h2><p>대상 접근과 함수 실행은 커널 요청으로 수행합니다.</p></div><span class="chip">드라이버 ${escape(version)} · PID ${pid}</span></div>
     ${!enabled?'<div class="notice">함수 호출에는 드라이버 2.2 이상이 필요합니다. 이미지 조회·분석은 계속 사용할 수 있습니다.</div>':''}
     ${c.error?`<div class="notice error">${escape(c.error)}</div>`:''}
     <div class="fields"><label class="wide">DLL 경로<input id="dll-path" value="${escape(c.path)}" placeholder="C:\\경로\\sample.dll"></label></div>
     <div class="actions"><button id="dll-load">DLL 로드 요청</button><label class="file-pick">DLL 파일 선택<input type="file" id="dll-file" accept=".dll"></label>${c.loadId?'<button id="dll-verify" class="secondary">로드 확인 갱신</button>':''}<span class="hint">로드 후 MEM_IMAGE 목록에서 실제 이미지를 확인합니다.</span></div>
    </section>
    <section class="card"><div class="card-head"><div><h2>메모리 이미지 목록</h2><p>MEM_IMAGE와 커밋된 읽기 가능 영역 시작의 PE를 함께 표시합니다.</p></div><button id="dll-refresh" class="secondary">목록 새로 고침</button></div>
     <div class="result-toolbar"><input id="dll-image-filter" aria-label="이미지 이름 / 주소 / 종류 검색" placeholder="이미지 이름 · 주소 · 종류 검색" value="${escape(c.imageFilter)}"></div><div id="dll-image-table"></div>
     <div class="fields"><label class="wide">분석할 이미지<select id="dll-image">${c.images.map(i=>`<option value="${escape(i.base)}" ${i.base===c.base?'selected':''}>${escape(i.name)} · ${escape(i.base)} · ${bytes(i.image_size)} · ${i.source==='PE_HEADER'?'PE 헤더 발견':escape(i.source||'MEM_IMAGE')}</option>`).join('')}</select></label>
      <label>PDB 선택 사항<select id="dll-pdb"><option value="">PDB 없이 분석</option>${c.symbols.map(s=>`<option value="${s.id}" ${s.id===c.pdb?'selected':''}>${escape(s.name)} · ${s.function_count}개</option>`).join('')}</select></label>
      <label class="file-pick">PDB 파일 추가<input type="file" id="pdb-file" accept=".pdb"></label><label>PDB 로컬 경로<input id="pdb-path" placeholder="서버의 PDB 절대 경로"></label></div>
     <div class="actions"><button id="dll-analyze">이미지 함수 분석</button><button id="pdb-add-path" class="secondary">경로의 PDB 추가</button>${c.pdb?'<button id="pdb-remove" class="secondary">선택 PDB 제거</button>':''}<span class="hint">PDB의 GUID·Age가 일치할 때 실제 이름과 형식을 적용합니다.</span></div>
     <p class="subtle">${c.images.length}개 이미지 · PE 헤더 발견 ${c.discovery?.header_images||0}개${c.catalogTruncated?' · 조회 상한 / 취소로 일부 결과':''} ${c.analysis?.codeview?`· 이미지 PDB: ${escape(c.analysis.codeview.pdb_path)}`:''}</p>
     <p class="subtle">PE 헤더 발견은 로더 등록·전체 코드 존재를 보장하지 않습니다. 크기는 헤더의 SizeOfImage이며, 이름이 없으면 unknown.exe / unknown.dll로 표시합니다.</p>
    </section>
    <section class="card"><div class="card-head"><h2>이미지 내 함수 목록</h2><span class="chip">${c.analysis?.count||0}개</span></div>
     <div class="result-toolbar"><input id="dll-filter" placeholder="함수명 · 주소 · 매개변수 검색" value="${escape(c.filter)}"><button id="dll-export" class="secondary small" ${c.analysis?'':'disabled'}>함수 목록 JSON 저장</button></div><div id="dll-function-table"></div>
    </section>
    <section class="card"><h2>선택 함수 호출</h2><p>${c.selected?escape(c.selected.signature||c.selected.name):'함수 목록에서 항목을 선택하세요.'}</p>
     <div class="fields"><label>함수 주소<input id="dll-call-address" readonly value="${escape(c.selected?.address||'')}"></label><label>인자 값 · 64비트 정수 또는 대상 포인터<input id="dll-parameter" value="${escape(c.parameter)}" placeholder="0 또는 0x주소"></label><label>첫 완료 확인<select id="dll-wait">${[['0','즉시 반환'],['100','100ms'],['500','500ms'],['1000','1초']].map(([v,n])=>`<option value="${v}" ${c.wait===v?'selected':''}>${n}</option>`).join('')}</select></label></div>
     <div class="actions"><button id="dll-call" ${enabled&&c.selected&&c.selected.call_compatible!==false?'':'disabled'}>커널로 함수 호출</button><span class="hint">단일 정수/포인터 인자 · 종료값은 32비트</span></div>
     ${c.selected?.call_compatible===false?'<div class="notice">PDB 형식이 이 호출 규약과 맞지 않습니다. DLL에 단일 인자를 받는 진입 함수를 사용하세요.</div>':''}
     <div id="dll-function-detail"></div>
    </section><section class="card"><div class="card-head"><h2>함수 호출 이력</h2><button id="dll-calls-refresh" class="secondary small">완료 상태 새로 고침</button></div><div id="dll-call-history"></div><p class="subtle">실행 중인 호출은 자동 조회합니다. 추적 해제는 기록의 커널 참조를 정리하는 작업입니다.</p></section></div>`;
   bind();drawImageTable();drawTable();drawDetail();drawCalls();
  }
  function bind(){
   const q=id=>root.querySelector('#'+id);
   q('dll-load').onclick=()=>perform(async()=>{const result=await request('dll_load_verified',{path:c.path});c.loadId=result.load_id;
    if(!result.loaded)throw Error(result.error||result.note||JSON.stringify(result.driver_response||result));
    await refresh();c.base=result.image.base;await analyze();});
   if(q('dll-verify'))q('dll-verify').onclick=()=>perform(async()=>{const r=await request('dll_load_check',{id:c.loadId});if(!r.loaded)throw Error(r.note||r.error);await refresh();c.base=r.image.base;await analyze();});
   q('dll-refresh').onclick=()=>perform(refresh);q('dll-analyze').onclick=()=>perform(analyze);
   q('dll-image').onchange=e=>chooseImage(e.target.value);
   q('dll-image-filter').oninput=e=>{c.imageFilter=e.target.value;c.imagePage=0;drawImageTable();};
   q('dll-pdb').onchange=e=>{remember();c.pdb=e.target.value;c.analysis=null;c.selected=null;c.detail=null;c.generation++;draw();};
   q('dll-path').oninput=e=>c.path=e.target.value;q('dll-parameter').oninput=e=>c.parameter=e.target.value;q('dll-wait').onchange=e=>c.wait=e.target.value;
   q('dll-filter').oninput=e=>{c.filter=e.target.value;c.page=0;drawTable();};
   q('dll-file').onchange=e=>perform(()=>upload(e.target.files[0],'dll'));q('pdb-file').onchange=e=>perform(()=>upload(e.target.files[0],'pdb'));
   q('pdb-add-path').onclick=()=>{const path=q('pdb-path').value;perform(async()=>{const r=await api('/api/studio/symbols',{path});if(!r.success)throw Error(r.error||'PDB 추가 실패');c.pdb=r.id;c.symbols=(await api('/api/studio/symbols')).results;c.analysis=null;c.selected=null;c.detail=null;c.generation++;});};
   if(q('pdb-remove'))q('pdb-remove').onclick=()=>perform(async()=>{await api('/api/studio/symbols/'+c.pdb,undefined,'DELETE');c.pdb='';c.symbols=(await api('/api/studio/symbols')).results;c.analysis=null;c.selected=null;c.detail=null;c.generation++;});
   q('dll-call').onclick=()=>perform(async()=>{const r=await request('function_call',{analysis_id:c.analysis.analysis_id,address:c.selected.address,parameter:c.parameter,wait_ms:c.wait});await refreshCalls();
    if(!r.success)throw Error(r.error||(r.thread_created?'스레드는 생성됐지만 결과 확인에 실패했습니다. 이력을 확인하세요.':'호출 실패: '+r.result_status));toast(r.completed?`함수 완료 · TID ${r.thread_id} · ${r.exit_status}`:`실행 중 · TID ${r.thread_id}`);});
   q('dll-calls-refresh').onclick=()=>perform(async()=>{for(const call of c.calls.filter(r=>!r.released&&r.call_id!=='0'))await request('function_call_query',{id:call.id});await refreshCalls();});
   q('dll-export').onclick=()=>options.download(JSON.stringify(c.analysis,null,2),'image-functions.json','application/json');
  }
  function chooseImage(base){remember();c.base=base;c.analysis=null;c.selected=null;c.detail=null;c.generation++;draw();}
  function drawImageTable(){
   const host=root.querySelector('#dll-image-table');if(!host)return;
   const query=c.imageFilter.toLowerCase();const rows=c.images.filter(i=>!query||[i.name,i.base,i.memory_type,i.pe_kind,i.source].join(' ').toLowerCase().includes(query));
   const pages=Math.max(1,Math.ceil(rows.length/12));c.imagePage=Math.min(c.imagePage,pages-1);const visible=rows.slice(c.imagePage*12,(c.imagePage+1)*12);
   host.innerHTML=`<div class="table-wrap"><table><thead><tr><th>이름</th><th>기준 주소</th><th>메모리 종류 / 발견 근거</th><th>이미지 크기</th><th>이름 근거</th><th></th></tr></thead><tbody>${visible.map((i,n)=>`<tr class="${i.base===c.base?'dll-selected':''}"><td>${escape(i.name)}${i.pe_kind?`<div class="subtle">${escape(i.pe_kind)} · ${i.bits}비트</div>`:''}</td><td class="mono">${escape(i.base)}</td><td>${escape(i.memory_type||'MEM_IMAGE')}<div class="subtle">${i.source==='PE_HEADER'?'MZ / PE 헤더':'커널 이미지 정보'}</div>${i.source==='PE_HEADER'?`<div class="subtle">헤더 영역 ${bytes(i.header_region_size)} · 보호 ${escape(i.protect)}</div>`:''}</td><td>${bytes(i.image_size)}${i.source==='PE_HEADER'?`<div class="subtle">커밋 ${bytes(i.committed_bytes)}${i.payload_complete?'':' · 일부 구간만 존재'}</div>`:''}</td><td>${escape(({kernel:'커널 메타데이터',export:'Export 이름',version_OriginalFilename:'버전 원본 파일명',version_InternalName:'버전 내부 이름',unknown:'이름 없음'})[i.name_source]||i.name_source||'커널 메타데이터')}${i.name_layout==='file_offset'?'<div class="subtle">파일 오프셋으로 이름 조회</div>':''}</td><td><button class="secondary small" data-image-row="${n}">이미지 선택</button></td></tr>`).join('')||'<tr><td colspan="6">일치하는 이미지가 없습니다.</td></tr>'}</tbody></table></div><div class="pagination"><span>${rows.length}개 · ${c.imagePage+1}/${pages}</span><div><button id="dll-image-prev" class="secondary small" ${c.imagePage?'':'disabled'}>이미지 이전</button><button id="dll-image-next" class="secondary small" ${c.imagePage+1<pages?'':'disabled'}>이미지 다음</button></div></div>`;
   for(const button of host.querySelectorAll('[data-image-row]'))button.onclick=()=>chooseImage(visible[Number(button.dataset.imageRow)].base);
   host.querySelector('#dll-image-prev').onclick=()=>{c.imagePage--;drawImageTable();};host.querySelector('#dll-image-next').onclick=()=>{c.imagePage++;drawImageTable();};
  }
  function drawTable(){
   const host=root.querySelector('#dll-function-table');if(!host)return;
   if(!c.analysis){host.innerHTML='<div class="empty">이미지를 선택하고 함수 분석을 실행하세요.</div>';return;}
   const rows=c.analysis.results.filter(r=>!c.filter||JSON.stringify(r).toLowerCase().includes(c.filter.toLowerCase()));
   const pages=Math.max(1,Math.ceil(rows.length/50));c.page=Math.min(c.page,pages-1);const visible=rows.slice(c.page*50,(c.page+1)*50);
   host.innerHTML=`<div class="table-wrap"><table><thead><tr><th>주소</th><th>함수명</th><th>매개변수</th><th>식별 근거</th><th>크기</th><th></th></tr></thead><tbody>${visible.map((r,i)=>`<tr class="${r.address===c.selected?.address?'dll-selected':''}"><td class="mono">${escape(r.address)}</td><td title="${escape(r.name)}">${escape(r.name)}</td><td class="wrap" title="${escape(r.signature)}">${escape(r.parameters)}${r.parameter_source==='pdb'?' · PDB':''}</td><td>${escape(r.sources.join(', '))}</td><td>${r.size||'미확인'}</td><td><button class="secondary small" data-function="${i}">선택 / 상세</button></td></tr>`).join('')}</tbody></table></div><div class="pagination"><span>${rows.length}개 · ${c.page+1}/${pages}</span><div><button id="dll-prev" class="secondary small" ${c.page?'':'disabled'}>이전</button><button id="dll-next" class="secondary small" ${c.page+1<pages?'':'disabled'}>다음</button></div></div><p class="subtle">${escape(c.analysis.note)} ${c.analysis.truncated?'· 반환 상한 적용':''}</p>${c.analysis.forwarders.length?`<details><summary>전달 Export ${c.analysis.forwarders.length}개</summary><pre>${escape(c.analysis.forwarders.map(r=>`${r.name} → ${r.forwarder}`).join('\n'))}</pre></details>`:''}`;
   for(const button of host.querySelectorAll('[data-function]'))button.onclick=()=>perform(async()=>{c.selected=visible[Number(button.dataset.function)];c.detail=await request('image_function_detail',{analysis_id:c.analysis.analysis_id,address:c.selected.address});if(!c.detail.success)throw Error(c.detail.error||'상세 분석 실패');});
   root.querySelector('#dll-prev').onclick=()=>{c.page--;drawTable();};root.querySelector('#dll-next').onclick=()=>{c.page++;drawTable();};
  }
  function drawDetail(){const host=root.querySelector('#dll-function-detail');if(!host||!c.detail)return;
   window.FunctionViews.mount(host,c.detail,{initialView:c.detailView||'asm',onView:view=>c.detailView=view,download:options.download});
  }
  function drawCalls(){const host=root.querySelector('#dll-call-history');if(!host)return;
   if(!c.calls.length){host.innerHTML='<div class="empty">이 대상의 함수 호출 기록이 없습니다.</div>';return;}
   host.innerHTML=`<div class="table-wrap"><table><thead><tr><th>함수</th><th>TID</th><th>인자</th><th>상태</th><th>종료값</th><th>CallId</th><th></th></tr></thead><tbody>${[...c.calls].reverse().map(r=>`<tr><td>${escape(r.name)}</td><td>${r.thread_id||'—'}</td><td class="mono">${escape(r.parameter)}</td><td title="${escape(r.query_error||'')}">${r.released?'추적 해제':r.query_error?'조회 실패':r.execution_unknown?'실행 여부 미확인':r.completed?'완료':r.thread_created?'실행 중':'생성 실패'}</td><td class="mono">${r.completed&&r.exit_value!==null?escape(r.exit_status):'—'}</td><td>${escape(r.call_id)}</td><td>${r.released?'':`<button class="small secondary" data-release-call="${r.id}">추적 해제</button>`}</td></tr>`).join('')}</tbody></table></div>`;
   for(const b of host.querySelectorAll('[data-release-call]'))b.onclick=()=>perform(async()=>{const r=await request('function_call_release',{id:b.dataset.releaseCall});if(!r.success)throw Error(r.error||'추적 해제 실패');await refreshCalls();});
  }
  draw();
  if(!c.identity)perform(refresh).then(()=>{timer=setTimeout(poll,1500);});else timer=setTimeout(poll,1500);
 }
 window.DllWorkbench={render,reset(pid){contexts.delete(pid);}};
})();
