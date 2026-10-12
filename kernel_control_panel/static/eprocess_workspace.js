/* Exact-OS EPROCESS layouts; one identity-bound snapshot at a time. */
(()=>{'use strict';
 const PERIOD=10,esc=value=>String(value??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
 let ctx=null,epoch=0,pageGeneration=0,presetRequest=0,timer=null,busy=false,monitoring=false,userPaused=false,fault=false,info=null,last=null,filter='',layout='',cells=new Map(),previous=new Map(),lastStart=null,samples=0,latency=0,actualPeriod=0,changedCount=0,lastError='';
 const q=id=>ctx?.root.querySelector('#'+id);
 const visible=()=>ctx && ctx.currentPid()===ctx.pid && ctx.currentPage()==='eprocess' && !document.hidden;
 const connected=()=>ctx?.connected()===true;
 const owner=()=>ctx?.processObject() || {};
 const validOwner=()=>/^0x[0-9a-f]{16}$/i.test(owner().address || '') && owner().address!=='0x0000000000000000' && /^\d+$/.test(owner().identity || '');
 const ready=()=>visible() && connected() && !!ctx.pid && info?.match?.success===true && validOwner();
 function clearTimer(){if(timer!==null)clearTimeout(timer);timer=null;}
 function stop(reason='',pause=false){epoch++;clearTimer();monitoring=false;if(pause)userPaused=true;if(reason)lastError=reason;controls();}
 function dispose(){stop();pageGeneration++;ctx=null;}
 function reset(){dispose();info=null;last=null;filter='';layout='';cells.clear();previous.clear();fault=false;lastStart=null;samples=0;latency=actualPeriod=changedCount=0;lastError='';}
 function sourceLink(url){return /^https?:\/\//i.test(String(url || ''))?`<a href="${esc(url)}" target="_blank" rel="noreferrer">프리셋 원문</a>`:'원문 링크 없음';}
 function presetInfo(){
  if(!q('ep-system'))return;
  const system=info?.system || {},preset=info?.match?.preset;
  q('ep-system').textContent=[preset?.family || system.product_name || 'OS 확인 중',preset?.release || system.display_version,system.architecture,
   system.build!==undefined?`빌드 ${system.build}${system.ubr!==undefined?'.'+system.ubr:''}`:'',system.product_type!==undefined?`제품 유형 ${system.product_type}`:''].filter(Boolean).join(' · ');
  q('ep-preset').innerHTML=preset?`${esc(preset.family || '')} ${esc(preset.release || preset.id)} · ${esc(preset.size)}바이트 · ${esc(preset.field_count ?? '—')}개 필드 · ${sourceLink(preset.source_url)}`:esc(info?.match?.reason || '현재 OS와 정확히 일치하는 프리셋을 확인합니다.');
  q('ep-presets').innerHTML=(info?.presets || []).map(p=>`<li>${esc(p.family || '')} ${esc(p.release || p.id)} · ${esc(p.architecture || 'x64')} · 빌드 ${esc((p.build_numbers || []).join(', '))} · ${esc(p.size)}바이트</li>`).join('');
 }
 function controls(){
  if(!q('ep-status'))return;
  const object=owner();q('ep-target').textContent=ctx.pid?`PID ${ctx.pid} · EPROCESS ${object.address || (object.loading?'조회 중…':'미조회')}`:'프로세스를 먼저 선택하세요';
  q('ep-status').textContent=monitoring?'10ms 목표로 모니터링 중':lastError || object.error || (!connected()?'드라이버 연결을 확인하세요':!info?'프리셋 확인 중':!info.match?.success?info.match?.reason || '지원 프리셋 없음':!validOwner()?'선택한 PID의 EPROCESS 주소 조회를 기다립니다':userPaused?'모니터링 일시정지':'준비됨');
  q('ep-status').classList.toggle('error',Boolean(fault || info && !info.match?.success));
  q('ep-monitor').textContent=monitoring?'모니터링 중지':'10ms 모니터링 시작';
  q('ep-monitor').disabled=!ready();q('ep-once').disabled=busy || !ready();
  q('ep-metrics').textContent=`목표 10ms · 실제 시작 간격 ${actualPeriod?actualPeriod.toFixed(2)+'ms':'—'} · 왕복 ${latency?latency.toFixed(2)+'ms':'—'} · 관측 ${samples}회 · 변경 ${changedCount}개`;
  q('ep-sampled').textContent=last?`마지막 표본 ${new Date(typeof last.sampled_at==='number'?last.sampled_at*1000:last.sampled_at).toLocaleTimeString()} · ${last.bytes_read}/${last.size}바이트 · 서버 ${Number(last.timing_ms || 0).toFixed(2)}ms`:'아직 읽은 표본이 없습니다';
 }
 function cellValue(value){if(value===null||value===undefined)return '—';return typeof value==='object'?JSON.stringify(value):String(value);}
 function rowHTML(field,index){return `<tr data-ep-index="${index}"><td class="mono">${esc(field.offset_hex || '0x'+Number(field.offset || 0).toString(16).toUpperCase())}</td><td title="${esc(field.path)}">${esc(field.name || field.path)}<small>${esc(field.kind || '')}${field.bit_width!==undefined && field.bit_width!==null?` · bit ${esc(field.bit_offset)}:${esc(field.bit_width)}`:''}</small></td><td class="mono">${esc(field.type)}<small>${field.size===null || field.size===undefined?'크기 미확정':esc(field.size)+'B'}</small></td><td class="mono ep-value" data-ep-value></td><td class="mono ep-raw" data-ep-raw></td></tr>`;}
 function rebuild(){
  if(!last || !q('ep-fields'))return;
  const root={fields:[],children:new Map()},term=filter.toLowerCase();
  last.fields.forEach((field,index)=>{
   if(term && ![field.path,field.name,field.type,field.offset_hex].some(v=>String(v || '').toLowerCase().includes(term)))return;
   const parts=String(field.path || field.name || '').split('.');parts.pop();let node=root;
   for(const part of parts){if(!node.children.has(part))node.children.set(part,{fields:[],children:new Map()});node=node.children.get(part);}
   node.fields.push([field,index]);
  });
  const table=entries=>entries.length?`<div class="table-wrap"><table><thead><tr><th>오프셋</th><th>필드</th><th>형식 / 크기</th><th>값</th><th>원본 HEX</th></tr></thead><tbody>${entries.map(([field,index])=>rowHTML(field,index)).join('')}</tbody></table></div>`:'';
  function group(node,depth=0){return table(node.fields)+[...node.children].map(([name,child])=>`<details class="ep-group" ${depth<1 || term?'open':''}><summary>${esc(name)}</summary>${group(child,depth+1)}</details>`).join('');}
  q('ep-fields').innerHTML=group(root) || '<div class="empty">일치하는 필드가 없습니다.</div>';
  cells.clear();for(const row of q('ep-fields').querySelectorAll('[data-ep-index]'))cells.set(Number(row.dataset.epIndex),{row,value:row.querySelector('[data-ep-value]'),raw:row.querySelector('[data-ep-raw]')});
  for(const details of q('ep-fields').querySelectorAll('details'))details.addEventListener('toggle',()=>patchValues(false));
  patchValues(false);
 }
 function rowVisible(row){let node=row.parentElement;while(node && node!==q('ep-fields')){if(node.tagName==='DETAILS' && !node.open)return false;node=node.parentElement;}return true;}
 function patchValues(count=true){
  if(!last)return;let changed=0;
  last.fields.forEach((field,index)=>{
   const value=cellValue(field.value),raw=String(field.raw_hex || ''),signature=value+'\0'+raw,key=index+':'+field.path;
   const differs=previous.has(key) && previous.get(key)!==signature;if(differs)changed++;
   const cell=cells.get(index);if(cell && rowVisible(cell.row)){
    if(cell.value.textContent!==value)cell.value.textContent=value;
    const preview=raw.length>64?raw.slice(0,64)+'…':raw;
    if(cell.raw.textContent!==preview)cell.raw.textContent=preview;
    if(cell.raw.title!==raw)cell.raw.title=raw;
    cell.row.classList.toggle('ep-changed',differs);
   }
   if(count)previous.set(key,signature);
  });
  if(count)changedCount=changed;
 }
 function rawText(){if(!last)return '';const data=String(last.data_hex || '');return Array.from({length:Math.ceil(data.length/32)},(_,i)=>'0x'+(i*16).toString(16).padStart(4,'0').toUpperCase()+'  '+(data.slice(i*32,i*32+32).match(/../g)||[]).join(' ').toUpperCase()).join('\n');}
 function consume(response){
  const nextLayout=String(response.preset?.id || '')+'|'+response.fields.map(f=>[f.path,f.type,f.offset,f.size,f.kind].join(':')).join('|');
  last=response;samples++;
  if(layout!==nextLayout){layout=nextLayout;previous.clear();rebuild();}
  patchValues();
  if(q('ep-raw-details')?.open)q('ep-raw-data').textContent=rawText();
 }
 function schedule(delay=0){clearTimer();if(monitoring && ready() && !busy)timer=setTimeout(()=>{timer=null;read(true);},delay);}
 function maybeStart(){if(!userPaused && !fault && ready()){monitoring=true;lastError='';controls();schedule();}}
 async function read(background=false){
  if(busy || !ready())return;
  const c=ctx,token=epoch,object=owner(),address=object.address,key=object.identity,started=performance.now();busy=true;
  if(lastStart!==null)actualPeriod=started-lastStart;lastStart=started;controls();
  const current=()=>ctx===c && epoch===token && visible() && owner().address===address && owner().identity===key;
  try{
   const result=await c.api('/api/studio/eprocess/snapshot',{pid:c.pid,expected_address:address,expected_start_key:key,_background:background});
   if(!current())return;
   if(!result.success)throw Error(result.error || `EPROCESS 읽기 실패 · ${result.result_status || ''}`);
   if(result.process_id!==c.pid || result.eprocess_address!==address || String(result.process_start_key)!==key || !Array.isArray(result.fields) || result.bytes_read!==result.size)throw Error('EPROCESS 표본의 대상 또는 읽기 길이가 다릅니다.');
   latency=performance.now()-started;consume(result);lastError='';
  }catch(error){if(current()){fault=true;stop(error.message);}}
  finally{busy=false;controls();if(monitoring && ready())schedule(Math.max(0,PERIOD-(performance.now()-started)));}
 }
 async function loadPresets(){
  const c=ctx,generation=pageGeneration,request=++presetRequest;
  const current=()=>ctx===c && generation===pageGeneration && request===presetRequest;
  try{const result=await c.api('/api/studio/eprocess/presets');if(!current())return;if(!result.success)throw Error(result.error || '프리셋 목록을 읽을 수 없습니다.');info=result;presetInfo();controls();maybeStart();}
  catch(error){if(current()){fault=true;stop(error.message);}}
 }
 function targetChanged(){if(!ctx)return;if(last && (last.eprocess_address!==owner().address || String(last.process_start_key)!==owner().identity)){stop();last=null;layout='';cells.clear();previous.clear();q('ep-fields').innerHTML='<div class="empty">현재 대상의 새 표본을 기다립니다.</div>';}controls();if(!monitoring)maybeStart();}
 function connectionChanged(){if(!ctx)return;if(!connected())stop('드라이버 연결이 끊어져 모니터링을 중지했습니다.');else maybeStart();}
 async function refreshAddress(){const c=ctx;if(!c)return;stop();fault=false;await c.refreshObject();if(ctx===c)targetChanged();}
 function refresh(){if(!ctx)return;fault=false;lastError='';if(!info || !info.match?.success){stop();info=null;controls();loadPresets();return;}if(!validOwner()){refreshAddress();return;}clearTimer();read(monitoring);}
 function render(context){
  dispose();ctx=context;fault=false;info=null;last=null;layout='';cells.clear();previous.clear();lastStart=null;samples=0;latency=actualPeriod=changedCount=0;lastError='';
  ctx.root.innerHTML=`<section id="ep-workspace" class="card"><div class="card-head"><div><h2>EPROCESS 구조체</h2><p id="ep-target"></p></div><span class="chip">읽기 전용</span></div><p id="ep-system" class="subtle"></p><p id="ep-preset"></p><div class="ep-toolbar"><button id="ep-once" class="secondary">지금 읽기</button><button id="ep-monitor">10ms 모니터링 시작</button><button id="ep-address-refresh" class="secondary">대상 주소 다시 확인</button><button id="ep-preset-refresh" class="secondary">OS 프리셋 다시 확인</button><label>필드 찾기<input id="ep-search" value="${esc(filter)}" placeholder="필드 · 형식 · 오프셋" autocomplete="off"></label></div><p id="ep-status" role="status" aria-live="polite"></p><p id="ep-metrics" class="ep-metrics"></p><p id="ep-sampled" class="subtle"></p><p class="ep-note">현재 OS의 아키텍처·제품 유형·빌드와 정확히 맞는 프리셋만 사용합니다. 실행 중인 대상의 관측 표본이므로 한 표본 안에서도 필드가 변할 수 있으며, 10ms는 요청 목표 간격입니다.</p><details><summary>보관한 OS 프리셋</summary><ul id="ep-presets"></ul></details></section><section class="card"><div id="ep-fields"><div class="empty">OS 프리셋과 대상 주소를 확인하는 중입니다.</div></div></section><details id="ep-raw-details" class="card"><summary>EPROCESS 원본 HEX</summary><pre id="ep-raw-data" class="ep-raw-data"></pre></details>`;
  q('ep-search').oninput=e=>{filter=e.target.value;rebuild();};
  q('ep-once').onclick=()=>{fault=false;lastError='';read(false);};
  q('ep-monitor').onclick=()=>{if(monitoring)stop('모니터링 일시정지',true);else{userPaused=false;fault=false;lastError='';maybeStart();}};
  q('ep-address-refresh').onclick=refreshAddress;
  q('ep-preset-refresh').onclick=()=>{stop();fault=false;info=null;controls();loadPresets();};
  q('ep-raw-details').addEventListener('toggle',()=>{if(q('ep-raw-details')?.open)q('ep-raw-data').textContent=rawText();});
  controls();loadPresets();
 }
 document.addEventListener('visibilitychange',()=>{if(document.hidden)stop('화면이 숨겨져 모니터링을 중지했습니다.');else maybeStart();});
 window.EprocessWorkbench={render,dispose,reset,refresh,targetChanged,connectionChanged,status:()=>({monitoring,busy,samples,latency,actualPeriod,changedCount})};
})();
