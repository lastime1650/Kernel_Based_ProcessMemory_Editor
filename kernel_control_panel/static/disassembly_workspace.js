/* Address analysis and reversible kernel patches. No target native APIs. */
(() => {
 'use strict';
 const esc=v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
 const fresh=()=>({pid:0,invalid:false,session:'',analysis:'',address:'',size:'1024',bits:'auto',detail:null,drafts:new Map(),view:'asm',
  visits:[],visit:-1,history:[],can_undo:false,can_redo:false,recovery:null,error:'',status:'',generation:0});
 let state=fresh(),context=null,editor=null,validation=0,validityTimer;
 function reset(){
  const old=state,ctx=context;state=fresh();state.generation=old.generation+1;validation++;editor?.close();editor?.remove();editor=null;
  clearTimeout(validityTimer);
  if(old.session&&ctx)ctx.api('/api/studio/execute',{operation:'disasm_release',args:{pid:old.pid,session_id:old.session}}).catch(()=>{});
 }
 const mounted=ctx=>!!ctx&&ctx===context&&ctx.root.querySelector('#da-form')&&ctx.currentPid()===state.pid;
 function history(result){for(const key of ['history','can_undo','can_redo','recovery'])if(key in result)state[key]=result[key];}
 async function request(operation,args={}){
  const generation=state.generation,ctx=context;
  const result=await ctx.api('/api/studio/execute',{operation,args:{pid:state.pid,session_id:state.session,...args}});
  if(generation===state.generation&&result.target_invalid){const pid=state.pid;reset();state.pid=pid;state.invalid=true;state.error=result.error+' · 대상을 다시 선택하세요.';ctx.address='';ctx.onAddress?.('');paint();}
  return result;
 }
 function controls(){
  if(!context||!mounted(context))return;
  const busy=context.isBusy()||state.invalid;
  for(const b of context.root.querySelectorAll('[data-da-action],#da-analyze'))b.disabled=busy||!state.pid;
  context.root.querySelector('#da-back').disabled=busy||state.visit<=0;
  context.root.querySelector('#da-forward').disabled=busy||state.visit>=state.visits.length-1;
  context.root.querySelector('#da-apply').disabled=busy||!state.drafts.size||!!state.recovery;
  context.root.querySelector('#da-undo').disabled=busy||!state.can_undo||!!state.drafts.size;
  context.root.querySelector('#da-redo').disabled=busy||!state.can_redo||!!state.drafts.size;
  context.root.querySelector('#da-discard').disabled=busy||!state.drafts.size;
  context.root.querySelector('#da-recover').hidden=!state.recovery;
 }
 function paint(){if(mounted(context))render(context);}
 async function analyze(target,visit=null){
  if(state.invalid)return context.toast('종료 / 교체된 대상입니다. 프로세스를 다시 선택하세요.',true);
  if(context.isBusy())return context.toast('진행 중인 요청을 기다리세요',true);
  if(!state.pid)return context.toast('대상 프로세스를 먼저 선택하세요',true);
  if(state.drafts.size)return context.toast('이동 전에 편집을 적용하거나 대기 편집을 지우세요',true);
  const ctx=context,generation=state.generation,pid=state.pid;
  ctx.setBusy(true);state.error='';state.status='커널 메모리를 읽어 분석하는 중…';controls();
  try{
   const result=await request('disasm_analyze',{address:target,size:state.size,bits:state.bits});
   if(generation!==state.generation){if(result.session_id)ctx.api('/api/studio/execute',{operation:'disasm_release',args:{pid,session_id:result.session_id}}).catch(()=>{});return;}
   if(!result.success)throw Error(result.error||'분석 실패');
   state.session=result.session_id;state.analysis=result.analysis_id;state.address=result.address;state.detail=result.detail;history(result);
   if(visit!==null)state.visit=visit;
   else if(state.visits[state.visit]!==state.address){state.visits.splice(state.visit+1);state.visits.push(state.address);if(state.visits.length>256)state.visits.shift();state.visit=state.visits.length-1;}
   ctx.address=state.address;ctx.onAddress?.(state.address);state.status=`${state.address} · 커널에서 ${result.detail.read_bytes}바이트 읽음`;
  }catch(error){if(generation===state.generation){state.error=error.message;ctx.toast(error.message,true);}}
  finally{ctx.setBusy(false);if(generation===state.generation)paint();else controls();}
 }
 async function mutate(operation){
  if(context.isBusy()||state.invalid)return;
  const ctx=context,generation=state.generation;
  ctx.setBusy(true);state.error='';controls();
  try{
   const result=await request(operation,{analysis_id:state.analysis,edits:Array.from(state.drafts.values(),d=>({address:d.address,text:d.text}))});
   if(generation!==state.generation)return;
   history(result);
   if(!result.success)throw Error(result.error||'커널 패치 실패');
   state.drafts.clear();state.status=operation==='disasm_apply'?'바이트 패치를 커널로 적용하고 다시 읽어 검증했습니다.':operation==='disasm_undo'?'원본 바이트로 복원했습니다.':operation==='disasm_redo'?'패치를 다시 적용했습니다.':'실패한 요청의 원본 / 페이지 보호를 복구했습니다.';
   // Refresh decoding from the committed bytes without creating a visit.
   const refresh=await request('disasm_analyze',{address:state.address,size:state.size,bits:state.bits});
   if(generation!==state.generation)return;
   if(refresh.success){state.session=refresh.session_id;state.analysis=refresh.analysis_id;state.detail=refresh.detail;history(refresh);}
   else state.error='바이트 작업은 완료했지만 분석 갱신 실패: '+refresh.error;
   ctx.toast(state.status);
  }catch(error){if(generation===state.generation){state.error=error.message;ctx.toast(error.message,true);}}
  finally{ctx.setBusy(false);if(generation===state.generation)paint();else controls();}
 }
 async function follow(item){
  if(context.isBusy()||state.invalid)return;
  if(state.drafts.size)return context.toast('이동 전에 편집을 적용하거나 대기 편집을 지우세요',true);
  if(item.raw)return analyze(item.address);
  const row=item.instruction,refs=row.references||[];
  if(!refs.length)return context.toast('레지스터 / 실행 시 계산되는 주소는 현재 정적 분석으로 이동할 수 없습니다.',true);
  if(item.reference===undefined&&refs.length>1){
   openDialog(`<h3>참조 주소 선택</h3><div class="da-ref-list">${refs.map((r,n)=>`<button type="button" data-ref="${n}">${esc(r.kind)} · ${esc(r.address)}</button>`).join('')}</div><button type="button" class="secondary" data-close>취소</button>`);
   for(const button of editor.querySelectorAll('[data-ref]'))button.onclick=()=>{const reference=button.dataset.ref;closeEditor();follow({instruction:row,reference});};return;
  }
  const ctx=context,generation=state.generation;ctx.setBusy(true);controls();let target;
  try{const result=await request('disasm_follow',{analysis_id:state.analysis,address:row.address,reference:item.reference??0});if(!result.success)throw Error(result.error);if(generation===state.generation)target=result.address;}
  catch(error){ctx.toast(error.message,true);state.error=error.message;}
  finally{ctx.setBusy(false);controls();}
  if(target)await analyze(target);
 }
 function closeEditor(){validation++;editor?.close();editor?.remove();editor=null;}
 function openDialog(html){
  closeEditor();editor=document.createElement('dialog');editor.className='da-editor';editor.innerHTML=html;document.body.append(editor);
  editor.querySelector('[data-close]')?.addEventListener('click',closeEditor);
  editor.addEventListener('cancel',e=>{e.preventDefault();closeEditor();});editor.showModal();
 }
 function edit(row){
  if(context.isBusy())return context.toast('진행 중인 요청을 기다리세요',true);
  const ctx=context,generation=state.generation,analysis=state.analysis;
  const prior=state.drafts.get(row.address);
  openDialog(`<div class="dialog-head"><h2>명령어 편집</h2><button type="button" class="secondary" data-close>닫기</button></div><p class="mono">${esc(row.address)} · ${esc(row.bytes)} · ${row.size}바이트</p><p class="subtle">${esc(row.instruction+' '+row.operands)}</p><label>Intel 어셈블리 · 대소문자 구분 없음<input id="da-assembly-input" spellcheck="false" autocomplete="off" value="${esc(prior?.text||row.instruction+' '+row.operands)}"></label><div id="da-validation" role="status" aria-live="polite"></div><div class="actions"><button type="button" id="da-stage" disabled>편집 대기 목록에 넣기</button><button type="button" id="da-remove-edit" class="secondary" ${prior?'':'hidden'}>이 줄의 편집 취소</button></div><p class="subtle">기존 명령 길이 이내에서 수정합니다. 짧은 명령은 NOP으로 나머지를 채웁니다. 적용 버튼을 눌러야 실제 메모리가 바뀝니다.</p>`);
  const dialog=editor,input=dialog.querySelector('#da-assembly-input'),feedback=dialog.querySelector('#da-validation'),stage=dialog.querySelector('#da-stage');
  let compiled=null,timer;
  async function validate(){
   const token=++validation;textStatus('인코딩 확인 중…');stage.disabled=true;compiled=null;
   try{const result=await ctx.api('/api/studio/execute',{operation:'disasm_validate',args:{pid:state.pid,session_id:state.session,analysis_id:analysis,address:row.address,text:input.value}});
    if(token!==validation||editor!==dialog||generation!==state.generation)return;
    if(!result.success)throw Error(result.error);
    compiled=result;feedback.className='da-validation-ok';feedback.innerHTML=`<strong>${esc(result.assembly)}</strong><div class="mono">${esc(result.patch_bytes)}</div><span>${result.size} / ${result.slot_size}바이트${result.padding?' · NOP '+result.padding+'바이트':''}</span>`;stage.disabled=ctx.isBusy();
   }catch(error){if(token!==validation||editor!==dialog)return;feedback.className='da-validation-error';feedback.textContent=error.message;}
  }
  function textStatus(text){feedback.className='';feedback.textContent=text;}
  input.oninput=()=>{validation++;compiled=null;stage.disabled=true;textStatus('입력 확인 중…');clearTimeout(timer);timer=setTimeout(validate,180);};
  stage.onclick=()=>{if(!compiled||ctx.isBusy()||generation!==state.generation)return;state.drafts.set(row.address,compiled);closeEditor();paint();};
  dialog.querySelector('#da-remove-edit').onclick=()=>{state.drafts.delete(row.address);closeEditor();paint();};
  input.onkeydown=e=>{if(e.key==='Enter'&&!stage.disabled){e.preventDefault();stage.click();}};
  input.focus();input.select();validate();
 }
 function render(ctx){
  context=ctx;
  if(state.pid!==ctx.pid){reset();state.pid=ctx.pid;}
  ctx.root.innerHTML=`<section class="card da-address-card"><div class="card-head"><div><h2>주소에서 코드 분석 / 편집</h2><p>커널 메모리에서 어셈블리 · Graph · C 의사코드를 함께 봅니다.</p></div><span class="chip">${ctx.pid?'PID '+ctx.pid:'대상을 선택하세요'}</span></div><form id="da-form"><div class="fields"><label>분석 주소<input id="da-address" autocomplete="off" placeholder="0x00000000" value="${esc(ctx.address||state.address||'')}"></label><label>최대 분석 바이트<input id="da-size" inputmode="numeric" value="${esc(state.size)}"></label><label>코드 아키텍처<select id="da-bits"><option value="auto">자동 · 대상 아키텍처</option><option value="64">x64</option><option value="32">x86</option></select></label></div><div class="actions"><button type="submit" id="da-analyze">주소 분석</button><button type="button" class="secondary" id="da-back" data-da-action="back">← 주소 Undo</button><button type="button" class="secondary" id="da-forward" data-da-action="forward">주소 Redo →</button><span class="subtle">${Math.max(0,state.visit+1)} / ${state.visits.length} · Ctrl+더블클릭으로 참조 이동</span></div></form></section><section class="card da-edit-toolbar"><div class="actions"><button id="da-apply" data-da-action="apply">편집 적용 · ${state.drafts.size}줄</button><button id="da-discard" class="secondary" data-da-action="discard">대기 편집 지우기</button><button id="da-undo" class="secondary" data-da-action="undo">패치 Undo · 복원</button><button id="da-redo" class="secondary" data-da-action="redo">패치 Redo · 다시 적용</button><button id="da-recover" class="danger" data-da-action="recover">실패한 요청 복구</button></div><p class="subtle">ASM / Graph의 명령어를 더블클릭해 편집합니다. 대상 재선택 시 기록은 삭제됩니다. 이미 적용한 바이트는 유지되므로 필요하면 먼저 복원하세요.</p><p class="da-live-note">여러 바이트 패치는 실행 중인 스레드에 대해 원자적이지 않습니다. 코드를 실행하지 않는 상태에서 적용하세요. 의사코드는 보기 전용입니다.</p><div id="da-status" role="status" class="${state.error?'da-error':'subtle'}">${esc(state.error||state.status)}</div>${state.recovery?`<p class="da-error">${esc(state.recovery.error)} ${esc((state.recovery.protection_errors||[]).join(' · '))}</p>`:''}${state.drafts.size?`<details open class="da-drafts"><summary>적용 대기 · ${state.drafts.size}줄</summary><div class="table-wrap"><table><thead><tr><th>주소</th><th>원본</th><th>편집</th><th>기록할 바이트</th></tr></thead><tbody>${Array.from(state.drafts.values(),d=>`<tr><td class="mono">${esc(d.address)}</td><td class="mono">${esc(d.before)}</td><td class="mono">${esc(d.assembly)}</td><td class="mono">${esc(d.patch_bytes)}</td></tr>`).join('')}</tbody></table></div></details>`:''}</section><section id="da-view" class="card">${state.detail?'':'<div class="empty">대상을 선택하고 코드 주소를 입력하세요. 메모리 이미지로 등록되지 않은 코드도 분석할 수 있습니다.</div>'}</section><section class="card da-history"><div class="card-head"><h3>이 대상의 편집 이력 · ${state.history.length}회</h3><button id="da-save-history" class="secondary small">이력 JSON 저장</button></div><p class="subtle">원본 / 적용 바이트는 서버 실행 세션에 보관됩니다. 새 적용 후에는 취소된 Redo 경로가 삭제됩니다.</p>${state.history.length?`<div class="table-wrap"><table><thead><tr><th>순서</th><th>상태</th><th>주소 / 변경 명령</th><th>원본 → 패치</th></tr></thead><tbody>${state.history.map((r,n)=>`<tr><td>${n+1}</td><td>${r.state==='applied'?'적용됨':'복원됨'}</td><td>${r.edits.map(e=>`<div class="mono">${esc(e.address)} · ${esc(e.assembly)}</div>`).join('')}</td><td>${r.edits.map(e=>`<div class="mono">${esc(e.before)} → ${esc(e.after)}</div>`).join('')}</td></tr>`).join('')}</tbody></table></div>`:'<div class="empty">아직 적용한 편집이 없습니다.</div>'}</section>`;
  ctx.root.querySelector('#da-bits').value=state.bits;
  ctx.root.querySelector('#da-form').onsubmit=e=>{e.preventDefault();state.size=ctx.root.querySelector('#da-size').value;state.bits=ctx.root.querySelector('#da-bits').value;analyze(ctx.root.querySelector('#da-address').value);};
  ctx.root.querySelector('#da-back').onclick=()=>analyze(state.visits[state.visit-1],state.visit-1);
  ctx.root.querySelector('#da-forward').onclick=()=>analyze(state.visits[state.visit+1],state.visit+1);
  ctx.root.querySelector('#da-apply').onclick=()=>mutate('disasm_apply');
  ctx.root.querySelector('#da-undo').onclick=()=>mutate('disasm_undo');
  ctx.root.querySelector('#da-redo').onclick=()=>mutate('disasm_redo');
  ctx.root.querySelector('#da-recover').onclick=()=>mutate('disasm_recover');
  ctx.root.querySelector('#da-discard').onclick=()=>{state.drafts.clear();paint();};
  ctx.root.querySelector('#da-save-history').onclick=()=>ctx.download(JSON.stringify({pid:state.pid,address:state.address,history:state.history,recovery:state.recovery},null,2),'disassembly-patches-'+state.pid+'.json','application/json');
  if(state.detail)window.FunctionViews.mount(ctx.root.querySelector('#da-view'),state.detail,{initialView:state.view,onView:v=>state.view=v,download:ctx.download,drafts:state.drafts,onEdit:edit,onNavigate:follow});
  controls();
  clearTimeout(validityTimer);
  const generation=state.generation;
  async function checkValidity(){
   if(!mounted(ctx)||generation!==state.generation||!state.session)return;
   if(!ctx.isBusy()&&!editor){try{await request('disasm_history');}catch{/* A transient connection failure does not discard recovery data. */}}
   if(mounted(ctx)&&generation===state.generation&&state.session)validityTimer=setTimeout(checkValidity,5000);
  }
  if(state.session)validityTimer=setTimeout(checkValidity,5000);
 }
 window.DisassemblyWorkbench={render,reset,exportState:()=>({address:state.address,size:state.size,bits:state.bits,view:state.view,visits:state.visits,visit:state.visit}),importState:value=>{reset();state.pid=context?.currentPid()||0;Object.assign(state,{address:value.address||'',size:value.size||'1024',bits:value.bits||'auto',view:value.view||'asm'});},refresh:()=>context?.root.querySelector('#da-form')?.requestSubmit()};
})();
