/* Kernel-only, read-only surrounding-memory viewer. Inferred groups are labelled as candidates. */
(()=>{'use strict';
 const LIMIT=0x800000000000n, ROW=26, MAP_PAGE=1024;
 const esc=x=>String(x??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
 const hex=x=>'0x'+BigInt(x).toString(16).toUpperCase();
 const raw=x=>Uint8Array.from(x.match(/../g)||[],b=>parseInt(b,16));
 function address(value){const s=String(value).trim();if(!/^(?:0x)?[a-f\d]+$/i.test(s))throw Error('주소는 16진수로 입력하세요');const n=BigInt(/^0x/i.test(s)?s:'0x'+s);if(n<1n||n>=LIMIT)throw Error('사용자 메모리 주소 범위를 확인하세요');return n;}
 const hash=s=>{let h=2166136261;for(const c of s)h=Math.imul(h^c.charCodeAt(0),16777619);return h>>>0;};
 const uint=bytes=>{let n=0n;for(let i=bytes.length-1;i>=0;i--)n=(n<<8n)|BigInt(bytes[i]);return n;};
 function textCandidate(text){
  if(text.length<3||!/^[\p{L}\p{M}\p{N}\p{P}\p{Zs}\p{Sc}\p{Sm}]+$/u.test(text))return false;
  const letters=[...text].filter(c=>/\p{L}/u.test(c));if(!letters.length)return /^[\d .,+-]+$/.test(text);
  const rules=[/[\p{Script=Latin}\p{Script=Hangul}]/u,/[\p{Script=Latin}\p{Script=Han}\p{Script=Hiragana}\p{Script=Katakana}]/u,/[\p{Script=Latin}\p{Script=Cyrillic}]/u,/[\p{Script=Latin}\p{Script=Greek}]/u,/[\p{Script=Latin}\p{Script=Arabic}]/u,/[\p{Script=Latin}\p{Script=Hebrew}]/u];
  return rules.some(rule=>letters.filter(c=>rule.test(c)).length/letters.length>=.85);
 }
 const pattern=deltas=>{if(deltas.length<3)return {name:'표본 대기',nonlinear:0};const a=deltas.slice(-8),linear=a.every(x=>x===a[0]);if(linear)return {name:'선형 · Δ '+a[0],nonlinear:0};const m=Math.max(...a.map(x=>Math.abs(Number(x))),1),spread=new Set(a.map(String)).size;return {name:'비선형 · 변화 폭 '+m,nonlinear:Math.min(1,(spread-1)/5)};};

 class Model {
  constructor(){this.seq=0;this.bytes=new Map();this.motion=new Map();}
  observe(base,data,valid,fields=[],opacity=50){
   base=BigInt(base);++this.seq;const seq=this.seq,states=[],groups=[],owners=Array(data.length).fill(-1);
   for(let i=0;i<data.length;i++){
    const key=String(base+BigInt(i));let s=this.bytes.get(key);
    if(!valid[i]){this.bytes.delete(key);states.push(null);continue;}
    if(!s||s.seq!==seq-1)s={value:data[i],history:[],deltas:[],born:null,seq:seq-1};
    const delta=data[i]-s.value;s.history.push(delta!==0?1:0);s.history=s.history.slice(-8);
    if(delta){s.deltas.push(delta);s.deltas=s.deltas.slice(-8);if(s.value===0&&data[i]!==0)s.born=seq;}
    if(!data[i])s.born=null;s.value=data[i];s.seq=seq;states.push(s);this.bytes.delete(key);this.bytes.set(key,s);
   }
   while(this.bytes.size>32768)this.bytes.delete(this.bytes.keys().next().value);
   const put=(start,end,kind,label,confirmed=false)=>{if(start>=end)return;const id=groups.length,g={start,end,kind,label,confirmed};groups.push(g);for(let j=start;j<end;j++)owners[j]=id;};
   for(const f of fields){const offset=BigInt(f.address)-base;if(offset>=BigInt(data.length)||offset+BigInt(f.width)<=0n)continue;const start=Math.max(0,Number(offset)),end=Math.min(data.length,Number(offset)+f.width);if(owners.slice(start,end).every(x=>x<0))put(start,end,f.type,f.path,true);}
   const free=(i,n)=>i+n<=data.length&&owners.slice(i,i+n).every(x=>x<0)&&valid.slice(i,i+n).every(Boolean);
   // Complete NUL-terminated strings only. Boundary fragments never imply a confirmed type.
   for(let i=0;i<data.length;i++){
    if(owners[i]>=0||!valid[i]||data[i]===0)continue;let end=i,text='';
    let narrow=i;while(narrow<data.length&&narrow-i<256&&free(narrow,1)&&data[narrow]!==0)narrow++;
    if(narrow-i>=3&&narrow<data.length&&free(narrow,1)&&data[narrow]===0)try{const t=new TextDecoder('utf-8',{fatal:true}).decode(data.slice(i,narrow));if(textCandidate(t)){put(i,narrow+1,'utf8','UTF-8 문자열 후보: '+t);i=narrow;continue;}}catch{}
    if((base+BigInt(i))%2n===0n){
     let j=i;while(j+1<data.length&&j-i<512&&free(j,2)){
      const c=data[j]|data[j+1]<<8;if(c===0){if(j-i>=6)try{text=new TextDecoder('utf-16le',{fatal:true}).decode(data.slice(i,j));if(textCandidate(text))end=j+2;}catch{}break;}
      if(c<32||c===0xffff)break;j+=2;
     }
    }
    if(end>i){put(i,end,'utf16','UTF-16 문자열 후보: '+text);i=end-1;continue;}
    let j=i;while(j<data.length&&j-i<256&&free(j,1)&&data[j]!==0)j++;
    if(j-i>=3&&j<data.length&&free(j,1)&&data[j]===0)try{text=new TextDecoder('utf-8',{fatal:true}).decode(data.slice(i,j));if(textCandidate(text)){put(i,j+1,'utf8','UTF-8 문자열 후보: '+text);i=j;}}catch{}
   }
   const related=(a,b)=>a&&b&&a.history.length>=4&&b.history.length===a.history.length&&a.history.reduce((n,v)=>n+v,0)>=3&&a.history.every((v,i)=>v===b.history[i]);
   for(let i=0;i<data.length;i++)if(free(i,2)&&related(states[i],states[i+1])){let j=i+2;while(j<data.length&&j-i<32&&free(j,1)&&related(states[j-1],states[j]))j++;put(i,j,'cochange','동시 변화 관측 묶음');i=j-1;}
   for(let i=0;i<data.length;i++)if((base+BigInt(i))%4n===0n&&free(i,4)&&data[i+2]===0&&data[i+3]===0&&(data[i]||data[i+1])){
    const observed=states.slice(i,i+4).filter((s,j)=>data[i+j]&&s.history.length>=4),independent=observed.length>1&&observed.some(s=>s.deltas.length>=3)&&observed.some(s=>!s.history.every((v,j)=>v===observed[0].history[j]));
    if(!independent)put(i,i+4,'uint32','uint32 후보 · 작은 정수 / 4바이트');
   }
   for(let i=0;i<data.length;i++){
    if(owners[i]>=0)continue;if(!valid[i]){put(i,i+1,'hole','읽기 불가');continue;}
    if(data[i]===0&&!states[i]?.deltas.length){let j=i+1;while(j<data.length&&owners[j]<0&&valid[j]&&data[j]===0&&!states[j]?.deltas.length)j++;put(i,j,'zero','0 바이트 구간');i=j-1;continue;}
    let j=i+1;while(j<data.length&&j-i<32&&owners[j]<0&&valid[j]&&related(states[j-1],states[j]))j++;
    put(i,j,j-i>1?'cochange':'byte',j-i>1?'동시 변화 관측 묶음':'독립 바이트');i=j-1;
   }
   const cells=Array(data.length);
   for(const g of groups){
    const slice=data.slice(g.start,g.end),nonzero=slice.some(Boolean),key=hex(base+BigInt(g.start))+':'+g.kind;
    let motion=this.motion.get(key);let value=uint(slice.length<=8?slice:Uint8Array.of(slice.reduce((n,b)=>n+b,0)%256));
    if(g.kind==='float32'&&slice.length===4)value=new DataView(slice.buffer,slice.byteOffset,4).getFloat32(0,true);
    if(g.kind==='float64'&&slice.length===8)value=new DataView(slice.buffer,slice.byteOffset,8).getFloat64(0,true);
    if(typeof value==='number'&&!Number.isFinite(value))value=0;
    if(!motion||motion.seq!==seq-1)motion={value,deltas:[],seq:seq-1};
    if(value!==motion.value){motion.deltas.push(value-motion.value);motion.deltas=motion.deltas.slice(-8);}motion.value=value;motion.seq=seq;
    this.motion.delete(key);this.motion.set(key,motion);const p=pattern(motion.deltas);
    const hue=g.kind==='byte'?190+data[g.start]/255*110:g.kind==='cochange'?205:30+(hash(g.confirmed?g.label:key)%310);
    g.pattern=p.name;g.address=hex(base+BigInt(g.start));g.value=String(value);
    for(let i=g.start;i<g.end;i++){
     const born=states[i]?.born,factor=born===null||born===undefined?1:Math.min(1,.18+(seq-born)*.14);
     const alpha=valid[i]&&nonzero?Math.max(0,Math.min(1,opacity/100))*factor:0;
     cells[i]={group:g,alpha,hue,light:46-p.nonlinear*17,color:`hsla(${hue.toFixed(1)},68%,${46-p.nonlinear*17}%,${alpha.toFixed(3)})`,title:`${hex(base+BigInt(i))} · ${g.label}${g.confirmed?' · 구조체 정의':' · 추정/관측'}\n범위 ${g.address} +${g.end-g.start}B · ${p.name}\n바이트 ${valid[i]?data[i].toString(16).padStart(2,'0').toUpperCase():'??'}`};
    }
   }
   while(this.motion.size>16384)this.motion.delete(this.motion.keys().next().value);
   return {groups,cells};
  }
 }

 let ctx=null,packet=null,regions=[],model=new Model(),colors=null,generation=0,timer=null,queueTimer=null,inFlight=false,queued=null,mapQueued=false,mapPage=0,schemas=[],selected='';
 let config={address:'',origin:'',opacity:50,columns:32,interval:150,live:true,schema:'',schemaAddress:''};
 const active=()=>ctx?.root.isConnected&&ctx.root.querySelector('#wv-panel')&&ctx.currentPid()===ctx.pid;
 const q=s=>ctx?.root.querySelector(s);
 function error(message){if(active())q('#wv-error').textContent=message;}
 function stash(){clearTimeout(timer);clearTimeout(queueTimer);queued=null;mapQueued=false;++generation;}
 function reset(){stash();if(packet&&ctx)ctx.api('/api/studio/wide-views/'+packet.id,undefined,'DELETE').catch(()=>{});packet=null;regions=[];model=new Model();colors=null;selected='';config.address=config.origin=config.schemaAddress='';}
 function count(){return Math.min(4096,Math.max(256,(Math.ceil((q('#wv-hex')?.clientHeight||416)/ROW)+2)*config.columns));}
 function start(target,size){const middle=BigInt(Math.floor(size/config.columns/2)*config.columns),row=target-target%BigInt(config.columns),base=row>middle?row-middle:1n;return base+BigInt(size)+8n<LIMIT?base:LIMIT-BigInt(size+9);}
 function schedule(){clearTimeout(timer);if(active()&&packet&&config.live&&!document.hidden)timer=setTimeout(()=>{queued??=config.address;pump();},config.interval);}
 function go(value){try{config.address=hex(address(value));if(!config.origin)config.origin=config.address;queued=config.address;pump();}catch(e){error(e.message);}}
 async function pump(){
  clearTimeout(queueTimer);if(!active()||inFlight||!queued&&!mapQueued)return;
  if(ctx.isBusy()){queueTimer=setTimeout(pump,40);return;}
  const current=ctx,token=generation,target=queued||config.address,mapOnly=!queued&&mapQueued;queued=null;mapQueued=false;inFlight=true;
  const manual=!packet; if(manual)current.setBusy(true);
  try{
   const size=count(),base=start(address(target),size),body={pid:current.pid,address:hex(base),size,schema:config.schema,definitions:config.schema?schemas:undefined,schema_address:config.schemaAddress||target,_background:!manual};
   const response=packet?await current.api(`/api/studio/wide-views/${packet.id}/${mapOnly?'map':'read'}`,body):await current.api('/api/studio/wide-views',body);
   if(token!==generation||!active()){if(!packet)current.api('/api/studio/wide-views/'+response.id,undefined,'DELETE').catch(()=>{});return;}
   if(response.pid!==current.pid)throw Error('대상 PID가 다른 응답을 거절했습니다');
   packet=response;if(response.regions){regions=response.regions;const i=regions.findIndex(r=>BigInt(r.address)<=address(target)&&BigInt(r.address)+BigInt(r.size)>address(target));if(i>=0)mapPage=Math.floor(i/MAP_PAGE);drawMap();}
   if(!mapOnly){selected=target;const data=raw(packet.data_hex),valid=raw(packet.valid_hex);if(data.length!==packet.size||valid.length!==packet.size)throw Error('Wide View 응답 바이트 길이가 잘못되었습니다');colors=model.observe(packet.address,data,valid,packet.fields,config.opacity);drawBytes(data,valid);if(target===config.address)current.onAddress(target);}
   drawCurrent();error('');
  }catch(e){if(token===generation&&active()){if(e.message.includes('Wide View 세션이 만료')){packet=null;regions=[];colors=null;model=new Model();selected='';}error(e.message);}}
  finally{inFlight=false;if(manual)current.setBusy(false);if(active()){if(queued||mapQueued)pump();else schedule();}}
 }
 function regionColor(r){if(r.guarded)return '#e77572';if(r.readable===false)return '#4f5969';if(r.executable)return '#698bec';if(String(r.type).toLowerCase()==='0x1000000')return '#b994f5';if(String(r.type).toLowerCase()==='0x40000')return '#e8b45d';if(String(r.state).toLowerCase()==='0x2000')return '#62778b';return '#6bbf98';}
 function drawMap(){
  if(!active())return;const pages=Math.max(1,Math.ceil(regions.length/MAP_PAGE));mapPage=Math.max(0,Math.min(pages-1,mapPage));const shown=regions.slice(mapPage*MAP_PAGE,(mapPage+1)*MAP_PAGE),rows=Math.max(4,Math.ceil(shown.length/64));
  q('#wv-map').innerHTML=`<svg viewBox="0 0 1024 ${rows*15}" role="group" aria-label="전체 프로세스 메모리 영역 미니맵">${shown.map((r,i)=>`<rect x="${i%64*16+1}" y="${Math.floor(i/64)*15+1}" width="14" height="13" rx="2" fill="${regionColor(r)}" data-region="${mapPage*MAP_PAGE+i}" tabindex="0" role="button" aria-label="${esc(r.address)} · ${r.size} bytes · ${esc(r.image_name||r.type)}"><title>${esc(r.address)} · ${r.size} bytes · ${esc(r.image_name||r.type)}${r.guarded?' · Guard':''}</title></rect>`).join('')}</svg>`;
  q('#wv-map-caption').textContent=`전체 ${regions.length.toLocaleString()}개 영역 · ${mapPage+1}/${pages} 페이지 · 주소 순 타일 (크기 비례 아님, 빈 주소 간격 생략)`;
  q('#wv-map-prev').disabled=mapPage===0;q('#wv-map-next').disabled=mapPage>=pages-1;
  const pick=e=>{const el=e.target.closest('[data-region]');if(!el)return;const r=regions[Number(el.dataset.region)];const target=BigInt(r.address)===0n?'0x1':r.address;q('#wv-address').value=target;go(target);ctx.onAddress(target);};
  q('#wv-map').onclick=pick;q('#wv-map').onkeydown=e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();pick(e);}};
 }
 function drawCurrent(){
  if(!active()||!packet)return;const target=address(selected||config.address),base=address(packet.address),end=base+BigInt(packet.size),r=regions.find(r=>BigInt(r.address)<=target&&BigInt(r.address)+BigInt(r.size)>target);
  for(const tile of q('#wv-map').querySelectorAll('[data-region]')){const a=regions[Number(tile.dataset.region)],lo=BigInt(a.address),hi=lo+BigInt(a.size);tile.classList.toggle('wv-current',lo<=target&&target<hi);tile.classList.toggle('wv-near',lo<end&&hi>base);}
  q('#wv-location').textContent=`현재 ${hex(target)} · ${r?`${r.image_name||r.type} · ${r.size.toLocaleString()}B`:'할당 영역 밖'} · 주변 ${packet.address}–${hex(end-1n)}`;
  q('#wv-status').textContent=`PID ${packet.pid} · ${packet.bits}-bit · ${packet.size}B / 표본 · 읽기 불가 ${packet.holes}구간 · 표본 ${model.seq} · ${config.interval}ms`;
  q('#wv-address').value=config.address;
  if(colors){const offset=Number(target-base),g=colors.cells[offset]?.group;q('#wv-inspector').textContent=g?`${hex(target)} · ${g.label}\n${g.address}부터 ${g.end-g.start}바이트 · ${g.pattern}\n${g.confirmed?'구조체 정의 범위':'자동 색상은 문자열/숫자 후보 또는 관측 묶음이며 실제 타입을 확정하지 않습니다.'}`:'바이트를 선택하면 주소와 색상 근거를 표시합니다.';}
 }
 function drawBytes(data=raw(packet.data_hex),valid=raw(packet.valid_hex)){
  if(!active()||!colors)return;const base=address(packet.address),rows=[];for(let offset=0;offset<data.length;offset+=config.columns)rows.push(offset);
  const available=q('#wv-hex').clientWidth||1100;q('#wv-hex').style.setProperty('--wv-cell-width',Math.max(13,Math.min(27,(available-164)/config.columns))+'px');q('#wv-hex').style.setProperty('--wv-font-size',config.columns===64?'10px':'12px');
  const layout=packet.address+':'+packet.size+':'+config.columns,host=q('#wv-bytes');
  if(host.dataset.layout!==layout){host.dataset.layout=layout;host.innerHTML=rows.map(offset=>`<div class="wv-row"><span class="wv-row-address">${hex(base+BigInt(offset))}</span><div class="wv-cells">${Array.from({length:Math.min(config.columns,data.length-offset)},(_,j)=>`<button data-offset="${offset+j}" class="wv-byte"></button>`).join('')}</div><span class="wv-ascii" data-ascii="${offset}"></span></div>`).join('');}
  for(const b of host.querySelectorAll('[data-offset]')){const i=Number(b.dataset.offset),c=colors.cells[i];b.textContent=valid[i]?data[i].toString(16).padStart(2,'0').toUpperCase():'??';b.style.backgroundColor=c.color;b.title=c.title;b.classList.toggle('wv-hole',!valid[i]);b.classList.toggle('wv-zero',c.alpha===0&&!!valid[i]);b.classList.toggle('wv-selected',base+BigInt(i)===address(selected||config.address));b.classList.toggle('wv-group-start',i===c.group.start);b.classList.toggle('wv-group-end',i===c.group.end-1);b.dataset.kind=c.group.kind;}
  for(const row of host.querySelectorAll('[data-ascii]')){const off=Number(row.dataset.ascii);row.textContent=Array.from(data.slice(off,off+config.columns),(b,i)=>valid[off+i]?(b>=32&&b<127?String.fromCharCode(b):'·'):'?').join('');}
  host.onclick=e=>{const b=e.target.closest('[data-offset]');if(!b)return;selected=hex(base+BigInt(b.dataset.offset));drawBytes();drawCurrent();};
  host.ondblclick=e=>{const b=e.target.closest('[data-offset]');if(b)ctx.route(hex(base+BigInt(b.dataset.offset)),'memory');};
 }
 function modelColors(){const data=raw(packet.data_hex),valid=raw(packet.valid_hex),base=address(packet.address),nonzero=new Map(colors.groups.map(g=>[g,data.slice(g.start,g.end).some(Boolean)]));for(let i=0;i<colors.cells.length;i++){const c=colors.cells[i],s=model.bytes.get(String(base+BigInt(i))),factor=s?.born===null||s?.born===undefined?1:Math.min(1,.18+(model.seq-s.born)*.14);c.alpha=valid[i]&&nonzero.get(c.group)?config.opacity/100*factor:0;c.color=`hsla(${c.hue.toFixed(1)},68%,${c.light}%,${c.alpha.toFixed(3)})`;}return colors;}
 async function render(context){
  stash();ctx=context;if(packet&&packet.pid!==ctx.pid)reset();const token=generation;
  if(ctx.address){try{const external=/^\d+$/.test(String(ctx.address))?hex(BigInt(ctx.address)):hex(address(ctx.address));if(external!==config.address)config.address=external;}catch{}}
  ctx.root.innerHTML=`<section id="wv-panel"><div class="card wv-title"><h2>메모리 Wide View <span class="chip">Beta</span></h2><p>주변 바이트와 변화 패턴을 한눈에 봅니다. 순수 0 구간은 투명하며, 색상은 구조체 범위·문자열 후보·숫자 후보·관측 변화에 따라 묶입니다.</p><div class="wv-controls"><label>주소 (HEX)<input id="wv-address" aria-label="Wide View 주소" value="${esc(config.address)}" placeholder="0x15FEE0"></label><button id="wv-open" ${ctx.pid?'':'disabled'}>열기</button><label>불투명도 <output id="wv-opacity-value">${config.opacity}%</output><input id="wv-opacity" aria-label="색상 불투명도" type="range" min="0" max="100" value="${config.opacity}"></label><label>행 너비<select id="wv-columns">${[16,32,64].map(n=>`<option ${n===config.columns?'selected':''}>${n}</option>`).join('')}</select></label><label>간격 (ms)<input id="wv-interval" type="number" min="50" max="5000" value="${config.interval}"></label><label class="wv-check"><input id="wv-live" type="checkbox" ${config.live?'checked':''}>실시간</label><button id="wv-refresh" class="secondary">지금 읽기</button></div><div class="wv-controls"><label>구조체 범위<select id="wv-schema"><option value="">자동 후보 / 관측</option></select></label><label>구조체 시작 주소<input id="wv-schema-address" value="${esc(config.schemaAddress)}" placeholder="선택 주소를 기준으로"></label><button id="wv-schema-apply" class="secondary">범위 적용</button><button id="wv-editor" class="secondary">선택 주소 편집</button><button id="wv-structure" class="secondary">구조체로 열기</button></div><div id="wv-error" class="error" role="alert"></div></div><div class="card wv-map-card"><div class="card-head"><h2>프로세스 전체 메모리 미니맵</h2><div><button id="wv-map-prev" class="secondary small">이전</button> <button id="wv-map-next" class="secondary small">다음</button> <button id="wv-map-current" class="secondary small">현재 영역</button> <button id="wv-map-refresh" class="secondary small">맵 갱신</button></div></div><div class="wv-legend"><span style="--c:#6bbf98">Private</span><span style="--c:#b994f5">Image</span><span style="--c:#698bec">실행 가능</span><span style="--c:#e8b45d">Mapped</span><span style="--c:#4f5969">읽기 불가</span><span style="--c:#e77572">Guard</span><span class="wv-marker">현재 위치</span></div><div id="wv-map"></div><p id="wv-map-caption" class="subtle">주소를 열면 커널 메모리 맵을 표시합니다.</p><p id="wv-location" class="mono"></p></div><div class="card wv-view-card"><div class="card-head"><h2>주변 HEX · 실시간 색상</h2><span class="subtle">휠: 주소 탐색 · 더블클릭: 에디터</span></div><div id="wv-hex" tabindex="0" aria-label="Wide View 실시간 바이트"><div id="wv-bytes"></div></div><div class="wv-key"><span>0: 투명</span><span>새 비영(非零) 값: 옅게 등장</span><span>유사 값: 가까운 색</span><span>동시 변화: 같은 묶음</span><span>비선형 변화: 진한 색</span></div><pre id="wv-inspector"></pre><p id="wv-status" class="subtle"></p></div></section>`;
  q('#wv-open').onclick=()=>{config.origin=q('#wv-address').value;go(q('#wv-address').value);ctx.onAddress(config.address);};q('#wv-address').onkeydown=e=>{if(e.key==='Enter')q('#wv-open').click();};
  q('#wv-opacity').oninput=e=>{config.opacity=Number(e.target.value);q('#wv-opacity-value').textContent=config.opacity+'%';if(colors){modelColors();drawBytes();}};
  q('#wv-columns').onchange=e=>{config.columns=Number(e.target.value);if(packet)go(config.address);};q('#wv-interval').onchange=e=>{config.interval=Math.max(50,Math.min(5000,Number(e.target.value)||150));e.target.value=config.interval;schedule();};q('#wv-live').onchange=e=>{config.live=e.target.checked;schedule();};q('#wv-refresh').onclick=()=>go(config.address||q('#wv-address').value);
  q('#wv-schema-apply').onclick=()=>{config.schema=q('#wv-schema').value;try{config.schemaAddress=q('#wv-schema-address').value?hex(address(q('#wv-schema-address').value)):config.address;q('#wv-schema-address').value=config.schemaAddress;go(config.address);}catch(e){error(e.message);}};
  q('#wv-editor').onclick=()=>{if(selected||config.address)ctx.route(selected||config.address,'memory');};q('#wv-structure').onclick=()=>{if(selected||config.address)ctx.route(selected||config.address,'structures');};
  q('#wv-map-prev').onclick=()=>{--mapPage;drawMap();drawCurrent();};q('#wv-map-next').onclick=()=>{++mapPage;drawMap();drawCurrent();};q('#wv-map-current').onclick=()=>{const target=address(selected||config.address),i=regions.findIndex(r=>BigInt(r.address)<=target&&BigInt(r.address)+BigInt(r.size)>target);if(i>=0)mapPage=Math.floor(i/MAP_PAGE);drawMap();drawCurrent();};q('#wv-map-refresh').onclick=()=>{if(packet){mapQueued=true;pump();}else go(q('#wv-address').value);};
  q('#wv-hex').addEventListener('wheel',e=>{if(!packet||e.ctrlKey)return;e.preventDefault();if(e.shiftKey){q('#wv-hex').scrollLeft+=e.deltaY;return;}const rows=e.deltaMode===1?e.deltaY:e.deltaMode===2?e.deltaY*count()/config.columns:e.deltaY/ROW,step=BigInt(Math.max(1,Math.round(Math.abs(rows))))*BigInt(config.columns),target=address(config.address)+(e.deltaY<0?-step:step),clamped=target<1n?1n:target>=LIMIT?LIMIT-1n:target;go(hex(clamped));},{passive:false});
  q('#wv-hex').onkeydown=e=>{if(packet&&['ArrowUp','ArrowDown','PageUp','PageDown'].includes(e.key)){e.preventDefault();const delta=BigInt(e.key.startsWith('Page')?count():config.columns),target=address(config.address)+(e.key.endsWith('Up')?-delta:delta);go(hex(target<1n?1n:target>=LIMIT?LIMIT-1n:target));}};
  if(packet){drawMap();drawBytes();drawCurrent();}if(config.address&&ctx.pid)go(config.address);
  try{const result=await ctx.api('/api/studio/suite/schemas',{});if(token!==generation||!active())return;schemas=[...new Map([...(result.definitions||[]),...(window.ProductivitySuite?.exportState()?.definitions||[])].map(s=>[s.name,s])).values()];q('#wv-schema').innerHTML='<option value="">자동 후보 / 관측</option>'+schemas.map(s=>`<option value="${esc(s.name)}">${esc(s.name)}</option>`).join('');q('#wv-schema').value=config.schema;}catch(e){if(token===generation&&active())error(e.message);}
 }
 document.addEventListener('visibilitychange',()=>{if(document.hidden)clearTimeout(timer);else schedule();});
 window.addEventListener('pagehide',()=>{if(packet)fetch('/api/studio/wide-views/'+packet.id,{method:'DELETE',keepalive:true}).catch(()=>{});});
 window.WideMemory={render,reset,stash,refresh:()=>go(config.address||q('#wv-address')?.value||''),Model,exportState:()=>({...config}),importState:value=>{reset();config={...config,...value,opacity:Math.max(0,Math.min(100,Number(value.opacity??50))),columns:[16,32,64].includes(value.columns)?value.columns:32,interval:Math.max(50,Math.min(5000,Number(value.interval)||150)),live:false};}};
})();
