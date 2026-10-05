/* Kernel byte presentations, with optional instruction edit/navigation callbacks. */
(() => {
 'use strict';
 const esc=v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
 const colors={true:'#229f79',false:'#e56d83',jump:'#7e9bed',fallthrough:'#8492ad',back:'#ba91f5'};
 function layout(graph){
  const nodes=(graph?.nodes||[]).map(n=>({...n,width:430,height:66+Math.min(n.instructions.length,14)*19+(n.instructions.length>14?22:0)}));
  const byId=new Map(nodes.map(n=>[n.id,n]));
  const edges=(graph?.edges||[]).filter(e=>byId.has(e.source)&&byId.has(e.target)).map(e=>({...e}));
  const forward=edges.filter(e=>!e.layout_back);
  const rank=new Map(nodes.map(n=>[n.id,0])),incoming=new Map(nodes.map(n=>[n.id,0]));
  for(const e of forward)incoming.set(e.target,incoming.get(e.target)+1);
  const pending=nodes.filter(n=>!incoming.get(n.id)).map(n=>n.id);
  while(pending.length){const id=pending.shift();for(const e of forward.filter(e=>e.source===id)){
   rank.set(e.target,Math.max(rank.get(e.target),rank.get(id)+1));incoming.set(e.target,incoming.get(e.target)-1);
   if(!incoming.get(e.target))pending.push(e.target);
  }}
  const layers=[];
  for(const n of nodes){const r=rank.get(n.id);(layers[r]||= []).push(n);}
  // Alternate barycentre sweeps keep corresponding branches close together.
  const position=id=>{const layer=layers[rank.get(id)];return layer.findIndex(n=>n.id===id)-(layer.length-1)/2;};
  for(let sweep=0;sweep<6;sweep++){
   const down=sweep%2===0,order=layers.map((_,i)=>i);if(!down)order.reverse();
   for(const r of order){const scores=new Map();for(const n of layers[r]){
    const neighbours=forward.filter(e=>down?e.target===n.id:e.source===n.id).map(e=>down?e.source:e.target);
    scores.set(n.id,neighbours.length?neighbours.reduce((s,id)=>s+position(id),0)/neighbours.length:position(n.id));
   }layers[r].sort((a,b)=>scores.get(a.id)-scores.get(b.id)||a.address.localeCompare(b.address));}
  }
  const loops=edges.filter(e=>e.layout_back).length;
  const gutter=36+loops*18,largest=Math.max(1,...layers.map(l=>l.length)),width=gutter+largest*470+36;
  let y=34;
  for(const layer of layers){const total=layer.length*430+(layer.length-1)*40,base=gutter+(width-gutter-total)/2;
   layer.forEach((n,i)=>{n.x=base+i*470;n.y=y;n.rank=rank.get(n.id);});y+=Math.max(0,...layer.map(n=>n.height))+92;
  }
  let loopIndex=0;
  for(const e of edges){const a=byId.get(e.source),b=byId.get(e.target);
   const siblings=edges.filter(x=>x.source===e.source&&!x.layout_back),i=siblings.indexOf(e);
   const sx=a.x+a.width/2+(i-(siblings.length-1)/2)*30,sy=a.y+a.height,tx=b.x+b.width/2,ty=b.y;
   if(e.layout_back){const x=20+(loopIndex++)*18;
    e.path=`M ${a.x} ${a.y+a.height/2} C ${x} ${a.y+a.height/2}, ${x} ${a.y+a.height/2}, ${x} ${a.y+a.height/2-24} L ${x} ${b.y+24} C ${x} ${b.y+10}, ${x} ${b.y+10}, ${b.x} ${b.y+24}`;
    e.labelX=x+7;e.labelY=(a.y+b.y+a.height/2)/2;
   }else{
    const mid=sy+Math.max(28,(ty-sy)/2);e.path=`M ${sx} ${sy} C ${sx} ${mid}, ${tx} ${mid}, ${tx} ${ty}`;
    e.labelX=sx+8;e.labelY=sy+25;
   }
   e.color=e.layout_back?colors.back:colors[e.kind]||colors.jump;
   e.label=e.layout_back?'반복':e.kind==='true'?'참':e.kind==='false'?'거짓':'';
  }
  return {nodes,edges,width,height:Math.max(180,y-42)};
 }
 function svgMarkup(result,name){
  const {nodes,edges,width,height}=result;
  const markerKeys=Object.keys(colors);
  return `<svg xmlns="http://www.w3.org/2000/svg" class="fv-svg" viewBox="0 0 ${width} ${height}" role="img" aria-label="${esc(name)} 제어 흐름 그래프"><title>${esc(name)} · 기본 블록 제어 흐름</title><defs>${markerKeys.map(key=>`<marker id="fv-arrow-${key}" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M 0 0 L 10 5 L 0 10 z" fill="${colors[key]}"/></marker>`).join('')}</defs><rect width="${width}" height="${height}" fill="#101723"/>${edges.map(e=>`<g class="fv-edge"><path d="${e.path}" fill="none" stroke="${e.color}" stroke-width="2" marker-end="url(#fv-arrow-${e.layout_back?'back':e.kind})"/><text x="${e.labelX}" y="${e.labelY}" fill="${e.color}" font-size="12" font-family="system-ui">${e.label}</text></g>`).join('')}${nodes.map(n=>`<g class="fv-node ${n.external?'fv-external':''}" data-node="${esc(n.id)}" tabindex="0" role="button" aria-label="${esc(n.label)} 블록 상세"><rect x="${n.x}" y="${n.y}" width="${n.width}" height="${n.height}" rx="9" fill="${n.external?'#241e2d':'#1b2639'}" stroke="${n.external?'#ac87cb':'#425b7f'}" stroke-width="1.5" ${n.external?'stroke-dasharray="5 4"':''}/><text x="${n.x+15}" y="${n.y+25}" fill="#e3edf9" font-size="13" font-family="system-ui" font-weight="650">${esc(n.label)}</text><text x="${n.x+15}" y="${n.y+46}" fill="#8aa6c9" font-size="11" font-family="system-ui">${n.external?'미해결 제어 이전':`${n.instructions.length}개 명령 · ${esc(n.address)}`}</text>${n.instructions.slice(0,14).map((ins,i)=>`<text x="${n.x+15}" y="${n.y+68+i*19}" fill="${['ret','jmp'].includes(ins.instruction)?'#baa1ef':'#c7d4e8'}" font-size="12" font-family="Consolas,monospace">${esc((ins.address.replace(/^0x/,'')+'  '+ins.instruction+' '+ins.operands).slice(0,54))}</text>`).join('')}${n.instructions.length>14?`<text x="${n.x+15}" y="${n.y+n.height-13}" fill="#83b8e5" font-size="12" font-family="system-ui">+ ${n.instructions.length-14}개 · 클릭하면 전체 명령 표시</text>`:''}</g>`).join('')}</svg>`;
 }
 function highlight(code){
  const pattern=/(\/\*[\s\S]*?\*\/|\/\/[^\n]*|"(?:\\.|[^"\\])*"|\b(?:if|else|while|return|goto|break|continue|void|uint\d+_t|int\d+_t|vec\d+_t|call_state)\b|\b(?:0x[0-9A-Fa-f]+|\d+)\b)/g;
  let end=0,result='';for(const match of code.matchAll(pattern)){
   result+=esc(code.slice(end,match.index));const token=match[0];
   const cls=token.startsWith('/')?'comment':token.startsWith('"')?'string':/^\d/.test(token)?'number':'keyword';
   result+=`<span class="fv-${cls}">${esc(token)}</span>`;end=match.index+token.length;
  }return result+esc(code.slice(end));
 }
 function mount(host,detail,options={}){
  host.ondblclick=null;host.onkeydown=null;
  const graph=detail.graph,pseudo=detail.pseudocode,name=detail.function?.name||'함수';
  const rendered=layout(graph),svg=svgMarkup(rendered,name);
  const fileStem=name.replace(/[^a-zA-Z0-9_\-]/g,'_').slice(0,80)||'function';
  const save=(data,filename,type)=>options.download?.(data,filename,type);
  let view=['asm','graph','pseudo'].includes(options.initialView)?options.initialView:'asm',scale=1,panX=0,panY=0;
  host.innerHTML=`<section class="fv-workspace"><div class="fv-heading"><div><h3>메모리의 명령어 · Capstone</h3><p>${esc(name)} · ${detail.bits||'?'}비트 · 커널 메모리 ${detail.read_bytes||0}바이트</p></div><span class="fv-badge">${detail.instruction_count??detail.results?.length??0}개 명령</span></div><div class="fv-tabs" role="tablist" aria-label="함수 분석 보기">${[['asm','어셈블리'],['graph','흐름 그래프'],['pseudo','C 의사코드']].map(([key,label])=>`<button class="secondary" type="button" role="tab" id="fv-tab-${key}" aria-controls="fv-panel-${key}" data-view="${key}">${label}</button>`).join('')}</div><div class="fv-source">${esc(detail.argument_hint||'')} · ${esc(detail.note||'')}</div>
   <div id="fv-panel-asm" role="tabpanel" aria-labelledby="fv-tab-asm"><div class="fv-tools"><span>도달 가능한 분기 경로를 포함합니다.</span><button class="secondary small" data-save="asm">ASM 저장</button></div><pre class="fv-asm">${esc((detail.results||[]).map(i=>`${i.address}  ${i.bytes.padEnd(26)}  ${i.instruction} ${i.operands}`).join('\n'))}</pre></div>
   <div id="fv-panel-graph" role="tabpanel" aria-labelledby="fv-tab-graph"><div class="fv-tools"><span>${graph?.block_count||0}개 기본 블록 · 미해결 ${graph?.unresolved_count||0}개</span><div class="fv-controls"><button class="secondary small" data-zoom="out" aria-label="그래프 축소">−</button><span class="fv-scale"></span><button class="secondary small" data-zoom="in" aria-label="그래프 확대">+</button><button class="secondary small" data-zoom="fit">화면 맞춤</button><button class="secondary small" data-zoom="actual">100%</button><button class="secondary small" data-save="svg">SVG 저장</button></div></div><div class="fv-legend"><span class="fv-true">● 참</span><span class="fv-false">● 거짓</span><span class="fv-loop">● 반복</span><span>드래그 이동 · 휠 확대 · 노드 클릭으로 상세</span></div><div class="fv-graph-stage" tabindex="0" aria-label="흐름 그래프 캔버스"><div class="fv-graph-transform">${svg}</div>${rendered.nodes.length?'':'<div class="fv-empty">해석 가능한 기본 블록이 없습니다.</div>'}</div><p class="fv-warning">${esc((graph?.notes||[]).join(' · '))}</p><div class="fv-block-detail"><p>노드를 선택하면 블록 전체 명령이 표시됩니다.</p></div></div>
   <div id="fv-panel-pseudo" role="tabpanel" aria-labelledby="fv-tab-pseudo"><div class="fv-tools"><span>${pseudo?.style==='structured'?'조건문 / 반복문 구조화':'복잡한 경로는 라벨 / goto로 보존'} · 미변환 ${pseudo?.unsupported?.length||0}개</span><div class="fv-controls"><button class="secondary small" data-copy="pseudo">의사코드 복사</button><button class="secondary small" data-save="pseudo">C 형태 저장</button></div></div><p class="fv-warning">${esc(pseudo?.note||'의사코드 분석이 없습니다.')}</p>${pseudo?.pdb_signature?`<p class="fv-source">PDB 선언: <code>${esc(pseudo.pdb_signature)}</code></p>`:''}<pre class="fv-code"><code>${highlight(pseudo?.code||'')}</code></pre><details class="fv-variables"><summary>변수 대응표 · ${pseudo?.variables?.length||0}개</summary><div class="table-wrap"><table><thead><tr><th>변수</th><th>표현 형식</th><th>레지스터 / 스택 / 임시값</th></tr></thead><tbody>${(pseudo?.variables||[]).map(v=>`<tr><td class="mono">${esc(v.name)}</td><td class="mono">${esc(v.type)}</td><td>${esc(v.storage)}</td></tr>`).join('')}</tbody></table></div></details>${pseudo?.unsupported?.length?`<details class="fv-unsupported"><summary>미변환 명령 · ${pseudo.unsupported.length}개</summary><pre>${esc(pseudo.unsupported.map(i=>`${i.address}  ${i.instruction} ${i.operands}`).join('\n'))}</pre></details>`:''}</div><div class="fv-bottom"><span role="status" class="fv-status"></span><button class="secondary small" data-save="json">전체 분석 JSON 저장</button></div></section>`;
  const stage=host.querySelector('.fv-graph-stage'),transform=host.querySelector('.fv-graph-transform');
  const rows=new Map((detail.results||[]).map(i=>[i.address,i]));
  const interactive=!!(options.onEdit||options.onNavigate);
  const lineMarkup=i=>`<span class="fv-ins ${options.drafts?.has(i.address)?'fv-pending':''}" data-ins-address="${esc(i.address)}" tabindex="${interactive?'0':'-1'}"><span class="fv-ins-address" data-literal-address="${esc(i.address)}">${esc(i.address)}</span><span class="fv-ins-bytes">${esc(i.bytes)}</span><span class="fv-ins-code">${esc(options.drafts?.get(i.address)?.assembly||i.instruction+' '+i.operands)}</span>${interactive?(i.references||[]).map((r,n)=>`<span class="fv-reference" data-reference="${n}" title="Ctrl+더블클릭: ${esc(r.kind)}">↗ ${esc(r.address)}</span>`).join(''):''}</span>`;
  if(interactive){
   host.querySelector('.fv-asm').innerHTML=(detail.results||[]).map(lineMarkup).join('');
   host.querySelector('.fv-workspace').classList.add('fv-interactive');
   for(const node of rendered.nodes){
    const element=Array.from(host.querySelectorAll('.fv-node')).find(n=>n.dataset.node===node.id);
    const lines=Array.from(element.querySelectorAll('text')).slice(2,2+Math.min(node.instructions.length,14));
    lines.forEach((line,n)=>{const row=node.instructions[n],draft=options.drafts?.get(row.address);line.dataset.insAddress=row.address;line.classList.add('fv-graph-ins');
     if(draft){line.textContent=(row.address.replace(/^0x/,'')+'  '+draft.assembly).slice(0,54);line.classList.add('fv-pending');}
     const title=document.createElementNS('http://www.w3.org/2000/svg','title');title.textContent=`${row.address}  ${row.instruction} ${row.operands}\n더블클릭: 편집 · Ctrl+더블클릭: 참조 이동`;line.append(title);
    });
   }
   host.ondblclick=e=>{const element=e.target.closest('[data-ins-address]'),row=rows.get(element?.dataset.insAddress);
    if(row){e.preventDefault();e.stopPropagation();
     if(e.ctrlKey){const literal=e.target.closest('[data-literal-address]');if(literal)options.onNavigate?.({address:literal.dataset.literalAddress,raw:true});
      else options.onNavigate?.({instruction:row,reference:e.target.closest('[data-reference]')?.dataset.reference});}
     else options.onEdit?.(row);return;
    }
    const node=e.target.closest('[data-node]');if(e.ctrlKey&&node){e.preventDefault();options.onNavigate?.({address:node.dataset.node,raw:true});}
   };
   host.onkeydown=e=>{const row=rows.get(e.target.closest('[data-ins-address]')?.dataset.insAddress);if(row&&e.key==='Enter'){e.preventDefault();if(e.ctrlKey)options.onNavigate?.({instruction:row});else options.onEdit?.(row);}};
  }
  transform.style.width=rendered.width+'px';transform.style.height=rendered.height+'px';
  const clamp=s=>Math.max(.15,Math.min(2.5,s));
  function update(){transform.style.transform=`translate(${panX}px, ${panY}px) scale(${scale})`;host.querySelector('.fv-scale').textContent=Math.round(scale*100)+'%';}
  function fit(){if(!stage.clientWidth)return;scale=clamp(Math.min((stage.clientWidth-30)/rendered.width,(stage.clientHeight-30)/rendered.height,1));panX=(stage.clientWidth-rendered.width*scale)/2;panY=Math.max(15,(stage.clientHeight-rendered.height*scale)/2);update();}
  function zoom(next,x=stage.clientWidth/2,y=stage.clientHeight/2){next=clamp(next);panX=x-(x-panX)*next/scale;panY=y-(y-panY)*next/scale;scale=next;update();}
  function show(next){view=next;for(const key of ['asm','graph','pseudo']){
   host.querySelector('#fv-panel-'+key).hidden=key!==view;const tab=host.querySelector('#fv-tab-'+key);tab.setAttribute('aria-selected',String(key===view));tab.tabIndex=key===view?0:-1;
  }options.onView?.(view);if(view==='graph'&&!stage.dataset.fitted){fit();stage.dataset.fitted='1';}}
  for(const b of host.querySelectorAll('[data-view]')){b.onclick=()=>show(b.dataset.view);b.onkeydown=e=>{
   const keys=['asm','graph','pseudo'];if(!['ArrowLeft','ArrowRight','Home','End'].includes(e.key))return;e.preventDefault();
   const index=e.key==='Home'?0:e.key==='End'?2:(keys.indexOf(view)+(e.key==='ArrowRight'?1:2))%3;show(keys[index]);host.querySelector('#fv-tab-'+keys[index]).focus();
  };}
  for(const b of host.querySelectorAll('[data-zoom]'))b.onclick=()=>{if(b.dataset.zoom==='fit')fit();else if(b.dataset.zoom==='actual')zoom(1);else zoom(scale*(b.dataset.zoom==='in'?1.25:.8));};
  let drag=null,suppressClick=false;
  stage.onpointerdown=e=>{if(e.button!==0)return;suppressClick=false;drag={id:e.pointerId,x:e.clientX,y:e.clientY,panX,panY,moved:false,captured:false};};
  stage.onpointermove=e=>{if(!drag||drag.id!==e.pointerId)return;const dx=e.clientX-drag.x,dy=e.clientY-drag.y;drag.moved ||=Math.abs(dx)+Math.abs(dy)>5;if(drag.moved){if(!drag.captured){stage.setPointerCapture?.(e.pointerId);drag.captured=true;}panX=drag.panX+dx;panY=drag.panY+dy;update();stage.classList.add('fv-dragging');}};
  stage.onpointerup=e=>{if(!drag)return;suppressClick=drag.moved;if(drag.captured)stage.releasePointerCapture?.(e.pointerId);drag=null;stage.classList.remove('fv-dragging');};stage.onpointercancel=()=>{drag=null;suppressClick=false;stage.classList.remove('fv-dragging');};
  stage.addEventListener('click',e=>{if(suppressClick){suppressClick=false;e.stopPropagation();}},{capture:true});
  stage.addEventListener('wheel',e=>{e.preventDefault();const rect=stage.getBoundingClientRect();zoom(scale*Math.exp(-e.deltaY*.0015),e.clientX-rect.left,e.clientY-rect.top);},{passive:false});
  function selectNode(element){for(const n of host.querySelectorAll('.fv-node'))n.classList.toggle('fv-node-selected',n===element);
   const node=rendered.nodes.find(n=>n.id===element.dataset.node);host.querySelector('.fv-block-detail').innerHTML=`<h4>${esc(node.label)} · ${node.instructions.length}개 명령</h4>${node.external?'<p class="fv-warning">이 제어 이전의 목적지 코드는 확인되지 않았습니다.</p>':`<pre>${interactive?node.instructions.map(lineMarkup).join(''):esc(node.instructions.map(i=>`${i.address}  ${i.instruction} ${i.operands}`).join('\n'))}</pre>`}`;
  }
  for(const n of host.querySelectorAll('.fv-node')){n.onclick=()=>selectNode(n);n.onkeydown=e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();selectNode(n);}};}
  for(const b of host.querySelectorAll('[data-save]'))b.onclick=()=>{
   if(b.dataset.save==='svg')save(svg,fileStem+'-graph.svg','image/svg+xml');
   else if(b.dataset.save==='pseudo')save(pseudo?.code||'',fileStem+'-pseudo.c','text/plain;charset=utf-8');
   else if(b.dataset.save==='asm')save((detail.results||[]).map(i=>`${i.address}  ${i.bytes}  ${i.instruction} ${i.operands}`).join('\n'),fileStem+'.asm','text/plain;charset=utf-8');
   else save(JSON.stringify(detail,null,2),fileStem+'-analysis.json','application/json');
  };
  host.querySelector('[data-copy]').onclick=async()=>{const status=host.querySelector('.fv-status');try{await navigator.clipboard.writeText(pseudo?.code||'');status.textContent='의사코드를 복사했습니다.';}catch{status.textContent='복사 권한이 없습니다. C 형태 저장을 사용하세요.';}};
  show(view);update();
 }
 window.FunctionViews={mount,layout};
})();
