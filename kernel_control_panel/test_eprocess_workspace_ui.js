'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
const source=fs.readFileSync(process.argv[2],'utf8'),ADDRESS='0xFFFFA123456789AB',KEY='18446744073709551614';
const flush=async()=>{await Promise.resolve();await Promise.resolve();};
function harness(){
 const pending=[],timers=new Map(),events={},nodes=new Map();let clock=0,nextTimer=0,page='eprocess',pid=42,isConnected=true;
 const object={address:ADDRESS,identity:KEY};
 class Element{
  constructor(){this.textContent='';this.title='';this.writes=0;this.rows=[];this.open=false;this.classes=new Set();this.classList={toggle:(name,on)=>on?this.classes.add(name):this.classes.delete(name)};this.parentElement=null;}
  set innerHTML(value){this.html=value;this.writes++;this.rows=[];for(const m of value.matchAll(/data-ep-index="(\d+)"/g)){const row=new Element();row.dataset={epIndex:m[1]};row.value=new Element();row.raw=new Element();row.querySelector=s=>s==='[data-ep-value]'?row.value:row.raw;this.rows.push(row);}}
  get innerHTML(){return this.html || '';}
  querySelectorAll(selector){return selector==='[data-ep-index]'?this.rows:[];}
  addEventListener(name,fn){this[name]=fn;}
 }
 const root=new Element();root.querySelector=selector=>nodes.get(selector.slice(1)) || null;
 Object.defineProperty(root,'innerHTML',{set(value){this.html=value;this.writes++;nodes.clear();for(const match of value.matchAll(/id="([^"]+)"/g))nodes.set(match[1],new Element());},get(){return this.html;}});
 const document={hidden:false,addEventListener:(name,fn)=>{events[name]=fn;}};
 const sandbox={window:{},document,console,Date,performance:{now:()=>clock},
  setTimeout:(fn,delay)=>{const id=++nextTimer;timers.set(id,{fn,delay});return id;},clearTimeout:id=>timers.delete(id)};
 vm.createContext(sandbox);vm.runInContext(source,sandbox);const api=sandbox.window.EprocessWorkbench;
 const context={root,pid:42,currentPid:()=>pid,currentPage:()=>page,connected:()=>isConnected,processObject:()=>object,
  refreshObject:async()=>{},api:(path,body)=>new Promise((resolve,reject)=>pending.push({path,body,resolve,reject}))};
 const preset={id:'windows-11-24h2',family:'Windows 11',release:'24H2',size:16,field_count:3,source_url:'https://example.test/preset'};
 const presets=match=>({success:true,system:{architecture:'x64',build:26100,ubr:1234,product_name:'Windows 10 Pro',product_type:1},match:match || {success:true,preset},presets:[{...preset,build_numbers:[26100]}]});
 const snapshot=(value='18446744073709551615',key=object.identity)=>({success:true,preset,process_id:pid,eprocess_address:object.address,process_start_key:key,size:16,bytes_read:16,sampled_at:'2026-10-09T15:34:22.123456+00:00',timing_ms:1,data_hex:'00112233445566778899aabbccddeeff',fields:[
  {path:'Pcb.Header.Type',name:'Type',type:'Uint8',offset:0,offset_hex:'0x0',size:1,kind:'scalar',value:'1',raw_hex:'01'},
  {path:'UniqueProcessId',name:'UniqueProcessId',type:'Uint8B',offset:8,offset_hex:'0x8',size:8,kind:'pointer',value,raw_hex:'ffffffffffffffff'},
  {path:'Flags.DeleteState',name:'DeleteState',type:'Uint4B',offset:4,offset_hex:'0x4',size:4,kind:'bitfield',bit_offset:2,bit_width:1,value:'0',raw_hex:'00000000'}]});
 const runTimer=()=>{assert.equal(timers.size,1,'only one timer can be pending');const [id,timer]=[...timers][0];timers.delete(id);clock+=timer.delay;timer.fn();return timer.delay;};
 return {api,context,pending,timers,events,nodes,document,object,preset,presets,snapshot,root,runTimer,advance:value=>clock+=value,setPage:value=>page=value,setPid:value=>pid=value,setConnected:value=>isConnected=value};
}
async function mounted(h,match){h.api.render(h.context);assert.equal(h.pending.length,1);assert.equal(h.pending[0].path,'/api/studio/eprocess/presets');h.pending.shift().resolve(h.presets(match));await flush();}
(async()=>{
 // Matching visible pages auto-start and use completion-based scheduling.
 const h=harness();await mounted(h);assert(h.api.status().monitoring);assert.equal(h.runTimer(),0);
 assert(h.nodes.get('ep-system').textContent.startsWith('Windows 11 · 24H2'));assert(h.nodes.get('ep-system').textContent.includes('26100.1234'));
 assert.equal(h.pending.length,1);assert.equal(h.timers.size,0);assert(h.api.status().busy);
 const first=h.pending.shift();assert.equal(first.path,'/api/studio/eprocess/snapshot');assert.equal(first.body.pid,42);assert.equal(first.body.expected_address,ADDRESS);assert.equal(first.body.expected_start_key,KEY);assert.equal(first.body._background,true);
 h.api.targetChanged();assert.equal(h.pending.length,0);assert.equal(h.timers.size,0,'no second request before the first completes');
 h.advance(3);first.resolve(h.snapshot());await flush();
 assert.equal(h.api.status().samples,1);assert.equal([...h.timers.values()][0].delay,7);
 assert(!h.nodes.get('ep-sampled').textContent.includes('Invalid Date'),'ISO8601 timestamps must display correctly');
 const fieldWrites=h.nodes.get('ep-fields').writes;assert(h.nodes.get('ep-fields').innerHTML.includes('ep-group'));
 assert(h.nodes.get('ep-fields').innerHTML.includes('bit 2:1'));
 assert.equal(h.nodes.get('ep-fields').rows.find(r=>r.dataset.epIndex==='1').value.textContent,'18446744073709551615');
 assert.equal(h.runTimer(),7);h.advance(15);h.pending.shift().resolve(h.snapshot('18446744073709551614'));await flush();
 assert.equal(h.api.status().samples,2);assert.equal(h.api.status().actualPeriod,10);assert.equal(h.api.status().changedCount,1);
 assert.equal([...h.timers.values()][0].delay,0,'slow reads do not queue missed ticks');
 assert.equal(h.nodes.get('ep-fields').writes,fieldWrites,'unchanged layouts must not rebuild the DOM');
 assert.equal(h.nodes.get('ep-fields').rows.find(r=>r.dataset.epIndex==='1').value.textContent,'18446744073709551614');
 h.nodes.get('ep-search').oninput({target:{value:'UniqueProcessId'}});assert.equal(h.nodes.get('ep-fields').rows.length,1);
 h.nodes.get('ep-raw-details').open=true;h.nodes.get('ep-raw-details').toggle();assert(h.nodes.get('ep-raw-data').textContent.includes('00 11 22 33'));
 // Hidden tabs stop in-flight publishing and resume without overlap.
 h.runTimer();const hidden=h.pending.shift();const sampleCount=h.api.status().samples;
 h.document.hidden=true;h.events.visibilitychange();assert(!h.api.status().monitoring);assert.equal(h.timers.size,0);
 h.document.hidden=false;h.events.visibilitychange();assert.equal(h.timers.size,0,'old native request still in flight');
 hidden.resolve(h.snapshot('7'));await flush();assert.equal(h.api.status().samples,sampleCount);assert.equal(h.timers.size,1);
 // Manual pause is respected across hidden/visible transitions.
 h.nodes.get('ep-monitor').onclick();assert(!h.api.status().monitoring);
 h.document.hidden=true;h.events.visibilitychange();h.document.hidden=false;h.events.visibilitychange();assert.equal(h.timers.size,0);
 h.api.refresh();assert.equal(h.pending.length,1);assert.equal(h.pending[0].body._background,false);h.api.refresh();assert.equal(h.pending.length,1,'global refresh also respects the in-flight request');
 h.pending.shift().resolve(h.snapshot());await flush();assert.equal(h.timers.size,0,'global refresh preserves manual pause');
 // No guessed latest preset or snapshot exists for an unmatched OS.
 const unmatched=harness();await mounted(unmatched,{success:false,reason:'빌드와 정확히 일치하는 프리셋 없음'});
 assert.equal(unmatched.timers.size,0);assert.equal(unmatched.pending.length,0);assert(unmatched.nodes.get('ep-status').textContent.includes('정확히'));
 // OS metadata arriving while hidden is retained so visible pages can start.
 const initialHidden=harness();initialHidden.api.render(initialHidden.context);initialHidden.document.hidden=true;initialHidden.events.visibilitychange();
 initialHidden.pending.shift().resolve(initialHidden.presets());await flush();assert.equal(initialHidden.timers.size,0);
 initialHidden.document.hidden=false;initialHidden.events.visibilitychange();assert.equal(initialHidden.timers.size,1);
 // A failed preset load has an explicit retry, and older GET results cannot overwrite it.
 const retry=harness();retry.api.render(retry.context);retry.pending.shift().reject(Error('목록 조회 실패'));await flush();assert.equal(retry.timers.size,0);
 retry.nodes.get('ep-preset-refresh').onclick();const older=retry.pending.shift();retry.nodes.get('ep-preset-refresh').onclick();const newer=retry.pending.shift();
 newer.resolve(retry.presets());await flush();assert.equal(retry.timers.size,1);
 older.reject(Error('늦은 실패'));await flush();assert(retry.api.status().monitoring);
 // Re-entering with the same context object still invalidates the previous page's GET.
 const reentry=harness();reentry.api.render(reentry.context);const departed=reentry.pending.shift();reentry.api.render(reentry.context);
 departed.reject(Error('이전 페이지 실패'));await flush();reentry.pending.shift().resolve(reentry.presets());await flush();assert.equal(reentry.timers.size,1);
 // Page leave, detach, disconnect and identity reuse each invalidate late output.
 for(const action of ['leave','detach','disconnect','identity']){
  const t=harness();await mounted(t);t.runTimer();const request=t.pending.shift();
  if(action==='leave'){t.setPage('home');t.api.dispose();}
  if(action==='detach'){t.setPid(0);t.api.reset();}
  if(action==='disconnect'){t.setConnected(false);t.api.connectionChanged();}
  if(action==='identity'){t.object.identity='99';t.api.targetChanged();}
  request.resolve(t.snapshot('123',KEY));await flush();assert.equal(t.api.status().samples,0,action);
  if(action!=='identity')assert.equal(t.timers.size,0,action);
  else {assert.equal(t.timers.size,1);t.runTimer();assert.equal(t.pending[0].body.expected_start_key,'99');}
 }
 // Request errors stop the loop, preserving a clear error until explicit retry.
 const error=harness();await mounted(error);error.runTimer();error.pending.shift().resolve({success:false,error:'현재 드라이버 미지원'});await flush();
 assert(!error.api.status().monitoring);assert.equal(error.timers.size,0);assert(error.nodes.get('ep-status').textContent.includes('미지원'));
 error.api.targetChanged();assert.equal(error.timers.size,0,'no automatic retry storm after failure');
 console.log('EPROCESS monitor checks passed');
})().catch(error=>{console.error(error);process.exitCode=1;});
