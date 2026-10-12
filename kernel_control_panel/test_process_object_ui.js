'use strict';
// Execute the actual browser state handlers against a fake DOM and deferred API.
const assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
const source=fs.readFileSync(process.argv[2],'utf8');
const pending=[],elements=new Map();
const state={pid:0,name:'',address:'',tid:'',busy:false,forms:{},results:{},lastId:'',processObject:{address:'',identity:'',error:'',loading:false}};
const context={state,window:{},console,clearVisits(){},persist(){},toast(){},render(){},
 esc:value=>String(value??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])),
 $:selector=>{if(!elements.has(selector))elements.set(selector,{innerHTML:'',value:'',close(){}});return elements.get(selector);},
 api:(path,body)=>new Promise((resolve,reject)=>pending.push({path,body,resolve,reject}))};
vm.createContext(context);
const begin=source.indexOf('function clearProcessObject('),end=source.indexOf('function pageInfo(',begin);
assert(begin>=0 && end>begin);
vm.runInContext('let targetRevision=0,processObjectRequest=0;\n'+source.slice(begin,end),context);
const address='0xFFFFA123456789AB',key='18446744073709551614';
const reply=(pid,extra={})=>({success:true,process_id:pid,eprocess_address:address,process_start_key:key,...extra});
const flush=()=>new Promise(resolve=>setImmediate(resolve));
(async()=>{
 context.selectTarget(42,'first.exe',key);
 assert.equal(pending[0].path,'/api/studio/execute');
 assert.equal(pending[0].body.operation,'process_object');
 assert.equal(pending[0].body.args.pid,42);
 pending.shift().resolve(reply(42));await flush();
 assert.equal(state.processObject.address,address);
 assert(elements.get('#target-summary').innerHTML.includes(address));
 // A late response from the previous target cannot overwrite the active PID.
 context.selectTarget(84,'second.exe',key);const old=pending.shift();
 assert.equal(state.processObject.address,'');
 assert(!elements.get('#target-summary').innerHTML.includes(address));
 context.selectTarget(126,'third.exe',key);const current=pending.shift();
 old.resolve(reply(84,{eprocess_address:'0xFFFFB00000000001'}));await flush();
 assert.equal(state.processObject.address,'');
 current.resolve(reply(126));await flush();assert.equal(state.processObject.address,address);
 // Same-PID reselection also invalidates the previous generation.
 context.selectTarget(126,'third.exe',key);const reused=pending.shift();
 context.selectTarget(126,'replacement.exe','99');const replacement=pending.shift();
 reused.resolve(reply(126));await flush();assert.equal(state.processObject.address,'');
 replacement.resolve(reply(126,{process_start_key:'99'}));await flush();assert.equal(state.processObject.identity,'99');
 // A manual retry shares the selected PID and unsupported responses expose no address.
 const retry=context.refreshProcessObject();const unsupported=pending.shift();
 assert.equal(unsupported.body.args.pid,126);
 unsupported.resolve({success:false,error:'현재 드라이버 미지원 · 20261010 필요'});await retry;
 assert.equal(state.processObject.address,'');assert(state.processObject.error.includes('미지원'));
 // A PID reused during the query is rejected even if the numeric PID is unchanged.
 const changed=context.refreshProcessObject();pending.shift().resolve(reply(126));await changed;
 assert.equal(state.processObject.address,'');assert(state.processObject.error.includes('교체'));
 // Numeric/zero addresses never become fabricated kernel addresses.
 for(const bad of [18446744073709551600,'0x0000000000000000']){
  const run=context.refreshProcessObject();pending.shift().resolve(reply(126,{eprocess_address:bad,process_start_key:'99'}));await run;
  assert.equal(state.processObject.address,'');
 }
 const beforeDetach=context.refreshProcessObject();const late=pending.shift();context.selectTarget(0,'');
 late.resolve(reply(126,{process_start_key:'99'}));await beforeDetach;
 assert.equal(state.pid,0);assert.equal(state.processObject.address,'');
 assert.equal(elements.get('#target-summary').innerHTML,'선택된 프로세스 없음');
 assert.equal(pending.length,0);
 context.selectTarget(42,'zero-key.exe','0');pending.shift().resolve(reply(42,{process_start_key:'0'}));await flush();
 assert.equal(state.processObject.address,address);assert.equal(state.processObject.identity,'0');
 // Generic form sends the current selected PID without a user-entered PID field.
 const formStart=source.indexOf('function formArgs('),formEnd=source.indexOf('\n',formStart);
 context.TOOLS={process_object:{fields:[]}};context.currentOperation=()=> 'process_object';state.pid=84;
 vm.runInContext(source.slice(formStart,formEnd),context);
 assert.equal(context.formArgs().pid,84);
 assert(source.includes("clearProcessObject();applyAddress(b.address)"));
 // Global refresh routes dedicated EPROCESS pages before generic tools.
 let refreshed=0;context.window.EprocessWorkbench={reset(){},targetChanged(){},refresh(){refreshed++;}};state.page='eprocess';
 const refreshStart=source.indexOf("$('#refresh-page').onclick="),refreshEnd=source.indexOf('\n',refreshStart);
 vm.runInContext(source.slice(refreshStart,refreshEnd),context);elements.get('#refresh-page').onclick();assert.equal(refreshed,1);
 // Process confirmation uses the server's decimal string, including a valid zero key.
 context.processControls=()=>{};context.renderProcesses=()=>{};context.processSelectionFailure=message=>{throw Error(message);};
 const identifyStart=source.indexOf('async function identifyProcess('),identifyEnd=source.indexOf("\n$('#choose-process')",identifyStart);
 vm.runInContext('let processRequestId=0,processSelectionBusy=false,processSelectionError="";\n'+source.slice(identifyStart,identifyEnd),context);
 for(const [identity,basicKey,expected] of [[{process_start_key:key},18446744073709551600,key],[{process_start_key:'0'},0,'0'],[undefined,0,'0']]){
  elements.get('#process-dialog').open=true;const identified=context.identifyProcess(42);assert.equal(pending[0].path,'/api/process/42');
  pending.shift().resolve({basic:{success:true,process_id:42,exit_status:259,process_start_key:basicKey},extended:{success:true,exit_status:259,image_file_name:'selected.exe'},identity});
  await identified;assert.equal(state.processObject.identity,expected);pending.shift().resolve(reply(42,{process_start_key:expected}));await flush();assert.equal(state.processObject.address,address);
 }
 console.log('EPROCESS browser checks passed');
})().catch(error=>{console.error(error);process.exitCode=1;});
