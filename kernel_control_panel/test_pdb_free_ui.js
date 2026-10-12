'use strict';
// Actual UI handlers with a fake DOM/API; no browser, process, or device access.
const assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm'),path=require('node:path');
function dom(){
 const elements=new Map(),added=[];
 const element=()=>({innerHTML:'',textContent:'',value:'',style:{},dataset:{},clientWidth:0,clientHeight:0,
   setAttribute(){},addEventListener(){},after(e){added.push(e);},classList:{add(){},remove(){},toggle(){}},
   querySelector:query,querySelectorAll(){return[];}});
 function query(s){if(!elements.has(s))elements.set(s,element());return elements.get(s);}
 return{root:element(),elements,added,element};
}
const panel=__dirname;
(async()=>{
 const d=dom(),clipboard=[];
 const context={window:{},document:{createElement:d.element},navigator:{clipboard:{async writeText(t){clipboard.push(t);}}}};
 vm.createContext(context);vm.runInContext(fs.readFileSync(path.join(panel,'static/function_views.js'),'utf8'),context);
 const detail={function:{name:'<unsafe-name>'},graph:{nodes:[],edges:[]},pseudocode:{code:'uint32_t fn(uint32_t a1) { return a1; }',
   style:'structured',unsupported:[],variables:[],semantic:{abi:'Windows x64',typed_calls:3,inferred_calls:2,unknown_calls:1,signature_inferred:true}}};
 context.window.FunctionViews.mount(d.root,detail,{initialView:'pseudo'});
 const summary=d.elements.get('#fv-panel-pseudo .fv-tools > span').textContent;
 assert(summary.includes('선언 확인 호출 1개'));assert(summary.includes('명령어 추론 호출 2개'));assert(summary.includes('미확인 호출 1개'));
 assert(d.added[0].textContent.includes('추론'));assert(d.root.innerHTML.includes('&lt;unsafe-name&gt;'));
 assert.equal(d.elements.get('#fv-panel-pseudo').hidden,false);
 await d.elements.get('[data-copy]').onclick();assert.equal(clipboard[0],detail.pseudocode.code);
 detail.pseudocode.semantic.signature_inferred=false;detail.pseudocode.semantic.signature_source='pdb';
 context.window.FunctionViews.mount(d.root,detail);assert(d.added.at(-1).textContent.includes('일치하는 PDB'));

 const e=dom(),requests=[],messages=[];let pending,busy=false;
 const api=async(url,body)=>{
   requests.push({url,body});if(url==='/api/studio/symbols')return{results:[{id:'verified',name:'module.pdb',function_count:10}]};
   switch(body.operation){
    case'image_catalog':return{success:true,process_start_key:'42',results:[{base:'0x10000',name:'one.dll',image_size:4096},{base:'0x20000',name:'two.dll',image_size:4096}]};
    case'status':return{success:true};case'function_calls':return{success:true,results:[]};
    case'image_functions':return{success:true,count:0,results:[],forwarders:[],data_exports:[],image:{name:'sample.dll'},analysis_id:'analysis'};
    case'image_public_symbols':return new Promise(resolve=>pending=resolve);
    default:throw Error('Unexpected action '+body.operation);
   }
 };
 const dllContext={window:{},clearTimeout(){},setTimeout(){return 1;},console};vm.createContext(dllContext);
 vm.runInContext(fs.readFileSync(path.join(panel,'static/dll_workspace.js'),'utf8'),dllContext);
 const options={root:e.root,pid:42,api,toast:(...m)=>messages.push(m),setBusy:v=>busy=v,isBusy:()=>busy,currentPid:()=>42,download(){}};
 dllContext.window.DllWorkbench.render(options);const flush=()=>new Promise(resolve=>setImmediate(resolve));await flush();
 assert(e.root.innerHTML.includes('Microsoft 공개 심볼'));
 // A valid public PDB is passed into analysis only for the selected image.
 const applying=e.elements.get('#pdb-public').onclick();assert.equal(requests.at(-1).body.operation,'image_public_symbols');
 assert.equal(requests.at(-1).body.args.base,'0x10000');pending({success:true,id:'verified',note:'verified'});await applying;
 assert.equal(requests.find(r=>r.body?.operation==='image_functions').body.args.pdb_id,'verified');
 // Changing the image while a download is pending invalidates that result.
 const before=requests.filter(r=>r.body?.operation==='image_functions').length;
 const stale=e.elements.get('#pdb-public').onclick();e.elements.get('#dll-image').onchange({target:{value:'0x20000'}});
 pending({success:true,id:'stale'});await stale;
 assert.equal(requests.filter(r=>r.body?.operation==='image_functions').length,before);
 // An unavailable public PDB leaves the no-PDB analysis path usable.
 e.elements.get('#dll-pdb').onchange({target:{value:''}});
 const missing=e.elements.get('#pdb-public').onclick();pending({success:false,error:'PDB 없이 분석 가능'});await missing;
 assert(messages.at(-1)[0].includes('PDB 없이'));
 await e.elements.get('#dll-analyze').onclick();assert.equal(requests.at(-1).body.args.pdb_id,'');
 assert.equal(requests.at(-1).body.args.base,'0x20000');assert.equal(busy,false);
 console.log('PDB-free UI: inferred/declaration labels, copy, public-symbol apply, stale reply, and unavailable-symbol fallback passed.');
})().catch(error=>{console.error(error);process.exitCode=1;});
