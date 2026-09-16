// One isolated WASM runner per scanner worker; serialize requests and recycle on failure.
let runner=null,chain=Promise.resolve(),generation=0;
export function disposeYara(){generation++;runner?.terminate();runner=null}
export function yaraScan(file,rules){
 const epoch=generation;
 const task=chain.then(()=>{
  if(epoch!==generation)return {error:'YARA: проверка прервана'};
  if(file.size>32*1024*1024)return {error:'YARA: файл больше лимита 32 МиБ; проверка не выполнена полностью'};
  if(!rules)return {error:'Нет загруженных YARA-правил'};
  return new Promise(resolve=>{
   let settled=false,w;
   const finish=(result,recycle=false)=>{if(settled)return;settled=true;clearTimeout(timer);if(w){w.onmessage=null;w.onerror=null}if(recycle){w?.terminate();if(runner===w)runner=null}resolve(result)};
   const timer=setTimeout(()=>finish({error:'YARA: превышено время 15 секунд'},true),15000);
   try{w=runner||(runner=new Worker('./yara-runner.js',{type:'module'}));w.onmessage=e=>finish(e.data,!!e.data.error);w.onerror=()=>finish({error:'YARA-WASM недоступен'},true);file.arrayBuffer().then(buffer=>{if(!settled)w.postMessage({buffer,rules},[buffer])}).catch(e=>finish({error:e.message},true))}catch(e){finish({error:e.message},true)}
  });
 });
 chain=task.catch(()=>{});return task;
}


export async function scanWithRules(file,pack){
 const base=await yaraScan(file,pack?.source);if(base.error)return base;
 const bytes=new Uint8Array(await file.slice(0,4).arrayBuffer());const magic=bytes.length===4?new DataView(bytes.buffer).getUint32(0):0;
 const platform=bytes[0]===77&&bytes[1]===90?'win':magic===0x7f454c46?'elf':[0xfeedface,0xfeedfacf,0xcefaedfe,0xcffaedfe,0xcafebabe,0xbebafeca,0xcafebabf,0xbfbafeca].includes(magic)?'osx':null;
 const shards=(pack?.manifest?.shards||[]).filter(s=>s.platform===platform),matches=new Set(base.matches),errors=[];let checked=0,extraRulesChecked=0;const started=performance.now();const {getShard}=await import('./rule-store.js');
 for(const shard of shards){if(performance.now()-started>60000){errors.push('Лимит общего времени Malpedia: оставшиеся части базы пропущены');break}try{const source=await getShard(pack,shard),result=await yaraScan(file,source);if(result.error)errors.push(result.error);else{checked++;extraRulesChecked+=shard.count||0;for(const m of result.matches)matches.add(m)}}catch(e){errors.push(e.message)}}
 return {...base,matches:[...matches],platform,baseRulesChecked:pack?.source?.match(/(?:^|\n)\s*(?:(?:private|global)\s+)*rule\s+\w+/g)?.length||0,extraRulesChecked,shardsChecked:checked,shardsSelected:shards.length,ruleVersion:pack?.manifest?.version,...(errors.length?{error:[...new Set(errors)].join('; ')}:{})};
}
