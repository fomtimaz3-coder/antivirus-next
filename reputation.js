let lastRequest=0,chain=Promise.resolve(),cacheEpoch=0;
const TTL=6*3600000;
const cancelled=()=>({status:'disabled',reason:'Онлайн-проверка отменена'});
function cache(){return new Promise((resolve,reject)=>{let expired=false;const timer=setTimeout(()=>{expired=true;reject(Error('Хранилище не отвечает'))},2000);const r=indexedDB.open('aw-reputation-v2',1);r.onupgradeneeded=()=>r.result.createObjectStore('hashes',{keyPath:'cacheKey'});r.onsuccess=()=>{clearTimeout(timer);if(expired)r.result.close();else resolve(r.result)};r.onerror=r.onblocked=()=>{clearTimeout(timer);expired=true;reject(r.error||Error('Хранилище занято'))}})}
async function cached(hash,value,valid=()=>true){const db=await cache();try{if(!valid())return;return await new Promise((resolve,reject)=>{const tx=db.transaction('hashes',value?'readwrite':'readonly'),s=tx.objectStore('hashes'),r=value?s.put(value):s.get(hash);let result;const timer=setTimeout(()=>tx.abort(),2000);r.onsuccess=()=>result=r.result;tx.oncomplete=()=>{clearTimeout(timer);resolve(result)};tx.onerror=tx.onabort=()=>{clearTimeout(timer);reject(tx.error||Error('Транзакция прервана'))}})}finally{db.close()}}
function wait(ms,signal){return new Promise(resolve=>{const done=()=>{clearTimeout(timer);signal?.removeEventListener('abort',done);resolve()};const timer=setTimeout(done,ms);if(signal?.aborted)done();else signal?.addEventListener('abort',done,{once:true})})}
function withAbort(promise,signal){if(!signal)return promise;if(signal.aborted)return Promise.resolve(cancelled());return new Promise((resolve,reject)=>{const abort=()=>resolve(cancelled());signal.addEventListener('abort',abort,{once:true});promise.then(resolve,reject).finally(()=>signal.removeEventListener('abort',abort))})}
export function lookup(hash,key,provider,active=()=>true,force=false,signal){
 const allowed=()=>!signal?.aborted&&active();
 const task=async()=>{
  if(!allowed())return cancelled();const cacheKey=provider+':'+hash,epoch=cacheEpoch;
  const old=force?null:await cached(cacheKey).catch(()=>null);if(!allowed())return cancelled();
  if(old&&old.checkedAt<=Date.now()&&Date.now()-old.checkedAt<TTL)return {...old,cached:true};
  await wait(Math.max(0,16000-(Date.now()-lastRequest)),signal);if(!allowed())return cancelled();lastRequest=Date.now();
  const controller=new AbortController(),abort=()=>controller.abort(),timer=setTimeout(abort,15000);signal?.addEventListener('abort',abort,{once:true});
  try{
   const r=await fetch('./api/reputation',{method:'POST',headers:{'Content-Type':'application/json',[provider==='VirusTotal'?'x-vt-key':'x-abuse-key']:key},body:JSON.stringify({sha256:hash,provider}),signal:controller.signal});
   if(!allowed())return cancelled();
   if(!r.ok){const error=await r.json().catch(()=>({}));return {status:'unavailable',httpStatus:r.status,reason:error.error==='origin'?'Запрос отклонён: источник страницы':r.status===429?'Исчерпан лимит запросов; повторите позже':r.status===401?'Сервис не принял ключ авторизации':r.status===403?'Сервис запретил доступ: проверьте права аккаунта':error.error==='invalid_report'?'Сервис вернул неподдерживаемый ответ':'Сервис недоступен (HTTP '+r.status+')'}}
   const v=await r.json();if(!allowed())return cancelled();if(v.sha256!==hash||v.provider!==provider||!['detections','unknown','no_detections'].includes(v.status))return {status:'unavailable',reason:'Некорректный ответ'};
   if(epoch===cacheEpoch)await cached(cacheKey,{...v,cacheKey},()=>allowed()&&epoch===cacheEpoch).catch(()=>{});return v;
  }catch{return allowed()?{status:'unavailable',reason:'Нет связи с сервисом или истекло время ожидания'}:cancelled()}finally{clearTimeout(timer);signal?.removeEventListener('abort',abort)}
 };
 const next=chain.then(task,task);chain=next.catch(()=>{});return withAbort(next,signal);
}
export async function clearReputation(){cacheEpoch++;const db=await cache();try{await new Promise((resolve,reject)=>{const tx=db.transaction('hashes','readwrite');tx.objectStore('hashes').clear();tx.oncomplete=resolve;tx.onerror=tx.onabort=()=>reject(tx.error)})}finally{db.close()}}
export async function reputation(hash,keys,active=()=>true,signal){const attempts=[];for(const [provider,key] of [['VirusTotal',keys.vt],['MalwareBazaar',keys.bazaar]]){if(!key||!active()||signal?.aborted)continue;const result=await lookup(hash,key,provider,active,false,signal);attempts.push({...result,provider});if(result.status==='detections')return {...result,attempts};if(result.status==='disabled')break}if(!attempts.length)return {status:'disabled',attempts};const status=attempts.some(x=>x.status==='no_detections')?'no_detections':attempts.some(x=>x.status==='unknown')?'unknown':attempts.some(x=>x.status==='unavailable')?'unavailable':'disabled';return {status,attempts,...(status==='unknown'?{reason:'Сведений о хеше нет; безопасность не установлена'}:status==='unavailable'?{reason:'Настроенные сервисы недоступны'}:{})}}
