import {inspectZip,LIMITS} from './archive.js';
import {SHA256} from './sha256.js';
const text=b=>new TextDecoder().decode(b).replace(/\0.*$/s,'');
export async function containerType(file,name=''){
 const b=new Uint8Array(await file.slice(0,512).arrayBuffer());
 if(b[0]===80&&b[1]===75)return 'ZIP';
 if(b[0]===31&&b[1]===139)return 'GZIP';
 if(text(b.subarray(257,263)).startsWith('ustar')||/\.tar$/i.test(name))return 'TAR';
 return null;
}
export async function inspectContainer(file,scanBytes=()=>[],onProgress=()=>{},inspectEntry=null,context={depth:0,budget:{entries:0,bytes:0}},name=file.name||'archive'){
 const type=await containerType(file,name);
 if(type==='ZIP')return {...await inspectZip(file,scanBytes,onProgress,inspectEntry,context),format:'ZIP'};
 if(!type)throw Error('Неподдерживаемый контейнер');
 const result={format:type,depth:context.depth,entries:[],total:0,scanned:0,skipped:0,expandedBytes:0,limitations:[],apk:null};
 async function entry(bytes,name){const hash=new SHA256();hash.update(bytes);const e={name,unpacked:bytes.length,sha256:hash.digest(),status:'scanned',findings:[]};result.entries.push(e);if(inspectEntry){e.analysis=await inspectEntry(bytes,name,e.sha256);e.findings.push(...e.analysis.findings||[]);if(e.analysis.partial)result.limitations.push(name+': часть анализа пропущена')}else e.findings.push(...scanBytes(new TextDecoder('latin1').decode(bytes),name));result.scanned++;await inspectNested(e,bytes,scanBytes,onProgress,inspectEntry,context,result);onProgress({archiveScanned:result.scanned,archiveTotal:result.total,archiveName:name});}
 try{
 if(type==='GZIP'){
  result.total=1;if(context.budget.entries>=LIMITS.entries)throw Error('Общий лимит записей архива');context.budget.entries++;
  const reader=file.stream().pipeThrough(new DecompressionStream('gzip')).getReader(),parts=[];let size=0;
  try{while(true){const {value,done}=await reader.read();if(done)break;size+=value.length;context.budget.bytes+=value.length;result.expandedBytes+=value.length;if(size>LIMITS.entryBytes||context.budget.bytes>LIMITS.totalBytes||size/Math.max(1,file.size)>LIMITS.ratio)throw Error('Превышен лимит безопасной распаковки GZIP');parts.push(value)}}finally{await reader.cancel().catch(()=>{})}
  const bytes=new Uint8Array(size);let at=0;for(const part of parts){bytes.set(part,at);at+=part.length}parts.length=0;
  await entry(bytes,name.replace(/\.tgz$/i,'.tar').replace(/\.(gzip|gz)$/i,'')||'gzip-content');
 }else{
  let at=0,terminated=false;
  while(at+512<=file.size){
   const h=new Uint8Array(await file.slice(at,at+512).arrayBuffer());if(h.every(x=>x===0)){terminated=true;break}
   if(context.budget.entries>=LIMITS.entries)throw Error('Общий лимит записей архива');context.budget.entries++;result.total++;
   const octal=(start,len)=>{const s=text(h.subarray(start,start+len)).trim();if(!/^[0-7]*$/.test(s))throw Error('Неподдерживаемое числовое поле TAR');const n=parseInt(s||'0',8);if(!Number.isSafeInteger(n))throw Error('Слишком большое числовое поле TAR');return n};
   const expected=octal(148,8);let sum=0;for(let i=0;i<512;i++)sum+=i>=148&&i<156?32:h[i];if(sum!==expected)throw Error('Контрольная сумма заголовка TAR не совпала');
   const size=octal(124,12),name=[text(h.subarray(345,500)),text(h.subarray(0,100))].filter(Boolean).join('/'),kind=h[156],start=at+512;at=start+Math.ceil(size/512)*512;if(at>file.size)throw Error('Обрезанная запись TAR');
   if(kind===53)continue;
   if(![0,48].includes(kind)||size>LIMITS.entryBytes||context.budget.bytes+size>LIMITS.totalBytes){result.skipped++;result.entries.push({name,status:'skipped',findings:[],reason:![0,48].includes(kind)?'TAR: ссылки, PAX/GNU и специальные записи не поддерживаются':'Превышен лимит размера TAR'});continue}
   context.budget.bytes+=size;result.expandedBytes+=size;await entry(new Uint8Array(await file.slice(start,start+size).arrayBuffer()),name);
  }
  if(!terminated)throw Error('Не найден завершающий блок TAR');
 }
 }catch(e){result.error=e.message;result.limitations.push(e.message);result.skipped++}
 result.treeBudget={...context.budget};return result;
}
export async function inspectNested(entry,bytes,scanBytes,onProgress,inspectEntry,context,result){
 const file=new Blob([bytes]),type=await containerType(file,entry.name);if(!type)return;
 if(context.depth>=LIMITS.depth){entry.reason='Достигнут предел: 2 вложенных уровня архивов';result.limitations.push(entry.name+': '+entry.reason);return}
 try{entry.archive=await inspectContainer(file,scanBytes,onProgress,inspectEntry,{depth:context.depth+1,budget:context.budget},entry.name);for(const child of entry.archive.entries)for(const f of child.findings||[])entry.findings.push({...f,path:entry.name+' / '+(f.path||child.name)});result.limitations.push(...entry.archive.limitations.map(x=>entry.name+' / '+x));if(entry.archive.skipped)result.limitations.push(entry.name+': пропущено вложенных записей '+entry.archive.skipped)}catch(e){entry.reason=type+': '+e.message;result.limitations.push(entry.name+': '+entry.reason)}
}
