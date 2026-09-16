import {inspectNested} from './containers.js';
import {SHA256} from './sha256.js';
export const LIMITS={entries:500,entryBytes:32*1024*1024,totalBytes:128*1024*1024,ratio:200,manifestBytes:2*1024*1024,depth:2};
const table=Uint32Array.from({length:256},(_,n)=>{for(let k=0;k<8;k++)n=n&1?0xedb88320^(n>>>1):n>>>1;return n>>>0});
function crc(bytes,c=0xffffffff){for(const b of bytes)c=table[(c^b)&255]^(c>>>8);return c>>>0}
export async function inspectZip(file,scanBytes,onProgress=()=>{},inspectEntry=null,context={depth:0,budget:{entries:0,bytes:0}}){
 const {depth,budget}=context;
 const result={depth,entries:[],total:0,scanned:0,skipped:0,expandedBytes:0,limitations:[],apk:null};
 const tailStart=Math.max(0,file.size-65557),tail=new Uint8Array(await file.slice(tailStart).arrayBuffer()),v=new DataView(tail.buffer);let end=-1;
 for(let p=tail.length-22;p>=0;p--)if(v.getUint32(p,true)===0x06054b50&&p+22+v.getUint16(p+20,true)===tail.length){end=p;break}
 if(end<0)throw Error('Не найден корректный каталог ZIP');
 const count=v.getUint16(end+10,true),size=v.getUint32(end+12,true),offset=v.getUint32(end+16,true);result.total=count;
 if(v.getUint16(end+4,true)||v.getUint16(end+6,true)||v.getUint16(end+8,true)!==count)throw Error('Многотомный ZIP не поддерживается');
 if(count===65535||size===0xffffffff||offset===0xffffffff)throw Error('ZIP64 не поддерживается');
 if(size>8*1024*1024||offset+size>tailStart+end)throw Error('Каталог ZIP повреждён или превышает 8 МиБ');
 const cat=new Uint8Array(await file.slice(offset,offset+size).arrayBuffer()),d=new DataView(cat.buffer);let p=0;
 try{for(let i=0;i<count;i++){
  if(budget.entries>=LIMITS.entries){result.skipped+=count-i;result.limitations.push('Общий лимит: 500 записей во всём дереве ZIP');break}budget.entries++;
  if(p+46>cat.length||d.getUint32(p,true)!==0x02014b50)throw Error('Повреждена запись каталога ZIP');
  const flags=d.getUint16(p+8,true),method=d.getUint16(p+10,true),checksum=d.getUint32(p+16,true),packed=d.getUint32(p+20,true),unpacked=d.getUint32(p+24,true),nl=d.getUint16(p+28,true),el=d.getUint16(p+30,true),cl=d.getUint16(p+32,true),local=d.getUint32(p+42,true);
  if(p+46+nl+el+cl>cat.length)throw Error('Повреждено имя записи ZIP');
  const rawName=cat.slice(p+46,p+46+nl),name=new TextDecoder(flags&2048?'utf-8':'windows-1252').decode(rawName);p+=46+nl+el+cl;
  if(name.endsWith('/')){result.total--;continue}
  const entry={name,packed,unpacked,status:'skipped',reason:'',findings:[]};result.entries.push(entry);
  try{
   if(flags&1)throw Error('Зашифрованный файл');
   if(![0,8].includes(method))throw Error('Неподдерживаемый метод сжатия '+method);
   if(unpacked>LIMITS.entryBytes||packed>LIMITS.entryBytes||unpacked/Math.max(1,packed)>LIMITS.ratio||budget.bytes+unpacked>LIMITS.totalBytes)throw Error('Превышен лимит безопасной распаковки');
   const head=new DataView(await file.slice(local,local+30).arrayBuffer());
   if(head.byteLength!==30||head.getUint32(0,true)!==0x04034b50)throw Error('Повреждён локальный заголовок');
   if(head.getUint16(6,true)!==flags||head.getUint16(8,true)!==method||head.getUint16(26,true)!==nl)throw Error('Заголовки ZIP противоречат друг другу');
   const localName=new Uint8Array(await file.slice(local+30,local+30+nl).arrayBuffer());if(!rawName.every((b,i)=>b===localName[i]))throw Error('Имена в заголовках не совпадают');
   const start=local+30+nl+head.getUint16(28,true);if(start+packed>offset)throw Error('Данные выходят за границы ZIP');
   let stream=file.slice(start,start+packed).stream();if(method===8){try{stream=stream.pipeThrough(new DecompressionStream('deflate-raw'))}catch{throw Error('Браузер не поддерживает распаковку Deflate')}}
   const reader=stream.getReader(),hash=new SHA256();let actual=0,checksumActual=0xffffffff,tailText='',manifestParts=[];
   const isManifest=name==='AndroidManifest.xml',parts=[];
   try{while(true){const {value,done}=await reader.read();if(done)break;actual+=value.length;result.expandedBytes+=value.length;budget.bytes+=value.length;
    if(actual>LIMITS.entryBytes||actual>unpacked||budget.bytes>LIMITS.totalBytes)throw Error('Распаковка остановлена: превышен лимит');
    parts.push(value);hash.update(value);checksumActual=crc(value,checksumActual);const text=tailText+new TextDecoder('latin1').decode(value);entry.findings.push(...scanBytes(text,name));tailText=text.slice(-512);
    if(isManifest&&unpacked<=LIMITS.manifestBytes)manifestParts.push(value);
   }}finally{await reader.cancel().catch(()=>{})}
   if(actual!==unpacked||((checksumActual^0xffffffff)>>>0)!==checksum)throw Error('Размер или CRC-32 не совпадает');
   entry.sha256=hash.digest();const all=new Uint8Array(actual);let at=0;for(const part of parts){all.set(part,at);at+=part.length}parts.length=0;if(inspectEntry){const analysis=await inspectEntry(all,name,entry.sha256);entry.analysis=analysis;entry.findings.push(...analysis.findings||[]);if(analysis.partial)result.limitations.push(name+': часть углублённого анализа пропущена');}entry.status='scanned';result.scanned++;
   await inspectNested(entry,all,scanBytes,onProgress,inspectEntry,context,result);
   if(/\.(7z|rar)$/i.test(name)){entry.reason='Формат вложенного архива не поддерживается';result.limitations.push(name+': '+entry.reason)}
   if(isManifest){if(unpacked>LIMITS.manifestBytes)result.limitations.push('AndroidManifest.xml превышает 2 МиБ');else{const all=new Uint8Array(actual);let at=0;for(const part of manifestParts){all.set(part,at);at+=part.length}try{result.apk=parseManifest(all)}catch(e){result.limitations.push('Манифест APK: '+e.message)}}}
  }catch(e){entry.reason=e.message;result.skipped++}
  entry.findings=[...new Map(entry.findings.map(f=>[f.rule+'|'+(f.path||name),f])).values()];onProgress({archiveScanned:result.scanned,archiveTotal:result.total,archiveName:name});
 }
 }catch(e){result.error=e.message;result.limitations.push(e.message);result.skipped+=Math.max(1,count-result.entries.length)}
 result.treeBudget={...budget};return result;
}
export function parseManifest(bytes){
 const d=new DataView(bytes.buffer,bytes.byteOffset,bytes.byteLength),strings=[];const out={package:null,versionName:null,versionCode:null,minSdk:null,targetSdk:null,permissions:[]};
 if(d.byteLength<8||d.getUint16(0,true)!==3||d.getUint32(4,true)!==bytes.length)throw Error('Поддерживается двоичный Android XML');
 let p=d.getUint16(2,true);if(p<8)throw Error('Повреждён заголовок XML');
 const str=i=>{if(i===0xffffffff)return null;if(i>=strings.length)throw Error('Некорректная ссылка на строку');return strings[i]};
 while(p+8<=bytes.length){const type=d.getUint16(p,true),hs=d.getUint16(p+2,true),sz=d.getUint32(p+4,true);if(hs<8||sz<hs||p+sz>bytes.length)throw Error('Повреждён блок XML');
  if(type===1){if(hs<28)throw Error('Повреждён пул строк');const count=d.getUint32(p+8,true),utf8=!!(d.getUint32(p+16,true)&256),base=p+d.getUint32(p+20,true);if(count>50000||p+hs+count*4>p+sz||base>p+sz)throw Error('Слишком большой пул строк');
   for(let i=0;i<count;i++){let q=base+d.getUint32(p+hs+i*4,true);const byte=()=>{if(q>=p+sz)throw Error('Строка вне блока');return bytes[q++]};const u16=()=>byte()|(byte()<<8);const len8=()=>{const a=byte();return a&128?((a&127)<<8)|byte():a};const len16=()=>{const a=u16();return a&32768?((a&32767)*65536)+u16():a};let n;if(utf8){len8();n=len8()}else n=len16()*2;if(q+n>p+sz)throw Error('Строка вне блока');strings.push(new TextDecoder(utf8?'utf-8':'utf-16le').decode(bytes.subarray(q,q+n)))}
  }else if(type===0x0102){const ext=p+hs;if(ext+20>p+sz)throw Error('Повреждён элемент XML');const tag=str(d.getUint32(ext+4,true)),as=d.getUint16(ext+8,true),step=d.getUint16(ext+10,true),count=d.getUint16(ext+12,true);if(step<20||ext+as+step*count>p+sz)throw Error('Повреждены атрибуты');const attrs={};for(let i=0;i<count;i++){const a=ext+as+i*step,name=str(d.getUint32(a+4,true)),raw=d.getUint32(a+8,true),type=bytes[a+15],value=d.getUint32(a+16,true);attrs[name]=raw!==0xffffffff?str(raw):type===3?str(value):type===16||type===17?String(value):'Ресурс 0x'+value.toString(16)}
   if(tag==='manifest'){out.package=attrs.package||null;out.versionName=attrs.versionName||null;out.versionCode=attrs.versionCode||null}if(tag==='uses-sdk'){out.minSdk=attrs.minSdkVersion||null;out.targetSdk=attrs.targetSdkVersion||null}if(tag==='uses-permission'||tag==='uses-permission-sdk-23')if(attrs.name)out.permissions.push(attrs.name);
  }p+=sz;
 }
 if(!out.package)throw Error('Не найдено имя пакета');out.permissions=[...new Set(out.permissions)];return out;
}
