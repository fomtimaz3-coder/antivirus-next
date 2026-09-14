import {inspectZip} from './archive.js';
import {SHA256} from './sha256.js';
import {hashIndex} from './bloom.js';
import {scanWithRules} from './yara.js';
import {staticAnalysis} from './static-analysis.js';
const CHUNK=2*1024*1024,STATIC_LIMIT=32*1024*1024;
let cloudResolve;
self.onmessage=async({data})=>{
 if(data.kind==='reputation'){cloudResolve?.(data.value);cloudResolve=null;return}
 const {file,id,database=[],rulePack,cloud=false}=data,start=performance.now(),hash=new SHA256(),found=[],limitations=[],log=[],index=hashIndex(database);let done=0,last=0,archive=null,analysis=null,yara=null,reputation={status:'disabled'};
 const progress=(phase,extra={})=>self.postMessage({kind:'progress',id,done,phase,seconds:(performance.now()-start)/1000,...extra});
 const inspect=async(b,name)=>{const result=staticAnalysis(b,name),y=await scanWithRules(new Blob([b]),rulePack);result.yara=y;if(y.error){result.partial=true;result.limitations.push(y.error)}for(const rule of y.matches||[])result.findings.push({rule,title:rule==='eicar'?'Обнаружен безвредный тест EICAR':'Совпадение YARA: '+rule,kind:rule==='eicar'?'test':'yara'});return result};
 try{
 for(let at=0;at<file.size;at+=CHUNK){const bytes=new Uint8Array(await file.slice(at,at+CHUNK).arrayBuffer());hash.update(bytes);done+=bytes.length;if(performance.now()-last>120||done===file.size){progress('hash');last=performance.now()}}
 const sha256=hash.digest();log.push('SHA-256 вычислен потоково по всем байтам файла');const hit=index.find(sha256);if(hit)found.push({rule:'HASH-DB',title:hit.name,kind:'hash'});log.push('Bloom-фильтр + точное сопоставление с импортированной базой; отрицание не отменяет анализ');
 if(cloud){progress('reputation');reputation=await new Promise(resolve=>{cloudResolve=resolve;self.postMessage({kind:'hash-ready',id,sha256})});if(reputation.status==='detections'){found.push({rule:'VT-REPUTATION',title:(reputation.provider||'Сервис репутации')+': есть обнаружения',kind:'reputation',evidence:reputation.stats||reputation.signature});self.postMessage({kind:'alert',id,text:(reputation.provider||'Сервис репутации')+' сообщил об обнаружениях; продолжаем локальную проверку'})}if(reputation.status==='unavailable')limitations.push('Репутация не проверена: '+reputation.reason);log.push('VirusTotal: '+reputation.status+'; локальный анализ не пропускается')}
 progress('yara');yara=await scanWithRules(file,rulePack);if(yara.error)limitations.push(yara.error);for(const rule of yara.matches||[])found.push({rule,title:rule==='eicar'?'Обнаружен безвредный тест EICAR':'Совпадение YARA: '+rule,kind:rule==='eicar'?'test':'yara'});
 progress('static');if(file.size<=STATIC_LIMIT){analysis=staticAnalysis(new Uint8Array(await file.arrayBuffer()),file.name);found.push(...analysis.findings);limitations.push(...analysis.limitations)}else limitations.push('Углублённый структурный анализ пропущен: размер больше 32 МиБ');
 const head=new Uint8Array(await file.slice(0,8).arrayBuffer());let type=analysis?.details?.format||'Не определён';if(head[0]===0x50&&head[1]===0x4b){type='ZIP / APK';progress('archive');try{archive=await inspectZip(file,()=>[],p=>progress('archive',p),inspect);for(const entry of archive.entries){for(const finding of entry.findings)found.push({...finding,path:finding.path||entry.name});const h=index.find(entry.sha256);if(h)found.push({rule:'HASH-DB-INNER',title:h.name,kind:'hash',path:entry.name})}limitations.push(...archive.limitations);if(archive.skipped)limitations.push('Пропущено записей ZIP: '+archive.skipped)}catch(e){archive={entries:[],error:e.message,scanned:0,skipped:0,limitations:[e.message]};limitations.push('ZIP: '+e.message)}}
 if(head[0]===0xd0&&head[1]===0xcf)limitations.push('OLE/VBA: разбор макросов пока не реализован');
 if(/\.(rar|7z|gz|tar|pdf|doc|xls|ppt)$/i.test(file.name))limitations.push('Содержимое этого контейнера/документа не распаковано');
 if(archive?.entries.some(x=>/vbaProject\.bin$/i.test(x.name)))limitations.push('Найден VBA-проект: декомпрессия макросов пока не реализована');
 if(archive?.apk)limitations.push('Криптографическая подпись APK не проверялась; отсутствие v1-файлов не означает отсутствие v2/v3-подписи');
 if(['PE','ELF'].includes(type)&&/\.(jpg|jpeg|png|pdf|txt|mp3|mp4)$/i.test(file.name))found.push({rule:'FORMAT-001',title:'Исполняемый файл скрыт за другим расширением',kind:'heuristic'});
 limitations.push(rulePack?.manifest?.description||'База YARA недоступна.','Статический анализ не доказывает безопасность и не проверяет поведение файла.');
 const partial=limitations.some(x=>/пока не реализован|не распаковано/.test(x))||!!yara.error||!!analysis?.partial||file.size>STATIC_LIMIT||!!archive&&(!!archive.error||archive.skipped>0||archive.limitations.length>0);
 self.postMessage({kind:'done',id,report:{id,name:file.name,size:file.size,mime:file.type||'Не указан',type,sha256,created:new Date().toISOString(),durationMs:Math.round(performance.now()-start),bytesRead:done,engine:'YARA 4.5.8 / AW 3.0',ruleVersion:rulePack?.manifest?.version||null,ruleDescription:rulePack?.manifest?.description||'База недоступна',databaseEntries:database.length,yara,reputation,analysis,archive,apk:archive?.apk||null,partial,findings:found,limitations:[...new Set(limitations)],status:found.length?'Есть находки':'Совпадений не найдено',coverage:partial?'Ограниченная проверка':'Статический анализ',log:[...log,'YARA: '+(yara.error||'проверка завершена'),'DEX/PE/ELF: ограниченный разбор структуры; скрипты: текстовые контекстные признаки']}});
 }catch(e){self.postMessage({kind:'error',id,error:String(e.message||e),done})}
};
