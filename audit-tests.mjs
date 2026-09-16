import assert from 'node:assert/strict';
import {staticAnalysis} from './static-analysis.js';
import fs from 'node:fs';import {createHash} from 'node:crypto';import {gzipSync} from 'node:zlib';
import {zip,tar,eicar} from './test/fixtures.mjs';
import {inspectContainer} from './containers.js';import {boundedBytes} from './bounded-read.js';import {scanNative} from './scripts/validate-rules.mjs';import handler from './api/reputation.mjs';import {lookup} from './reputation.js';
const detect=async(bytes)=>({format:'other',findings:new TextDecoder().decode(bytes).includes('EICAR')?[{rule:'fixture',title:'fixture'}]:[],limitations:[]});
const gz=gzipSync(tar([['sample.txt',eicar]]));
let r=await inspectContainer(new Blob([gz]),()=>[],()=>{},detect,undefined,'sample.tar.gz');assert.equal(r.format,'GZIP');assert.equal(r.entries[0].archive.format,'TAR');assert(r.entries[0].findings.some(x=>x.path?.endsWith('sample.txt')));
r=await inspectContainer(new Blob([gzipSync(Buffer.alloc(1024*1024))]),()=>[],()=>{},detect,undefined,'bomb.gz');assert.match(r.error,/лимит/);
const corrupt=zip([['good.txt',eicar],['bad.txt','data']]);const off=corrupt.readUInt32LE(corrupt.length-6);corrupt.writeUInt32LE(0,off+46+Buffer.byteLength('good.txt'));r=await inspectContainer(new Blob([corrupt]),()=>[],()=>{},detect,undefined,'bad.zip');assert(r.error);assert.equal(r.entries[0].findings.length,1);
const badTar=tar([['good.txt',eicar],['bad.txt','data']]);badTar[1024+148]=57;r=await inspectContainer(new Blob([badTar]),()=>[],()=>{},detect,undefined,'bad.tar');assert(r.error);assert.equal(r.entries[0].findings.length,1);
await assert.rejects(()=>boundedBytes(new Response(new Uint8Array(20)),10),/размер/);
// Real WASM + whole scanner: nested hash matching and TAR/GZIP EICAR.
globalThis.Worker=class{postMessage({buffer,rules}){scanNative(new Uint8Array(buffer),rules).then(matches=>this.onmessage?.({data:{matches}})).catch(e=>this.onerror?.(e))}terminate(){}};
let messages=[];globalThis.self={postMessage:m=>messages.push(m)};await import('./worker.js');const source=fs.readFileSync('rules/MALW_Eicar.yar','utf8');
async function scan(bytes,name,database=[]){messages=[];const file=new Blob([bytes]);file.name=name;await self.onmessage({data:{file,id:'audit',database,rulePack:{source,manifest:{version:'audit'}}}});assert.equal(messages.at(-1).kind,'done');return messages.at(-1).report}
const h=createHash('sha256').update('hash fixture').digest('hex');let report=await scan(zip([['inner.zip',zip([['payload.bin','hash fixture']])]]),'outer.zip',[{sha256:h,name:'Hash fixture'}]);assert(report.findings.some(x=>x.kind==='hash'&&x.path==='inner.zip / payload.bin'));
report=await scan(gz,'sample.tar.gz');assert(report.findings.some(x=>x.rule==='eicar'&&x.path?.endsWith('sample.txt')));assert.equal(report.type,'GZIP');
report=await scan(corrupt,'bad.zip');assert(report.partial);assert(report.findings.some(x=>x.rule==='eicar'));
const originalFetch=globalThis.fetch;let answer;const res={setHeader(){},status(n){this.code=n;return this},json(x){answer=x;return this}},hash='a'.repeat(64),req={method:'POST',headers:{host:'test','x-vt-key':'fixture'},body:{sha256:hash,provider:'VirusTotal'}};
globalThis.fetch=async()=>({ok:true,json:async()=>({data:{id:hash,attributes:{last_analysis_stats:{malicious:0,suspicious:0,undetected:0,harmless:0}}}})});await handler(req,res);assert.equal(answer.status,'unknown');
globalThis.fetch=async()=>({ok:true,json:async()=>({data:{id:'b'.repeat(64),attributes:{last_analysis_stats:{malicious:0,suspicious:0,undetected:1,harmless:0}}}})});await handler(req,res);assert.equal(res.code,502);assert.equal(answer.error,'hash_mismatch');
let began;const started=new Promise(resolve=>began=resolve);let aborted=false;globalThis.fetch=async(url,options)=>new Promise((resolve,reject)=>{options.signal.addEventListener('abort',()=>{aborted=true;reject(Error('aborted'))});began()});const controller=new AbortController();const pending=lookup(hash,'fixture','VirusTotal',()=>true,true,controller.signal);await started;controller.abort();assert.equal((await pending).status,'disabled');assert(aborted);globalThis.fetch=originalFetch;
console.log('PASS: TAR/GZIP extraction and bomb limit, preserved findings on corrupt catalog, nested hash detection, bounded responses, VT hash/zero stats, network abort.');

const thin=Buffer.alloc(1208);thin.writeUInt32LE(0xfeedfacf,0);thin.writeUInt32LE(1,16);thin.writeUInt32LE(152,20);thin.writeUInt32LE(0x19,32);thin.writeUInt32LE(152,36);thin.writeBigUInt64LE(1208n,80);thin.writeUInt32LE(4,92);thin.writeUInt32LE(1,96);thin.write('__text',104);thin.writeBigUInt64LE(1024n,144);thin.writeUInt32LE(184,152);for(let i=0;i<1024;i++)thin[184+i]=i&255;
const fat=Buffer.alloc(64+thin.length);fat.writeUInt32BE(0xcafebabe,0);fat.writeUInt32BE(1,4);fat.writeUInt32BE(64,16);fat.writeUInt32BE(thin.length,20);thin.copy(fat,64);const universal=staticAnalysis(fat,'universal');assert.equal(universal.details.sections[0].entropy,8);assert.equal(universal.details.sections[0].fileOffset,248);assert(universal.findings.some(x=>x.rule==='EXEC-ENTROPY'));console.log('PASS: universal Mach-O section entropy uses architecture-relative bytes.');
