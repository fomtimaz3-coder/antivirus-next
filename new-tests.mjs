import assert from 'node:assert/strict';import {parseMachO} from './macho.js';import handler from './api/reputation.mjs';
for(const le of [true,false]){const b=new Uint8Array(32),d=new DataView(b.buffer);d.setUint32(0,0xfeedfacf,le);d.setUint32(4,0x1000007,le);assert.equal(parseMachO(b).bits,64);d.setUint32(16,1,le);assert.throws(()=>parseMachO(b));}
const fat=new Uint8Array(64),d=new DataView(fat.buffer);d.setUint32(0,0xcafebabe);d.setUint32(4,1);d.setUint32(16,32);d.setUint32(20,32);d.setUint32(32,0xfeedfacf,true);assert.equal(parseMachO(fat).architectures.length,1);d.setUint32(16,1000);assert.throws(()=>parseMachO(fat));
let answer;const res={setHeader(){},status(n){this.code=n;return this},json(x){answer=x;return this}};const originalFetch=globalThis.fetch;let calls=0;
globalThis.fetch=async(url,options)=>{calls++;assert.equal(url,'https://mb-api.abuse.ch/api/v1/');assert.equal(options.headers['Auth-Key'],'test-key');assert.equal(new URLSearchParams(options.body).get('query'),'get_info');return {ok:true,json:async()=>({query_status:'ok',data:[{sha256_hash:'a'.repeat(64),signature:'fixture'}]})}};
await handler({method:'POST',headers:{host:'test','x-abuse-key':'test-key'},body:{sha256:'a'.repeat(64),provider:'MalwareBazaar'}},res);assert.equal(answer.status,'detections');assert.equal(calls,1);
await handler({method:'POST',headers:{host:'test'},body:{sha256:'a'.repeat(64),provider:'arbitrary-host'}},res);assert.equal(res.code,400);assert.equal(calls,1);
await handler({method:'POST',headers:{host:'test'},body:{sha256:'a'.repeat(64),file:'bytes'}},res);assert.equal(res.code,400);
globalThis.fetch=originalFetch;console.log('PASS: Mach-O endian/universal/bounds; reputation fixed-host, matching hash, body validation. Mocked service responses, not live credentials.');
