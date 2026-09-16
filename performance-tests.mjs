import assert from 'node:assert/strict';
import {Worker as NodeWorker} from 'node:worker_threads';
import {yaraScan,disposeYara} from './yara.js';
import {scanNative} from './scripts/validate-rules.mjs';
let created=0;
globalThis.Worker=class{
 constructor(){created++;this.w=new NodeWorker(new URL('./test/runner-node.mjs',import.meta.url));this.w.on('message',data=>this.onmessage?.({data}));this.w.on('error',e=>this.onerror?.(e))}
 postMessage(data,transfer){this.w.postMessage(data,transfer)}terminate(){this.w.terminate()}
};
const rules='rule hit { strings: $a="needle" condition: $a }';
try{
 const inputs=['needle','normal','needle repeated','', 'other'];
 const expected=await Promise.all(inputs.map(x=>scanNative(new TextEncoder().encode(x),rules)));
 const actual=await Promise.all(inputs.map(x=>yaraScan(new Blob([x]),rules)));
 assert.deepEqual(actual.map(x=>x.matches),expected);assert.equal(created,1,'one worker for serialised concurrent requests');
 const bad=await yaraScan(new Blob(['needle']),'not a valid rule');assert(bad.error);
 assert.deepEqual((await yaraScan(new Blob(['needle']),rules)).matches,['hit']);assert.equal(created,2,'failed instance recycled');
 disposeYara();assert.deepEqual((await yaraScan(new Blob(['needle']),rules)).matches,['hit']);assert.equal(created,3);
 console.log('PASS: persistent real WASM runner, matching results, serialized requests, failure recovery and disposal.');
}finally{disposeYara()}
