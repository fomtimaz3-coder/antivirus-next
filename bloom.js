export class Bloom{
 constructor(n){this.bits=new Uint8Array(Math.max(8,Math.ceil(n*12/8)));}
 indices(hex){let a=2166136261,b=0x9e3779b9;for(let i=0;i<hex.length;i++){a=Math.imul(a^hex.charCodeAt(i),16777619)>>>0;b=Math.imul(b^hex.charCodeAt(i),2246822519)>>>0}return Array.from({length:7},(_,i)=>((a+Math.imul(i,b|1))>>>0)%(this.bits.length*8))}
 add(hash){for(const n of this.indices(hash))this.bits[n>>3]|=1<<(n&7)}
 has(hash){return this.indices(hash).every(n=>this.bits[n>>3]&(1<<(n&7)))}
}
export function hashIndex(records){const bloom=new Bloom(records.length),map=new Map();for(const r of records){bloom.add(r.sha256);map.set(r.sha256,r)}return {find:hash=>typeof hash==='string'&&bloom.has(hash)?map.get(hash):undefined,size:map.size}}
