import {SHA256} from './sha256.js';
self.onmessage=()=>{const b=new Uint8Array(1024*1024);for(let i=0;i<b.length;i++)b[i]=i&255;new SHA256().update(b);const t=performance.now();for(let i=0;i<8;i++)new SHA256().update(b).digest();self.postMessage({mbps:8/Math.max(.001,(performance.now()-t)/1000)});};
