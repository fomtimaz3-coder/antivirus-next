const CACHE='anti-wiew-2.1.0';
const ASSETS=['./','./index.html','./app.js','./style.css','./worker.js','./sha256.js','./archive.js','./scheduler.js','./ui-logic.js','./manifest.webmanifest','./icon.svg','./icon-192.png','./icon-512.png'];
self.addEventListener('install',e=>e.waitUntil(caches.open(CACHE).then(async cache=>{for(const url of ASSETS){const r=await fetch(url,{cache:'reload'});if(!r.ok||r.redirected)throw Error('Offline asset unavailable');await cache.put(url,r)}})));
self.addEventListener('activate',e=>e.waitUntil((async()=>{for(const k of await caches.keys())if(k.startsWith('anti-wiew-')&&k!==CACHE)await caches.delete(k);await self.clients.claim()})()));
self.addEventListener('message',e=>{if(e.data?.type==='ACTIVATE')self.skipWaiting()});
self.addEventListener('fetch',e=>{const u=new URL(e.request.url);if(e.request.method!=='GET'||u.origin!==self.location.origin||u.pathname.endsWith('/version.json'))return;e.respondWith(caches.open(CACHE).then(async cache=>(await cache.match(e.request,{ignoreSearch:true}))||fetch(e.request)))});
