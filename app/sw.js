/* NetSec PWA: cache only a generic offline help page, never authenticated telemetry. */
const CACHE='netsec-shell-1.1.0';
self.addEventListener('install',e=>{e.waitUntil(caches.open(CACHE).then(c=>c.add('/offline.html')));self.skipWaiting();});
self.addEventListener('activate',e=>{e.waitUntil(caches.keys().then(names=>Promise.all(names.filter(n=>n!==CACHE).map(n=>caches.delete(n)))));self.clients.claim();});
self.addEventListener('fetch',e=>{
  if(e.request.mode==='navigate'){
    e.respondWith(fetch(e.request,{cache:'no-store'}).catch(()=>caches.match('/offline.html')));
  }
});
self.addEventListener('push',e=>{
  let obj={};try{obj=e.data?.json()||{};}catch(_e){}
  const url=typeof obj.url==='string'&&obj.url.startsWith(self.location.origin+'/#jimmy')?obj.url:self.location.origin+'/#jimmy';
  const title=typeof obj.title==='string'?obj.title:'NetSec security notice';
  const body=typeof obj.body==='string'?obj.body:'Sign in to NetSec to review.';
  e.waitUntil(self.registration.showNotification(title,{body,tag:obj.tag||'netsec-alert',icon:'/icon-192.png',badge:'/icon-192.png',data:{url}}));
});
self.addEventListener('notificationclick',e=>{
  e.notification.close();const url=e.notification.data?.url||self.location.origin+'/#jimmy';
  e.waitUntil(self.clients.matchAll({type:'window',includeUncontrolled:true}).then(async clients=>{
    for(const c of clients){if(new URL(c.url).origin===self.location.origin){await c.focus();await c.navigate(url);return;}}
    return self.clients.openWindow(url);
  }));
});
