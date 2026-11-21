/* NetSec v1.3 — dark conversation, optimistic send, read-only assessment history. */
(() => {
'use strict';
const el=id=>document.getElementById(id);
const field=(tag,cls,text)=>{const n=document.createElement(tag);if(cls)n.className=cls;if(text!==undefined)n.textContent=String(text);return n;};
const status=el('jimmyWorkspaceStatus');
if(!status)return;
let currentId='',selectedId='',currentReport=null,sending=false,transient=null;
function message(s){status.textContent=s;}
function post(path,body){return fetch(path,{method:'POST',credentials:'same-origin',cache:'no-store',
  headers:{'Content-Type':'application/json','X-NetSec-Action':'dashboard'},body:JSON.stringify(body)}).then(async r=>{
    const j=await r.json();if(!r.ok||!j.ok)throw new Error(j.error||'HTTP '+r.status);return j;
  });}
function kv(id,v){el(id).textContent=String(v??'—');}
function toBottom(){const list=el('jimmyChatLog');list.scrollTop=list.scrollHeight;}
function contentText(node,body){
  // Render a deliberately small Markdown subset with DOM text nodes, never innerHTML.
  const lines=String(body||'').split('\n');
  for(let i=0;i<lines.length;i++){
    if(i)node.append(document.createElement('br'));
    const fragments=lines[i].split(/(\*\*[^*]+\*\*|`[^`]+`)/g);
    for(const part of fragments){
      if(part.startsWith('**')&&part.endsWith('**')&&part.length>4){
        node.append(field('strong','',part.slice(2,-2)));
      }else if(part.startsWith('\x60')&&part.endsWith('\x60')&&part.length>2){
        node.append(field('code','',part.slice(1,-1)));
      }else node.append(document.createTextNode(part));
    }
  }
}
function bubble(role,body,at='',pending=false){
  const row=field('div','jimmy-msg '+(role==='user'?'from-operator':'from-jimmy')+(pending?' jimmy-pending':''));
  const text=field('div','jimmy-bubble-text');
  contentText(text,body);
  row.append(text);
  if(at)row.append(field('small','',at));
  return row;
}
function draw(report,items,feedback,incidents){
  currentReport=report;
  const list=el('jimmyChatLog');list.replaceChildren();
  for(const line of items||[])list.append(bubble(line.role,line.content,line.at||''));
  if(transient){
    list.append(bubble('user',transient.message,transient.failed?'Not sent':'Sent · waiting for Jimmy',!transient.failed));
    if(transient.failed){
      const retry=field('button','btn','Retry message');retry.type='button';
      retry.onclick=()=>{el('jimmyQuestion').value=transient.message;transient=null;draw(currentReport,items,feedback,incidents);el('jimmyQuestion').focus();};
      list.append(retry);
    }else{
      const typing=field('div','jimmy-msg from-jimmy jimmy-typing','●  ●  ●');
      typing.setAttribute('aria-label','Jimmy is typing');list.append(typing);
    }
  }
  if(!items?.length&&!transient)list.append(field('div','jimmy-placeholder','Ask Jimmy about incidents, source IPs, or changes between assessments.'));
  const ibox=el('jimmyIncidents');ibox.replaceChildren();
  for(const incident of (incidents||[]).slice(0,6)){
    const row=field('div','jimmy-incident');
    row.append(field('span','',incident.created_at+' · '+(incident.ack_at?'ACKNOWLEDGED':'Needs review')));
    if(!incident.ack_at){const b=field('button','btn','Acknowledge');b.type='button';b.onclick=async()=>{
      try{await post('/api/jimmy/ack',{incident_id:incident.id});await load();}catch(e){message(e.message);}
    };row.append(b);}
    ibox.append(row);
  }
  if(!ibox.children.length)ibox.append(field('div','jimmy-placeholder','No evidence-calibrated red incidents recorded.'));
  const send=el('jimmyChatForm').querySelector('button[type=submit]');
  send.disabled=!report||sending;
  send.textContent=sending?'Jimmy is responding…':'Send';
  toBottom();
}

async function load(requested=''){
  message('Loading assessment workspace…');
  try{
    const q=requested?'?report_id='+encodeURIComponent(requested):'';
    const r=await fetch('/api/jimmy/workspace'+q,{cache:'no-store',credentials:'same-origin'});
    const d=await r.json();if(!r.ok||!d.ok)throw new Error(d.error||'HTTP '+r.status);
    currentId=d.current_report_id||'';selectedId=d.report_id||'';
    draw(d.report,d.messages,d.feedback,d.incidents);
    window.netsecJimmyActionPlan?.(d.report);
    message(selectedId?'Assessment loaded · conversation continues across reports.':'No successful assessment found.');
  }catch(e){message('Workspace unavailable: '+e.message);}
}
el('jimmyChatForm').addEventListener('submit',async e=>{
  e.preventDefault();
  const input=el('jimmyQuestion'),msg=input.value.trim();
  if(!msg||!selectedId||sending)return;
  sending=true;transient={message:msg,failed:false};input.value='';
  const log=el('jimmyChatLog');
  log.append(bubble('user',msg,'Sent · waiting for Jimmy',true));
  const typing=field('div','jimmy-msg from-jimmy jimmy-typing','●  ●  ●');
  typing.setAttribute('aria-label','Jimmy is typing');log.append(typing);
  const send=el('jimmyChatForm').querySelector('button[type=submit]');
  send.disabled=true;send.textContent='Jimmy is responding…';toBottom();
  message('Message sent · Jimmy is investigating…');
  try{
    await post('/api/jimmy/chat',{report_id:selectedId,message:msg});
    transient=null;sending=false;await load(selectedId);
    message('Jimmy answered · conversation saved.');
  }catch(ex){
    sending=false;transient={message:msg,failed:true};
    typing.remove();message('Jimmy chat error: '+ex.message);
    // Restore a failed message as editable text and keep it visible as unsent.
    if(!input.value.trim())input.value=msg;
    log.append(field('div','jimmy-send-error','Not delivered. You can retry without losing the text.'));
    send.disabled=false;send.textContent='Send';
  }finally{
    if(!sending){send.disabled=!currentReport;send.textContent='Send';}
  }
});
el('jimmyReload').onclick=()=>load();
el('jimmyLatest').onclick=()=>{history.replaceState(null,'','#jimmy');load();};
el('jimmyQuiet').onclick=async()=>{try{const hours=Number(el('jimmyQuietHours').value);await post('/api/jimmy/quiet',{hours});message(hours?'Notifications quiet for '+hours+' hours.':'Quiet period removed.');}
  catch(e){message('Quiet period not saved: '+e.message);}};
el('jimmyEscalation').onclick=async()=>{try{const hours=Number(el('jimmyEscalationHours').value);
  await post('/api/jimmy/escalation',{hours});message(hours?'One reminder after '+hours+' hours without acknowledgement.':'Escalation disabled.');}
  catch(e){message('Escalation not saved: '+e.message);}};
const decodeKey=s=>{const b64=s.replace(/-/g,'+').replace(/_/g,'/');const raw=atob(b64+'='.repeat((4-b64.length%4)%4));return Uint8Array.from(raw,c=>c.charCodeAt(0));};
async function pushInfo(){
  try{const r=await fetch('/api/push/status',{cache:'no-store'});const d=await r.json();
    if(el('jimmyEscalationHours'))el('jimmyEscalationHours').value=String(d.escalation_after_hours||0);
    kv('jimmyPushState',d.enabled?'Push ready · '+d.subscribers+' subscribed device(s)':'Push not configured on server');
    return d;
  }catch(e){kv('jimmyPushState','Push status unavailable');return null;}
}
el('jimmyPushEnable').onclick=async()=>{
  try{
    const d=await pushInfo();if(!d?.enabled)throw new Error('Enable Web Push during installation first.');
    if(!('serviceWorker' in navigator)||!('PushManager' in window)||!('Notification' in window))throw new Error('This device/browser does not support Web Push.');
    const perm=await Notification.requestPermission();if(perm!=='granted')throw new Error('Notification permission not granted.');
    const reg=await navigator.serviceWorker.ready;
    let sub=await reg.pushManager.getSubscription();
    if(!sub)sub=await reg.pushManager.subscribe({userVisibleOnly:true,applicationServerKey:decodeKey(d.public_key)});
    await post('/api/push/subscribe',{subscription:sub.toJSON()});message('Notifications enabled on this device.');await pushInfo();
  }catch(e){message('Cannot enable notifications: '+e.message);}
};
el('jimmyPushTest').onclick=async()=>{try{const d=await post('/api/push/test',{});message('Test sent to '+d.delivered+' device(s); '+d.failed+' failed.');}
  catch(e){message('Push test: '+e.message);}};
el('jimmyPushDisable').onclick=async()=>{try{const reg=await navigator.serviceWorker.ready;const s=await reg.pushManager.getSubscription();
   if(s){await post('/api/push/unsubscribe',{endpoint:s.endpoint});await s.unsubscribe();}message('Notifications disabled on this device.');await pushInfo();}
   catch(e){message('Disable failed: '+e.message);}};
if('serviceWorker' in navigator){navigator.serviceWorker.register('/sw.js',{scope:'/'}).catch(e=>console.warn('NetSec offline shell not available',e.name));}
// Only offline.html is cached by the service worker. No authenticated API data is cached.
const deep=location.hash.match(/^#jimmy&report=([0-9a-f]{24})$/);
load(deep?deep[1]:'');pushInfo();
document.querySelector('[data-hub-tab="jimmy"]')?.addEventListener('click',()=>{if(!selectedId)load();});
window.netsecJimmySummary=ai=>{
  const elem=el('jimmyCommandSummary');
  if(elem)elem.textContent='Jimmy: '+String(ai.severity||'unknown').toUpperCase()+' · '+String(ai.summary||'No recent assessment').slice(0,180);
};
})();
