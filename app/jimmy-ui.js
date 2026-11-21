/* NetSec 1.2.0 — focused analyst workspace and opt-in PWA push. */
(() => {
'use strict';
const el=id=>document.getElementById(id);
const field=(tag,cls,text)=>{const n=document.createElement(tag);if(cls)n.className=cls;if(text!==undefined)n.textContent=String(text);return n;};
const status=el('jimmyWorkspaceStatus');
if(!status)return;
let currentId='',selectedId='',currentReport=null;
function message(s){status.textContent=s;}
function post(path,body){return fetch(path,{method:'POST',credentials:'same-origin',cache:'no-store',
  headers:{'Content-Type':'application/json','X-NetSec-Action':'dashboard'},body:JSON.stringify(body)}).then(async r=>{
    const j=await r.json();if(!r.ok||!j.ok)throw new Error(j.error||'HTTP '+r.status);return j;
  });}
function kv(id,v){el(id).textContent=String(v??'—');}
function draw(report,items,feedback,incidents){
  currentReport=report;
  if(report){
    kv('jimmyReportId',selectedId);kv('jimmyReportTime',report.updated_at);
    kv('jimmyReportSeverity',(report.severity||'unknown').toUpperCase());
    kv('jimmyReportSummary',report.summary);
    const risk=report.risk_assessment||{};
    kv('jimmyReportEvidence',(risk.reasons||[]).join(' · ')||'No verified reason supplied');
    kv('jimmyReportLimits',risk.limitations||report.warning||'Read-only bounded evidence');
  } else {
    kv('jimmyReportId','No assessment');kv('jimmyReportTime','—');kv('jimmyReportSeverity','NOT CONFIGURED');
    kv('jimmyReportSummary','Run a successful Jimmy assessment before starting a linked conversation.');
    kv('jimmyReportEvidence','No evidence');kv('jimmyReportLimits','—');
  }
  const list=el('jimmyChatLog');list.replaceChildren();
  for(const line of items||[]){
    const row=field('div','jimmy-msg '+(line.role==='user'?'from-operator':'from-jimmy'));
    row.append(field('strong','',line.role==='user'?'Operator':'Jimmy'),field('div','',line.content),field('small','',line.at||''));
    list.append(row);
  }
  if(!items?.length)list.append(field('div','jimmy-placeholder','Ask Jimmy about the latest findings, earlier assessments, or what to investigate next.'));
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
  const active=!!report;
  el('jimmyChatForm').querySelector('button[type=submit]').disabled=!active;

}
async function load(requested=''){
  message('Loading assessment workspace…');
  try{
    const q=requested?'?report_id='+encodeURIComponent(requested):'';
    const r=await fetch('/api/jimmy/workspace'+q,{cache:'no-store',credentials:'same-origin'});
    const d=await r.json();if(!r.ok||!d.ok)throw new Error(d.error||'HTTP '+r.status);
    currentId=d.current_report_id||'';selectedId=d.report_id||'';
    draw(d.report,d.messages,d.feedback,d.incidents);
    message(selectedId?'Assessment loaded · conversation continues across reports.':'No successful assessment found.');
  }catch(e){message('Workspace unavailable: '+e.message);}
}
el('jimmyChatForm').addEventListener('submit',async e=>{
  e.preventDefault();const input=el('jimmyQuestion');const msg=input.value.trim();if(!msg||!selectedId)return;
  const send=el('jimmyChatForm').querySelector('button[type=submit]');send.disabled=true;message('Jimmy is investigating…');
  try{const r=await post('/api/jimmy/chat',{report_id:selectedId,message:msg});input.value='';await load(selectedId);
       message('Jimmy answered · conversation saved.');}
  catch(ex){message('Jimmy chat error: '+ex.message);}finally{send.disabled=false;}
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
