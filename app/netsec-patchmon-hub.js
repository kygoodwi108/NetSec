/* NetSec PatchMon Command Hub: authenticated read-only host inventory, not a reachability badge. */
(() => {
'use strict';
const el = id => document.getElementById(id);
const make = (tag, text='', cls='') => {
  const n=document.createElement(tag);
  if(cls)n.className=cls;
  n.textContent=String(text ?? '');
  return n;
};
let lastLoad=0, busy=false;
function set(id, value){const n=el(id);if(n)n.textContent=String(value??'—');}
function summary(value){return Number.isFinite(value)?value.toLocaleString():'—';}
function render(data){
  const state=data.state||'unavailable', hosts=el('patchmonHubHosts');
  if(!hosts)return;
  const link=el('patchmonHubLink');
  if(link){link.hidden=!data.public_url;if(data.public_url)link.href=data.public_url;}
  const ready=state==='ready';
  set('patchmonHubState',ready?'Authenticated · Host inventory':{
    reachability_only:data.status==='up'?'Reachable · HTTP '+data.http_code:'Unreachable',
    not_configured:'Not configured',needs_credentials:'Read-only token required',
    credential_error:'Credential file issue',access_denied:'API access denied',
    unavailable:'API unavailable',api_error:'PatchMon API error',invalid_config:'Invalid endpoint'
  }[state]||'Unknown state');
  set('patchmonHubSecurity',ready?summary(data.security_updates):'—');
  set('patchmonHubUpdates',ready?summary(data.updates):'—');
  set('patchmonHubReport',ready?summary(data.hosts_stale_or_overdue):'—');
  set('patchmonHubReboots',ready?summary(data.hosts_need_reboot):'—');
  set('patchmonHubScope',ready?'Read-only host:get · '+(data.displayed_hosts??0)+'/'+(data.total_hosts??'?')+' host(s) · checked '+(data.checked_at||'unknown'):'Read-only API · '+String(data.reason||'No authenticated inventory available'));
  hosts.replaceChildren();
  if(!ready){hosts.append(make('p',data.reason||'PatchMon data not available.','subtle tiny'));return;}
  const list=Array.isArray(data.hosts)?data.hosts:[];
  if(!list.length){hosts.append(make('p','PatchMon has no enrolled hosts to analyze. Enroll hosts in PatchMon first.','subtle tiny'));return;}
  const wrap=make('div','','table-scroll');
  const table=make('table','','hub-table');
  const head=make('thead'),heading=make('tr');
  ['Host','Reporting','Updates','Security','Reboot','Recent pending packages'].forEach(t=>heading.append(make('th',t)));
  head.append(heading);table.append(head);
  const body=make('tbody');
  for(const host of list.slice(0,24)){
    const tr=make('tr');
    const name=make('td');name.append(make('strong',host.name||'Unnamed'));
    name.append(make('div',[host.ip,host.os].filter(Boolean).join(' · '),'subtle tiny'));
    tr.append(name, make('td',host.reporting||host.effective_status||'unknown'),
      make('td',summary(host.updates)),make('td',summary(host.security_updates)),
      make('td',host.needs_reboot?'Required':'—'));
    const pkg=make('td');
    if(host.packages?.length){
      const parts=host.packages.slice(0,4).map(p=>p.name+(p.security?' [security]':''));
      pkg.textContent=parts.join(', ');
    }else pkg.textContent=(Number(host.updates)>0)?'Details not available':'—';
    tr.append(pkg);body.append(tr);
  }
  table.append(body);wrap.append(table);hosts.append(wrap);
  const notes=[];
  if(data.partial)notes.push('Host inventory truncated; totals shown may be incomplete.');
  if(data.detail_fetch_failures)notes.push(data.detail_fetch_failures+' package detail request(s) failed.');
  notes.push('Available updates do not establish exploitation; stale agents limit confidence.');
  hosts.append(make('p',notes.join(' '),'subtle tiny'));
}
async function load(force=false){
 if(busy||!el('patchmonHubPanel'))return;
 if(!force&&Date.now()-lastLoad<45000)return;
 busy=true;
 const reload=el('patchmonHubRefresh');if(reload)reload.disabled=true;
 set('patchmonHubState','Checking authenticated PatchMon API…');
 try{
   const r=await fetch('/api/integrations/patchmon',{cache:'no-store',credentials:'same-origin'});
   const data=await r.json();
   if(!r.ok||!data.ok)throw new Error(data.error||'HTTP '+r.status);
   render(data);lastLoad=Date.now();
 }catch(e){
   render({state:'unavailable',reason:'NetSec integration request failed: '+e.message});
 }finally{busy=false;if(reload)reload.disabled=false;}
}
const button=el('patchmonHubRefresh');if(button)button.addEventListener('click',()=>load(true));
el('patchmonHubAsk')?.addEventListener('click',()=>{
 const nav=document.querySelector('.nav [data-hub-tab="jimmy"]');nav?.click();
 const q=el('jimmyQuestion');if(q){q.value='Analyze the latest PatchMon host inventory: identify specific hosts with security updates, stale agents and reboots, and name verified outdated packages where available. Prioritize legitimate concerns and explain uncertainty. Do not execute changes.';q.focus();}
});
document.querySelector('.nav [data-hub-tab="command"]')?.addEventListener('click',()=>load());
load(true);
setInterval(()=>{if(!el('hub-tab-command')?.hidden)load();},60000);
})();
