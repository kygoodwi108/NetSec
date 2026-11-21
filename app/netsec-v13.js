/* NetSec v1.3 — Unified Source Intelligence & bounded request explorer. */
(() => {
'use strict';
const $=id=>document.getElementById(id);
const make=(tag,cls,value)=>{
  const e=document.createElement(tag);
  if(cls)e.className=cls;
  if(value!==undefined)e.textContent=String(value);
  return e;
};
const root=$('hub-tab-intel'),rows=$('hubConnRows');
if(!root||!rows)return;
let manual={},ai={},activeIP='',page=0,windowKey='24h',status='all',term='',response=null,serial=0;
function notify(text){const e=$('v13Notice');if(e)e.textContent=text;else console.info(text);}
const post=async(path,payload)=>{
  const response=await fetch(path,{method:'POST',credentials:'same-origin',cache:'no-store',
    headers:{'Content-Type':'application/json','X-NetSec-Action':'dashboard'},body:JSON.stringify(payload)});
  const data=await response.json();if(!response.ok||!data.ok)throw Error(data.error||'HTTP '+response.status);return data;
};
async function refreshLabels(){
  try{
    const r=await fetch('/api/source-labels',{credentials:'same-origin',cache:'no-store'});
    const j=await r.json();if(!r.ok||!j.ok)throw Error(j.error||'Cannot load labels');
    manual=j.labels||{};ai=j.ai||{};decorate();
  }catch(ex){notify('Source metadata unavailable: '+ex.message);}
}
const options=[['unknown','Unconfirmed'],['friendly','Friendly'],['watch','Watch'],['routine','Routine'],['scanner','Scanner'],['suspicious','Suspicious'],['hostile','Hostile']];
async function setClass(ip,value,oldValue){
  if(value==='friendly'&&!confirm('Confirm '+ip+' is personally known or explicitly trusted? This changes classification, NOT CrowdSec enforcement.'))return false;
  if(value==='hostile'&&!confirm('Mark '+ip+' hostile? This label does not ban the address.'))return false;
  const label=value==='unknown'?'':prompt('Optional descriptive label for '+ip+':',manual[ip]?.label||ip);
  if(label===null)return false;
  const result=await post('/api/intel/label',{ip,status:value,label});
  if(result.metadata)manual[ip]=result.metadata;else delete manual[ip];
  notify(ip+' classified '+value+'. Saved to operator metadata.');
  document.dispatchEvent(new Event('netsec-sources-changed'));
  return true;
}
function clearlyLocal(ip){
  return /^(127\.|10\.|192\.168\.|169\.254\.|0\.|::1$|fc|fd|fe80:)/i.test(ip)||
    /^172\.(1[6-9]|2\d|3[01])\./.test(ip);
}
async function ban(ip,button){
  if(manual[ip]?.status==='friendly'||clearlyLocal(ip))return notify('Protected or local IP cannot be banned.');
  const duration=prompt('CrowdSec ban duration for '+ip+' (1h, 4h, 24h):','1h');
  if(duration===null)return;
  if(!['1h','4h','24h'].includes(duration.trim()))return notify('Ban not requested: choose 1h, 4h or 24h.');
  if(!confirm('Queue a '+duration+' CrowdSec ban for '+ip+'? This may affect access to your Nginx sites.'))return;
  button.disabled=true;
  try{
    const result=await post('/api/ban',{ip,duration:duration.trim()});
    notify('CrowdSec request queued for '+ip+'. Worker confirmation and enforcement are separate.');
    const jobId=result.job_id;
    if(jobId&&/^[a-f0-9]{24}$/.test(jobId)){
      // A bounded progress check, not a claim that enforcement has been verified.
      for(let i=0;i<8;i++){
        await new Promise(resolve=>setTimeout(resolve,750));
        const resp=await fetch('/api/ban/job?id='+encodeURIComponent(jobId),{credentials:'same-origin',cache:'no-store'});
        if(!resp.ok)break;
        const job=await resp.json();
        if(job.state==='added'){notify('CrowdSec decision added for '+ip+'. Verify bouncer enforcement separately.');return;}
        if(job.state==='failed'){notify('Ban failed: '+(job.error||'worker rejected request'));return;}
      }
      notify('Ban still pending. Check the CrowdSec worker status.');
    }
  }catch(ex){notify('Ban not queued: '+ex.message);}
  finally{button.disabled=false;}
}
function decorate(){
  const header=rows.closest('table')?.querySelector('thead tr');
  if(header&&!header.querySelector('[data-v13-action]')){
    const th=make('th','','Actions');th.dataset.v13Action='1';header.append(th);
  }
  for(const tr of rows.querySelectorAll('tr')){
    const ipbtn=tr.querySelector('.hub-ip-button');
    if(!ipbtn||tr.dataset.v13Applied==='1')continue;
    const ip=ipbtn.textContent.trim(),cell=tr.children[1];
    if(!cell)continue;
    tr.dataset.v13Applied='1';
    const old=cell.querySelector('.hub-pill:not(.flag)');
    if(old)old.remove();
    const select=make('select','v13-classify');
    select.setAttribute('aria-label','Classification for '+ip);
    let selected=manual[ip]?.status||(tr.querySelector('.hub-pill.trusted')?'friendly':'unknown');
    for(const [value,label] of options){const opt=make('option','',label);opt.value=value;select.append(opt);}
    if(!options.some(x=>x[0]===selected))selected='unknown';
    select.value=selected;select.dataset.value=selected;
    select.addEventListener('change',async()=>{
      const old=select.dataset.value,newValue=select.value;select.disabled=true;
      try{
        const saved=await setClass(ip,newValue,old);
        if(saved){select.dataset.value=newValue;select.dataset.value=newValue;select.dataset.value=newValue;select.dataset.value=newValue;}
        else select.value=old;
      }catch(ex){select.value=old;notify('Classification failed: '+ex.message);}
      finally{select.disabled=false;select.dataset.value=select.value;}
    });
    cell.prepend(select);
    const action=make('td','v13-source-action');
    const banButton=make('button','btn v13-ban','Ban');
    banButton.type='button';banButton.disabled=selected==='friendly'||clearlyLocal(ip);
    banButton.title=banButton.disabled?'Protected/local sources cannot be banned':'Queue a manual CrowdSec ban';
    banButton.addEventListener('click',()=>ban(ip,banButton));
    action.append(banButton);tr.append(action);
    ipbtn.title='Explore every available recorded HTTP request';
    ipbtn.setAttribute('aria-label','Inspect individual HTTP requests from '+ip);
    ipbtn.addEventListener('click',()=>{activeIP=ip;page=0;windowKey=$('hubConnPeriods')?.querySelector('.active')?.dataset.window||'24h';status='all';term='';setTimeout(openExplorer,0);});
  }
}
const observer=new MutationObserver(()=>decorate());
observer.observe(rows,{childList:true});
function controls(){
  const wrapper=make('section','v13-explorer');wrapper.id='v13Explorer';
  const h=make('h3','', 'Individual HTTP requests · '+activeIP);
  const note=make('p','subtle tiny','Only requests present in readable Nginx logs are shown. Query strings, credentials and headers are excluded.');
  const bar=make('div','v13-explorer-controls');
  const windowSelect=make('select');windowSelect.setAttribute('aria-label','Request history window');
  for(const v of ['1h','24h','7d']){const o=make('option','',v);o.value=v;windowSelect.append(o);}
  windowSelect.value=windowKey;windowSelect.onchange=()=>{windowKey=windowSelect.value;page=0;loadRequests();};
  const codeSelect=make('select');codeSelect.setAttribute('aria-label','Filter HTTP responses');
  for(const v of ['all','2xx','3xx','4xx','5xx']){const o=make('option','',v.toUpperCase());o.value=v;codeSelect.append(o);}
  codeSelect.value=status;codeSelect.onchange=()=>{status=codeSelect.value;page=0;loadRequests();};
  const search=make('input');search.type='search';search.placeholder='Search request paths';search.maxLength=100;search.value=term;
  let timeout;search.oninput=()=>{term=search.value.trim();page=0;clearTimeout(timeout);timeout=setTimeout(loadRequests,350);};
  const exportButton=make('button','btn','Export current page');exportButton.type='button';
  exportButton.onclick=()=>{
    if(!response?.records?.length)return;
    const fields=['at','method','path','status','bytes','probe_like'];
    const quote=v=>'"'+String(v??'').replace(/"/g,'""')+'"';
    const lines=[fields.join(','),...response.records.map(r=>fields.map(k=>quote(r[k])).join(','))];
    const blob=new Blob([lines.join('\r\n')],{type:'text/csv;charset=utf-8'});
    const u=URL.createObjectURL(blob);const a=document.createElement('a');a.href=u;a.download='netsec-'+activeIP+'-requests.csv';a.click();setTimeout(()=>URL.revokeObjectURL(u),2000);
  };
  const ask=make('button','btn','Ask Jimmy about this IP');ask.type='button';
  ask.onclick=()=>{
    const patterns=(response?.records||[]).slice(0,12).map(r=>r.method+' '+r.path+' HTTP '+r.status).join('; ');
    const promptText='Investigate source IP '+activeIP+' using available verified telemetry and explain whether it merits action. Current explorer window: '+windowKey+'. Example observed requests (sanitized and bounded): '+patterns+'. Distinguish missing evidence from observed traffic.';
    location.hash='jimmy';document.querySelector('[data-hub-tab="jimmy"]')?.click();
    const text=$('jimmyQuestion');if(text){text.value=promptText.slice(0,2000);text.focus();}
  };
  bar.append(windowSelect,codeSelect,search,exportButton,ask);
  const scroller=make('div','table-scroll');scroller.style.maxHeight='420px';
  const table=make('table','v13-explorer-table');
  const head=make('thead'),tr=make('tr');
  for(const label of ['UTC time','Method','Request path','HTTP','Bytes'])tr.append(make('th','',label));
  head.append(tr);table.append(head);
  const body=make('tbody');body.id='v13RequestRows';table.append(body);scroller.append(table);
  const controls=make('div','v13-explorer-controls');
  const back=make('button','btn','← Previous');back.id='v13Back';back.type='button';back.onclick=()=>{page=Math.max(0,page-100);loadRequests();};
  const forward=make('button','btn','Next →');forward.id='v13Forward';forward.type='button';forward.onclick=()=>{if(response?.next_offset!=null){page=response.next_offset;loadRequests();}};
  controls.append(back,forward);
  const meta=make('div','v13-explorer-status','Loading request history…');meta.id='v13RequestStatus';
  wrapper.append(h,note,bar,scroller,controls,meta);
  return wrapper;
}
function openExplorer(){
  const detail=$('hubConnDetail');if(!detail||!activeIP)return;
  detail.querySelector('#v13Explorer')?.remove();
  detail.append(controls());loadRequests();
}
async function loadRequests(){
  const id=++serial;
  const body=$('v13RequestRows'),meta=$('v13RequestStatus');
  if(!body||!meta)return;
  meta.textContent='Loading actual Nginx requests…';
  const query=new URLSearchParams({ip:activeIP,window:windowKey,offset:String(page),limit:'100',status,search:term});
  try{
    const req=await fetch('/api/source-requests?'+query,{credentials:'same-origin',cache:'no-store'});
    const data=await req.json();if(id!==serial)return;
    if(!req.ok||!data.ok)throw Error(data.error||'Request explorer unavailable');
    response=data;body.replaceChildren();
    for(const r of data.records){
      const tr=make('tr');
      for(const field of ['at','method','path','status','bytes']){
        const td=make('td','',r[field]);if(field==='path')td.title=r.path;tr.append(td);
      }
      body.append(tr);
    }
    if(!data.records.length){const tr=make('tr'),td=make('td','','No matching request records in available logs.');td.colSpan=5;tr.append(td);body.append(tr);}
    $('v13Back').disabled=page===0;$('v13Forward').disabled=data.next_offset===null;
    const coverage=data.coverage||{};
    meta.textContent='Showing '+data.records.length+' requests starting at '+(page+1)+' of '+data.matching_records+
      ' observed matching rows · '+coverage.log_files_readable+' readable log file(s). '+
      (coverage.complete?'All matching records within scanned retention were available.':'INCOMPLETE COVERAGE: bounded or missing log data. ')+
      (coverage.warnings?.length?coverage.warnings.join('; '):'');
  }catch(ex){if(id===serial)meta.textContent='Unable to load request history: '+ex.message;}
}
const notice=make('p','v13-explorer-status','');notice.id='v13Notice';notice.setAttribute('role','status');
const detail=$('hubConnDetail');
if(detail)detail.after(notice);
const nav=document.querySelector('.nav');
nav?.querySelector('[data-hub-tab="connections"]')?.remove();
refreshLabels();decorate();
document.addEventListener('netsec-sources-changed',refreshLabels);
const changes=new MutationObserver(()=>{if(!$('hub-tab-intel')?.hidden)refreshLabels();});
const labelTable=$('intelLabels');if(labelTable)changes.observe(labelTable,{childList:true});
})();
