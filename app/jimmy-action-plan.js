/* Jimmy Action Plan: evidence-linked, read-only operator workflow. */
(() => {
'use strict';
const get=id=>document.getElementById(id);
const text=(tag,value,cls='')=>{const n=document.createElement(tag);n.textContent=String(value);if(cls)n.className=cls;return n;};
const CHECKS={
 'services-down':{step:'Check configured service reachability, process status and recent journal errors before restarting anything.',command:'systemctl --failed --no-pager'},
 'nginx-upstream':{step:'Correlate Nginx upstream errors with the affected backend; do not blindly change retry limits.',command:"journalctl -u nginx -n 80 --no-pager"},
 'http-error-rate':{step:'Identify which virtual hosts and response codes contribute to the 5xx count before changing proxy settings.',command:"tail -n 150 /var/log/nginx/access.log"},
 'crowdsec-connectivity':{step:'Check CrowdSec connectivity and bouncer synchronization.',command:'cscli metrics'},
 'sensitive-path':{step:'Confirm sensitive paths are denied by the appropriate Nginx server block; preserve ACME routes.',command:'nginx -T'},
 'probe-activity':{step:'Investigate source request paths and CrowdSec decisions before changing ban thresholds.',command:'cscli decisions list'},
 'auth-denials':{step:'Inspect the affected endpoints; 401/403 alone is not evidence of an attack.',command:'tail -n 150 /var/log/nginx/access.log'},
 'missing-logs':{step:'Verify Nginx logs are present and accessible to the NetSec log reader.',command:'ls -lah /var/log/nginx/'},
 'crowdsec-export':{step:'Verify that CrowdSec export data is refreshed and readable.',command:'cscli metrics'},
 'cve-inventory-needed':{step:'Inventory NGINX package revision, vendor backports and enabled HTTP/2, HTTP/3, resolver and mail features before claiming exposure.',command:'nginx -V 2>&1; dpkg-query -W nginx nginx-common 2>/dev/null'},
 'cve-package-review':{step:'Review the relevant NGINX advisory and distribution security tracker; version alone cannot establish exposure.',command:'nginx -V 2>&1; apt-cache policy nginx'},
 'international-traffic':{step:'Attribute foreign requests to the contacted virtual host and authentication outcome; do not ban solely by country.',command:''},
 'bouncer-sync':{step:'Inspect last API pull, exporter freshness and NGINX bouncer health without disabling existing enforcement.',command:'cscli bouncers list; cscli metrics'},
 'nginx-upstream-resolved':{step:'Confirm backend health and that the last upstream error predates the recovery window.',command:'journalctl -u nginx -n 80 --no-pager'},
 'crowdsec-connectivity-recovered':{step:'Verify current LAPI synchronization and differentiate historical timer errors from active enforcement gaps.',command:'cscli bouncers list'},
 'traffic-change':{step:'Compare the same time windows and check for normal scheduled activity.',command:'tail -n 150 /var/log/nginx/access.log'}
};
const priorities={high:0,medium:1,low:2};
function drawPlan(report){
 const list=get('jimmyActionList');if(!list)return;
 list.replaceChildren();
 const findings=(Array.isArray(report?.findings)?report.findings:[]).filter(f=>f&&typeof f==='object');
 if(!findings.length){list.append(text('p','No verified action items in this assessment. Jimmy can still investigate a question.','subtle tiny'));return;}
 findings.sort((a,b)=>(priorities[a.priority]??3)-(priorities[b.priority]??3));
 for(const f of findings.slice(0,8)){
  const box=text('article','','jimmy-action-item');
  const heading=text('div','','jimmy-action-heading');
  heading.append(text('strong',f.title||'Investigation'));
  heading.append(text('span',String(f.lifecycle||'unverified').toUpperCase()+' · '+String(f.priority||'review').toUpperCase(),'jimmy-action-priority'));
  box.append(heading,text('p',f.summary||'Review the underlying evidence.','jimmy-action-evidence'));
  const step=CHECKS[f.id]||{step:'Review available evidence, identify affected endpoints, and verify an expected change before applying it.',command:''};
  box.append(text('p','Next check: '+step.step,'jimmy-action-next'));
  box.append(text('p','Evidence: '+(f.origin||'Assessment')+' · confidence: '+(f.confidence||'unspecified')+' · '+(report.updated_at||'unknown time'),'jimmy-action-provenance'));
  const actions=text('div','','jimmy-action-buttons');
  const investigate=text('button','Ask Jimmy to investigate','btn');investigate.type='button';
  investigate.onclick=()=>{
   const input=get('jimmyQuestion');
   input.value='Investigate this finding using available bounded evidence: '+String(f.title||'').slice(0,120)+'. Distinguish confirmed facts from inference and give a safe, prioritized verification and rollback plan. Do not claim changes have been applied.';
   input.focus();
  };
  actions.append(investigate);
  if(step.command){
    const copy=text('button','Copy read-only check','btn');copy.type='button';
    copy.onclick=async()=>{
      try{await navigator.clipboard.writeText(step.command);copy.textContent='Copied — run manually';}
      catch(e){copy.textContent='Copy unavailable';}
    };actions.append(copy);
  }
  box.append(actions);list.append(box);
 }
}
window.netsecJimmyActionPlan=drawPlan;
})();
