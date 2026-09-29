(()=>{'use strict';
const tabs=[...document.querySelectorAll('[role=tab]')];
const panels=[...document.querySelectorAll('.node-panel')];
function select(tab,focus=false){for(const t of tabs){const active=t===tab;t.setAttribute('aria-selected',String(active));t.tabIndex=active?0:-1;document.getElementById(t.getAttribute('aria-controls')).hidden=!active;}if(focus)tab.focus();}
function node(id){for(const p of panels)p.hidden=p.id!==id;for(const a of document.querySelectorAll('.node-choice')){if(a.dataset.panel===id)a.setAttribute('aria-current','true');else a.removeAttribute('aria-current');}}
for(const tab of tabs){tab.addEventListener('click',()=>select(tab));tab.addEventListener('keydown',e=>{let i=tabs.indexOf(tab);if(e.key==='ArrowRight')i=(i+1)%tabs.length;else if(e.key==='ArrowLeft')i=(i+tabs.length-1)%tabs.length;else if(e.key==='Home')i=0;else if(e.key==='End')i=tabs.length-1;else return;e.preventDefault();select(tabs[i],true);});}
for(const link of document.querySelectorAll('[data-panel]'))link.addEventListener('click',()=>{const id=link.dataset.panel;select(document.getElementById('tab-'+(id.startsWith('node-')?'nodes':id)));if(id.startsWith('node-'))node(id);const target=document.getElementById(link.hash.slice(1));if(target&&target.tagName==='DETAILS')target.open=true;});
const search=document.getElementById('issue-search'),severity=document.getElementById('severity-filter'),classification=document.getElementById('class-filter');
function filter(){let shown=0;for(const item of document.querySelectorAll('#issues .issue-row')){const visible=item.textContent.toLowerCase().includes(search.value.toLowerCase())&&(!severity.value||item.dataset.severity===severity.value)&&(!classification.value||item.dataset.classification===classification.value);item.hidden=!visible;if(visible)shown++;}document.getElementById('issue-count').textContent=shown+' matching issues';document.getElementById('no-matches').hidden=shown!==0;}
for(const control of [search,severity,classification])control.addEventListener('input',filter);
function filterNodes(){const query=document.getElementById('node-search').value.toLowerCase(),health=document.getElementById('node-health').value;let shown=0;for(const a of document.querySelectorAll('.node-choice')){a.hidden=!a.textContent.toLowerCase().includes(query)||(health&&a.dataset.health!==health);if(!a.hidden)shown++;}document.getElementById('node-count').textContent=shown+' matching nodes';}
for(const id of ['node-search','node-health'])document.getElementById(id).addEventListener('input',filterNodes);
let printState;
window.addEventListener('beforeprint',()=>{printState=[...document.querySelectorAll('details')].map(r=>[r,r.open]);printState.forEach(([r])=>r.open=true);});
window.addEventListener('afterprint',()=>{if(printState)printState.forEach(([r,open])=>r.open=open);});
document.getElementById('print-report').addEventListener('click',()=>window.print());
if(panels.length)node(document.querySelector('.node-choice').dataset.panel);select(tabs[0]);
})();
