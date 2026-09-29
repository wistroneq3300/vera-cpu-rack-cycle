(()=>{'use strict';
const tabs=[...document.querySelectorAll('[role=tab]')];
function select(tab,focus=false){for(const t of tabs){const active=t===tab;t.setAttribute('aria-selected',String(active));t.tabIndex=active?0:-1;document.getElementById(t.getAttribute('aria-controls')).hidden=!active;}if(focus)tab.focus();}
for(const tab of tabs){tab.addEventListener('click',()=>select(tab));tab.addEventListener('keydown',e=>{let i=tabs.indexOf(tab);if(e.key==='ArrowRight')i=(i+1)%tabs.length;else if(e.key==='ArrowLeft')i=(i+tabs.length-1)%tabs.length;else if(e.key==='Home')i=0;else if(e.key==='End')i=tabs.length-1;else return;e.preventDefault();select(tabs[i],true);});}
for(const link of document.querySelectorAll('[data-panel]'))link.addEventListener('click',()=>{const tab=tabs.find(t=>t.getAttribute('aria-controls')===link.dataset.panel);if(tab)select(tab);const detail=document.querySelector(link.getAttribute('href'));if(detail&&detail.tagName==='DETAILS')detail.open=true;});
const search=document.getElementById('issue-search'),severity=document.getElementById('severity-filter'),classification=document.getElementById('class-filter');
function filter(){let shown=0;for(const item of document.querySelectorAll('.issue-row')){const visible=item.textContent.toLowerCase().includes(search.value.toLowerCase())&&(!severity.value||item.dataset.severity===severity.value)&&(!classification.value||item.dataset.classification===classification.value);item.hidden=!visible;if(visible)shown++;}document.getElementById('issue-count').textContent=shown+' matching issues';document.getElementById('no-matches').hidden=shown!==0;}
for(const control of [search,severity,classification])if(control)control.addEventListener('input',filter);
document.getElementById('print-report').addEventListener('click',()=>{const records=[...document.querySelectorAll('details')],state=records.map(r=>r.open);records.forEach(r=>r.open=true);window.print();records.forEach((r,i)=>r.open=state[i]);});
select(tabs[0]);
})();
