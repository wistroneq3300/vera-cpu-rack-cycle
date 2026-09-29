// Offline browser verification. Run with NODE_PATH pointing to Playwright.
const { chromium } = require('playwright');
const path = require('path');
const fs = require('fs');
const assert = require('assert');
(async()=>{
 const browser=await chromium.launch({headless:true,...(process.env.VERA_TEST_BROWSER?{channel:process.env.VERA_TEST_BROWSER}:{})});
 const page=await browser.newPage();
 const errors=[];page.on('pageerror',e=>errors.push(String(e)));
 const report=path.resolve(process.argv[2]||'test-results/demo/CYCLE_REVIEW_REPORT.html');
 const output=path.resolve('.impeccable/review');fs.mkdirSync(output,{recursive:true});
 const checks=[];
 for(const [name,width,height] of [['desktop',1440,1000],['mobile',390,844]]){
   await page.setViewportSize({width,height});await page.goto('file:///'+report.replaceAll('\\','/'));
   assert.equal(await page.locator('[role=tabpanel]:visible').count(),1);
   assert(await page.locator('#overview').isVisible());
   assert(await page.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth),name+' document overflow');
   await page.screenshot({path:path.join(output,name+'.png'),fullPage:true});
   await page.getByRole('tab',{name:'L105-21R_n2',exact:true}).click();
   await page.locator('#node-1-loop-2 > summary').click();
   assert(await page.locator('#node-1-loop-2').getAttribute('open')!==null);
   assert(await page.locator('#node-1-loop-2').innerText().then(s=>s.includes('downgraded')));
   await page.screenshot({path:path.join(output,name+'-node.png'),fullPage:true});
   await page.getByRole('tab',{name:/Issues \(/}).click();
   await page.locator('#class-filter').selectOption('NEW');
   assert.equal(await page.locator('.issue-row:visible').count(),2);
   await page.locator('#issue-search').fill('no_such_issue');
   assert(await page.locator('#no-matches').isVisible());
   await page.locator('#issue-search').fill('downgrade');
   assert.equal(await page.locator('.issue-row:visible').count(),1);
   await page.locator('.issue-row:visible > summary').click();
   await page.screenshot({path:path.join(output,name+'-issues.png'),fullPage:true});
   await page.locator('.issue-row:visible a[data-panel]').first().click();
   assert(await page.locator('#node-1').isVisible());
   await page.getByRole('tab',{name:'Overview',exact:true}).focus();
   await page.keyboard.press('ArrowRight');
   assert(await page.locator('#node-0').isVisible());
   checks.push({viewport:name,overflow:false,tabs:true,filters:true,evidenceNavigation:true,keyboard:true});
 }
 assert.deepEqual(errors,[]);
 fs.writeFileSync(path.join(output,'browser-checks.json'),JSON.stringify({checks,errors},null,2));
 console.log(JSON.stringify({checks,errors}));
 await browser.close();
})().catch(e=>{console.error(e);process.exit(1)});
