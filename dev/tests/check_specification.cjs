// Offline browser verification for CYCLE_VALIDATION_SPECIFICATION.html.
const { chromium } = require('playwright');
const path = require('path');
const assert = require('assert');

(async()=>{
  const browser=await chromium.launch({headless:true,...(process.env.VERA_TEST_BROWSER?{channel:process.env.VERA_TEST_BROWSER}:{})});
  const page=await browser.newPage({viewport:{width:1440,height:1000}});
  const errors=[]; page.on('pageerror',e=>errors.push(String(e)));
  const spec=path.resolve(process.argv[2]||'CYCLE_VALIDATION_SPECIFICATION.html');
  await page.goto('file:///'+spec.replaceAll('\\','/'));
  assert.equal(await page.locator('[data-lang-button="zh-TW"]').getAttribute('aria-pressed'),'true');
  assert(await page.locator('text=Vera Cycle 驗證規範').first().isVisible());
  assert.equal(await page.locator('.matrix-entry').count(),29);
  assert.equal(await page.locator('section.doc-section').count(),12);
  assert(await page.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth),'desktop overflow');
  await page.locator('[data-lang-button="en"]').click();
  assert.equal(await page.locator('body').getAttribute('data-lang'),'en');
  assert.equal(await page.locator('html').getAttribute('lang'),'en');
  assert(await page.locator('text=Validation Methodology, Execution Flow, Pass/Fail Criteria and Evidence Definition').isVisible());
  assert(await page.locator('text=驗證方法、執行流程、通過／失敗判定準則與證據定義').isHidden());
  await page.locator('[data-lang-button="zh-TW"]').click();
  await page.locator('.matrix-entry').first().locator('summary').click();
  assert(await page.locator('.matrix-entry[open]').count()===1);
  await page.emulateMedia({media:'print'});
  assert.equal(await page.locator('.toc:visible').count(),0);
  assert.equal(await page.locator('.language-switch:visible').count(),0);
  assert(await page.locator('style').innerText().then(s=>s.includes('@page')));
  assert.deepEqual(errors,[]);
  console.log(JSON.stringify({languageSwitch:true,matrix:true,sections:12,print:true,errors}));
  await browser.close();
})().catch(e=>{console.error(e);process.exit(1)});
