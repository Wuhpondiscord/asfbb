// GitHub-hosted only. Every network request is mocked; no target scans.
const fs = require('node:fs');
const assert = require('node:assert/strict');
const { chromium } = require(process.env.ASFB_PLAYWRIGHT_MODULE);
(async () => {
 const browser = await chromium.launch();
 const page = await browser.newPage({viewport:{width:1440,height:1000},reducedMotion:'reduce'});
 page.setDefaultTimeout(10000);
 const errors=[];page.on('pageerror',e=>errors.push(e.message));
 const html=fs.readFileSync('app/index.html','utf8'),now=Date.now()/1000;
 const jobs=[
  {id:'job-one',target:'https://alpha.example.org/',status:'running',created:now-20,stage:'idor-forge',progress:50,request_count:0,modules:['idor-forge'],pipeline:{'idor-forge':'running'},alerts:[],endpoints:[],stage_details:{}},
  {id:'job-two',target:'https://beta.example.org/',status:'partial',created:now-60,stage:'partial',progress:100,request_count:1,modules:['gau'],pipeline:{gau:'timeout'},alerts:[],endpoints:[],stage_details:{gau:{status:'timeout',elapsed_ms:12000,reason:'Common Crawl deadline',summary:'Partial archive coverage'}}},
  {id:'job-three',target:'https://gamma.example.org/',status:'queued',created:now-10,stage:'queued',progress:0,request_count:0,modules:['zap-passive'],pipeline:{},alerts:[],endpoints:[]}
 ];
 const events=[
  {event_id:'e1',time:now-10,job_id:'job-one',target:jobs[0].target,event:'stage_started',module:'idor-forge',level:'info'},
  {event_id:'e2',time:now-8,job_id:'job-two',target:jobs[1].target,event:'stage_finished',module:'gau',status:'timeout',level:'warning',elapsed_ms:12000,reason:'Common Crawl deadline',diagnostics:{providers:[{provider:'commoncrawl',status:'timeout'}]}},
  {event_id:'e3',time:now-5,job_id:'job-one',target:jobs[0].target,event:'stage_exception',module:'idor-forge',level:'error',error_type:'ExampleError'}
 ];
 await page.route('**/*',async route=>{
  const u=new URL(route.request().url());
  assert.equal(u.hostname,'asfb.test','Unexpected live network request');
  let data={};
  if(u.pathname==='/')return route.fulfill({contentType:'text/html',body:html});
  if(u.pathname==='/api/assets')data={assets:[{id:'a',name:'https://alpha.example.org/',description:'Example authorized target',compatibility:'web',type:'URL',bounty:true,max_severity:'high',resolved_reports:0}]};
  else if(u.pathname==='/api/accounts')data=[];
  else if(u.pathname==='/api/scans')data=jobs;
  else if(u.pathname==='/api/logs')data={events,total:3,returned:3,truncated:false};
  else if(u.pathname==='/api/nuclei/defaults')data={templates:[{id:'technology-headers'}],default_ids:['technology-headers']};
  return route.fulfill({contentType:'application/json',headers:{'X-ASFB-Session':'offline-browser-session'},body:JSON.stringify(data)});
 });
 await page.goto('http://asfb.test/');
 await page.waitForFunction(()=>document.querySelector('#total').textContent==='1');
 const tabs=await page.locator('nav.tabs button').evaluateAll(nodes=>nodes.map(n=>n.id));
 assert.equal(tabs.at(-1),'tab-settings');
 await page.locator('#tab-settings').click();
 await page.locator('#moduleSearch').fill('idor');
 assert.equal(await page.locator('.module-card:visible').count(),1);
 await page.locator('#modIdorForge').check();
 await page.locator('#moduleSearch').fill('');
 await page.locator('button[onclick="enableFullPipeline()"]').click();
 assert.equal(await page.locator('.module-card input:checked').count(),23);
 await page.locator('[data-settings="inputs"]').click();
 await page.locator('#moduleIdorPath').fill('/api/item');
 await page.locator('#moduleIdorBaseline').fill('known-id');
 await page.locator('#moduleIdorValues').fill('other-id');
 const inputs=await page.evaluate(()=>moduleInputs());
 assert.equal(inputs.idor_path,'/api/item');assert.deepEqual(inputs.idor_values,['other-id']);
 await page.locator('[data-settings="nuclei"]').click();
 assert(await page.locator('#nucleiBuiltins').isVisible());
 await page.locator('[data-settings="identity"]').click();
 assert(await page.locator('#acookie').isVisible());
 await page.locator('#tab-scope').click();
 assert((await page.locator('#pipelinePreview').textContent()).includes('idor-forge'));
 await page.locator('#tab-jobs').click();
 await page.locator('#jobSearch').fill('beta');
 assert.equal(await page.locator('#scans > details').count(),1);
 assert((await page.locator('#scans').textContent()).includes('beta.example.org'));
 await page.locator('#jobSearch').fill('');
 await page.locator('#jobStatus').selectOption('active');
 assert.equal(await page.locator('#scans > details').count(),2);
 await page.locator('button[onclick="clearJobFilters()"]').click();
 await page.locator('[data-detail-key="job-two"] > summary').click();
 assert(await page.locator('[data-detail-key="job-two"]').getAttribute('open')!==null);
 await page.locator('button[onclick="loadScans(true)"]').click();
 assert(await page.locator('[data-detail-key="job-two"]').getAttribute('open')!==null);
 assert.equal(await page.locator('.job-card.status-running > summary .status-dot').count(),1);
 await page.locator('[data-detail-key="job-two"] button').filter({hasText:'View job logs'}).click();
 await page.waitForFunction(()=>document.querySelector('#logJob').value==='job-two');
 assert.equal(await page.locator('#fullLogs > details').count(),1);
 assert((await page.locator('#fullLogs').textContent()).includes('Common Crawl deadline'));
 await page.locator('button[onclick="clearLogFilters()"]').click();
 await page.locator('#logSearch').fill('commoncrawl');
 assert.equal(await page.locator('#fullLogs > details').count(),1); // nested provider detail is searchable
 await page.locator('#logSearch').fill('');
 await page.locator('#logLevel').selectOption('error');
 assert.equal(await page.locator('#fullLogs > details').count(),1);
 await page.locator('button[onclick="clearLogFilters()"]').click();
 await page.locator('#pauseLogs').click();
 assert.equal(await page.locator('#pauseUpdates').textContent(),'Resume live updates');
 assert.equal(await page.locator('#pauseLogs').textContent(),'Resume live updates');
 fs.mkdirSync('ui-review',{recursive:true});
 for(const width of [1440,390]){
  await page.setViewportSize({width,height:1000});
  for(const name of ['scope','jobs','logs','settings']){
   await page.locator('#tab-'+name).click();
   if(name==='settings')await page.locator('[data-settings="pipeline"]').click();
   const overflow=await page.evaluate(()=>document.documentElement.scrollWidth>window.innerWidth+1);
   assert(!overflow,'Horizontal page overflow: '+name+' at '+width);
   await page.screenshot({path:'ui-review/'+name+'-'+width+'.png',fullPage:true});
  }
 }
 assert.deepEqual(errors,[]);
 await browser.close();
 console.log('Dashboard browser checks passed: settings order, module inputs, job filters, status dots, stable details, job logs, search, pause and responsive layouts');
})().catch(e=>{console.error(e);process.exit(1)});
