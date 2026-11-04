// GitHub-hosted only. Every network request is mocked; no target scans.
const fs = require('node:fs');
const assert = require('node:assert/strict');
const { chromium } = require(process.env.ASFB_PLAYWRIGHT_MODULE);
(async () => {
 const browser = await chromium.launch();
 const page = await browser.newPage({viewport:{width:1440,height:1000},reducedMotion:'reduce'});
 page.setDefaultTimeout(10000);
 const errors=[];page.on('pageerror',e=>errors.push(e.message));
 let html=fs.readFileSync('app/index.html','utf8');const now=Date.now()/1000;
 let builtinInfo={templates:[{id:'technology-headers'}],default_ids:['technology-headers']};
 const discoveryQueries=[];
 let batchAccountEnabled=false,batchSubmitted=false;
 const jobs=[
  {id:'job-one',target:'https://alpha.example.org/',status:'running',created:now-20,stage:'idor-forge',progress:50,request_count:0,modules:['idor-forge'],pipeline:{'idor-forge':'running',amass:'completed'},alerts:[],endpoints:[],stage_details:{amass:{status:'completed',elapsed_ms:120000,early_stop:true,coverage_complete:false,stop_reason:'native_time_budget',reason:'Early stop: native time budget; coverage is incomplete'}}},
  {id:'job-two',target:'https://beta.example.org/',status:'partial',created:now-60,stage:'partial',progress:100,request_count:1,modules:['gau'],pipeline:{gau:'timeout'},alerts:[],endpoints:[],stage_details:{gau:{status:'timeout',elapsed_ms:12000,reason:'Common Crawl deadline',summary:'Partial archive coverage'}}},
  {id:'job-three',target:'https://gamma.example.org/',status:'queued',created:now-10,stage:'queued',progress:0,request_count:0,modules:['zap-passive'],pipeline:{},alerts:[],endpoints:[]}
 ];
 jobs[0].discovery={checked:1,check_limit:10,dependency_candidates:1,resources:[{url:'https://alpha.example.org/app.js',checked:true,status_code:200,kind:'javascript',sources:['katana']}],
  suggestions:[{kind:'garak',url:'https://alpha.example.org/api/generate',evidence:'Documented JSON prompt and response schemas; review required',review_required:true,inputs:{llm_path:'/api/generate',prompt_field:'prompt',response_field:'response'}}]};
 const events=[
  {event_id:'e1',time:now-10,job_id:'job-one',target:jobs[0].target,event:'stage_started',module:'idor-forge',level:'info'},
  {event_id:'e2',time:now-8,job_id:'job-two',target:jobs[1].target,event:'stage_finished',module:'gau',status:'timeout',level:'warning',elapsed_ms:12000,reason:'Common Crawl deadline',diagnostics:{providers:[{provider:'commoncrawl',status:'timeout'}]}},
  {event_id:'e3',time:now-5,job_id:'job-one',target:jobs[0].target,event:'stage_exception',module:'idor-forge',level:'error',error_type:'ExampleError'}
 ];
 const importedAssets=[{id:'a',name:'https://alpha.example.org/',description:'Example authorized target',compatibility:'web',type:'URL',bounty:true,max_severity:'high',resolved_reports:0}];
 function addImported(id,name,format){
  importedAssets.push({id,name,description:'Imported fixture',compatibility:'web',type:'URL',bounty:false,max_severity:'unknown',resolved_reports:null});
  return {imported:1,web:1,duplicates:0,format,asset_ids:[id],web_asset_ids:[id]};
 }
 await page.route('**/*',async route=>{
  const u=new URL(route.request().url());
  assert.equal(u.hostname,'asfb.test','Unexpected live network request');
  let data={};
  if(u.pathname==='/preferences.js')return route.fulfill({contentType:'text/javascript',body:fs.readFileSync('app/preferences.js','utf8')});
  if(u.pathname==='/')return route.fulfill({contentType:'text/html',body:html});
  if(u.pathname==='/api/discovery/programs'){
   discoveryQueries.push(Object.fromEntries(u.searchParams));
   const programs=Number(u.searchParams.get('offset')||0)===0?[
    {id:'hackerone:fixture',platform:'hackerone',handle:'fixture',name:'Fixture Example',url:'https://hackerone.com/fixture',offers_bounties:true,min_bounty:100,max_bounty:5000,currency:'usd'},
    {id:'bugcrowd:review',platform:'bugcrowd',handle:'review',name:'Review Example',url:'https://bugcrowd.com/review',offers_bounties:true,min_bounty:null,max_bounty:null,currency:null}
   ]:[{id:'yeswehack:extra',platform:'yeswehack',handle:'extra',name:'Extra Example',url:'https://yeswehack.com/programs/extra',offers_bounties:true,max_bounty:1000,currency:'usd'}];
   if(Number(u.searchParams.get('offset')||0)===0)for(let i=0;i<12;i++)programs.push({id:'hackerone:extra'+i,platform:'hackerone',handle:'extra'+i,name:'Extra program '+i,url:'https://hackerone.com/extra'+i,offers_bounties:true,max_bounty:1000,currency:'usd'});
   return route.fulfill({contentType:'application/json',body:JSON.stringify({programs,total:3,next_offset:Number(u.searchParams.get('offset')||0)===0?25:null,partial:false})});
  }
  if(u.pathname.startsWith('/api/discovery/programs/')){
   const manual=u.pathname.includes('/bugcrowd/');
   return route.fulfill({contentType:'application/json',body:JSON.stringify({
    review_id:manual?'review-two':'review-one',program_id:manual?'bugcrowd:review':'hackerone:fixture',name:manual?'review':'fixture',url:manual?'https://bugcrowd.com/review':'https://hackerone.com/fixture',
    source:{mode:'live',fetched_at:'2026-11-03T12:00:00Z'},total:1,next_offset:null,
    assets:[{id:manual?'scope-two':'scope-one',identifier:manual?'https://review.example.org/':'https://bounty.example.org/',type:'url',instructions:'Only authorized test accounts',eligible_for_bounty:true}],
    exclusions:[{identifier:'https://bounty.example.org/admin',instructions:'Excluded'}],
    analysis:{user_agents:manual?[]:[{value:'HackerOne-<username>',mode:'exact',evidence:'User-Agent: HackerOne-<username>'}],email_domains:manual?[]:['wearehackerone.com'],headers:[],max_rps:null,automation_prohibited:false,review_required:manual,review_reasons:manual?['No supported identification requirements were found']:[],text:'Published rules <img src=x onerror=alert(1)>',partial:false}
   })});
  }
  if(u.pathname==='/api/discovery/resolve'){
   const body=route.request().postDataJSON();
   const programs=body.programs.map(p=>{
    const manual=p.review_id==='review-two',s=p.settings;
    const ready=manual?s.rules_reviewed:!!(s.researcher&&s.test_email&&s.test_account_confirmed);
    return {review_id:p.review_id,ready,user_agent:manual?(s.custom_agent||s.default_agent||null):'HackerOne-'+s.researcher,agent_source:manual?'scan queue fallback':'program rules',headers:{},reason:manual?'Confirm rule review':'Confirm testing account setup'};
   });
   return route.fulfill({contentType:'application/json',body:JSON.stringify({programs})});
  }
  if(u.pathname==='/api/discovery/import'){
   const body=route.request().postDataJSON();assert.equal(body.programs.length,2);
   assert.equal(body.programs[0].review_id,'review-one');
   assert.equal(body.programs[0].settings.researcher,'fixture-private-handle');
   assert.equal(body.programs[0].settings.test_email,'fixture-private@wearehackerone.com');
   assert.equal(body.programs[0].settings.test_account_confirmed,true);
   assert.equal(body.programs[0].settings.custom_agent,'');
   assert.equal(body.programs[0].settings.default_agent,'Wrong-Identity-Default');
   const data=addImported('bounty-target','https://bounty.example.org/','discovery');
   return route.fulfill({contentType:'application/json',body:JSON.stringify({...data,programs:1,skipped:[{review_id:'review-two',program_id:'bugcrowd:review',reason:'Confirm rule review'}]})});
  }
  if(u.pathname==='/api/scans/batch'){
   const body=route.request().postDataJSON();
   assert.deepEqual(body.asset_ids,['direct-url','file-url']);
   assert.equal(body.account_id,'batch-account');
   assert(body.options.inputs.nosql);
   assert.equal(body.options.inputs.source_text,'batch-private-source');
   assert.equal(body.options.inputs.idor_path,'/api/items');
   assert.equal(body.inputs_by_asset['file-url'].nosql,null);
   assert.equal(body.inputs_by_asset['file-url'].source_text,'different-private-source');
   batchSubmitted=true;
   return route.fulfill({contentType:'application/json',body:JSON.stringify({queued:2,reused:0,scans:[{id:'batch-one'},{id:'batch-two'}]})});
  }
  if(u.pathname==='/api/assets')data={assets:importedAssets};
  else if(u.pathname==='/api/import/text'){
   const body=route.request().postDataJSON();
   assert.equal(body.text,'https://single.example.org/search?q=test');assert.equal(body.format,'auto');
   data=addImported('direct-url',body.text,'text');
  }
  else if(u.pathname==='/api/import'){
   assert.equal(u.searchParams.get('format'),'auto');
   assert(route.request().postDataBuffer().toString().includes('https://file.example.org/'));
   data=addImported('file-url','https://file.example.org/','text');
  }
  else if(u.pathname==='/api/accounts')data=batchAccountEnabled?[{id:'batch-account',name:'Batch fixture',host:'single.example.org'}]:[];
  else if(u.pathname==='/api/scans')data=jobs;
  else if(u.pathname==='/api/logs')data={events,total:3,returned:3,truncated:false};
  else if(u.pathname==='/api/pipeline/plan'){
   const request=route.request().postDataJSON();
   const effective=request.order_mode==='manual'?request.modules:['gau',...request.modules.filter(m=>m!=='gau')].filter(m=>request.modules.includes(m));
   data={mode:request.order_mode,effective,requested:request.modules,changed:JSON.stringify(effective)!==JSON.stringify(request.modules),
         warnings:request.order_mode==='manual'?['Manual fixture ordering warning']:[],handoffs:[{from:'gau',to:'katana',data:'URL inventory',available:true}],
         coverage_profile:request.coverage_profile,budgets:{retire_files:8,retire_bytes:2097152,dalfox_scan_seconds:60,dalfox_payloads:12,amass_timeout:95}};
  }
  else if(u.pathname==='/api/nuclei/defaults')data=builtinInfo;
  return route.fulfill({contentType:'application/json',headers:{'X-ASFB-Session':'offline-browser-session'},body:JSON.stringify(data)});
 });
 await page.goto('http://asfb.test/');
 await page.waitForFunction(()=>document.querySelector('#total').textContent==='1');
 await page.locator('#formatHelpButton').hover();
 assert(await page.getByRole('tooltip').isVisible());
 assert((await page.getByRole('tooltip').textContent()).includes('JSONL'));
 await page.locator('#formatHelpButton').focus();
 await page.keyboard.press('Escape');
 assert(!(await page.getByRole('tooltip').isVisible()));
 await page.locator('#formatHelpButton').click();
 assert(await page.getByRole('tooltip').isVisible());
 await page.locator('header h1').click();
 assert(!(await page.getByRole('tooltip').isVisible()));
 await page.locator('#targetText').fill('https://single.example.org/search?q=test');
 await page.locator('#addTargets').click();
 await page.waitForFunction(()=>document.querySelector('#total').textContent==='2'&&!document.querySelector('#addTargets').disabled);
 assert.equal(await page.locator('#targetText').inputValue(),'');
 assert(await page.evaluate(()=>selectedIds.has('direct-url')));
 assert(await page.locator('#start').isDisabled());
 await page.locator('#file').setInputFiles({name:'targets.txt',mimeType:'text/plain',buffer:Buffer.from('https://file.example.org/\n')});
 await page.locator('#uploadTargets').click();
 await page.waitForFunction(()=>document.querySelector('#total').textContent==='3'&&!document.querySelector('#uploadTargets').disabled);
 assert(await page.evaluate(()=>selectedIds.has('file-url')));
 assert.equal(await page.evaluate(()=>selectedIds.size),2);
 assert(await page.locator('#start').isDisabled());

 const tabs=await page.locator('nav.tabs button').evaluateAll(nodes=>nodes.map(n=>n.id));
 assert.equal(tabs.at(-1),'tab-settings');
 assert.equal(await page.locator('#parallelJobs').inputValue(),'1');
 await page.locator('#tab-settings').click();
 await page.locator('#settingsParallel').selectOption('2');
 assert.equal(await page.locator('#parallelJobs').inputValue(),'2');
 assert.equal(await page.evaluate(()=>pipelineOptions().parallel_jobs),2);
 await page.locator('#moduleSearch').fill('idor');
 assert.equal(await page.locator('.module-card:visible').count(),1);
 await page.locator('#modIdorForge').check();
 await page.locator('#moduleSearch').fill('');
 await page.locator('button[onclick="enableFullPipeline()"]').click();
 assert.equal(await page.locator('.module-card input:checked').count(),33);
 assert.equal(await page.locator('#pipelineMode').inputValue(),'guided');
 assert.equal(await page.locator('#coverageProfile').inputValue(),'balanced');
 await page.locator('#pipelineMode').selectOption('manual');
 const reversed=await page.evaluate(()=>enabledModules().slice().reverse().join(', '));
 await page.locator('#settingsOrder').fill(reversed);
 await page.waitForFunction(()=>document.querySelector('#pipelinePlanSummary').textContent.includes('Manual execution order'));
 assert.equal(await page.evaluate(()=>pipelineOptions().order_mode),'manual');
 assert.equal(await page.evaluate(()=>el('stageOrder').value),reversed);
 assert((await page.locator('#pipelinePlanSummary').textContent()).includes('Manual fixture ordering warning'));
 await page.locator('#pipelineMode').selectOption('guided');
 await page.locator('#coverageProfile').selectOption('thorough');
 await page.waitForFunction(()=>document.querySelector('#pipelinePlanHint').textContent.includes('thorough'));
 assert.equal(await page.evaluate(()=>pipelineOptions().coverage_profile),'thorough');
 assert.equal(await page.evaluate(()=>pipelineOptions().reuse_discovery),true);
 await page.locator('button[onclick="enableFullPipeline()"]').click();
 await page.locator('[data-settings="inputs"]').click();
 assert(!(await page.locator('#moduleTrufflehogVerify').isChecked()));
 assert.equal(await page.evaluate(()=>moduleInputs().trufflehog_verify),false);
 await page.locator('#moduleTrufflehogVerify').check();
 assert.equal(await page.evaluate(()=>moduleInputs().trufflehog_verify),true);
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
 await page.locator('#parallelJobs').selectOption('3');
 assert.equal(await page.locator('#settingsParallel').inputValue(),'3');
 assert.equal(await page.evaluate(()=>pipelineOptions().parallel_jobs),3);
 await page.locator('#tab-jobs').click();
 assert((await page.locator('#scans').textContent()).includes('amass: completed · early stop'));
 assert((await page.locator('#scans').textContent()).includes('amass · completed · early stop'));
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
 assert((await page.locator('#fullLogs > details > summary').textContent()).includes('Common Crawl deadline'));
 await page.locator('button[onclick="clearLogFilters()"]').click();
 await page.locator('#logSearch').fill('commoncrawl');
 assert.equal(await page.locator('#fullLogs > details').count(),1); // nested provider detail is searchable
 await page.locator('#logSearch').fill('');
 await page.locator('#logLevel').selectOption('error');
 assert.equal(await page.locator('#fullLogs > details').count(),1);
 await page.locator('button[onclick="clearLogFilters()"]').click();
 await page.evaluate(()=>{
  logEvents.push({event_id:'early-stop-ui',time:Date.now()/1000,job_id:'job-one',target:'https://alpha.example.org/',event:'stage_finished',module:'amass',level:'info',status:'completed',diagnostics:{early_stop:true,stop_reason:'native_time_budget',coverage_complete:false}});
  renderLogs();
 });
 assert((await page.locator('#fullLogs > details > summary').allTextContents()).some(text=>text.includes('early stop')));
 await page.evaluate(()=>{logEvents=logEvents.filter(e=>e.event_id!=='early-stop-ui');renderLogs();});
 await page.locator('#pauseLogs').click();
 assert.equal(await page.locator('#pauseUpdates').textContent(),'Resume live updates');
 assert.equal(await page.locator('#pauseLogs').textContent(),'Resume live updates');
 fs.mkdirSync('ui-review',{recursive:true});
 for(const width of [1440,390]){
  await page.setViewportSize({width,height:1000});
  for(const name of ['scope','jobs','logs','settings']){
   await page.locator('#tab-'+name).click();
   if(name==='settings')await page.locator('[data-settings="pipeline"]').click();
   if(width===390&&name==='scope'){
    await page.locator('#formatHelpButton').click();
    assert(await page.getByRole('tooltip').isVisible());
    assert(!(await page.evaluate(()=>document.documentElement.scrollWidth>window.innerWidth+1)));
    await page.keyboard.press('Escape');
   }
   const overflow=await page.evaluate(()=>document.documentElement.scrollWidth>window.innerWidth+1);
   if(overflow)console.error(await page.evaluate(()=>Array.from(document.querySelectorAll('body *')).filter(n=>{const r=n.getBoundingClientRect();return r.width&&r.right>window.innerWidth+1}).slice(0,30).map(n=>({tag:n.tagName,id:n.id,class:n.className,right:n.getBoundingClientRect().right,width:n.getBoundingClientRect().width}))));
   await page.screenshot({path:'ui-review/'+name+'-'+width+'.png',fullPage:true});
   assert(!overflow,'Horizontal page overflow: '+name+' at '+width);
   await page.screenshot({path:'ui-review/'+name+'-'+width+'.png',fullPage:true});
  }
 }

 // Real browser cookie round-trip, with every HTTP request still mocked.
 await page.setViewportSize({width:1440,height:1000});
 await page.locator('#tab-settings').click();
 await page.locator('[data-settings="pipeline"]').click();
 await page.locator('button[onclick="setBaselinePipeline()"]').click();
 await page.locator('#modRetirejs').check();
 await page.getByText('Advanced discovery limits',{exact:true}).click();
 await page.locator('#settingsZapWait').fill('240');
 await page.locator('#settingsLimit').fill('225');
 await page.locator('#coverageProfile').selectOption('thorough');
 await page.locator('#settingsParallel').selectOption('2');
 await page.locator('#pipelineMode').selectOption('manual');
 const customOrder=await page.evaluate(()=>el('settingsOrder').defaultValue.split(',').map(s=>s.trim()).reverse().join(', '));
 await page.locator('#settingsOrder').fill(customOrder);
 await page.locator('[data-settings="inputs"]').click();
 await page.locator('#moduleSastLanguage').selectOption('typescript');
 await page.locator('#moduleGraphqlPath').fill('/fixture-private-graphql');
 await page.locator('#moduleCorsPath').fill('/fixture-private-cors');
 await page.locator('#moduleWebsocketPath').fill('/fixture-private-ws');
 await page.locator('[data-settings="replay"]').click();
 await page.locator('#raceProfile').fill(JSON.stringify({...await page.evaluate(()=>REPLAY_EXAMPLES.race),control_value:'fixture-private-control'}));
 await page.locator('#nosqlProfile').fill(JSON.stringify(await page.evaluate(()=>REPLAY_EXAMPLES.nosql)));
 await page.locator('[data-settings="inputs"]').click();
 await page.locator('#moduleSource').fill('fixture-private-source');
 await page.locator('#moduleSbom').fill('fixture-private-sbom');
 await page.locator('#moduleTrufflehogVerify').check();
 await page.locator('#moduleIdorValues').fill('fixture-private-id');
 await page.locator('[data-settings="identity"]').click();
 await page.locator('#acookie').fill('fixture-private-auth-cookie');
 await page.getByText('Offline JWT metadata review',{exact:true}).click();
 await page.locator('#jwt').fill('fixture-private-jwt');
 await page.locator('[data-settings="nuclei"]').click();
 await page.locator('#nucleiBuiltins input').first().uncheck();
 await page.locator('#nucleiCustom').fill('fixture-private-custom-template');
 await page.evaluate(()=>{
  el('policy').checked=true;el('activeConsent').checked=true;
  nucleiCommunityPaths.add('http/exposures/configs/example.yaml');renderNucleiCommunity();
  preferenceStore.flush();
 });
 let cookies=await page.context().cookies();
 assert(cookies.some(c=>c.name==='asfb_pref_pipeline'&&c.expires>Date.now()/1000));
 assert(!JSON.stringify(cookies).includes('fixture-private'));
 assert(!cookies.some(c=>c.name.includes('TrufflehogVerify')));
 await page.reload();
 await page.waitForFunction(()=>document.querySelector('#nucleiBuiltins').dataset.initialized==='true');
 assert.equal(await page.locator('#settingsZapWait').inputValue(),'240');
 assert.equal(await page.locator('#moduleSastLanguage').inputValue(),'typescript');
 assert.equal(await page.locator('#settingsLimit').inputValue(),'225');
 assert.equal(await page.locator('#coverageProfile').inputValue(),'thorough');
 assert.equal(await page.locator('#pipelineMode').inputValue(),'manual');
 assert.equal(await page.locator('#settingsOrder').inputValue(),customOrder);
 assert.equal(await page.locator('#parallelJobs').inputValue(),'2');
 assert.equal(await page.locator('#settingsParallel').inputValue(),'2');
 assert(await page.locator('#modRetirejs').isChecked());
 assert(!(await page.locator('#modNuclei').isChecked()));
 assert.equal(await page.locator('#reports').inputValue(),'');
 assert(!(await page.locator('#nucleiBuiltins input').first().isChecked()));
 assert(await page.evaluate(()=>nucleiCommunityPaths.has('http/exposures/configs/example.yaml')));
 for(const id of ['raceProfile','nosqlProfile','moduleTargetInputs','moduleGraphqlPath','moduleCorsPath','moduleWebsocketPath','moduleSource','moduleSbom','moduleIdorValues','acookie','jwt','nucleiCustom'])
  assert.equal(await page.locator('#'+id).inputValue(),'');
 for(const id of ['policy','activeConsent','moduleTrufflehogVerify'])
  assert(!(await page.locator('#'+id).isChecked()));
 // A new release adds a setting and builtin: existing saved choices survive.
 html=html.replace('id="settingsHttpx" type="number" value="10"','id="settingsHttpx" type="number" value="12"');
 html=html.replace('const names={"race-replay":','const names={"future":"modFuture","race-replay":')
  .replaceAll('gau, katana, takeover, httpx, wafw00f','gau, katana, takeover, httpx, future, wafw00f')
  .replace('<p id="moduleSearchEmpty"','<label class="module-card" data-module-search="future"><input id="modFuture" type="checkbox"/><span>Future module</span></label><p id="moduleSearchEmpty"');
 builtinInfo={templates:[{id:'technology-headers'},{id:'future-default'}],default_ids:['technology-headers','future-default']};
 await page.reload();
 await page.waitForFunction(()=>document.querySelector('#nucleiBuiltins input[value="future-default"]'));
 assert.equal(await page.locator('#settingsHttpx').inputValue(),'12');
 assert.equal(await page.locator('#settingsOrder').inputValue(),customOrder+', future');
 assert(!(await page.locator('#modFuture').isChecked()));
 assert.equal(await page.locator('#settingsZapWait').inputValue(),'240');
 assert(!(await page.locator('#nucleiBuiltins input[value="technology-headers"]').isChecked()));
 assert(await page.locator('#nucleiBuiltins input[value="future-default"]').isChecked());
 // Invalid values cannot reset unrelated settings.
 await page.evaluate(()=>{
  const name='asfb_pref_pipeline=';
  const raw=document.cookie.split(';').map(s=>s.trim()).find(s=>s.startsWith(name));
  const data=JSON.parse(decodeURIComponent(raw.slice(name.length)));
  data.values.settingsLimit='invalid';data.values.futureSetting={kept:true};
  document.cookie=name+encodeURIComponent(JSON.stringify(data))+'; Path=/; SameSite=Lax';
 });
 await page.reload();
 await page.waitForFunction(()=>document.querySelector('#nucleiBuiltins').dataset.initialized==='true');
 assert.equal(await page.locator('#settingsLimit').inputValue(),'100');
 assert.equal(await page.locator('#settingsZapWait').inputValue(),'240');
 await page.evaluate(()=>{el('settingsZapWait').value='180';preferenceStore.flush()});
 const data=await page.evaluate(()=>JSON.parse(decodeURIComponent(document.cookie.split(';').map(s=>s.trim()).find(s=>s.startsWith('asfb_pref_pipeline=')).split('=').slice(1).join('='))));
 assert.deepEqual(data.values.futureSetting,{kept:true});
 assert.equal(data.values.settingsZapWait,180);

 await page.setViewportSize({width:1440,height:1000});
 assert.equal(await page.locator('#tab-discovery').count(),0);
 await page.locator('#tab-settings').click();
 await page.locator('[data-settings="identity"]').click();
 await page.locator('#replacementResearcher').fill('fixture-private-handle');
 await page.locator('#replacementHackeroneEmail').fill('fixture-private@wearehackerone.com');
 await page.locator('#replacementAgent').fill('Wrong-Identity-Default');
 await page.locator('[data-replacement-key]').fill('TEAM');
 await page.locator('[data-replacement-value]').fill('fixture-team');
 await page.evaluate(()=>preferenceStore.flush());
 assert(!JSON.stringify(await page.context().cookies()).includes('fixture-private'));
 await page.setViewportSize({width:1440,height:1000});
 await page.locator('#tab-scope').click();
 await page.locator('#scopeSourceBounties').click();
 await page.waitForFunction(()=>document.querySelectorAll('.discovery-program').length>=2);
 const scrollBox=page.locator('#discoveryResults');
 assert(await scrollBox.evaluate(n=>getComputedStyle(n).overflowY==='auto'&&n.scrollHeight>n.clientHeight));
 const pageHeight=await page.evaluate(()=>document.body.scrollHeight);
 await scrollBox.evaluate(n=>n.scrollTop=300);
 assert(await scrollBox.evaluate(n=>n.scrollTop>0));
 assert.equal(await page.evaluate(()=>document.body.scrollHeight),pageHeight);
 await page.locator('#discoverySearch').fill('Example');
 await page.locator('#discoveryCurrency').selectOption('USD');
 await page.locator('#discoveryReward').fill('1000');
 await page.locator('#discoverySort').selectOption('max_bounty');
 await page.getByRole('button',{name:'Apply filters'}).click();
 await page.waitForFunction(()=>!discoveryState.busy);
 assert(discoveryQueries.some(q=>q.search==='Example'&&q.currency==='USD'&&q.reward_at_least==='1000'&&q.sort_by==='max_bounty'));
 await page.locator('[data-program-id="hackerone:fixture"]').check();
 await page.locator('[data-program-id="bugcrowd:review"]').check();
 assert((await page.locator('#discoverySelectedCount').textContent()).includes('2 programs'));
 await page.locator('#discoveryReviewButton').click();
 await page.waitForFunction(()=>document.querySelectorAll('.discovery-review').length===2);
 assert.equal(await page.locator('.discovery-review').count(),2);
 assert.equal(await page.locator('#discoveryBrowser').getAttribute('open'),null);
 assert((await page.locator('#discoveryRuleCards').textContent()).includes('No supported identification requirements were found'));
 assert.equal(await page.locator('#discoveryRuleCards img').count(),0);
 assert.equal(await page.locator('#discoveryResearcher').inputValue(),'fixture-private-handle');
 assert(!(await page.locator('#scanHint').textContent()).includes('100 approved'));
 assert(!(await page.locator('.scan-launch').textContent()).includes('up to 100 approved'));
 assert.equal(await page.evaluate(()=>programSetupSettings(discoveryState.reviews[0],0).custom_agent),'');
 assert.equal(await page.locator('[data-policy-email="0"]').inputValue(),'fixture-private@wearehackerone.com');
 await page.locator('[data-policy-account="0"]').check();
 await page.waitForFunction(()=>document.querySelector('[data-agent-hint="0"]').textContent.includes('HackerOne-fixture-private-handle'));
 assert((await page.locator('[data-agent-hint="0"]').textContent()).includes('program rules'));
 await page.locator('[data-scope-id="scope-one"]').check();
 await page.locator('[data-review-index="1"] > summary').click();
 await page.locator('[data-scope-id="scope-two"]').check();
 await page.screenshot({path:'ui-review/discovery-review.png',fullPage:true});
 await page.locator('#discoveryImportButton').click();
 await page.waitForFunction(()=>currentTab==='scope'&&selectedIds.has('bounty-target'));
 assert(!(await page.locator('#policy').isChecked()));
 assert(!(await page.locator('#activeConsent').isChecked()));
 assert.equal(await page.locator('[data-policy-email="0"]').inputValue(),'');
 assert((await page.locator('#discoveryImportStatus').textContent()).includes('Skipped 1'));
 await page.evaluate(()=>preferenceStore.flush());
 assert(!JSON.stringify(await page.context().cookies()).includes('fixture-private'));
 // Conditional account instructions and scanner discouragement remain distinct.
 await page.evaluate(()=>{
  discoveryState.reviews=[{review_id:'review-discouraged',title:'Manual testing program',program_id:'hackerone:manual',
   url:'https://hackerone.com/manual',assets:[{id:'scope-manual',identifier:'example.org',type:'domain'}],
   analysis:{user_agents:[],headers:[],email_domains:[],conditional_email_domains:['wearehackerone.com'],
    automation_discouraged:true,automation_prohibited:false,review_required:true,review_reasons:['Review conditional account instructions'],text:'Manual testing instructions'}}];
  renderDiscoveryReviews();
 });
 assert((await page.locator('#discoveryRuleCards').textContent()).includes('discourage automated vulnerability scanning'));
 assert((await page.locator('#discoveryRuleCards').textContent()).includes('Conditional email-testing instructions'));
 assert.equal(await page.locator('[data-policy-email="0"]').count(),0);
 assert(await page.locator('[data-scope-id="scope-manual"]').isDisabled());
 // Identity defaults are retained only after an explicit opt-in.
 await page.locator('#tab-settings').click();await page.locator('[data-settings="identity"]').click();
 await page.locator('#replacementResearcher').fill('saved-researcher');
 await page.locator('#replacementHackeroneEmail').fill('saved@wearehackerone.com');
 await page.locator('[data-replacement-value]').fill('SavedTeam');
 await page.locator('#rememberReplacements').check();await page.evaluate(()=>preferenceStore.flush());
 await page.reload();await page.waitForFunction(()=>document.querySelector('#nucleiBuiltins').dataset.initialized==='true');
 await page.locator('#tab-settings').click();await page.locator('[data-settings="identity"]').click();
 assert.equal(await page.locator('#replacementResearcher').inputValue(),'saved-researcher');
 assert.equal(await page.locator('#replacementHackeroneEmail').inputValue(),'saved@wearehackerone.com');
 assert(await page.locator('#rememberReplacements').isChecked());
 await page.locator('#rememberReplacements').uncheck();await page.evaluate(()=>preferenceStore.flush());
 const savedIdentity=await page.evaluate(()=>{const pair=document.cookie.split(';').map(s=>s.trim()).find(s=>s.startsWith('asfb_pref_identity_defaults='));return pair?JSON.parse(decodeURIComponent(pair.slice(pair.indexOf('=')+1))):{values:{}}});
 assert.equal(savedIdentity.values.values,undefined);
 assert.equal(await page.locator('nav.tabs button').last().getAttribute('id'),'tab-settings');
 // Resource evidence is visible and review drafts do not enable modules or queue jobs.
 const beforeDraft=await page.evaluate(()=>enabledModules());
 await page.evaluate(()=>useDiscoveryDraft('job-one',0));
 assert.equal(JSON.parse(await page.locator('#moduleTargetInputs').inputValue())['https://alpha.example.org/'].llm_path,'/api/generate');
 assert.deepEqual(await page.evaluate(()=>enabledModules()),beforeDraft);
 await page.locator('#moduleTargetInputs').fill('');
 // Queue a real dashboard batch with replay, IDOR, source and per-target inputs.
 batchAccountEnabled=true;
 await page.evaluate(async ()=>{
  await loadAccounts();
  selectedIds=new Set(['direct-url','file-url']);
  document.querySelectorAll('.module-card input').forEach(n=>n.checked=false);
  el('modNosql').checked=true;el('modIdorForge').checked=true;el('modSemgrep').checked=true;
  el('nosqlProfile').value=JSON.stringify(REPLAY_EXAMPLES.nosql);
  el('moduleIdorPath').value='/api/items';el('moduleIdorBaseline').value='first';el('moduleIdorValues').value='second';
  el('moduleSource').value='batch-private-source';el('moduleSastLanguage').value='python';
  el('moduleTargetInputs').value=JSON.stringify({'https://file.example.org/':{nosql:null,source_text:'different-private-source'}});
  el('account').value='batch-account';el('policy').checked=true;el('activeConsent').checked=true;
  switchTab('scope');showScopeSource('import');render();
 });
 await page.locator('#start').click();
 await page.waitForFunction(()=>!selectedIds.has('direct-url')&&!selectedIds.has('file-url'));
 assert(batchSubmitted);
 for(const id of ['moduleTargetInputs','nosqlProfile','moduleSource','moduleIdorBaseline','moduleIdorValues'])
  assert.equal(await page.locator('#'+id).inputValue(),'');
 await page.evaluate(()=>preferenceStore.flush());
 assert(!JSON.stringify(await page.context().cookies()).includes('batch-private-source'));
 assert.deepEqual(errors,[]);
 await browser.close();
 console.log('Dashboard browser checks passed: settings order, module inputs, job filters, status dots, stable details, job logs, search, pause and responsive layouts');
})().catch(e=>{console.error(e);process.exit(1)});