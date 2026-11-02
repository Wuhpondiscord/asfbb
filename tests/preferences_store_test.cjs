// GitHub-hosted only: pure cookie-store regression tests; no network requests.
const fs=require('node:fs'),vm=require('node:vm'),assert=require('node:assert/strict');
const context={setTimeout,clearTimeout};vm.createContext(context);
vm.runInContext(fs.readFileSync('app/preferences.js','utf8'),context);
const {PreferenceStore}=context.ASFBPreferences;
function fixture(seed={},schemas={}){
 const jar=new Map(Object.entries(seed)),messages=[];
 const store=new PreferenceStore({read:()=>[...jar].map(([k,v])=>k+'='+v).join('; '),
  write:(name,value,age)=>age?jar.set(name,value):jar.delete(name),schemas,status:s=>messages.push(s)});
 return {jar,store,messages};
}
const cookie=values=>encodeURIComponent(JSON.stringify({v:1,values}));
function bind(store,key,defaultValue=1,group='pipeline'){
 const field={value:defaultValue};
 store.register(group,key,{defaultValue,get:()=>field.value,set:v=>field.value=v,
  valid:v=>typeof v===typeof defaultValue&&(!Array.isArray(v))});
 return field;
}
{
 const {store,jar}=fixture({asfb_pref_pipeline:cookie({limit:42,retiredKey:'preserve'})});
 const old=bind(store,'limit'),added=bind(store,'newFeature',false);
 assert.equal(old.value,42);assert.equal(added.value,false);
 added.value=true;store.flush();
 const data=JSON.parse(decodeURIComponent(jar.get('asfb_pref_pipeline')));
 assert.equal(data.values.limit,42);assert.equal(data.values.retiredKey,'preserve');
 assert.equal(data.values.newFeature,true);
}
{
 const {store,jar}=fixture({asfb_pref_pipeline:cookie({bad:'not-a-number',good:7})});
 assert.equal(bind(store,'bad').value,1);assert.equal(bind(store,'good').value,7);
 const good=bind(store,'good');good.value=9;store.flush();
 assert.equal(JSON.parse(decodeURIComponent(jar.get('asfb_pref_pipeline'))).values.good,9);
}
{
 const future=encodeURIComponent(JSON.stringify({v:3,values:{limit:8,newThing:9}}));
 const {store,jar,messages}=fixture({asfb_pref_pipeline:future});
 const field=bind(store,'limit');assert.equal(field.value,8);
 field.value=2;store.flush();assert.equal(jar.get('asfb_pref_pipeline'),future);
 assert(messages.some(s=>s.includes('Newer')));
}
{
 const old=encodeURIComponent(JSON.stringify({v:0,values:{oldLimit:12,unknown:true}}));
 const {store,jar}=fixture({asfb_pref_pipeline:old},{pipeline:{version:1,migrations:{0:v=>({...v,limit:v.oldLimit})}}});
 const field=bind(store,'limit');assert.equal(field.value,12);field.value=13;store.flush();
 const saved=JSON.parse(decodeURIComponent(jar.get('asfb_pref_pipeline')));
 assert.equal(saved.v,1);assert.equal(saved.values.unknown,true);assert.equal(saved.values.limit,13);
}
{
 const {store,jar}=fixture({asfb_pref_pipeline:'%broken',asfb_pref_view:cookie({sort:'oldest'})});
 assert.equal(bind(store,'limit').value,1);assert.equal(bind(store,'sort','newest','view').value,'oldest');
 assert.equal(jar.get('asfb_pref_pipeline'),'%broken');
}
{
 const {store,jar}=fixture({asfb_session:'keep',asfb_pref_pipeline:cookie({limit:5}),asfb_pref_future:cookie({x:1})});
 const value=bind(store,'limit');value.value=9;store.reset();store.flush();
 assert.equal(jar.size,1);assert.equal(jar.get('asfb_session'),'keep');
}
{
 const {store,jar,messages}=fixture();
 const text=bind(store,'large','');text.value='x'.repeat(4000);store.flush();
 assert(!jar.has('asfb_pref_pipeline'));assert(messages.some(s=>s.includes('too large')));
}
{
 const {store,jar}=fixture(),first=bind(store,'first'),second=bind(store,'second');
 jar.set('asfb_pref_pipeline',cookie({otherTab:9}));
 first.value=2;store.flush();
 assert.equal(JSON.parse(decodeURIComponent(jar.get('asfb_pref_pipeline'))).values.otherTab,9);
 second.value=3;store.flush();
 assert.equal(JSON.parse(decodeURIComponent(jar.get('asfb_pref_pipeline'))).values.first,2);
}
{
 const {store,jar}=fixture(),removed=bind(store,'builtin.old',true,'nuclei');
 store.unregister('nuclei','builtin.');removed.value=false;store.flush();
 assert(!jar.has('asfb_pref_nuclei'));
}
{
 let value=1;const messages=[];
 const store=new PreferenceStore({read:()=>'',write:()=>{},status:s=>messages.push(s)});
 store.register('pipeline','limit',{defaultValue:1,get:()=>value,set:v=>value=v,valid:v=>typeof v==='number'});
 value=2;store.flush();assert(messages.some(s=>s.includes('blocked')));
}
console.log('Preference store checks passed: additive defaults, migrations, future versions, isolated corruption, cookie limits, merged writes, selective reset and blocked cookies');
