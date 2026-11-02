/* Versioned browser preferences. No scan artifacts, credentials or authorizations. */
(function(root){
 'use strict';
 const PREFIX='asfb_pref_';
 const plain=v=>v!==null&&typeof v==='object'&&!Array.isArray(v);
 const same=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
 class PreferenceStore{
  constructor({read,write,schemas={},status=()=>{}}){
   this.read=read;this.write=write;this.schemas=schemas;this.status=status;
   this.fields=[];this.timer=null;
  }
  schema(group){return this.schemas[group]||{version:1,migrations:{}}}
  load(group){
   const name=PREFIX+group,version=this.schema(group).version;
   let raw;
   try{
    const pair=this.read().split(';').map(s=>s.trim()).find(s=>s.startsWith(name+'='));
    if(!pair)return {v:version,values:{}};
    raw=JSON.parse(decodeURIComponent(pair.slice(name.length+1)));
    if(!plain(raw)||!Number.isInteger(raw.v)||raw.v<0||!plain(raw.values))throw Error('format');
    while(raw.v<version){
     const migration=this.schema(group).migrations?.[raw.v];
     raw.values=migration?migration(raw.values):raw.values;
     if(!plain(raw.values))throw Error('migration');
     raw.v++;
    }
    return raw;
   }catch(e){this.status('Some saved preferences were unreadable; valid settings are retained.');return {v:version,values:{}}}
  }
  register(group,key,{get,set,defaultValue,valid}){
   if(!/^[a-z0-9_-]{1,32}$/.test(group)||!/^[-a-zA-Z0-9_.]{1,100}$/.test(key))throw Error('Invalid preference key');
   const saved=this.load(group);
   const value=Object.hasOwn(saved.values,key)&&valid(saved.values[key])?saved.values[key]:defaultValue;
   set(value);
   // A normalizer may append new defaults. Do not overwrite older stored data on load.
   this.fields=this.fields.filter(field=>field.group!==group||field.key!==key);
   this.fields.push({group,key,get,defaultValue,valid,last:get()});
  }
  unregister(group,prefix=''){this.fields=this.fields.filter(field=>field.group!==group||!field.key.startsWith(prefix))}
  flush(){
   clearTimeout(this.timer);
   const patches=new Map();
   for(const field of this.fields){
    const value=field.get();
    if(!field.valid(value)||same(value,field.last))continue;
    if(!patches.has(field.group))patches.set(field.group,[]);
    patches.get(field.group).push({field,value});
   }
   for(const [group,changes] of patches){
    const data=this.load(group),version=this.schema(group).version;
    if(data.v>version){this.status('Newer preference data retained; this page will not overwrite it.');continue}
    for(const {field,value} of changes){
     if(same(value,field.defaultValue))delete data.values[field.key];
     else Object.defineProperty(data.values,field.key,{value,enumerable:true,writable:true,configurable:true});
    }
    const encoded=encodeURIComponent(JSON.stringify(data)),name=PREFIX+group;
    if(name.length+encoded.length>3800){this.status('Preference group is too large to save; previous saved values retained.');continue}
    try{
     this.write(name,encoded,31536000);
     const readBack=this.read().split(';').map(s=>s.trim()).find(s=>s.startsWith(name+'='));
     if(readBack!==name+'='+encoded)throw Error('blocked');
     changes.forEach(({field,value})=>field.last=value);
     this.status('Settings saved in this browser.');
    }catch(e){this.status('Browser blocked preference cookies; settings apply to this page only.')}
   }
  }
  schedule(){clearTimeout(this.timer);this.timer=setTimeout(()=>this.flush(),300)}
  reset(){
   clearTimeout(this.timer);this.fields=[];
   for(const part of this.read().split(';')){
    const name=part.trim().split('=')[0];
    if(new RegExp('^'+PREFIX+'[a-z0-9_-]{1,32}$').test(name))this.write(name,'',0);
   }
  }
 }
 root.ASFBPreferences={PreferenceStore,PREFIX};
})(typeof window!=='undefined'?window:globalThis);
