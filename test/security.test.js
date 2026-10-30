'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict'),{spawn}=require('node:child_process'),fs=require('node:fs'),os=require('node:os'),path=require('node:path'),crypto=require('node:crypto');
test('owner authentication, video permissions, uploads and persistent state',async()=>{
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'sora-test-')),port=18978,base=`http://localhost:${port}`,password='unit-test-'+crypto.randomBytes(32).toString('hex'),secret='JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP';let processHandle,cookie='',csrf='';
 function start(){processHandle=spawn(process.execPath,['server.js'],{cwd:path.join(__dirname,'..'),env:{...process.env,NODE_ENV:'test',PORT:String(port),PUBLIC_ORIGIN:base,DATA_DIR:dir,SORA_ADMIN_KEY:password,SORA_TOTP_SECRET:secret},stdio:'pipe'});}
 async function ready(){for(let i=0;i<60;i++){try{if((await fetch(base+'/healthz')).ok)return;}catch{}await new Promise(r=>setTimeout(r,50));}throw Error('Server failed to start');}
 async function stop(){if(processHandle.exitCode!==null)return;const done=new Promise(r=>processHandle.once('exit',r));processHandle.kill();await done;}
 const req=(route,options={})=>fetch(base+route,options);
 const post=(route,data,headers={})=>req(route,{method:'POST',headers:{Origin:base,'Content-Type':'application/json',Cookie:cookie,'X-CSRF-Token':csrf,...headers},body:JSON.stringify(data)});
 function code(){let bits='';for(const c of secret)bits+='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'.indexOf(c).toString(2).padStart(5,'0');const key=Buffer.from(bits.match(/.{8}/g).map(x=>parseInt(x,2))),b=Buffer.alloc(8);b.writeBigUInt64BE(BigInt(Math.floor(Date.now()/30000)));const h=crypto.createHmac('sha1',key).update(b).digest(),o=h[19]&15;return String((h.readUInt32BE(o)&0x7fffffff)%1000000).padStart(6,'0');}
 try{start();await ready();
 assert.equal((await req('/admin/state')).status,401);
 assert.equal((await req('/admin/state',{headers:{Authorization:'Bearer '+password}})).status,401);
 assert.equal((await post('/auth/login',{password,code:'wrong'})).status,401);
 const login=await post('/auth/login',{password,code:code()});assert.equal(login.status,200);const rawCookie=login.headers.get('set-cookie');assert.match(rawCookie,/HttpOnly/);assert.match(rawCookie,/SameSite=Strict/);cookie=rawCookie.split(';')[0];csrf=(await login.json()).csrf;
 assert.equal((await post('/admin/create',{name:'A'},{'X-CSRF-Token':'fake'})).status,403);
 assert.equal((await post('/admin/create',{name:'A'},{Origin:'https://evil.example'})).status,403);
 const customer=await (await post('/admin/create',{name:'<img src=x onerror=alert(1)>'})).json();assert.ok(customer.key);
 assert.equal((await req('/admin/state',{headers:{Authorization:'Bearer '+customer.key}})).status,401);
 const upload=await req('/admin/upload?name=demo.mp4',{method:'PUT',headers:{Cookie:cookie,Origin:base,'X-CSRF-Token':csrf},body:Buffer.from('0123456789abcdef')});assert.equal(upload.status,200);
 assert.equal((await req('/admin/upload?name=..%2Fbad.mp4',{method:'PUT',headers:{Cookie:cookie,Origin:base,'X-CSRF-Token':csrf},body:'bad'})).status,400);
 const h={Authorization:'Bearer '+customer.key};assert.equal((await req('/api/videos')).status,403);assert.deepEqual((await (await req('/api/videos',{headers:h})).json()).files,['demo.mp4']);
 const video=await req('/api/video/demo.mp4',{headers:{...h,Range:'bytes=2-5'}});assert.equal(video.status,206);assert.equal(await video.text(),'2345');assert.equal((await req('/api/video/demo.mp4',{headers:{...h,Range:'bytes=999-'}})).status,416);
 const state=await (await req('/admin/state',{headers:{Cookie:cookie}})).json();assert.equal(state.videoCount,1);assert.equal(state.licenses[0].keyHash,undefined);
 await post('/admin/toggle',{id:customer.id,enabled:false});assert.equal((await req('/api/videos',{headers:h})).status,403);
 await post('/admin/toggle',{id:customer.id,enabled:true});await post('/admin/service',{enabled:false});assert.equal((await req('/api/videos',{headers:h})).status,403);await post('/admin/service',{enabled:true});
 const html=await req('/');assert.match(html.headers.get('content-security-policy'),/frame-ancestors 'none'/);assert.equal((await req('/data/licenses.json',{headers:h})).status,404);
 await post('/auth/logout',{});assert.equal((await req('/admin/state',{headers:{Cookie:cookie}})).status,401);
 for(let i=0;i<10;i++)await post('/auth/login',{password:'bad',code:'000000'});assert.equal((await post('/auth/login',{password:'bad',code:'000000'})).status,429);
 await stop();start();await ready();assert.equal((await req('/api/videos',{headers:h})).status,200);assert.ok(fs.existsSync(path.join(dir,'private-videos','demo.mp4')));
 }finally{await stop();fs.rmSync(dir,{recursive:true,force:true});}
});
