'use strict';
const http=require('node:http'),fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const DATA=process.env.DATA_DIR||path.join(__dirname,'data');
fs.mkdirSync(DATA,{recursive:true,mode:0o700});
const ROOT=path.join(DATA,'private-videos'),DB=path.join(DATA,'licenses.json');fs.mkdirSync(ROOT,{recursive:true,mode:0o700});
const auth=require('./owner-auth');

const hash=x=>crypto.createHash('sha256').update(x).digest('hex');
const equal=(a,b)=>crypto.timingSafeEqual(Buffer.from(hash(a)),Buffer.from(hash(b)));
if(!fs.existsSync(DB))fs.writeFileSync(DB,JSON.stringify({enabled:true,licenses:[]}),{mode:0o600});
const read=()=>JSON.parse(fs.readFileSync(DB,'utf8'));
function save(d){fs.writeFileSync(DB+'.tmp',JSON.stringify(d,null,2),{mode:0o600});fs.renameSync(DB+'.tmp',DB);}
function json(res,status,data){res.writeHead(status,{'Content-Type':'application/json','Cache-Control':'no-store'});res.end(JSON.stringify(data));}
async function body(req){let s='';for await(const chunk of req){s+=chunk;if(s.length>8192)throw Error('Request too large');}return JSON.parse(s);}
http.createServer(async(req,res)=>{try{
res.setHeader('Cache-Control','no-store');res.setHeader('X-Content-Type-Options','nosniff');res.setHeader('Referrer-Policy','no-referrer');res.setHeader('X-Frame-Options','DENY');res.setHeader('Content-Security-Policy',"default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'");if(process.env.NODE_ENV==='production')res.setHeader('Strict-Transport-Security','max-age=31536000');
const u=new URL(req.url,'http://localhost'),token=(req.headers.authorization||'').replace(/^Bearer /,'');
if(u.pathname==='/healthz')return json(res,200,{ok:true});
if(await auth.route(req,res,u,json,body))return;
if(['/admin.js','/style.css'].includes(u.pathname)&&req.method==='GET'){res.setHeader('Content-Type',u.pathname.endsWith('.js')?'text/javascript':'text/css');return res.end(fs.readFileSync(path.join(__dirname,u.pathname.slice(1))));}
if(u.pathname==='/'&&req.method==='GET'){res.setHeader('Content-Type','text/html; charset=utf-8');return res.end(fs.readFileSync(path.join(__dirname,'admin.html')));}
if(u.pathname.startsWith('/admin/')){
 if(!auth.authorize(req,res,json))return;
 if(req.method==='PUT'&&u.pathname==='/admin/upload'){
 const name=u.searchParams.get('name')||'';if(!name||name.startsWith('.')||/[\\/\x00]/.test(name)||! /\.(mp4|webm|mov)$/i.test(name))return json(res,400,{error:'Invalid video filename'});
 const tmp=path.join(ROOT,'.upload-'+crypto.randomUUID());let size=0;const handle=await fs.promises.open(tmp,'wx',0o600);try{for await(const chunk of req){size+=chunk.length;if(size>64*1024*1024)throw Error('Video exceeds 64 MB');await handle.writeFile(chunk);}if(!size)throw Error('Empty upload');await handle.close();await fs.promises.rename(tmp,path.join(ROOT,name));return json(res,200,{ok:true});}catch(e){await handle.close().catch(()=>{});await fs.promises.unlink(tmp).catch(()=>{});throw e;}
 }
 const d=read();
 if(req.method==='GET'&&u.pathname==='/admin/state')return json(res,200,{enabled:d.enabled,videoCount:fs.readdirSync(ROOT).filter(n=>/\.(mp4|webm|mov)$/i.test(n)).length,licenses:d.licenses.map(({keyHash,...l})=>l)});
 if(req.method!=='POST')return json(res,405,{error:'Method not allowed'});
 const b=await body(req);Object.assign(d,read());
 if(u.pathname==='/admin/create') {const key=crypto.randomBytes(32).toString('hex'),id=crypto.randomUUID();d.licenses.push({id,name:String(b.name||'Customer').slice(0,100),enabled:true,keyHash:hash(key)});save(d);return json(res,200,{id,key});}
 if(u.pathname==='/admin/toggle'){const l=d.licenses.find(l=>l.id===b.id);if(!l)return json(res,404,{error:'Unknown license'});l.enabled=b.enabled===true;save(d);return json(res,200,{ok:true});}
 if(u.pathname==='/admin/service'){d.enabled=b.enabled===true;save(d);return json(res,200,{ok:true});}
 return json(res,404,{error:'Not found'});
}
const d=read();if(!token||!d.enabled||!d.licenses.some(l=>l.enabled&&equal(l.keyHash,hash(token))))return json(res,403,{error:'Video access disabled or invalid license'});
if(!['GET','HEAD'].includes(req.method))return json(res,405,{error:'Method not allowed'});
if(u.pathname==='/api/videos')return json(res,200,{files:fs.readdirSync(ROOT).filter(n=>/\.(mp4|webm|mov)$/i.test(n))});
if(!u.pathname.startsWith('/api/video/'))return json(res,404,{error:'Not found'});
const name=decodeURIComponent(u.pathname.slice(11));if(!name||/[\\/\x00]/.test(name)||! /\.(mp4|webm|mov)$/i.test(name))return json(res,400,{error:'Invalid filename'});
const file=path.join(ROOT,name);let stat;try{stat=fs.lstatSync(file);}catch{return json(res,404,{error:'Missing video'});}if(!stat.isFile()||stat.isSymbolicLink())return json(res,404,{error:'Missing video'});
let start=0,end=stat.size-1,status=200;
if(req.headers.range){const m=/^bytes=(\d*)-(\d*)$/.exec(req.headers.range);if(!m||(!m[1]&&!m[2])){res.setHeader('Content-Range','bytes */'+stat.size);return res.writeHead(416).end();}if(m[1]){start=Number(m[1]);end=m[2]?Math.min(Number(m[2]),end):end;}else start=Math.max(0,stat.size-Number(m[2]));if(start>end||start<0||!Number.isSafeInteger(start)||!Number.isSafeInteger(end)){res.setHeader('Content-Range','bytes */'+stat.size);return res.writeHead(416).end();}status=206;res.setHeader('Content-Range',`bytes ${start}-${end}/${stat.size}`);}
res.setHeader('Content-Type',name.endsWith('.webm')?'video/webm':name.endsWith('.mov')?'video/quicktime':'video/mp4');res.setHeader('Accept-Ranges','bytes');res.setHeader('Content-Length',end-start+1);res.writeHead(status);if(req.method==='HEAD')return res.end();const stream=fs.createReadStream(file,{start,end});stream.on('error',()=>res.destroy());res.on('close',()=>stream.destroy());stream.pipe(res);
}catch(e){if(!res.headersSent)json(res,400,{error:'Request failed'});else res.destroy();}}).listen(Number(process.env.PORT||8787),process.env.HOST||'0.0.0.0',()=>console.log('SORA Video API listening'));
