'use strict';
const crypto=require('node:crypto');
const password=process.env.SORA_ADMIN_KEY||'', secret=(process.env.SORA_TOTP_SECRET||'').replace(/\s/g,'').toUpperCase();
if(password.length<32||!/^[A-Z2-7]{32,}$/.test(secret))throw Error('Set SORA_ADMIN_KEY (32+ characters) and SORA_TOTP_SECRET (32+ base32 characters). See setup instructions.');
const prod=process.env.NODE_ENV==='production', origin=process.env.PUBLIC_ORIGIN||process.env.RENDER_EXTERNAL_URL||'http://localhost:8787';
if(prod&&!origin.startsWith('https://'))throw Error('Production PUBLIC_ORIGIN must use HTTPS');
const sessions=new Map(), attempts=[];let lastStep=-1;
const digest=s=>crypto.createHash('sha256').update(s).digest('hex');
const eq=(a,b)=>crypto.timingSafeEqual(Buffer.from(digest(a)),Buffer.from(digest(b)));
const cookieName=prod?'__Host-sora_owner':'sora_owner';
function cookie(value,age){return `${cookieName}=${value}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${age}${prod?'; Secure':''}`;}
function session(req){const raw=(req.headers.cookie||'').split(';').map(s=>s.trim()).find(s=>s.startsWith(cookieName+'='));if(!raw)return null;const key=digest(raw.slice(cookieName.length+1)),s=sessions.get(key);if(!s)return null;if(s.expires<Date.now()){sessions.delete(key);return null;}return {...s,key};}
function sameOrigin(req){return req.headers.origin===origin;}
function totp(code){if(!/^\d{6}$/.test(code))return false;let bits='';for(const c of secret)bits+='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'.indexOf(c).toString(2).padStart(5,'0');const bytes=Buffer.from((bits.match(/.{8}/g)||[]).map(b=>parseInt(b,2)));const now=Math.floor(Date.now()/30000);for(const step of [now-1,now,now+1]){if(step<=lastStep)continue;const b=Buffer.alloc(8);b.writeBigUInt64BE(BigInt(step));const h=crypto.createHmac('sha1',bytes).update(b).digest(),o=h[19]&15;const expected=String((h.readUInt32BE(o)&0x7fffffff)%1000000).padStart(6,'0');if(eq(code,expected)){lastStep=step;return true;}}return false;}
exports.authorize=(req,res,json)=>{const s=session(req);if(!s){json(res,401,{error:'Sign in as owner'});return false;}if(!['GET','HEAD'].includes(req.method)&&(!sameOrigin(req)||!eq(req.headers['x-csrf-token']||'',s.csrf))){json(res,403,{error:'Request rejected'});return false;}return true;};
exports.route=async(req,res,u,json,body)=>{
 if(!['/auth/login','/auth/session','/auth/logout'].includes(u.pathname))return false;
 if(u.pathname==='/auth/session'&&req.method==='GET'){const s=session(req);json(res,s?200:401,s?{csrf:s.csrf}:{error:'Sign in'});return true;}
 if(req.method!=='POST'||!sameOrigin(req)){json(res,403,{error:'Request rejected'});return true;}
 if(u.pathname==='/auth/logout'){const s=session(req);if(!s||!eq(req.headers['x-csrf-token']||'',s.csrf)){json(res,403,{error:'Request rejected'});return true;}sessions.delete(s.key);res.setHeader('Set-Cookie',cookie('',0));json(res,200,{ok:true});return true;}
 if(u.pathname!=='/auth/login'){json(res,405,{error:'Method not allowed'});return true;}
 const now=Date.now();while(attempts.length&&attempts[0]<now-600000)attempts.shift();if(attempts.length>=10){res.setHeader('Retry-After','600');json(res,429,{error:'Too many attempts. Wait 10 minutes.'});return true;}attempts.push(now);
 const b=await body(req);if(!eq(String(b.password||''),password)||!totp(String(b.code||''))){json(res,401,{error:'Incorrect owner password or authenticator code'});return true;}
 attempts.length=0;for(const [k,s] of sessions)if(s.expires<now)sessions.delete(k);if(sessions.size>=5)sessions.delete(sessions.keys().next().value);
 const token=crypto.randomBytes(32).toString('hex'),csrf=crypto.randomBytes(32).toString('hex');sessions.set(digest(token),{csrf,expires:now+3600000});res.setHeader('Set-Cookie',cookie(token,3600));json(res,200,{csrf});return true;
};
