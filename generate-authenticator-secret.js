'use strict';
const crypto=require('node:crypto');const bytes=crypto.randomBytes(20);let bits='';for(const b of bytes)bits+=b.toString(2).padStart(8,'0');let secret='';for(let i=0;i<bits.length;i+=5)secret+='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'[parseInt(bits.slice(i,i+5),2)];
console.log('SORA_TOTP_SECRET (keep private):\n'+secret+'\n\nAdd this setup key manually to your authenticator app.\nAccount: SORA Owner | Type: Time-based | Digits: 6 | Period: 30 seconds | Algorithm: SHA1\nSave a private recovery copy. Never commit it to Git or send it to customers.');
