const express = require('express');
const session = require('express-session');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'aztan.sqlite');
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'ChangeMe-Immediately-2026!';
if (process.env.NODE_ENV === 'production' && (!process.env.SESSION_SECRET || !process.env.ADMIN_PASSWORD)) {
  console.warn('WARNING: Set SESSION_SECRET and ADMIN_PASSWORD in production environment.');
}
const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.exec(`
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS orders (
 id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, phone TEXT NOT NULL,
 quantity INTEGER NOT NULL, amount INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'pending',
 created_at TEXT NOT NULL, ticket_numbers TEXT DEFAULT '[]'
);
CREATE TABLE IF NOT EXISTS winners (
 id INTEGER PRIMARY KEY AUTOINCREMENT, prize TEXT NOT NULL, order_id INTEGER NOT NULL,
 name TEXT NOT NULL, phone TEXT NOT NULL, ticket_number TEXT NOT NULL, created_at TEXT NOT NULL
);
`);
const defaults = {
 title:'АЗТАН — Том азтан тодорно!', description:'Сугалаандаа оролцоод азтан болоорой.',
 ticketPrice:'5000', totalTickets:'1000', startAt:'', endAt:'',
 bankName:'', accountNumber:'', accountOwner:'', qrUrl:'',
 prizes:JSON.stringify(['Утасны кейс — 10 азтан','Утасгүй чихэвч — 5 азтан','10,000mAh Power bank — 2 азтан','iPhone 17 Pro Max — 1 азтан'])
};
const getSetting = db.prepare('SELECT value FROM settings WHERE key=?');
const setSetting = db.prepare('INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value');
for (const [k,v] of Object.entries(defaults)) if (!getSetting.get(k)) setSetting.run(k,v);
function settings() {
 const out={}; for (const k of Object.keys(defaults)) out[k]=getSetting.get(k).value;
 out.prizes=JSON.parse(out.prizes);
 return out;
}
app.set('trust proxy', 1);
app.use(helmet({contentSecurityPolicy:false}));
app.use(express.json({limit:'1mb'}));
app.use(express.urlencoded({extended:false}));
app.use(session({
 secret:process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex'),
 resave:false, saveUninitialized:false,
 cookie:{httpOnly:true,sameSite:'lax',secure:process.env.NODE_ENV==='production',maxAge:8*60*60*1000}
}));
const publicLimiter=rateLimit({windowMs:15*60*1000,limit:30,standardHeaders:true,legacyHeaders:false});
const loginLimiter=rateLimit({windowMs:15*60*1000,limit:8,standardHeaders:true,legacyHeaders:false});
const admin=(req,res,next)=>req.session && req.session.admin ? next() : res.status(401).json({error:'Админ эрх шаардлагатай.'});
app.use(express.static(path.join(__dirname,'public')));
app.get('/api/public', (req,res)=>{
 const s=settings();
 const paid=db.prepare("SELECT COUNT(*) c, COALESCE(SUM(quantity),0) q FROM orders WHERE status='paid'").get();
 res.json({...s,soldTickets:paid.q,remainingTickets:Math.max(0,Number(s.totalTickets)-paid.q)});
});
app.post('/api/orders', publicLimiter, (req,res)=>{
 const name=String(req.body.name||'').trim().slice(0,100);
 const phone=String(req.body.phone||'').trim().slice(0,30);
 const quantity=Number(req.body.quantity);
 if(name.length<2 || phone.length<6 || !Number.isInteger(quantity) || quantity<1 || quantity>20) return res.status(400).json({error:'Нэр, утас болон тасалбарын тоогоо зөв оруулна уу. Нэг захиалгаар 1–20 тасалбар авна.'});
 const s=settings(), paid=db.prepare("SELECT COALESCE(SUM(quantity),0) q FROM orders WHERE status='paid'").get().q;
 if(s.startAt && Date.now()<new Date(s.startAt).getTime()) return res.status(400).json({error:'Сугалаа хараахан эхлээгүй байна.'});
 if(s.endAt && Date.now()>new Date(s.endAt).getTime()) return res.status(400).json({error:'Сугалааны хугацаа дууссан байна.'});
 if(paid+quantity>Number(s.totalTickets)) return res.status(400).json({error:'Үлдсэн тасалбар хүрэлцэхгүй байна.'});
 const amount=quantity*Number(s.ticketPrice);
 const info=db.prepare('INSERT INTO orders(name,phone,quantity,amount,status,created_at) VALUES(?,?,?,?,?,?)')
  .run(name,phone,quantity,amount,'pending',new Date().toISOString());
 res.json({ok:true,orderId:info.lastInsertRowid,amount,bankName:s.bankName,accountNumber:s.accountNumber,accountOwner:s.accountOwner,qrUrl:s.qrUrl,message:'Захиалга хүлээн авлаа. Шилжүүлгээ хийж, админ төлбөрийг баталгаажуулахыг хүлээнэ үү.'});
});
app.post('/api/admin/login',loginLimiter,async(req,res)=>{
 const pass=String(req.body.password||'');
 let ok=false;
 if(process.env.ADMIN_PASSWORD_HASH) ok=await bcrypt.compare(pass,process.env.ADMIN_PASSWORD_HASH);
 else ok=pass===ADMIN_PASSWORD;
 if(!ok)return res.status(401).json({error:'Нууц үг буруу байна.'});
 req.session.admin=true; res.json({ok:true});
});
app.post('/api/admin/logout',admin,(req,res)=>req.session.destroy(()=>res.json({ok:true})));
app.get('/api/admin/me',admin,(req,res)=>res.json({ok:true}));
app.get('/api/admin/orders',admin,(req,res)=>{
 res.json(db.prepare('SELECT * FROM orders ORDER BY id DESC LIMIT 500').all());
});
app.put('/api/admin/settings',admin,(req,res)=>{
 const allowed=['title','description','ticketPrice','totalTickets','startAt','endAt','bankName','accountNumber','accountOwner','qrUrl'];
 for(const k of allowed) if(req.body[k]!==undefined) setSetting.run(k,String(req.body[k]).slice(0,1000));
 if(Array.isArray(req.body.prizes)) setSetting.run('prizes',JSON.stringify(req.body.prizes.map(x=>String(x).slice(0,150)).slice(0,30)));
 res.json({ok:true,settings:settings()});
});
app.post('/api/admin/orders/:id/approve',admin,(req,res)=>{
 const order=db.prepare("SELECT * FROM orders WHERE id=? AND status='pending'").get(req.params.id);
 if(!order)return res.status(404).json({error:'Хүлээгдэж буй захиалга олдсонгүй.'});
 const s=settings();
 const paid=db.prepare("SELECT COALESCE(SUM(quantity),0) q FROM orders WHERE status='paid'").get().q;
 if(paid+order.quantity>Number(s.totalTickets))return res.status(400).json({error:'Нийт тасалбарын хязгаар хүрсэн байна.'});
 const max=db.prepare("SELECT COALESCE(MAX(CAST(ticket_number AS INTEGER)),0) m FROM (SELECT json_each.value AS ticket_number FROM orders,json_each(orders.ticket_numbers) WHERE orders.status='paid')").get().m;
 const nums=Array.from({length:order.quantity},(_,i)=>String(max+i+1).padStart(4,'0'));
 db.prepare("UPDATE orders SET status='paid',ticket_numbers=? WHERE id=?").run(JSON.stringify(nums),order.id);
 res.json({ok:true,ticketNumbers:nums});
});
app.post('/api/admin/orders/:id/reject',admin,(req,res)=>{
 const r=db.prepare("UPDATE orders SET status='rejected' WHERE id=? AND status='pending'").run(req.params.id);
 res.json({ok:r.changes>0});
});
app.post('/api/admin/draw',admin,(req,res)=>{
 const old=db.prepare('SELECT COUNT(*) c FROM winners').get().c;
 if(old) return res.status(409).json({error:'Тохирол аль хэдийн явагдсан байна. Дахин тохирол явуулахыг хаасан.'});
 const s=settings();
 const paid=db.prepare("SELECT * FROM orders WHERE status='paid' ORDER BY id").all();
 const participants=paid.map(o=>({orderId:o.id,name:o.name,phone:o.phone,tickets:JSON.parse(o.ticket_numbers||'[]')}));
 const unique=[...new Map(participants.map(p=>[p.phone,p])).values()];
 if(unique.length<18)return res.status(400).json({error:`18 өөр төлбөр баталгаажсан оролцогч шаардлагатай. Одоогоор ${unique.length} байна.`});
 // Fisher-Yates with cryptographically secure random selection
 for(let i=unique.length-1;i>0;i--){const j=crypto.randomInt(i+1);[unique[i],unique[j]]=[unique[j],unique[i]];}
 const labels=['Кейс 1','Кейс 2','Кейс 3','Кейс 4','Кейс 5','Кейс 6','Кейс 7','Кейс 8','Кейс 9','Кейс 10','Чихэвч 1','Чихэвч 2','Чихэвч 3','Чихэвч 4','Чихэвч 5','Power bank 1','Power bank 2','iPhone 17 Pro Max'];
 const insert=db.prepare('INSERT INTO winners(prize,order_id,name,phone,ticket_number,created_at) VALUES(?,?,?,?,?,?)');
 const tx=db.transaction(()=>labels.forEach((prize,i)=>{const p=unique[i];insert.run(prize,p.orderId,p.name,p.phone,p.tickets[0]||'',new Date().toISOString());}));
 tx();
 res.json({ok:true,winners:db.prepare('SELECT * FROM winners ORDER BY id').all()});
});
app.get('/api/winners',(req,res)=>res.json(db.prepare('SELECT prize,name,ticket_number,created_at FROM winners ORDER BY id').all()));
app.get('*',(req,res)=>res.sendFile(path.join(__dirname,'public','index.html')));
app.listen(PORT,()=>console.log(`AZTAN site listening on ${PORT}`));
