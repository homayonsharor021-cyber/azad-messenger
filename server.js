const express = require('express');
const http = require('http');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const { Server } = require('socket.io');

const app = express();
const server = http.createServer(app);
const io = new Server(server);
const PORT = process.env.PORT || 3000;
const SECRET = process.env.JWT_SECRET || 'CHANGE_THIS_SECRET_BEFORE_PUBLIC_DEPLOYMENT';
const DATA = path.join(__dirname, 'data');
const UPLOADS = path.join(__dirname, 'uploads');
fs.mkdirSync(DATA, {recursive:true});
fs.mkdirSync(UPLOADS, {recursive:true});
const USERS = path.join(DATA, 'users.json');
const MESSAGES = path.join(DATA, 'messages.json');
for (const f of [USERS, MESSAGES]) if (!fs.existsSync(f)) fs.writeFileSync(f, '[]');
const read = f => JSON.parse(fs.readFileSync(f, 'utf8'));
const write = (f, v) => fs.writeFileSync(f, JSON.stringify(v, null, 2));
app.use(express.json({limit:'1mb'}));
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(UPLOADS));

const storage = multer.diskStorage({
  destination: (_, __, cb) => cb(null, UPLOADS),
  filename: (_, file, cb) => cb(null, crypto.randomUUID() + path.extname(file.originalname).slice(0,12))
});
const upload = multer({storage, limits:{fileSize:100*1024*1024}});

function auth(req,res,next) {
  const token = (req.headers.authorization || '').replace(/^Bearer\s+/,'');
  try { req.user = jwt.verify(token, SECRET); next(); }
  catch { res.status(401).json({error:'ابتدا وارد حساب شوید'}); }
}
app.post('/api/register', async (req,res) => {
  const username = String(req.body.username || '').trim();
  const password = String(req.body.password || '');
  if (!/^[A-Za-z0-9_]{3,20}$/.test(username))
    return res.status(400).json({error:'نام کاربری باید ۳ تا ۲۰ حرف انگلیسی، عدد یا _ باشد'});
  if (password.length < 6) return res.status(400).json({error:'رمز باید حداقل ۶ کاراکتر باشد'});
  const users = read(USERS);
  if (users.some(u => u.username.toLowerCase() === username.toLowerCase()))
    return res.status(409).json({error:'این نام کاربری قبلاً ثبت شده است'});
  users.push({id:crypto.randomUUID(), username, password:await bcrypt.hash(password,12), createdAt:Date.now()});
  write(USERS, users);
  res.json({ok:true});
});
app.post('/api/login', async (req,res) => {
  const username = String(req.body.username || '').trim();
  const password = String(req.body.password || '');
  const user = read(USERS).find(u => u.username.toLowerCase() === username.toLowerCase());
  if (!user || !(await bcrypt.compare(password,user.password)))
    return res.status(401).json({error:'نام کاربری یا رمز اشتباه است'});
  const token = jwt.sign({id:user.id, username:user.username}, SECRET, {expiresIn:'30d'});
  res.json({token, username:user.username});
});
app.get('/api/users', auth, (req,res) => {
  res.json(read(USERS).filter(u=>u.id!==req.user.id).map(u=>({id:u.id,username:u.username})));
});
app.get('/api/messages/:otherId', auth, (req,res) => {
  const msgs = read(MESSAGES).filter(m =>
    (m.from===req.user.id && m.to===req.params.otherId) ||
    (m.to===req.user.id && m.from===req.params.otherId)
  );
  res.json(msgs.slice(-300));
});
app.post('/api/upload', auth, upload.single('file'), (req,res) => {
  if (!req.file) return res.status(400).json({error:'فایلی انتخاب نشده'});
  res.json({url:'/uploads/'+req.file.filename, name:req.file.originalname, mime:req.file.mimetype, size:req.file.size});
});

const online = new Map();
io.use((socket,next)=>{
  try {
    const token = socket.handshake.auth.token;
    socket.user = jwt.verify(token, SECRET);
    next();
  } catch { next(new Error('unauthorized')); }
});
io.on('connection', socket => {
  online.set(socket.user.id, socket.id);
  socket.on('send-message', payload => {
    const to = String(payload.to || '');
    const text = String(payload.text || '').slice(0,5000);
    const attachment = payload.attachment || null;
    if (!read(USERS).some(u=>u.id===to) || (!text && !attachment)) return;
    const msg = {id:crypto.randomUUID(), from:socket.user.id, fromName:socket.user.username,
      to, text, attachment, createdAt:Date.now()};
    const msgs = read(MESSAGES); msgs.push(msg); write(MESSAGES,msgs);
    socket.emit('new-message',msg);
    const target = online.get(to);
    if (target) io.to(target).emit('new-message',msg);
  });
  socket.on('disconnect',()=>{ if(online.get(socket.user.id)===socket.id) online.delete(socket.user.id); });
});
server.listen(PORT,()=>console.log(`Azad Messenger running on port ${PORT}`));
