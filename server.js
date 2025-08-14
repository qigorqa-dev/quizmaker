// Quiz Maker — v16 Sprint1 Fix Clean (single-file API)
const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const initSqlJs = require('sql.js');

const app = express();
const PORT = 38216;
app.use(express.json({ limit: '2mb' }));

const cfgPath = path.join(process.env.HOME || process.env.USERPROFILE || '.', '.quizmaker_cfg.json');
let settings = { base: 'http://127.0.0.1:11434', model: 'llama3:instruct' };
try{ if (fs.existsSync(cfgPath)) settings = JSON.parse(fs.readFileSync(cfgPath,'utf8')); }catch{}
function normBase(b){
  b = String(b||'').trim();
  if (!/^https?:\/\//i.test(b)) b = 'http://' + b;
  b = b.replace('localhost','127.0.0.1').replace(/\/+$/,'');
  if(!/\/api$/i.test(b)) b += '/api';
  return b;
}
function saveCfg(){ try{ fs.writeFileSync(cfgPath, JSON.stringify(settings)); }catch{} }

let SQL, db, dbPath;
async function initDB(){
  SQL = await initSqlJs();
  dbPath = path.join(process.cwd(), 'quizmaker.db');
  if (fs.existsSync(dbPath)) db = new SQL.Database(fs.readFileSync(dbPath));
  else db = new SQL.Database();
  ddl(); persist();
}
function persist(){ const data = db.export(); fs.writeFileSync(dbPath, Buffer.from(data)); }
function exec(sql, params=[]){ const st=db.prepare(sql); st.bind(params); while(st.step()){} st.free(); persist(); }
function one(sql, params=[]){ const st=db.prepare(sql); st.bind(params); let r=null; if(st.step()) r=st.getAsObject(); st.free(); return r; }
function all(sql, params=[]){ const st=db.prepare(sql); st.bind(params); const out=[]; while(st.step()) out.push(st.getAsObject()); st.free(); return out; }
function ddl(){
  exec(`CREATE TABLE IF NOT EXISTS users(
    user_id TEXT PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    password_salt TEXT NOT NULL,
    created_at INTEGER NOT NULL
  )`);
  exec(`CREATE TABLE IF NOT EXISTS sessions_auth(
    token TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
  )`);
  exec(`CREATE TABLE IF NOT EXISTS content(
    content_id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    raw_text TEXT NOT NULL,
    created_at INTEGER NOT NULL
  )`);
  exec(`CREATE TABLE IF NOT EXISTS summary(
    content_id TEXT PRIMARY KEY,
    summary_json TEXT NOT NULL
  )`);
  exec(`CREATE TABLE IF NOT EXISTS quiz_session(
    session_id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    content_id TEXT NOT NULL,
    created_at INTEGER NOT NULL
  )`);
  exec(`CREATE TABLE IF NOT EXISTS attempt(
    attempt_id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    question_json TEXT NOT NULL,
    chosen_index INTEGER NOT NULL,
    is_correct INTEGER NOT NULL,
    created_at INTEGER NOT NULL
  )`);
  exec(`CREATE TABLE IF NOT EXISTS result(
    result_id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    content_id TEXT NOT NULL,
    correct_count INTEGER NOT NULL,
    wrong_count INTEGER NOT NULL,
    created_at INTEGER NOT NULL
  )`);
}

function rid(n=16){ return crypto.randomBytes(n).toString('hex'); }
async function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')){
  return new Promise((resolve,reject)=>{
    crypto.scrypt(password, salt, 64, {N:16384,r:8,p:1}, (err,dk)=>{
      if(err) return reject(err); resolve({ hash: dk.toString('hex'), salt });
    });
  });
}
async function verifyPassword(password, hash, salt){
  return new Promise((resolve,reject)=>{
    crypto.scrypt(password, salt, 64, {N:16384,r:8,p:1}, (err,dk)=>{
      if(err) return reject(err); resolve(crypto.timingSafeEqual(Buffer.from(hash,'hex'), dk));
    });
  });
}
const APP_SECRET='replace_me_with_random_secret';
function signToken(raw){ const sig = crypto.createHmac('sha256', APP_SECRET).update(raw).digest('hex'); return raw+'.'+sig; }
function verifySigned(tok){
  const i = tok.lastIndexOf('.'); if (i<0) return null;
  const raw=tok.slice(0,i), sig=tok.slice(i+1);
  const sig2=crypto.createHmac('sha256', APP_SECRET).update(raw).digest('hex');
  if (!crypto.timingSafeEqual(Buffer.from(sig,'hex'), Buffer.from(sig2,'hex'))) return null;
  const [id,u,exp]=raw.split('|'); if (!id||!u||!exp) return null;
  if (Date.now()>Number(exp)) return null;
  return { id, user_id:u, exp:Number(exp) };
}
function authRequired(req,res,next){
  const a=req.headers.authorization||'';
  if (!a.startsWith('Bearer ')) return res.status(401).json({ error:'no_token' });
  const token=a.slice(7);
  const parsed=verifySigned(token); if(!parsed) return res.status(401).json({ error:'bad_token' });
  const row=one('SELECT user_id,expires_at FROM sessions_auth WHERE token=?',[token]);
  if(!row || Date.now()>Number(row.expires_at)) return res.status(401).json({ error:'expired' });
  req.user={ user_id: parsed.user_id, token }; next();
}

function tryParse(s){ try{return JSON.parse(s);}catch{return null;} }
function stripTrailingCommas(s){ return s.replace(/,\s*([}\]])/g,'$1'); }
function balanceBrackets(s){
  let out=s;
  let oc=(s.match(/{/g)||[]).length, cc=(s.match(/}/g)||[]).length;
  let osq=(s.match(/\[/g)||[]).length, csq=(s.match(/]/g)||[]).length;
  while(oc>cc){ out+='}'; cc++; } while(osq>csq){ out+=']'; csq++; }
  return out;
}
function extractJsonBlock(text){
  const base=String(text||'').replace(/^\uFEFF/,'').trim();
  const fence=base.match(/```json\s*([\s\S]*?)```/i) || base.match(/```\s*([\s\S]*?)```/i);
  if(fence){ const inner=fence[1].trim(); const x=tryParse(inner)||tryParse(stripTrailingCommas(inner))||tryParse(balanceBrackets(stripTrailingCommas(inner))); if(x) return x; }
  let start=-1, depth=0, inStr=false, esc=false;
  for(let i=0;i<base.length;i++){
    const ch=base[i];
    if(start===-1){ if(ch==='{'||ch==='['){ start=i; depth=1; } continue; }
    if(inStr){ if(esc){esc=false;} else if(ch==='\\'){esc=true;} else if(ch=='"'){inStr=false;} continue; }
    if(ch=='"'){ inStr=true; continue; }
    if(ch==='{'||ch==='[') depth++;
    else if(ch==='}'||ch===']'){ depth--; if(depth===0){ const slice=base.slice(start,i+1); const x=tryParse(slice)||tryParse(stripTrailingCommas(slice))||tryParse(balanceBrackets(stripTrailingCommas(slice))); if(x) return x; break; } }
  }
  const fb=base.indexOf('{'), lb=base.lastIndexOf('}');
  if(fb!==-1 && lb>fb){ const cand=base.slice(fb,lb+1); const x=tryParse(cand)||tryParse(stripTrailingCommas(cand))||tryParse(balanceBrackets(stripTrailingCommas(cand))); if(x) return x; }
  const fsq=base.indexOf('['), lsq=base.lastIndexOf(']');
  if(fsq!==-1 && lsq>fsq){ const cand2=base.slice(fsq,lsq+1); const x=tryParse(cand2)||tryParse(stripTrailingCommas(cand2))||tryParse(balanceBrackets(stripTrailingCommas(cand2))); if(x) return x; }
  return null;
}
function sleep(ms){ return new Promise(r=>setTimeout(r, ms)); }
async function withRetry(fn, {tries=3, delays=[500,1500], label='task'}={}){
  let last;
  for(let i=0;i<tries;i++){
    try{ return await fn(i); }catch(e){ last=e; if(i<tries-1) await sleep(delays[Math.min(i,delays.length-1)]); }
  }
  throw new Error(`${label}_failed: ${last?.message||last}`);
}
async function ollamaChat(messages, { max_tokens=1200, temperature=0.25 }={}, ms=45000){
  const controller = new AbortController(); const t=setTimeout(()=>controller.abort(), ms);
  try{
    const base = normBase(settings.base);
    const res = await fetch(base + '/chat', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ model: settings.model, messages, stream:false, options:{ temperature, num_predict:max_tokens } }),
      signal: controller.signal
    });
    if(!res.ok) throw new Error(`ollama ${res.status}: ${await res.text()}`);
    const data = await res.json();
    return data?.message?.content ?? data?.content ?? '';
  } finally { clearTimeout(t); }
}

function chunkText(raw, target=1800){
  const s=String(raw||'').replace(/\s+/g,' ').trim();
  if(!s) return [];
  if(s.length<=target) return [s];
  const parts=[]; let cur='';
  for(const sent of s.split(/(?<=[.!?…])\s+/)){
    if((cur+sent).length>target){ if(cur) parts.push(cur.trim()); cur=sent+' '; }
    else cur+=sent+' ';
  }
  if(cur.trim()) parts.push(cur.trim());
  return parts;
}

let placeholderFlip = 0;
const placeholderSeq = ['все варианты верны', 'нет верного ответа'];
function sanitizeOption(s){
  s=String(s||'').trim();
  if(!s) return null;
  if(/^[-–—*]$/.test(s)) return null;
  if(/^\d+(\.\d+)?$/.test(s)) return null;
  if(/неверн/i.test(s)) return null;
  return s;
}
function normalizeQuestion(q){
  const question=String(q.q||q.question||'').trim();
  let correct = q.correct || (Array.isArray(q.options)? q.options[q.answer||0] : '');
  let ds = Array.isArray(q.distractors) ? q.distractors : (Array.isArray(q.options) ? q.options.filter((_,i)=>i!==(q.answer||0)) : []);
  ds = ds.map(sanitizeOption).filter(Boolean);
  if(!correct) correct='Правильный ответ недоступен';
  while(ds.length<3){ ds.push( placeholderSeq[(placeholderFlip++) % placeholderSeq.length] ); }
  ds = ds.slice(0,3);
  const opts=[correct, ...ds].map(String);
  return { q: question, options: opts, answer: 0 };
}

app.post('/auth/register', async (req,res)=>{
  try{
    const { email, password } = req.body||{};
    if(!email || !password || password.length<8) return res.status(400).json({ error:'invalid_fields' });
    const ex=one('SELECT user_id FROM users WHERE email=?',[email]);
    if(ex) return res.status(409).json({ error:'email_taken' });
    const { hash, salt } = await hashPassword(password);
    const user_id='u_'+rid(12);
    exec('INSERT INTO users(user_id,email,password_hash,password_salt,created_at) VALUES(?,?,?,?,?)',[user_id,email,hash,salt,Date.now()]);
    const tokenId='t_'+rid(12), exp=Date.now()+1000*60*60*24*7;
    const token=signToken([tokenId,user_id,exp].join('|'));
    exec('INSERT INTO sessions_auth(token,user_id,created_at,expires_at) VALUES(?,?,?,?)',[token,user_id,Date.now(),exp]);
    res.json({ ok:true, token, user:{ user_id, email } });
  }catch(e){ res.status(500).json({ error:'register_failed', message:e.message }); }
});
app.post('/auth/login', async (req,res)=>{
  try{
    const { email, password } = req.body||{};
    const u=one('SELECT * FROM users WHERE email=?',[email]);
    if(!u) return res.status(401).json({ error:'invalid_credentials' });
    const ok=await verifyPassword(password, u.password_hash, u.password_salt);
    if(!ok) return res.status(401).json({ error:'invalid_credentials' });
    const tokenId='t_'+rid(12), exp=Date.now()+1000*60*60*24*7;
    const token=signToken([tokenId,u.user_id,exp].join('|'));
    exec('INSERT INTO sessions_auth(token,user_id,created_at,expires_at) VALUES(?,?,?,?)',[token,u.user_id,Date.now(),exp]);
    res.json({ ok:true, token, user:{ user_id:u.user_id, email:u.email } });
  }catch(e){ res.status(500).json({ error:'login_failed', message:e.message }); }
});
app.post('/auth/logout', (req,res)=>{
  const a=req.headers.authorization||'';
  const t=a.startsWith('Bearer ')? a.slice(7): null;
  if(t) exec('DELETE FROM sessions_auth WHERE token=?',[t]);
  res.json({ ok:true });
});

app.get('/health', async (req,res)=>{
  try{
    const base=normBase(settings.base);
    const r=await fetch(base + '/tags');
    if(!r.ok) return res.status(500).json({ ok:false, reason:'server_error', status:r.status, base });
    const tags=await r.json();
    const models=Array.isArray(tags.models)? tags.models.map(m=>m.name): [];
    const found=models.includes(settings.model);
    res.json({ ok:found, ready:found, model:settings.model, models, base, reason:found?null:'model_not_found' });
  }catch(e){ res.status(500).json({ ok:false, reason:'fetch_failed', message:e.message }); }
});
app.post('/settings', authRequired, (req,res)=>{
  settings = { base: req.body.base||settings.base, model: req.body.model||settings.model };
  saveCfg(); res.json({ ok:true, settings });
});

app.post('/ingest', authRequired, (req,res)=>{
  const { text } = req.body||{}; if(!text || !String(text).trim()) return res.status(400).json({ error:'empty_text' });
  const MAX_LEN = 50000;
  if (String(text).length > MAX_LEN) return res.status(413).json({ error:'too_long', max: MAX_LEN, length: String(text).length });
  const content_id='c_'+rid(8);
  exec('INSERT INTO content(content_id,user_id,raw_text,created_at) VALUES(?,?,?,?)',[content_id, req.user.user_id, String(text), Date.now()]);
  res.json({ content_id });
});

app.post('/summarize', authRequired, async (req,res)=>{
  const started = Date.now();
  const HARD_TIMEOUT = 90000;
  try{
    const { content_id } = req.body||{};
    const C = one('SELECT raw_text FROM content WHERE content_id=? AND user_id=?',[content_id, req.user.user_id]);
    if(!C) return res.status(404).json({ error:'content_not_found' });
    const chunks = chunkText(C.raw_text, 1800);
    if(chunks.length===0) return res.status(400).json({ error:'empty_text' });

    async function summarizeChunk(text, idx){
      const sentences = text.split(/(?<=[.!?…])\s+/).map((t,i)=>`[${i+1}] ${t}`).join('\\n');
      const msgs = [
        { role:'system', content:'Ты работаешь ТОЛЬКО на русском и возвращаешь ТОЛЬКО валидный JSON.' },
        { role:'user', content:`Кратко законспектируй (2–4 пункта) и 1–2 термина с evidence (номера предложений).\\nФормат:\\n{"summary":[{"text":"...","evidence":[1]}], "glossary":[{"term":"...","definition":"...","evidence":[2]}]}\\nТекст:\\n${sentences}` }
      ];
      const out = await withRetry(
        () => ollamaChat(msgs, { max_tokens: 256, temperature:0.2 }, 90000),
        { tries:3, delays:[500,1500], label:`summ_chunk_${idx}` }
      );
      const obj = extractJsonBlock(out);
      if(!obj) throw new Error('bad_llm_json');
      return obj;
    }

    const partial = [];
    for(let i=0;i<chunks.length;i++){
      if(Date.now() - started > HARD_TIMEOUT) break;
      try{ partial.push(await summarizeChunk(chunks[i], i)); }catch{ /* skip */ }
    }
    if (partial.length===0) return res.status(504).json({ error:'summarize_timeout', message:'Не удалось получить ответ от модели в отведённое время' });

    const payload = {
      summary: partial.flatMap(p => Array.isArray(p.summary)? p.summary : []),
      glossary: partial.flatMap(p => Array.isArray(p.glossary)? p.glossary : [])
    };
    const mergeMsgs = [
      { role:'system', content:'Ты редактор конспектов. Верни ТОЛЬКО валидный JSON.' },
      { role:'user', content:`Объедини и отредактируй ниже, оставив 5–7 пунктов summary и 3–5 терминов. Убери повторы, сохрани evidence.\\nФормат:\\n{"summary":[{"text":"...","evidence":[1]}], "glossary":[{"term":"...","definition":"...","evidence":[2]}]}\\nИсходные пункты:\\n${JSON.stringify(payload)}` }
    ];
    let merged = null;
    try{
      const mergedOut = await withRetry(
        () => ollamaChat(mergeMsgs, { max_tokens: 384, temperature:0.2 }, 90000),
        { tries:2, delays:[800], label:'summ_merge' }
      );
      merged = extractJsonBlock(mergedOut);
    }catch{}
    const final = merged || payload;
    exec('INSERT OR REPLACE INTO summary(content_id,summary_json) VALUES(?,?)',[content_id, JSON.stringify(final)]);
    res.json({ summary: final, partialUsed: partial.length, chunks: chunks.length });
  }catch(e){
    res.status(500).json({ error:'summarize_failed', message: e.message||String(e) });
  }
});

app.post('/questions/base', authRequired, async (req,res)=>{
  try{
    const { content_id } = req.body||{};
    const S=one('SELECT summary_json FROM summary WHERE content_id=?',[content_id]);
    if(!S) return res.status(400).json({ error:'no_summary' });
    const summary=JSON.parse(S.summary_json);
    const msgs=[
      { role:'system', content:'Ты — генератор тестов на русском. Верни только валидный JSON.' },
      { role:'user', content:`Сгенерируй РОВНО 5 вопросов по summary. Для каждого: { "q":"...", "correct":"...", "distractors":["...","...","..."] }.\\nВерни:\\n{"questions":[ {...}, {...}, {...}, {...}, {...} ]}\\nsummary:\\n${JSON.stringify(summary)}` }
    ];
    const out = await ollamaChat(msgs, { temperature:0.25, max_tokens:1600 }, 45000);
    const obj = extractJsonBlock(out);
    if(!obj) return res.status(500).json({ error:'bad_llm_json', raw: out });
    let qs = Array.isArray(obj.questions)? obj.questions : (obj.questions||[]);
    qs = qs.slice(0,5).map(normalizeQuestion);
    res.json({ questions: qs });
  }catch(e){ res.status(500).json({ error:'qgen_failed', message:e.message }); }
});

app.post('/session', authRequired, (req,res)=>{
  const { content_id, questions } = req.body||{};
  if(!content_id || !Array.isArray(questions) || questions.length!==5) return res.status(400).json({ error:'bad_session_init' });
  const session_id='s_'+rid(10);
  exec('INSERT INTO quiz_session(session_id,user_id,content_id,created_at) VALUES(?,?,?,?)',[session_id, req.user.user_id, content_id, Date.now()]);
  res.json({ session_id, queue: questions.map((q,i)=>({ ...q, seed:'base_'+i })) });
});
app.post('/answer', authRequired, (req,res)=>{
  const { session_id, chosen_index, question } = req.body||{};
  const sess = one('SELECT * FROM quiz_session WHERE session_id=? AND user_id=?',[session_id, req.user.user_id]);
  if(!sess) return res.status(404).json({ error:'session_not_found' });
  const is_correct = Number(chosen_index)===0 ? 1 : 0;
  exec('INSERT INTO attempt(attempt_id,session_id,user_id,question_json,chosen_index,is_correct,created_at) VALUES(?,?,?,?,?,?,?)',
    ['a_'+rid(10), session_id, req.user.user_id, JSON.stringify(question||{}), Number(chosen_index), is_correct, Date.now()]);
  res.json({ is_correct: !!is_correct });
});
app.post('/finish', authRequired, (req,res)=>{
  const { session_id, content_id } = req.body||{};
  const rows = all('SELECT is_correct FROM attempt WHERE session_id=? AND user_id=?',[session_id, req.user.user_id]);
  const correct = rows.filter(r=>Number(r.is_correct)===1).length;
  const wrong = rows.length - correct;
  exec('INSERT INTO result(result_id,session_id,user_id,content_id,correct_count,wrong_count,created_at) VALUES(?,?,?,?,?,?,?)',
    ['r_'+rid(8), session_id, req.user.user_id, content_id, correct, wrong, Date.now()]);
  res.json({ ok:true, correct, wrong });
});
app.get('/content/:id/status', authRequired, (req,res)=>{
  const cid=req.params.id;
  const rs=all('SELECT correct_count,wrong_count FROM result WHERE content_id=? AND user_id=?',[cid, req.user.user_id]);
  const mastered = rs.length>0 && rs[rs.length-1].wrong_count===0;
  res.json({ mastered, attempts: rs.length, last: rs[rs.length-1]||null });
});

app.post('/remedial/preview', authRequired, (req,res)=>{
  const { session_id } = req.body||{};
  const atts = all('SELECT question_json,is_correct FROM attempt WHERE session_id=? AND user_id=?',[session_id, req.user.user_id]);
  const wrongQs = atts.filter(a=>Number(a.is_correct)===0).map(a=>JSON.parse(a.question_json||'{}'));
  const count = wrongQs.length * 3;
  res.json({ wrongSeeds: wrongQs.length, remedialQuestionsPlanned: count });
});
app.post('/remedial', authRequired, async (req,res)=>{
  try{
    const { session_id, content_id } = req.body||{};
    const sumRow = one('SELECT summary_json FROM summary WHERE content_id=?',[content_id]);
    const summary = sumRow ? JSON.parse(sumRow.summary_json) : {};
    const atts = all('SELECT question_json,is_correct FROM attempt WHERE session_id=? AND user_id=?',[session_id, req.user.user_id]);
    const wrongQs = atts.filter(a=>Number(a.is_correct)===0).map(a=>JSON.parse(a.question_json||'{}'));
    const blocks=[]; const queue=[];
    for(const w of wrongQs){
      const tMsgs=[
        { role:'system', content:'Ты — преподаватель. Объясняй кратко на русском. Верни только JSON.' },
        { role:'user', content:`Дай 2–4 предложения теории по теме ошибки.\\nВерни {"theory":"HTML-текст"}.\\nВопрос:\\n${JSON.stringify(w)}\\nsummary:\\n${JSON.stringify(summary)}` }
      ];
      const tOut = await ollamaChat(tMsgs, { max_tokens:600, temperature:0.15 }, 30000);
      const tObj = extractJsonBlock(tOut) || { theory:"" };

      const qMsgs=[
        { role:'system', content:'Ты — генератор тестов на русском. Верни только валидный JSON.' },
        { role:'user', content:`Сгенерируй РОВНО 3 вопроса по теме ошибки. Каждый: { "q":"...", "correct":"...", "distractors":["...","...","..."] }.\\nВерни {"questions":[...]}\\nВопрос:\\n${JSON.stringify(w)}\\nsummary:\\n${JSON.stringify(summary)}` }
      ];
      const qOut = await ollamaChat(qMsgs, { max_tokens:1600, temperature:0.3 }, 45000);
      const qObj = extractJsonBlock(qOut) || { questions:[] };
      const qs = (Array.isArray(qObj.questions)? qObj.questions : (qObj.questions||[])).slice(0,3).map(normalizeQuestion);
      blocks.push({ seed: w.q||w.question||'seed', theory: tObj.theory||"", questions: qs });
      queue.push(...qs.map((q,i)=>({ ...q, seed:(w.q||'seed')+'_r'+i })));
    }
    res.json({ blocks, queue });
  }catch(e){ res.status(500).json({ error:'remedial_failed', message:e.message }); }
});
app.post('/remedial/mega', authRequired, async (req,res)=>{
  try{
    const { content_id } = req.body||{};
    const sumRow=one('SELECT summary_json FROM summary WHERE content_id=?',[content_id]);
    const summary = sumRow ? JSON.parse(sumRow.summary_json) : {};
    const tMsgs=[
      { role:'system', content:'Ты — преподаватель. Верни только JSON.' },
      { role:'user', content:`Дай 5–8 предложений теории по ключевым темам summary.\\nВерни {"theory":"HTML-текст"}.\\nsummary:\\n${JSON.stringify(summary)}` }
    ];
    const tOut = await ollamaChat(tMsgs, { max_tokens:900, temperature:0.15 }, 35000);
    const tObj = extractJsonBlock(tOut) || { theory:"" };
    const qMsgs=[
      { role:'system', content:'Ты — генератор тестов на русском. Верни только валидный JSON.' },
      { role:'user', content:`Сгенерируй РОВНО 15 вопросов по ключевым темам summary. Каждый: { "q":"...", "correct":"...", "distractors":["...","...","..."] }.\\nВерни {"questions":[...]}\\nsummary:\\n${JSON.stringify(summary)}` }
    ];
    const qOut = await ollamaChat(qMsgs, { max_tokens:2800, temperature:0.35 }, 60000);
    const qObj = extractJsonBlock(qOut) || { questions:[] };
    const qs = (Array.isArray(qObj.questions)? qObj.questions : (qObj.questions||[])).slice(0,15).map(normalizeQuestion);
    res.json({ theory: tObj.theory||"", questions: qs.map((q,i)=>({ ...q, seed:'mega_'+i })) });
  }catch(e){ res.status(500).json({ error:'mega_failed', message:e.message }); }
});

app.get('/export/:session_id', authRequired, (req,res)=>{
  const sid=req.params.session_id;
  const sess=one('SELECT * FROM quiz_session WHERE session_id=? AND user_id=?',[sid, req.user.user_id]);
  if(!sess) return res.status(404).json({ error:'not_found' });
  const cont=one('SELECT * FROM content WHERE content_id=?',[sess.content_id]);
  const sum=one('SELECT summary_json FROM summary WHERE content_id=?',[sess.content_id]);
  const atts=all('SELECT * FROM attempt WHERE session_id=?',[sid]);
  res.json({ content: cont, summary: sum?JSON.parse(sum.summary_json):null, session: sess, attempts: atts });
});
app.post('/import', authRequired, (req,res)=>{
  const data=req.body||{}; if(!data.content || !data.summary) return res.status(400).json({ error:'bad_payload' });
  const content_id='c_'+rid(8);
  exec('INSERT INTO content(content_id,user_id,raw_text,created_at) VALUES(?,?,?,?)',[content_id, req.user.user_id, data.content.raw_text||'', Date.now()]);
  exec('INSERT OR REPLACE INTO summary(content_id,summary_json) VALUES(?,?)',[content_id, JSON.stringify(data.summary)]);
  res.json({ content_id });
});

initDB().then(()=> app.listen(PORT, ()=>console.log('API on', PORT)));
