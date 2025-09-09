// app.js  — BlueMagic Instagram Username Manager (full version)
// Adds "Scrape & Format IG" (UI + progress + CSV) for all logged-in users.

// ===== Imports =====
const express = require('express');
const mongoose = require('mongoose');
const multer = require('multer');
const session = require('express-session');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcrypt');
const path = require('path');
const fetch = require('node-fetch');
const { Parser } = require('json2csv');
const crypto = require('crypto');
const fs = require('fs');

require('dotenv').config();

console.log('cwd:', process.cwd());
console.log('env file seen:', fs.existsSync('.env'));
console.log('SESSION_SECRET length:', (process.env.SESSION_SECRET || '').trim().length);

const {
  MONGO_URL,
  PORT = 3000,
  SESSION_SECRET,
  USER_PASSWORD,
  ADMIN_PASSWORD,
  NODE_ENV = 'development',
} = process.env;

const RAPIDAPI_KEY = process.env.RAPIDAPI_KEY;
const RAPIDAPI_HOST = process.env.RAPIDAPI_HOST || 'instagram-looter2.p.rapidapi.com';
const SCRAPE_CONCURRENCY = parseInt(process.env.SCRAPE_CONCURRENCY || '4', 10);
const SCRAPE_DELAY_MS = parseInt(process.env.SCRAPE_DELAY_MS || '180', 10);

const IS_PROD = NODE_ENV === 'production';

// ===== CONSTANTS =====
const CLEAR_CONFIRM_TEXT = 'I confirm to clear Database';
const PRESENCE_TTL_MS = 60 * 1000; // presence shown if pinged in last 60s

// ===== App init =====
const app = express();

app.use(helmet({ contentSecurityPolicy: false }));
app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 800 }));
app.use(express.urlencoded({ extended: true, limit: '5mb' }));
app.use(express.json({ limit: '5mb' }));
app.set('trust proxy', 1);

app.use(
  session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: 'lax',
      secure: IS_PROD,
      maxAge: 1000 * 60 * 60 * 12, // 12h
    },
  })
);

// Static for branding
app.use('/static', express.static(path.join(__dirname, 'static')));

// Scrape jobs (in-memory per-process)
const scrapeJobs = new Map(); // jobId -> { total, done, start, rows, status, error, delay, conc }

// Multer for .txt uploads
const upload = multer({ storage: multer.memoryStorage() });

// ===== Mongo =====
mongoose
  .connect(MONGO_URL, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('Connected to MongoDB'))
  .catch((err) => { console.error('MongoDB connection error:', err); process.exit(1); });

// ===== Schemas =====
const usernameSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true, lowercase: true, trim: true },
  date_added: { type: Date, default: Date.now },
  used_by: { type: [String], default: [] },
  last_used_at: { type: Date, default: null },
  last_used_by: { type: String, default: null },
});

const logSchema = new mongoose.Schema({
  ts: { type: Date, default: Date.now },
  actor_type: { type: String, enum: ['user', 'admin', 'va'], default: 'user' },
  actor_name: { type: String, default: null },
  action: { type: String, required: true },
  details: { type: Object, default: {} },
});

const modelSchema = new mongoose.Schema({
  name: { type: String, unique: true, required: true, trim: true },
  created_at: { type: Date, default: Date.now },
});

const vaSchema = new mongoose.Schema({
  name: { type: String, unique: true, required: true, trim: true },
  password_hash: { type: String, required: true },
  // role: 'admin' | 'management' | 'va'
  role: { type: String, enum: ['admin', 'management', 'va'], default: 'va' },
  created_at: { type: Date, default: Date.now },
});


// track take activity for revert + KPI
const activitySchema = new mongoose.Schema({
  ts: { type: Date, default: Date.now },
  model: { type: String, required: true },
  va: { type: String, default: null },
  accounts: { type: Number, required: true }, // A
  per_line: { type: Number, required: true }, // B
  total_usernames: { type: Number, required: true }, // A*B actually assigned
  username_ids: { type: [mongoose.Schema.Types.ObjectId], default: [] },
  undone: { type: Boolean, default: false },
});

const Username = mongoose.model('Username', usernameSchema);
const Log = mongoose.model('Log', logSchema);
const Model = mongoose.model('Model', modelSchema);
const VAUser = mongoose.model('VAUser', vaSchema);
const Activity = mongoose.model('Activity', activitySchema);

// ===== X (Twitter) Schemas =====
const usernameXSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true, lowercase: true, trim: true },
  date_added: { type: Date, default: Date.now },
  used_by: { type: [String], default: [] },
  last_used_at: { type: Date, default: null },
  last_used_by: { type: String, default: null },
});

const modelXSchema = new mongoose.Schema({
  name: { type: String, unique: true, required: true, trim: true },
  created_at: { type: Date, default: Date.now },
});

const activityXSchema = new mongoose.Schema({
  ts: { type: Date, default: Date.now },
  model: { type: String, required: true },
  va: { type: String, default: null },
  accounts: { type: Number, required: true }, // A
  per_line: { type: Number, required: true }, // B
  total_usernames: { type: Number, required: true }, // A*B actually assigned
  username_ids: { type: [mongoose.Schema.Types.ObjectId], default: [] },
  undone: { type: Boolean, default: false },
});

const UsernameX = mongoose.model('UsernameX', usernameXSchema);
const ModelX = mongoose.model('ModelX', modelXSchema);
const ActivityX = mongoose.model('ActivityX', activityXSchema);

// ===== Presence (in-memory) =====
const presence = new Map(); // sessionId -> { name, when }

// ===== View helpers =====
function isAdmin(req)       { return req.session?.role === 'admin'; }
function isManagement(req)  { return req.session?.role === 'management'; }
function isVA(req)          { return req.session?.role === 'va'; }

// VA-only can access just this set:
const VA_ALLOWED_PATHS = new Set([
  '/mass-follow-formatter', '/presence/ping', '/presence/list', '/logout', '/health', '/static'
]);


function pageHead(title) {
  return `
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>${title} • BlueMagic</title>
    <link rel="icon" type="image/png" href="/static/favicon.png" />
    <style>
      :root { color-scheme: dark; }
      body { font-family: Inter, system-ui, -apple-system, Segoe UI, Arial, sans-serif; background:#0e1320; color:#e8ebf5; margin:0; }
      .container { max-width: 1080px; margin:0 auto; padding:24px; }
      header { display:flex; align-items:center; gap:12px; margin-bottom:16px; }
      header img.logo { width:32px; height:32px; border-radius:6px; }
      .brand { font-size:12px; opacity:.8; margin-top:2px; }
      h1 { margin:6px 0 16px; font-size:22px; }
      h2 { margin: 18px 0 12px; font-size:18px; }
      nav { display:flex; gap:10px; flex-wrap:wrap; margin-bottom:16px; }
      nav a { color:#9ec1ff; text-decoration:none; background:#131a33; padding:8px 10px; border:1px solid #223064; border-radius:8px; }
      form { display:grid; gap:10px; margin-bottom:20px; }
      label { font-size:13px; opacity:.9; }
      input, select, button, textarea {
        padding:10px; border-radius:8px; border:1px solid #2a3766; background:#111834; color:#e8ebf5;
      }
      textarea { min-height: 240px; white-space: pre; }
      button { background:linear-gradient(180deg,#6a0dad,#52118e); border:none; cursor:pointer; font-weight:600; }
      button:hover { filter:brightness(1.06); }
      .row { display:grid; grid-template-columns:1fr 1fr; gap:10px; }
      .grid-3 { display:grid; grid-template-columns:repeat(3,1fr); gap:12px; }
      .notice { padding:12px; background:#0f172f; border:1px solid #223064; border-radius:8px; }
      .card { padding:16px; background:#0e152b; border:1px solid #223064; border-radius:12px; }
      table { width:100%; border-collapse:collapse; }
      th, td { border-bottom:1px solid #223064; padding:8px; text-align:left; font-size:13px; }
      .danger { background:linear-gradient(180deg,#d64b4b,#a52929); }
      .muted { opacity:.8; font-size:12px; }
      .kpi-pill { display:inline-block; padding:4px 8px; border:1px solid #223064; border-radius:999px; margin-right:6px; margin-bottom:6px; }
      .actions { display:flex; gap:8px; flex-wrap:wrap; }
      .presence { position:fixed; right:12px; bottom:12px; padding:10px; background:#0f172f; border:1px solid #223064; border-radius:10px; font-size:12px; min-width:160px;}
      .presence h4 { margin:0 0 6px; font-size:12px; opacity:.8; }
    </style>
  `;
}
function renderPage(title, content, req) {
  const role = req.session?.role || null;

  let nav = '';
  if (req.session?.loggedIn) {
    if (isVA(req)) {
      nav = `<nav>
        <a href="/mass-follow-formatter">Mass follow formatter</a>
        <a href="/logout">Logout</a>
      </nav>`;
    } else if (isManagement(req)) {
      nav = `<nav>
        <a href="/add">Import</a>
        <a href="/format">Format & Take</a>
        <a href="/scrape">Scrape & Format IG</a>
        <a href="/revert">Revert</a>
        <a href="/kpi">KPI</a>
        <a href="/mass-follow-formatter">Mass follow formatter</a>
        <a href="/x" style="background: linear-gradient(180deg,#1da1f2,#0d8bd9);">X</a>
        <a href="/logout">Logout</a>
      </nav>`;
    } else if (isAdmin(req)) {
      nav = `<nav>
        <a href="/add">Import</a>
        <a href="/format">Format & Take</a>
        <a href="/scrape">Scrape & Format IG</a>
        <a href="/revert">Revert</a>
        <a href="/kpi">KPI</a>
        <a href="/admin">Admin</a>
        <a href="/mass-follow-formatter">Mass follow formatter</a>
        <a href="/x" style="background: linear-gradient(180deg,#1da1f2,#0d8bd9);">X</a>
        <a href="/logout">Logout</a>
      </nav>`;
    }
  }

  return `<!DOCTYPE html>
  <html lang="en">
  <head>
    ${pageHead(title)}
    <style>
      .presence .p { margin:2px 0; }
      .presence .r-admin { color:#ff6868; font-weight:800; }
      .presence .r-mgmt { color:#85ff8f; font-weight:700; }
      .presence .r-va { color:#e8ebf5; opacity:.85; }
    </style>
  </head>
  <body>
    <div class="container">
      <header>
        <img src="/static/logo.png" class="logo" alt="BlueMagic"/>
        <div><div class="brand">BlueMagic</div><h1>${title}</h1></div>
      </header>
      ${nav}
      ${content}
    </div>

    <div class="presence" id="presenceBox" style="display:none">
      <h4>Online now</h4>
      <div id="presenceList">—</div>
    </div>

    <script>
      // presence
      fetch('/presence/ping',{method:'POST', headers:{'Content-Type':'application/json'}}).catch(()=>{});
      setInterval(()=>{ fetch('/presence/ping',{method:'POST', headers:{'Content-Type':'application/json'}}).catch(()=>{}); }, 20000);

      function renderPerson(p){
        const cls = p.role==='admin' ? 'r-admin' : (p.role==='management' ? 'r-mgmt' : 'r-va');
        return '<div class="p '+cls+'">• '+p.name+'</div>';
      }
      function refreshPresence(){
        fetch('/presence/list').then(r=>r.json()).then(d=>{
          const box=document.getElementById('presenceBox');
          const list=document.getElementById('presenceList');
          list.innerHTML = (d.people||[]).map(renderPerson).join('') || '—';
          box.style.display='block';
        }).catch(()=>{});
      }
      refreshPresence(); setInterval(refreshPresence,15000);

      // clipboard helper
      function copyFrom(id){
        const el = document.getElementById(id);
        if(!el) return;
        el.select(); document.execCommand('copy');
        if (navigator.clipboard) { navigator.clipboard.writeText(el.value).catch(()=>{}); }
        alert('Copied to clipboard');
      }
      window.copyFrom = copyFrom;
    </script>
  </body></html>`;
}


async function logEvent({ action, details = {}, req, actor_type = 'user' }) {
  try {
    const actor_name = req?.session?.vaName || null;
    await Log.create({ action, details, actor_type, actor_name });
  } catch (e) { console.error('Log error:', e); }
}

// ---- IG Scraper helpers ----
if (!RAPIDAPI_KEY) console.warn('WARNING: RAPIDAPI_KEY missing – /scrape will fail until set.');

const sleep = (ms) => new Promise(r => setTimeout(r, ms));

function pickProfile(payload) {
  if (payload && typeof payload === 'object') {
    if (payload.data && typeof payload.data === 'object') return payload.data;
    if (payload.profile && typeof payload.profile === 'object') return payload.profile;
  }
  return payload;
}

async function fetchProfile(username) {
  const url = `https://${RAPIDAPI_HOST}/profile?username=${encodeURIComponent(username)}`;
  const res = await fetch(url, {
    headers: {
      'x-rapidapi-host': RAPIDAPI_HOST,
      'x-rapidapi-key': RAPIDAPI_KEY
    }
  });
  const text = await res.text();
  let json;
  try { json = JSON.parse(text); } catch (e) {
    throw new Error(`Non-JSON: ${text.slice(0,120)}`);
  }
  const p = pickProfile(json);
  if (!p || typeof p !== 'object') throw new Error('No profile object');
  return p;
}

// Map API → Airtable-style CSV (Username first)
function mapToCsvRow(p, inputUsername) {
  const media_count =
    p.media_count ??
    p.edge_owner_to_timeline_media?.count ??
    p.timeline_media_count ?? null;

  const followers =
    p.followers_count ??
    p.follower_count ??
    p.edge_followed_by?.count ?? null;

  const following =
    p.following_count ??
    p.edge_follow?.count ?? null;

  const bioLinksArr = Array.isArray(p.bio_links) ? p.bio_links : [];
  const linkInBio = bioLinksArr.length > 0;
  const isPrivate = !!(p.is_private);

  return {
    'Username': inputUsername,
    'Name': p.full_name || p.fullName || p.name || '',
    'Media Count': media_count == null ? null : Number(media_count),
    'Followers Ordered': followers == null ? null : Number(followers),
    'Followers': followers == null ? null : Number(followers),
    'Following': following == null ? null : Number(following),
    'Link in bio?': linkInBio ? 'TRUE' : 'FALSE',
    'Private?': isPrivate ? 'TRUE' : 'FALSE'
  };
}

// ===== Auth middleware =====
function requireUser(req, res, next) {
  const publicPaths = ['/login', '/admin/login', '/health', '/static', '/presence/ping', '/presence/list', '/inventory'];
  if (publicPaths.some((p) => req.path.startsWith(p))) return next();
  if (req.session?.loggedIn) return next();
  return res.redirect('/login');
}
function requireAdmin(req, res, next) {
  return isAdmin(req) ? next() : res.redirect('/admin/login');
}
app.use(requireUser);

// VA: restrict pages
app.use((req, res, next) => {
  if (!isVA(req)) return next();
  // allow only VA-allowed paths or exact matches
  const p = req.path;
  if (VA_ALLOWED_PATHS.has(p) || [...VA_ALLOWED_PATHS].some(base => p.startsWith(base))) return next();
  return res.redirect('/mass-follow-formatter');
});


// ===== Health =====
app.get('/health', (_req, res) => res.send('ok'));

// ===== Login (single field supports Admin/VA/User) =====
app.get('/login', (req, res) => {
  const html = renderPage(
    'Login',
    `
    <div class="card">
      <form action="/login" method="post">
        <label>Enter password (Admin, VA, or Access)</label>
        <input type="password" name="password" placeholder="Password" required />
        <button type="submit">Login</button>
        <p class="muted">One login per session. Admin password works here directly.</p>
      </form>
    </div>`,
    req
  );
  res.send(html);
});

app.post('/login', async (req, res) => {
  const pwd = (req.body.password || '').trim();

  // Admin password
  if (pwd === ADMIN_PASSWORD) {
    req.session.loggedIn = true;
    req.session.role = 'admin';
    req.session.vaName = 'Admin';
    await logEvent({ action: 'admin_login_via_main', req, actor_type: 'admin' });
    return res.redirect('/admin');
  }

  // Management (site-wide access) password
  if (pwd === USER_PASSWORD) {
    req.session.loggedIn = true;
    req.session.role = 'management';
    req.session.vaName = 'Management';
    await logEvent({ action: 'management_login', req, actor_type: 'user' });
    return res.redirect('/add');
  }

  // VA login (bcrypt) — role from DB
  const vaUsers = await VAUser.find({}).lean();
  for (const v of vaUsers) {
    if (await bcrypt.compare(pwd, v.password_hash)) {
      req.session.loggedIn = true;
      req.session.role = v.role || 'va';
      req.session.vaName = v.name;
      await logEvent({ action: 'va_login', req, actor_type: v.role === 'admin' ? 'admin' : (v.role === 'management' ? 'user' : 'va'), details: { va: v.name, role: v.role } });
      return res.redirect(isVA({ session: { role: v.role } }) ? '/mass-follow-formatter' : (v.role === 'admin' ? '/admin' : '/add'));
    }
  }

  const html = renderPage('Login', `<div class="notice">Wrong password.</div><p><a href="/login">Try again</a></p>`, req);
  res.status(401).send(html);
});

app.get('/logout', async (req, res) => {
  await logEvent({
    action: 'logout',
    req,
    actor_type: req.session?.isAdmin ? 'admin' : (req.session?.vaName ? 'va' : 'user'),
  });
  req.session.destroy(() => res.redirect('/login'));
});

// ===== Presence =====
app.post('/presence/ping', (req, res) => {
  const name = req.session?.vaName || (isAdmin(req) ? 'Admin' : isManagement(req) ? 'Management' : 'VA');
  const role = req.session?.role || (req.session?.isAdmin ? 'admin' : 'management');
  if (req.sessionID) presence.set(req.sessionID, { name, role, when: Date.now() });
  res.json({ ok: true });
});

app.get('/presence/list', (_req, res) => {
  const now = Date.now();
  const list = [];
  for (const [sid, info] of presence.entries()) {
    if (now - info.when <= PRESENCE_TTL_MS) list.push({ name: info.name, role: info.role || 'va' });
    else presence.delete(sid);
  }
  // de-dup by name+role
  const uniq = [];
  const seen = new Set();
  for (const p of list) {
    const k = p.name + '|' + p.role;
    if (!seen.has(k)) { uniq.push(p); seen.add(k); }
  }
  res.json({ people: uniq });
});


// ===== Home redirect =====
app.get('/', (_req, res) => res.redirect('/add'));

// ===== Models CRUD (Admin) =====
app.get('/admin/models', requireAdmin, async (req, res) => {
  const models = await Model.find({}).sort({ name: 1 }).lean();
  const rows = models.map(m => `<tr>
      <td>${m.name}</td>
      <td class="actions">
        <form action="/admin/models/delete" method="post" style="display:inline">
          <input type="hidden" name="name" value="${m.name}"/>
          <button class="danger">Delete</button>
        </form>
      </td>
    </tr>`).join('');
  const html = renderPage(
    'Models',
    `
    <div class="card">
      <form action="/admin/models/add" method="post" class="actions">
        <input type="text" name="name" placeholder="New model name" required />
        <button type="submit">Add model</button>
        <a href="/admin">Back to Admin</a>
      </form>
    </div>
    <div class="card">
      <table><thead><tr><th>Model</th><th>Actions</th></tr></thead><tbody>${rows || '<tr><td colspan="2">No models yet.</td></tr>'}</tbody></table>
    </div>`,
    req
  );
  res.send(html);
});
app.post('/admin/models/add', requireAdmin, async (req, res) => {
  const name = (req.body.name || '').trim();
  if (name) {
    await Model.updateOne({ name }, { $setOnInsert: { name } }, { upsert: true });
    await logEvent({ action: 'admin_model_add', req, actor_type: 'admin', details: { name } });
  }
  res.redirect('/admin/models');
});
app.post('/admin/models/delete', requireAdmin, async (req, res) => {
  const name = (req.body.name || '').trim();
  if (name) {
    await Model.deleteOne({ name });
    await logEvent({ action: 'admin_model_delete', req, actor_type: 'admin', details: { name } });
  }
  res.redirect('/admin/models');
});

// ===== VA Users CRUD (Admin) with Admin checkbox =====
app.get('/admin/users', requireAdmin, async (req, res) => {
  const users = await VAUser.find({}).sort({ name: 1 }).lean();
  const rows = users.map(u => `
    <tr>
      <td>${u.name}</td>
      <td>${u.role}</td>
      <td class="actions">
        <form action="/admin/users/delete" method="post" style="display:inline">
          <input type="hidden" name="name" value="${u.name}"/>
          <button class="danger">Delete</button>
        </form>
      </td>
    </tr>`).join('');

  const html = renderPage(
    'Employees',
    `
    <div class="card">
      <form action="/admin/users/add" method="post" class="row">
        <div><input type="text" name="name" placeholder="Employee name" required /></div>
        <div><input type="password" name="password" placeholder="New/Update password" required /></div>
        <div>
          <label>Role</label>
          <select name="role" required>
            <option value="va">va (aging)</option>
            <option value="management">management</option>
            <option value="admin">admin</option>
          </select>
        </div>
        <div style="display:flex;align-items:end;"><button type="submit">Add / Update</button></div>
      </form>
      <p class="muted">Passwords are hashed with bcrypt. Role controls access:
      <b>admin</b> (red, full), <b>management</b> (green, no admin panel), <b>va</b> (black, Mass follow formatter only).</p>
      <p><a href="/admin">Back to Admin</a></p>
    </div>
    <div class="card">
      <table><thead><tr><th>Name</th><th>Role</th><th>Actions</th></tr></thead><tbody>${rows || '<tr><td colspan="3">No employees yet.</td></tr>'}</tbody></table>
    </div>`,
    req
  );
  res.send(html);
});

app.post('/admin/users/add', requireAdmin, async (req, res) => {
  const name = (req.body.name || '').trim();
  const pwd  = (req.body.password || '').trim();
  const role = (req.body.role || 'va').trim();
  if (!name || !pwd) return res.redirect('/admin/users');
  const hash = await bcrypt.hash(pwd, 10);
  await VAUser.updateOne(
    { name },
    { $set: { password_hash: hash, role } },
    { upsert: true }
  );
  await logEvent({ action: 'admin_employee_add_or_update', req, actor_type: 'admin', details: { name, role } });
  res.redirect('/admin/users');
});


// ===== Import usernames =====
app.get('/add', (req, res) => {
  const html = renderPage(
    'Import Usernames',
    `
    <div class="card">
      <form action="/add" method="post" enctype="multipart/form-data">
        <label>Upload a .txt file with one Instagram username per line:</label>
        <input type="file" name="file" accept=".txt" required />
        <button type="submit">Import Usernames</button>
      </form>
      <div class="actions">
        <a href="/format">Format & Take</a>
        <a href="/scrape">Scrape & Format IG</a>
        <a href="/revert">Revert</a>
        <a href="/kpi">KPI</a>
        <a href="/admin">Admin panel</a>
      </div>
      <div class="muted">Duplicates ignored automatically.</div>
    </div>`,
    req
  );
  res.send(html);
});

app.post('/add', upload.single('file'), async (req, res) => {
  if (!req.file) return res.status(400).send('No file uploaded');

  const content = req.file.buffer.toString('utf-8');
  const lines = content.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);

  const ops = lines.map((raw) => {
    const username = raw.toLowerCase().replace(/^@/, '');
    return {
      updateOne: {
        filter: { username },
        update: { $setOnInsert: { username, date_added: new Date(), used_by: [] } },
        upsert: true,
      },
    };
  });

  let inserted = 0;
  try {
    const result = await Username.bulkWrite(ops, { ordered: false });
    inserted = result.upsertedCount || 0;
  } catch (_) {}
  const duplicates = lines.length - inserted;

  await logEvent({
    action: 'import_usernames',
    details: { processed: lines.length, inserted, duplicates },
    req,
    actor_type: req.session?.vaName ? 'va' : 'user',
  });

  const html = renderPage(
    'Import Usernames Result',
    `
    <div class="notice">
      <p>Processed ${lines.length} usernames.</p>
      <p>Inserted ${inserted} new entries.</p>
      <p>Detected ${duplicates} duplicates.</p>
    </div>
    <p><a href="/add">Back to Import</a></p>
    <p><a href="/format">Go to Format & Take Usernames</a></p>`,
    req
  );
  res.send(html);
});

// ===== Inventory counters API (for model select live update) =====
app.get('/inventory/:model', async (req, res) => {
  const model = (req.params.model || '').trim();
  const total = await Username.countDocuments({});
  const unusedForModel = model ? await Username.countDocuments({ used_by: { $ne: model } }) : total;
  res.json({ total, unusedForModel });
});

// ===== X Inventory counters API (for model select live update) =====
app.get('/x/inventory/:model', async (req, res) => {
  const model = (req.params.model || '').trim();
  const total = await UsernameX.countDocuments({});
  const unusedForModel = model ? await UsernameX.countDocuments({ used_by: { $ne: model } }) : total;
  res.json({ total, unusedForModel });
});
// ===== Mass follow order formatter (VA-only page, but visible to others too) =====
const MASS_PREFIX = process.env.MASS_PREFIX || '5566'; // constant at line start

app.get('/mass-follow-formatter', (req, res) => {
  const html = renderPage(
    'Mass follow order formatter',
    `
    <div class="card">
      <form id="mfForm">
        <label>Paste Instagram links (one per line)</label>
        <textarea id="mfInput" placeholder="instagram.com/lilpuffbynat&#10;instagram.com/cutecoastnat&#10;instagram.com/icingonbynat"></textarea>

        <div class="row">
          <div><label>Min followers</label><input id="minF" type="number" value="175" min="1"/></div>
          <div><label>Max followers</label><input id="maxF" type="number" value="215" min="1"/></div>
        </div>

        <button type="submit">Format</button>
      </form>
    </div>

    <div class="card">
      <label>Result</label>
      <textarea id="mfOut" readonly placeholder="Result will appear here..."></textarea>
      <div class="actions"><button type="button" onclick="copyFrom('mfOut')">Copy to clipboard</button></div>
      <div class="muted">Lines will be formatted as: <code>${MASS_PREFIX} | instagram.com/handle | N</code>, where N is a random integer in your range.</div>
    </div>

    <script>
      function randInt(min, max){ min=Math.floor(min); max=Math.floor(max); return Math.floor(Math.random()*(max-min+1))+min; }
      function cleanLine(s){
        s = (s||'').trim();
        if(!s) return '';
        // allow with/without protocol and @
        s = s.replace(/^https?:\\/\\//i,'').replace(/^www\\./i,'').replace(/^@/,'');
        if(!s.toLowerCase().startsWith('instagram.com/')) s = 'instagram.com/'+s;
        return s;
      }
      document.getElementById('mfForm').addEventListener('submit', (e)=>{
        e.preventDefault();
        const raw = document.getElementById('mfInput').value || '';
        const min = parseInt(document.getElementById('minF').value||'175',10);
        const max = parseInt(document.getElementById('maxF').value||'215',10);
        const lines = raw.split(/\\r?\\n/).map(cleanLine).filter(Boolean);
        const out = lines.map(link => '${MASS_PREFIX} | '+link+' | '+randInt(min,max)).join('\\n');
        document.getElementById('mfOut').value = out;
      });
    </script>
    `,
    req
  );
  res.send(html);
});


// ===== Format & Take =====
async function fetchInventoryCounts(model) {
  const total = await Username.countDocuments({});
  const unusedForModel = await Username.countDocuments({ used_by: { $ne: model } });
  return { total, unusedForModel };
}
async function takeUsernames(model, takeCount) {
  const docs = await Username.find({ used_by: { $ne: model } })
    .sort({ date_added: -1 })
    .limit(takeCount)
    .lean();
  const ids = docs.map(d => d._id);
  if (ids.length) {
    await Username.updateMany(
      { _id: { $in: ids } },
      { $addToSet: { used_by: model }, $set: { last_used_at: new Date(), last_used_by: model } }
    );
  }
  return { usernames: docs.map(d => d.username), ids };
}

// X Format & Take helpers
async function fetchXInventoryCounts(model) {
  const total = await UsernameX.countDocuments({});
  const unusedForModel = await UsernameX.countDocuments({ used_by: { $ne: model } });
  return { total, unusedForModel };
}

async function takeXUsernames(model, takeCount) {
  const docs = await UsernameX.find({ used_by: { $ne: model } })
    .sort({ date_added: -1 })
    .limit(takeCount)
    .lean();
  const ids = docs.map(d => d._id);
  if (ids.length) {
    await UsernameX.updateMany(
      { _id: { $in: ids } },
      { $addToSet: { used_by: model }, $set: { last_used_at: new Date(), last_used_by: model } }
    );
  }
  return { usernames: docs.map(d => d.username), ids };
}

app.get('/format', async (req, res) => {
  const models = await Model.find({}).sort({ name: 1 }).lean();
  const options = models.length
    ? models.map(m => `<option value="${m.name}">${m.name}</option>`).join('')
    : `<option value="Natalie">Natalie</option>`;

  const html = renderPage(
    'Format & Take Usernames',
    `
    <div class="card">
      <form action="/format" method="post" id="formatForm">
        <div class="row">
          <div>
            <label>Select model:</label>
            <select name="model" id="modelSelect" required>${options}</select>
            <div class="muted" id="invInfo" style="margin-top:6px;">Total: — | Unused: —</div>
          </div>
          <div>
            <label>Number of accounts performing the follow task (A)</label>
            <input type="number" name="count" min="1" value="10" required />
          </div>
        </div>
        <div class="row">
          <div>
            <label>Number of usernames per line</label>
            <input type="number" name="perLine" min="1" value="10" required />
          </div>
          <div>
            <label>Total = A × B</label>
            <input type="text" id="calcBox" value="Calculated after submit" disabled />
          </div>
        </div>
        <button type="submit">Format and Preview</button>
      </form>
      <div class="muted">Select model to see inventory counters instantly.</div>
    </div>
    <script>
      const sel = document.getElementById('modelSelect');
      const info = document.getElementById('invInfo');
      const form = document.getElementById('formatForm');
      const a = form.querySelector('input[name="count"]');
      const b = form.querySelector('input[name="perLine"]');
      const calc = document.getElementById('calcBox');
      function updateCalc(){ const A=parseInt(a.value||'0',10), B=parseInt(b.value||'0',10); if(A>0&&B>0) calc.value = (A*B)+' usernames'; }
      a.addEventListener('input', updateCalc); b.addEventListener('input', updateCalc);
      async function updateInv(){
        const m = sel.value;
        if(!m) return;
        const r = await fetch('/inventory/'+encodeURIComponent(m));
        const d = await r.json();
        info.textContent = 'Total: '+d.total+' | Unused: '+d.unusedForModel;
      }
      sel.addEventListener('change', updateInv);
      updateInv();
    </script>`,
    req
  );
  res.send(html);
});

app.post('/format', async (req, res) => {
  const count = parseInt(req.body.count, 10);
  const perLine = parseInt(req.body.perLine, 10);
  const model = (req.body.model || 'Natalie').trim();
  if (!count || !perLine || count < 1 || perLine < 1) return res.status(400).send('Invalid form values');

  const totalToFetch = count * perLine;
  const { usernames, ids } = await takeUsernames(model, totalToFetch);

  // group into B per line
  const lines = [];
  for (let i = 0; i < usernames.length; i += perLine) {
    lines.push(usernames.slice(i, i + perLine).join(','));
  }
  const formatted = lines.join('\n');

  // activity
  const act = await Activity.create({
    model,
    va: req.session?.vaName || null,
    accounts: count,
    per_line: perLine,
    total_usernames: usernames.length,
    username_ids: ids,
  });

  await logEvent({
    action: 'format_take',
    details: { model, requested_accounts: count, per_line: perLine, total_requested: totalToFetch, total_returned: usernames.length, activity_id: String(act._id) },
    req,
    actor_type: req.session?.vaName ? 'va' : 'user',
  });

  const inv = await fetchInventoryCounts(model);

  const html = renderPage(
    'Formatted Usernames',
    `
    <div class="notice">
      <p>Model: <b>${model}</b></p>
      <p>A=${count} • B=${perLine} ⇒ Requested: ${totalToFetch}, Returned: ${usernames.length}</p>
      <div class="kpi-pill">Total in DB: ${inv.total}</div>
      <div class="kpi-pill">Unused for ${model}: ${inv.unusedForModel}</div>
    </div>

    <label>Preview:</label>
    <textarea id="formattedBox" readonly>${formatted}</textarea>
    <div class="actions">
      <button type="button" onclick="copyFrom('formattedBox')">Copy to clipboard</button>
      <form action="/download" method="post">
        <input type="hidden" name="data" value="${encodeURIComponent(formatted)}" />
        <input type="hidden" name="filename" value="usernames_${model}.txt" />
        <button type="submit">Download .txt</button>
      </form>
    </div>

    <div class="muted" style="margin-top:10px;">Activity saved. You can revert it from the <a href="/revert">Revert</a> page.</div>

    <p style="margin-top:14px;"><a href="/format">Back to Format & Take</a></p>`,
    req
  );
  res.send(html);
});

// Download file
app.post('/download', (req, res) => {
  const data = decodeURIComponent(req.body.data || '');
  const filename = req.body.filename || 'usernames.txt';
  res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
  res.setHeader('Content-Type', 'text/plain');
  res.send(data);
});

// ===== Scrape & Format IG (new) =====
app.get('/scrape', (req, res) => {
  const html = renderPage(
    'Scrape & Format IG',
    `
    <div class="card">
      <form id="scrapeForm" enctype="multipart/form-data">
        <label>Upload a .txt with one Instagram username per line</label>
        <input type="file" name="file" accept=".txt" required />
        <div class="row">
          <div><label>Delay per request (ms)</label><input type="number" name="delay" min="0" value="${SCRAPE_DELAY_MS}"/></div>
          <div><label>Concurrency</label><input type="number" name="conc" min="1" max="5" value="${SCRAPE_CONCURRENCY}"/></div>
        </div>
        <button type="submit">Start Scrape</button>
      </form>
    </div>

    <div class="card">
      <label>Progress</label>
      <div id="bar" style="height:16px;background:#0f172f;border:1px solid #223064;border-radius:8px;overflow:hidden;">
        <div id="fill" style="height:100%;width:0%;background:linear-gradient(90deg,#6a0dad,#52118e);"></div>
      </div>
      <div class="muted" id="meta" style="margin-top:8px;">0%</div>
      <div id="doneBox" style="display:none;margin-top:10px;">
        <a id="dl" href="#" class="muted">Download CSV</a>
      </div>
    </div>

    <script>
      const form = document.getElementById('scrapeForm');
      const fill = document.getElementById('fill');
      const meta = document.getElementById('meta');
      const doneBox = document.getElementById('doneBox');
      const dl = document.getElementById('dl');

      form.addEventListener('submit', async (e)=>{
        e.preventDefault();
        doneBox.style.display = 'none';
        fill.style.width = '0%';
        meta.textContent = '0%';

        const fd = new FormData(form);
        const r = await fetch('/scrape/start', { method:'POST', body: fd });
        const j = await r.json();
        if(!j.ok){ alert('Error: '+(j.error||'unknown')); return; }

        const job = j.jobId;

        const timer = setInterval(async ()=>{
          const s = await fetch('/scrape/status?job='+encodeURIComponent(job)).then(r=>r.json()).catch(()=>null);
          if(!s) return;
          const pct = s.total ? Math.round((s.done/s.total)*100) : 0;
          fill.style.width = pct+'%';
          const eta = s.eta_s != null ? s.eta_s : 0;
          meta.textContent = pct+'%  '+s.done+'/'+s.total+'  ETA '+(eta>60?Math.round(eta/60)+'m':Math.round(eta)+'s');

          if(s.status==='done'){
            clearInterval(timer);
            fill.style.width = '100%';
            meta.textContent = '100%  '+s.done+'/'+s.total+'  Completed';
            dl.href = '/scrape/download?job='+encodeURIComponent(job);
            doneBox.style.display = 'block';
          }
          if(s.status==='error'){
            clearInterval(timer);
            alert('Scrape failed: '+s.error);
          }
        }, 600);
      });
    </script>
    `,
    req
  );
  res.send(html);
});

app.post('/scrape/start', upload.single('file'), async (req, res) => {
  try {
    if (!req.file) return res.json({ ok:false, error:'No file uploaded' });
    const delay = Math.max(0, parseInt(req.body.delay || SCRAPE_DELAY_MS, 10));
    const conc = Math.max(1, Math.min(parseInt(req.body.conc || SCRAPE_CONCURRENCY, 10), 5));

    const content = req.file.buffer.toString('utf8');
    const usernames = content.split(/\r?\n/).map(s=>s.trim()).filter(Boolean);
    if (!usernames.length) return res.json({ ok:false, error:'Empty file' });

    const jobId = crypto.randomBytes(8).toString('hex');
    const job = { total: usernames.length, done: 0, start: Date.now(), rows: [], status: 'running', error: null, delay, conc };
    scrapeJobs.set(jobId, job);

    // background worker
    (async () => {
      const queue = usernames.slice();
      const workers = new Array(job.conc).fill(0).map(async () => {
        while (queue.length) {
          const u = queue.shift();
          try {
            const p = await fetchProfile(u);
            const row = mapToCsvRow(p, u);
            job.rows.push(row);
          } catch (e) {
            job.rows.push({
              'Username': u, 'Name':'', 'Media Count':null, 'Followers Ordered':null, 'Followers':null, 'Following':null, 'Link in bio?':'FALSE', 'Private?':'FALSE', _error: e.message
            });
          } finally {
            job.done++;
            if (job.delay) await sleep(job.delay);
          }
        }
      });

      try {
        await Promise.all(workers);
        job.status = 'done';
      } catch (e) {
        job.status = 'error';
        job.error = e.message;
      }
    })();

    res.json({ ok:true, jobId });
  } catch (e) {
    res.json({ ok:false, error:e.message });
  }
});

app.get('/scrape/status', (req, res) => {
  const id = (req.query.job || '').trim();
  const job = scrapeJobs.get(id);
  if (!job) return res.json({ ok:false, error:'job not found' });
  const elapsed = (Date.now() - job.start) / 1000;
  const rate = job.done > 0 ? job.done / elapsed : 0;
  const remaining = Math.max(0, job.total - job.done);
  const eta_s = rate > 0 ? remaining / rate : null;
  res.json({ ok:true, status: job.status, done: job.done, total: job.total, eta_s, error: job.error || null });
});

app.get('/scrape/download', (req, res) => {
  const id = (req.query.job || '').trim();
  const job = scrapeJobs.get(id);
  if (!job || job.status !== 'done') return res.status(404).send('Job not ready');

  const fields = ['Username','Name','Media Count','Followers Ordered','Followers','Following','Link in bio?','Private?'];
  const example = job.rows.find(r => Object.keys(r).some(k => k.startsWith('_'))) || {};
  const extra = Object.keys(example).filter(k => !fields.includes(k));
  const parser = new Parser({ fields: fields.concat(extra) });

  const csv = parser.parse(job.rows);
  res.setHeader('Content-Disposition', `attachment; filename="profiles_${Date.now()}.csv"`);
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.send(csv);
});

// ===== Revert last actions (per VA shows their own 10) =====
app.get('/revert', async (req, res) => {
  const who = req.session?.vaName;
  const query = who ? { va: who, undone: false } : { undone: false };
  const acts = await Activity.find(query).sort({ ts: -1 }).limit(10).lean();
  const rows = acts.map(a => `
    <tr>
      <td>${new Date(a.ts).toLocaleString()}</td>
      <td>${a.va || '—'}</td>
      <td>${a.model}</td>
      <td>A=${a.accounts}, B=${a.per_line}, Total=${a.total_usernames}</td>
      <td>
        <form action="/revert" method="post" onsubmit="return confirm('Revert this activity?');">
          <input type="hidden" name="id" value="${a._id}" />
          <button class="danger">Revert</button>
        </form>
      </td>
    </tr>`).join('');
  const html = renderPage(
    'Revert Last Actions',
    `
    <div class="card">
      <div class="muted">Showing ${acts.length} recent activities ${who ? `(for VA: ${who})` : '(all users)'}</div>
      <table>
        <thead><tr><th>Date</th><th>VA</th><th>Model</th><th>Counts</th><th>Action</th></tr></thead>
        <tbody>${rows || '<tr><td colspan="5">No recent activities.</td></tr>'}</tbody>
      </table>
    </div>`,
    req
  );
  res.send(html);
});

app.post('/revert', async (req, res) => {
  const id = (req.body.id || '').trim();
  const act = await Activity.findById(id);
  if (!act || act.undone) return res.redirect('/revert');

  await Username.updateMany({ _id: { $in: act.username_ids } }, { $pull: { used_by: act.model } });
  act.undone = true; await act.save();

  await logEvent({ action: 'revert_activity', details: { activity_id: id, model: act.model, total_usernames: act.total_usernames }, req, actor_type: req.session?.vaName ? 'va' : 'user' });

  res.redirect('/revert');
});

// ===== KPI Builder =====
app.get('/kpi', async (req, res) => {
  const models = await Model.find({}).sort({ name: 1 }).lean();
  const options = models.length
    ? `<option value="">All models</option>` + models.map(m => `<option>${m.name}</option>`).join('')
    : `<option value="">All models</option><option>Natalie</option>`;

  const html = renderPage(
    'KPI Builder',
    `
    <div class="card">
      <form action="/kpi" method="post" class="row">
        <div><label>From</label><input type="date" name="from" required/></div>
        <div><label>To</label><input type="date" name="to" required/></div>
        <div><label>Model</label><select name="model">${options}</select></div>
        <div style="display:flex; align-items:end;"><button type="submit">Load</button></div>
      </form>
      <div class="muted">Pick a range, optionally filter by model, then select activities to add to totals.</div>
    </div>`,
    req
  );
  res.send(html);
});

app.post('/kpi', async (req, res) => {
  const { from, to, model = '' } = req.body;
  const q = { ts: { $gte: new Date(from), $lte: new Date(to + 'T23:59:59.999Z') }, undone: false };
  if (model) q.model = model;
  const acts = await Activity.find(q).sort({ ts: -1 }).lean();

  const rows = acts.map(a => `
    <tr>
      <td><input type="checkbox" name="pick" value="${a._id}" data-a="${a.accounts}" data-b="${a.per_line}" data-total="${a.total_usernames}"/></td>
      <td>${new Date(a.ts).toLocaleString()}</td>
      <td>${a.va || '—'}</td>
      <td>${a.model}</td>
      <td>A=${a.accounts}</td>
      <td>B=${a.per_line}</td>
      <td>Total=${a.total_usernames}</td>
    </tr>`).join('');

  const html = renderPage(
    'KPI Builder',
    `
    <div class="card">
      <div class="actions" style="margin-bottom:8px;">
        <button type="button" onclick="selectAll(true)">Select all</button>
        <button type="button" onclick="selectAll(false)">Clear</button>
      </div>
      <table>
        <thead><tr><th></th><th>Date</th><th>VA</th><th>Model</th><th>A</th><th>B</th><th>Total</th></tr></thead>
        <tbody>${rows || '<tr><td colspan="7">No activities in range.</td></tr>'}</tbody>
      </table>
      <div class="notice" style="margin-top:10px;">
        <div id="kpiOut">A=0; Total=0</div> <!-- B removed from summary -->
      </div>
      <script>
        function recalc(){
          let A=0, T=0;
          document.querySelectorAll('input[name=pick]:checked').forEach(cb=>{
            A += parseInt(cb.dataset.a,10);
            T += parseInt(cb.dataset.total,10);
          });
          document.getElementById('kpiOut').innerText = 'A='+A+'; Total='+T;
        }
        function selectAll(v){
          document.querySelectorAll('input[name=pick]').forEach(cb => { cb.checked=v; });
          recalc();
        }
        document.querySelectorAll('input[name=pick]').forEach(cb=>cb.addEventListener('change', recalc));
      </script>
    </div>
    <p><a href="/kpi">Back</a></p>`,
    req
  );
  res.send(html);
});

// ===== Admin panel =====
app.get('/admin', requireAdmin, async (req, res) => {
  const total = await Username.countDocuments({});
  const models = await Model.find({}).sort({ name: 1 }).lean();

  // per-model counts
  let modelRows = '';
  for (const m of models) {
    const used = await Username.countDocuments({ used_by: m.name });
    const unused = await Username.countDocuments({ used_by: { $ne: m.name } });
    modelRows += `<tr><td>${m.name}</td><td>${used}</td><td>${unused}</td></tr>`;
  }

  const html = renderPage(
    'Admin Panel',
    `
    <div class="card">
      <h2>Metrics</h2>
      <div class="kpi-pill">Total usernames: ${total}</div>
      <table style="margin-top:10px;"><thead><tr><th>Model</th><th>Used</th><th>Unused</th></tr></thead><tbody>${modelRows || '<tr><td colspan="3">No models yet.</td></tr>'}</tbody></table>
    </div>

    <div class="grid-3">
      <div class="card">
        <h2>Export CSV</h2>
        <p class="muted">Filter and export database slices to CSV.</p>
        <a href="/admin/export">Open Export</a>
      </div>

      <div class="card">
        <h2>Manage Models</h2>
        <p class="muted">Add or delete models.</p>
        <a href="/admin/models">Open Models</a>
      </div>

      <div class="card">
        <h2>Manage VA Users</h2>
        <p class="muted">Create VA accounts and toggle Admin role.</p>
        <a href="/admin/users">Open Users</a>
      </div>
    </div>

    <div class="card">
      <h2>Logs</h2>
      <div class="actions">
        <a href="/admin/logs">View latest logs</a>
      </div>
    </div>

    <div class="card">
      <h2>Sync used usernames (by model)</h2>
      <form action="/admin/upload-used" method="post" enctype="multipart/form-data" class="row">
        <div>
          <label>Model</label>
          <select name="model" required>
            ${models.length ? models.map(m => `<option value="${m.name}">${m.name}</option>`).join('') : '<option value="Natalie">Natalie</option>'}
          </select>
        </div>
        <div>
          <label>File (.txt)</label>
          <input type="file" name="file" accept=".txt" required />
        </div>
        <div style="display:flex; align-items:end;"><button type="submit">Sync</button></div>
      </form>
    </div>

    <div class="card">
      <h2>Danger zone</h2>
      <form action="/admin/clear" method="post">
        <label class="muted">Type exactly: <b>${CLEAR_CONFIRM_TEXT}</b></label>
        <input type="text" name="confirm" placeholder="${CLEAR_CONFIRM_TEXT}" required />
        <button type="submit" class="danger">Clear Database</button>
      </form>
      <p class="muted">Deletes <b>all</b> usernames. Logs remain.</p>
    </div>`,
    req
  );
  res.send(html);
});

// Admin logs
app.get('/admin/logs', requireAdmin, async (req, res) => {
  const logs = await Log.find({}).sort({ ts: -1 }).limit(300).lean();
  const rows = logs
    .map(l => `<tr>
      <td>${new Date(l.ts).toLocaleString()}</td>
      <td>${l.actor_type}${l.actor_name ? ' ('+l.actor_name+')' : ''}</td>
      <td>${l.action}</td>
      <td><code>${JSON.stringify(l.details || {})}</code></td>
    </tr>`).join('');
  const html = renderPage(
    'Recent Logs',
    `
    <div class="notice">Last ${logs.length} events.</div>
    <table>
      <thead><tr><th>Date</th><th>Actor</th><th>Action</th><th>Details</th></tr></thead>
      <tbody>${rows || '<tr><td colspan="4">No logs yet.</td></tr>'}</tbody>
    </table>
    <p><a href="/admin">Back to Admin</a></p>`,
    req
  );
  res.send(html);
});

// Admin CSV export UI + POST
app.get('/admin/export', requireAdmin, (_req, res) => {
  res.send(renderPage(
    'Export CSV',
    `
    <div class="card">
      <form action="/admin/export" method="post" class="row">
        <div><label>Filter by model (optional):</label><input type="text" name="model" placeholder="e.g. Natalie" /></div>
        <div><label>Used status:</label>
          <select name="status">
            <option value="any">Any</option>
            <option value="unused">Unused by model</option>
            <option value="used_by_model">Used by model</option>
            <option value="used_by_any">Used by any model</option>
          </select>
        </div>
        <div><label>From date (optional):</label><input type="date" name="from" /></div>
        <div><label>To date (optional):</label><input type="date" name="to" /></div>
        <div><label>Limit:</label><input type="number" name="limit" min="1" value="1000" /></div>
        <div style="display:flex; align-items:end;"><button type="submit">Export CSV</button></div>
      </form>
      <p class="muted">CSV: username, date_added, used_by, last_used_at, last_used_by</p>
    </div>
    <p><a href="/admin">Back</a></p>`,
    _req
  ));
});
app.post('/admin/export', requireAdmin, async (req, res) => {
  const { model = '', status = 'any', from = '', to = '', limit = '1000' } = req.body;
  const q = {};
  if (from || to) q.date_added = {};
  if (from) q.date_added.$gte = new Date(from);
  if (to) q.date_added.$lte = new Date(to + 'T23:59:59.999Z');

  if (status === 'unused' && model) q.used_by = { $ne: model };
  if (status === 'used_by_model' && model) q.used_by = model;
  if (status === 'used_by_any') q.used_by = { $exists: true, $ne: [] };

  const lim = Math.max(1, Math.min(parseInt(limit, 10) || 1000, 100000));
  const docs = await Username.find(q).sort({ date_added: -1 }).limit(lim).lean();

  await logEvent({ action: 'admin_export_csv', req, actor_type: 'admin', details: { count: docs.length, query: q } });

  let csv = 'username,date_added,used_by,last_used_at,last_used_by\n';
  for (const d of docs) {
    const used = (d.used_by || []).join('|');
    csv += `${d.username},${new Date(d.date_added).toISOString()},${used},${d.last_used_at ? new Date(d.last_used_at).toISOString() : ''},${d.last_used_by || ''}\n`;
  }
  res.setHeader('Content-Disposition', `attachment; filename="export_${Date.now()}.csv"`);
  res.setHeader('Content-Type', 'text/csv');
  res.send(csv);
});

// Sync Used (Admin) with model SELECT
app.post('/admin/upload-used', requireAdmin, upload.single('file'), async (req, res) => {
  if (!req.file) return res.status(400).send('No file uploaded');
  const model = (req.body.model || 'Natalie').trim();
  const content = req.file.buffer.toString('utf-8');
  const lines = content.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);

  let updated = 0, inserted = 0;
  for (const raw of lines) {
    const username = raw.toLowerCase().replace(/^@/, '');
    try {
      const existing = await Username.findOne({ username });
      if (existing) {
        await Username.updateOne({ _id: existing._id }, { $addToSet: { used_by: model }, $set: { last_used_at: new Date(), last_used_by: model } });
        updated++;
      } else {
        await Username.create({ username, used_by: [model], last_used_at: new Date(), last_used_by: model });
        inserted++;
      }
    } catch (e) { console.error(e); }
  }
  await logEvent({ action: 'admin_sync_used', req, actor_type: 'admin', details: { model, processed: lines.length, updated, inserted } });

  res.send(renderPage(
    'Sync Used Usernames Result',
    `
    <div class="notice">
      <p>Model: ${model}</p>
      <p>Processed ${lines.length} usernames.</p>
      <p>Updated ${updated} existing entries.</p>
      <p>Inserted ${inserted} new entries.</p>
    </div>
    <p><a href="/admin">Back to Admin</a></p>`,
    req
  ));
});

// Clear DB
app.post('/admin/clear', requireAdmin, async (req, res) => {
  const confirm = (req.body.confirm || '').trim();
  if (confirm !== CLEAR_CONFIRM_TEXT) {
    return res.status(400).send(renderPage('Clear Database',
      `<div class="notice">Confirmation text mismatch. Type exactly: <b>${CLEAR_CONFIRM_TEXT}</b></div><p><a href="/admin">Back to Admin</a></p>`, req));
  }
  const del = await Username.deleteMany({});
  await logEvent({ action: 'admin_clear_db', req, actor_type: 'admin', details: { deleted: del.deletedCount } });
  res.send(renderPage('Database Cleared', `<div class="notice">Deleted ${del.deletedCount} usernames.</div><p><a href="/admin">Back to Admin</a></p>`, req));
});

// ===== X (Twitter) Panel Routes =====
app.get('/x', (req, res) => {
  const html = renderPage(
    'X (Twitter) Panel',
    `
    <div class="card">
      <h2>X (Twitter) Management</h2>
      <p class="muted">Manage X usernames and activities. Same functionality as Instagram but for X platform.</p>
      <div class="actions">
        <a href="/x/add">Import X Usernames</a>
        <a href="/x/format">Format & Take X</a>
        <a href="/x/revert">Revert X</a>
        <a href="/x/kpi">X KPI</a>
        <a href="/x/admin">X Admin Panel</a>
      </div>
    </div>
    `,
    req
  );
  res.send(html);
});

// X Import usernames
app.get('/x/add', (req, res) => {
  const html = renderPage(
    'Import X Usernames',
    `
    <div class="card">
      <form action="/x/add" method="post" enctype="multipart/form-data">
        <label>Upload a .txt file with one X username per line:</label>
        <input type="file" name="file" accept=".txt" required />
        <button type="submit">Import X Usernames</button>
      </form>
      <div class="actions">
        <a href="/x/format">Format & Take X</a>
        <a href="/x/revert">Revert X</a>
        <a href="/x/kpi">X KPI</a>
        <a href="/x/admin">X Admin Panel</a>
      </div>
      <div class="muted">Duplicates ignored automatically.</div>
    </div>`,
    req
  );
  res.send(html);
});

app.post('/x/add', upload.single('file'), async (req, res) => {
  if (!req.file) return res.status(400).send('No file uploaded');

  const content = req.file.buffer.toString('utf-8');
  const lines = content.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);

  const ops = lines.map((raw) => {
    const username = raw.toLowerCase().replace(/^@/, '');
    return {
      updateOne: {
        filter: { username },
        update: { $setOnInsert: { username, date_added: new Date(), used_by: [] } },
        upsert: true,
      },
    };
  });

  let inserted = 0;
  try {
    const result = await UsernameX.bulkWrite(ops, { ordered: false });
    inserted = result.upsertedCount || 0;
  } catch (_) {}
  const duplicates = lines.length - inserted;

  await logEvent({
    action: 'import_x_usernames',
    details: { processed: lines.length, inserted, duplicates },
    req,
    actor_type: req.session?.vaName ? 'va' : 'user',
  });

  const html = renderPage(
    'Import X Usernames Result',
    `
    <div class="notice">
      <p>Processed ${lines.length} X usernames.</p>
      <p>Inserted ${inserted} new entries.</p>
      <p>Detected ${duplicates} duplicates.</p>
    </div>
    <p><a href="/x/add">Back to Import X</a></p>
    <p><a href="/x/format">Go to Format & Take X Usernames</a></p>`,
    req
  );
  res.send(html);
});

// X Format & Take
app.get('/x/format', async (req, res) => {
  const models = await ModelX.find({}).sort({ name: 1 }).lean();
  const options = models.length
    ? models.map(m => `<option value="${m.name}">${m.name}</option>`).join('')
    : `<option value="Natalie">Natalie</option>`;

  const html = renderPage(
    'Format & Take X Usernames',
    `
    <div class="card">
      <form action="/x/format" method="post" id="xFormatForm">
        <div class="row">
          <div>
            <label>Select model:</label>
            <select name="model" id="xModelSelect" required>${options}</select>
            <div class="muted" id="xInvInfo" style="margin-top:6px;">Total: — | Unused: —</div>
          </div>
          <div>
            <label>Number of X accounts you want</label>
            <input type="number" name="count" min="1" value="10" required />
          </div>
        </div>
        <button type="submit">Get X Usernames</button>
      </form>
      <div class="muted">Select model to see inventory counters instantly.</div>
    </div>
    <script>
      const sel = document.getElementById('xModelSelect');
      const info = document.getElementById('xInvInfo');
      async function updateInv(){
        const m = sel.value;
        if(!m) return;
        const r = await fetch('/x/inventory/'+encodeURIComponent(m));
        const d = await r.json();
        info.textContent = 'Total: '+d.total+' | Unused: '+d.unusedForModel;
      }
      sel.addEventListener('change', updateInv);
      updateInv();
    </script>`,
    req
  );
  res.send(html);
});

app.post('/x/format', async (req, res) => {
  const count = parseInt(req.body.count, 10);
  const model = (req.body.model || 'Natalie').trim();
  if (!count || count < 1) return res.status(400).send('Invalid form values');

  const { usernames, ids } = await takeXUsernames(model, count);

  // Format as one username per line
  const formatted = usernames.join('\n');

  // activity
  const act = await ActivityX.create({
    model,
    va: req.session?.vaName || null,
    accounts: count,
    per_line: 1, // Always 1 per line for X
    total_usernames: usernames.length,
    username_ids: ids,
  });

  await logEvent({
    action: 'format_take_x',
    details: { model, requested_accounts: count, total_returned: usernames.length, activity_id: String(act._id) },
    req,
    actor_type: req.session?.vaName ? 'va' : 'user',
  });

  const inv = await fetchXInventoryCounts(model);

  const html = renderPage(
    'X Usernames Assigned',
    `
    <div class="notice">
      <p>Model: <b>${model}</b></p>
      <p>Requested: ${count}, Returned: ${usernames.length}</p>
      <div class="kpi-pill">Total in X DB: ${inv.total}</div>
      <div class="kpi-pill">Unused for ${model}: ${inv.unusedForModel}</div>
    </div>

    <label>X Usernames (one per line):</label>
    <textarea id="xFormattedBox" readonly>${formatted}</textarea>
    <div class="actions">
      <button type="button" onclick="copyFrom('xFormattedBox')">Copy to clipboard</button>
      <form action="/download" method="post">
        <input type="hidden" name="data" value="${encodeURIComponent(formatted)}" />
        <input type="hidden" name="filename" value="x_usernames_${model}.txt" />
        <button type="submit">Download .txt</button>
      </form>
    </div>

    <div class="muted" style="margin-top:10px;">Activity saved. You can revert it from the <a href="/x/revert">Revert</a> page.</div>

    <p style="margin-top:14px;"><a href="/x/format">Back to Format & Take X</a></p>`,
    req
  );
  res.send(html);
});

// X KPI Builder
app.get('/x/kpi', async (req, res) => {
  const models = await ModelX.find({}).sort({ name: 1 }).lean();
  const options = models.length
    ? `<option value="">All models</option>` + models.map(m => `<option>${m.name}</option>`).join('')
    : `<option value="">All models</option><option>Natalie</option>`;

  const html = renderPage(
    'X KPI Builder',
    `
    <div class="card">
      <h2>X KPI Builder</h2>
      <form action="/x/kpi" method="post" class="row">
        <div><label>From</label><input type="date" name="from" required/></div>
        <div><label>To</label><input type="date" name="to" required/></div>
        <div><label>Model</label><select name="model">${options}</select></div>
        <div style="display:flex; align-items:end;"><button type="submit">Load X Activities</button></div>
      </form>
      <div class="muted">Pick a range, optionally filter by model, then select activities to add to totals.</div>
    </div>`,
    req
  );
  res.send(html);
});

app.post('/x/kpi', async (req, res) => {
  const { from, to, model = '' } = req.body;
  const q = { ts: { $gte: new Date(from), $lte: new Date(to + 'T23:59:59.999Z') }, undone: false };
  if (model) q.model = model;
  const acts = await ActivityX.find(q).sort({ ts: -1 }).lean();

  const rows = acts.map(a => `
    <tr>
      <td><input type="checkbox" name="pick" value="${a._id}" data-a="${a.accounts}" data-total="${a.total_usernames}"/></td>
      <td>${new Date(a.ts).toLocaleString()}</td>
      <td>${a.va || '—'}</td>
      <td>${a.model}</td>
      <td>Accounts=${a.accounts}</td>
      <td>Total=${a.total_usernames}</td>
    </tr>`).join('');

  const html = renderPage(
    'X KPI Builder',
    `
    <div class="card">
      <div class="actions" style="margin-bottom:8px;">
        <button type="button" onclick="selectAll(true)">Select all</button>
        <button type="button" onclick="selectAll(false)">Clear</button>
      </div>
      <table>
        <thead><tr><th></th><th>Date</th><th>VA</th><th>Model</th><th>Accounts</th><th>Total Usernames</th></tr></thead>
        <tbody>${rows || '<tr><td colspan="6">No X activities in range.</td></tr>'}</tbody>
      </table>
      <div class="notice" style="margin-top:10px;">
        <div id="xKpiOut">Accounts=0; Total Usernames=0</div>
      </div>
      <script>
        function recalc(){
          let A=0, T=0;
          document.querySelectorAll('input[name=pick]:checked').forEach(cb=>{
            A += parseInt(cb.dataset.a,10);
            T += parseInt(cb.dataset.total,10);
          });
          document.getElementById('xKpiOut').innerText = 'Accounts='+A+'; Total Usernames='+T;
        }
        function selectAll(v){
          document.querySelectorAll('input[name=pick]').forEach(cb => { cb.checked=v; });
          recalc();
        }
        document.querySelectorAll('input[name=pick]').forEach(cb=>cb.addEventListener('change', recalc));
      </script>
    </div>
    <p><a href="/x/kpi">Back to X KPI</a></p>`,
    req
  );
  res.send(html);
});

// X Revert last actions (per VA shows their own 10)
app.get('/x/revert', async (req, res) => {
  const who = req.session?.vaName;
  const query = who ? { va: who, undone: false } : { undone: false };
  const acts = await ActivityX.find(query).sort({ ts: -1 }).limit(10).lean();
  const rows = acts.map(a => `
    <tr>
      <td>${new Date(a.ts).toLocaleString()}</td>
      <td>${a.va || '—'}</td>
      <td>${a.model}</td>
      <td>Accounts=${a.accounts}, Total=${a.total_usernames}</td>
      <td>
        <form action="/x/revert" method="post" onsubmit="return confirm('Revert this X activity?');">
          <input type="hidden" name="id" value="${a._id}" />
          <button class="danger">Revert</button>
        </form>
      </td>
    </tr>`).join('');
  const html = renderPage(
    'Revert Last X Actions',
    `
    <div class="card">
      <div class="muted">Showing ${acts.length} recent X activities ${who ? `(for VA: ${who})` : '(all users)'}</div>
      <table>
        <thead><tr><th>Date</th><th>VA</th><th>Model</th><th>Counts</th><th>Action</th></tr></thead>
        <tbody>${rows || '<tr><td colspan="5">No recent X activities.</td></tr>'}</tbody>
      </table>
    </div>`,
    req
  );
  res.send(html);
});

app.post('/x/revert', async (req, res) => {
  const id = (req.body.id || '').trim();
  const act = await ActivityX.findById(id);
  if (!act || act.undone) return res.redirect('/x/revert');

  await UsernameX.updateMany({ _id: { $in: act.username_ids } }, { $pull: { used_by: act.model } });
  act.undone = true; await act.save();

  await logEvent({ action: 'revert_x_activity', details: { activity_id: id, model: act.model, total_usernames: act.total_usernames }, req, actor_type: req.session?.vaName ? 'va' : 'user' });

  res.redirect('/x/revert');
});

// X Admin Panel
app.get('/x/admin', requireAdmin, async (req, res) => {
  const total = await UsernameX.countDocuments({});
  const models = await ModelX.find({}).sort({ name: 1 }).lean();

  // per-model counts
  let modelRows = '';
  for (const m of models) {
    const used = await UsernameX.countDocuments({ used_by: m.name });
    const unused = await UsernameX.countDocuments({ used_by: { $ne: m.name } });
    modelRows += `<tr><td>${m.name}</td><td>${used}</td><td>${unused}</td></tr>`;
  }

  const html = renderPage(
    'X Admin Panel',
    `
    <div class="card">
      <h2>X Metrics</h2>
      <div class="kpi-pill">Total X usernames: ${total}</div>
      <table style="margin-top:10px;"><thead><tr><th>Model</th><th>Used</th><th>Unused</th></tr></thead><tbody>${modelRows || '<tr><td colspan="3">No models yet.</td></tr>'}</tbody></table>
    </div>

    <div class="grid-3">
      <div class="card">
        <h2>Export CSV</h2>
        <p class="muted">Filter and export X database slices to CSV.</p>
        <a href="/x/admin/export">Open Export</a>
      </div>

      <div class="card">
        <h2>Manage Models</h2>
        <p class="muted">Add or delete X models.</p>
        <a href="/x/admin/models">Open Models</a>
      </div>

      <div class="card">
        <h2>Manage VA Users</h2>
        <p class="muted">Create VA accounts and toggle Admin role.</p>
        <a href="/admin/users">Open Users</a>
      </div>
    </div>

    <div class="card">
      <h2>Logs</h2>
      <div class="actions">
        <a href="/admin/logs">View latest logs</a>
      </div>
    </div>

    <div class="card">
      <h2>Sync used X usernames (by model)</h2>
      <form action="/x/admin/upload-used" method="post" enctype="multipart/form-data" class="row">
        <div>
          <label>Model</label>
          <select name="model" required>
            ${models.length ? models.map(m => `<option value="${m.name}">${m.name}</option>`).join('') : '<option value="Natalie">Natalie</option>'}
          </select>
        </div>
        <div>
          <label>File (.txt)</label>
          <input type="file" name="file" accept=".txt" required />
        </div>
        <div style="display:flex; align-items:end;"><button type="submit">Sync</button></div>
      </form>
    </div>

    <div class="card">
      <h2>Danger zone</h2>
      <form action="/x/admin/clear" method="post">
        <label class="muted">Type exactly: <b>${CLEAR_CONFIRM_TEXT}</b></label>
        <input type="text" name="confirm" placeholder="${CLEAR_CONFIRM_TEXT}" required />
        <button type="submit" class="danger">Clear X Database</button>
      </form>
      <p class="muted">Deletes <b>all</b> X usernames. Logs remain.</p>
    </div>`,
    req
  );
  res.send(html);
});

// X Models CRUD (Admin)
app.get('/x/admin/models', requireAdmin, async (req, res) => {
  const models = await ModelX.find({}).sort({ name: 1 }).lean();
  const rows = models.map(m => `<tr>
      <td>${m.name}</td>
      <td class="actions">
        <form action="/x/admin/models/delete" method="post" style="display:inline">
          <input type="hidden" name="name" value="${m.name}"/>
          <button class="danger">Delete</button>
        </form>
      </td>
    </tr>`).join('');
  const html = renderPage(
    'X Models',
    `
    <div class="card">
      <form action="/x/admin/models/add" method="post" class="actions">
        <input type="text" name="name" placeholder="New X model name" required />
        <button type="submit">Add X model</button>
        <a href="/x/admin">Back to X Admin</a>
      </form>
    </div>
    <div class="card">
      <table><thead><tr><th>X Model</th><th>Actions</th></tr></thead><tbody>${rows || '<tr><td colspan="2">No X models yet.</td></tr>'}</tbody></table>
    </div>`,
    req
  );
  res.send(html);
});

app.post('/x/admin/models/add', requireAdmin, async (req, res) => {
  const name = (req.body.name || '').trim();
  if (name) {
    await ModelX.updateOne({ name }, { $setOnInsert: { name } }, { upsert: true });
    await logEvent({ action: 'admin_x_model_add', req, actor_type: 'admin', details: { name } });
  }
  res.redirect('/x/admin/models');
});

app.post('/x/admin/models/delete', requireAdmin, async (req, res) => {
  const name = (req.body.name || '').trim();
  if (name) {
    await ModelX.deleteOne({ name });
    await logEvent({ action: 'admin_x_model_delete', req, actor_type: 'admin', details: { name } });
  }
  res.redirect('/x/admin/models');
});

// X CSV export UI + POST
app.get('/x/admin/export', requireAdmin, (_req, res) => {
  res.send(renderPage(
    'Export X CSV',
    `
    <div class="card">
      <form action="/x/admin/export" method="post" class="row">
        <div><label>Filter by model (optional):</label><input type="text" name="model" placeholder="e.g. Natalie" /></div>
        <div><label>Used status:</label>
          <select name="status">
            <option value="any">Any</option>
            <option value="unused">Unused by model</option>
            <option value="used_by_model">Used by model</option>
            <option value="used_by_any">Used by any model</option>
          </select>
        </div>
        <div><label>From date (optional):</label><input type="date" name="from" /></div>
        <div><label>To date (optional):</label><input type="date" name="to" /></div>
        <div><label>Limit:</label><input type="number" name="limit" min="1" value="1000" /></div>
        <div style="display:flex; align-items:end;"><button type="submit">Export X CSV</button></div>
      </form>
      <p class="muted">CSV: username, date_added, used_by, last_used_at, last_used_by</p>
    </div>
    <p><a href="/x/admin">Back to X Admin</a></p>`,
    _req
  ));
});

app.post('/x/admin/export', requireAdmin, async (req, res) => {
  const { model = '', status = 'any', from = '', to = '', limit = '1000' } = req.body;
  const q = {};
  if (from || to) q.date_added = {};
  if (from) q.date_added.$gte = new Date(from);
  if (to) q.date_added.$lte = new Date(to + 'T23:59:59.999Z');

  if (status === 'unused' && model) q.used_by = { $ne: model };
  if (status === 'used_by_model' && model) q.used_by = model;
  if (status === 'used_by_any') q.used_by = { $exists: true, $ne: [] };

  const lim = Math.max(1, Math.min(parseInt(limit, 10) || 1000, 100000));
  const docs = await UsernameX.find(q).sort({ date_added: -1 }).limit(lim).lean();

  await logEvent({ action: 'admin_export_x_csv', req, actor_type: 'admin', details: { count: docs.length, query: q } });

  let csv = 'username,date_added,used_by,last_used_at,last_used_by\n';
  for (const d of docs) {
    const used = (d.used_by || []).join('|');
    csv += `${d.username},${new Date(d.date_added).toISOString()},${used},${d.last_used_at ? new Date(d.last_used_at).toISOString() : ''},${d.last_used_by || ''}\n`;
  }
  res.setHeader('Content-Disposition', `attachment; filename="x_export_${Date.now()}.csv"`);
  res.setHeader('Content-Type', 'text/csv');
  res.send(csv);
});

// Sync Used X (Admin) with model SELECT
app.post('/x/admin/upload-used', requireAdmin, upload.single('file'), async (req, res) => {
  if (!req.file) return res.status(400).send('No file uploaded');
  const model = (req.body.model || 'Natalie').trim();
  const content = req.file.buffer.toString('utf-8');
  const lines = content.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);

  let updated = 0, inserted = 0;
  for (const raw of lines) {
    const username = raw.toLowerCase().replace(/^@/, '');
    try {
      const existing = await UsernameX.findOne({ username });
      if (existing) {
        await UsernameX.updateOne({ _id: existing._id }, { $addToSet: { used_by: model }, $set: { last_used_at: new Date(), last_used_by: model } });
        updated++;
      } else {
        await UsernameX.create({ username, used_by: [model], last_used_at: new Date(), last_used_by: model });
        inserted++;
      }
    } catch (e) { console.error(e); }
  }
  await logEvent({ action: 'admin_sync_used_x', req, actor_type: 'admin', details: { model, processed: lines.length, updated, inserted } });

  res.send(renderPage(
    'Sync Used X Usernames Result',
    `
    <div class="notice">
      <p>Model: ${model}</p>
      <p>Processed ${lines.length} X usernames.</p>
      <p>Updated ${updated} existing entries.</p>
      <p>Inserted ${inserted} new entries.</p>
    </div>
    <p><a href="/x/admin">Back to X Admin</a></p>`,
    req
  ));
});

// Clear X DB
app.post('/x/admin/clear', requireAdmin, async (req, res) => {
  const confirm = (req.body.confirm || '').trim();
  if (confirm !== CLEAR_CONFIRM_TEXT) {
    return res.status(400).send(renderPage('Clear X Database',
      `<div class="notice">Confirmation text mismatch. Type exactly: <b>${CLEAR_CONFIRM_TEXT}</b></div><p><a href="/x/admin">Back to X Admin</a></p>`, req));
  }
  const del = await UsernameX.deleteMany({});
  await logEvent({ action: 'admin_clear_x_db', req, actor_type: 'admin', details: { deleted: del.deletedCount } });
  res.send(renderPage('X Database Cleared', `<div class="notice">Deleted ${del.deletedCount} X usernames.</div><p><a href="/x/admin">Back to X Admin</a></p>`, req));
});

// ===== Start =====
app.listen(PORT, () => console.log(`BlueMagic server running on :${PORT}`));
