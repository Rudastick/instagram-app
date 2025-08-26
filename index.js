// app.js  — BlueMagic Instagram Username Manager (full version)
// Implements login (user/VA/admin), admin panel, logs, revert, KPI, CSV export,
// presence list, models CRUD, VA CRUD (with Admin checkbox), inventory counters,
// Sync Used (with model select), and UI copy-to-clipboard. :)

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



require('dotenv').config();

require('dotenv').config();
console.log('cwd:', process.cwd());
console.log('env file seen:', require('fs').existsSync('.env'));
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
const SCRAPE_CONCURRENCY = parseInt(process.env.SCRAPE_CONCURRENCY || '1', 10);
const SCRAPE_DELAY_MS = parseInt(process.env.SCRAPE_DELAY_MS || '200', 10);


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
const scrapeJobs = new Map(); // jobId -> { total, done, start, rows, status, error }


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
  isAdmin: { type: Boolean, default: false }, // <— VA can be admin
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

// ===== Presence (in-memory) =====
const presence = new Map(); // sessionId -> { name, when }

// ===== View helpers =====
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
  const nav = req.session?.loggedIn
  ? `<nav>
      <a href="/add">Import</a>
      <a href="/format">Format & Take</a>
      <a href="/scrape">Scrape & Format IG</a>
      <a href="/revert">Revert</a>
      <a href="/kpi">KPI</a>
      <a href="/admin">Admin</a>
      <a href="/logout">Logout</a>
    </nav>` : '';

  return `<!DOCTYPE html>
  <html lang="en">
  <head>${pageHead(title)}</head>
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
      function copyFrom(id){
        const el = document.getElementById(id);
        if(!el) return;
        el.select(); document.execCommand('copy');
        if (navigator.clipboard) { navigator.clipboard.writeText(el.value).catch(()=>{}); }
        alert('Copied to clipboard');
      }
      // presence
      fetch('/presence/ping',{method:'POST', headers:{'Content-Type':'application/json'}}).catch(()=>{});
      setInterval(()=>{ fetch('/presence/ping',{method:'POST', headers:{'Content-Type':'application/json'}}).catch(()=>{}); }, 20000);
      function refreshPresence(){
        fetch('/presence/list').then(r=>r.json()).then(d=>{
          const box=document.getElementById('presenceBox');
          const list=document.getElementById('presenceList');
          list.innerHTML = (d.people||[]).map(p=>'• '+p).join('<br>') || '—';
          box.style.display='block';
        }).catch(()=>{});
      }
      refreshPresence(); setInterval(refreshPresence,15000);
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

// Map to Airtable-aligned CSV fields (plus Username first)
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
  if (req.session?.isAdmin) return next();
  return res.redirect('/admin/login');
}
app.use(requireUser);

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

  // Admin works here too (instant admin)
  if (pwd === ADMIN_PASSWORD) {
    req.session.loggedIn = true;
    req.session.isAdmin = true;
    req.session.vaName = null;
    await logEvent({ action: 'admin_login_via_main', req, actor_type: 'admin' });
    return res.redirect('/admin');
  }

  // Site-wide access password
  if (pwd === USER_PASSWORD) {
    req.session.loggedIn = true;
    req.session.isAdmin = false;
    req.session.vaName = null;
    await logEvent({ action: 'user_login', req, actor_type: 'user' });
    return res.redirect('/add');
  }

  // VA login (bcrypt) — elevate if VA.isAdmin
  const vaUsers = await VAUser.find({}).lean();
  for (const v of vaUsers) {
    if (await bcrypt.compare(pwd, v.password_hash)) {
      req.session.loggedIn = true;
      req.session.isAdmin = !!v.isAdmin;
      req.session.vaName = v.name;
      await logEvent({ action: 'va_login', req, actor_type: req.session.isAdmin ? 'admin' : 'va', details: { va: v.name } });
      return res.redirect(req.session.isAdmin ? '/admin' : '/add');
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
  const name = req.session?.vaName || (req.session?.isAdmin ? 'Admin' : 'User');
  if (req.sessionID) presence.set(req.sessionID, { name, when: Date.now() });
  res.json({ ok: true });
});
app.get('/presence/list', (_req, res) => {
  const now = Date.now();
  const list = [];
  for (const [sid, info] of presence.entries()) {
    if (now - info.when <= PRESENCE_TTL_MS) list.push(info.name);
    else presence.delete(sid);
  }
  res.json({ people: [...new Set(list)] });
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
      <td>${u.isAdmin ? 'Yes' : 'No'}</td>
      <td class="actions">
        <form action="/admin/users/delete" method="post" style="display:inline">
          <input type="hidden" name="name" value="${u.name}"/>
          <button class="danger">Delete</button>
        </form>
      </td>
    </tr>`).join('');

  const html = renderPage(
    'VA Users',
    `
    <div class="card">
      <form action="/admin/users/add" method="post" class="row">
        <div><input type="text" name="name" placeholder="VA name" required /></div>
        <div><input type="password" name="password" placeholder="New/Update password" required /></div>
        <div style="display:flex;align-items:center;gap:6px;">
          <input type="checkbox" id="isAdmin" name="isAdmin"/><label for="isAdmin">Admin</label>
        </div>
        <div><button type="submit">Add / Update</button></div>
      </form>
      <p class="muted">Passwords are hashed with bcrypt.</p>
      <p><a href="/admin">Back to Admin</a></p>
    </div>
    <div class="card">
      <table><thead><tr><th>VA</th><th>Admin</th><th>Actions</th></tr></thead><tbody>${rows || '<tr><td colspan="3">No VAs yet.</td></tr>'}</tbody></table>
    </div>`,
    req
  );
  res.send(html);
});
app.post('/admin/users/add', requireAdmin, async (req, res) => {
  const name = (req.body.name || '').trim();
  const pwd = (req.body.password || '').trim();
  const isAdmin = !!req.body.isAdmin;
  if (!name || !pwd) return res.redirect('/admin/users');
  const hash = await bcrypt.hash(pwd, 10);
  await VAUser.updateOne({ name }, { $set: { password_hash: hash, isAdmin } }, { upsert: true });
  await logEvent({ action: 'admin_va_add_or_update', req, actor_type: 'admin', details: { name, isAdmin } });
  res.redirect('/admin/users');
});
app.post('/admin/users/delete', requireAdmin, async (req, res) => {
  const name = (req.body.name || '').trim();
  if (name) {
    await VAUser.deleteOne({ name });
    await logEvent({ action: 'admin_va_delete', req, actor_type: 'admin', details: { name } });
  }
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
        <div id="kpiOut">A=0; Total=0</div> <!-- B removed from summary as requested -->
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

// ===== Start =====
app.listen(PORT, () => console.log(`BlueMagic server running on :${PORT}`));
