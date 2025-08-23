// app.js
const express = require('express');
const mongoose = require('mongoose');
const multer = require('multer');
const session = require('express-session');
const fs = require('fs');

// ===== ENV =====
const {
  MONGO_URL,
  PORT = 3000,
  SESSION_SECRET = 'change-me-please',
} = process.env;

// ===== CONSTANTS (Passwords) =====
const USER_PASSWORD = 'Blue@magicTeam!7';
const ADMIN_PASSWORD = 'Nigwedeek217';
const CLEAR_CONFIRM_TEXT = 'I confirm to clear Database';

// ===== APP INIT =====
const app = express();
app.use(express.urlencoded({ extended: true }));

// sessions (one-time login per browser session)
app.use(
  session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: { httpOnly: true, sameSite: 'lax', maxAge: 1000 * 60 * 60 * 12 }, // 12h
  })
);

// Multer for .txt uploads from memory
const upload = multer({ storage: multer.memoryStorage() });

// ===== DB =====
mongoose
  .connect(MONGO_URL, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('Connected to MongoDB'))
  .catch((err) => {
    console.error('MongoDB connection error:', err);
    process.exit(1);
  });

const usernameSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true, lowercase: true, trim: true },
  date_added: { type: Date, default: Date.now },
  used_by: { type: [String], default: [] }, // models that used this username
});

const logSchema = new mongoose.Schema({
  ts: { type: Date, default: Date.now },
  actor: { type: String, enum: ['user', 'admin'], default: 'user' },
  action: { type: String, required: true },
  details: { type: Object, default: {} },
});

const Username = mongoose.model('Username', usernameSchema);
const Log = mongoose.model('Log', logSchema);

// ===== UTIL =====
function renderPage(title, content, opts = {}) {
  const { sessionUser = {}, showAdminNav = false } = opts;
  const nav = `
    <nav class="nav">
      ${sessionUser.loggedIn ? `<a href="/add">Import</a>
      <a href="/format">Format & Take</a>` : ''}
      ${sessionUser.isAdmin ? `<a href="/admin">Admin</a>` : ''}
      ${sessionUser.loggedIn ? `<a href="/logout">Logout</a>` : ''}
    </nav>`;

  return `<!DOCTYPE html>
  <html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>${title}</title>
    <style>
      :root { color-scheme: dark; }
      body { font-family: Inter, system-ui, Arial, sans-serif; background-color: #0f1115; color: #eaeaf0; padding: 24px; }
      .container { max-width: 900px; margin: 0 auto; }
      h1 { margin: 0 0 16px; font-size: 24px; }
      h2 { margin: 24px 0 12px; font-size: 18px; }
      .nav { display:flex; gap:12px; margin-bottom: 16px; }
      .nav a { color:#9ec1ff; text-decoration:none; background:#151926; padding:8px 10px; border-radius:8px; }
      form { display: grid; gap: 10px; margin-bottom: 20px; }
      label { font-size: 14px; opacity: 0.9; }
      input[type="file"], input[type="number"], input[type="text"], input[type="password"], select, button, textarea {
        padding: 10px; border-radius: 8px; border: 1px solid #2a2f45; background-color: #121624; color: #eaeaf0;
      }
      textarea { min-height: 220px; white-space: pre; }
      button { background: linear-gradient(180deg, #6a0dad, #52118e); border: none; cursor: pointer; font-weight: 600; }
      button:hover { filter: brightness(1.06); }
      .row { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }
      .notice { padding: 12px; background-color: #11172b; border: 1px solid #2a2f45; border-radius: 8px; }
      table { width: 100%; border-collapse: collapse; }
      th, td { border-bottom: 1px solid #2a2f45; padding: 8px; text-align: left; font-size: 13px; }
      .danger { background: linear-gradient(180deg, #d64b4b, #a52929); }
      .muted { opacity: 0.8; font-size: 12px; }
      .help { font-size:12px; opacity:0.8; }
      .card { padding:16px; background:#0f1424; border:1px solid #222a44; border-radius:12px; }
      .actions { display:flex; gap: 10px; flex-wrap: wrap; }
    </style>
  </head>
  <body>
    <div class="container">
      ${nav}
      <h1>${title}</h1>
      ${content}
    </div>
  </body>
  </html>`;
}

async function logEvent(action, details = {}, actor = 'user') {
  try {
    await Log.create({ action, details, actor });
  } catch (e) {
    console.error('Log error:', e);
  }
}

// ===== AUTH MIDDLEWARES =====
function requireUser(req, res, next) {
  if (req.path === '/login' || req.path.startsWith('/admin') || req.path === '/health') return next();
  if (req.session?.loggedIn) return next();
  return res.redirect('/login');
}

function requireAdmin(req, res, next) {
  if (req.session?.isAdmin) return next();
  return res.redirect('/admin/login');
}

app.use(requireUser);

// ===== HEALTH =====
app.get('/health', (_req, res) => res.send('ok'));

// ===== LOGIN / LOGOUT =====
app.get('/login', (req, res) => {
  const html = renderPage(
    'Login',
    `
    <form action="/login" method="post" class="card">
      <label>Enter password to access</label>
      <input type="password" name="password" placeholder="Password" required />
      <button type="submit">Login</button>
      <p class="help">You only need to login once per session.</p>
    </form>
    `,
    { sessionUser: req.session }
  );
  res.send(html);
});

app.post('/login', async (req, res) => {
  const pwd = req.body.password || '';
  if (pwd === USER_PASSWORD) {
    req.session.loggedIn = true;
    await logEvent('user_login', {}, 'user');
    return res.redirect('/add');
  }
  const html = renderPage('Login', `<div class="notice">Wrong password.</div>
    <p><a href="/login">Try again</a></p>`, { sessionUser: req.session });
  res.status(401).send(html);
});

app.get('/logout', async (req, res) => {
  await logEvent('user_logout', {}, req.session?.isAdmin ? 'admin' : 'user');
  req.session.destroy(() => res.redirect('/login'));
});

// ===== ADMIN AUTH =====
app.get('/admin/login', (req, res) => {
  const html = renderPage(
    'Admin Login',
    `
    <form action="/admin/login" method="post" class="card">
      <label>Admin password</label>
      <input type="password" name="password" placeholder="Admin password" required />
      <button type="submit">Login as Admin</button>
      <p class="help">Admin lets you view logs, sync used usernames, export CSV, and clear the database.</p>
    </form>
    `,
    { sessionUser: req.session }
  );
  res.send(html);
});

app.post('/admin/login', async (req, res) => {
  const pwd = req.body.password || '';
  if (pwd === ADMIN_PASSWORD) {
    req.session.loggedIn = true; // ensure base auth as well
    req.session.isAdmin = true;
    await logEvent('admin_login', {}, 'admin');
    return res.redirect('/admin');
  }
  const html = renderPage('Admin Login', `<div class="notice">Wrong admin password.</div>
    <p><a href="/admin/login">Try again</a></p>`, { sessionUser: req.session });
  res.status(401).send(html);
});

// ===== ROUTES =====

// Home → redirect
app.get('/', (req, res) => res.redirect('/add'));

// Import usernames (USER)
app.get('/add', (req, res) => {
  const html = renderPage(
    'Import Usernames',
    `
    <form action="/add" method="post" enctype="multipart/form-data" class="card">
      <label>Upload a .txt file with one Instagram username per line:</label>
      <input type="file" name="file" accept=".txt" required />
      <button type="submit">Import Usernames</button>
    </form>
    <div class="help">Duplicates are ignored automatically. Results will show counts.</div>
    <p><a href="/format">Go to Format & Take Usernames</a></p>
    <p><a href="/admin">Admin panel</a></p>
    `,
    { sessionUser: req.session }
  );
  res.send(html);
});

app.post('/add', upload.single('file'), async (req, res) => {
  if (!req.file) return res.status(400).send('No file uploaded');

  const content = req.file.buffer.toString('utf-8');
  const lines = content.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);

  let inserted = 0;
  for (const raw of lines) {
    const username = raw.toLowerCase();
    try {
      const result = await Username.updateOne(
        { username },
        { $setOnInsert: { date_added: new Date(), used_by: [] } },
        { upsert: true }
      );
      if (result.upsertedCount > 0) inserted++;
    } catch (err) {
      console.error(`Error inserting ${username}:`, err);
    }
  }
  const duplicates = lines.length - inserted;
  await logEvent('import_usernames', { processed: lines.length, inserted, duplicates });

  const html = renderPage(
    'Import Usernames Result',
    `
    <div class="notice">
      <p>Processed ${lines.length} usernames.</p>
      <p>Inserted ${inserted} new entries.</p>
      <p>Detected ${duplicates} duplicates.</p>
    </div>
    <p><a href="/add">Back to Import</a></p>
    <p><a href="/format">Go to Format & Take Usernames</a></p>
    `,
    { sessionUser: req.session }
  );
  res.send(html);
});

// Legacy /take
app.get('/take', (_req, res) => res.redirect('/format'));
app.post('/take', (req, res) => res.redirect(307, '/format'));

// Helper: Fetch next usernames for a model
async function fetchUsernames(model, count) {
  const docs = await Username.find({ used_by: { $ne: model } })
    .sort({ date_added: -1 })
    .limit(count)
    .exec();
  const ids = docs.map((d) => d._id);
  if (ids.length) {
    await Username.updateMany({ _id: { $in: ids } }, { $addToSet: { used_by: model } });
  }
  return docs.map((d) => d.username);
}

// Format & Take (USER)
app.get('/format', (req, res) => {
  const html = renderPage(
    'Format & Take Usernames',
    `
    <form action="/format" method="post" class="card">
      <div class="row">
        <div>
          <label>Select model:</label>
          <select name="model" required>
            <option value="Natalie">Natalie</option>
          </select>
        </div>
        <div>
          <label>Accounts to pull (A):</label>
          <input type="number" name="count" min="1" value="10" required />
          <div class="help">These are the accounts that will follow.</div>
        </div>
      </div>
      <div class="row">
        <div>
          <label>Usernames per line (B):</label>
          <input type="number" name="perLine" min="1" value="10" required />
          <div class="help">These are scraped usernames per account.</div>
        </div>
        <div>
          <label>Total usernames fetched = A × B (auto)</label>
          <input type="text" value="Calculated after submit" disabled />
        </div>
      </div>
      <button type="submit">Format and Preview</button>
    </form>
    <p><a href="/add">Import more usernames</a></p>
    <p><a href="/admin">Admin panel</a></p>
    `,
    { sessionUser: req.session }
  );
  res.send(html);
});

app.post('/format', async (req, res) => {
  const count = parseInt(req.body.count, 10);
  const perLine = parseInt(req.body.perLine, 10);
  const model = (req.body.model || 'Natalie').trim();

  if (!count || !perLine || count < 1 || perLine < 1) {
    return res.status(400).send('Invalid form values');
  }

  try {
    // NEW: fetch A × B usernames total
    const totalToFetch = count * perLine;
    const usernames = await fetchUsernames(model, totalToFetch);

    // Group into B per line
    const lines = [];
    for (let i = 0; i < usernames.length; i += perLine) {
      lines.push(usernames.slice(i, i + perLine).join(','));
    }
    const formatted = lines.join('\n');

    await logEvent('format_take', {
      model,
      requested_accounts: count,
      per_line: perLine,
      total_requested: totalToFetch,
      total_returned: usernames.length,
    });

    const html = renderPage(
      'Formatted Usernames',
      `
      <div class="notice">
        <p>Model: <b>${model}</b></p>
        <p>Accounts (A): ${count} &nbsp; | &nbsp; Per line (B): ${perLine} &nbsp; ⇒ &nbsp; Requested total: ${totalToFetch}</p>
        <p>Returned: ${usernames.length}</p>
      </div>

      <label>Preview (Ctrl+A then Ctrl+C to copy all):</label>
      <textarea readonly>${formatted}</textarea>

      <form action="/download" method="post" class="actions">
        <input type="hidden" name="data" value="${encodeURIComponent(formatted)}" />
        <input type="hidden" name="filename" value="usernames_${model}.txt" />
        <button type="submit">Download .txt</button>
      </form>

      <p><a href="/format">Back to Format & Take</a></p>
      <p><a href="/add">Import more usernames</a></p>
      <p><a href="/admin">Admin panel</a></p>
      `,
      { sessionUser: req.session }
    );
    res.send(html);
  } catch (err) {
    console.error(err);
    res.status(500).send('Server error');
  }
});

// Download formatted data
app.post('/download', (req, res) => {
  const data = decodeURIComponent(req.body.data || '');
  const filename = req.body.filename || 'usernames.txt';
  res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
  res.setHeader('Content-Type', 'text/plain');
  res.send(data);
});

// ===== ADMIN PANEL =====
app.get('/admin', requireAdmin, async (req, res) => {
  const html = renderPage(
    'Admin Panel',
    `
    <div class="card">
      <h2>Logs</h2>
      <form action="/admin/logs" method="get" class="actions">
        <button type="submit">View latest logs</button>
      </form>
    </div>

    <div class="card">
      <h2>Sync used usernames</h2>
      <form action="/admin/upload-used" method="post" enctype="multipart/form-data">
        <label>Upload a .txt file of usernames already used by <b>Natalie</b>:</label>
        <input type="file" name="file" accept=".txt" required />
        <button type="submit">Sync</button>
      </form>
    </div>

    <div class="card">
      <h2>Export CSV</h2>
      <form action="/admin/export" method="post" class="row">
        <div>
          <label>Filter by model (optional):</label>
          <input type="text" name="model" placeholder="e.g. Natalie" />
        </div>
        <div>
          <label>Used status:</label>
          <select name="status">
            <option value="any">Any</option>
            <option value="unused">Unused by model</option>
            <option value="used_by_model">Used by model</option>
            <option value="used_by_any">Used by any model</option>
          </select>
        </div>
        <div>
          <label>From date (optional):</label>
          <input type="text" name="from" placeholder="YYYY-MM-DD" />
        </div>
        <div>
          <label>To date (optional):</label>
          <input type="text" name="to" placeholder="YYYY-MM-DD" />
        </div>
        <div>
          <label>Limit:</label>
          <input type="number" name="limit" min="1" value="1000" />
        </div>
        <div style="display:flex; align-items:end;">
          <button type="submit">Export CSV</button>
        </div>
      </form>
      <p class="help">CSV columns: username, date_added (ISO), used_by (pipe-separated)</p>
    </div>

    <div class="card">
      <h2>Danger zone</h2>
      <form action="/admin/clear" method="post">
        <label class="help">Type exactly: <b>${CLEAR_CONFIRM_TEXT}</b></label>
        <input type="text" name="confirm" placeholder="${CLEAR_CONFIRM_TEXT}" required />
        <button type="submit" class="danger">Clear Database</button>
      </form>
      <p class="help">Requires you to be logged in as admin (already are). This deletes <b>all</b> usernames.</p>
    </div>
    `,
    { sessionUser: req.session }
  );
  res.send(html);
});

// Admin logs
app.get('/admin/logs', requireAdmin, async (req, res) => {
  const logs = await Log.find({}).sort({ ts: -1 }).limit(200).lean();
  const rows = logs
    .map(
      (l) =>
        `<tr><td>${new Date(l.ts).toLocaleString()}</td><td>${l.actor}</td><td>${l.action}</td><td><code>${JSON.stringify(
          l.details || {}
        )}</code></td></tr>`
    )
    .join('');
  const html = renderPage(
    'Recent Logs',
    `
    <div class="notice">Last ${logs.length} events.</div>
    <table>
      <thead><tr><th>Date</th><th>Actor</th><th>Action</th><th>Details</th></tr></thead>
      <tbody>${rows || '<tr><td colspan="4">No logs yet.</td></tr>'}</tbody>
    </table>
    <p><a href="/admin">Back to Admin</a></p>
    `,
    { sessionUser: req.session }
  );
  res.send(html);
});

// Move Sync used usernames to Admin
app.post('/admin/upload-used', requireAdmin, upload.single('file'), async (req, res) => {
  if (!req.file) return res.status(400).send('No file uploaded');
  const content = req.file.buffer.toString('utf-8');
  const lines = content.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);

  let updated = 0;
  let inserted = 0;
  for (const raw of lines) {
    const username = raw.toLowerCase();
    try {
      const existing = await Username.findOne({ username });
      if (existing) {
        await Username.updateOne({ _id: existing._id }, { $addToSet: { used_by: 'Natalie' } });
        updated++;
      } else {
        await Username.create({ username, used_by: ['Natalie'] });
        inserted++;
      }
    } catch (err) {
      console.error(err);
    }
  }
  await logEvent('admin_sync_used', { processed: lines.length, updated, inserted }, 'admin');

  const html = renderPage(
    'Sync Used Usernames Result',
    `
    <div class="notice">
      <p>Processed ${lines.length} usernames.</p>
      <p>Updated ${updated} existing entries.</p>
      <p>Inserted ${inserted} new entries.</p>
    </div>
    <p><a href="/admin">Back to Admin</a></p>
    `,
    { sessionUser: req.session }
  );
  res.send(html);
});

// Admin CSV export
app.post('/admin/export', requireAdmin, async (req, res) => {
  const { model = '', status = 'any', from = '', to = '', limit = '1000' } = req.body;

  const q = {};
  // date filter
  if (from || to) q.date_added = {};
  if (from) q.date_added.$gte = new Date(from);
  if (to) q.date_added.$lte = new Date(to + 'T23:59:59.999Z');

  // used status logic
  if (status === 'unused' && model) q.used_by = { $ne: model };
  if (status === 'used_by_model' && model) q.used_by = model;
  if (status === 'used_by_any') q.used_by = { $exists: true, $ne: [] };

  const lim = Math.max(1, Math.min(parseInt(limit, 10) || 1000, 100000));
  const docs = await Username.find(q).sort({ date_added: -1 }).limit(lim).lean();

  await logEvent('admin_export_csv', { count: docs.length, query: q }, 'admin');

  let csv = 'username,date_added,used_by\n';
  for (const d of docs) {
    const used = (d.used_by || []).join('|');
    csv += `${d.username},${new Date(d.date_added).toISOString()},${used}\n`;
  }

  res.setHeader('Content-Disposition', `attachment; filename="export_${Date.now()}.csv"`);
  res.setHeader('Content-Type', 'text/csv');
  res.send(csv);
});

// Admin clear DB (with confirmation text)
app.post('/admin/clear', requireAdmin, async (req, res) => {
  const confirm = req.body.confirm || '';
  if (confirm !== CLEAR_CONFIRM_TEXT) {
    const html = renderPage(
      'Clear Database',
      `<div class="notice">Confirmation text mismatch. Type exactly: <b>${CLEAR_CONFIRM_TEXT}</b></div>
       <p><a href="/admin">Back to Admin</a></p>`,
      { sessionUser: req.session }
    );
    return res.status(400).send(html);
  }
  const del = await Username.deleteMany({});
  await logEvent('admin_clear_db', { deleted: del.deletedCount }, 'admin');

  const html = renderPage(
    'Database Cleared',
    `<div class="notice">Deleted ${del.deletedCount} usernames.</div>
     <p><a href="/admin">Back to Admin</a></p>`,
    { sessionUser: req.session }
  );
  res.send(html);
});

// ===== START =====
app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
});
