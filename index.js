const express = require('express');
const mongoose = require('mongoose');
const multer = require('multer');
const fs = require('fs');

// Load environment variables
const { MONGO_URL, PORT = 3000 } = process.env;

// Initialize Express
const app = express();
app.use(express.urlencoded({ extended: true }));

// Multer setup for handling .txt uploads from memory
const upload = multer({ storage: multer.memoryStorage() });

// Connect to MongoDB
mongoose
  .connect(MONGO_URL, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log('Connected to MongoDB'))
  .catch((err) => {
    console.error('MongoDB connection error:', err);
    process.exit(1);
  });

// Define Username schema
const usernameSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true,
  },
  date_added: {
    type: Date,
    default: Date.now,
  },
  used_by: {
    type: [String],
    default: [],
  },
});

const Username = mongoose.model('Username', usernameSchema);

// Helper: render HTML page with a basic dark theme. Accepts optional content and title.
function renderPage(title, content) {
  return `<!DOCTYPE html>
  <html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>${title}</title>
    <style>
      body { font-family: Arial, sans-serif; background-color: #121212; color: #f5f5f5; padding: 20px; }
      h1 { margin-bottom: 1rem; }
      .container { max-width: 600px; margin: 0 auto; }
      form { display: flex; flex-direction: column; gap: 0.75rem; margin-bottom: 2rem; }
      input[type="file"], input[type="number"], select, button { padding: 0.5rem; border-radius: 4px; border: none; }
      input[type="number"], select { background-color: #1e1e1e; color: #f5f5f5; }
      input[type="file"] { color: #f5f5f5; }
      button { background-color: #6a0dad; color: white; cursor: pointer; }
      button:hover { background-color: #5b099f; }
      a { color: #84aeea; text-decoration: none; }
      pre { background-color: #1e1e1e; padding: 1rem; border-radius: 4px; overflow-x: auto; }
      .notice { margin-top: 1rem; padding: 1rem; background-color: #1e1e1e; border-radius: 4px; }
    </style>
  </head>
  <body>
    <div class="container">
      <h1>${title}</h1>
      ${content}
    </div>
  </body>
  </html>`;
}

// Route: Home redirects to add page
app.get('/', (req, res) => {
  res.redirect('/add');
});

// Route: Add usernames page
app.get('/add', (req, res) => {
  const html = renderPage(
    'Import Usernames',
    `
    <form action="/add" method="post" enctype="multipart/form-data">
      <label>Upload a .txt file with one Instagram username per line:</label>
      <input type="file" name="file" accept=".txt" required />
      <button type="submit">Import Usernames</button>
    </form>
    <p><a href="/format">Go to Format & Take Usernames</a></p>
    <p><a href="/upload-used">Sync used usernames</a></p>
    `
  );
  res.send(html);
});

// Route: Handle file upload and insertion
app.post('/add', upload.single('file'), async (req, res) => {
  if (!req.file) {
    return res.status(400).send('No file uploaded');
  }
  const content = req.file.buffer.toString('utf-8');
  // Split into lines, trim and filter empty lines
  const rawLines = content.split(/\r?\n/);
  const lines = rawLines.map((l) => l.trim()).filter((l) => l !== '');
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
  const html = renderPage(
    'Import Usernames Result',
    `
    <div class="notice">
      <p>Processed ${lines.length} usernames.</p>
      <p>Inserted ${inserted} new entries.</p>
      <p>Detected ${duplicates} duplicates (already present in the database or repeated within the file).</p>
    </div>
    <p><a href="/add">Back to Import</a></p>
    <p><a href="/format">Go to Format & Take Usernames</a></p>
    `
  );
  res.send(html);
});

// Route: legacy take page (redirects to format page for improved UI)
app.get('/take', (req, res) => {
  res.redirect('/format');
});

// Utility to fetch next usernames for a model
async function fetchUsernames(model, count) {
  const docs = await Username.find({ used_by: { $ne: model } })
    .sort({ date_added: -1 })
    .limit(count)
    .exec();
  const usernames = docs.map((d) => d.username);
  if (usernames.length > 0) {
    await Username.updateMany({ _id: { $in: docs.map((d) => d._id) } }, { $addToSet: { used_by: model } });
  }
  return usernames;
}

// New UI: Format & take usernames page
app.get('/format', (req, res) => {
  const html = renderPage(
    'Format & Take Usernames',
    `
    <form action="/format" method="post">
      <label>Select model:</label>
      <select name="model" required>
        <option value="Natalie">Natalie</option>
      </select>
      <label>Number of accounts to pull:</label>
      <input type="number" name="count" min="1" required />
      <label>Usernames per line:</label>
      <input type="number" name="perLine" min="1" value="10" required />
      <button type="submit">Format and Download</button>
    </form>
    <p><a href="/add">Import more usernames</a></p>
    <p><a href="/upload-used">Sync used usernames</a></p>
    `
  );
  res.send(html);
});

// Handle format & take usernames
app.post('/format', async (req, res) => {
  const count = parseInt(req.body.count, 10);
  const perLine = parseInt(req.body.perLine, 10);
  const model = (req.body.model || 'Natalie').trim();
  if (!count || !perLine) {
    return res.status(400).send('Invalid form values');
  }
  try {
    const usernames = await fetchUsernames(model, count);
    // Group usernames by perLine for formatting
    const lines = [];
    for (let i = 0; i < usernames.length; i += perLine) {
      lines.push(usernames.slice(i, i + perLine).join(','));
    }
    const formatted = lines.join('\n');
    const html = renderPage(
      'Formatted Usernames',
      `
      <div class="notice">
        <p>Model: ${model}</p>
        <p>Requested: ${count}, Returned: ${usernames.length}</p>
      </div>
      <label>Preview:</label>
      <pre>${formatted}</pre>
      <form action="/download" method="post">
        <input type="hidden" name="data" value="${encodeURIComponent(formatted)}" />
        <input type="hidden" name="filename" value="usernames_${model}.txt" />
        <button type="submit">Download Formatted List</button>
      </form>
      <p><a href="/format">Back to Format & Take Usernames</a></p>
      <p><a href="/add">Import more usernames</a></p>
      `
    );
    res.send(html);
  } catch (err) {
    console.error(err);
    res.status(500).send('Server error');
  }
});

// Endpoint to download formatted data
app.post('/download', (req, res) => {
  const data = decodeURIComponent(req.body.data || '');
  const filename = req.body.filename || 'usernames.txt';
  res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
  res.setHeader('Content-Type', 'text/plain');
  res.send(data);
});

// Page to sync used usernames
app.get('/upload-used', (req, res) => {
  const html = renderPage(
    'Sync Used Usernames',
    `
    <form action="/upload-used" method="post" enctype="multipart/form-data">
      <label>Upload a .txt file of usernames already used by Natalie:</label>
      <input type="file" name="file" accept=".txt" required />
      <button type="submit">Sync</button>
    </form>
    <p><a href="/format">Back to Format & Take Usernames</a></p>
    <p><a href="/add">Import more usernames</a></p>
    `
  );
  res.send(html);
});

// Handle syncing used usernames
app.post('/upload-used', upload.single('file'), async (req, res) => {
  if (!req.file) {
    return res.status(400).send('No file uploaded');
  }
  const content = req.file.buffer.toString('utf-8');
  const lines = content.split(/\r?\n/).map((l) => l.trim()).filter((l) => l !== '');
  let updated = 0;
  let inserted = 0;
  for (const raw of lines) {
    const username = raw.toLowerCase();
    try {
      const existing = await Username.findOne({ username });
      if (existing) {
        const result = await Username.updateOne({ _id: existing._id }, { $addToSet: { used_by: 'Natalie' } });
        updated++;
      } else {
        // Insert new doc with used_by containing Natalie
        await Username.create({ username, used_by: ['Natalie'] });
        inserted++;
      }
    } catch (err) {
      console.error(err);
    }
  }
  const html = renderPage(
    'Sync Used Usernames Result',
    `
    <div class="notice">
      <p>Processed ${lines.length} usernames.</p>
      <p>Updated ${updated} existing entries.</p>
      <p>Inserted ${inserted} new entries.</p>
    </div>
    <p><a href="/upload-used">Back to Sync</a></p>
    <p><a href="/format">Back to Format & Take Usernames</a></p>
    `
  );
  res.send(html);
});

// Start the server
app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
});