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

// Helper: render simple HTML page
function renderPage(title, content) {
  return `<!DOCTYPE html>
  <html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta http-equiv="X-UA-Compatible" content="IE=edge" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>${title}</title>
    <style>
      body { font-family: Arial, sans-serif; margin: 2rem; }
      form { margin-bottom: 2rem; }
      input[type="text"], input[type="number"] { padding: 0.4rem; margin-right: 0.5rem; }
    </style>
  </head>
  <body>
    <h1>${title}</h1>
    ${content}
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
    'Add Instagram Usernames',
    `<form action="/add" method="post" enctype="multipart/form-data">
      <label>Upload .txt file with one username per line:</label><br/>
      <input type="file" name="file" accept=".txt" required />
      <button type="submit">Upload</button>
    </form>
    <p><a href="/take">Go to Take Usernames</a></p>`
  );
  res.send(html);
});

// Route: Handle file upload and insertion
app.post('/add', upload.single('file'), async (req, res) => {
  if (!req.file) {
    return res.status(400).send('No file uploaded');
  }
  const content = req.file.buffer.toString('utf-8');
  const lines = content.split(/\r?\n/).filter((line) => line.trim() !== '');
  let inserted = 0;
  for (const raw of lines) {
    const username = raw.trim().toLowerCase();
    try {
      // Use upsert with $setOnInsert to avoid duplicates and set defaults
      const result = await Username.updateOne(
        { username },
        {
          $setOnInsert: { date_added: new Date(), used_by: [] },
        },
        { upsert: true }
      );
      if (result.upsertedCount > 0) inserted++;
    } catch (err) {
      console.error(`Error inserting ${username}:`, err);
      // continue to next line without stopping entire operation
    }
  }
  const html = renderPage(
    'Add Instagram Usernames',
    `<p>Processed ${lines.length} usernames, inserted ${inserted} new entries.</p>
    <p><a href="/add">Back to Add</a></p>
    <p><a href="/take">Go to Take Usernames</a></p>`
  );
  res.send(html);
});

// Route: Take usernames page
app.get('/take', (req, res) => {
  const html = renderPage(
    'Take Instagram Usernames',
    `<form action="/take" method="post">
      <label>Number of usernames to take:</label>
      <input type="number" name="count" min="1" required /><br/><br/>
      <label>Model name:</label>
      <input type="text" name="model" required /><br/><br/>
      <button type="submit">Take Usernames</button>
    </form>
    <p><a href="/add">Go to Add Usernames</a></p>`
  );
  res.send(html);
});

// Route: Handle taking usernames and updating used_by
app.post('/take', async (req, res) => {
  const count = parseInt(req.body.count, 10);
  const model = (req.body.model || '').trim();
  if (!count || !model) {
    return res.status(400).send('Invalid count or model');
  }
  try {
    // Find usernames not used by this model, sorted newest first
    const docs = await Username.find({ used_by: { $ne: model } })
      .sort({ date_added: -1 })
      .limit(count)
      .exec();
    const usernames = docs.map((doc) => doc.username);
    if (usernames.length > 0) {
      // Update each returned username by pushing the model into used_by
      await Username.updateMany(
        { _id: { $in: docs.map((d) => d._id) } },
        { $addToSet: { used_by: model } }
      );
    }
    const html = renderPage(
      'Take Instagram Usernames',
      `<p>Model: ${model}</p>
      <p>Requested: ${count}, Returned: ${usernames.length}</p>
      <pre>${usernames.join('\n')}</pre>
      <p><a href="/take">Back to Take Usernames</a></p>
      <p><a href="/add">Go to Add Usernames</a></p>`
    );
    res.send(html);
  } catch (err) {
    console.error('Error taking usernames:', err);
    res.status(500).send('Server error');
  }
});

// Start the server
app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
});