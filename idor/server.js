const express = require('express');
const path = require('path');
const fs = require('fs');
const app = express();

app.use(express.json());


const BASE_DIR = path.join(__dirname, 'public');

if (!fs.existsSync(BASE_DIR)) fs.mkdirSync(BASE_DIR);

app.post('/read-no-validate', (req, res) => {
  const filename = req.body.filename || '';

  const allowedFiles = ['public.txt', 'readme.md', 'data.json', 'notes.txt'];

  if (!allowedFiles.includes(filename)) {
      return res.status(403).json({ error: "Access Denied: Invalid filename" });
  }

  const joined = path.join(BASE_DIR, filename);

  if (!fs.existsSync(joined)) {
      return res.status(404).json({ error: 'File not found' });
  }
  
  const content = fs.readFileSync(joined, 'utf8');
  res.json({ path: joined, content });
});

const PORT = 3000;
app.listen(PORT, () => console.log(`Listening on port ${PORT}`));
