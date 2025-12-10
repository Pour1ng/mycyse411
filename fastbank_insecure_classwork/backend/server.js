const express = require('express');
const path = require('path');
const fs = require('fs');
const { body, validationResult } = require('express-validator');

const app = express();

// --- ZAP FIXES: SECURITY HEADERS ---
app.disable('x-powered-by'); // Fixes "Server Leaks Information"

app.use((req, res, next) => {
  // Fixes "CSP: Failure to Define Directive"
  res.setHeader("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; form-action 'self'; frame-ancestors 'none';");
  
  // Fixes "Permissions Policy Header Not Set"
  res.setHeader("Permissions-Policy", "geolocation=(), camera=(), microphone=()");
  
  // Fixes "Storable and Cacheable Content"
  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate");
  res.setHeader("Pragma", "no-cache");
  res.setHeader("Expires", "0");
  
  next();
});
// -----------------------------------

app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const BASE_DIR = path.resolve(__dirname, 'files');
if (!fs.existsSync(BASE_DIR)) fs.mkdirSync(BASE_DIR, { recursive: true });

// helper to canonicalize and check
function resolveSafe(baseDir, userInput) {
  try {
    userInput = decodeURIComponent(userInput);
  } catch (e) {}
  return path.resolve(baseDir, userInput);
}

// Secure route
app.post(
  '/read',
  body('filename')
    .exists().withMessage('filename required')
    .bail()
    .isString()
    .trim()
    .notEmpty().withMessage('filename must not be empty')
    .custom(value => {
      if (value.includes('\0')) throw new Error('null byte not allowed');
      return true;
    }),
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const filename = req.body.filename;
    const normalized = resolveSafe(BASE_DIR, filename);
    if (!normalized.startsWith(BASE_DIR + path.sep)) {
      return res.status(403).json({ error: 'Path traversal detected' });
    }
    if (!fs.existsSync(normalized)) return res.status(404).json({ error: 'File not found' });

    const content = fs.readFileSync(normalized, 'utf8');
    res.json({ path: normalized, content });
  }
);

// --- SEMGREP FIX: WHITELIST APPROACH ---
app.post('/read-no-validate', (req, res) => {
  const userInput = req.body.filename || '';

  // NUCLEAR FIX: We look up the file in a dictionary.
  // We NEVER use the user input directly in the file path.
  const safeFiles = {
    'hello.txt': 'hello.txt',
    'readme.md': 'readme.md',
    'notes/readme.md': 'notes/readme.md',
    'public.txt': 'public.txt'
  };

  const safeName = safeFiles[userInput];

  if (!safeName) {
      return res.status(403).json({ error: "Access Denied: Invalid filename" });
  }

  // Use the hardcoded string from our map, not the user input
  const joined = path.join(BASE_DIR, safeName);

  if (!fs.existsSync(joined)) return res.status(404).json({ error: 'File not found' });
  
  const content = fs.readFileSync(joined, 'utf8');
  res.json({ path: joined, content });
});
// ---------------------------------------

// Helper route for samples
app.post('/setup-sample', (req, res) => {
  const samples = {
    'hello.txt': 'Hello from safe file!\n',
    'notes/readme.md': '# Readme\nSample readme file'
  };
  Object.keys(samples).forEach(k => {
    const p = path.resolve(BASE_DIR, k);
    const d = path.dirname(p);
    if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true });
    fs.writeFileSync(p, samples[k], 'utf8');
  });
  res.json({ ok: true, base: BASE_DIR });
});

// Only listen when run directly
if (require.main === module) {
  const port = process.env.PORT || 4000;
  app.listen(port, () => {
    console.log(`Server listening on http://localhost:${port}`);
  });
}

module.exports = app;
