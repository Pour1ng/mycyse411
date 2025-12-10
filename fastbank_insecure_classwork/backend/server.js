const express = require("express");
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const cors = require("cors");
const sqlite3 = require("sqlite3").verbose();
const crypto = require("crypto");

const app = express();

// --- ZAP SECURITY HEADERS (REQUIRED) ---
app.disable('x-powered-by');

app.use((req, res, next) => {
  // 1. CSP: Strictly define allowed sources. 
  // ZAP Alert 10055 requires 'frame-ancestors' and 'form-action' to be explicitly defined 
  // because they do not fallback to 'default-src'.
  res.setHeader(
    "Content-Security-Policy",
    "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; form-action 'self'; upgrade-insecure-requests;"
  );

  // 2. Permissions Policy
  res.setHeader("Permissions-Policy", "geolocation=(), camera=(), microphone=()");

  // 3. Cache Control
  // ZAP often flags 'no-store' as an informational alert, but for security, we keep it strict.
  res.setHeader("Cache-Control", "no-cache, no-store, must-revalidate");
  res.setHeader("Pragma", "no-cache");
  res.setHeader("Expires", "0");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY"); // Redundant with CSP frame-ancestors but good for depth

  next();
});
// ---------------------------------------

app.use(
  cors({
   origin: ["http://localhost:3001", "http://127.0.0.1:3001"],
    credentials: true
  })
);

app.use(bodyParser.json());
app.use(cookieParser());

const db = new sqlite3.Database(":memory:");

db.serialize(() => {
  db.run(`
    CREATE TABLE users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE,
      password_hash TEXT,
      email TEXT
    );
  `);

  db.run(`
    CREATE TABLE transactions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      amount REAL,
      description TEXT
    );
  `);

  db.run(`
    CREATE TABLE feedback (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user TEXT,
      comment TEXT
    );
  `);

  const passwordHash = crypto.createHash("sha256").update("password123").digest("hex");

  db.run(`INSERT INTO users (username, password_hash, email)
          VALUES ('alice', '${passwordHash}', 'alice@example.com');`);

  db.run(`INSERT INTO transactions (user_id, amount, description) VALUES (1, 25.50, 'Coffee shop')`);
  db.run(`INSERT INTO transactions (user_id, amount, description) VALUES (1, 100, 'Groceries')`);
});

const sessions = {};

function fastHash(pwd) {
  return crypto.createHash("sha256").update(pwd).digest("hex");
}

function auth(req, res, next) {
  const sid = req.cookies.sid;
  if (!sid || !sessions[sid]) return res.status(401).json({ error: "Not authenticated" });
  req.user = { id: sessions[sid].userId };
  next();
}

// --- NEW ROOT ROUTE FOR ZAP SCANNER ---
// This ensures ZAP gets a 200 OK on the home page and reads headers correctly
app.get("/", (req, res) => {
  res.send("FastBank Backend is running. Security headers are active.");
});
// --------------------------------------

app.post("/login", (req, res) => {
  const { username, password } = req.body;
  const sql = `SELECT id, username, password_hash FROM users WHERE username = '${username}'`;

  // Vulnerable to SQLi? Yes, but we are fixing headers for DAST first.
  db.get(sql, (err, user) => {
    if (!user) return res.status(404).json({ error: "Unknown username" });

    const candidate = fastHash(password);
    if (candidate !== user.password_hash) {
      return res.status(401).json({ error: "Wrong password" });
    }

    const sid = `${username}-${Date.now()}`;
    sessions[sid] = { userId: user.id };
    
    // Cookie Security: Add httpOnly and secure (if https)
    // Note: ZAP might flag missing 'Secure' flag if running on http, but httpOnly should be there.
    res.cookie("sid", sid, { httpOnly: true, sameSite: 'strict' });
    res.json({ success: true });
  });
});

app.get("/me", auth, (req, res) => {
  db.get(`SELECT username, email FROM users WHERE id = ${req.user.id}`, (err, row) => {
    res.json(row);
  });
});

app.get("/transactions", auth, (req, res) => {
  const q = req.query.q || "";
  const sql = `
    SELECT id, amount, description
    FROM transactions
    WHERE user_id = ${req.user.id}
      AND description LIKE '%${q}%'
    ORDER BY id DESC
  `;
  db.all(sql, (err, rows) => res.json(rows));
});

app.post("/feedback", auth, (req, res) => {
  const comment = req.body.comment;
  const userId = req.user.id;

  db.get(`SELECT username FROM users WHERE id = ${userId}`, (err, row) => {
    const username = row.username;
    const insert = `
      INSERT INTO feedback (user, comment)
      VALUES ('${username}', '${comment}')
    `;
    db.run(insert, () => {
      res.json({ success: true });
    });
  });
});

app.get("/feedback", auth, (req, res) => {
  db.all("SELECT user, comment FROM feedback ORDER BY id DESC", (err, rows) => {
    res.json(rows);
  });
});

app.post("/change-email", auth, (req, res) => {
  const newEmail = req.body.email;
  if (!newEmail.includes("@")) return res.status(400).json({ error: "Invalid email" });
  const sql = `
    UPDATE users SET email = '${newEmail}' WHERE id = ${req.user.id}
  `;
  db.run(sql, () => {
    res.json({ success: true, email: newEmail });
  });
});

app.listen(4000, () =>
  console.log("FastBank Version A backend running on http://localhost:4000")
);
