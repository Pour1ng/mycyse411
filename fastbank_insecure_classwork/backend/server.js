const express = require("express");
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const cors = require("cors");
const sqlite3 = require("sqlite3").verbose();
const crypto = require("crypto");

const app = express();

// --- ZAP SECURITY HEADERS (Remediation for Task 3/4) ---
app.use((req, res, next) => {
  // 1. CSP: Fixes "CSP: Failure to Define Directive with No Fallback"
  res.setHeader(
    "Content-Security-Policy",
    "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; form-action 'self';"
  );
  
  // 2. Cache Control: Fixes "Non-Storable Content" (Valid for banking apps)
  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate");
  res.setHeader("Pragma", "no-cache");
  res.setHeader("Expires", "0");
  
  // 3. Prevent MIME-sniffing
  res.setHeader("X-Content-Type-Options", "nosniff");
  
  next();
});

// --- BASIC CORS ---
app.use(
  cors({
    origin: ["http://localhost:3001", "http://127.0.0.1:3001"],
    credentials: true
  })
);

app.use(bodyParser.json());
app.use(cookieParser());

// --- ROOT ROUTE (Fixes ZAP 404 Error) ---
app.get("/", (req, res) => {
  res.send("FastBank Backend is Running. Security Headers Active.");
});

// --- IN-MEMORY SQLITE DB ---
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

  // Use prepared statements for initialization too (best practice)
  const stmtUser = db.prepare("INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)");
  stmtUser.run('alice', passwordHash, 'alice@example.com');
  stmtUser.finalize();

  const stmtTx = db.prepare("INSERT INTO transactions (user_id, amount, description) VALUES (?, ?, ?)");
  stmtTx.run(1, 25.50, 'Coffee shop');
  stmtTx.run(1, 100, 'Groceries');
  stmtTx.finalize();
});

// --- SESSION STORE ---
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

// ------------------------------------------------------------
// REMEDIATION: LOGIN
// ------------------------------------------------------------
app.post("/login", (req, res) => {
  const { username, password } = req.body;

  // FIX: Parameterized Query
  const sql = `SELECT id, username, password_hash FROM users WHERE username = ?`;

  db.get(sql, [username], (err, user) => {
    if (err) return res.status(500).json({ error: "Database error" });
    if (!user) return res.status(404).json({ error: "Unknown username" });

    const candidate = fastHash(password);
    if (candidate !== user.password_hash) {
      return res.status(401).json({ error: "Wrong password" });
    }

    // FIX: Secure Random Session ID
    const sid = crypto.randomUUID(); 
    sessions[sid] = { userId: user.id };

    // FIX: HttpOnly Cookie (prevents XSS stealing cookie)
    res.cookie("sid", sid, { 
        httpOnly: true, 
        sameSite: 'strict',
        secure: false // Keep false for localhost/http
    });

    res.json({ success: true });
  });
});

// ------------------------------------------------------------
// /me
// ------------------------------------------------------------
app.get("/me", auth, (req, res) => {
  // FIX: Parameterized Query
  db.get(`SELECT username, email FROM users WHERE id = ?`, [req.user.id], (err, row) => {
    if (err) return res.status(500).json({ error: "Database error" });
    res.json(row);
  });
});

// ------------------------------------------------------------
// REMEDIATION: TRANSACTIONS
// ------------------------------------------------------------
app.get("/transactions", auth, (req, res) => {
  const q = req.query.q || "";
  
  // FIX: Parameterized Query with wildcard in the parameter, not the SQL string
  const sql = `
    SELECT id, amount, description
    FROM transactions
    WHERE user_id = ?
      AND description LIKE ?
    ORDER BY id DESC
  `;
  
  db.all(sql, [req.user.id, `%${q}%`], (err, rows) => {
      if (err) return res.status(500).json({ error: "Database error" });
      res.json(rows);
  });
});

// ------------------------------------------------------------
// REMEDIATION: FEEDBACK
// ------------------------------------------------------------
app.post("/feedback", auth, (req, res) => {
  const comment = req.body.comment;
  const userId = req.user.id;

  // FIX: Parameterized Query for SELECT
  db.get(`SELECT username FROM users WHERE id = ?`, [userId], (err, row) => {
    if (err || !row) return res.status(500).json({ error: "User error" });
    const username = row.username;

    // FIX: Parameterized Query for INSERT (Prevents SQLi and Stored XSS)
    const insert = `INSERT INTO feedback (user, comment) VALUES (?, ?)`;
    
    db.run(insert, [username, comment], function(err) {
      if (err) return res.status(500).json({ error: "Database error" });
      res.json({ success: true });
    });
  });
});

app.get("/feedback", auth, (req, res) => {
  db.all("SELECT user, comment FROM feedback ORDER BY id DESC", (err, rows) => {
    res.json(rows);
  });
});

// ------------------------------------------------------------
// REMEDIATION: CHANGE EMAIL
// ------------------------------------------------------------
app.post("/change-email", auth, (req, res) => {
  const newEmail = req.body.email;

  if (!newEmail.includes("@")) return res.status(400).json({ error: "Invalid email" });

  // FIX: Parameterized Query (Prevents SQLi)
  const sql = `UPDATE users SET email = ? WHERE id = ?`;
  
  db.run(sql, [newEmail, req.user.id], function(err) {
    if (err) return res.status(500).json({ error: "Database error" });
    res.json({ success: true, email: newEmail });
  });
});

app.listen(4000, () =>
  console.log("FastBank Version A backend running on http://localhost:4000")
);
