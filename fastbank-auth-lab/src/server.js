const express = require("express");
const app = express();

// --- ZAP REMEDIATION START ---

// 1. Fix "Server Leaks Information via X-Powered-By"
app.disable('x-powered-by');

app.use((req, res, next) => {
  // 2. Fix "CSP: Failure to Define Directive with No Fallback"
  // ZAP specifically checks for 'frame-ancestors' and 'form-action'
  res.setHeader("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; form-action 'self'; frame-ancestors 'none';");
  
  // 3. Fix "Permissions Policy Header Not Set"
  res.setHeader("Permissions-Policy", "geolocation=(), camera=(), microphone=()");
  
  // 4. Fix "Storable and Cacheable Content" (Informational)
  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate");
  res.setHeader("Pragma", "no-cache");
  res.setHeader("Expires", "0");
  
  next();
});
// --- ZAP REMEDIATION END ---

app.use(express.json());

// Mock Data
const users = [
  { id: 1, name: "Alice", role: "customer", department: "north" },
  { id: 2, name: "Bob", role: "customer", department: "south" },
  { id: 3, name: "Charlie", role: "support", department: "north" },
];

const orders = [
  { id: 1, userId: 1, item: "Laptop", region: "north", total: 2000 },
  { id: 2, userId: 1, item: "Mouse", region: "north", total: 40 },
  { id: 3, userId: 2, item: "Monitor", region: "south", total: 300 },
  { id: 4, userId: 2, item: "Keyboard", region: "south", total: 60 },
];

function fakeAuth(req, res, next) {
  const idHeader = req.header("X-User-Id");
  const id = idHeader ? parseInt(idHeader, 10) : null;

  const user = users.find((u) => u.id === id);
  if (!user) {
    return res.status(401).json({ error: "Unauthenticated: set X-User-Id" });
  }

  req.user = user;
  next();
}

app.use(fakeAuth);

// IDOR Check (You likely already have this from the previous steps)
app.get("/orders/:id", (req, res) => {
  const orderId = parseInt(req.params.id, 10);

  const order = orders.find((o) => o.id === orderId);
  if (!order) {
    return res.status(404).json({ error: "Order not found" });
  }

  if (req.user.role !== 'support' && order.userId !== req.user.id) {
      return res.status(403).json({ error: "Access Denied: You do not own this order." });
  }

  return res.json(order);
});

app.get("/", (req, res) => {
  res.json({ message: "Access Control Tutorial API", currentUser: req.user });
});

const PORT = 3000; // Even if it says 3000 here, your package.json scripts might be setting it to 4000 via env vars
app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
