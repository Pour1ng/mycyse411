const express = require("express");
const app = express();

// FIX 1: Disable the "X-Powered-By" header to hide the tech stack
app.disable('x-powered-by');

// FIX 2: Strict Security Headers for ZAP
app.use((req, res, next) => {
  // ZAP requires 'form-action' and 'frame-ancestors' to be explicitly defined
  res.setHeader("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; form-action 'self'; frame-ancestors 'none';");
  res.setHeader("Permissions-Policy", "geolocation=(), camera=(), microphone=()");
  // Cache control to fix "Storable and Cacheable Content" info alert
  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate");
  res.setHeader("Pragma", "no-cache");
  res.setHeader("Expires", "0");
  next();
});

app.use(express.json());

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

app.get("/orders/:id", (req, res) => {
  const orderId = parseInt(req.params.id, 10);

  const order = orders.find((o) => o.id === orderId);
  if (!order) {
    return res.status(404).json({ error: "Order not found" });
  }

  // IDOR FIX
  if (req.user.role !== 'support' && order.userId !== req.user.id) {
      return res.status(403).json({ error: "Access Denied: You do not own this order." });
  }

  return res.json(order);
});

app.get("/", (req, res) => {
  res.json({ message: "Access Control Tutorial API", currentUser: req.user });
});

const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
