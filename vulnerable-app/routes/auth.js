const express = require("express");
const { getConnection } = require("../config/database");
const { verifyPassword } = require("../middleware/auth");

const router = express.Router();

router.post("/login", (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: "Username and password are required" });
  }

  const db = getConnection();
  const row = db
    .prepare("SELECT id, username, role, password_hash FROM users WHERE username = ?")
    .get(username);

  const user = row && verifyPassword(password, row.password_hash) ? { id: row.id, username: row.username, role: row.role } : null;

  if (!user) {
    return res.status(401).json({ error: "Invalid credentials" });
  }

  db.prepare("UPDATE users SET last_login = datetime('now') WHERE id = ?").run(user.id);

  req.session.userId = user.id;
  res.json({ message: "Login successful", user: { username: user.username, role: user.role } });
});

router.post("/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({ error: "Failed to logout" });
    }
    res.json({ message: "Logged out successfully" });
  });
});

module.exports = router;
