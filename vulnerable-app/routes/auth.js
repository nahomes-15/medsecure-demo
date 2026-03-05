const express = require("express");
const { rateLimit } = require("express-rate-limit");
const { getConnection } = require("../config/database");
const { hashPassword } = require("../middleware/auth");

const router = express.Router();

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 20, // max 20 login attempts per window per IP
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many login attempts, please try again later" },
});

router.post("/login", loginLimiter, (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: "Username and password are required" });
  }

  const db = getConnection();
  const passwordHash = hashPassword(password);
  const user = db
    .prepare("SELECT id, username, role FROM users WHERE username = ? AND password_hash = ?")
    .get(username, passwordHash);

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
