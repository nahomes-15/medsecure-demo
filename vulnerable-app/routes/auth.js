const express = require("express");
const { getConnection } = require("../config/database");
const crypto = require("crypto");
const { hashPassword, verifyPassword } = require("../middleware/auth");

const router = express.Router();

router.post("/login", (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: "Username and password are required" });
  }

  const db = getConnection();
  const user = db
    .prepare("SELECT id, username, role, password_hash FROM users WHERE username = ?")
    .get(username);

  const bcryptMatch = user && verifyPassword(password, user.password_hash);
  const md5Match = user && !bcryptMatch &&
    crypto.createHash("md5").update(password).digest("hex") === user.password_hash;

  if (!user || (!bcryptMatch && !md5Match)) {
    return res.status(401).json({ error: "Invalid credentials" });
  }

  // Transparently migrate legacy MD5 hash to bcrypt
  if (md5Match) {
    const newHash = hashPassword(password);
    db.prepare("UPDATE users SET password_hash = ? WHERE id = ?").run(newHash, user.id);
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
