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
  const row = db
    .prepare("SELECT id, username, role, password_hash FROM users WHERE username = ?")
    .get(username);

  let user = null;
  if (row) {
    const isBcrypt = row.password_hash && row.password_hash.startsWith("$2");
    if (isBcrypt) {
      // Modern bcrypt hash
      if (verifyPassword(password, row.password_hash)) {
        user = { id: row.id, username: row.username, role: row.role };
      }
    } else {
      // Legacy MD5 hash — verify then transparently upgrade to bcrypt
      const md5Hash = crypto.createHash("md5").update(password).digest("hex");
      if (md5Hash === row.password_hash) {
        const newHash = hashPassword(password);
        db.prepare("UPDATE users SET password_hash = ? WHERE id = ?").run(newHash, row.id);
        user = { id: row.id, username: row.username, role: row.role };
      }
    }
  }

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
