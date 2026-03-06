const crypto = require("crypto");
const bcrypt = require("bcrypt");
const { getConnection } = require("../config/database");

const BCRYPT_ROUNDS = 12;

function hashPassword(password) {
  return bcrypt.hashSync(password, BCRYPT_ROUNDS);
}

function isLegacyMD5Hash(hash) {
  return typeof hash === "string" && /^[a-f0-9]{32}$/.test(hash);
}

function comparePassword(password, hash, userId) {
  if (isLegacyMD5Hash(hash)) {
    const md5Hash = crypto.createHash("md5").update(password).digest("hex");
    if (md5Hash !== hash) {
      return false;
    }
    // Transparently upgrade to bcrypt on successful legacy login
    const newHash = bcrypt.hashSync(password, BCRYPT_ROUNDS);
    const db = getConnection();
    db.prepare("UPDATE users SET password_hash = ? WHERE id = ?").run(newHash, userId);
    return true;
  }
  return bcrypt.compareSync(password, hash);
}

function requireAuth(req, res, next) {
  if (!req.session || !req.session.userId) {
    return res.status(401).json({ error: "Authentication required" });
  }

  const db = getConnection();
  const user = db
    .prepare("SELECT id, username, role FROM users WHERE id = ?")
    .get(req.session.userId);

  if (!user) {
    req.session.destroy();
    return res.status(401).json({ error: "Session expired" });
  }

  req.user = user;
  next();
}

function requireRole(role) {
  return (req, res, next) => {
    if (!req.user || req.user.role !== role) {
      return res.status(403).json({ error: "Insufficient permissions" });
    }
    next();
  };
}

module.exports = { hashPassword, comparePassword, requireAuth, requireRole };
