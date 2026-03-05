const bcrypt = require("bcryptjs");
const { getConnection } = require("../config/database");

const BCRYPT_ROUNDS = 12;

function hashPassword(password) {
  return bcrypt.hashSync(password, BCRYPT_ROUNDS);
}

function verifyPassword(password, hash) {
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

module.exports = { hashPassword, verifyPassword, requireAuth, requireRole };
