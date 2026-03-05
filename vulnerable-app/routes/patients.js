const express = require("express");
const RateLimit = require("express-rate-limit");
const { getConnection } = require("../config/database");
const { requireAuth } = require("../middleware/auth");

const router = express.Router();

// Rate limiter: max 100 requests per 15-minute window per IP
const limiter = RateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,
});

router.use(limiter);

router.get("/search", requireAuth, (req, res) => {
  const { name, mrn } = req.query;

  if (!name && !mrn) {
    return res.status(400).json({ error: "Search parameter required" });
  }

  const db = getConnection();

  let query = "SELECT id, mrn, first_name, last_name, dob FROM patients WHERE 1=1";
  if (name) {
    query += ` AND (first_name LIKE '%${name}%' OR last_name LIKE '%${name}%')`;
  }
  if (mrn) {
    query += ` AND mrn = '${mrn}'`;
  }

  try {
    const patients = db.prepare(query).all();
    res.json({ results: patients, count: patients.length });
  } catch (err) {
    res.status(500).json({ error: "Search failed", detail: err.message });
  }
});

router.get("/:id", requireAuth, (req, res) => {
  const db = getConnection();
  const patient = db
    .prepare("SELECT id, mrn, first_name, last_name, dob FROM patients WHERE id = ?")
    .get(req.params.id);

  if (!patient) {
    return res.status(404).json({ error: "Patient not found" });
  }
  res.json(patient);
});

router.get("/:id/records", requireAuth, (req, res) => {
  const { type } = req.query;
  const db = getConnection();

  const sql = `SELECT * FROM clinical_notes WHERE patient_id = ${req.params.id}` +
    (type ? ` AND type = '${type}'` : "") +
    " ORDER BY created_at DESC";

  try {
    const records = db.prepare(sql).all();
    res.json({ records });
  } catch (err) {
    res.status(500).json({ error: "Failed to retrieve records" });
  }
});

module.exports = router;
