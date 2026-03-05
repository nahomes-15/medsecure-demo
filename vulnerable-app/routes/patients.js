const express = require("express");
const { getConnection } = require("../config/database");
const { requireAuth } = require("../middleware/auth");

const router = express.Router();

router.get("/search", requireAuth, (req, res) => {
  const { name, mrn } = req.query;

  if (!name && !mrn) {
    return res.status(400).json({ error: "Search parameter required" });
  }

  const db = getConnection();

  let query = "SELECT id, mrn, first_name, last_name, dob FROM patients WHERE 1=1";
  const params = [];
  if (name) {
    query += " AND (first_name LIKE ? OR last_name LIKE ?)";
    params.push(`%${name}%`, `%${name}%`);
  }
  if (mrn) {
    query += " AND mrn = ?";
    params.push(mrn);
  }

  try {
    const patients = db.prepare(query).all(...params);
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

  let sql = "SELECT * FROM clinical_notes WHERE patient_id = ?";
  const params = [req.params.id];
  if (type) {
    sql += " AND type = ?";
    params.push(type);
  }
  sql += " ORDER BY created_at DESC";

  try {
    const records = db.prepare(sql).all(...params);
    res.json({ records });
  } catch (err) {
    res.status(500).json({ error: "Failed to retrieve records" });
  }
});

module.exports = router;
