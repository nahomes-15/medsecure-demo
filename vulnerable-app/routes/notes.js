const express = require("express");
const { getConnection } = require("../config/database");
const { requireAuth } = require("../middleware/auth");

const router = express.Router();

router.post("/:patientId", requireAuth, (req, res) => {
  const { content } = req.body;
  const { patientId } = req.params;

  if (!content) {
    return res.status(400).json({ error: "Note content is required" });
  }

  const db = getConnection();
  const patient = db.prepare("SELECT id FROM patients WHERE id = ?").get(patientId);

  if (!patient) {
    return res.status(404).json({ error: "Patient not found" });
  }

  const result = db
    .prepare("INSERT INTO clinical_notes (patient_id, author_id, content) VALUES (?, ?, ?)")
    .run(patientId, req.user.id, content);

  res.status(201).json({ id: result.lastInsertRowid, message: "Note added" });
});

router.get("/:patientId", requireAuth, (req, res) => {
  const { patientId } = req.params;

  const db = getConnection();
  const notes = db
    .prepare("SELECT id, content, author_id, created_at FROM clinical_notes WHERE patient_id = ?")
    .all(patientId);

  res.json({ notes });
});

router.post("/:patientId/search", requireAuth, (req, res) => {
  const { patientId } = req.params;
  const { q } = req.body;

  if (!q) {
    return res.status(400).json({ error: "Search query is required" });
  }

  const db = getConnection();
  const notes = db
    .prepare("SELECT id, content, author_id, created_at FROM clinical_notes WHERE patient_id = ?")
    .all(patientId);

  const filtered = notes.filter((n) => n.content.includes(q));
  res.json({ results: filtered });
});

module.exports = router;
