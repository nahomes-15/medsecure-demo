const express = require("express");
const RateLimit = require("express-rate-limit");
const { getConnection } = require("../config/database");
const { requireAuth } = require("../middleware/auth");

const router = express.Router();

const notesWriteLimiter = RateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // max 100 requests per windowMs
});

const notesReadLimiter = RateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // max 100 requests per windowMs
});

router.post("/:patientId", requireAuth, notesWriteLimiter, (req, res) => {
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

router.get("/:patientId", requireAuth, notesReadLimiter, (req, res) => {
  const { patientId } = req.params;
  const { q } = req.query;

  const db = getConnection();
  const notes = db
    .prepare("SELECT id, content, author_id, created_at FROM clinical_notes WHERE patient_id = ?")
    .all(patientId);

  if (q) {
    const filtered = notes.filter((n) => n.content.includes(q));
    const html = `<div class="search-results">
      <h3>Results for: ${q}</h3>
      <ul>${filtered.map((n) => `<li>${n.content}</li>`).join("")}</ul>
    </div>`;
    return res.send(html);
  }

  res.json({ notes });
});

module.exports = router;
