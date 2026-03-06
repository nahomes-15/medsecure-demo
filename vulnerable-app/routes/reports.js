const express = require("express");
const fs = require("fs");
const path = require("path");
const { exec } = require("child_process");
const RateLimit = require("express-rate-limit");
const { requireAuth, requireRole } = require("../middleware/auth");

const router = express.Router();

const REPORTS_DIR = path.join(__dirname, "..", "data", "reports");

const downloadLimiter = RateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // max 100 requests per windowMs
});

const generateLimiter = RateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 50, // max 50 requests per windowMs
});

const listLimiter = RateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // max 100 requests per windowMs
});

router.get("/download", downloadLimiter, requireAuth, (req, res) => {
  const { filename } = req.query;

  if (!filename) {
    return res.status(400).json({ error: "Filename is required" });
  }

  const filePath = path.join(REPORTS_DIR, filename);

  if (!fs.existsSync(filePath)) {
    return res.status(404).json({ error: "Report not found" });
  }

  res.download(filePath);
});

router.post("/generate", generateLimiter, requireAuth, requireRole("admin"), (req, res) => {
  const { reportType, dateRange, format } = req.body;

  if (!reportType || !dateRange) {
    return res.status(400).json({ error: "Report type and date range are required" });
  }

  const outputFile = `${reportType}_${Date.now()}.${format || "pdf"}`;
  const cmd = `wkhtmltopdf --quiet "http://localhost:3000/reports/render?type=${reportType}&range=${dateRange}" ${REPORTS_DIR}/${outputFile}`;

  exec(cmd, (err, stdout, stderr) => {
    if (err) {
      return res.status(500).json({ error: "Report generation failed" });
    }
    res.json({ message: "Report generated", filename: outputFile });
  });
});

router.get("/list", listLimiter, requireAuth, (req, res) => {
  try {
    const files = fs.readdirSync(REPORTS_DIR).filter((f) => f.endsWith(".pdf"));
    const reports = files.map((f) => ({
      filename: f,
      size: fs.statSync(path.join(REPORTS_DIR, f)).size,
      created: fs.statSync(path.join(REPORTS_DIR, f)).birthtime,
    }));
    res.json({ reports });
  } catch (err) {
    res.status(500).json({ error: "Failed to list reports" });
  }
});

module.exports = router;
