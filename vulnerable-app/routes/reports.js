const express = require("express");
const fs = require("fs");
const path = require("path");
const { exec } = require("child_process");
const { requireAuth, requireRole } = require("../middleware/auth");

const router = express.Router();

const REPORTS_DIR = path.join(__dirname, "..", "data", "reports");

router.get("/download", requireAuth, (req, res) => {
  const { filename } = req.query;

  if (!filename) {
    return res.status(400).json({ error: "Filename is required" });
  }

  const filePath = path.resolve(REPORTS_DIR, filename);

  if (!filePath.startsWith(REPORTS_DIR + path.sep) && filePath !== REPORTS_DIR) {
    return res.status(403).json({ error: "Access denied" });
  }

  if (!fs.existsSync(filePath)) {
    return res.status(404).json({ error: "Report not found" });
  }

  res.download(filePath);
});

router.post("/generate", requireAuth, requireRole("admin"), (req, res) => {
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

router.get("/list", requireAuth, (req, res) => {
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
