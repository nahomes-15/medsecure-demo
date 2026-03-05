const express = require("express");
const session = require("express-session");
const cookieParser = require("cookie-parser");
const morgan = require("morgan");
const { initializeSchema } = require("./config/database");

const authRoutes = require("./routes/auth");
const patientRoutes = require("./routes/patients");
const reportRoutes = require("./routes/reports");
const noteRoutes = require("./routes/notes");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(morgan("combined"));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(
  session({
    secret: "medsecure-session-key-2024",
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 8 * 60 * 60 * 1000 },
  })
);

app.use("/api/auth", authRoutes);
app.use("/api/patients", patientRoutes);
app.use("/api/reports", reportRoutes);
app.use("/api/notes", noteRoutes);

app.get("/api/health", (req, res) => {
  res.json({ status: "ok", version: "2.4.1", timestamp: new Date().toISOString() });
});

app.use((err, req, res, _next) => {
  console.error(`[${new Date().toISOString()}] Unhandled error:`, err.message);
  res.status(500).json({ error: "Internal server error" });
});

initializeSchema();

app.listen(PORT, () => {
  console.log(`MedSecure Patient Portal API listening on port ${PORT}`);
});

module.exports = app;
