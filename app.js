const express = require("express");
const app = express();

// Basic middleware
app.use(express.json());

// Simple GET to test server is alive
app.get("/", (req, res) => {
  res.json({ message: "Server is running!" });
});

// Simple POST to test it works
app.post("/test", (req, res) => {
  console.log("POST received:", req.body);
  res.json({ 
    success: true, 
    received: req.body,
    message: "POST works!"
  });
});

// Health check
app.get("/health", (req, res) => {
  res.json({ status: "ok" });
});

// Start server - MUST bind to 0.0.0.0 for Railway
const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on port ${PORT}`);
});