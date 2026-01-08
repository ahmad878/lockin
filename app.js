const express = require("express");
const http = require("http");
const rateLimit = require("express-rate-limit");
const { Server } = require("socket.io");
const Together = require("together-ai");
const path = require("path");
const cors = require("cors");

// ===== Cloudinary & Multer Imports =====
const cloudinary = require("cloudinary").v2;
const multer = require("multer");

// ===== Cloudinary Configuration =====
cloudinary.config({
  cloud_name: 'dxxpkyitl',
  api_key: '126471723935395',
  api_secret: 'IBlq5rjUvtdIxBn34N_yjY4dOB0'
});

// ===== Multer with memoryStorage =====
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowedTypes = ['image/jpeg', 'image/png', 'image/webp', 'image/gif', 'video/mp4'];
    if (allowedTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('Invalid file type'));
    }
  }
});

// ===== Together AI Setup =====
const together = new Together({
  apiKey: "a1cab1d451defe94e8817b0d82bfdccf3bf647a4481ce27c1ab48588bb4c42a7"
});

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: "*" }
});

// ===== Middleware (ORDER MATTERS!) =====
// 1. CORS first
app.use(cors({
  origin: true,
  methods: ["GET", "POST", "OPTIONS"],
  allowedHeaders: ["Content-Type"],
  credentials: false
}));

// 2. Body parsing
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// 3. Static files
app.use(express.static(path.join(__dirname, "public")));

// 4. Rate limiting
app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { error: "Too many requests. Slow down." }
}));

// ===== Health Check =====
app.get("/health", (req, res) => {
  res.status(200).json({ status: "ok", timestamp: new Date().toISOString() });
});

// ===== Serve dashboard.html at root =====
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public/dashboard.html"));
});

// ===== Upload Route =====
app.post("/upload-image", (req, res) => {
  console.log('POST REQUEST RECEIVED!');
  console.log('Body:', req.body);
  console.log('Headers:', req.headers);
  
  res.json({
    success: true,
    message: 'Got your request!',
    data: req.body
  });
});

// ===== Socket.io therapy chat =====
io.on("connection", (socket) => {
  console.log("Socket connected:", socket.id);

  socket.on("therapy-message", async (userMessage) => {
    try {
      const response = await together.chat.completions.create({
        model: "deepseek-ai/DeepSeek-V3",
        messages: [
          {
            role: "system",
            content: `You are a calm, kind therapy AI. Speak like a human therapist. Keep responses VERY short and simple. Be warm, empathetic, and supportive. Never judge.`
          },
          { role: "user", content: userMessage }
        ],
        temperature: 0.7
      });

      socket.emit("therapy-response", response.choices[0].message.content);
    } catch (err) {
      console.error(err);
      socket.emit("therapy-response", "I'm here with you. Something went wrong, but you're not alone.");
    }
  });

  socket.on("disconnect", () => {
    console.log("Socket disconnected:", socket.id);
  });
});

// ===== Start Server =====
const PORT = process.env.PORT || 3000;


app.listen(3000, '0.0.0.0', () => {
  console.log(`Server running on port 3000`);
});