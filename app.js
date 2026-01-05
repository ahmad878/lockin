const express = require("express");
const http = require("http");
const rateLimit = require("express-rate-limit");
const { Server } = require("socket.io");
const Together = require("together-ai");
const path = require("path");

const together = new Together({
  apiKey: "a1cab1d451defe94e8817b0d82bfdccf3bf647a4481ce27c1ab48588bb4c42a7"
});

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: "*" } // allow frontend to connect
});

// ===== Middleware =====
app.use(express.json());
app.use(express.static(path.join(__dirname, "public"))); // serve static files

// Rate limiting
app.use(rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,
  message: { error: "Too many requests. Slow down." }
}));

// ===== Serve dashboard.html at root =====
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public/dashboard.html"));
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
            content: `
You are a calm, kind therapy AI.
Speak like a human therapist.
Keep responses VERY short and simple.
Be warm, empathetic, and supportive.
Never judge.
`
          },
          {
            role: "user",
            content: userMessage
          }
        ],
        temperature: 0.7
      });

      socket.emit("therapy-response", response.choices[0].message.content);

    } catch (err) {
      console.error(err);
      socket.emit(
        "therapy-response",
        "I’m here with you. Something went wrong, but you’re not alone."
      );
    }
  });

  socket.on("disconnect", () => {
    console.log("Socket disconnected:", socket.id);
  });
});

// ===== Start Server =====
const PORT = 3000;
server.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
