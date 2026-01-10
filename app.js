const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const Together = require("together-ai");
const path = require("path");
const cors = require("cors");

// ===== MongoDB / Mongoose =====
const mongoose = require("mongoose");

// ===== Cloudinary & Multer Imports =====
const cloudinary = require("cloudinary").v2;
const multer = require("multer");

// ===== MongoDB Connection =====
const MONGO_URI =
  "mongodb+srv://Hxmoudiii:Hellomimi123@cluster0.yzozf.mongodb.net/todo?retryWrites=true&w=majority";

mongoose
  .connect(MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
  })
  .then(() => {
    console.log("✅ MongoDB connected successfully");
  })
  .catch((err) => {
    console.error("❌ MongoDB connection error:", err);
  });

// ===== MongoDB Schema for Profiles =====
const profileSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    trim: true
  },
  email: {
    type: String,
    required: true,
    trim: true,
    lowercase: true
  },
  phone: {
    type: String,
    trim: true
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

const Profile = mongoose.model("Profile", profileSchema);

// ===== Cloudinary Configuration =====
cloudinary.config({
  cloud_name: "dxxpkyitl",
  api_key: "126471723935395",
  api_secret: "IBlq5rjUvtdIxBn34N_yjY4dOB0"
});

// ===== Multer with memoryStorage =====
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 10 * 1024 * 1024
  },
  fileFilter: (req, file, cb) => {
    const allowedTypes = [
      "image/jpeg",
      "image/png",
      "image/webp",
      "image/gif",
      "video/mp4"
    ];
    if (allowedTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error("Invalid file type"));
    }
  }
});

// ===== Together AI Setup =====
const together = new Together({
  apiKey:
    "a1cab1d451defe94e8817b0d82bfdccf3bf647a4481ce27c1ab48588bb4c42a7"
});

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: "*" }
});

// ===== Middleware =====
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

// ===== Serve dashboard =====
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public/dashboard.html"));
});

// ===== NEW: Save Profile Route =====
app.post("/save-profile", async (req, res) => {
  console.log("====== SAVE PROFILE REQUEST ======");
  console.log("Body:", req.body);

  try {
    const { name, email, phone } = req.body;

    // Validation
    if (!name || !email) {
      return res.status(400).json({
        success: false,
        error: "Name and email are required"
      });
    }

    // Create new profile
    const newProfile = new Profile({
      name,
      email,
      phone: phone || ""
    });

    // Save to MongoDB
    await newProfile.save();

    console.log("✅ Profile saved:", newProfile);

    res.json({
      success: true,
      profile: newProfile,
      message: "Profile saved successfully"
    });
  } catch (err) {
    console.error("❌ Save profile error:", err);
    res.status(500).json({
      success: false,
      error: err.message
    });
  }
});

// ===== NEW: Get All Profiles Route =====
app.get("/profiles", async (req, res) => {
  try {
    const profiles = await Profile.find()
      .sort({ createdAt: -1 })
      .limit(10);

    res.json({
      success: true,
      profiles
    });
  } catch (err) {
    console.error("❌ Get profiles error:", err);
    res.status(500).json({
      success: false,
      error: err.message
    });
  }
});

// ===== Upload Image Route =====
app.post("/upload-image", upload.single("image"), async (req, res) => {
  console.log("====== UPLOAD REQUEST RECEIVED ======");

  try {
    if (!req.file) {
      return res.status(400).json({
        success: false,
        error: "No file uploaded"
      });
    }

    const uploadToCloudinary = () => {
      return new Promise((resolve, reject) => {
        const uploadStream = cloudinary.uploader.upload_stream(
          {
            folder: "therapy-app-uploads",
            resource_type: "auto",
            quality: "auto:good",
            transformation: [{ width: 1200, height: 1200, crop: "limit" }]
          },
          (error, result) => {
            if (error) reject(error);
            else resolve(result);
          }
        );

        uploadStream.end(req.file.buffer);
      });
    };

    const result = await uploadToCloudinary();

    res.json({
      success: true,
      url: result.secure_url,
      public_id: result.public_id
    });
  } catch (err) {
    console.error("❌ Upload error:", err);
    res.status(500).json({
      success: false,
      error: err.message
    });
  }
});

// ===== Socket.io Therapy Chat =====
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

      socket.emit(
        "therapy-response",
        response.choices[0].message.content
      );
    } catch (err) {
      console.error(err);
      socket.emit(
        "therapy-response",
        "I'm here with you. Something went wrong, but you're not alone."
      );
    }
  });

  socket.on("disconnect", () => {
    console.log("Socket disconnected:", socket.id);
  });
});

// ===== Start Server =====
const PORT = process.env.PORT || 3000;
app.listen(PORT, "0.0.0.0", () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`📱 Profile API ready at /save-profile and /profiles`);
});