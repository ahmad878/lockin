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
  .connect(MONGO_URI)
  .then(() => {
    console.log("✅ MongoDB connected successfully");
  })
  .catch((err) => {
    console.error("❌ MongoDB connection error:", err);
  });

// ===== MongoDB Schema for Todos =====
const todoSchema = new mongoose.Schema({
  title: {
    type: String,
    required: true,
    trim: true
  },
  description: {
    type: String,
    trim: true,
    default: ""
  },
  completed: {
    type: Boolean,
    default: false
  },
  priority: {
    type: String,
    enum: ['low', 'medium', 'high'],
    default: 'medium'
  },
  category: {
    type: String,
    trim: true,
    default: ""
  },
  dueDate: {
    type: Date,
    default: null
  },
  createdAt: {
    type: Date,
    default: Date.now
  },
  notificationSent: {
    type: Boolean,
    default: false
  }
});

const Todo = mongoose.model("Todo", todoSchema);

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
    trim: true,
    default: ""
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
  apiKey: "a1cab1d451defe94e8817b0d82bfdccf3bf647a4481ce27c1ab48588bb4c42a7"
});

const app = express();
const server = http.createServer(app);

// ===== Socket.IO Setup =====
const io = new Server(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  }
});

// ===== CORS Configuration =====
app.use(cors({
  origin: "*",
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
  credentials: true
}));

// ===== Middleware =====
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve static files
if (require("fs").existsSync(path.join(__dirname, "public"))) {
  app.use(express.static(path.join(__dirname, "public")));
}

// ===== Request Logger =====
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
  next();
});

// ===== Health Check Route =====
app.get("/health", (req, res) => {
  res.json({
    success: true,
    message: "Server is running",
    mongodb: mongoose.connection.readyState === 1 ? "connected" : "disconnected",
    timestamp: new Date().toISOString()
  });
});

// ===== Root Route =====
app.get("/", (req, res) => {
  const dashboardPath = path.join(__dirname, "public", "dashboard.html");
  if (require("fs").existsSync(dashboardPath)) {
    res.sendFile(dashboardPath);
  } else {
    res.json({
      success: true,
      message: "TaskFlow API is running",
      endpoints: {
        health: "GET /health",
        todos: "GET /todos",
        createTodo: "POST /todos",
        updateTodo: "PUT /todos/:id",
        deleteTodo: "DELETE /todos/:id",
        saveProfile: "POST /save-profile",
        getProfiles: "GET /profiles",
        uploadImage: "POST /upload-image"
      }
    });
  }
});

// ========================================
// TODO ROUTES
// ========================================

// Get all todos
app.get("/todos", async (req, res) => {
  console.log("====== GET TODOS REQUEST ======");
  
  try {
    if (mongoose.connection.readyState !== 1) {
      return res.status(503).json({
        success: false,
        error: "Database connection unavailable",
        todos: []
      });
    }

    const todos = await Todo.find()
      .sort({ createdAt: -1 })
      .lean();

    console.log(`✅ Retrieved ${todos.length} todos`);

    res.json({
      success: true,
      todos: todos,
      count: todos.length
    });
  } catch (err) {
    console.error("❌ Get todos error:", err);
    res.status(500).json({
      success: false,
      error: err.message || "Internal server error",
      todos: []
    });
  }
});

// Create a new todo
app.post("/todos", async (req, res) => {
  console.log("====== CREATE TODO REQUEST ======");
  console.log("Body:", req.body);

  try {
    const { title, description, priority, category, dueDate } = req.body;

    if (!title) {
      return res.status(400).json({
        success: false,
        error: "Title is required"
      });
    }

    if (mongoose.connection.readyState !== 1) {
      return res.status(503).json({
        success: false,
        error: "Database connection unavailable"
      });
    }

    const newTodo = new Todo({
      title: title.trim(),
      description: description ? description.trim() : "",
      priority: priority || 'medium',
      category: category || "",
      dueDate: dueDate || null,
      completed: false
    });

    const savedTodo = await newTodo.save();

    console.log("✅ Todo created:", savedTodo._id);

    res.json({
      success: true,
      todo: savedTodo,
      message: "Todo created successfully"
    });
  } catch (err) {
    console.error("❌ Create todo error:", err);
    res.status(500).json({
      success: false,
      error: err.message || "Internal server error"
    });
  }
});

// Update a todo
app.put("/todos/:id", async (req, res) => {
  console.log("====== UPDATE TODO REQUEST ======");
  console.log("ID:", req.params.id);
  console.log("Body:", req.body);

  try {
    const { id } = req.params;
    const { title, description, completed, priority, category, dueDate } = req.body;

    if (mongoose.connection.readyState !== 1) {
      return res.status(503).json({
        success: false,
        error: "Database connection unavailable"
      });
    }

    const updateData = {};
    if (title !== undefined) updateData.title = title.trim();
    if (description !== undefined) updateData.description = description.trim();
    if (completed !== undefined) updateData.completed = completed;
    if (priority !== undefined) updateData.priority = priority;
    if (category !== undefined) updateData.category = category;
    if (dueDate !== undefined) updateData.dueDate = dueDate;

    const updatedTodo = await Todo.findByIdAndUpdate(
      id,
      updateData,
      { new: true, runValidators: true }
    );

    if (!updatedTodo) {
      return res.status(404).json({
        success: false,
        error: "Todo not found"
      });
    }

    console.log("✅ Todo updated:", updatedTodo._id);

    res.json({
      success: true,
      todo: updatedTodo,
      message: "Todo updated successfully"
    });
  } catch (err) {
    console.error("❌ Update todo error:", err);
    res.status(500).json({
      success: false,
      error: err.message || "Internal server error"
    });
  }
});

// Delete a todo
app.delete("/todos/:id", async (req, res) => {
  console.log("====== DELETE TODO REQUEST ======");
  console.log("ID:", req.params.id);

  try {
    const { id } = req.params;

    if (mongoose.connection.readyState !== 1) {
      return res.status(503).json({
        success: false,
        error: "Database connection unavailable"
      });
    }

    const deletedTodo = await Todo.findByIdAndDelete(id);

    if (!deletedTodo) {
      return res.status(404).json({
        success: false,
        error: "Todo not found"
      });
    }

    console.log("✅ Todo deleted:", deletedTodo._id);

    res.json({
      success: true,
      message: "Todo deleted successfully"
    });
  } catch (err) {
    console.error("❌ Delete todo error:", err);
    res.status(500).json({
      success: false,
      error: err.message || "Internal server error"
    });
  }
});

// ========================================
// PROFILE ROUTES
// ========================================

// Save Profile
app.post("/save-profile", async (req, res) => {
  console.log("====== SAVE PROFILE REQUEST ======");
  console.log("Body:", req.body);

  try {
    const { name, email, phone } = req.body;

    if (!name || !email) {
      console.log("❌ Validation failed: missing name or email");
      return res.status(400).json({
        success: false,
        error: "Name and email are required"
      });
    }

    if (mongoose.connection.readyState !== 1) {
      console.log("❌ MongoDB not connected");
      return res.status(503).json({
        success: false,
        error: "Database connection unavailable"
      });
    }

    const newProfile = new Profile({
      name: name.trim(),
      email: email.trim().toLowerCase(),
      phone: phone ? phone.trim() : ""
    });

    const savedProfile = await newProfile.save();

    console.log("✅ Profile saved successfully:", savedProfile._id);

    res.json({
      success: true,
      profile: {
        id: savedProfile._id,
        name: savedProfile.name,
        email: savedProfile.email,
        phone: savedProfile.phone,
        createdAt: savedProfile.createdAt
      },
      message: "Profile saved successfully"
    });
  } catch (err) {
    console.error("❌ Save profile error:", err);
    
    if (err.code === 11000) {
      return res.status(400).json({
        success: false,
        error: "Email already exists"
      });
    }

    res.status(500).json({
      success: false,
      error: err.message || "Internal server error"
    });
  }
});

// Get All Profiles
app.get("/profiles", async (req, res) => {
  console.log("====== GET PROFILES REQUEST ======");
  
  try {
    if (mongoose.connection.readyState !== 1) {
      console.log("❌ MongoDB not connected");
      return res.status(503).json({
        success: false,
        error: "Database connection unavailable",
        profiles: []
      });
    }

    const profiles = await Profile.find()
      .sort({ createdAt: -1 })
      .limit(20)
      .select("name email phone createdAt")
      .lean();

    console.log(`✅ Retrieved ${profiles.length} profiles`);

    res.json({
      success: true,
      profiles: profiles,
      count: profiles.length
    });
  } catch (err) {
    console.error("❌ Get profiles error:", err);
    res.status(500).json({
      success: false,
      error: err.message || "Internal server error",
      profiles: []
    });
  }
});

// ========================================
// IMAGE UPLOAD ROUTE
// ========================================

app.post("/upload-image", upload.single("image"), async (req, res) => {
  console.log("====== UPLOAD IMAGE REQUEST ======");

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

    console.log("✅ Image uploaded to Cloudinary");

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

// ========================================
// SOCKET.IO THERAPY CHAT
// ========================================

io.on("connection", (socket) => {
  console.log("✅ Socket connected:", socket.id);

  socket.on("therapy-message", async (userMessage) => {
    try {
      console.log("Therapy message received:", userMessage);
      
      const response = await together.chat.completions.create({
        model: "deepseek-ai/DeepSeek-V3",
        messages: [
          {
            role: "system",
            content: "You are a calm, kind therapy AI. Speak like a human therapist. Keep responses VERY short and simple. Be warm, empathetic, and supportive. Never judge."
          },
          {
            role: "user",
            content: userMessage
          }
        ],
        temperature: 0.7,
        max_tokens: 200
      });

      socket.emit("therapy-response", response.choices[0].message.content);
    } catch (err) {
      console.error("❌ Therapy message error:", err);
      socket.emit(
        "therapy-response",
        "I'm here with you. Something went wrong, but you're not alone."
      );
    }
  });

  socket.on("disconnect", () => {
    console.log("❌ Socket disconnected:", socket.id);
  });
});

// ========================================
// NOTIFICATION CHECKER (runs every minute)
// ========================================

setInterval(async () => {
  try {
    const now = new Date();
    const oneHourFromNow = new Date(now.getTime() + 60 * 60 * 1000);

    const dueSoonTodos = await Todo.find({
      completed: false,
      dueDate: { $lte: oneHourFromNow, $gte: now },
      notificationSent: false
    });

    dueSoonTodos.forEach(async (todo) => {
      console.log(`📢 Notification: "${todo.title}" is due soon!`);
      
      // Mark as notified
      await Todo.findByIdAndUpdate(todo._id, { notificationSent: true });
      
      // You can add email/SMS notification logic here
      // For now, just log it
    });
  } catch (err) {
    console.error("❌ Notification checker error:", err);
  }
}, 60000); // Check every minute

// ===== 404 Handler =====
app.use((req, res) => {
  res.status(404).json({
    success: false,
    error: "Endpoint not found",
    path: req.url
  });
});

// ===== Error Handler =====
app.use((err, req, res, next) => {
  console.error("❌ Global error handler:", err);
  res.status(500).json({
    success: false,
    error: err.message || "Internal server error"
  });
});

// ===== Start Server =====
app.listen(3000, function(){
  console.log("Server is running on port 3000");
});