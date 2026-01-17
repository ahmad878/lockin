  require('dotenv').config();

  const express = require("express");
  const http = require("http");
  const { Server } = require("socket.io");
  const Together = require("together-ai");
  const path = require("path");
  const jwt = require('jsonwebtoken');
  const SibApiV3Sdk = require('sib-api-v3-sdk');
  const bcrypt = require('bcrypt');
  const cookieParser = require('cookie-parser');
  const JWT_SECRET = process.env.JWT_SECRET;
  const apiKey = process.env.SENDINBLUE_API_KEY;

  SibApiV3Sdk.ApiClient.instance.authentications['api-key'].apiKey = apiKey;
  const COOKIE_NAME = 'auth_token';
  const cors = require("cors");


  // ===== MongoDB / Mongoose =====
  const mongoose = require("mongoose");

  // ===== Cloudinary & Multer Imports =====
  const cloudinary = require("cloudinary").v2;
  const multer = require("multer");

  // ===== MongoDB Connection =====
  const MONGO_URI = process.env.MONGO_URI;

  mongoose
    .connect(MONGO_URI)
    .then(() => {
      console.log("✅ MongoDB connected successfully");
    })
    .catch((err) => {
      console.error("❌ MongoDB connection error:", err);
    });
  const counterSchema = new mongoose.Schema({
    _id: { type: String, required: true },
    seq: { type: Number, default: 0 }
  });

  const Counter = mongoose.model('Counter', counterSchema);
  async function getNextSequence(name) {
    const counter = await Counter.findOneAndUpdate(
      { _id: name },
      { $inc: { seq: 1 } },
      { new: true, upsert: true }
    );
    return counter.seq;
  }

  function generateToken(user) {
    return jwt.sign(
      {
        id: user.id,
        fullname: user.fullname,
        email: user.email
      },
      JWT_SECRET,
      { expiresIn: '30d' }
    );
  }

  function verifyToken(token) {
    try {
      return jwt.verify(token, JWT_SECRET);
    } catch (err) {
      return null;
    }
  }

  function authenticateUser(req, res, next) {
    const token = req.cookies[COOKIE_NAME];

    if (!token) {
      return res.redirect('/signup');
    }

    const decoded = verifyToken(token);
    if (!decoded) {
      return res.status(401).json({
        success: false,
        message: 'Invalid or expired token'
      });
    }

    req.user = decoded;
    next();
  }

  const COOKIE_OPTIONS = {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: 30 * 24 * 60 * 60 * 1000,
    path: '/',
  };

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

  // ===== MongoDB Schema for Users =====
  const userSchema = new mongoose.Schema({
    fullName: {
      type: String,
      required: true,
      trim: true
    },
    email: {
      type: String,
      required: true,
      unique: true,
      trim: true,
      lowercase: true
    },
    password: {
      type: String,
      required: true
    },
    verified: {
      type: Boolean,
      default: false
    },
    createdAt: {
      type: Date,
      default: Date.now
    }
  });

  const User = mongoose.model("User", userSchema);

  // ===== Verification & Security Constants =====
  const verificationCodes = new Map();
  const VERIFICATION_TIMEOUT = 10 * 60 * 1000; // 10 minutes
  const bannedWords = ['admin', 'moderator', 'system', 'test123', 'fuck', 'shit', 'damn']; // Add more as needed

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
      origin: ["http://localhost:3000", "https://lockin-production.up.railway.app"],
      methods: ["GET", "POST"],
      credentials: true
    },
    transports: ["websocket", "polling"]
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
  app.use(cookieParser());

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

  // ===== Auth Check Route =====
  app.post("/check", (req, res) => {
    const token = req.cookies[COOKIE_NAME];
    console.log('checking auth with token:', token);
    if (!token) {
      return res.json({
        success: false,
        authenticated: false,
        message: 'No authentication token found'
      });
    }

    const decoded = verifyToken(token);
    if (!decoded) {
      return res.json({
        success: false,
        authenticated: false,
        message: 'Invalid or expired token'
      });
    }

    res.json({
      success: true,
      authenticated: true,
      user: decoded
    });
  });

  // ===== Root Route =====
  app.get("/", (req, res) => {
    const dashboardPath = path.join(__dirname, "public", "index.html");
   
    }
  );



  app.post('/signup', async function(req, res) {
    try {
      console.log('Received signup request:', req.body);
      const { fullName, email, password } = req.body;

      if (!fullName || !email || !password) {
        return res.status(400).json({
          success: false,
          message: 'All fields are required'
        });
      }

      const nameRegex = /^[A-Za-z\s]+$/;
      if (!nameRegex.test(fullName)) {
        return res.status(400).json({
          success: false,
          message: 'Name can only contain letters and spaces'
        });
      }

      const nameLower = fullName.toLowerCase();
      const hasProfanity = bannedWords.some(word =>
        nameLower.includes(word.toLowerCase())
      );

      if (hasProfanity) {
        return res.status(400).json({
          success: false,
          message: 'Username contains inappropriate language'
        });
      }

      const existingEmail = await User.findOne({ email: email });
      if (existingEmail) {
        return res.status(400).json({
          success: false,
          message: 'Email already registered'
        });
      }

      const existingFullname = await User.findOne({ fullName: fullName });
      if (existingFullname) {
        return res.status(400).json({
          success: false,
          message: 'Name already exists'
        });
      }

      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (!emailRegex.test(email)) {
        return res.status(400).json({
          success: false,
          message: 'Invalid email format'
        });
      }

      if (password.length < 8) {
        return res.status(400).json({
          success: false,
          message: 'Password must be at least 8 characters'
        });
      }

      if (!/[!@#$%^&*]/.test(password)) {
        return res.status(400).json({
          success: false,
          message: 'Password needs at least one special character!'
        });
      }

      const verificationCode = Math.floor(100000 + Math.random() * 900000);
      console.log('Generated verification code:', verificationCode);

      const apiInstance = new SibApiV3Sdk.TransactionalEmailsApi();
      const sendSmtpEmail = new SibApiV3Sdk.SendSmtpEmail();
      sendSmtpEmail.sender = { email: 'kindnestlehelp@gmail.com', name: 'KindNestle' };
      sendSmtpEmail.to = [{ email: email }];
      sendSmtpEmail.subject = 'KindNestle: Verify Your Email';
      sendSmtpEmail.htmlContent = `
        <html>
        <head>
          <style>
            body { font-family: Arial, sans-serif; background-color: #f7f7f7; margin: 0; padding: 0; }
            .container { max-width: 600px; margin: 20px auto; background-color: #ffffff; padding: 20px; }
            .header { background-color:rgb(252, 25, 25); color: white; text-align: center; padding: 10px; }
            .code { font-size: 32px; font-weight: bold; color:rgb(124, 21, 21); margin: 20px 0; text-align: center; }
            .footer { text-align: center; font-size: 12px; color: #888; margin-top: 20px; }
          </style>
        </head>
        <body>
          <div class="container">
            <div class="header">
              <h1>KindNestle</h1>
            </div>
            <p>Thank you for signing up. Use the code below to verify your email address:</p>
            <div class="code">${verificationCode}</div>
            <div class="footer">
              © 2024 KindNestle. All rights reserved.<br>
            </div>
          </div>
        </body>
        </html>
      `;

      try {
        const emailResponse = await apiInstance.sendTransacEmail(sendSmtpEmail);
        console.log('Email sent successfully:', emailResponse);

        verificationCodes.set(email, {
          code: verificationCode,
          timestamp: Date.now(),
          fullName: fullName,
          password: password
        });

        setTimeout(() => {
          verificationCodes.delete(email);
        }, VERIFICATION_TIMEOUT);

        return res.status(200).json({
          success: true,
          message: 'Signup successful. Please check your email for verification.'
        });
      } catch (emailError) {
        console.error('Email sending failed:', emailError);
        throw new Error('Failed to send verification email');
      }
    } catch (error) {
      console.error('Signup error:', error);
      return res.status(500).json({
        success: false,
        message: error.message || 'Server error during signup'
      });
    }
  });
  app.post('/verify', async function(req, res) {
    try {
      const { code, email } = req.body;
      console.log('Verification attempt:', { code, email });

      if (!code || !email) {
        return res.status(400).json({
          success: false,
          message: 'Verification code and email are required'
        });
      }

      const verificationData = verificationCodes.get(email);

      if (!verificationData) {
        return res.status(400).json({
          success: false,
          message: 'No verification code found for this email or code has expired'
        });
      }

      if (parseInt(code) === verificationData.code) {
        const hashedPassword = await bcrypt.hash(verificationData.password, 10);

        const newUser = new User({
          fullName: verificationData.fullName,
          email: email,
          password: hashedPassword,
          verified: true
        });

        await newUser.save();

        const user = {
          id: newUser._id,
          fullname: newUser.fullName,
          email: newUser.email
        };

        const token = generateToken(user);
        res.cookie(COOKIE_NAME, token, COOKIE_OPTIONS);

        verificationCodes.delete(email);
        return res.status(200).json({
          success: true,
          message: 'Email verified successfully',
          user: {
            fullname: user.fullname,
            email: user.email
          }
        });
      } else {
        return res.status(400).json({
          success: false,
          message: 'Invalid verification code'
        });
      }
    } catch (error) {
      console.error('Verification error:', error);
      return res.status(500).json({
        success: false,
        message: 'Server error during verification'
      });
    }
  });

  app.post('/login', async function(req, res) {
    try {
      const { email, password } = req.body;
      console.log('Login attempt:', email);

      if (!email || !password) {
        return res.status(400).json({
          success: false,
          message: 'Email and password are required'
        });
      }

      const existingUser = await User.findOne({ email: email });

      if (!existingUser) {
        return res.status(404).json({
          success: false,
          message: 'User does not exist'
        });
      }

      const passwordMatch = await bcrypt.compare(password, existingUser.password);

      if (!passwordMatch) {
        return res.status(401).json({
          success: false,
          message: 'Invalid password'
        });
      }

      const user = {
        id: existingUser._id,
        fullname: existingUser.fullName,
        email: existingUser.email
      };

      const token = generateToken(user);
      res.cookie(COOKIE_NAME, token, COOKIE_OPTIONS);

      return res.status(200).json({
        success: true,
        message: 'Login successful',
        user: {
          fullname: user.fullname,
          email: user.email
        }
      });

    } catch (error) {
      console.error('Login error:', error);
      return res.status(500).json({
        success: false,
        message: 'Server error during login'
      });
    }
  });



  app.get('/login', function(req, res) {
    const loginPath = path.join(__dirname, 'login.html');
    res.sendFile(loginPath);
  });

  // Send message notification by email
  app.post('/send-message-notification', async function(req, res) {
    try {
      const { toEmail, fromUserId, fromName } = req.body;
      console.log('Send message notification request:', { toEmail, fromUserId, fromName });

      if (!toEmail || !fromUserId) {
        return res.status(400).json({
          success: false,
          message: 'Email and fromUserId are required'
        });
      }

      // Validate email format
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      let correctedEmail = toEmail.trim().toLowerCase();
      
      // Auto-correct email if invalid
      if (!emailRegex.test(correctedEmail)) {
        // Remove spaces
        correctedEmail = correctedEmail.replace(/\s+/g, '');
        
        // If no @ symbol, add one before the last dot or at the end
        if (!correctedEmail.includes('@')) {
          const lastDot = correctedEmail.lastIndexOf('.');
          if (lastDot > 0) {
            correctedEmail = correctedEmail.substring(0, lastDot) + '@' + correctedEmail.substring(lastDot + 1);
          } else {
            correctedEmail = correctedEmail + '@email.com';
          }
        }
        
        // If @ exists but no domain after it, add default domain
        if (correctedEmail.includes('@')) {
          const atIndex = correctedEmail.indexOf('@');
          const afterAt = correctedEmail.substring(atIndex + 1);
          if (!afterAt || !afterAt.includes('.')) {
            correctedEmail = correctedEmail + (afterAt ? '.' : '') + 'com';
          }
        }
        
        // Validate again after correction
        if (!emailRegex.test(correctedEmail)) {
          return res.status(400).json({
            success: false,
            message: 'Invalid email format'
          });
        }
      }

      // Find user by email in database
      const targetUser = await User.findOne({ email: correctedEmail });

      if (!targetUser) {
        return res.status(404).json({
          success: false,
          message: 'User with this email does not exist'
        });
      }

      const targetUserId = targetUser._id.toString();

      // Check if user is online (has socket connection)
      const recipientSocketId = userSocketMap.get(targetUserId);

      if (recipientSocketId) {
        // Send notification via socket
        io.to(recipientSocketId).emit('message-notification', {
          id: Date.now(),
          fromUserId: fromUserId,
          fromName: fromName || 'Someone',
          message: 'You received a message',
          timestamp: new Date().toISOString()
        });

        console.log(`✅ Message notification sent to ${targetUserId} (${correctedEmail})`);
        
        return res.status(200).json({
          success: true,
          message: 'Notification sent successfully',
          recipientEmail: correctedEmail
        });
      } else {
        // User is not online
        return res.status(404).json({
          success: false,
          message: 'User is not currently online'
        });
      }

    } catch (error) {
      console.error('Send message notification error:', error);
      return res.status(500).json({
        success: false,
        message: 'Server error while sending notification'
      });
    }
  });

  app.post("/save-profile", async (req, res) => {
    console.log("====== SAVE PROFILE REQUEST ======");
    console.log("Body:", req.body);

    try {
      const { name, email } = req.body;

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
        email: email.trim().toLowerCase()
      });

      const savedProfile = await newProfile.save();

      console.log("✅ Profile saved successfully:", savedProfile._id);

      res.json({
        success: true,
        profile: {
          id: savedProfile._id,
          name: savedProfile.name,
          email: savedProfile.email,
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
        .select("name email createdAt")
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
  // SOCKET.IO CALL SIGNALING (WhatsApp Style)
  // ========================================

  // Map to store userId -> socketId for call routing
  const userSocketMap = new Map();

  io.on("connection", (socket) => {
    console.log("✅ Socket connected:", socket.id);

    // ===== User Registration =====
    socket.on("register-user", (userId) => {
      userSocketMap.set(userId, socket.id);
      console.log(`📱 User ${userId} registered with socket ${socket.id}`);
      console.log("📊 Active users:", Array.from(userSocketMap.keys()));
    });

    // ===== Incoming Call Handler =====
    socket.on("call-user", (callData) => {
      const { fromUserId, toUserId, callerName } = callData;
      const recipientSocketId = userSocketMap.get(toUserId);

      console.log(`📞 Call initiated: ${fromUserId} -> ${toUserId}`);
      console.log(`🔍 Recipient socket: ${recipientSocketId}`);

      if (recipientSocketId) {
        // Send incoming call ONLY to the recipient
        io.to(recipientSocketId).emit("incoming-call", {
          fromUserId: fromUserId,
          callerName: callerName,
          callId: `${fromUserId}-${Date.now()}`,
          timestamp: new Date().toISOString()
        });
        console.log(`✅ Incoming call notification sent to ${toUserId}`);
      } else {
        // User not online
        socket.emit("call-failed", {
          message: `User ${toUserId} is not online`,
          code: "USER_OFFLINE"
        });
        console.log(`❌ User ${toUserId} is offline`);
      }
    });

    // ===== Accept Call Handler =====
    socket.on("accept-call", (callData) => {
      const { fromUserId, acceptedByUserId } = callData;
      const callerSocketId = userSocketMap.get(fromUserId);

      console.log(`✅ Call accepted: ${acceptedByUserId} accepted call from ${fromUserId}`);

      if (callerSocketId) {
        // Notify caller that call was accepted
        io.to(callerSocketId).emit("call-accepted", {
          acceptedBy: acceptedByUserId,
          timestamp: new Date().toISOString()
        });
        console.log(`📢 Call accepted notification sent to ${fromUserId}`);
      }
    });

    // ===== Reject Call Handler =====
    socket.on("reject-call", (callData) => {
      const { fromUserId, rejectedByUserId } = callData;
      const callerSocketId = userSocketMap.get(fromUserId);

      console.log(`❌ Call rejected: ${rejectedByUserId} rejected call from ${fromUserId}`);

      if (callerSocketId) {
        // Notify caller that call was rejected
        io.to(callerSocketId).emit("call-rejected", {
          rejectedBy: rejectedByUserId,
          reason: callData.reason || "User declined",
          timestamp: new Date().toISOString()
        });
        console.log(`📢 Call rejection notification sent to ${fromUserId}`);
      }
    });

    // ===== End Call Handler =====
    socket.on("end-call", (callData) => {
      const { fromUserId, toUserId } = callData;
      const recipientSocketId = userSocketMap.get(toUserId);

      console.log(`🔴 Call ended: ${fromUserId} -> ${toUserId}`);

      if (recipientSocketId) {
        io.to(recipientSocketId).emit("call-ended", {
          endedBy: fromUserId,
          timestamp: new Date().toISOString()
        });
      }
    });

    // ===== Therapy Chat Handler =====
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

    // ===== Disconnect Handler =====
    socket.on("disconnect", () => {
      // Remove user from map
      for (const [userId, socketId] of userSocketMap.entries()) {
        if (socketId === socket.id) {
          userSocketMap.delete(userId);
          console.log(`❌ User ${userId} disconnected`);
          console.log("📊 Active users:", Array.from(userSocketMap.keys()));
          break;
        }
      }
    });
  });



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
  server.listen(3000, function(){
    console.log("Server is running on port 3000");
    console.log("Socket.IO is ready for connections");
  });
