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
  const admin = require('firebase-admin');
if (process.env.FIREBASE_SERVICE_ACCOUNT) {
    const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
    admin.initializeApp({
        credential: admin.credential.cert(serviceAccount)
    });
    console.log('✅ Firebase Admin initialized');
} else {
    console.warn('⚠️ FIREBASE_SERVICE_ACCOUNT not set, skipping Firebase initialization');
}

  SibApiV3Sdk.ApiClient.instance.authentications['api-key'].apiKey = apiKey;
  const COOKIE_NAME = 'auth_token';
  const cors = require("cors");
  const rateLimit = require('express-rate-limit');


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
    secure: true, // Always secure for mobile/localhost
    sameSite: 'none', // Allow cross-origin cookies
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
    fcmToken: {
      type: String,
      default: null
    },
    contacts: [{
      contactUserId: {
        type: String,
        required: true
      },
      contactEmail: {
        type: String,
        required: true
      },
      customName: {
        type: String,
        required: true,
        trim: true
      },
      addedAt: {
        type: Date,
        default: Date.now
      }
    }],
    calls: [{
      callerId: {
        type: String,
        required: true
      },
      callerEmail: {
        type: String,
        default: ''
      },
      callerName: {
        type: String,
        default: 'Unknown'
      },
      receiverId: {
        type: String,
        required: true
      },
      receiverEmail: {
        type: String,
        default: ''
      },
      receiverName: {
        type: String,
        default: 'Unknown'
      },
      type: {
        type: String,
        enum: ['outgoing', 'incoming', 'missed'],
        required: true
      },
      status: {
        type: String,
        enum: ['completed', 'missed', 'rejected'],
        default: 'completed'
      },
      duration: {
        type: Number,
        default: 0
      },
      timestamp: {
        type: Date,
        default: Date.now
      }
    }],
    createdAt: {
      type: Date,
      default: Date.now
    }
  });

  const User = mongoose.model("User", userSchema);

  // ===== MongoDB Schema for Chats =====
  const chatSchema = new mongoose.Schema({
    person1: {
      userId: {
        type: String,
        required: true
      },
      email: {
        type: String,
        required: true
      },
      name: {
        type: String,
        required: true
      }
    },
    person2: {
      userId: {
        type: String,
        required: true
      },
      email: {
        type: String,
        required: true
      },
      name: {
        type: String,
        required: true
      }
    },
    messages: [{
      senderId: {
        type: String,
        required: true
      },
      receiverId: {
        type: String,
        required: true
      },
      messageType: {
        type: String,
        enum: ['text', 'voice', 'image'],
        default: 'text'
      },
      message: {
        type: String,
        required: function() {
          return this.messageType === 'text';
        }
      },
      voiceUrl: {
        type: String,
        required: function() {
          return this.messageType === 'voice';
        }
      },
      voiceDuration: {
        type: Number,
        default: 0
      },
      imageUrl: {
        type: String,
        required: function() {
          return this.messageType === 'image';
        }
      },
      timestamp: {
        type: Date,
        default: Date.now
      },
      read: {
        type: Boolean,
        default: false
      },
      delivered: {
        type: Boolean,
        default: false
      },
      deleted: {
        type: Boolean,
        default: false
      }
    }],
    lastMessage: {
      message: {
        type: String,
        default: ''
      },
      timestamp: {
        type: Date,
        default: Date.now
      },
      senderId: {
        type: String,
        default: ''
      }
    },
    createdAt: {
      type: Date,
      default: Date.now
    },
    updatedAt: {
      type: Date,
      default: Date.now
    }
  });

  // Index for efficient querying
  chatSchema.index({ 'person1.userId': 1, 'person2.userId': 1 });
  chatSchema.index({ updatedAt: -1 });

  const Chat = mongoose.model("Chat", chatSchema);

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
        "video/mp4",
        // Audio types for voice messages
        "audio/webm",
        "audio/ogg",
        "audio/mpeg",
        "audio/mp4",
        "audio/wav",
        "audio/x-m4a"
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
      origin: ["http://localhost:3000", "https://localhost", "capacitor://localhost", "https://lockin-production.up.railway.app"],
      methods: ["GET", "POST"],
      credentials: true
    },
    transports: ["websocket", "polling"]
  });

  // ===== CORS Configuration =====
  app.use(cors({
    origin: ["http://localhost:3000", "https://localhost", "capacitor://localhost", "https://lockin-production.up.railway.app"],
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

  // ===== Rate Limiting Configuration =====
  
  // Strict rate limiter for email sending (signup/verification)
  const emailRateLimiter = rateLimit({
    windowMs: 60 * 60 * 1000, // 60 minutes (1 hour)
    max: 10, // Max 10 emails per hour per IP
    message: { 
      success: false, 
      message: 'Too many email requests. Please try again later.' 
    },
    standardHeaders: true,
    legacyHeaders: false,
  });

  // Login rate limiter - prevents brute force attacks
  const loginRateLimiter = rateLimit({
    windowMs: 30 * 60 * 1000, // 30 minutes
    max: 15, // Max 15 login attempts per 30 minutes per IP
    message: { 
      success: false, 
      message: 'Too many login attempts. Please try again in 30 minutes.' 
    },
    standardHeaders: true,
    legacyHeaders: false,
  });

  // Verification code rate limiter
  const verifyRateLimiter = rateLimit({
    windowMs: 30 * 60 * 1000, // 30 minutes
    max: 20, // Max 20 verification attempts per 30 minutes per IP
    message: { 
      success: false, 
      message: 'Too many verification attempts. Please try again later.' 
    },
    standardHeaders: true,
    legacyHeaders: false,
  });

  // General API rate limiter
  const generalRateLimiter = rateLimit({
    windowMs: 1 * 60 * 1000, // 1 minute
    max: 200, // Max 200 requests per minute per IP
    message: { 
      success: false, 
      message: 'Too many requests. Please slow down.' 
    },
    standardHeaders: true,
    legacyHeaders: false,
  });

  // Apply general rate limiter to all routes
  app.use(generalRateLimiter);

  console.log('✅ Rate limiting enabled');

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

  // Register FCM token - saves to MongoDB for persistence
app.post('/register-fcm-token', async function(req, res) {
    try {
        const { token, userId } = req.body;
        
        if (!token || !userId) {
            return res.status(400).json({
                success: false,
                message: 'Token and userId required'
            });
        }
        
        // Save to MongoDB for persistence (survives server restarts)
        const user = await User.findOneAndUpdate(
            { _id: userId },
            { fcmToken: token },
            { new: true }
        );
        
        if (!user) {
            console.warn(`⚠️ User not found for ID: ${userId}`);
            // Still keep in memory as fallback
            userFCMTokens.set(userId, token);
        } else {
            console.log(`✅ FCM token saved to MongoDB for user ${userId} (${user.email})`);
        }
        
        // Also keep in memory for quick access
        userFCMTokens.set(userId, token);
        
        return res.status(200).json({
            success: true,
            message: 'FCM token registered successfully'
        });
    } catch (error) {
        console.error('FCM token registration error:', error);
        return res.status(500).json({
            success: false,
            message: 'Server error'
        });
    }
});

  // ===== Root Route (serves index.html - the phone UI) =====
  app.get("/", (req, res) => {
    const indexPath = path.join(__dirname, "public", "index.html");
    if (require("fs").existsSync(indexPath)) {
      res.sendFile(indexPath);
    } else {
      res.json({
        success: true,
        message: "WishTripper API is running",
        endpoints: {
          health: "GET /health",
          saveProfile: "POST /save-profile",
          getProfiles: "GET /profiles",
          uploadImage: "POST /upload-image"
        }
      });
    }
  });
  
  // ===== Signup Route (serves signup.html) =====
  app.get("/signup", (req, res) => {
    const signupPath = path.join(__dirname, "public", "signup.html");
    res.sendFile(signupPath);
  });



  app.post('/signup', emailRateLimiter, async function(req, res) {
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
  app.post('/verify', verifyRateLimiter, async function(req, res) {
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

  app.post('/login', loginRateLimiter, async function(req, res) {
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

  app.post('/logout', async function(req, res) {
  try {
    const token = req.cookies[COOKIE_NAME];
    
    // If there's a token, try to decode it to get user info
    if (token) {
      const decoded = verifyToken(token);
      if (decoded && decoded.id) {
        // Remove user from Socket.IO map
        userSocketMap.delete(decoded.id);
        // Remove FCM token from memory
        userFCMTokens.delete(decoded.id);
        // Clear FCM token from MongoDB too
        await User.findByIdAndUpdate(decoded.id, { fcmToken: null });
        console.log(`🔓 User ${decoded.id} logged out, removed from active connections`);
      }
    }
    
    // Clear the authentication cookie
    res.clearCookie(COOKIE_NAME, {
      httpOnly: true,
      secure: true,
      sameSite: 'none',
      path: '/'
    });
    
    console.log('✅ Logout successful, cookie cleared');
    
    return res.status(200).json({
      success: true,
      message: 'Logged out successfully'
    });
    
  } catch (error) {
    console.error('Logout error:', error);
    
    // Even if there's an error, clear the cookie
    res.clearCookie(COOKIE_NAME, {
      httpOnly: true,
      secure: true,
      sameSite: 'none',
      path: '/'
    });
    
    return res.status(200).json({
      success: true,
      message: 'Logged out successfully'
    });
  }
});


  app.get('/login', function(req, res) {
    const loginPath = path.join(__dirname, 'public', 'login.html');
    res.sendFile(loginPath);
  });

  // ===== CONTACTS MANAGEMENT =====
  
  // Get all contacts for current user
  app.get('/contacts', async function(req, res) {
    try {
      const token = req.cookies[COOKIE_NAME];
      if (!token) {
        return res.status(401).json({
          success: false,
          message: 'Not authenticated'
        });
      }

      const decoded = verifyToken(token);
      if (!decoded) {
        return res.status(401).json({
          success: false,
          message: 'Invalid token'
        });
      }

      const user = await User.findById(decoded.id);
      if (!user) {
        return res.status(404).json({
          success: false,
          message: 'User not found'
        });
      }

      return res.status(200).json({
        success: true,
        contacts: user.contacts || []
      });

    } catch (error) {
      console.error('Get contacts error:', error);
      return res.status(500).json({
        success: false,
        message: 'Server error'
      });
    }
  });

  // Add a new contact
  app.post('/contacts/add', async function(req, res) {
    try {
      const token = req.cookies[COOKIE_NAME];
      if (!token) {
        return res.status(401).json({
          success: false,
          message: 'Not authenticated'
        });
      }

      const decoded = verifyToken(token);
      if (!decoded) {
        return res.status(401).json({
          success: false,
          message: 'Invalid token'
        });
      }

      const { contactEmail, customName } = req.body;

      if (!contactEmail || !customName) {
        return res.status(400).json({
          success: false,
          message: 'Contact email and custom name are required'
        });
      }

      const cleanEmail = contactEmail.trim().toLowerCase();
      const cleanName = customName.trim();

      // Can't add yourself
      if (cleanEmail === decoded.email) {
        return res.status(400).json({
          success: false,
          message: 'Cannot add yourself as a contact'
        });
      }

      // Check if contact user exists in database
      const contactUser = await User.findOne({ email: cleanEmail });
      if (!contactUser) {
        return res.status(404).json({
          success: false,
          message: 'This user has not signed up for the app yet'
        });
      }

      // Check if already in contacts
      const user = await User.findById(decoded.id);
      const existingContact = user.contacts.find(c => c.contactEmail === cleanEmail);
      
      if (existingContact) {
        return res.status(400).json({
          success: false,
          message: 'Contact already exists'
        });
      }

      // Add contact to current user's contacts
      const newContact = {
        contactUserId: contactUser._id.toString(),
        contactEmail: cleanEmail,
        customName: cleanName,
        addedAt: new Date()
      };

      user.contacts.push(newContact);
      await user.save();

      console.log(`✅ Contact added: ${cleanName} (${cleanEmail}) for user ${decoded.id}`);

      return res.status(200).json({
        success: true,
        message: 'Contact added successfully',
        contact: newContact
      });

    } catch (error) {
      console.error('Add contact error:', error);
      return res.status(500).json({
        success: false,
        message: 'Server error'
      });
    }
  });

  // Delete a contact (mutual deletion - also removes you from their contacts)
  app.delete('/contacts/:contactEmail', async function(req, res) {
    try {
      const token = req.cookies[COOKIE_NAME];
      if (!token) {
        return res.status(401).json({
          success: false,
          message: 'Not authenticated'
        });
      }

      const decoded = verifyToken(token);
      if (!decoded) {
        return res.status(401).json({
          success: false,
          message: 'Invalid token'
        });
      }

      const contactEmail = req.params.contactEmail.trim().toLowerCase();

      const user = await User.findById(decoded.id);
      if (!user) {
        return res.status(404).json({
          success: false,
          message: 'User not found'
        });
      }

      const initialLength = user.contacts.length;
      user.contacts = user.contacts.filter(c => c.contactEmail !== contactEmail);

      if (user.contacts.length === initialLength) {
        return res.status(404).json({
          success: false,
          message: 'Contact not found'
        });
      }

      await user.save();

      // Also remove current user from the other person's contacts (mutual deletion)
      const otherUser = await User.findOne({ email: contactEmail });
      if (otherUser) {
        const currentUserEmail = user.email.toLowerCase();
        otherUser.contacts = otherUser.contacts.filter(c => c.contactEmail !== currentUserEmail);
        await otherUser.save();
        console.log(`✅ Mutual deletion: Also removed ${currentUserEmail} from ${contactEmail}'s contacts`);
      }

      console.log(`✅ Contact deleted: ${contactEmail} for user ${decoded.id}`);

      return res.status(200).json({
        success: true,
        message: 'Contact deleted successfully'
      });

    } catch (error) {
      console.error('Delete contact error:', error);
      return res.status(500).json({
        success: false,
        message: 'Server error'
      });
    }
  });

  // Update contact name
  app.put('/contacts/:contactEmail', async function(req, res) {
    try {
      const token = req.cookies[COOKIE_NAME];
      if (!token) {
        return res.status(401).json({
          success: false,
          message: 'Not authenticated'
        });
      }

      const decoded = verifyToken(token);
      if (!decoded) {
        return res.status(401).json({
          success: false,
          message: 'Invalid token'
        });
      }

      const contactEmail = req.params.contactEmail.trim().toLowerCase();
      const { customName } = req.body;

      if (!customName) {
        return res.status(400).json({
          success: false,
          message: 'Custom name is required'
        });
      }

      const user = await User.findById(decoded.id);
      if (!user) {
        return res.status(404).json({
          success: false,
          message: 'User not found'
        });
      }

      const contact = user.contacts.find(c => c.contactEmail === contactEmail);
      if (!contact) {
        return res.status(404).json({
          success: false,
          message: 'Contact not found'
        });
      }

      contact.customName = customName.trim();
      await user.save();

      console.log(`✅ Contact updated: ${contactEmail} renamed to ${customName} for user ${decoded.id}`);

      return res.status(200).json({
        success: true,
        message: 'Contact updated successfully',
        contact: contact
      });

    } catch (error) {
      console.error('Update contact error:', error);
      return res.status(500).json({
        success: false,
        message: 'Server error'
      });
    }
  });

  // ===== CHAT MANAGEMENT =====
  
  // Get chat messages with a specific contact
  app.get('/chat/:contactEmail', async function(req, res) {
    try {
      const token = req.cookies[COOKIE_NAME];
      if (!token) {
        return res.status(401).json({
          success: false,
          message: 'Not authenticated'
        });
      }

      const decoded = verifyToken(token);
      if (!decoded) {
        return res.status(401).json({
          success: false,
          message: 'Invalid token'
        });
      }

      const contactEmail = req.params.contactEmail.trim().toLowerCase();
      
      // Find the contact user
      const contactUser = await User.findOne({ email: contactEmail });
      if (!contactUser) {
        return res.status(404).json({
          success: false,
          message: 'Contact not found'
        });
      }

      // Find chat between current user and contact (either direction)
      const chat = await Chat.findOne({
        $or: [
          { 'person1.userId': decoded.id, 'person2.userId': contactUser._id.toString() },
          { 'person1.userId': contactUser._id.toString(), 'person2.userId': decoded.id }
        ]
      });

      if (!chat) {
        return res.status(200).json({
          success: true,
          chat: null,
          message: 'No chat history'
        });
      }

      return res.status(200).json({
        success: true,
        chat: chat
      });

    } catch (error) {
      console.error('Get chat error:', error);
      return res.status(500).json({
        success: false,
        message: 'Server error'
      });
    }
  });

  // Get all chats for current user (including from non-contacts)
  app.get('/chats', async function(req, res) {
    try {
      const token = req.cookies[COOKIE_NAME];
      if (!token) {
        return res.status(401).json({
          success: false,
          message: 'Not authenticated'
        });
      }

      const decoded = verifyToken(token);
      if (!decoded) {
        return res.status(401).json({
          success: false,
          message: 'Invalid token'
        });
      }

      // Find all chats where user is person1 or person2
      const chats = await Chat.find({
        $or: [
          { 'person1.userId': decoded.id },
          { 'person2.userId': decoded.id }
        ]
      }).sort({ updatedAt: -1 });

      // Transform chats to include the other person's info
      const transformedChats = chats.map(chat => {
        const isUserPerson1 = chat.person1.userId === decoded.id;
        const otherPerson = isUserPerson1 ? chat.person2 : chat.person1;
        
        return {
          chatId: chat._id,
          otherUserId: otherPerson.userId,
          otherEmail: (otherPerson.email || '').toLowerCase(), // Normalize to lowercase
          otherName: otherPerson.name,
          lastMessage: chat.lastMessage,
          updatedAt: chat.updatedAt,
          messageCount: chat.messages.length
        };
      });

      return res.status(200).json({
        success: true,
        chats: transformedChats
      });

    } catch (error) {
      console.error('Get all chats error:', error);
      return res.status(500).json({
        success: false,
        message: 'Server error'
      });
    }
  });

  // Delete a specific message from a chat
  app.delete('/chat/:contactEmail/message/:messageIndex', async function(req, res) {
    try {
      const token = req.cookies[COOKIE_NAME];
      if (!token) {
        return res.status(401).json({
          success: false,
          message: 'Not authenticated'
        });
      }

      const decoded = verifyToken(token);
      if (!decoded) {
        return res.status(401).json({
          success: false,
          message: 'Invalid token'
        });
      }

      const contactEmail = req.params.contactEmail.trim().toLowerCase();
      const messageIndex = parseInt(req.params.messageIndex);

      if (isNaN(messageIndex) || messageIndex < 0) {
        return res.status(400).json({
          success: false,
          message: 'Invalid message index'
        });
      }

      // Find the contact user
      const contactUser = await User.findOne({ email: contactEmail });
      if (!contactUser) {
        return res.status(404).json({
          success: false,
          message: 'Contact not found'
        });
      }

      // Find chat between current user and contact
      const chat = await Chat.findOne({
        $or: [
          { 'person1.userId': decoded.id, 'person2.userId': contactUser._id.toString() },
          { 'person1.userId': contactUser._id.toString(), 'person2.userId': decoded.id }
        ]
      });

      if (!chat) {
        return res.status(404).json({
          success: false,
          message: 'Chat not found'
        });
      }

      // Check if message index is valid
      if (messageIndex >= chat.messages.length) {
        return res.status(404).json({
          success: false,
          message: 'Message not found'
        });
      }

      // Check if user is the sender of the message (only allow deleting own messages)
      const message = chat.messages[messageIndex];
      if (message.senderId !== decoded.id) {
        return res.status(403).json({
          success: false,
          message: 'You can only delete your own messages'
        });
      }

      // Mark the message as deleted (don't remove it, so other person sees it was deleted)
      chat.messages[messageIndex].deleted = true;
      chat.messages[messageIndex].message = 'This message was deleted';

      // Update lastMessage if this was the last message
      if (messageIndex === chat.messages.length - 1) {
        chat.lastMessage = {
          message: 'This message was deleted',
          timestamp: chat.messages[messageIndex].timestamp,
          senderId: chat.messages[messageIndex].senderId
        };
      }

      chat.updatedAt = new Date();
      await chat.save();

      // Notify the other person via socket that a message was deleted
      const recipientSocketId = userSocketMap.get(contactUser._id.toString());
      if (recipientSocketId) {
        io.to(recipientSocketId).emit('message-deleted', {
          fromUserId: decoded.id,
          fromEmail: decoded.email,
          messageIndex: messageIndex,
          timestamp: new Date().toISOString()
        });
      }

      return res.status(200).json({
        success: true,
        message: 'Message deleted successfully'
      });

    } catch (error) {
      console.error('Delete message error:', error);
      return res.status(500).json({
        success: false,
        message: 'Server error'
      });
    }
  });

  // ===== CALL HISTORY MANAGEMENT =====
  
  // Get call history for current user
  app.get('/calls', async function(req, res) {
    try {
      const token = req.cookies[COOKIE_NAME];
      if (!token) {
        return res.status(401).json({
          success: false,
          message: 'Not authenticated'
        });
      }

      const decoded = verifyToken(token);
      if (!decoded) {
        return res.status(401).json({
          success: false,
          message: 'Invalid token'
        });
      }

      const user = await User.findById(decoded.id);
      if (!user) {
        return res.status(404).json({
          success: false,
          message: 'User not found'
        });
      }

      // Sort calls by timestamp descending (most recent first)
      const sortedCalls = (user.calls || []).sort((a, b) => 
        new Date(b.timestamp) - new Date(a.timestamp)
      );

      return res.status(200).json({
        success: true,
        calls: sortedCalls
      });

    } catch (error) {
      console.error('Get call history error:', error);
      return res.status(500).json({
        success: false,
        message: 'Server error'
      });
    }
  });
  app.post('/calls/save', async function(req, res) {
    try {
      const token = req.cookies[COOKIE_NAME];
      if (!token) {
        return res.status(401).json({
          success: false,
          message: 'Not authenticated'
        });
      }

      const decoded = verifyToken(token);
      if (!decoded) {
        return res.status(401).json({
          success: false,
          message: 'Invalid token'
        });
      }

      const { 
        callerId, callerEmail, callerName,
        receiverId, receiverEmail, receiverName,
        type, status, duration 
      } = req.body;

      if (!callerId || !receiverId) {
        return res.status(400).json({
          success: false,
          message: 'Caller and receiver IDs are required'
        });
      }

      // Validate required email fields to prevent Mongoose validation errors
      if (!callerEmail || !receiverEmail) {
        return res.status(400).json({
          success: false,
          message: 'Caller and receiver emails are required'
        });
      }

      const user = await User.findById(decoded.id);
      if (!user) {
        return res.status(404).json({
          success: false,
          message: 'User not found'
        });
      }

      const callRecord = {
        callerId,
        callerEmail: callerEmail || '',
        callerName: callerName || 'Unknown',
        receiverId,
        receiverEmail: receiverEmail || '',
        receiverName: receiverName || 'Unknown',
        type: type || 'outgoing',
        status: status || 'completed',
        duration: duration || 0,
        timestamp: new Date()
      };

      user.calls.push(callRecord);
      
      // Keep only last 100 calls to prevent unbounded growth
      if (user.calls.length > 100) {
        user.calls = user.calls.slice(-100);
      }
      
      await user.save();

      console.log(`📞 Call saved for user ${decoded.id}: ${type} call with ${type === 'outgoing' ? receiverEmail : callerEmail}`);

      return res.status(200).json({
        success: true,
        message: 'Call saved to history',
        call: callRecord
      });

    } catch (error) {
      console.error('Save call error:', error);
      return res.status(500).json({
        success: false,
        message: 'Server error'
      });
    }
  });

 app.post('/send-message-notification', emailRateLimiter, async function(req, res) {
  try {
    const { toEmail, fromUserId, fromName } = req.body;
    console.log('Send message notification request:', { toEmail, fromUserId, fromName });

    if (!toEmail || !fromUserId) {
      return res.status(400).json({
        success: false,
        message: 'Email and fromUserId are required'
      });
    }

    // Clean email
    const correctedEmail = toEmail.trim().toLowerCase();

    // Check if the caller has this person in their contacts
    const caller = await User.findById(fromUserId);
    if (!caller) {
      return res.status(404).json({
        success: false,
        message: 'Caller not found'
      });
    }

    const hasContact = caller.contacts.some(c => c.contactEmail === correctedEmail);
    if (!hasContact) {
      return res.status(403).json({
        success: false,
        message: 'You must add this person as a contact before calling'
      });
    }

    const targetUser = await User.findOne({ email: correctedEmail });

    if (!targetUser) {
      return res.status(404).json({
        success: false,
        message: 'User with this email does not exist'
      });
    }

    const targetUserId = targetUser._id.toString();
    const recipientSocketId = userSocketMap.get(targetUserId);

    // Check if caller is in the receiver's contacts to get their custom name
    const callerInReceiverContacts = targetUser.contacts.find(c => c.contactUserId === fromUserId || c.contactEmail === caller.email);
    const displayName = callerInReceiverContacts ? callerInReceiverContacts.customName : (fromName || 'Someone');

    // Try Socket.IO first (if user is online)
    if (recipientSocketId) {
      io.to(recipientSocketId).emit('incoming-call', {
        fromUserId: fromUserId,
        callerName: displayName,
        callId: `${fromUserId}-${Date.now()}`,
        timestamp: new Date().toISOString()
      });
      
      console.log(`✅ Socket notification sent to ${targetUserId}`);
    }
    
    // ALWAYS send FCM notification (works even if app is closed)
    // Try memory first, then MongoDB
    let fcmToken = userFCMTokens.get(targetUserId);
    
    if (!fcmToken) {
      // Fetch from MongoDB (persisted tokens)
      console.log(`🔍 Fetching FCM token from MongoDB for user ${targetUserId}...`);
      const userWithToken = await User.findById(targetUserId);
      if (userWithToken && userWithToken.fcmToken) {
        fcmToken = userWithToken.fcmToken;
        // Cache in memory for next time
        userFCMTokens.set(targetUserId, fcmToken);
        console.log(`✅ Found FCM token in MongoDB for user ${targetUserId}`);
      }
    }
    
    if (fcmToken) {
      // DATA-ONLY message - our CallFirebaseMessagingService handles it and opens the call screen
      const message = {
        data: {
          fromUserId: fromUserId,
          callerName: displayName,
          callerEmail: caller ? caller.email : '',
          callId: `${fromUserId}-${Date.now()}`,
          type: 'incoming-call',
          timestamp: new Date().toISOString()
        },
        token: fcmToken,
        android: {
          priority: 'high'
        }
      };
      
      try {
        const response = await admin.messaging().send(message);
        console.log('✅ FCM notification sent successfully:', response);
      } catch (fcmError) {
        console.error('❌ FCM send error:', fcmError);
        console.error('FCM error details:', JSON.stringify(fcmError, null, 2));
        
        // If token is invalid, remove it from both memory and MongoDB
        if (fcmError.code === 'messaging/invalid-registration-token' || 
            fcmError.code === 'messaging/registration-token-not-registered') {
          userFCMTokens.delete(targetUserId);
          await User.findByIdAndUpdate(targetUserId, { fcmToken: null });
          console.log(`🗑️ Removed invalid FCM token for user ${targetUserId}`);
        }
      }
    } else {
      console.log('⚠️ No FCM token found for user:', targetUserId, '- they may not have opened the app yet');
    }
    
    return res.status(200).json({
      success: true,
      message: 'Notification sent successfully',
      recipientEmail: correctedEmail,
      socketSent: !!recipientSocketId,
      fcmSent: !!fcmToken
    });

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
  // VOICE MESSAGE UPLOAD ROUTE
  // ========================================

  app.post("/upload-voice", upload.single("voice"), async (req, res) => {
    console.log("====== UPLOAD VOICE MESSAGE REQUEST ======");

    try {
      if (!req.file) {
        return res.status(400).json({
          success: false,
          error: "No voice file uploaded"
        });
      }

      const uploadToCloudinary = () => {
        return new Promise((resolve, reject) => {
          const uploadStream = cloudinary.uploader.upload_stream(
            {
              folder: "chat-voice-messages",
              resource_type: "video", // Cloudinary uses 'video' for audio files
              format: "mp3"
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

      console.log("✅ Voice message uploaded to Cloudinary");

      res.json({
        success: true,
        url: result.secure_url,
        public_id: result.public_id,
        duration: result.duration || 0
      });
    } catch (err) {
      console.error("❌ Voice upload error:", err);
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
  const userFCMTokens = new Map();
  // Map to track pending message notifications: recipientId -> Set of senderIds who have pending notifications
  const pendingMessageNotifications = new Map();
  
  io.on("connection", (socket) => {
    console.log("✅ Socket connected:", socket.id);

    // ===== User Registration =====
    socket.on("register-user", (userId) => {
      userSocketMap.set(userId, socket.id);
      // Clear pending message notifications when user opens app
      pendingMessageNotifications.delete(userId);
      console.log(`📱 User ${userId} registered with socket ${socket.id}`);
      console.log("📊 Active users:", Array.from(userSocketMap.keys()));
    });

    // ===== Incoming Call Handler =====
    socket.on("call-user", async (callData) => {
      const { fromUserId, toUserId, callerName } = callData;
      const recipientSocketId = userSocketMap.get(toUserId);

      console.log(`📞 Call initiated: ${fromUserId} -> ${toUserId}`);
      console.log(`🔍 Recipient socket: ${recipientSocketId}`);

      if (recipientSocketId) {
        // Look up caller in recipient's contacts to get custom name
        let displayName = callerName;
        try {
          const recipient = await User.findById(toUserId);
          const caller = await User.findById(fromUserId);
          if (recipient && caller) {
            const callerInContacts = recipient.contacts.find(c => c.contactUserId === fromUserId || c.contactEmail === caller.email);
            if (callerInContacts) {
              displayName = callerInContacts.customName;
            }
          }
        } catch (err) {
          console.error('Error looking up contact name:', err);
        }

        // Send incoming call ONLY to the recipient
        io.to(recipientSocketId).emit("incoming-call", {
          fromUserId: fromUserId,
          fromName: displayName,
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
      const { fromUserId, acceptedByUserId, acceptedByName } = callData;
      const callerSocketId = userSocketMap.get(fromUserId);

      console.log(`✅ Call accepted: ${acceptedByUserId} accepted call from ${fromUserId}`);

      if (callerSocketId) {
        // Notify caller that call was accepted
        io.to(callerSocketId).emit("call-accepted", {
          acceptedByUserId: acceptedByUserId,
          acceptedByName: acceptedByName,
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

    // ===== WebRTC Signaling Handlers =====
    socket.on("webrtc-offer", (data) => {
      const { toUserId, offer, fromUserId } = data;
      const recipientSocketId = userSocketMap.get(toUserId);
      
      console.log(`📡 WebRTC offer: ${fromUserId} -> ${toUserId}`);
      
      if (recipientSocketId) {
        io.to(recipientSocketId).emit("webrtc-offer", {
          offer,
          fromUserId
        });
      }
    });

    socket.on("webrtc-answer", (data) => {
      const { toUserId, answer, fromUserId } = data;
      const recipientSocketId = userSocketMap.get(toUserId);
      
      console.log(`📡 WebRTC answer: ${fromUserId} -> ${toUserId}`);
      
      if (recipientSocketId) {
        io.to(recipientSocketId).emit("webrtc-answer", {
          answer,
          fromUserId
        });
      }
    });

    socket.on("webrtc-ice-candidate", (data) => {
      const { toUserId, candidate, fromUserId } = data;
      const recipientSocketId = userSocketMap.get(toUserId);
      
      console.log(`🧊 ICE candidate: ${fromUserId} -> ${toUserId}`);
      
      if (recipientSocketId) {
        io.to(recipientSocketId).emit("webrtc-ice-candidate", {
          candidate,
          fromUserId
        });
      }
    });

    // ===== Chat Message Handler =====
    socket.on("chat", async (data) => {
      try {
        console.log('💬 Chat message received:', data);
        
        const { fromUserId, fromEmail, fromName, toUserId, toEmail, toName, message, messageType, voiceUrl, voiceDuration, imageUrl, timestamp } = data;
        
        if (!fromUserId || !toUserId) {
          console.error('Invalid chat data: missing user IDs');
          return;
        }

        // Validate based on message type
        if (messageType === 'voice') {
          if (!voiceUrl) {
            console.error('Invalid voice message: missing voiceUrl');
            return;
          }
        } else if (messageType === 'image') {
          if (!imageUrl) {
            console.error('Invalid image message: missing imageUrl');
            return;
          }
        } else {
          if (!message) {
            console.error('Invalid text message: missing message');
            return;
          }
        }
        
        // Check if chat already exists between these two users
        // Chat can be in either direction: person1->person2 or person2->person1
        let existingChat = await Chat.findOne({
          $or: [
            { 'person1.userId': fromUserId, 'person2.userId': toUserId },
            { 'person1.userId': toUserId, 'person2.userId': fromUserId }
          ]
        });
        
        const newMessage = {
          senderId: fromUserId,
          receiverId: toUserId,
          messageType: messageType || 'text',
          timestamp: timestamp || new Date(),
          read: false,
          delivered: false
        };

        // Add message content based on type
        if (messageType === 'voice') {
          newMessage.voiceUrl = voiceUrl;
          newMessage.voiceDuration = voiceDuration || 0;
        } else if (messageType === 'image') {
          newMessage.imageUrl = imageUrl;
        } else {
          newMessage.message = message;
        }

        // Prepare last message preview
        let lastMessageText = message;
        if (messageType === 'voice') {
          lastMessageText = '🎤 Voice message';
        } else if (messageType === 'image') {
          lastMessageText = '📷 Photo';
        }
        
        if (existingChat) {
          // Add message to existing chat
          existingChat.messages.push(newMessage);
          existingChat.lastMessage = {
            message: lastMessageText,
            timestamp: newMessage.timestamp,
            senderId: fromUserId
          };
          existingChat.updatedAt = new Date();
          console.log('✅ Message added to existing chat');
        } else {
          // Create new chat - normalize emails to lowercase
          const newChat = new Chat({
            person1: {
              userId: fromUserId,
              email: (fromEmail || '').toLowerCase(),
              name: fromName
            },
            person2: {
              userId: toUserId,
              email: (toEmail || '').toLowerCase(),
              name: toName
            },
            messages: [newMessage],
            lastMessage: {
              message: lastMessageText,
              timestamp: newMessage.timestamp,
              senderId: fromUserId
            }
          });
          await newChat.save();
          console.log('✅ New chat created');
        }
        
        // Send message to recipient if they're online
        const recipientSocketId = userSocketMap.get(toUserId);
        if (recipientSocketId) {
          // Mark message as delivered since recipient is online
          newMessage.delivered = true;
          
          const emitData = {
            fromUserId: fromUserId,
            fromName: fromName,
            timestamp: newMessage.timestamp,
            messageType: messageType || 'text'
          };

          // Add appropriate content based on type
          if (messageType === 'voice') {
            emitData.voiceUrl = voiceUrl;
            emitData.voiceDuration = voiceDuration || 0;
          } else if (messageType === 'image') {
            emitData.imageUrl = imageUrl;
          } else {
            emitData.message = message;
          }

          io.to(recipientSocketId).emit('new-message', emitData);
          console.log('📨 Message sent to recipient socket');
        } else {
          // Recipient is OFFLINE - message remains undelivered
          console.log('📱 Recipient offline, message not delivered yet');
          
          // Send FCM notification if not already notified
          // Check if we already sent a notification from this sender
          let pendingFromSenders = pendingMessageNotifications.get(toUserId);
          if (!pendingFromSenders) {
            pendingFromSenders = new Set();
            pendingMessageNotifications.set(toUserId, pendingFromSenders);
          }
          
          // Only send notification if we haven't already notified about messages from this sender
          if (!pendingFromSenders.has(fromUserId)) {
            pendingFromSenders.add(fromUserId);
            
            // Get FCM token for recipient
            let fcmToken = userFCMTokens.get(toUserId);
            if (!fcmToken) {
              const recipientUser = await User.findById(toUserId);
              if (recipientUser && recipientUser.fcmToken) {
                fcmToken = recipientUser.fcmToken;
                userFCMTokens.set(toUserId, fcmToken);
              }
            }
            
            if (fcmToken) {
              // Get display name from recipient's contacts
              let displayName = fromName;
              try {
                const recipientUser = await User.findById(toUserId);
                if (recipientUser) {
                  const senderInContacts = recipientUser.contacts.find(c => c.contactUserId === fromUserId);
                  if (senderInContacts) {
                    displayName = senderInContacts.customName;
                  }
                }
              } catch (err) {
                console.error('Error looking up contact name for message:', err);
              }
              
              const fcmMessage = {
                notification: {
                  title: `New message from ${displayName}`,
                  body: messageType === 'voice' ? '🎤 Voice message' : (message.length > 100 ? message.substring(0, 100) + '...' : message)
                },
                data: {
                  type: 'new-message',
                  fromUserId: fromUserId,
                  fromName: displayName,
                  timestamp: new Date().toISOString()
                },
                token: fcmToken,
                android: {
                  priority: 'high',
                  notification: {
                    channelId: 'messages',
                    sound: 'default'
                  }
                }
              };
              
              try {
                await admin.messaging().send(fcmMessage);
                console.log(`📩 Message notification sent to ${toUserId} from ${fromUserId}`);
              } catch (fcmError) {
                console.error('❌ FCM message notification error:', fcmError);
                if (fcmError.code === 'messaging/invalid-registration-token' || 
                    fcmError.code === 'messaging/registration-token-not-registered') {
                  userFCMTokens.delete(toUserId);
                  await User.findByIdAndUpdate(toUserId, { fcmToken: null });
                }
              }
            }
          } else {
            console.log(`⏭️ Skipping notification - ${toUserId} already notified about messages from ${fromUserId}`);
          }
        }
        
        // Save the chat after setting delivered status
        if (existingChat) {
          await existingChat.save();
        }
        
      } catch (error) {
        console.error('❌ Chat message error:', error);
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

    // ===== Typing Indicator Handlers =====
    socket.on("typing", (data) => {
      const { fromUserId, toUserId } = data;
      const recipientSocketId = userSocketMap.get(toUserId);
      
      if (recipientSocketId) {
        io.to(recipientSocketId).emit("user-typing", {
          fromUserId: fromUserId
        });
      }
    });

    socket.on("stop-typing", (data) => {
      const { fromUserId, toUserId } = data;
      const recipientSocketId = userSocketMap.get(toUserId);
      
      if (recipientSocketId) {
        io.to(recipientSocketId).emit("user-stop-typing", {
          fromUserId: fromUserId
        });
      }
    });

    // ===== Mark Messages as Read Handler =====
    socket.on("mark-messages-read", async (data) => {
      try {
        const { fromUserId, contactUserId } = data;
        console.log('👁️ Marking messages as read:', { fromUserId, contactUserId });
        
        // Find the chat between these users
        const chat = await Chat.findOne({
          $or: [
            { 'person1.userId': fromUserId, 'person2.userId': contactUserId },
            { 'person1.userId': contactUserId, 'person2.userId': fromUserId }
          ]
        });
        
        if (chat) {
          // Update all unread messages from the contact to the current user as read
          const updateResult = await Chat.updateOne(
            { _id: chat._id, 'messages.senderId': contactUserId, 'messages.read': false },
            { $set: { 'messages.$[elem].read': true } },
            { 
              arrayFilters: [{ 'elem.senderId': contactUserId, 'elem.read': false }],
              multi: true
            }
          );
          
          console.log(`✅ Marked ${updateResult.modifiedCount} messages as read`);
          
          // Notify the sender that their messages have been read
          const senderSocketId = userSocketMap.get(contactUserId);
          if (senderSocketId) {
            io.to(senderSocketId).emit('messages-read', {
              fromUserId: fromUserId
            });
            console.log('📤 Notified sender that messages were read');
          }
        }
      } catch (error) {
        console.error('❌ Error marking messages as read:', error);
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
