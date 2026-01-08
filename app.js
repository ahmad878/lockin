const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const Together = require("together-ai");
const path = require("path");

// ===== Cloudinary & Multer Imports =====
const cloudinary = require("cloudinary").v2;
const multer = require("multer");

// ===== Cloudinary Configuration =====
cloudinary.config({
  cloud_name: 'dxxpkyitl',
  api_key: '126471723935395',
  api_secret: 'IBlq5rjUvtdIxBn34N_yjY4dOB0'
});

// ===== Multer with memoryStorage (no files saved to disk) =====
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 10 * 1024 * 1024 // 10MB limit - adjust as needed
  },
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

// ===== Middleware =====
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));


// ===== Serve dashboard.html at root =====
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public/dashboard.html"));
});

// ===== Image/Video Upload Route with Proper Debugging =====
app.post("/upload-image", upload.single("image"), async (req, res) => {
  console.log('====== UPLOAD REQUEST RECEIVED ======');
  console.log('Headers:', req.headers);
  console.log('Body:', req.body);
  console.log('File info:', req.file ? {
    fieldname: req.file.fieldname,
    originalname: req.file.originalname,
    encoding: req.file.encoding,
    mimetype: req.file.mimetype,
    size: req.file.size,
    bufferLength: req.file.buffer ? req.file.buffer.length : 'no buffer'
  } : 'NO FILE');
  
  try {
    if (!req.file) {
      console.log('❌ No file in request');
      return res.status(400).json({ 
        success: false, 
        error: "No file uploaded",
        debug: {
          hasFile: false,
          bodyKeys: Object.keys(req.body),
          body: req.body
        }
      });
    }

    console.log('✅ File received, uploading to Cloudinary...');
    
    // Wrap upload_stream in a Promise
    const uploadToCloudinary = () => {
      return new Promise((resolve, reject) => {
        const uploadStream = cloudinary.uploader.upload_stream(
          {
            folder: "therapy-app-uploads",
            resource_type: "auto",
            quality: "auto:good",
            transformation: [
              { width: 1200, height: 1200, crop: "limit" }
            ]
          },
          (error, result) => {
            if (error) {
              console.error('❌ Cloudinary upload error:', error);
              reject(error);
            } else {
              console.log('✅ Cloudinary upload success:', {
                url: result.secure_url,
                public_id: result.public_id,
                format: result.format,
                bytes: result.bytes
              });
              resolve(result);
            }
          }
        );

        // Write the buffer to the stream
        uploadStream.end(req.file.buffer);
      });
    };

    const result = await uploadToCloudinary();

    console.log('✅ Sending success response');
    res.json({
      success: true,
      url: result.secure_url,
      public_id: result.public_id,
      format: result.format,
      bytes: result.bytes,
      message: "File uploaded successfully"
    });

  } catch (err) {
    console.error("❌ Upload error:", err);
    console.error("Error stack:", err.stack);
    res.status(500).json({ 
      success: false, 
      error: err.message || "Upload failed",
      errorDetails: err.toString()
    });
  }
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

app.listen(3000, '0.0.0.0', () => {
  console.log(`Server running on port 3000`);
});