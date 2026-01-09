const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const Together = require("together-ai");
const path = require("path");

// ===== Cloudinary & Multer Imports =====
const cloudinary = require("cloudinary").v2;
const multer = require("multer");

// ===== PDF Creation Imports =====
const { PDFDocument } = require("pdf-lib");
const sharp = require("sharp");

// ===== Cloudinary Configuration =====
cloudinary.config({
  cloud_name: 'dxxpkyitl',
  api_key: '126471723935395',
  api_secret: 'IBlq5rjUvtdIxBn34N_yjY4dOB0'
});

// ===== Multer with memoryStorage =====
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 10 * 1024 * 1024 // 10MB limit
  },
  fileFilter: (req, file, cb) => {
    const allowedTypes = ['image/jpeg', 'image/png', 'image/webp', 'image/gif'];
    if (allowedTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('Invalid file type. Only images allowed.'));
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

// ===== Image to PDF Conversion Route =====
app.post("/convert-to-pdf", upload.single("image"), async (req, res) => {
  console.log('====== PDF CONVERSION REQUEST RECEIVED ======');
  console.log('File info:', req.file ? {
    originalname: req.file.originalname,
    mimetype: req.file.mimetype,
    size: req.file.size
  } : 'NO FILE');
  
  try {
    if (!req.file) {
      console.log('❌ No file in request');
      return res.status(400).json({ 
        success: false, 
        error: "No image uploaded"
      });
    }

    console.log('✅ File received, processing image...');
    
    // Step 1: Process image with sharp (optimize and convert to JPEG)
    const processedImageBuffer = await sharp(req.file.buffer)
      .jpeg({ quality: 90 })
      .resize(2480, 3508, { // A4 size at 300 DPI
        fit: 'inside',
        withoutEnlargement: true
      })
      .toBuffer();

    console.log('✅ Image processed, creating PDF...');

    // Step 2: Create PDF with pdf-lib
    const pdfDoc = await PDFDocument.create();
    
    // Embed the image in the PDF
    const image = await pdfDoc.embedJpg(processedImageBuffer);
    
    // Get image dimensions
    const imageDims = image.scale(1);
    
    // Create a page with the image dimensions (or standard A4 size)
    const pageWidth = Math.min(imageDims.width, 595); // A4 width in points
    const pageHeight = Math.min(imageDims.height, 842); // A4 height in points
    
    const page = pdfDoc.addPage([pageWidth, pageHeight]);
    
    // Calculate scaling to fit image on page
    const scale = Math.min(
      pageWidth / imageDims.width,
      pageHeight / imageDims.height
    );
    
    const scaledWidth = imageDims.width * scale;
    const scaledHeight = imageDims.height * scale;
    
    // Center the image on the page
    const x = (pageWidth - scaledWidth) / 2;
    const y = (pageHeight - scaledHeight) / 2;
    
    page.drawImage(image, {
      x: x,
      y: y,
      width: scaledWidth,
      height: scaledHeight,
    });

    // Save the PDF as bytes
    const pdfBytes = await pdfDoc.save();
    const pdfBuffer = Buffer.from(pdfBytes);

    console.log('✅ PDF created, uploading to Cloudinary...');

    // Step 3: Upload PDF to Cloudinary
    const uploadToCloudinary = () => {
      return new Promise((resolve, reject) => {
        const uploadStream = cloudinary.uploader.upload_stream(
          {
            folder: "pdf-conversions",
            resource_type: "raw",
            format: "pdf",
            public_id: `converted_${Date.now()}`
          },
          (error, result) => {
            if (error) {
              console.error('❌ Cloudinary upload error:', error);
              reject(error);
            } else {
              console.log('✅ Cloudinary upload success:', {
                url: result.secure_url,
                public_id: result.public_id
              });
              resolve(result);
            }
          }
        );

        uploadStream.end(pdfBuffer);
      });
    };

    const result = await uploadToCloudinary();

    console.log('✅ Sending success response');
    res.json({
      success: true,
      pdfUrl: result.secure_url,
      public_id: result.public_id,
      bytes: result.bytes,
      message: "PDF created and uploaded successfully"
    });

  } catch (err) {
    console.error("❌ Conversion error:", err);
    console.error("Error stack:", err.stack);
    res.status(500).json({ 
      success: false, 
      error: err.message || "Conversion failed",
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
        "I'm here with you. Something went wrong, but you're not alone."
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