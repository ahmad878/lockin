const Together = require("together-ai");
const together = new Together({ apiKey: "a1cab1d451defe94e8817b0d82bfdccf3bf647a4481ce27c1ab48588bb4c42a7" });
const express = require("express");
const mongoose = require("mongoose");
const mongodb = require("mongodb");
const app = express();
const SibApiV3Sdk = require('sib-api-v3-sdk');
const cookieParser = require("cookie-parser");
app.use(cookieParser());
const jwt = require("jsonwebtoken");
const rateLimit = require('express-rate-limit');
app.use(express.static(__dirname));
app.use(rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: { success: false, message: 'Too many requests, please try again later.' }
}));

const mongo_uri = 'mongodb+srv://aljawadhamoudii:WS3MqTzBWIwaeJXL@flipproject.eidbspl.mongodb.net/'

mongoose.connect(mongo_uri)
  .then(() => console.log('MongoDB connected successfully.'))
  .catch(err => console.error('MongoDB connection error:', err));

app.use(express.json());

app.listen(3000, function(){
    console.log("Server is running on port 3000");
})
app.get('/', function(req,res){
    res.sendFile(__dirname + '/index.html');
})

async function getChatResponse(prompt) {
  const response = await together.chat.completions.create({
    messages: [{
      "role": "user",
      "content": `You are a professional travel planner. Research and provide REAL, BOOKABLE travel recommendations.

IMPORTANT FLIGHT REQUIREMENTS:
- Use real airline booking websites Only look at flights from  Aviasales (https://www.aviasales.com), or direct airline sites
- For flight links, provide a direct booking link similar to this format: https://www.aviasales.com/search/NYC0508LAX12081 (where the link includes the deperature and arrivial)
Dates must be DDMM (day + month), e.g., July 15 = 1507
IN THE LINK DONT RETURN ANY ROUND TRIPS DONT INCLUDE ANY RETURN JUST ONE WAY SAME WITH RETURN ONE WAY

For round trips, return date comes after destination code with no extra letters, so full pattern is:
ORIGINDATEDESTINATIONRETURNDATEPASSENGERS

Passengers is just a single number at the end.
- Include flight numbers, departure/arrival times, and prices
- Format: "Flight: [Airline] [Flight Number] - [Departure Time] to [Arrival Time] - $[Price] - [Direct Booking Link]"

HOTEL REQUIREMENTS:
- Provide real hotel booking links from Expedia, Booking.com, Hotels.com, or direct hotel sites
- Include actual prices and availability for the specified dates
- Format: "Hotel: [Hotel Name] - $[Price]/night - [Direct Booking Link]"

RESPONSE FORMAT:
Don't include* *Final Recommendations part! just the information needed!
Use these exact section headers (no asterisks):
#### Hotels
#### Flights
#### Travel Plan
#### Places & Activities (only if requested)

For each section, provide:
- Real prices in USD
- Direct booking/purchase links
- Specific details (flight numbers, hotel names, etc.)
- Step-by-step travel instructions

DO NOT include sections that weren't requested. Only provide what the user specifically asked for.

Here is the travel request: ${prompt}`
    }],
    model: "deepseek-ai/DeepSeek-V3"
  });
  return response.choices[0].message.content;
}
app.post('/', function(req, res) {
  console.log(req.body);


  const prompt = `
    Destination: ${req.body.destination}
    Departure: ${req.body.departure}
    Check-In: ${req.body.checkIn}
    Check-Out: ${req.body.checkOut}
    Budget: ${req.body.budget}
    Include Hotels: ${req.body.includeHotels}
    Include Flights: ${req.body.includeFlights}
    Include Guides: ${req.body.includeGuides}
    Include Places: ${req.body.includePlaces}
  `;

  getChatResponse(prompt).then(response => {
    console.log("Response:", response);
    res.json({ response });
  }).catch(error => {
    console.error("Error:", error);
    res.status(500).json({ error: "An error occurred while processing your request." });
  });
});

app.get('/signup', function(req,res){
  res.sendFile(__dirname +'/signup.html');
});

app.post('/signup', function(req,res){
  console.log(req.body);
})
app.post('/signup', async function(req, res) {
  try {
    console.log('Received signup request:', req.body);
    const { fullname, email, password } = req.body;

    if (!fullname || !email || !password) {
      return res.status(400).json({
        success: false,
        message: 'All fields are required'
      });
    }

    const nameRegex = /^[A-Za-z\s]+$/;
    if (!nameRegex.test(fullname)) {
      return res.status(400).json({
        success: false,
        message: 'Name can only contain letters and spaces'
      });
    }

    const nameLower = fullname.toLowerCase();
    const hasProfanity = bannedWords.some(word =>
      nameLower.includes(word.toLowerCase())
    );

    if (hasProfanity) {
      return res.status(400).json({
        success: false,
        message: 'Username contains inappropriate language'
      });
    }

    const existingEmail = await User.findOne({ 'User.email': email });
    if (existingEmail) {
      return res.status(400).json({
        success: false,
        message: 'Email already registered'
      });
    }

    const existingFullname = await User.findOne({ 'User.FullName': fullname });
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
        fullname: fullname,
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
      const userId = await getNextSequence('userId');
      const user = {
        id: userId,
        fullname: verificationData.fullname,
        email: email
      };

      const token = generateToken(user);
      res.cookie(COOKIE_NAME, token, COOKIE_OPTIONS);
      const hashedPassword = await bcrypt.hash(verificationData.password, 10);

      const newUser = new User({
        User: [{
          id: userId,
          FullName: verificationData.fullname,
          KindCoins: 0,
          email: email,
          profilePicture: "none",
          password: hashedPassword
        }]
      });

      const newNotification = new Notification({
        fullName: verificationData.fullname,
        email: email,
        notifications: [{
          message: "Welcome to KindNestle! Start helping others today.",
          type: "system",
          read: false
        }]
      });

      await Promise.all([
        newUser.save(),
        newNotification.save()
      ]);

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
app.get("/login", function(req,res){
  res.sendFile(__dirname + '/login.html');
})