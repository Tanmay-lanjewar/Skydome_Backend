// import express from 'express';
// import mongoose from 'mongoose';
// import bcrypt from 'bcrypt';
// import bodyParser from 'body-parser';
// import cors from 'cors';
// import crypto from "crypto";
// import nodemailer from "nodemailer";
// import dotenv from 'dotenv';
// import Razorpay from "razorpay";
// import WebSocketServer from 'ws';




const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const cors = require('cors');
const crypto = require('crypto');
const dotenv = require('dotenv');
const Razorpay = require('razorpay');
const { WebSocketServer } = require("ws");
const path = require("path");
const multer = require("multer");
const helmet = require("helmet");
const cloudinary = require("cloudinary").v2;
const { CloudinaryStorage } = require("multer-storage-cloudinary");
const sendEmail = require("./utils/sendEmail");









dotenv.config();
const app = express();

app.use("/razorpay-webhook", express.raw({ type: "application/json" }));

app.use(express.json());







// app.use(express.json())

app.use(helmet());
app.use(cors());




cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET,
});



// MongoDB connection
mongoose.connect(process.env.MONGODB_URI)
    .then(() => console.log("Connected to MongoDB"))
    .catch(err => console.error("Failed to connect to MongoDB:", err));

// User Schema
const userSchema = new mongoose.Schema({
    username: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    resetPasswordToken: { type: String },
    resetPasswordExpires: { type: Date },
});

let otpStore = {};  // Initialize the OTP store globally






// Initialize Razorpay
const razorpay = new Razorpay({
    key_id: process.env.RAZORPAY_KEY_ID,
    key_secret: process.env.RAZORPAY_KEY_SECRET,
});

// WebSocket server setup
const wss = new WebSocketServer({ noServer: true });
let connectedClients = [];

// Broadcast a message to all connected clients
const broadcast = (message) => {
    connectedClients.forEach((client) => {
        if (client.readyState === 1) {
            client.send(JSON.stringify(message));
        }
    });
};

// Handle WebSocket connections
wss.on("connection", (ws) => {
    connectedClients.push(ws);

    ws.on("close", () => {
        connectedClients = connectedClients.filter((client) => client !== ws);
    });
});


const User = mongoose.model("User", userSchema);

// 2. Define a Schema (structure for your data)
const formDataSchema = new mongoose.Schema({
    address: String,
    category: String,
    city: String,
    classXBoard: String,
    classXIIBoard: String,
    classXIIPassingYear: String,
    classXIISchoolName: String,
    classXPassingYear: String,
    classXPercentage: String,
    classXSchoolName: String,
    country: String,
    dob: String,
    email: String,
    fatherName: String,
    fname: String,
    gender: String,
    lname: String,
    login_email: String,
    motherName: String,
    number: String,
    parentEmail: String,
    parentMobile: String,
    photo: String,
    pin: String,
    polytechnicPassingYear: String,
    polytechniccollegeName: String,
    priority1: String,
    priority2: String,
    priority3: String,
    qualification: String,
    state: String,
    universityBoard: String,
    status: String
});

const FormData = mongoose.model('FormData', formDataSchema);

const PaymentSchema = new mongoose.Schema({
    login_email: String,
    amount: Number,
    paymentId: String,
    orderId: String,
    status: String,
});

const PaymentData = mongoose.model('PaymentData', PaymentSchema);


// Route to create a new order
app.post("/create-order", async (req, res) => {
    const { amount, currency, receipt } = req.body;

    try {
        const options = {
            amount: amount * 100, // Amount in smallest currency unit (e.g., paise)
            currency,
            receipt,
        };
        const order = await razorpay.orders.create(options);
        res.status(200).json(order);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Route to verify payment signature
app.post("/verify-payment", (req, res) => {
    const { razorpay_order_id, razorpay_payment_id, razorpay_signature } = req.body;

    const generatedSignature = crypto
        .createHmac("sha256", process.env.RAZORPAY_KEY_SECRET)
        .update(`${razorpay_order_id}|${razorpay_payment_id}`)
        .digest("hex");

    if (generatedSignature === razorpay_signature) {
        // Notify clients about successful payment
        broadcast({
            status: "success",
            orderId: razorpay_order_id,
            paymentId: razorpay_payment_id,
        });
        res.status(200).json({ message: "Payment verification successful" });
    } else {
        res.status(400).json({ error: "Invalid signature" });
    }
});


app.post('/api/save-payment-data', async (req, res) => {
    try {
        const { login_email, amount, orderId, paymentId } = req.body;
        const newPaymentData = new PaymentData({
            login_email,
            amount,
            paymentId,
            orderId,
            status: true
        });
        await newPaymentData.save();

        //update staus in form data:
        // Check if the user already exists using login_email
        const existingUser = await FormData.findOne({ login_email });
        if (existingUser) {
            // Convert MongoDB document to a plain JavaScript object
            const userData = existingUser.toObject();

            // Add status: true to the existing data
            userData.status = true;

            console.log('User data:', userData);

            // If user exists, update the existing data
            await FormData.updateOne({ login_email }, { $set: userData });
        }

        return res.status(200).json({ message: 'Payement saved successfully' });



    }
    catch (error) {
        console.error("Error saving end  data:", error);
        res.status(500).json({ message: 'Error saving end data' });
    }
});


app.post('/api/save-form-data', async (req, res) => {
    try {
        const { login_email, photo, ...otherData } = req.body;

        // Log the received data for debugging
        console.log('Received data:', req.body);



        // Check if the user already exists using login_email
        const existingUser = await FormData.findOne({ login_email });

        if (existingUser) {
            // If user exists, update the existing data
            await FormData.updateOne({ login_email }, { ...otherData, photo });

            return res.status(200).json({ message: 'User data updated successfully' });
        } else {
            // If user does not exist, insert new data
            const newFormData = new FormData({
                login_email,
                ...otherData,
                photo, // Include the Base64 image
            });

            await newFormData.save();
            return res.status(200).json({ message: 'Form data saved successfully' });
        }
    } catch (error) {
        console.error("Error saving form data:", error);
        res.status(500).json({ message: 'Error saving form data' });
    }
});



app.post("/send-otp", async (req, res) => {
    const { email } = req.body;

    // 1️⃣ Generate 6-digit OTP
    const otp = crypto.randomInt(100000, 999999).toString();

    // 2️⃣ Store OTP with expiry (10 minutes)
    otpStore[email] = {
        otp: otp,
        expiresAt: Date.now() + 10 * 60 * 1000
    };

    try {
        // 3️⃣ Send OTP email
        await sendEmail({
            to: email,
            subject: "Your OTP Code",
            html: `
        <h2>Hello!</h2>
        <p>Your OTP is:</p>
        <h1>${otp}</h1>
        <p>This OTP is valid for <strong>10 minutes</strong>.</p>
      `,
        });

        res.status(200).json({
            success: true,
            message: "OTP sent successfully"
        });

    } catch (error) {
        console.error("OTP send error:", error);
        res.status(500).json({
            success: false,
            message: "Failed to send OTP"
        });
    }
});


app.post("/verify-otp", (req, res) => {
    const { email, otp } = req.body;

    const record = otpStore[email];

    // 1️⃣ Check if OTP exists
    if (!record) {
        return res.status(400).json({
            success: false,
            message: "OTP expired or not found"
        });
    }

    // 2️⃣ Check expiry
    if (record.expiresAt < Date.now()) {
        delete otpStore[email]; // cleanup
        return res.status(400).json({
            success: false,
            message: "OTP expired"
        });
    }

    // 3️⃣ Verify OTP
    if (record.otp !== otp) {
        return res.status(400).json({
            success: false,
            message: "Invalid OTP"
        });
    }

    // 4️⃣ Success → delete OTP
    //   delete otpStore[email];

    res.status(200).json({
        success: true,
        message: "OTP verified successfully"
    });
});


app.post("/register", async (req, res) => {
    try {
        const { username, email, password, otp } = req.body;

        // 1️⃣ Get OTP record
        const record = otpStore[email];

        console.log("Received OTP:", otp);
        console.log("Stored OTP Record:", record);

        // 2️⃣ Validate OTP
        if (!record) {
            return res.status(400).json({
                success: false,
                message: "OTP expired or not found"
            });
        }

        if (record.expiresAt < Date.now()) {
            delete otpStore[email]; // cleanup expired OTP
            return res.status(400).json({
                success: false,
                message: "OTP expired"
            });
        }

        if (record.otp !== otp) {
            return res.status(400).json({
                success: false,
                message: "Invalid OTP"
            });
        }

        // 3️⃣ Check if user already exists
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({
                success: false,
                message: "Email already exists"
            });
        }

        // 4️⃣ Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // 5️⃣ Create user
        const newUser = new User({
            username,
            email,
            password: hashedPassword,
        });

        await newUser.save();

        // 6️⃣ Cleanup OTP after successful registration
        delete otpStore[email];

        // 7️⃣ Success response
        res.status(201).json({
            success: true,
            message: "Registration successful"
        });

    } catch (error) {
        console.error("Register error:", error);
        res.status(500).json({
            success: false,
            message: "Error registering user"
        });
    }
});


//  API to send form and payment details via email
app.post("/send-email", async (req, res) => {
    const { login_email } = req.body;

    try {
        const userData = await FormData.findOne({ login_email });
        const paymentData = await PaymentData.findOne({ login_email });

        if (!userData || !paymentData) {
            return res.status(404).json({ error: "User or payment data not found" });
        }

        await sendEmail({
            to: "aviationcetofficial@gmail.com",
            subject: "New Registration on Your Website",
            html: `
        <h2>New Registration Details</h2>
        <p><strong>Name:</strong> ${userData.fname} ${userData.lname}</p>
        <p><strong>Email:</strong> ${userData.email}</p>
        <p><strong>Phone:</strong> ${userData.number}</p>
        <p><strong>Amount Paid:</strong> ${paymentData.amount}</p>
        <p><strong>Order ID:</strong> ${paymentData.orderId}</p>
        <p><strong>Status:</strong> ${userData.status}</p>
      `,
        });

        res.status(200).json({ message: "Email sent successfully" });

    } catch (error) {
        console.error("Brevo email error:", error);
        res.status(500).json({ error: "Failed to send email" });
    }
});



// Fetch form data from MongoDB
app.get('/api/get-form-data', async (req, res) => {

    try {
        const { login_email } = req.query;
        const formData = await FormData.findOne({ login_email });
        console.log("Fetched form data:", formData); // Log the data
        res.status(200).json(formData);
    } catch (error) {
        console.error("Error fetching form data:", error);
        res.status(500).json({ message: 'Error fetching form data' });
    }
});

// Fetch payment data from MongoDB:
app.get('/api/get-payment-data', async (req, res) => {
    try {
        const { login_email } = req.query;
        const paymentData = await PaymentData.find({ login_email });
        console.log("Fetched payment data:", paymentData);
        res.status(200).json(paymentData);
    }
    catch (error) {
        console.error("Error fetching payment data:", error);
        res.status(500).json({ message: 'Error fetching payment data' });
    }
});




// Login endpoint
app.post("/login", async (req, res) => {
    const { email, password } = req.body;

    console.log("Incoming request:", req.body);

    try {
        const user = await User.findOne({ email });
        if (!user) {
            console.log("User not found");
            return res.status(400).json({ message: "Invalid email or password" });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            console.log("Password mismatch");
            return res.status(400).json({ message: "Invalid email or password" });
        }

        console.log("User authenticated successfully");

        res.status(200).json({ message: "Login successful", email: user.email, username: user.username });
    } catch (error) {
        console.error("Error during login:", error);
        res.status(500).json({ message: "Error logging in" });
    }
});

app.post("/forgot-password", async (req, res) => {
    try {
        const { email } = req.body;

        // 1️⃣ Check if user exists
        const user = await User.findOne({ email });

        // IMPORTANT: Do NOT reveal if email exists (security best practice)
        if (!user) {
            return res.status(200).json({
                message: "If the email exists, a reset link has been sent."
            });
        }

        // 2️⃣ Generate reset token (RAW token for URL)
        const resetToken = crypto.randomBytes(32).toString("hex");

        // 3️⃣ Hash token before saving (SECURITY)
        const hashedToken = crypto
            .createHash("sha256")
            .update(resetToken)
            .digest("hex");

        // 4️⃣ Save token + expiry in DB
        user.resetPasswordToken = hashedToken;
        user.resetPasswordExpires = Date.now() + 60 * 60 * 1000; // 1 hour
        await user.save();

        // 5️⃣ Create reset link (FRONTEND URL)
        const resetLink = `https://aviationcetofficial.in/reset-password/${resetToken}`;

        // 6️⃣ SEND EMAIL USING BREVO ✅
        await sendEmail({
            to: user.email,
            subject: "Password Reset Request",
            html: `
        <div style="font-family: Arial, sans-serif;">
          <h2>Password Reset</h2>
          <p>Hello ${user.username || "User"},</p>
          <p>You requested to reset your password.</p>
          <p>Click the button below to reset it:</p>

          <a href="${resetLink}"
             style="
               display:inline-block;
               padding:12px 20px;
               background:#007bff;
               color:#ffffff;
               text-decoration:none;
               border-radius:5px;
               margin:10px 0;
             ">
             Reset Password
          </a>

          <p>This link is valid for <strong>1 hour</strong>.</p>
          <p>If you did not request this, please ignore this email.</p>

          <br/>
          <p>— Aviation CET Team</p>
        </div>
      `,
        });

        // 7️⃣ Response
        res.status(200).json({
            message: "If the email exists, a reset link has been sent."
        });

    } catch (error) {
        console.error("Forgot-password error:", error);
        res.status(500).json({
            error: "Failed to process password reset request."
        });
    }
});


// Verify reset password token route (GET)
app.get('/reset-password/:token', async (req, res) => {
    const { token } = req.params;

    try {
        // Hash the token to compare with the stored hashed token
        const hashedToken = crypto.createHash('sha256').update(token).digest('hex');

        // Find the user by the reset token and ensure the token hasn't expired
        const user = await User.findOne({
            resetPasswordToken: hashedToken,
            resetPasswordExpires: { $gt: Date.now() }, // Ensure the token hasn't expired
        });

        if (!user) {
            return res.status(400).json({ message: 'Invalid or expired token.' });
        }

        // If the token is valid, return a success response
        res.status(200).json({ message: 'Token is valid. You can now reset your password.' });
    } catch (error) {
        console.error('Error during token verification:', error);
        res.status(500).json({ message: 'An error occurred. Please try again later.' });
    }
});





// Reset password route (POST):
app.post('/reset-password/:token', async (req, res) => {
    const { token } = req.params;
    const { password } = req.body;
    console.log("Reset Password Token:", token);

    try {
        // Hash the token provided in the URL to compare with the stored hashed token
        const hashedToken = crypto.createHash('sha256').update(token).digest('hex');

        // Find the user by the reset token and ensure the token hasn't expired
        const user = await User.findOne({
            resetPasswordToken: hashedToken,
            resetPasswordExpires: { $gt: Date.now() }, // Ensure the token hasn't expired (1 hour window)
        });

        if (!user) {
            return res.status(400).json({ message: 'Invalid or expired token.' });
        }

        // Hash the new password before saving it (you can skip this if you're not hashing passwords)
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        // Update the user's password and clear reset token data
        user.password = hashedPassword;
        user.resetPasswordToken = undefined; // Clear the reset token
        user.resetPasswordExpires = undefined; // Clear the expiration time
        await user.save();

        // Send success response
        res.status(200).json({ message: 'Password reset successfully.' });
    } catch (error) {
        console.error('Error during password reset:', error);
        res.status(500).json({ message: 'An error occurred. Please try again later.' });
    }
});

//  **Get Order Status**
app.get("/get-order-status/:orderId", async (req, res) => {
    const { orderId } = req.params;

    try {
        // Fetch payment details from Razorpay
        const razorpayOrder = await razorpay.orders.fetch(orderId);

        // Check if order exists in the database
        const savedPayment = await PaymentData.findOne({ orderId });

        if (razorpayOrder.status === "paid" || (savedPayment && savedPayment.status === "paid")) {
            return res.json({ status: "paid", payment_id: savedPayment?.paymentId || null });
        } else {
            return res.json({ status: "pending" });
        }
    } catch (error) {
        console.error("Error fetching order status:", error);
        res.status(500).json({ error: "Failed to fetch order status" });
    }
});



app.post("/razorpay-webhook", (req, res) => {
    const secret = process.env.RAZORPAY_WEBHOOK_SECRET;

    // Same as entered in Razorpay dashboard

    // Verify Razorpay signature
    const expectedSignature = crypto
        .createHmac("sha256", secret)
        .update(JSON.stringify(req.body))
        .digest("hex");

    const receivedSignature = req.headers["x-razorpay-signature"];

    if (expectedSignature !== receivedSignature) {
        console.error("⚠ Invalid Razorpay Webhook Signature!");
        return res.status(400).send("Invalid signature");
    }

    const event = req.body.event;
    console.log(" Razorpay Webhook Event:", event);

    if (event === "payment.captured") {
        const paymentId = req.body.payload.payment.entity.id;
        const orderId = req.body.payload.payment.entity.order_id;
        console.log("✅ Payment Captured - Payment ID:", paymentId, "Order ID:", orderId);


    } else if (event === "payment.failed") {
        console.error(" Payment Failed:", req.body);
    }

    res.json({ status: "success" });
});



//  Route to check if backend is running
app.get("/backend-test", (req, res) => {
    res.status(200).json({ message: " Backend is running!" });
});






app.get("/", (req, res) => {
    res.send("finaly.");
});










// Multer configuration
const storage = new CloudinaryStorage({
    cloudinary,
    params: async (req, file) => ({
        folder: "skydome_uploads",   // ✅ REAL folder name
        format: "jpg",
        public_id: `photo_${Date.now()}`,
    }),
});




const upload = multer({
    storage: storage,
    limits: { fileSize: 2 * 1024 * 1024 }, // 50KB limit
    fileFilter: (req, file, cb) => {
        const allowedTypes = ["image/jpeg", "image/png"];
        if (allowedTypes.includes(file.mimetype)) {
            cb(null, true);
        } else {
            cb(new Error("Only JPEG and PNG images are allowed"));
        }
    },
});

// Route to handle image upload
app.post("/api/upload-photo", upload.single("image"), (req, res) => {
    if (!req.file) {
        return res.status(400).json({ error: "No file uploaded" });
    }

    // Cloudinary URL
    res.json({
        filePath: req.file.path,   // <-- THIS IS A PUBLIC URL
    });
});




// Start the server with WebSocket support
const PORT = process.env.PORT || 3000;
const server = app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});

// Upgrade HTTP server to handle WebSocket connections
server.on("upgrade", (request, socket, head) => {
    wss.handleUpgrade(request, socket, head, (ws) => {
        wss.emit("connection", ws, request);
    });
});


setInterval(() => {
    const now = Date.now();
    for (const email in otpStore) {
        if (otpStore[email].expiresAt < now) {
            delete otpStore[email];
        }
    }
}, 5 * 60 * 1000);
