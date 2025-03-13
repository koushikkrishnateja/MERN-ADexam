const express = require('express');
const router = express.Router();
const User = require('../models/User');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');

// User registration route
router.post('/register', async (req, res) => {
    const { username, password, email } = req.body; // Added email to registration
    const hashedPassword = await bcrypt.hash(password, 10);
    
    const newUser = new User({
        username,
        password: hashedPassword,
        email, // Store email in the user model
        isVerified: false // New field for email verification status
    });

    try {
        await newUser.save();
        // Send verification email
        const transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: {
                user: 'your_email@gmail.com', // Your email
                pass: 'your_email_password' // Your email password
            }
        });

        const verificationToken = jwt.sign({ id: newUser._id }, 'your_jwt_secret', { expiresIn: '1h' });
        const verificationUrl = `http://yourdomain.com/verify-email/${verificationToken}`;

        await transporter.sendMail({
            to: email,
            subject: 'Email Verification',
            html: `<p>Please verify your email by clicking on the following link: <a href="${verificationUrl}">Verify Email</a></p>`
        });

        res.status(201).send('User registered. Verification email sent.');

    } catch (error) {
        res.status(400).send('Error registering user');
    }
});

// User login route
router.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const user = await User.findOne({ username });

    if (!user) {
        return res.status(400).send('User not found');
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
        return res.status(400).send('Invalid credentials');
    }

    const token = jwt.sign({ id: user._id }, 'your_jwt_secret', { expiresIn: '1h' });
    res.status(200).json({ token });
});

// Email verification route
router.get('/verify-email/:token', async (req, res) => {
    const { token } = req.params;

    try {
        const decoded = jwt.verify(token, 'your_jwt_secret');
        const user = await User.findById(decoded.id);

        if (!user) {
            return res.status(400).send('Invalid token');
        }

        user.isVerified = true; // Update verification status
        await user.save();

        res.status(200).send('Email verified successfully');
    } catch (error) {
        res.status(400).send('Error verifying email');
    }
});

module.exports = router;
