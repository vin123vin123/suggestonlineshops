const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const path = require('path');

const app = express();
const PORT = 3000;

// Middleware
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Connect to MongoDB (local database named 'userDB')
mongoose.connect('mongodb://localhost:27017/userDB')
    .then(() => console.log('Successfully connected to MongoDB.'))
    .catch(err => console.error('MongoDB connection error:', err));

// Define User Schema and Model
const userSchema = new mongoose.Schema({
    userId: { type: String, required: true, unique: true },
    password: { type: String, required: true }
});

const User = mongoose.model('User', userSchema);

// API Route: Sign Up
app.post('/api/signup', async (req, res) => {
    try {
        const { userId, password } = req.body;

        // Check if username already exists
        const userExists = await User.findOne({ userId });
        if (userExists) {
            return res.status(400).json({ message: 'User ID already taken.' });
        }

        // Hash the password securely before saving
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        // Save new user profile
        const newUser = new User({ userId, password: hashedPassword });
        await newUser.save();

        res.status(201).json({ message: 'Account created successfully! Redirecting...' });
    } catch (error) {
        res.status(500).json({ message: 'Server error processing signup.' });
    }
});

// API Route: Login
app.post('/api/login', async (req, res) => {
    try {
        const { userId, password } = req.body;

        // Check if user exists
        const user = await User.findOne({ userId });
        if (!user) {
            return res.status(400).json({ message: 'Invalid User ID or Password.' });
        }

        // Compare input password with hashed database password
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ message: 'Invalid User ID or Password.' });
        }

        res.status(200).json({ message: `Welcome back, ${userId}! Login successful.` });
    } catch (error) {
        res.status(500).json({ message: 'Server error processing login.' });
    }
});

// Start the server
app.listen(PORT, () => {
    console.log(`Server running smoothly on http://localhost:${PORT}`);
});
