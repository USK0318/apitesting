const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser'); // Ensure you use cookie-parser middleware
const router = express.Router();
const User = require('../models/user');
const { check, validationResult } = require('express-validator');

const ACCESS_TOKEN_SECRET = process.env.ACCESS_TOKEN_SECRET || 'defaultAccessTokenSecret';
const REFRESH_TOKEN_SECRET = process.env.REFRESH_TOKEN_SECRET || 'defaultRefreshTokenSecret';

// Middleware to parse cookies
router.use(cookieParser());

// Authentication middleware to verify access tokens
const authenticateToken = (req, res, next) => {
    const token = req.cookies?.accessToken || req.headers['authorization']?.split(' ')[1];
    const refreshToken = req.cookies?.refreshToken;
    // console.log('token', token);

    // Check if access token is provided
    if (!token) {
        return res.status(401).json({ message: 'Access token is missing' });
    }

    // Verify access token
    jwt.verify(token, ACCESS_TOKEN_SECRET, (err, user) => {
        if (err) {
            // Handle token expiration
            if (err.name === 'TokenExpiredError') {
                // Check for refresh token
                if (!refreshToken) {
                    return res.status(401).json({ message: 'Refresh token is missing, please log in again' });
                }

                // Verify refresh token
                jwt.verify(refreshToken, REFRESH_TOKEN_SECRET, (err, decoded) => {
                    if (err) {
                        return res.status(403).json({ message: 'Invalid refresh token, please log in again' });
                    }

                    // If refresh token is valid, issue a new access token
                    const newAccessToken = jwt.sign({ userId: decoded.userId }, ACCESS_TOKEN_SECRET, { expiresIn: '1h' });

                    // Set new access token in cookies
                    res.cookie('accessToken', newAccessToken, { httpOnly: true, sameSite: 'Strict', secure: process.env.NODE_ENV === 'production' });

                    // Assign user data to the request
                    req.user = { userId: decoded.userId };
                    return next(); // Proceed to the next middleware or route
                });
            } else {
                return res.status(403).json({ message: 'Invalid access token' });
            }
        } else {
            // Access token is valid
            req.user = user; // Set user data from token to the request
            next(); // Proceed to the next middleware or route
        }
    });
};
// Validation rules for registration and login

const validateUser = [
    check('name', 'Name is required and should be at least 3 characters')
        .isLength({ min: 3 })
        .matches(/^[a-zA-Z\s]+$/).withMessage('Name can only contain letters and spaces'),

    check('email', 'Email is not valid').isEmail(),

    check('password', 'Password must be 6 or more characters')
        .isLength({ min: 6 })
        .matches(/[a-z]/).withMessage('Password must contain at least one lowercase letter')
        .matches(/[A-Z]/).withMessage('Password must contain at least one uppercase letter')
        .matches(/\d/).withMessage('Password must contain at least one number')
        .matches(/[\W_]/).withMessage('Password must contain at least one special character'),
    
    check('phone', 'Phone number must be valid')
        .isMobilePhone().withMessage('Invalid phone number format')
        .isLength({ min: 10, max: 15 }).withMessage('Phone number should be between 10 to 15 digits')
];




// Register endpoint
router.post('/register', validateUser, async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    try {
        const { email, password } = req.body;
        let existingUser = await User.findOne({ email });

        if (existingUser) {
            return res.status(400).json({ message: 'User already exists' });
        }

        const hashedPassword = await bcrypt.hash(password, 12);
        const user = new User({ ...req.body, password: hashedPassword });
        await user.save();

        res.status(201).send({ message: 'User created successfully' });
    } catch (error) {
        res.status(500).send({ message: error.message });
    }
});

// Login endpoint
router.post('/login', async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });

        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ message: 'Invalid credentials' });
        }

        // Generate tokens
        const accessToken = jwt.sign({ userId: user._id }, ACCESS_TOKEN_SECRET, { expiresIn: '1h' });
        const refreshToken = jwt.sign({ userId: user._id }, REFRESH_TOKEN_SECRET, { expiresIn: '6d' });

        // Store tokens in cookies
        const isDevelopment = process.env.NODE_ENV !== 'production';

        res.cookie('accessToken', accessToken, {
            httpOnly: true,
            sameSite: 'Strict',
            secure: isDevelopment ? false : true, // Allow non-secure cookies in development
            maxAge: 3600000 // 1 hour
        });

        res.cookie('refreshToken', refreshToken, {
            httpOnly: true,
            sameSite: 'Strict',
            secure: isDevelopment ? false : true, // Allow non-secure cookies in development
            maxAge: 86400000 // 1 day
        });

        res.status(200).json({ message: 'Login successful' });
    } catch (error) {
        res.status(500).send({ message: error.message });
    }
});

// Logout endpoint
router.post('/logout', (req, res) => {
    try {
        res.cookie('accessToken', '', { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'Strict', maxAge: 0 });
        res.cookie('refreshToken', '', { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'Strict', maxAge: 0 });

        return res.status(200).json({ message: 'Logout successful' });
    } catch (error) {
        res.status(500).send({ message: error.message });
    }
});

// Protected route to get user data
router.get('/me', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.userId).select('-password');
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }
        res.json(user);
    } catch (error) {
        res.status(500).send({ message: error.message });
    }
});

// Token refresh endpoint
router.post('/token', async (req, res) => {
    const refreshToken = req.cookies.refreshToken || req.body.refreshToken;
    if (!refreshToken) return res.status(401).json({ message: 'Refresh token missing' });

    jwt.verify(refreshToken, REFRESH_TOKEN_SECRET, (err, user) => {
        if (err) return res.status(403).json({ message: 'Invalid refresh token' });

        const newAccessToken = jwt.sign({ userId: user.userId }, ACCESS_TOKEN_SECRET, { expiresIn: '1h' });
        res.cookie('accessToken', newAccessToken, { httpOnly: true, sameSite: 'Strict', secure: process.env.NODE_ENV === 'production', maxAge: 3600000 });

        res.json({ accessToken: newAccessToken });
    });
});

module.exports = router;
