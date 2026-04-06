const express = require('express');
const jwt = require('jsonwebtoken');
const { findByEmail, findById, createUser, comparePassword } = require('../models/User');
const authMiddleware = require('../middleware/auth');

const router = express.Router();

/**
 * Generate a JWT for a user.
 */
function generateToken(user) {
  return jwt.sign(
    { id: user._id, email: user.email, fullName: user.fullName },
    process.env.JWT_SECRET,
    { expiresIn: '7d' }
  );
}

/* ─────────────────────────────────────────────
   POST /api/auth/signup
   ───────────────────────────────────────────── */
router.post('/signup', async (req, res) => {
  try {
    const { fullName, email, password, confirmPassword, organization, wazuhIp } = req.body;

    // Validation
    if (!fullName || !email || !password || !confirmPassword) {
      return res.status(400).json({ message: 'Please fill in all required fields.' });
    }

    if (password.length < 8) {
      return res.status(400).json({ message: 'Password must be at least 8 characters.' });
    }

    if (password !== confirmPassword) {
      return res.status(400).json({ message: 'Passwords do not match.' });
    }

    // Check if user already exists
    const existingUser = await findByEmail(email);
    if (existingUser) {
      return res.status(409).json({ message: 'An account with this email already exists.' });
    }

    // Create user
    const user = await createUser({ fullName, email, password, organization, wazuhIp });

    const token = generateToken(user);

    res.status(201).json({
      message: 'Account created successfully.',
      token,
      user: {
        id:           user._id,
        fullName:     user.fullName,
        email:        user.email,
        organization: user.organization,
        wazuhIp:      user.wazuhIp,
      },
    });
  } catch (err) {
    // ORA-00001: unique constraint violated (duplicate email)
    if (err.errorNum === 1) {
      return res.status(409).json({ message: 'An account with this email already exists.' });
    }
    console.error('Signup error:', err);
    res.status(500).json({ message: 'Server error. Please try again later.' });
  }
});

/* ─────────────────────────────────────────────
   POST /api/auth/login
   ───────────────────────────────────────────── */
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: 'Please enter your email and password.' });
    }

    // Find user including password hash
    const user = await findByEmail(email, true);
    if (!user) {
      return res.status(401).json({ message: 'Invalid email or password.' });
    }

    const isMatch = await comparePassword(password, user.passwordHash);
    if (!isMatch) {
      return res.status(401).json({ message: 'Invalid email or password.' });
    }

    const token = generateToken(user);

    res.json({
      message: 'Login successful.',
      token,
      user: {
        id:           user._id,
        fullName:     user.fullName,
        email:        user.email,
        organization: user.organization,
        wazuhIp:      user.wazuhIp,
      },
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ message: 'Server error. Please try again later.' });
  }
});

/* ─────────────────────────────────────────────
   GET /api/auth/me  (protected)
   ───────────────────────────────────────────── */
router.get('/me', authMiddleware, async (req, res) => {
  try {
    const user = await findById(req.user.id);
    if (!user) {
      return res.status(404).json({ message: 'User not found.' });
    }

    res.json({
      user: {
        id:           user._id,
        fullName:     user.fullName,
        email:        user.email,
        organization: user.organization,
        wazuhIp:      user.wazuhIp,
      },
    });
  } catch (err) {
    console.error('Me error:', err);
    res.status(500).json({ message: 'Server error.' });
  }
});

module.exports = router;
