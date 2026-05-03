const express = require('express');
const https   = require('https');
const jwt     = require('jsonwebtoken');
const { findByEmail, findById, createUser, comparePassword, updateWazuhCreds } = require('../models/User');
const authMiddleware = require('../middleware/auth');
const { encrypt, decrypt } = require('../utils/crypto');

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
    const {
      fullName, email, password, confirmPassword, organization,
      wazuhIp, wazuhIndexerIp,
      indexerUser, indexerPassword,
      apiUser,     apiPassword,
    } = req.body;

    // Validation — account fields
    if (!fullName || !email || !password || !confirmPassword) {
      return res.status(400).json({ message: 'Please fill in all required fields.' });
    }
    if (password.length < 8) {
      return res.status(400).json({ message: 'Password must be at least 8 characters.' });
    }
    if (password !== confirmPassword) {
      return res.status(400).json({ message: 'Passwords do not match.' });
    }

    // Validation — Wazuh credentials (all required)
    if (!wazuhIp) {
      return res.status(400).json({ message: 'Wazuh IP / Hostname is required.' });
    }
    if (!indexerUser || !indexerPassword) {
      return res.status(400).json({ message: 'Indexer username and password are required.' });
    }
    if (!apiUser || !apiPassword) {
      return res.status(400).json({ message: 'Manager API username and password are required.' });
    }

    const existingUser = await findByEmail(email);
    if (existingUser) {
      return res.status(409).json({ message: 'An account with this email already exists.' });
    }

    const user = await createUser({
      fullName, email, password,
      organization:     organization   || '',
      wazuhIp,                                    // Manager API IP (port 55000)
      wazuhIndexerIp:   wazuhIndexerIp || '',     // Indexer IP (port 9200); blank = same as wazuhIp
      wazuhUser:        indexerUser,
      wazuhPassword:    encrypt(indexerPassword),
      wazuhApiUser:     apiUser,
      wazuhApiPassword: encrypt(apiPassword),
    });

    const token = generateToken(user);

    res.status(201).json({
      message: 'Account created successfully.',
      token,
      user: {
        id:            user._id,
        fullName:      user.fullName,
        email:         user.email,
        organization:  user.organization,
        wazuhIp:       user.wazuhIp,
        wazuhUser:     user.wazuhUser,
        hasWazuhCreds: true,
      },
    });
  } catch (err) {
    if (err.errno === 1062) {
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
        id:            user._id,
        fullName:      user.fullName,
        email:         user.email,
        organization:  user.organization,
        wazuhIp:       user.wazuhIp,
        wazuhUser:     user.wazuhUser,
        hasWazuhCreds: !!(user.wazuhUser && user.wazuhPassword),
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

/* ─────────────────────────────────────────────
   PATCH /api/auth/wazuh-credentials  (protected)
   Body: { wazuhIp, indexerUser, indexerPassword, apiUser, apiPassword }
   ───────────────────────────────────────────── */
router.patch('/wazuh-credentials', authMiddleware, async (req, res) => {
  try {
    const { wazuhIp, indexerUser, indexerPassword, apiUser, apiPassword } = req.body;

    if (!wazuhIp || !indexerUser || !indexerPassword) {
      return res.status(400).json({ message: 'Wazuh IP, Indexer user, and Indexer password are required.' });
    }

    await updateWazuhCreds(req.user.id, {
      wazuhIp,
      wazuhUser:        indexerUser,
      wazuhPassword:    encrypt(indexerPassword),
      wazuhApiUser:     apiUser     || '',
      wazuhApiPassword: apiPassword ? encrypt(apiPassword) : '',
    });

    res.json({ message: 'Wazuh credentials updated.' });
  } catch (err) {
    console.error('wazuh-credentials error:', err);
    res.status(500).json({ message: 'Server error.' });
  }
});

/* ─────────────────────────────────────────────
   POST /api/auth/test-wazuh  (protected)
   Body: { wazuhIp, indexerUser, indexerPassword, apiUser, apiPassword }
   Tests both Indexer and Manager API connectivity.
   ───────────────────────────────────────────── */
router.post('/test-wazuh', authMiddleware, async (req, res) => {
  const { wazuhIp, indexerUser, indexerPassword, apiUser, apiPassword } = req.body;

  if (!wazuhIp) return res.status(400).json({ message: 'Wazuh IP is required.' });

  function httpsGet(host, port, path, headers, timeoutMs = 8000) {
    return new Promise((resolve) => {
      const req = https.request(
        { hostname: host, port, path, method: 'GET', headers, timeout: timeoutMs, rejectUnauthorized: false },
        (r) => { let d = ''; r.on('data', c => d += c); r.on('end', () => resolve({ status: r.statusCode, body: d })); }
      );
      req.on('error',   () => resolve({ status: 0, body: 'connection_refused' }));
      req.on('timeout', () => { req.destroy(); resolve({ status: 0, body: 'timeout' }); });
      req.end();
    });
  }

  function httpsPost(host, port, path, headers, timeoutMs = 8000) {
    return new Promise((resolve) => {
      const req = https.request(
        { hostname: host, port, path, method: 'POST', headers, timeout: timeoutMs, rejectUnauthorized: false },
        (r) => { let d = ''; r.on('data', c => d += c); r.on('end', () => resolve({ status: r.statusCode, body: d })); }
      );
      req.on('error',   () => resolve({ status: 0, body: 'connection_refused' }));
      req.on('timeout', () => { req.destroy(); resolve({ status: 0, body: 'timeout' }); });
      req.end();
    });
  }

  const results = { indexer: null, manager: null };

  // Test Indexer (port 9200)
  if (indexerUser && indexerPassword) {
    const auth = 'Basic ' + Buffer.from(`${indexerUser}:${indexerPassword}`).toString('base64');
    const r    = await httpsGet(wazuhIp, 9200, '/', { 'Authorization': auth });
    if (r.status === 0) {
      results.indexer = { ok: false, error: r.body === 'timeout' ? 'Connection timed out' : 'Connection refused — check IP and that port 9200 is open' };
    } else if (r.status === 401) {
      results.indexer = { ok: false, error: 'Invalid indexer credentials' };
    } else if (r.status === 200) {
      results.indexer = { ok: true };
    } else {
      results.indexer = { ok: false, error: `Unexpected HTTP ${r.status}` };
    }
  }

  // Test Manager API (port 55000)
  if (apiUser && apiPassword) {
    const auth = 'Basic ' + Buffer.from(`${apiUser}:${apiPassword}`).toString('base64');
    const r    = await httpsPost(wazuhIp, 55000, '/security/user/authenticate', { 'Authorization': auth, 'Content-Type': 'application/json' });
    if (r.status === 0) {
      results.manager = { ok: false, error: r.body === 'timeout' ? 'Connection timed out' : 'Connection refused — check IP and that port 55000 is open' };
    } else if (r.status === 401) {
      results.manager = { ok: false, error: 'Invalid Manager API credentials' };
    } else if (r.status === 200) {
      results.manager = { ok: true };
    } else {
      results.manager = { ok: false, error: `Unexpected HTTP ${r.status}` };
    }
  }

  const allOk = Object.values(results).every(r => r === null || r.ok);
  res.json({ ok: allOk, results });
});

module.exports = router;
