/**
 * Chat Routes — Proxy to Python Chatbot Service
 * Injects the authenticated user's Wazuh credentials into every proxied request.
 */

const express        = require('express');
const http           = require('http');
const authMiddleware = require('../middleware/auth');
const { findById }   = require('../models/User');
const { decrypt }    = require('../utils/crypto');

const router = express.Router();

const CHATBOT_HOST = process.env.CHATBOT_HOST || 'localhost';
const CHATBOT_PORT = process.env.CHATBOT_PORT || 5002;

/* ── Helper: proxy a request to the Python chatbot service ── */
function proxyToChatbot(path, method, body) {
  return new Promise((resolve, reject) => {
    const options = {
      hostname: CHATBOT_HOST,
      port:     CHATBOT_PORT,
      path,
      method,
      headers:  { 'Content-Type': 'application/json' },
      timeout:  120000,
    };

    const req = http.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        try {
          resolve({ status: res.statusCode, body: JSON.parse(data) });
        } catch {
          resolve({ status: res.statusCode, body: data });
        }
      });
    });

    req.on('error',   (err) => reject(err));
    req.on('timeout', ()    => { req.destroy(); reject(new Error('Chatbot service request timed out')); });

    if (body) req.write(JSON.stringify(body));
    req.end();
  });
}

/* ── GET /api/chat/health ── */
router.get('/health', async (_req, res) => {
  try {
    const result = await proxyToChatbot('/health', 'GET');
    res.status(result.status).json(result.body);
  } catch (err) {
    res.status(503).json({
      status:  'unreachable',
      error:   'Chatbot service is not running',
      hint:    'Start it with: python Backend/chatbot/chatbot_server.py',
      details: err.message,
    });
  }
});

/* ── POST /api/chat/message ── */
router.post('/message', authMiddleware, async (req, res) => {
  const { message, history, context } = req.body;

  if (!message || typeof message !== 'string') {
    return res.status(400).json({ error: 'message (string) is required' });
  }

  // Fetch the authenticated user's Wazuh credentials from DB
  let managerIp = '127.0.0.1';
  let indexerIp = '127.0.0.1';
  let idxUser   = '';
  let idxPass   = '';
  let apiUser   = '';
  let apiPass   = '';

  try {
    const user = await findById(req.user.id);
    if (user) {
      managerIp = user.wazuhIp        || '127.0.0.1';
      indexerIp = user.wazuhIndexerIp || managerIp;
      idxUser   = user.wazuhUser        || '';
      idxPass   = user.wazuhPassword    ? decrypt(user.wazuhPassword)    : '';
      apiUser   = user.wazuhApiUser     || '';
      apiPass   = user.wazuhApiPassword ? decrypt(user.wazuhApiPassword) : '';
    }
  } catch (err) {
    console.warn('Could not fetch Wazuh credentials for user:', err.message);
  }

  try {
    const result = await proxyToChatbot('/chat', 'POST', {
      message,
      history:          history  || [],
      context:          context  || {},
      wazuh_ip:         managerIp,
      wazuh_indexer_ip: indexerIp,
      wazuh_idx_user:   idxUser,
      wazuh_idx_pass:   idxPass,
      wazuh_api_user:   apiUser,
      wazuh_api_pass:   apiPass,
    });
    res.status(result.status).json(result.body);
  } catch (err) {
    res.status(503).json({
      error:   'Chatbot service unreachable',
      details: err.message,
      hint:    'Ensure chatbot_server.py is running on port ' + CHATBOT_PORT,
    });
  }
});

module.exports = router;
