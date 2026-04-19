/**
 * Chat Routes — Proxy to Python Chatbot Service
 * Forwards chat messages from the Express backend to the chatbot orchestrator.
 */

const express = require('express');
const http    = require('http');
const router  = express.Router();

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
      timeout:  120000,  // 2 min timeout for LLM inference
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

    if (body) {
      req.write(JSON.stringify(body));
    }
    req.end();
  });
}

/* ── GET /api/chat/health — chatbot service health check ── */
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

/* ── POST /api/chat/message — send a chat message ── */
router.post('/message', async (req, res) => {
  const { message, history, context } = req.body;

  if (!message || typeof message !== 'string') {
    return res.status(400).json({ error: 'message (string) is required' });
  }

  try {
    const result = await proxyToChatbot('/chat', 'POST', {
      message,
      history: history || [],
      context: context || {},
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
