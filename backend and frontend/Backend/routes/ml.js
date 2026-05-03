/**
 * ML Inference Proxy Routes
 * Forwards requests from the Express backend to the Python Flask inference service.
 * Later: SLM chatbot will consume these predictions.
 */

const express = require('express');
const http    = require('http');
const router  = express.Router();

const ML_SERVICE_HOST = process.env.ML_HOST || 'localhost';
const ML_SERVICE_PORT = process.env.ML_PORT || 5001;

/* ── Helper: proxy a request to the Python ML service ── */
function proxyToML(path, method, body) {
  return new Promise((resolve, reject) => {
    const options = {
      hostname: ML_SERVICE_HOST,
      port:     ML_SERVICE_PORT,
      path,
      method,
      headers:  { 'Content-Type': 'application/json' },
      timeout:  30000,
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

    req.on('error', (err) => {
      reject(err);
    });

    req.on('timeout', () => {
      req.destroy();
      reject(new Error('ML service request timed out'));
    });

    if (body) {
      req.write(JSON.stringify(body));
    }
    req.end();
  });
}

/* ── GET /api/ml/health — ML service health check ── */
router.get('/health', async (_req, res) => {
  try {
    const result = await proxyToML('/health', 'GET');
    res.status(result.status).json(result.body);
  } catch (err) {
    res.status(503).json({
      status: 'unreachable',
      error:  'ML inference service is not running',
      hint:   `Start it with: python Backend/ml_service/inference_server.py`,
      details: err.message,
    });
  }
});

/* ── GET /api/ml/model-info — model metadata ── */
router.get('/model-info', async (_req, res) => {
  try {
    const result = await proxyToML('/model-info', 'GET');
    res.status(result.status).json(result.body);
  } catch (err) {
    res.status(503).json({ error: 'ML service unreachable', details: err.message });
  }
});

/* ── POST /api/ml/predict — classify a single log/flow ── */
router.post('/predict', async (req, res) => {
  try {
    const result = await proxyToML('/predict', 'POST', req.body);
    res.status(result.status).json(result.body);
  } catch (err) {
    res.status(503).json({ error: 'ML service unreachable', details: err.message });
  }
});

/* ── POST /api/ml/batch-predict — classify multiple logs ── */
router.post('/batch-predict', async (req, res) => {
  try {
    const result = await proxyToML('/batch-predict', 'POST', req.body);
    res.status(result.status).json(result.body);
  } catch (err) {
    res.status(503).json({ error: 'ML service unreachable', details: err.message });
  }
});

module.exports = router;
