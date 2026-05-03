/**
 * Sentinel Routes — Live Wazuh data endpoints
 * All routes are auth-protected; Wazuh credentials are fetched per-user.
 */

const express        = require('express');
const https          = require('https');
const authMiddleware = require('../middleware/auth');
const { findById }   = require('../models/User');
const { decrypt }    = require('../utils/crypto');

const router = express.Router();

// ── Helpers ──

function wazuhRequest(wazuhIp, port, path, method, headers, body, timeoutMs = 15000) {
  return new Promise((resolve, reject) => {
    const bodyStr = body ? (typeof body === 'string' ? body : JSON.stringify(body)) : null;
    const options = {
      hostname:           wazuhIp,
      port,
      path,
      method,
      headers:            { ...headers, ...(bodyStr ? { 'Content-Length': Buffer.byteLength(bodyStr) } : {}) },
      timeout:            timeoutMs,
      rejectUnauthorized: false,
    };

    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', chunk => { data += chunk; });
      res.on('end', () => {
        try   { resolve({ status: res.statusCode, body: JSON.parse(data) }); }
        catch { resolve({ status: res.statusCode, body: data }); }
      });
    });

    req.on('error',   reject);
    req.on('timeout', () => { req.destroy(); reject(new Error(`Wazuh timeout: ${path}`)); });
    if (bodyStr) req.write(bodyStr);
    req.end();
  });
}

async function getManagerToken(managerIp, wazuhUser, wazuhPass) {
  const auth   = Buffer.from(`${wazuhUser}:${wazuhPass}`).toString('base64');
  const result = await wazuhRequest(managerIp, 55000, '/security/user/authenticate', 'POST', {
    'Content-Type':  'application/json',
    'Authorization': `Basic ${auth}`,
  }, null);

  if (result.status === 200 && result.body?.data?.token) return result.body.data.token;
  throw new Error(`Manager auth failed (HTTP ${result.status})`);
}

async function getWazuhCreds(userId) {
  const user = await findById(userId);
  if (!user) throw new Error('User not found');
  if (!user.wazuhUser || !user.wazuhPassword) throw new Error('Wazuh credentials not configured');
  const managerIp = user.wazuhIp        || '127.0.0.1';
  const indexerIp = user.wazuhIndexerIp || managerIp;   // separate IP for indexer if set
  return {
    managerIp,
    indexerIp,
    indexerUser:  user.wazuhUser,
    indexerPass:  decrypt(user.wazuhPassword),
    apiUser:      user.wazuhApiUser     || user.wazuhUser,
    apiPass:      user.wazuhApiPassword ? decrypt(user.wazuhApiPassword) : decrypt(user.wazuhPassword),
  };
}

function levelToSeverity(level) {
  if (level >= 12) return 'critical';
  if (level >= 10) return 'high';
  if (level >=  7) return 'medium';
  return 'low';
}

// ── Routes ──

/* GET /api/sentinel/offenses */
router.get('/offenses', authMiddleware, async (req, res) => {
  try {
    const { indexerIp, indexerUser, indexerPass } = await getWazuhCreds(req.user.id);
    const auth     = Buffer.from(`${indexerUser}:${indexerPass}`).toString('base64');
    const minutes  = parseInt(req.query.minutes_ago) || 120;
    const fromTime = new Date(Date.now() - minutes * 60_000).toISOString();

    const query = {
      size: 100,
      sort: [{ '@timestamp': { order: 'desc' } }],
      query: {
        bool: {
          filter: [
            { range: { '@timestamp': { gte: fromTime } } },
            { range: { 'rule.level': { gte: 7 } } },
          ],
        },
      },
      _source: ['@timestamp', 'agent.name', 'agent.ip', 'rule.description',
                'rule.level', 'rule.id', 'data.srcip', 'location'],
    };

    const result = await wazuhRequest(
      indexerIp, 9200, '/wazuh-alerts-*/_search', 'POST',
      { 'Content-Type': 'application/json', 'Authorization': `Basic ${auth}` },
      query,
    );

    if (result.status !== 200) {
      return res.status(502).json({ error: 'Wazuh Indexer error', details: result.body });
    }

    const hits    = result.body?.hits?.hits || [];
    const grouped = {};

    for (const hit of hits) {
      const s    = hit._source;
      const src  = s.data?.srcip || s.agent?.ip || s.agent?.name || 'Unknown';
      const name = s.rule?.description || 'Unknown Alert';
      const key  = `${name}|${src}`;
      const tsMs = new Date(s['@timestamp'] || Date.now()).getTime();
      const ago  = Math.round((Date.now() - tsMs) / 60_000);

      if (grouped[key]) {
        grouped[key].count++;
        grouped[key].ago = Math.min(grouped[key].ago, ago);
      } else {
        grouped[key] = {
          id:       hit._id,
          name,
          severity: levelToSeverity(s.rule?.level || 0),
          source:   src,
          count:    1,
          ago,
          ruleId:   s.rule?.id,
          agent:    s.agent?.name,
        };
      }
    }

    res.json({ offenses: Object.values(grouped), total: hits.length });
  } catch (err) {
    console.error('[sentinel/offenses]', err.message);
    res.status(503).json({ error: err.message });
  }
});

/* GET /api/sentinel/agents */
router.get('/agents', authMiddleware, async (req, res) => {
  try {
    const { managerIp, apiUser, apiPass } = await getWazuhCreds(req.user.id);
    const token = await getManagerToken(managerIp, apiUser, apiPass);

    const result = await wazuhRequest(
      managerIp, 55000,
      '/agents?limit=50&select=id,name,ip,status,os.name,version,lastKeepAlive',
      'GET',
      { 'Authorization': `Bearer ${token}` },
      null,
    );

    if (result.status !== 200) {
      return res.status(502).json({ error: 'Wazuh Manager error', details: result.body });
    }

    const items  = result.body?.data?.affected_items || [];
    const agents = items
      .filter(a => a.id !== '000')
      .map(a => ({
        id:       a.id,
        name:     a.name || `Agent-${a.id}`,
        ip:       a.ip   || 'N/A',
        status:   a.status === 'active' ? 'active' : a.status === 'disconnected' ? 'error' : 'inactive',
        type:     a.os?.name || 'Wazuh Agent',
        eps:      0,
        version:  a.version,
        lastSeen: a.lastKeepAlive,
      }));

    res.json({ agents });
  } catch (err) {
    console.error('[sentinel/agents]', err.message);
    res.status(503).json({ error: err.message });
  }
});

/* GET /api/sentinel/recent-logs */
router.get('/recent-logs', authMiddleware, async (req, res) => {
  try {
    const { indexerIp, indexerUser, indexerPass } = await getWazuhCreds(req.user.id);
    const auth = Buffer.from(`${indexerUser}:${indexerPass}`).toString('base64');
    const size = Math.min(parseInt(req.query.size) || 20, 50);

    const query = {
      size,
      sort:    [{ '@timestamp': { order: 'desc' } }],
      query:   { match_all: {} },
      _source: ['@timestamp', 'agent.name', 'agent.ip', 'rule.description', 'rule.level', 'data.srcip'],
    };

    const result = await wazuhRequest(
      indexerIp, 9200, '/wazuh-alerts-*/_search', 'POST',
      { 'Content-Type': 'application/json', 'Authorization': `Basic ${auth}` },
      query,
    );

    if (result.status !== 200) {
      return res.status(502).json({ error: 'Wazuh Indexer error', details: result.body });
    }

    const hits = result.body?.hits?.hits || [];
    const logs = hits.map(hit => {
      const s        = hit._source;
      const level    = s.rule?.level || 0;
      const severity = levelToSeverity(level);
      const colorMap = { critical: 'critical', high: 'high', medium: 'medium', low: 'low' };
      return {
        timestamp: s['@timestamp'],
        level:     severity.toUpperCase(),
        color:     colorMap[severity] || 'info',
        source:    s.data?.srcip || s.agent?.ip || s.agent?.name || 'Unknown',
        message:   s.rule?.description || 'Alert triggered',
      };
    });

    res.json({ logs });
  } catch (err) {
    console.error('[sentinel/recent-logs]', err.message);
    res.status(503).json({ error: err.message });
  }
});

/* GET /api/sentinel/network-flows */
router.get('/network-flows', authMiddleware, async (req, res) => {
  try {
    const { indexerIp, indexerUser, indexerPass } = await getWazuhCreds(req.user.id);
    const auth    = Buffer.from(`${indexerUser}:${indexerPass}`).toString('base64');
    const minutes = parseInt(req.query.minutes_ago) || 30;
    const from    = new Date(Date.now() - minutes * 60_000).toISOString();

    const query = {
      size:  100,
      sort:  [{ '@timestamp': { order: 'desc' } }],
      query: {
        bool: {
          filter:  [{ range: { '@timestamp': { gte: from } } }],
          should:  [
            { exists: { field: 'data.srcip' } },
            { exists: { field: 'data.src_ip' } },
            { term:   { 'rule.groups': 'network' } },
            { term:   { 'rule.groups': 'firewall' } },
          ],
          minimum_should_match: 1,
        },
      },
      _source: [
        '@timestamp', 'rule.level', 'data.srcip', 'data.dstip',
        'data.srcport', 'data.dstport', 'data.proto',
        'data.bytes', 'data.packets',
      ],
    };

    const result = await wazuhRequest(
      indexerIp, 9200, '/wazuh-alerts-*/_search', 'POST',
      { 'Content-Type': 'application/json', 'Authorization': `Basic ${auth}` },
      query,
    );

    if (result.status !== 200) {
      return res.status(502).json({ error: 'Wazuh Indexer error', details: result.body });
    }

    const hits  = result.body?.hits?.hits || [];
    const flows = hits.map(hit => {
      const s = hit._source;
      const d = s.data || {};
      return {
        IN_BYTES:    parseInt(d.bytes    || d.in_bytes  || 0),
        OUT_BYTES:   parseInt(d.out_bytes || 0),
        IN_PKTS:     parseInt(d.packets  || d.in_pkts  || 1),
        OUT_PKTS:    parseInt(d.out_pkts || 1),
        PROTOCOL:    (d.proto === 'udp' || d.proto === '17') ? 17 : 6,
        L4_DST_PORT: parseInt(d.dstport  || d.dst_port || 0),
        L4_SRC_PORT: parseInt(d.srcport  || d.src_port || 0),
        DURATION:    1,
        TCP_FLAGS:   (s.rule?.level || 0) >= 10 ? 2 : 24,
      };
    });

    res.json({ flows, count: flows.length, source: flows.length > 0 ? 'wazuh' : 'empty' });
  } catch (err) {
    console.error('[sentinel/network-flows]', err.message);
    res.status(503).json({ error: err.message });
  }
});

module.exports = router;
