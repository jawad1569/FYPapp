/* ========================================
   WAZUHBOT — Sentinel Panel
   Live Wazuh data + Gmail email alerts
   ======================================== */

let sentinelActive   = false;
let sentinelTab      = 'offenses';
let logInterval      = null;
let dataInterval     = null;
let liveLogInterval  = null;
let aiAnalysisInterval = null;

/* ── API Config ── */
const SENTINEL_API = window.location.hostname === 'localhost'
  ? 'http://localhost:5000/api'
  : '/api';

/* ── Live data (populated from Wazuh; falls back to demo) ── */
let liveOffenses  = [];
let liveAgents    = [];
let usingDemoData = false;
let dataLoaded    = false;

/* ── Configurable Intervals (ms) — persisted in localStorage ── */
const DEFAULT_INTERVALS = {
  logStream:    1000,
  epsUpdate:    2000,
  offenseCheck: 30000,
  sourceCheck:  60000,
  aiAnalysis:   300000,
};

function loadIntervals() {
  try {
    const stored = JSON.parse(localStorage.getItem('wazuhbot-sentinel-intervals'));
    return { ...DEFAULT_INTERVALS, ...stored };
  } catch { return { ...DEFAULT_INTERVALS }; }
}

function saveIntervals(intervals) {
  localStorage.setItem('wazuhbot-sentinel-intervals', JSON.stringify(intervals));
}

let intervals = loadIntervals();

/* ── Email Alert Settings ── */
function isEmailAlertsEnabled() {
  return localStorage.getItem('wazuhbot-email-alerts') === 'true';
}

function setEmailAlertsEnabled(enabled) {
  localStorage.setItem('wazuhbot-email-alerts', enabled ? 'true' : 'false');
}

let alertedOffenseIds = new Set();

/* ── Dismissed Offenses (persisted in localStorage) ── */
function loadDismissedOffenses() {
  try { return new Set(JSON.parse(localStorage.getItem('wazuhbot-dismissed-offenses') || '[]')); }
  catch { return new Set(); }
}
function saveDismissedOffenses() {
  localStorage.setItem('wazuhbot-dismissed-offenses', JSON.stringify([...dismissedOffenseIds]));
}
let dismissedOffenseIds = loadDismissedOffenses();

function visibleOffenses() {
  return liveOffenses.filter(o => !dismissedOffenseIds.has(String(o.id)));
}

function dismissOffense(id) {
  dismissedOffenseIds.add(String(id));
  saveDismissedOffenses();
  closeDetailModal();
  renderSidebarList();
  renderDashboardCards();
  updateBadges();
}

/* ── Demo fallback data ── */
const DEMO_OFFENSES = [
  { id: 1, name: 'SSH Brute Force Attack',      severity: 'critical', source: '192.168.1.45', count: 142, ago: 2  },
  { id: 2, name: 'Port Scan Detected',           severity: 'high',     source: '10.0.0.23',   count: 78,  ago: 5  },
  { id: 3, name: 'Malware C2 Communication',     severity: 'critical', source: '172.16.0.8',  count: 23,  ago: 8  },
  { id: 4, name: 'Suspicious Admin Login',       severity: 'medium',   source: '10.0.1.100',  count: 5,   ago: 12 },
  { id: 5, name: 'Privilege Escalation Attempt', severity: 'high',     source: '192.168.0.55',count: 3,   ago: 15 },
  { id: 6, name: 'Lateral Movement',             severity: 'critical', source: '10.0.2.77',   count: 11,  ago: 20 },
];

const DEMO_AGENTS = [
  { id: 1, name: 'Windows-DC-01',  status: 'active',   type: 'Windows Event Log',  eps: 245 },
  { id: 2, name: 'Linux-Web-01',   status: 'active',   type: 'Syslog',             eps: 87  },
  { id: 3, name: 'Firewall-FW-01', status: 'error',    type: 'Firewall Log',       eps: 0   },
  { id: 4, name: 'Switch-CORE-01', status: 'active',   type: 'SNMP Trap',          eps: 34  },
  { id: 5, name: 'Linux-DB-01',    status: 'inactive', type: 'Syslog',             eps: 0   },
  { id: 6, name: 'Windows-WS-05',  status: 'active',   type: 'Windows Event Log',  eps: 12  },
  { id: 7, name: 'Apache-Web-02',  status: 'active',   type: 'Apache Access Log',  eps: 56  },
];

const LOG_TEMPLATES = [
  { level: 'CRITICAL', color: 'critical', msg: s => `Brute force from ${s} — 150 failed logins`       },
  { level: 'HIGH',     color: 'high',     msg: s => `Port scan detected originating from ${s}`        },
  { level: 'CRITICAL', color: 'critical', msg: s => `Malware signature match on ${s}`                 },
  { level: 'HIGH',     color: 'high',     msg: s => `Privilege escalation attempt by user on ${s}`    },
  { level: 'MEDIUM',   color: 'medium',   msg: s => `Unusual authentication attempt on ${s}`          },
  { level: 'MEDIUM',   color: 'medium',   msg: s => `Repeated failed logins from ${s}`                },
  { level: 'LOW',      color: 'low',      msg: s => `Configuration change detected on ${s}`           },
  { level: 'INFO',     color: 'info',     msg: s => `Agent heartbeat received from ${s}`              },
  { level: 'INFO',     color: 'info',     msg: s => `Successful admin login from ${s}`                },
  { level: 'HIGH',     color: 'high',     msg: s => `Lateral movement detected from ${s}`             },
];

const IP_POOL = [
  '192.168.1.45', '10.0.0.23', '172.16.0.8',
  '10.0.1.100',   'DC-01',     'WEB-01',
  'DB-01',        '10.0.2.77', '192.168.0.55',
];

const rand    = arr => arr[Math.floor(Math.random() * arr.length)];
const nowTime = ()  => new Date().toLocaleTimeString('en-US', { hour12: false });

function authToken() {
  return localStorage.getItem('wazuhbot-token');
}

/* ══════════════════════════════════════════════
   LIVE DATA FETCH
   ══════════════════════════════════════════════ */

async function fetchLiveData() {
  const token = authToken();
  if (!token) {
    usingDemoData = true;
    liveOffenses  = DEMO_OFFENSES.slice();
    liveAgents    = DEMO_AGENTS.slice();
    dataLoaded    = true;
    return;
  }

  try {
    const [offRes, agRes] = await Promise.all([
      fetch(`${SENTINEL_API}/sentinel/offenses?minutes_ago=120`, {
        headers: { 'Authorization': `Bearer ${token}` },
      }),
      fetch(`${SENTINEL_API}/sentinel/agents`, {
        headers: { 'Authorization': `Bearer ${token}` },
      }),
    ]);

    let anyFailed = false;

    if (offRes.ok) {
      const data   = await offRes.json();
      liveOffenses = data.offenses || [];
    } else {
      liveOffenses = DEMO_OFFENSES.slice();
      anyFailed    = true;
    }

    if (agRes.ok) {
      const data = await agRes.json();
      liveAgents = data.agents || [];
    } else {
      liveAgents = DEMO_AGENTS.slice();
      anyFailed  = true;
    }

    usingDemoData = anyFailed;
  } catch {
    usingDemoData = true;
    liveOffenses  = DEMO_OFFENSES.slice();
    liveAgents    = DEMO_AGENTS.slice();
  }

  dataLoaded = true;
}

async function fetchRecentLogs() {
  const token = authToken();
  if (!token) return;

  const feed = document.getElementById('sentinelLogFeed');
  if (!feed) return;

  try {
    const res = await fetch(`${SENTINEL_API}/sentinel/recent-logs?size=20`, {
      headers: { 'Authorization': `Bearer ${token}` },
    });
    if (!res.ok) {
      if (!feed.children.length) showLogPlaceholder(feed, 'Could not reach Wazuh Indexer for logs.');
      return;
    }

    const data = await res.json();
    if (!data.logs?.length) {
      if (!feed.children.length) showLogPlaceholder(feed, 'No recent log events found in Wazuh.');
      return;
    }

    // Remove placeholder if present
    const placeholder = feed.querySelector('.log-placeholder');
    if (placeholder) placeholder.remove();

    // Prepend newest-first (backend returns oldest-first)
    for (const log of [...data.logs].reverse()) {
      const ts = log.timestamp
        ? new Date(log.timestamp).toLocaleTimeString('en-US', { hour12: false })
        : nowTime();
      const entry = document.createElement('div');
      entry.className = `log-entry log-entry--${log.color}`;
      entry.innerHTML = `
        <div class="log-top">
          <span class="log-time">${ts}</span>
          <span class="log-level log-level--${log.color}">${log.level}</span>
        </div>
        <div class="log-msg">${log.message} <span class="log-src">[${log.source}]</span></div>
      `;
      feed.prepend(entry);
    }
    while (feed.children.length > 80) feed.removeChild(feed.lastChild);
  } catch { /* silent — live log fetch is best-effort */ }
}

function showLogPlaceholder(feed, msg) {
  if (feed.querySelector('.log-placeholder')) return;
  const el = document.createElement('div');
  el.className = 'log-placeholder';
  el.textContent = msg;
  feed.appendChild(el);
}

/* ══════════════════════════════════════════════
   DETAIL MODAL — offense & agent click-through
   ══════════════════════════════════════════════ */
function getOrCreateDetailModal() {
  let overlay = document.getElementById('sentinelDetailOverlay');
  if (!overlay) {
    overlay = document.createElement('div');
    overlay.id        = 'sentinelDetailOverlay';
    overlay.className = 'sentinel-detail-overlay';
    overlay.innerHTML = `
      <div class="sentinel-detail-modal">
        <button class="sentinel-detail-close" id="sentinelDetailClose">×</button>
        <div id="sentinelDetailContent"></div>
      </div>
    `;
    document.body.appendChild(overlay);
    overlay.addEventListener('click', e => { if (e.target === overlay) closeDetailModal(); });
    document.getElementById('sentinelDetailClose').addEventListener('click', closeDetailModal);
  }
  return overlay;
}

function closeDetailModal() {
  const overlay = document.getElementById('sentinelDetailOverlay');
  if (overlay) overlay.classList.remove('active');
}

function showOffenseDetail(offense) {
  if (!offense) return;
  const overlay = getOrCreateDetailModal();
  document.getElementById('sentinelDetailContent').innerHTML = `
    <div class="detail-header">
      <div class="sentinel-list-dot sentinel-dot--${offense.severity}" style="width:10px;height:10px;flex-shrink:0"></div>
      <div class="detail-title">${offense.name}</div>
      <span class="sentinel-list-sev sentinel-sev--${offense.severity}">${offense.severity.toUpperCase()}</span>
    </div>
    <div class="detail-body">
      <div class="detail-row"><span class="detail-label">Source IP</span><span class="detail-value">${offense.source || '—'}</span></div>
      <div class="detail-row"><span class="detail-label">Agent</span><span class="detail-value">${offense.agent || '—'}</span></div>
      <div class="detail-row"><span class="detail-label">Event count</span><span class="detail-value">${offense.count}</span></div>
      <div class="detail-row"><span class="detail-label">First seen</span><span class="detail-value">${offense.ago}m ago</span></div>
      ${offense.ruleId ? `<div class="detail-row"><span class="detail-label">Rule ID</span><span class="detail-value">${offense.ruleId}</span></div>` : ''}
    </div>
    <button class="sentinel-dismiss-action" id="detailDismissBtn">Dismiss Offense</button>
  `;
  document.getElementById('detailDismissBtn').onclick = () => dismissOffense(offense.id);
  overlay.classList.add('active');
}

function showAgentDetail(agent) {
  if (!agent) return;
  const overlay = getOrCreateDetailModal();
  document.getElementById('sentinelDetailContent').innerHTML = `
    <div class="detail-header">
      <div class="sentinel-list-dot sentinel-dot--${agent.status}" style="width:10px;height:10px;flex-shrink:0"></div>
      <div class="detail-title">${agent.name}</div>
      <span class="sentinel-list-sev sentinel-sev--${agent.status}">${agent.status.toUpperCase()}</span>
    </div>
    <div class="detail-body">
      <div class="detail-row"><span class="detail-label">Agent ID</span><span class="detail-value">${agent.id || '—'}</span></div>
      <div class="detail-row"><span class="detail-label">IP Address</span><span class="detail-value">${agent.ip && agent.ip !== 'N/A' ? agent.ip : '—'}</span></div>
      <div class="detail-row"><span class="detail-label">Type</span><span class="detail-value">${agent.type || '—'}</span></div>
      <div class="detail-row"><span class="detail-label">Events/sec</span><span class="detail-value">${agent.eps || 0} EPS</span></div>
      ${agent.version ? `<div class="detail-row"><span class="detail-label">Version</span><span class="detail-value">${agent.version}</span></div>` : ''}
      ${agent.lastSeen ? `<div class="detail-row"><span class="detail-label">Last seen</span><span class="detail-value">${new Date(agent.lastSeen).toLocaleString()}</span></div>` : ''}
    </div>
  `;
  overlay.classList.add('active');
}

/* ── Manual refresh ── */
async function refreshSentinelData() {
  const btn = document.getElementById('sentinelRefreshBtn');
  if (!btn || btn.disabled) return;

  btn.disabled = true;
  btn.classList.add('sentinel-btn--spinning');

  await fetchLiveData();

  renderSidebarList();
  renderDashboardCards();
  updateBadges();
  checkAndAlertCritical();
  if (!usingDemoData) fetchRecentLogs();

  btn.disabled = false;
  btn.classList.remove('sentinel-btn--spinning');
}

/* ──────────────────────────────────────────
   Init — called from app.js once DOM ready
   ────────────────────────────────────────── */
let _onCloseCallback = null;

export function initSentinel({ onClose } = {}) {
  _onCloseCallback = onClose || null;

  updateBadges();

  fetchLiveData().then(() => {
    updateBadges();
    checkAndAlertCritical();
  });

  document.getElementById('sentinelBtn').addEventListener('click', openSentinel);
  document.getElementById('sentinelBackBtn').addEventListener('click', closeSentinel);
  document.getElementById('sentinelAiBtn').addEventListener('click', runAiAnalysis);
  document.getElementById('sentinelRefreshBtn').addEventListener('click', refreshSentinelData);

  document.querySelectorAll('.sentinel-tab').forEach(tab => {
    tab.addEventListener('click', () => {
      document.querySelectorAll('.sentinel-tab').forEach(t => t.classList.remove('active'));
      tab.classList.add('active');
      sentinelTab = tab.dataset.tab;
      renderSidebarList();
    });
  });

  initSentinelSettings();
}

/* ── Open / Close ── */
function openSentinel() {
  sentinelActive = true;

  document.getElementById('sentinelSidebarPanel').classList.add('active');
  document.getElementById('sentinelDashboard').style.display  = 'flex';
  document.getElementById('chatMessages').style.display       = 'none';
  document.querySelector('.input-area').style.display         = 'none';
  document.getElementById('sentinelLogPanel').classList.add('active');

  renderSidebarList();
  renderDashboardCards();
  startLogStream();
  startDataUpdates();

  // Refresh live data and re-render when ready
  fetchLiveData().then(() => {
    if (!sentinelActive) return;
    renderSidebarList();
    renderDashboardCards();
    updateBadges();
    checkAndAlertCritical();
    startLiveLogPoll();
    startAiAnalysisInterval();
  });
}

function closeSentinel() {
  sentinelActive = false;

  document.getElementById('sentinelSidebarPanel').classList.remove('active');
  document.getElementById('sentinelDashboard').style.display  = 'none';
  document.getElementById('chatMessages').style.display       = '';
  document.querySelector('.input-area').style.display         = '';
  document.getElementById('sentinelLogPanel').classList.remove('active');

  clearInterval(logInterval);
  clearInterval(dataInterval);
  clearInterval(liveLogInterval);
  clearInterval(aiAnalysisInterval);

  // Re-render the chat view so it's in sync with current state
  if (_onCloseCallback) _onCloseCallback();
}

/* ── Badge counts on button ── */
function updateBadges() {
  const visible      = visibleOffenses();
  const criticalHigh = visible.filter(o => o.severity === 'critical' || o.severity === 'high').length;
  const badSources   = liveAgents.filter(s => s.status !== 'active').length;

  document.getElementById('offenseCountBadge').textContent = visible.length;
  document.getElementById('sourceCountBadge').textContent  =
    badSources > 0 ? `${badSources} !` : `${liveAgents.length} OK`;

  const btn = document.getElementById('sentinelBtn');
  btn.classList.toggle('sentinel-btn--critical', criticalHigh > 0);
  btn.classList.toggle('sentinel-btn--ok',       criticalHigh === 0);
}

/* ── Sidebar list (offenses or agents) ── */
function renderSidebarList() {
  const list = document.getElementById('sentinelSidebarList');
  list.onclick = null;

  if (sentinelTab === 'offenses') {
    const visible = visibleOffenses();
    const dismissedCount = liveOffenses.length - visible.length;
    const resetLink = dismissedCount > 0
      ? `<div class="sentinel-dismissed-note">${dismissedCount} dismissed — <button class="sentinel-reset-dismissed" onclick="window._sentinelResetDismissed()">restore</button></div>`
      : '';

    if (!visible.length) {
      list.innerHTML = `<div class="sentinel-list-empty">No offenses in the last 2 hours</div>${resetLink}`;
      if (dismissedCount > 0) window._sentinelResetDismissed = resetDismissedOffenses;
      return;
    }
    list.innerHTML = visible.map((o, i) => `
      <div class="sentinel-list-item" data-type="offense" data-idx="${i}">
        <div class="sentinel-list-dot sentinel-dot--${o.severity}"></div>
        <div class="sentinel-list-info">
          <div class="sentinel-list-name">${o.name}</div>
          <div class="sentinel-list-meta">${o.source} &middot; ${o.ago}m ago &middot; ${o.count} event${o.count !== 1 ? 's' : ''}</div>
        </div>
        <span class="sentinel-list-sev sentinel-sev--${o.severity}">${o.severity.toUpperCase()}</span>
        <button class="sentinel-dismiss-btn" data-dismiss-id="${o.id}" title="Dismiss">×</button>
      </div>
    `).join('') + resetLink;
    window._sentinelResetDismissed = resetDismissedOffenses;

    list.onclick = (e) => {
      const dismissBtn = e.target.closest('.sentinel-dismiss-btn');
      if (dismissBtn) { dismissOffense(dismissBtn.dataset.dismissId); return; }
      const item = e.target.closest('[data-type="offense"]');
      if (item) showOffenseDetail(visibleOffenses()[parseInt(item.dataset.idx)]);
    };
  } else {
    if (!liveAgents.length) {
      list.innerHTML = '<div class="sentinel-list-empty">No agents found</div>';
      return;
    }
    list.innerHTML = liveAgents.map((s, i) => `
      <div class="sentinel-list-item" data-type="agent" data-idx="${i}">
        <div class="sentinel-list-dot sentinel-dot--${s.status}"></div>
        <div class="sentinel-list-info">
          <div class="sentinel-list-name">${s.name}</div>
          <div class="sentinel-list-meta">${s.type}${s.ip && s.ip !== 'N/A' ? ' &middot; ' + s.ip : ''} &middot; ${s.eps} EPS</div>
        </div>
        <span class="sentinel-list-sev sentinel-sev--${s.status}">${s.status.toUpperCase()}</span>
      </div>
    `).join('');

    list.onclick = (e) => {
      const item = e.target.closest('[data-type="agent"]');
      if (item) showAgentDetail(liveAgents[parseInt(item.dataset.idx)]);
    };
  }
}

function resetDismissedOffenses() {
  dismissedOffenseIds.clear();
  saveDismissedOffenses();
  renderSidebarList();
  renderDashboardCards();
  updateBadges();
}

/* ── Dashboard overview cards ── */
function renderDashboardCards() {
  const offenses      = visibleOffenses();
  const criticalCount = offenses.filter(o => o.severity === 'critical').length;
  const highCount     = offenses.filter(o => o.severity === 'high').length;
  const mediumCount   = offenses.filter(o => o.severity === 'medium').length;
  const activeSources   = liveAgents.filter(s => s.status === 'active').length;
  const errorSources    = liveAgents.filter(s => s.status === 'error').length;
  const inactiveSources = liveAgents.filter(s => s.status === 'inactive').length;
  const totalEps        = liveAgents.reduce((a, s) => a + (s.eps || 0), 0);
  const allClear        = criticalCount === 0 && highCount === 0 && errorSources === 0;

  const pill = document.getElementById('sentinelStatusPill');
  const sourceTag = !dataLoaded ? '' : usingDemoData ? ' (Demo)' : ' (Live)';
  pill.textContent = allClear ? `● ALL CLEAR${sourceTag}` : `● ${criticalCount} CRITICAL${sourceTag}`;
  pill.className   = `sentinel-status-pill ${allClear ? 'pill--ok' : 'pill--critical'}`;

  // Update log panel header to indicate live vs demo
  const logHeaderSpan = document.querySelector('.sentinel-log-header span:first-child');
  if (logHeaderSpan && dataLoaded) {
    logHeaderSpan.textContent = usingDemoData ? '⬤ Logs (Demo)' : '⬤ Live Logs';
  }

  const banner = document.getElementById('sentinelDemoBanner');
  if (dataLoaded && usingDemoData) {
    banner.innerHTML = `
      <div class="sentinel-demo-banner">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
        <div class="sentinel-demo-banner-text">
          <strong>Demo Mode</strong> — You are viewing sample data. Wazuh credentials are not configured for your account.
          To connect live data, update your Wazuh IP, username, and password in your account settings.
        </div>
      </div>
    `;
  } else {
    banner.innerHTML = '';
  }

  document.getElementById('sentinelCards').innerHTML = `
    <!-- Offenses card -->
    <div class="sentinel-card ${offenses.length > 0 ? 'card--alert' : 'card--ok'}">
      <div class="sentinel-card-header">
        <span class="sentinel-card-icon">⚡</span>
        <span class="sentinel-card-status ${offenses.length > 0 ? 'status--critical' : 'status--ok'}">
          ${offenses.length > 0 ? 'ACTIVE' : 'OK'}
        </span>
      </div>
      <div class="sentinel-card-count">${offenses.length}</div>
      <div class="sentinel-card-title">Offenses</div>
      <div class="sentinel-card-breakdown">
        <span class="breakdown-item sev-critical">${criticalCount} Critical</span>
        <span class="breakdown-item sev-high">${highCount} High</span>
        <span class="breakdown-item sev-medium">${mediumCount} Medium</span>
      </div>
    </div>

    <!-- Agents card -->
    <div class="sentinel-card ${errorSources > 0 ? 'card--alert' : inactiveSources > 0 ? 'card--warn' : 'card--ok'}">
      <div class="sentinel-card-header">
        <span class="sentinel-card-icon">📡</span>
        <span class="sentinel-card-status ${errorSources > 0 ? 'status--critical' : inactiveSources > 0 ? 'status--warn' : 'status--ok'}">
          ${errorSources > 0 ? 'ERROR' : inactiveSources > 0 ? 'WARNING' : 'OK'}
        </span>
      </div>
      <div class="sentinel-card-count">${liveAgents.length}</div>
      <div class="sentinel-card-title">Agents</div>
      <div class="sentinel-card-breakdown">
        <span class="breakdown-item sev-ok">${activeSources} Active</span>
        <span class="breakdown-item sev-high">${errorSources} Disconnected</span>
        <span class="breakdown-item sev-medium">${inactiveSources} Inactive</span>
      </div>
    </div>

    <!-- Events/sec card -->
    <div class="sentinel-card card--ok">
      <div class="sentinel-card-header">
        <span class="sentinel-card-icon">📊</span>
        <span class="sentinel-card-status status--ok">NORMAL</span>
      </div>
      <div class="sentinel-card-count" id="epsCard">${totalEps || activeSources * 30}</div>
      <div class="sentinel-card-title">Events / Second</div>
      <div class="sentinel-card-breakdown">
        <span class="breakdown-item sev-ok">Live ingestion rate</span>
      </div>
    </div>

    <!-- Critical Threats card -->
    <div class="sentinel-card ${criticalCount > 0 ? 'card--alert' : 'card--ok'}">
      <div class="sentinel-card-header">
        <span class="sentinel-card-icon">🔒</span>
        <span class="sentinel-card-status ${criticalCount > 0 ? 'status--critical' : 'status--ok'}">
          ${criticalCount > 0 ? 'THREAT' : 'SECURE'}
        </span>
      </div>
      <div class="sentinel-card-count">${criticalCount}</div>
      <div class="sentinel-card-title">Critical Threats</div>
      <div class="sentinel-card-breakdown">
        <span class="breakdown-item ${criticalCount > 0 ? 'sev-critical' : 'sev-ok'}">
          ${criticalCount > 0 ? 'Immediate action required' : 'No critical threats'}
        </span>
      </div>
    </div>
  `;
}

/* ══════════════════════════════════════════════
   SETTINGS MODAL (opened via button in header)
   ══════════════════════════════════════════════ */
function initSentinelSettings() {
  const overlay  = document.getElementById('sentinelSettingsOverlay');
  const closeBtn = document.getElementById('sentinelSettingsCloseBtn');
  const openBtn  = document.getElementById('sentinelSettingsBtn');

  const selectMap = {
    'ss-logStream':    'logStream',
    'ss-epsUpdate':    'epsUpdate',
    'ss-offenseCheck': 'offenseCheck',
    'ss-sourceCheck':  'sourceCheck',
    'ss-aiAnalysis':   'aiAnalysis',
  };

  // Set each select to the closest saved value
  for (const [id, key] of Object.entries(selectMap)) {
    const sel = document.getElementById(id);
    if (!sel) continue;
    sel.value = String(intervals[key]);
    // If exact value missing from options, pick the closest available
    if (!sel.value || sel.selectedIndex === -1) {
      const opts    = Array.from(sel.options).map(o => parseInt(o.value));
      const closest = opts.reduce((a, b) =>
        Math.abs(b - intervals[key]) < Math.abs(a - intervals[key]) ? b : a);
      sel.value = String(closest);
    }
    sel.addEventListener('change', (e) => {
      intervals[key] = parseInt(e.target.value);
      saveIntervals(intervals);
      if (sentinelActive) {
        clearInterval(logInterval);
        clearInterval(dataInterval);
        clearInterval(aiAnalysisInterval);
        startLogStream();
        startDataUpdates();
        startAiAnalysisInterval();
      }
    });
  }

  // Email toggle
  const emailToggle = document.getElementById('emailAlertToggle');
  if (emailToggle) {
    emailToggle.checked = isEmailAlertsEnabled();
    emailToggle.addEventListener('change', (e) => setEmailAlertsEnabled(e.target.checked));
  }

  // Open / close
  if (openBtn)  openBtn.addEventListener('click', () => overlay.classList.add('active'));
  if (closeBtn) closeBtn.addEventListener('click', () => overlay.classList.remove('active'));
  if (overlay)  overlay.addEventListener('click', (e) => {
    if (e.target === overlay) overlay.classList.remove('active');
  });
}

/* ══════════════════════════════════════════════
   EMAIL ALERT SYSTEM
   ══════════════════════════════════════════════ */
function getUserEmail() {
  try {
    const stored = JSON.parse(localStorage.getItem('wazuhbot-user'));
    return stored?.email || null;
  } catch { return null; }
}

async function sendAlertEmail(offense) {
  if (!isEmailAlertsEnabled()) return;
  const email = getUserEmail();
  if (!email) return;
  if (alertedOffenseIds.has(offense.id)) return;
  alertedOffenseIds.add(offense.id);

  try {
    await fetch(`${SENTINEL_API}/alerts/send`, {
      method:  'POST',
      headers: {
        'Content-Type':  'application/json',
        'Authorization': `Bearer ${authToken()}`,
      },
      body: JSON.stringify({
        email,
        alertData: {
          offenseName: offense.name,
          severity:    offense.severity,
          source:      offense.source,
          count:       offense.count,
          timestamp:   new Date().toISOString(),
          details:     `Detected ${offense.ago} minutes ago with ${offense.count} related events.`,
        },
      }),
    });
  } catch (err) {
    console.warn('Email alert failed:', err.message);
  }
}

function checkAndAlertCritical() {
  const criticals = liveOffenses.filter(o => o.severity === 'critical' || o.severity === 'high');
  criticals.forEach(offense => sendAlertEmail(offense));
}

/* ── Live log stream (synthetic — demo mode only) ── */
function startLogStream() {
  const feed = document.getElementById('sentinelLogFeed');

  function addSyntheticLog() {
    if (!usingDemoData) return;  // real Wazuh connected — skip synthetic entries
    const tmpl  = rand(LOG_TEMPLATES);
    const src   = rand(IP_POOL);
    const entry = document.createElement('div');
    entry.className = `log-entry log-entry--${tmpl.color}`;
    entry.innerHTML = `
      <div class="log-top">
        <span class="log-time">${nowTime()}</span>
        <span class="log-level log-level--${tmpl.color}">${tmpl.level}</span>
      </div>
      <div class="log-msg">${tmpl.msg(src)}</div>
    `;
    feed.prepend(entry);
    while (feed.children.length > 80) feed.removeChild(feed.lastChild);
    updateEps();
  }

  addSyntheticLog();
  logInterval = setInterval(addSyntheticLog, intervals.logStream);
}

/* ── Live log poll (real Wazuh logs — live mode only) ── */
function startLiveLogPoll() {
  clearInterval(liveLogInterval);
  if (usingDemoData) return;
  fetchRecentLogs();
  liveLogInterval = setInterval(() => {
    if (sentinelActive) fetchRecentLogs();
  }, 30000);
}

/* ── Auto AI analysis ── */
function startAiAnalysisInterval() {
  clearInterval(aiAnalysisInterval);
  if (usingDemoData) return;
  aiAnalysisInterval = setInterval(() => {
    if (sentinelActive) runAiAnalysis();
  }, intervals.aiAnalysis);
}

/* ── EPS jitter ── */
function startDataUpdates() {
  dataInterval = setInterval(() => {
    const el = document.getElementById('epsCard');
    if (!el) return;
    const baseEps    = liveAgents.reduce((a, s) => a + (s.eps || 0), 0);
    const activeCount = liveAgents.filter(s => s.status === 'active').length;
    const base   = baseEps > 0 ? baseEps : activeCount * 30;
    const jitter = Math.floor((Math.random() - 0.5) * 40);
    el.textContent = Math.max(0, base + jitter);
  }, intervals.epsUpdate);
}

function updateEps() {
  const baseEps     = liveAgents.reduce((a, s) => a + (s.eps || 0), 0);
  const activeCount = liveAgents.filter(s => s.status === 'active').length;
  const base   = baseEps > 0 ? baseEps : activeCount * 30;
  const jitter = Math.floor((Math.random() - 0.5) * 20);
  const el = document.getElementById('sentinelLogEps');
  if (el) el.textContent = Math.max(0, base + jitter) + ' EPS';
}

/* ══════════════════════════════════════════════
   AI ANALYSIS — uses real Wazuh network flows
   ══════════════════════════════════════════════ */

function generateSyntheticFlows() {
  // Normal benign traffic patterns only — used in demo mode when no Wazuh data is available
  return [
    { IN_BYTES: 1200,  OUT_BYTES: 900,   IN_PKTS: 12, OUT_PKTS: 10, PROTOCOL: 6,  L4_DST_PORT: 443,  L4_SRC_PORT: 51200, DURATION: 3,  TCP_FLAGS: 24 },
    { IN_BYTES: 800,   OUT_BYTES: 600,   IN_PKTS: 8,  OUT_PKTS: 7,  PROTOCOL: 6,  L4_DST_PORT: 443,  L4_SRC_PORT: 51201, DURATION: 2,  TCP_FLAGS: 24 },
    { IN_BYTES: 400,   OUT_BYTES: 300,   IN_PKTS: 4,  OUT_PKTS: 4,  PROTOCOL: 6,  L4_DST_PORT: 80,   L4_SRC_PORT: 51202, DURATION: 1,  TCP_FLAGS: 24 },
    { IN_BYTES: 500,   OUT_BYTES: 350,   IN_PKTS: 5,  OUT_PKTS: 5,  PROTOCOL: 6,  L4_DST_PORT: 443,  L4_SRC_PORT: 51203, DURATION: 2,  TCP_FLAGS: 24 },
    { IN_BYTES: 200,   OUT_BYTES: 150,   IN_PKTS: 3,  OUT_PKTS: 3,  PROTOCOL: 17, L4_DST_PORT: 53,   L4_SRC_PORT: 43100, DURATION: 0,  TCP_FLAGS: 0  },
    { IN_BYTES: 350,   OUT_BYTES: 280,   IN_PKTS: 4,  OUT_PKTS: 4,  PROTOCOL: 17, L4_DST_PORT: 53,   L4_SRC_PORT: 43101, DURATION: 0,  TCP_FLAGS: 0  },
    { IN_BYTES: 900,   OUT_BYTES: 700,   IN_PKTS: 9,  OUT_PKTS: 8,  PROTOCOL: 6,  L4_DST_PORT: 443,  L4_SRC_PORT: 51204, DURATION: 3,  TCP_FLAGS: 24 },
    { IN_BYTES: 600,   OUT_BYTES: 450,   IN_PKTS: 6,  OUT_PKTS: 6,  PROTOCOL: 6,  L4_DST_PORT: 80,   L4_SRC_PORT: 51205, DURATION: 2,  TCP_FLAGS: 24 },
    { IN_BYTES: 1100,  OUT_BYTES: 850,   IN_PKTS: 11, OUT_PKTS: 10, PROTOCOL: 6,  L4_DST_PORT: 443,  L4_SRC_PORT: 51206, DURATION: 4,  TCP_FLAGS: 24 },
    { IN_BYTES: 700,   OUT_BYTES: 500,   IN_PKTS: 7,  OUT_PKTS: 6,  PROTOCOL: 6,  L4_DST_PORT: 443,  L4_SRC_PORT: 51207, DURATION: 2,  TCP_FLAGS: 24 },
  ];
}

async function runAiAnalysis() {
  const btn = document.getElementById('sentinelAiBtn');
  if (!btn || btn.disabled) return;

  btn.disabled = true;
  btn.classList.add('ai-btn--loading');
  btn.querySelector('span').textContent = 'Analyzing…';

  const prev = document.getElementById('sentinelAiResultCard');
  if (prev) prev.remove();

  let flows      = [];
  let flowSource = 'synthetic';
  const token    = authToken();

  // Try to get real network flows from Wazuh
  if (token) {
    try {
      const flowRes = await fetch(`${SENTINEL_API}/sentinel/network-flows?minutes_ago=30`, {
        headers: { 'Authorization': `Bearer ${token}` },
      });
      if (flowRes.ok) {
        const flowData = await flowRes.json();
        if (flowData.flows && flowData.flows.length > 0) {
          flows      = flowData.flows;
          flowSource = 'wazuh';
        }
      }
    } catch { /* fall through to synthetic */ }
  }

  // Only use synthetic flows when no live data is available at all
  if (flows.length === 0) {
    flows      = generateSyntheticFlows();
    flowSource = 'synthetic';
  }

  try {
    const mlHeaders = { 'Content-Type': 'application/json' };
    if (token) mlHeaders['Authorization'] = `Bearer ${token}`;

    // Use backend proxy when authenticated, else try direct ML service
    const mlUrl = token
      ? `${SENTINEL_API}/ml/batch-predict`
      : 'http://localhost:5001/batch-predict';

    const res = await fetch(mlUrl, {
      method:  'POST',
      headers: mlHeaders,
      body:    JSON.stringify({ logs: flows }),
    });

    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    renderAiResultCard(data, null, flowSource);
  } catch (err) {
    renderAiResultCard(null, err.message, flowSource);
  } finally {
    btn.disabled = false;
    btn.classList.remove('ai-btn--loading');
    btn.querySelector('span').textContent = 'Run AI Analysis';
  }
}

function renderAiResultCard(data, errorMsg, flowSource) {
  const container = document.getElementById('sentinelCards');
  if (!container) return;

  const card = document.createElement('div');
  card.id        = 'sentinelAiResultCard';
  card.className = 'sentinel-ai-card';

  if (errorMsg) {
    card.innerHTML = `
      <div class="sentinel-ai-card-header">
        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/></svg>
        <span>AI Analysis</span>
        <span class="ai-card-badge ai-badge--error">ERROR</span>
      </div>
      <p class="ai-card-error">Could not reach ML service: ${errorMsg}</p>
      <p class="ai-card-hint">Make sure the inference server is running on port 5001.</p>
    `;
    card.classList.add('ai-card--error');
  } else {
    const { count, threat_count, normal_count, class_summary, results } = data;
    const srcLabel = flowSource === 'wazuh' ? 'Live Wazuh flows' : flowSource === 'mixed' ? 'Live + synthetic' : 'Synthetic flows';

    const classRows = Object.entries(class_summary)
      .sort((a, b) => b[1] - a[1])
      .map(([cls, n]) => {
        const isNorm = cls === 'Normal';
        const pct    = Math.round((n / count) * 100);
        return `
          <div class="ai-class-row">
            <span class="ai-class-dot ${isNorm ? 'dot--ok' : 'dot--threat'}"></span>
            <span class="ai-class-name">${cls}</span>
            <div class="ai-class-bar-wrap">
              <div class="ai-class-bar ${isNorm ? 'bar--ok' : 'bar--threat'}" style="width:${pct}%"></div>
            </div>
            <span class="ai-class-pct">${pct}%</span>
            <span class="ai-class-count">${n}</span>
          </div>`;
      }).join('');

    // Aggregate all threats by type with count + avg confidence
    const threatMap = {};
    results.forEach(r => {
      if (!r.is_threat) return;
      if (!threatMap[r.prediction]) threatMap[r.prediction] = { count: 0, totalConf: 0 };
      threatMap[r.prediction].count++;
      threatMap[r.prediction].totalConf += r.confidence;
    });
    const allThreatRows = Object.entries(threatMap)
      .map(([name, s]) => ({ name, count: s.count, avgConf: s.totalConf / s.count }))
      .sort((a, b) => b.count - a.count)
      .map(t => `
        <div class="ai-threat-row">
          <span class="ai-class-dot dot--threat"></span>
          <span class="ai-threat-name">${t.name}</span>
          <span class="ai-threat-count">${t.count} flow${t.count !== 1 ? 's' : ''}</span>
          <span class="ai-threat-conf">${(t.avgConf * 100).toFixed(1)}% avg confidence</span>
        </div>
      `).join('');

    const hasThreat  = threat_count > 0;
    const badgeClass = hasThreat ? 'ai-badge--threat' : 'ai-badge--ok';
    const badgeTxt   = hasThreat ? `${threat_count} THREATS` : 'ALL CLEAR';

    card.innerHTML = `
      <div class="sentinel-ai-card-header">
        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/><polyline points="3.27 6.96 12 12.01 20.73 6.96"/><line x1="12" y1="22.08" x2="12" y2="12"/></svg>
        <span>AI Analysis</span>
        <span class="ai-card-badge ${badgeClass}">${badgeTxt}</span>
        <span class="ai-card-ts">${new Date().toLocaleTimeString('en-US', { hour12: false })}</span>
      </div>

      <div class="ai-data-source">Data: ${srcLabel}</div>

      <div class="ai-summary-row">
        <div class="ai-summary-stat">
          <span class="ai-stat-val">${count}</span>
          <span class="ai-stat-lbl">Flows Analyzed</span>
        </div>
        <div class="ai-summary-stat ${hasThreat ? 'stat--threat' : ''}">
          <span class="ai-stat-val">${threat_count}</span>
          <span class="ai-stat-lbl">Threats Detected</span>
        </div>
        <div class="ai-summary-stat">
          <span class="ai-stat-val">${normal_count}</span>
          <span class="ai-stat-lbl">Normal</span>
        </div>
      </div>

      <div class="ai-class-list">${classRows}</div>

      ${hasThreat ? `
      <div class="ai-threats-section">
        <div class="ai-threats-title">All Detected Threats</div>
        ${allThreatRows}
      </div>` : ''}
    `;
    card.classList.toggle('ai-card--threat', hasThreat);
  }

  container.parentNode.appendChild(card);
}
