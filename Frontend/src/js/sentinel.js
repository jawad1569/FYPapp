/* ========================================
   WAZUHBOT — Sentinel Panel
   Configurable intervals + Gmail email alerts
   ======================================== */

let sentinelActive = false;
let sentinelTab    = 'offenses';
let logInterval    = null;
let dataInterval   = null;

/* ── API Config ── */
const SENTINEL_API = window.location.hostname === 'localhost'
  ? 'http://localhost:5000/api'
  : '/api';

/* ── Configurable Intervals (ms) — persisted in localStorage ── */
const DEFAULT_INTERVALS = {
  logStream:      1200,    // Live log stream refresh (ms)
  epsUpdate:      2000,    // EPS jitter update (ms)
  offenseCheck:   30000,   // Check for new offenses (ms)
  sourceCheck:    60000,   // Check log source status (ms)
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

// Track already-alerted offenses to avoid duplicate emails
let alertedOffenseIds = new Set();

/* ── Mock Data ── */
const OFFENSES = [
  { id: 1, name: 'SSH Brute Force Attack',      severity: 'critical', source: '192.168.1.45', count: 142, ago: 2  },
  { id: 2, name: 'Port Scan Detected',           severity: 'high',     source: '10.0.0.23',   count: 78,  ago: 5  },
  { id: 3, name: 'Malware C2 Communication',     severity: 'critical', source: '172.16.0.8',  count: 23,  ago: 8  },
  { id: 4, name: 'Suspicious Admin Login',       severity: 'medium',   source: '10.0.1.100',  count: 5,   ago: 12 },
  { id: 5, name: 'Privilege Escalation Attempt', severity: 'high',     source: '192.168.0.55',count: 3,   ago: 15 },
  { id: 6, name: 'Lateral Movement',             severity: 'critical', source: '10.0.2.77',   count: 11,  ago: 20 },
];

const LOG_SOURCES = [
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

/* ──────────────────────────────────────────
   Init — called from app.js once DOM ready
   ────────────────────────────────────────── */
export function initSentinel() {
  updateBadges();
  checkAndAlertCritical();   // check on load

  document.getElementById('sentinelBtn').addEventListener('click', openSentinel);
  document.getElementById('sentinelBackBtn').addEventListener('click', closeSentinel);

  document.querySelectorAll('.sentinel-tab').forEach(tab => {
    tab.addEventListener('click', () => {
      document.querySelectorAll('.sentinel-tab').forEach(t => t.classList.remove('active'));
      tab.classList.add('active');
      sentinelTab = tab.dataset.tab;
      renderSidebarList();
    });
  });
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
  renderIntervalSettings();
  startLogStream();
  startDataUpdates();
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
}

/* ── Badge counts on button ── */
function updateBadges() {
  const criticalHigh = OFFENSES.filter(o => o.severity === 'critical' || o.severity === 'high').length;
  const badSources   = LOG_SOURCES.filter(s => s.status !== 'active').length;

  document.getElementById('offenseCountBadge').textContent = OFFENSES.length;
  document.getElementById('sourceCountBadge').textContent  =
    badSources > 0 ? `${badSources} !` : `${LOG_SOURCES.length} OK`;

  const btn = document.getElementById('sentinelBtn');
  btn.classList.toggle('sentinel-btn--critical', criticalHigh > 0);
  btn.classList.toggle('sentinel-btn--ok',       criticalHigh === 0);
}

/* ── Sidebar list (offenses or log sources) ── */
function renderSidebarList() {
  const list = document.getElementById('sentinelSidebarList');

  if (sentinelTab === 'offenses') {
    list.innerHTML = OFFENSES.map(o => `
      <div class="sentinel-list-item">
        <div class="sentinel-list-dot sentinel-dot--${o.severity}"></div>
        <div class="sentinel-list-info">
          <div class="sentinel-list-name">${o.name}</div>
          <div class="sentinel-list-meta">${o.source} &middot; ${o.ago}m ago &middot; ${o.count} events</div>
        </div>
        <span class="sentinel-list-sev sentinel-sev--${o.severity}">${o.severity.toUpperCase()}</span>
      </div>
    `).join('');
  } else {
    list.innerHTML = LOG_SOURCES.map(s => `
      <div class="sentinel-list-item">
        <div class="sentinel-list-dot sentinel-dot--${s.status}"></div>
        <div class="sentinel-list-info">
          <div class="sentinel-list-name">${s.name}</div>
          <div class="sentinel-list-meta">${s.type} &middot; ${s.eps} EPS</div>
        </div>
        <span class="sentinel-list-sev sentinel-sev--${s.status}">${s.status.toUpperCase()}</span>
      </div>
    `).join('');
  }
}

/* ── Dashboard overview cards ── */
function renderDashboardCards() {
  const criticalCount   = OFFENSES.filter(o => o.severity === 'critical').length;
  const highCount       = OFFENSES.filter(o => o.severity === 'high').length;
  const mediumCount     = OFFENSES.filter(o => o.severity === 'medium').length;
  const activeSources   = LOG_SOURCES.filter(s => s.status === 'active').length;
  const errorSources    = LOG_SOURCES.filter(s => s.status === 'error').length;
  const inactiveSources = LOG_SOURCES.filter(s => s.status === 'inactive').length;
  const totalEps        = LOG_SOURCES.reduce((a, s) => a + s.eps, 0);
  const allClear        = criticalCount === 0 && highCount === 0 && errorSources === 0;

  const pill = document.getElementById('sentinelStatusPill');
  pill.textContent = allClear ? '● ALL CLEAR' : `● ${criticalCount} CRITICAL`;
  pill.className   = `sentinel-status-pill ${allClear ? 'pill--ok' : 'pill--critical'}`;

  document.getElementById('sentinelCards').innerHTML = `
    <!-- Offenses card -->
    <div class="sentinel-card ${OFFENSES.length > 0 ? 'card--alert' : 'card--ok'}">
      <div class="sentinel-card-header">
        <span class="sentinel-card-icon">⚡</span>
        <span class="sentinel-card-status ${OFFENSES.length > 0 ? 'status--critical' : 'status--ok'}">
          ${OFFENSES.length > 0 ? 'ACTIVE' : 'OK'}
        </span>
      </div>
      <div class="sentinel-card-count">${OFFENSES.length}</div>
      <div class="sentinel-card-title">Offenses</div>
      <div class="sentinel-card-breakdown">
        <span class="breakdown-item sev-critical">${criticalCount} Critical</span>
        <span class="breakdown-item sev-high">${highCount} High</span>
        <span class="breakdown-item sev-medium">${mediumCount} Medium</span>
      </div>
    </div>

    <!-- Log Sources card -->
    <div class="sentinel-card ${errorSources > 0 ? 'card--alert' : inactiveSources > 0 ? 'card--warn' : 'card--ok'}">
      <div class="sentinel-card-header">
        <span class="sentinel-card-icon">📡</span>
        <span class="sentinel-card-status ${errorSources > 0 ? 'status--critical' : inactiveSources > 0 ? 'status--warn' : 'status--ok'}">
          ${errorSources > 0 ? 'ERROR' : inactiveSources > 0 ? 'WARNING' : 'OK'}
        </span>
      </div>
      <div class="sentinel-card-count">${LOG_SOURCES.length}</div>
      <div class="sentinel-card-title">Log Sources</div>
      <div class="sentinel-card-breakdown">
        <span class="breakdown-item sev-ok">${activeSources} Active</span>
        <span class="breakdown-item sev-high">${errorSources} Error</span>
        <span class="breakdown-item sev-medium">${inactiveSources} Inactive</span>
      </div>
    </div>

    <!-- Events/sec card -->
    <div class="sentinel-card card--ok">
      <div class="sentinel-card-header">
        <span class="sentinel-card-icon">📊</span>
        <span class="sentinel-card-status status--ok">NORMAL</span>
      </div>
      <div class="sentinel-card-count" id="epsCard">${totalEps}</div>
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
   INTERVAL SETTINGS PANEL
   ══════════════════════════════════════════════ */
function renderIntervalSettings() {
  const container = document.getElementById('sentinelCards');
  if (!container) return;

  // Append the settings card after the existing cards
  const settingsCard = document.createElement('div');
  settingsCard.className = 'sentinel-settings-card';
  settingsCard.innerHTML = `
    <div class="sentinel-settings-header">
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.32 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>
      <span>Sentinel Settings</span>
    </div>

    <div class="sentinel-interval-group">
      <label class="sentinel-interval-label">
        <span>Log Stream Refresh</span>
        <div class="sentinel-interval-control">
          <input type="range" min="500" max="5000" step="100" value="${intervals.logStream}" data-key="logStream" class="sentinel-slider" />
          <span class="sentinel-interval-value" id="val-logStream">${(intervals.logStream / 1000).toFixed(1)}s</span>
        </div>
      </label>

      <label class="sentinel-interval-label">
        <span>EPS Update</span>
        <div class="sentinel-interval-control">
          <input type="range" min="1000" max="10000" step="500" value="${intervals.epsUpdate}" data-key="epsUpdate" class="sentinel-slider" />
          <span class="sentinel-interval-value" id="val-epsUpdate">${(intervals.epsUpdate / 1000).toFixed(1)}s</span>
        </div>
      </label>

      <label class="sentinel-interval-label">
        <span>Offense Check</span>
        <div class="sentinel-interval-control">
          <input type="range" min="5000" max="120000" step="5000" value="${intervals.offenseCheck}" data-key="offenseCheck" class="sentinel-slider" />
          <span class="sentinel-interval-value" id="val-offenseCheck">${(intervals.offenseCheck / 1000)}s</span>
        </div>
      </label>

      <label class="sentinel-interval-label">
        <span>Source Check</span>
        <div class="sentinel-interval-control">
          <input type="range" min="10000" max="300000" step="10000" value="${intervals.sourceCheck}" data-key="sourceCheck" class="sentinel-slider" />
          <span class="sentinel-interval-value" id="val-sourceCheck">${(intervals.sourceCheck / 1000)}s</span>
        </div>
      </label>
    </div>

    <div class="sentinel-email-section">
      <div class="sentinel-email-header">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,13 2,6"/></svg>
        <span>Email Alerts</span>
      </div>
      <div class="sentinel-email-toggle-row">
        <span>Send email on critical offenses</span>
        <label class="sentinel-toggle">
          <input type="checkbox" id="emailAlertToggle" ${isEmailAlertsEnabled() ? 'checked' : ''} />
          <span class="sentinel-toggle-track"></span>
        </label>
      </div>
      <p class="sentinel-email-hint">Alerts sent to your registered email when critical or high severity offenses are detected.</p>
    </div>
  `;

  container.parentNode.insertBefore(settingsCard, container.nextSibling);

  // Bind slider events
  settingsCard.querySelectorAll('.sentinel-slider').forEach(slider => {
    slider.addEventListener('input', (e) => {
      const key = e.target.dataset.key;
      const val = parseInt(e.target.value);
      intervals[key] = val;
      const display = val >= 1000 ? `${(val / 1000).toFixed(val % 1000 === 0 ? 0 : 1)}s` : `${val}ms`;
      document.getElementById(`val-${key}`).textContent = display;
      saveIntervals(intervals);

      // Restart affected timers immediately
      if (sentinelActive) {
        clearInterval(logInterval);
        clearInterval(dataInterval);
        startLogStream();
        startDataUpdates();
      }
    });
  });

  // Bind email toggle
  const emailToggle = document.getElementById('emailAlertToggle');
  if (emailToggle) {
    emailToggle.addEventListener('change', (e) => {
      setEmailAlertsEnabled(e.target.checked);
    });
  }
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

  // Don't re-alert the same offense
  if (alertedOffenseIds.has(offense.id)) return;
  alertedOffenseIds.add(offense.id);

  try {
    const token = localStorage.getItem('wazuhbot-token');
    await fetch(`${SENTINEL_API}/alerts/send`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`,
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
  const criticals = OFFENSES.filter(o => o.severity === 'critical' || o.severity === 'high');
  criticals.forEach(offense => sendAlertEmail(offense));
}

/* ── Live log stream ── */
function startLogStream() {
  const feed = document.getElementById('sentinelLogFeed');

  function addLog() {
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
    // Cap at 80 entries
    while (feed.children.length > 80) feed.removeChild(feed.lastChild);
    updateEps();
  }

  addLog();
  logInterval = setInterval(addLog, intervals.logStream);
}

/* ── Live EPS jitter ── */
function startDataUpdates() {
  dataInterval = setInterval(() => {
    const el = document.getElementById('epsCard');
    if (!el) return;
    const base   = LOG_SOURCES.reduce((a, s) => a + s.eps, 0);
    const jitter = Math.floor((Math.random() - 0.5) * 40);
    el.textContent = Math.max(0, base + jitter);
  }, intervals.epsUpdate);
}

function updateEps() {
  const base   = LOG_SOURCES.reduce((a, s) => a + s.eps, 0);
  const jitter = Math.floor((Math.random() - 0.5) * 20);
  const el = document.getElementById('sentinelLogEps');
  if (el) el.textContent = Math.max(0, base + jitter) + ' EPS';
}
