/* ========================================
   WAZUHBOT — Sentinel Panel
   ======================================== */

let sentinelActive = false;
let sentinelTab    = 'offenses';
let logInterval    = null;
let dataInterval   = null;

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
    badSources > 0 ? `${badSources} ⚠` : `${LOG_SOURCES.length} ✓`;

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
  logInterval = setInterval(addLog, 900 + Math.random() * 600);
}

/* ── Live EPS jitter ── */
function startDataUpdates() {
  dataInterval = setInterval(() => {
    const el = document.getElementById('epsCard');
    if (!el) return;
    const base   = LOG_SOURCES.reduce((a, s) => a + s.eps, 0);
    const jitter = Math.floor((Math.random() - 0.5) * 40);
    el.textContent = Math.max(0, base + jitter);
  }, 2000);
}

function updateEps() {
  const base   = LOG_SOURCES.reduce((a, s) => a + s.eps, 0);
  const jitter = Math.floor((Math.random() - 0.5) * 20);
  const el = document.getElementById('sentinelLogEps');
  if (el) el.textContent = Math.max(0, base + jitter) + ' EPS';
}
