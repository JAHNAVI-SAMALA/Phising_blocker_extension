// popup.js — PhishGuard AI v3.1
// Separate file required by Chrome MV3 Content Security Policy

const BACKEND_URL = 'https://phishguard-backend-517z.onrender.com';

let currentURL = '';
let currentResult = null;
let currentIntel = null;
let communityAlerts = [];
let lastAlertSince = new Date(0).toISOString();

// ── Tab switching ──────────────────────────────────────────────────────────
document.querySelectorAll('.tab').forEach(tab => {
  tab.addEventListener('click', () => {
    const name = tab.dataset.tab;
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
    document.getElementById(`tab-${name}`).classList.add('active');
    document.getElementById(`panel-${name}`).classList.add('active');
    if (name === 'alerts') {
      updateAlertBadge(0);
      fetchAlerts();
    }
  });
});

// ── Manual URL scan ────────────────────────────────────────────────────────
document.getElementById('btn-manual-scan').addEventListener('click', doManualScan);
document.getElementById('manual-url-input').addEventListener('keydown', e => {
  if (e.key === 'Enter') doManualScan();
});

function doManualScan() {
  let url = document.getElementById('manual-url-input').value.trim();
  if (!url) return;
  // Auto-prepend https if missing
  if (!url.startsWith('http')) url = 'https://' + url;

  const btn = document.getElementById('btn-manual-scan');
  btn.disabled = true;
  btn.textContent = '…';

  // Switch to scan tab and show spinner
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
  document.getElementById('tab-scan').classList.add('active');
  document.getElementById('panel-scan').classList.add('active');

  document.getElementById('scan-content').innerHTML =
    '<div class="spin-wrap"><div class="spinner"></div>Scanning ' +
    escapeHtml(url.replace(/^https?:\/\//, '').slice(0, 40)) + '…</div>';

  // Send to background for analysis (proxied — avoids mixed content in popup)
  chrome.runtime.sendMessage({ type: 'ANALYZE_URL', url }, res => {
    btn.disabled = false;
    btn.textContent = 'Scan';
    if (res?.result) {
      currentResult = res.result;
      renderScanPanel(res.result, url);
    } else {
      document.getElementById('scan-content').innerHTML = `
        <div class="site-status loading">
          <span class="status-icon">⚠️</span>
          <div class="status-info">
            <div class="status-title status-loading">Scan Failed</div>
            <div class="status-desc">${res?.error || 'Backend offline or URL unreachable.'}</div>
          </div>
        </div>`;
    }
  });
}

// ── Init: get current tab URL ──────────────────────────────────────────────
chrome.tabs.query({ active: true, currentWindow: true }, tabs => {
  if (!tabs[0]) return;
  currentURL = tabs[0].url || '';
  document.getElementById('footer-url').textContent =
    currentURL.replace(/^https?:\/\//, '').slice(0, 38);

  // Check cache first
  chrome.runtime.sendMessage({ type: 'GET_RESULT', url: currentURL }, res => {
    currentResult = res?.result || null;
    currentIntel = res?.intel || null;

    if (currentResult) {
      renderScanPanel(currentResult, currentURL);
    } else if (currentURL.startsWith('http')) {
      // Not cached — fetch directly
      fetch(`${BACKEND_URL}/analyze`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: currentURL, page_content: '' })
      })
        .then(r => r.json())
        .then(result => { currentResult = result; renderScanPanel(result, currentURL); })
        .catch(() => {
          document.getElementById('scan-content').innerHTML = `
          <div class="site-status loading">
            <span class="status-icon">⚠️</span>
            <div class="status-info">
              <div class="status-title status-loading">Backend Offline</div>
              <div class="status-desc">Start the Python backend: <code>python app.py</code></div>
            </div>
          </div>`;
        });
    } else {
      document.getElementById('scan-content').innerHTML = `
        <div class="empty-state">
          <span class="icon">🛡️</span>
          <strong>No Page to Scan</strong>
          <p>Navigate to a website, or paste any URL in the box above.</p>
        </div>`;
    }

    if (currentIntel) {
      renderIntelPanel(currentIntel);
    } else if (currentURL.startsWith('http')) {
      fetch(`${BACKEND_URL}/domain-intel`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: currentURL, page_content: '' })
      })
        .then(r => r.json())
        .then(intel => { currentIntel = intel; renderIntelPanel(intel); })
        .catch(() => { });
    } else {
      renderIntelPanel(null);
    }
  });

  fetchAlerts();
});

// ── Backend health check + footer stats ───────────────────────────────────
(async function checkHealth() {
  const dot = document.getElementById('status-dot');
  const stat = document.getElementById('footer-stat');
  try {
    const r = await fetch(`${BACKEND_URL}/health`);
    const d = await r.json();
    if (d.model_loaded === false) {
      dot.className = 'status-dot warning';
      stat.textContent = 'Model not loaded';
    } else {
      dot.className = 'status-dot';
      const reports = d.community_reports || 0;
      const threats = d.active_threats || 0;
      stat.textContent = `${reports} reports · ${threats} active threats`;
      if (threats > 0) stat.className = 'footer-stat threat';
      else stat.className = 'footer-stat safe';
    }
    // Load local scan count from storage
    chrome.storage.local.get(['scan_count', 'threats_blocked'], data => {
      if (data.scan_count) {
        const scans = data.scan_count || 0;
        const blocked = data.threats_blocked || 0;
        stat.textContent = `${scans} scanned · ${blocked} blocked`;
      }
    });
  } catch {
    dot.className = 'status-dot offline';
    stat.textContent = 'Backend offline';
    stat.className = 'footer-stat threat';
  }
})();

// ── Render Scan Panel ──────────────────────────────────────────────────────
function renderScanPanel(result, scanUrl) {
  const el = document.getElementById('scan-content');
  if (!result) {
    el.innerHTML = `
      <div class="site-status loading">
        <span class="status-icon">🔄</span>
        <div class="status-info">
          <div class="status-title status-loading">Analyzing…</div>
          <div class="status-desc">Checking URL against ML model and community database</div>
        </div>
      </div>`;
    return;
  }

  const isPhish = result.is_phishing;
  const conf = result.confidence || 0;
  const rl = result.risk_level || (isPhish ? 'HIGH' : 'LOW');
  const statusCls = isPhish ? (rl === 'MEDIUM' ? 'suspicious' : 'phishing') : 'safe';
  const icon = isPhish ? (rl === 'CRITICAL' ? '🚨' : '⚠️') : '✅';
  const titleCls = isPhish ? (rl === 'MEDIUM' ? 'status-suspicious' : 'status-phishing') : 'status-safe';
  const title = isPhish
    ? `${rl} Risk — Phishing Detected`
    : 'Site Appears Safe';
  const displayConf = isPhish ? conf : (100 - conf);
  const desc = isPhish
    ? `${conf.toFixed(0)}% threat confidence.${result.source === 'community_database' ? ' ⚠️ Community flagged.' : ' Detected by ML model.'}`
    : `${(100 - conf).toFixed(0)}% safety confidence. No phishing signals found.`;
  const fillColor = isPhish ? (rl === 'MEDIUM' ? '#ff9500' : '#ff2d55') : '#30d158';
  const fillWidth = isPhish ? conf : (100 - conf);
  const factors = (result.risk_factors || []).slice(0, 5);

  // Source tag
  const sourceTag = result.source === 'community_database'
    ? '<span style="background:rgba(255,45,85,0.15);border:1px solid rgba(255,45,85,0.3);border-radius:5px;padding:2px 7px;font-size:10px;font-weight:700;color:#ff6b8a">Community DB</span>'
    : result.source === 'safe_list'
      ? '<span style="background:rgba(48,209,88,0.1);border:1px solid rgba(48,209,88,0.2);border-radius:5px;padding:2px 7px;font-size:10px;font-weight:700;color:#30d158">Trusted Domain</span>'
      : '<span style="background:rgba(108,99,255,0.12);border:1px solid rgba(108,99,255,0.25);border-radius:5px;padding:2px 7px;font-size:10px;font-weight:700;color:#8b7fff">ML Model</span>';

  el.innerHTML = `
    <div class="site-status ${statusCls}">
      <span class="status-icon">${icon}</span>
      <div class="status-info">
        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:4px">
          <div class="status-title ${titleCls}">${title}</div>
          ${sourceTag}
        </div>
        <div class="status-desc">${desc}</div>
        <div class="conf-bar-wrap">
          <div class="conf-label">
            <span>${isPhish ? 'Threat' : 'Safety'} Confidence</span>
            <span>${fillWidth.toFixed(0)}%</span>
          </div>
          <div class="conf-bar">
            <div class="conf-fill" style="width:0%;background:${fillColor}" id="cf-bar"></div>
          </div>
        </div>
      </div>
    </div>
    ${factors.length ? `
      <div class="section-hdr">🚩 Risk Factors</div>
      <div style="display:flex;flex-wrap:wrap">
        ${factors.map(f => `<span class="factor-tag">🔴 ${escapeHtml(f)}</span>`).join('')}
      </div>` : ''}
    ${result.community_reports > 0 ? `
      <div class="section-hdr">👥 Community Reports</div>
      <div class="reports-card">
        <div class="reports-num">${result.community_reports}</div>
        <div><div style="font-weight:700;font-size:12px">Users Reported</div>
        <div class="reports-label">This domain was flagged by the PhishGuard community</div></div>
      </div>` : ''}
    <button class="btn-report" id="report-btn">🚨 Report This Site as Phishing</button>
  `;

  // Animate confidence bar after paint
  requestAnimationFrame(() => {
    const bar = document.getElementById('cf-bar');
    if (bar) requestAnimationFrame(() => { bar.style.width = `${fillWidth}%`; });
  });

  document.getElementById('report-btn').addEventListener('click', reportPhishing);
}

// ── Render Intel Panel ─────────────────────────────────────────────────────
function renderIntelPanel(intel) {
  const el = document.getElementById('intel-content');
  if (!intel || intel.error) {
    el.innerHTML = `
      <div class="empty-state">
        <span class="icon">🌐</span>
        <strong>Intel Unavailable</strong>
        <p>Backend may be offline, or this page hasn't loaded domain data yet.</p>
      </div>`;
    return;
  }

  const w = intel.whois || {};
  const ssl = intel.ssl || {};
  const pa = intel.page_analysis || {};
  const signals = intel.risk_signals || [];
  const ageDays = w.domain_age_days;

  // Age classification
  const ageClass = ageDays != null && ageDays >= 0
    ? (ageDays < 30 ? 'danger' : ageDays < 90 ? 'warn' : 'ok')
    : '';

  el.innerHTML = `
    <div class="section-hdr">🌐 WHOIS & Domain</div>
    ${row('Domain', intel.domain || '—', '')}
    ${row('Created', w.creation_date || 'Unknown', ageClass)}
    ${row('Domain Age', ageDays != null && ageDays >= 0 ? `${ageDays} days` : 'Unknown', ageClass)}
    ${row('Registrar', w.registrar || 'Unknown', '')}
    ${row('Country', w.country || 'Unknown', '')}

    <div class="section-hdr">🔒 SSL Certificate</div>
    ${row('Valid', ssl.valid ? '✅ Yes' : '❌ No', ssl.valid ? 'ok' : 'danger')}
    ${ssl.issuer ? row('Issuer', ssl.issuer, '') : ''}
    ${ssl.expiry ? row('Expires', ssl.expiry, '') : ''}
    ${row('DNS Exists', intel.dns?.exists ? '✅ Yes' : '❌ No', intel.dns?.exists ? 'ok' : 'danger')}

    <div class="section-hdr">📄 Page Analysis</div>
    ${chk('Fake Login Page', pa.has_fake_login)}
    ${chk(`Brand Impersonation${pa.brand_impersonation ? ': ' + pa.brand_impersonation : ''}`, !!pa.brand_impersonation)}
    ${chk('Credential Harvesting Form', pa.form_steals_credentials)}
    ${chk('Obfuscated JavaScript', pa.has_obfuscated_js)}
    ${chk('Hidden iFrame Detected', pa.iframe_detected)}
    ${chk('External Favicon', pa.external_favicon)}

    ${signals.length ? `
      <div class="section-hdr">⚠️ Risk Signals</div>
      ${signals.map(s => `
        <div class="check">
          <span>${s.severity === 'CRITICAL' ? '🔴' : s.severity === 'HIGH' ? '🟠' : '🟡'}</span>
          <span class="check-detected" style="color:${s.severity === 'CRITICAL' ? 'var(--red)' : s.severity === 'HIGH' ? 'var(--orange)' : '#ffd60a'}">${escapeHtml(s.label)}</span>
        </div>`).join('')}
    ` : ''}
  `;
}

function row(key, val, cls) {
  return `<div class="whois-row"><span class="wk">${key}</span><span class="wv ${cls}">${val}</span></div>`;
}
function chk(label, detected) {
  return `<div class="check"><span>${detected ? '🔴' : '🟢'}</span><span class="${detected ? 'check-detected' : 'check-clean'}">${label}</span></div>`;
}
function escapeHtml(str) {
  return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

// ── Community Alerts ───────────────────────────────────────────────────────
async function fetchAlerts() {
  try {
    const r = await fetch(`${BACKEND_URL}/alerts/recent?since=${encodeURIComponent(lastAlertSince)}`);
    const data = await r.json();
    if (data.alerts && data.alerts.length > 0) {
      communityAlerts = [...data.alerts, ...communityAlerts].slice(0, 20);
      lastAlertSince = new Date().toISOString();
      renderAlerts();
      updateAlertBadge(data.alerts.length);
    }
  } catch (_) { }
}

function renderAlerts() {
  const el = document.getElementById('alerts-content');
  if (!communityAlerts.length) {
    el.innerHTML = `
      <div class="empty-state">
        <span class="icon">✅</span>
        <strong>All Clear</strong>
        <p>No threats reported in the last 24 hours.</p>
      </div>`;
    return;
  }
  el.innerHTML = communityAlerts.map(a => {
    const severityColor = a.severity === 'CRITICAL' ? 'var(--red)' : 'var(--orange)';
    return `
      <div class="alert-item">
        <div class="alert-domain">🚨 ${escapeHtml(a.domain)}
          <span class="alert-badge">${a.severity || 'HIGH'}</span>
        </div>
        <div class="alert-meta">
          ${a.report_count} report(s) &middot;
          <span style="color:${severityColor};font-weight:700">${a.severity || 'HIGH'}</span> &middot;
          ${new Date(a.created_at).toLocaleTimeString()}
        </div>
      </div>`;
  }).join('');
}

function updateAlertBadge(count) {
  const badge = document.getElementById('alert-badge');
  badge.textContent = count;
  badge.style.display = count > 0 ? 'inline-flex' : 'none';
}

// ── Report Phishing ────────────────────────────────────────────────────────
function reportPhishing() {
  const btn = document.getElementById('report-btn');
  if (!btn || !currentURL) return;
  btn.disabled = true;
  btn.textContent = '⏳ Reporting…';

  chrome.runtime.sendMessage(
    { type: 'REPORT_PHISHING', url: currentURL, content: '' },
    res => {
      if (res?.success) {
        btn.textContent = '✅ Reported! Community notified.';
        btn.style.color = 'var(--green)';
        btn.style.borderColor = 'rgba(48,209,88,0.3)';
        btn.style.background = 'rgba(48,209,88,0.08)';
      } else {
        btn.textContent = '❌ Report failed — backend offline?';
        btn.disabled = false;
      }
    }
  );
}

// ── Email results from content script ─────────────────────────────────────
chrome.runtime.onMessage.addListener(msg => {
  if ((msg.type === 'EMAIL_SCAN_RESULT' || msg.type === 'OPEN_POPUP_WITH_EMAIL') && msg.result) {
    renderEmailResult(msg.result);
  }
});

function renderEmailResult(result) {
  const el = document.getElementById('email-content');
  const icons = { PHISHING: '🚨', SUSPICIOUS: '⚠️', SAFE: '✅' };
  const titles = { PHISHING: 'Phishing Email!', SUSPICIOUS: 'Suspicious Email', SAFE: 'Email Looks Safe' };
  const findings = (result.findings || []).slice(0, 4);
  const susLinks = (result.links_analyzed || []).filter(l => l.is_suspicious).slice(0, 3);

  el.innerHTML = `
    <div class="email-verdict v-${result.verdict}">
      <span class="v-icon">${icons[result.verdict]}</span>
      <div class="v-title v-title-${result.verdict}">${titles[result.verdict]}</div>
      <div class="v-desc">${escapeHtml(result.summary)}</div>
    </div>
    <div class="section-hdr">📊 Risk Score</div>
    <div class="conf-bar-wrap" style="margin-bottom:12px">
      <div class="conf-label">
        <span>Phishing Risk</span><span>${result.risk_score}/100</span>
      </div>
      <div class="conf-bar">
        <div class="conf-fill" style="width:${result.risk_score}%;background:${result.risk_score >= 70 ? 'var(--red)' : result.risk_score >= 40 ? 'var(--orange)' : 'var(--green)'}"></div>
      </div>
    </div>
    ${findings.length ? `
      <div class="section-hdr">⚠️ Findings</div>
      ${findings.map(f => `<div class="check"><span>🔴</span><span class="check-detected">${escapeHtml(f.label)}</span></div>`).join('')}
    ` : ''}
    ${susLinks.length ? `
      <div class="section-hdr">⛓ Suspicious Links</div>
      ${susLinks.map(l => `
        <div class="check"><span>🔴</span>
        <span class="check-detected" style="word-break:break-all;font-size:11px">
          ${escapeHtml(l.url.slice(0, 52))}${l.url.length > 52 ? '…' : ''} (${l.confidence.toFixed(0)}%)
        </span></div>`).join('')}
    ` : ''}
  `;

  // Auto-switch to email tab
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
  document.getElementById('tab-email').classList.add('active');
  document.getElementById('panel-email').classList.add('active');
}
