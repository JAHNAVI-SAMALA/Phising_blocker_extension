// blocked.js — PhishGuard AI blocked page logic

const params     = new URLSearchParams(location.search);
const blockedURL = decodeURIComponent(params.get('url')        || 'Unknown URL');
const risk       = params.get('risk')                          || 'HIGH';
const confidence = parseFloat(params.get('confidence')         || '85');
const factors    = JSON.parse(decodeURIComponent(params.get('factors')  || '[]'));
const source     = decodeURIComponent(params.get('source')     || 'ml_model');
const reports    = parseInt(params.get('reports')              || '0', 10);

// ── Populate URL and risk ──────────────────────────────────────────────────
document.getElementById('blocked-url').textContent = blockedURL;

const riskBadge = document.getElementById('risk-badge');
riskBadge.textContent  = `${risk} RISK`;
riskBadge.className    = `risk-badge risk-${risk}`;

// Source badge
const srcBadge = document.getElementById('source-badge');
if (source === 'community_database') {
  srcBadge.textContent = '👥 Community Reported';
  srcBadge.style.background = 'rgba(255,45,85,0.1)';
  srcBadge.style.borderColor = 'rgba(255,45,85,0.25)';
  srcBadge.style.color = '#ff6b8a';
} else if (source === 'safe_list') {
  srcBadge.textContent = '✅ Safe List';
} else {
  srcBadge.textContent = '🤖 ML Model';
}

// ── Confidence bar ─────────────────────────────────────────────────────────
document.getElementById('conf-text').textContent = `${confidence.toFixed(0)}%`;
// Animate bar after paint
requestAnimationFrame(() => {
  requestAnimationFrame(() => {
    document.getElementById('conf-fill').style.width = `${confidence}%`;
  });
});

// ── Community reports card ─────────────────────────────────────────────────
if (reports > 0) {
  document.getElementById('community-card').style.display = 'flex';
  document.getElementById('community-num').textContent    = reports;
}

// ── Risk factors ───────────────────────────────────────────────────────────
if (factors.length > 0) {
  document.getElementById('factors-card').style.display = 'block';
  document.getElementById('factors-list').innerHTML = factors
    .slice(0, 6)
    .map(f => `<div class="factor"><div class="factor-dot"></div><div>${f}</div></div>`)
    .join('');
}

// ── Floating particles ─────────────────────────────────────────────────────
const container = document.getElementById('particles');
for (let i = 0; i < 18; i++) {
  const p = document.createElement('div');
  p.className = 'particle';
  const size = Math.random() * 4 + 2;
  p.style.cssText = [
    `width:${size}px`, `height:${size}px`,
    `left:${Math.random() * 100}%`,
    `bottom:${Math.random() * 30}%`,
    `animation-duration:${Math.random() * 6 + 5}s`,
    `animation-delay:${Math.random() * 5}s`,
    `opacity:0`,
  ].join(';');
  container.appendChild(p);
}

// ── Expandable "why blocked?" ──────────────────────────────────────────────
document.getElementById('why-toggle').addEventListener('click', () => {
  const toggle = document.getElementById('why-toggle');
  const body   = document.getElementById('why-body');
  const isOpen = toggle.classList.toggle('open');
  body.classList.toggle('open', isOpen);
});

// ── Go back button ─────────────────────────────────────────────────────────
document.getElementById('btn-back').addEventListener('click', () => {
  if (history.length > 1) {
    history.back();
  } else {
    location.href = 'https://www.google.com';
  }
});

// ── Countdown before "Proceed Anyway" unlocks ─────────────────────────────
let countdown = 5;
const proceedBtn     = document.getElementById('btn-proceed');
const countdownLabel = document.getElementById('countdown-text');

const timer = setInterval(() => {
  countdown--;
  if (countdown <= 0) {
    clearInterval(timer);
    proceedBtn.disabled          = false;
    countdownLabel.textContent   = '(risky)';
    countdownLabel.style.color   = '#ff2d55';
  } else {
    countdownLabel.textContent = `(wait ${countdown}s)`;
  }
}, 1000);

// ── Proceed anyway ─────────────────────────────────────────────────────────
proceedBtn.addEventListener('click', () => {
  if (proceedBtn.disabled) return;
  const confirmed = confirm(
    '⚠️ WARNING\n\n' +
    'This site has been flagged as a phishing attack by PhishGuard AI.\n\n' +
    'Visiting it may result in:\n' +
    '  • Your passwords being stolen\n' +
    '  • Credit card or banking fraud\n' +
    '  • Malware being installed\n\n' +
    'Are you absolutely sure you want to continue?'
  );
  if (confirmed) {
    // Notify background to whitelist this URL for one navigation
    chrome.runtime.sendMessage({ type: 'ALLOW_ONCE', url: blockedURL }, () => {
      location.href = blockedURL;
    });
  }
});