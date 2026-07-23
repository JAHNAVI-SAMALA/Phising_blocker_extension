// PhishGuard AI — Background Service Worker v3.1
// Handles: URL interception, ML analysis, blocking, caching, badge, SSE proxy

const API_BASE = 'http://localhost:5000';
const API_URL  = `${API_BASE}/analyze`;

// ── In-memory cache: url → { result, intel } ──────────────────────────────
const cache = new Map();
const allowOnceList = new Set();

// ── Analyze every page navigation ─────────────────────────────────────────
chrome.webNavigation.onCommitted.addListener(async (details) => {
  if (details.frameId !== 0) return;
  if (!details.url.startsWith('http')) return;

  const url = details.url;

  // User chose to proceed anyway — allow once, show warning badge
  if (allowOnceList.has(url)) {
    allowOnceList.delete(url);
    updateBadge(details.tabId, { is_phishing: true, risk_level: 'HIGH' });
    return;
  }

  // Show a neutral "scanning" badge immediately so icon isn't blank
  // while waiting for WHOIS / DNS / SSL lookups (can take 5–15 s)
  chrome.action.setBadgeText({ tabId: details.tabId, text: '...' });
  chrome.action.setBadgeBackgroundColor({ tabId: details.tabId, color: '#555566' });
  chrome.action.setTitle({ tabId: details.tabId, title: 'PhishGuard AI — Scanning...' });

  try {
    const result = await analyzeURL(url, '');
    // Fetch intel in parallel (non-blocking — failure is fine)
    fetchIntelAndCache(url, details.tabId);

    cache.set(url, { result, intel: null }); // intel filled in by fetchIntelAndCache
    updateBadge(details.tabId, result);
    incrementScanCount();

    if (result.is_phishing && result.confidence > 80) {
      blockTab(details.tabId, url, result);
    }
  } catch (err) {
    console.error('[PhishGuard] Analysis error:', err);
    chrome.action.setBadgeText({ tabId: details.tabId, text: '' });
  }
});

// ── Fetch domain intel and update cache ───────────────────────────────────
async function fetchIntelAndCache(url, tabId) {
  try {
    const res = await fetch(`${API_BASE}/domain-intel`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url, page_content: '' })
    });
    const intel = await res.json();
    const existing = cache.get(url) || {};
    cache.set(url, { ...existing, intel });
  } catch (_) {
    // Intel fetch failure is non-critical — popup will show unavailable
  }
}

// ── Track scan count in persistent storage ────────────────────────────────
async function incrementScanCount() {
  try {
    const data = await chrome.storage.local.get(['scan_count', 'threats_blocked']);
    chrome.storage.local.set({
      scan_count: (data.scan_count || 0) + 1
    });
  } catch (_) {}
}

async function incrementThreatsBlocked() {
  try {
    const data = await chrome.storage.local.get(['threats_blocked']);
    chrome.storage.local.set({
      threats_blocked: (data.threats_blocked || 0) + 1
    });
  } catch (_) {}
}

// ── Handle messages from content script and popup ─────────────────────────
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {

  if (msg.type === 'PAGE_CONTENT') {
    if (allowOnceList.has(msg.url)) {
      const cached = cache.get(msg.url);
      sendResponse(cached?.result || null);
      return true;
    }
    analyzeURL(msg.url, msg.content).then(result => {
      const existing = cache.get(msg.url) || {};
      cache.set(msg.url, { ...existing, result });
      updateBadge(sender.tab.id, result);
      incrementScanCount();
      if (result.is_phishing && result.confidence > 80) {
        blockTab(sender.tab.id, msg.url, result);
        incrementThreatsBlocked();
      }
      sendResponse(result);
    });
    return true;
  }

  if (msg.type === 'GET_RESULT') {
    const cached = cache.get(msg.url) || {};
    sendResponse({ result: cached.result || null, intel: cached.intel || null });
    return true;
  }

  if (msg.type === 'REPORT_PHISHING') {
    fetch(`${API_BASE}/report`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: msg.url, page_content: msg.content || '' })
    })
    .then(r => r.json())
    .then(data => sendResponse({ success: true, data }))
    .catch(err => sendResponse({ success: false, error: err.message }));
    return true;
  }

  if (msg.type === 'ALLOW_ONCE') {
    allowOnceList.add(msg.url);
    sendResponse({ success: true });
    return true;
  }

  if (msg.type === 'ANALYZE_URL') {
    // Manual URL scan from popup input field
    analyzeURL(msg.url, '').then(result => {
      sendResponse({ result });
    }).catch(err => sendResponse({ error: err.message }));
    return true;
  }

  // ── Email scan — proxied here because content scripts on HTTPS
  // pages cannot fetch http://localhost (Mixed Content). Service
  // worker has no such restriction.
  if (msg.type === 'SCAN_EMAIL') {
    const ctrl    = new AbortController();
    const timeout = setTimeout(() => ctrl.abort(), 20000);
    fetch(`${API_BASE}/scan-email`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      signal: ctrl.signal,
      body: JSON.stringify({
        subject: msg.subject || '',
        sender:  msg.sender  || '',
        body:    (msg.body   || '').slice(0, 4000),
        links:   (msg.links  || []).slice(0, 5)
      })
    })
    .then(r => r.json())
    .then(data => { clearTimeout(timeout); sendResponse(data); })
    .catch(err => {
      clearTimeout(timeout);
      sendResponse({
        error: err.message, verdict: 'SAFE', findings: [],
        links_analyzed: [], risk_score: 0, suspicious_links_count: 0,
        summary: 'Backend offline or scan timed out.'
      });
    });
    return true;
  }
});

// ── API call ───────────────────────────────────────────────────────────────
async function analyzeURL(url, pageContent) {
  const response = await fetch(API_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url, page_content: pageContent })
  });
  return response.json();
}

// ── Badge update ───────────────────────────────────────────────────────────
function updateBadge(tabId, result) {
  if (!result) return;
  if (result.is_phishing) {
    const color = (result.risk_level === 'CRITICAL' || result.risk_level === 'HIGH')
                ? '#ff2d55'
                : '#ff9500';
    const text  = result.risk_level === 'CRITICAL' ? 'CRIT' : '!';
    chrome.action.setBadgeText({ tabId, text });
    chrome.action.setBadgeBackgroundColor({ tabId, color });
    chrome.action.setTitle({ tabId, title: `⚠️ PhishGuard: ${result.risk_level} RISK — Click for details` });
  } else {
    chrome.action.setBadgeText({ tabId, text: 'OK' });
    chrome.action.setBadgeBackgroundColor({ tabId, color: '#32d74b' });
    chrome.action.setTitle({ tabId, title: '✅ PhishGuard: Site is Safe' });
  }
}

// ── Block tab ──────────────────────────────────────────────────────────────
function blockTab(tabId, url, result) {
  const encoded    = encodeURIComponent(url);
  const risk       = encodeURIComponent(result.risk_level);
  const confidence = encodeURIComponent(result.confidence);
  const factors    = encodeURIComponent(JSON.stringify(result.risk_factors || []));
  const source     = encodeURIComponent(result.source || 'ml_model');
  const reports    = encodeURIComponent(result.community_reports || 0);

  chrome.tabs.update(tabId, {
    url: chrome.runtime.getURL(
      `pages/blocked.html?url=${encoded}&risk=${risk}&confidence=${confidence}&factors=${factors}&source=${source}&reports=${reports}`
    )
  });

  chrome.notifications.create('phishguard-block-' + tabId, {
    type: 'basic',
    iconUrl: 'icons/icon48.png',
    title: '🚨 PhishGuard: Phishing Site Blocked!',
    message: `${result.risk_level} risk — ${result.confidence}% confidence. Click the extension icon for details.`
  });
}