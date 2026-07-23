// PhishGuard AI — Content Script v3
// Two responsibilities:
//   1. Auto page-status pill  → shows scan result directly on every page
//   2. Gmail / Outlook email scanner

(function () {
  'use strict';

  const url      = window.location.href;
  const hostname = window.location.hostname;
  if (!url.startsWith('http')) return;

  const isEmailClient = hostname === 'mail.google.com' || hostname.includes('outlook');

  // ─── 1. PAGE STATUS PILL ────────────────────────────────────────────────────
  // Inject immediately so users see "Scanning…" right away, then update in-place
  // once background.js responds. No clicks required.
  let pill = null;

  function createPill() {
    const el = document.createElement('div');
    el.id = 'pg-status-pill';
    el.style.cssText = [
      'position:fixed', 'bottom:20px', 'right:20px',
      'z-index:2147483647',
      'display:flex', 'align-items:center', 'gap:8px',
      'padding:8px 15px', 'border-radius:99px',
      'font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Inter,sans-serif',
      'font-size:12px', 'font-weight:600',
      'background:rgba(14,14,26,0.92)', 'color:#888',
      'border:1px solid rgba(255,255,255,0.08)',
      'box-shadow:0 4px 20px rgba(0,0,0,0.5)',
      'backdrop-filter:blur(16px)',
      'opacity:0', 'transform:translateY(10px)',
      'transition:opacity 0.35s ease, transform 0.35s ease',
      'cursor:default', 'user-select:none', 'max-width:300px',
    ].join(';');
    el.innerHTML = '<span id="pg-pill-icon">🛡️</span><span id="pg-pill-text">Scanning…</span>';

    // Inject into <html> not <body> so it works even before body is ready
    (document.body || document.documentElement).appendChild(el);

    // Animate in on next frame
    requestAnimationFrame(() => requestAnimationFrame(() => {
      el.style.opacity = '1';
      el.style.transform = 'translateY(0)';
    }));

    return el;
  }

  function setPillSafe() {
    if (!pill) return;
    pill.style.background    = 'rgba(48,209,88,0.1)';
    pill.style.borderColor   = 'rgba(48,209,88,0.3)';
    pill.style.color         = '#30d158';
    pill.style.boxShadow     = '0 4px 20px rgba(0,0,0,0.5), 0 0 12px rgba(48,209,88,0.15)';
    pill.querySelector('#pg-pill-icon').textContent = '✅';
    pill.querySelector('#pg-pill-text').textContent = 'Safe';
    // Increment scan count in storage
    try {
      chrome.storage.local.get(['scan_count'], d => {
        chrome.storage.local.set({ scan_count: (d.scan_count || 0) + 1 });
      });
    } catch (_) {}
    // Fade out after 3.5 s
    setTimeout(() => {
      if (!pill) return;
      pill.style.opacity   = '0';
      pill.style.transform = 'translateY(8px)';
      setTimeout(() => { pill && pill.remove(); pill = null; }, 380);
    }, 3500);
  }

  function setPillThreat(result) {
    if (!pill) return;
    const isCrit = result.risk_level === 'CRITICAL' || result.risk_level === 'HIGH';
    const accent = isCrit ? '#ff2d55' : '#ff9500';
    const glowColor = isCrit ? 'rgba(255,45,85,0.25)' : 'rgba(255,149,0,0.2)';
    pill.style.background   = isCrit ? 'rgba(255,45,85,0.13)' : 'rgba(255,149,0,0.12)';
    pill.style.borderColor  = accent + '66';
    pill.style.color        = accent;
    pill.style.borderRadius = '12px';
    pill.style.padding      = '10px 14px';
    pill.style.cursor       = 'default';
    // Pulsing glow for threat
    pill.style.animation    = 'none';
    pill.style.boxShadow    = `0 4px 24px rgba(0,0,0,0.6), 0 0 20px ${glowColor}`;

    // Inject keyframe for threat glow pulse
    if (!document.getElementById('pg-glow-style')) {
      const s = document.createElement('style');
      s.id = 'pg-glow-style';
      s.textContent = `@keyframes pg-glow-pulse { 0%,100%{box-shadow:0 4px 24px rgba(0,0,0,0.6),0 0 20px ${glowColor}} 50%{box-shadow:0 4px 24px rgba(0,0,0,0.6),0 0 32px ${glowColor}} }`;
      document.head.appendChild(s);
    }
    pill.style.animation = 'pg-glow-pulse 2s ease-in-out infinite';

    const factor = (result.risk_factors || [])[0] || '';
    pill.innerHTML = `
      <div style="display:flex;align-items:center;gap:8px;">
        <span style="font-size:17px">${isCrit ? '🚨' : '⚠️'}</span>
        <div>
          <div style="font-weight:700;font-size:12px;color:${accent}">
            ${result.risk_level} RISK &mdash; ${Math.round(result.confidence)}%
          </div>
          ${factor ? `<div style="font-size:11px;font-weight:400;color:rgba(255,255,255,0.5);margin-top:2px">${factor}</div>` : ''}
        </div>
        <button id="pg-pill-close" style="
          margin-left:auto;background:none;border:none;color:rgba(255,255,255,0.3);
          cursor:pointer;font-size:17px;padding:0 0 0 8px;line-height:1;flex-shrink:0
        ">&times;</button>
      </div>`;

    document.getElementById('pg-pill-close').addEventListener('click', () => {
      pill.style.opacity   = '0';
      pill.style.transform = 'translateY(8px)';
      setTimeout(() => { pill && pill.remove(); pill = null; }, 380);
    });
  }

  // Only inject the pill on normal pages, not Gmail/Outlook (they get email banners)
  if (!isEmailClient) {
    pill = createPill();

    // Send page content to background; callback updates the pill
    setTimeout(() => {
      const content = document.documentElement.innerHTML.slice(0, 50000);
      chrome.runtime.sendMessage(
        { type: 'PAGE_CONTENT', url, content },
        (result) => {
          // Suppress "receiving end does not exist" and similar errors
          if (chrome.runtime.lastError || !result) {
            if (pill) { pill.style.opacity = '0'; setTimeout(() => { pill && pill.remove(); pill = null; }, 380); }
            return;
          }
          if (result.is_phishing) {
            setPillThreat(result);
          } else {
            setPillSafe();
          }
        }
      );
    }, 1200);
  }

  // ─── 2. EMAIL SCANNERS ──────────────────────────────────────────────────────
  if (hostname === 'mail.google.com') {
    console.log('[PhishGuard] Gmail detected — starting email scanner');
    startGmailScanner();
  }
  if (hostname.includes('outlook')) {
    console.log('[PhishGuard] Outlook detected — starting email scanner');
    startOutlookScanner();
  }

})(); // end IIFE


// ─────────────────────────────────────────────────────────────────────────────
// GMAIL SCANNER
// ─────────────────────────────────────────────────────────────────────────────
function startGmailScanner() {
  let lastHash   = '';
  let scanTimer  = null;

  function schedScan() {
    // Debounce: wait 700 ms of quiet before scanning
    clearTimeout(scanTimer);
    scanTimer = setTimeout(doScan, 700);
  }

  function doScan() {
    // Email body — try selectors in priority order
    const emailBody =
      document.querySelector('.a3s.aiL') ||
      document.querySelector('.ii.gt')   ||
      document.querySelector('[data-message-id]');
    if (!emailBody) return;

    const subjectEl =
      document.querySelector('h2.hP') ||
      document.querySelector('[data-legacy-thread-id] h2');
    const subject = subjectEl ? subjectEl.innerText.trim() : '';

    const senderEl =
      document.querySelector('.gD') ||
      document.querySelector('span[email]');
    const sender = senderEl
      ? (senderEl.getAttribute('email') || senderEl.innerText.trim())
      : '';

    const bodyText = (emailBody.innerText || '').slice(0, 4000); // keep msg small

    // Unwrap Google redirect links
    const links = Array.from(emailBody.querySelectorAll('a[href]'))
      .map(a => {
        try {
          if (a.href.includes('google.com/url?')) {
            const q = new URL(a.href).searchParams.get('q');
            if (q && q.startsWith('http')) return q;
          }
        } catch (_) {}
        return a.href;
      })
      .filter(h => h.startsWith('http'))
      .slice(0, 5); // cap at 5 — keeps backend response under service-worker timeout

    if (!bodyText && links.length === 0) return;

    // Stable dedup — don't re-scan the same email
    const raw  = bodyText.slice(0, 300) + links.join(',');
    const hash = raw.split('').reduce((h, c) => (Math.imul(31, h) + c.charCodeAt(0)) | 0, 0).toString(36);
    if (hash === lastHash) return;
    lastHash = hash;

    console.log('[PhishGuard] Scanning Gmail email —', { subject, links: links.length });
    sendEmailToBackground({ subject, sender, body: bodyText, links });
  }

  // MutationObserver — debounced so it doesn't fire on every keypress
  new MutationObserver(schedScan).observe(document.body, { childList: true, subtree: true });
  // Also trigger on click (user opens a new email)
  document.addEventListener('click', () => setTimeout(doScan, 900));
}


// ─────────────────────────────────────────────────────────────────────────────
// OUTLOOK SCANNER
// ─────────────────────────────────────────────────────────────────────────────
function startOutlookScanner() {
  let lastHash  = '';
  let scanTimer = null;

  function schedScan() {
    clearTimeout(scanTimer);
    scanTimer = setTimeout(doScan, 700);
  }

  function doScan() {
    const emailBody =
      document.querySelector('[role="main"] [role="document"]') ||
      document.querySelector('.ReadingPaneContent')              ||
      document.querySelector('[aria-label="Message body"]');
    if (!emailBody) return;

    const subjectEl =
      document.querySelector('[role="main"] [role="heading"]') ||
      document.querySelector('.subject');
    const subject = subjectEl ? subjectEl.innerText.trim() : '';

    const bodyText = (emailBody.innerText || '').slice(0, 4000);
    const links = Array.from(emailBody.querySelectorAll('a[href]'))
      .map(a => a.href)
      .filter(h => h.startsWith('http'))
      .slice(0, 5);

    if (!bodyText && links.length === 0) return;

    const raw  = bodyText.slice(0, 300) + links.join(',');
    const hash = raw.split('').reduce((h, c) => (Math.imul(31, h) + c.charCodeAt(0)) | 0, 0).toString(36);
    if (hash === lastHash) return;
    lastHash = hash;

    console.log('[PhishGuard] Scanning Outlook email —', { subject, links: links.length });
    sendEmailToBackground({ subject, sender: '', body: bodyText, links });
  }

  new MutationObserver(schedScan).observe(document.body, { childList: true, subtree: true });
  document.addEventListener('click', () => setTimeout(doScan, 900));
}


// ─────────────────────────────────────────────────────────────────────────────
// SHARED: send to background, show banner from response
// ─────────────────────────────────────────────────────────────────────────────
function sendEmailToBackground({ subject, sender, body, links }) {
  // Route through background.js — content scripts on HTTPS pages (Gmail/Outlook)
  // cannot fetch http://localhost directly (Mixed Content block). The service
  // worker is exempt from that restriction.
  chrome.runtime.sendMessage(
    { type: 'SCAN_EMAIL', subject, sender, body, links },
    (result) => {
      // Suppress "receiving end does not exist" when popup isn't open
      void chrome.runtime.lastError;

      if (!result) {
        console.warn('[PhishGuard] No response from background — backend may be offline');
        return;
      }
      if (result.error) {
        console.warn('[PhishGuard] Email scan error:', result.error);
        return;
      }

      console.log('[PhishGuard] Email scan result:', result.verdict, result.risk_score);

      if (result.verdict === 'PHISHING' || result.verdict === 'SUSPICIOUS') {
        showEmailWarningBanner(result);
      }

      // Forward to popup only if it's actually open (swallow the error if not)
      try {
        chrome.runtime.sendMessage({ type: 'EMAIL_SCAN_RESULT', result }, () => {
          void chrome.runtime.lastError; // suppress "no receiver" error
        });
      } catch (_) {}
    }
  );
}


// ─────────────────────────────────────────────────────────────────────────────
// EMAIL WARNING BANNER
// ─────────────────────────────────────────────────────────────────────────────
function showEmailWarningBanner(result) {
  const existing = document.getElementById('phishguard-email-banner');
  if (existing) existing.remove();

  const isPhishing = result.verdict === 'PHISHING';
  const icon  = isPhishing ? '🚨' : '⚠️';
  const title = isPhishing ? 'PHISHING EMAIL DETECTED' : 'SUSPICIOUS EMAIL';
  const accent = isPhishing ? '#ff2d55' : '#ff9500';

  const findings = (result.findings || []).slice(0, 3)
    .map(f => `<span style="display:inline-block;background:rgba(255,255,255,0.06);border-radius:4px;padding:2px 8px;margin:2px;font-size:11px;color:#ccc">${f.label}</span>`)
    .join('');

  const susLinks = (result.links_analyzed || []).filter(l => l.is_suspicious).slice(0, 3);

  const banner = document.createElement('div');
  banner.id = 'phishguard-email-banner';
  banner.style.cssText = [
    'position:fixed', 'top:64px', 'right:16px', 'z-index:2147483647',
    'background:rgba(14,14,22,0.96)', `border:1px solid ${accent}44`,
    'border-radius:14px', 'padding:14px 16px', 'max-width:340px',
    'font-family:-apple-system,sans-serif',
    'box-shadow:0 8px 32px rgba(0,0,0,0.5)', 'backdrop-filter:blur(12px)',
    'opacity:0', 'transform:translateX(20px)',
    'transition:opacity 0.3s ease,transform 0.3s ease',
  ].join(';');

  banner.innerHTML = `
    <div style="display:flex;align-items:flex-start;gap:10px;margin-bottom:10px">
      <span style="font-size:20px;flex-shrink:0">${icon}</span>
      <div style="flex:1">
        <div style="color:${accent};font-weight:800;font-size:13px;letter-spacing:.3px">${title}</div>
        <div style="color:#888;font-size:11px;margin-top:2px">PhishGuard AI · Risk score ${result.risk_score}/100</div>
      </div>
      <button id="pg-email-close" style="background:none;border:none;color:#555;cursor:pointer;font-size:20px;padding:0;line-height:1;flex-shrink:0">×</button>
    </div>
    <div style="color:#bbb;font-size:12px;line-height:1.5;margin-bottom:8px">${result.summary}</div>
    ${findings ? `<div style="margin-bottom:8px">${findings}</div>` : ''}
    ${susLinks.length ? `
      <div style="color:${accent};font-size:11px;font-weight:700;margin-bottom:6px">
        ⛓ ${result.suspicious_links_count} suspicious link(s) — do NOT click
      </div>
      ${susLinks.map(l => `
        <div style="background:rgba(255,255,255,0.04);border:1px solid rgba(255,255,255,0.08);
                    border-radius:7px;padding:5px 9px;margin-top:4px;font-size:10px;
                    color:#8aabff;word-break:break-all;display:flex;justify-content:space-between;gap:8px">
          <span>🔴 ${l.url.length > 55 ? l.url.slice(0, 55) + '…' : l.url}</span>
          <span style="color:#ff2d55;font-weight:700;white-space:nowrap">${l.confidence.toFixed(0)}%</span>
        </div>`).join('')}
    ` : ''}`;

  document.documentElement.appendChild(banner);

  // Animate in
  requestAnimationFrame(() => requestAnimationFrame(() => {
    banner.style.opacity   = '1';
    banner.style.transform = 'translateX(0)';
  }));

  document.getElementById('pg-email-close').addEventListener('click', () => {
    banner.style.opacity   = '0';
    banner.style.transform = 'translateX(20px)';
    setTimeout(() => banner.remove(), 320);
  });

  if (!isPhishing) {
    setTimeout(() => {
      if (!banner.isConnected) return;
      banner.style.opacity   = '0';
      banner.style.transform = 'translateX(20px)';
      setTimeout(() => banner.remove(), 320);
    }, 15000);
  }
}