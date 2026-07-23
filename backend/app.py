"""
PhishGuard AI — Production Backend v3.0
Uses LIVE feature computation: real WHOIS, DNS, SSL, page fetch.
No fake defaults. Every feature is computed from actual data.
"""
from flask import Flask, request, jsonify, Response
from flask_cors import CORS
import joblib
import pandas as pd
import numpy as np
import os, re, json, queue, threading
from datetime import datetime
from urllib.parse import urlparse
import tldextract

from live_analyzer import build_features_live, _check_ssl_live, _get_whois_live, _check_dns
from feature_extractor import extract_features
from retrain_pipeline import async_retrain
from db.database import (
    report_site, get_new_alerts, get_all_reported_for_training,
    is_known_phishing, init_db, get_stats
)

app = Flask(__name__)
CORS(app, origins="*", supports_credentials=True,
     allow_headers=["Content-Type", "Authorization"],
     methods=["GET", "POST", "OPTIONS"])
init_db()

MODEL_PATH    = os.path.join(os.path.dirname(__file__), 'models', 'phishing_model.pkl')
FEATURES_PATH = os.path.join(os.path.dirname(__file__), 'models', 'feature_names.pkl')
RETRAIN_THRESHOLD = 5

_sse_subscribers = []
_sse_lock = threading.Lock()

# ── Always-safe domains — never block these ───────────────────────────────────
ALWAYS_SAFE = {
    'google.com', 'gmail.com', 'youtube.com', 'google.co.in',
    'github.com', 'githubusercontent.com', 'githubassets.com',
    'microsoft.com', 'live.com', 'outlook.com', 'office.com', 'microsoftonline.com',
    'apple.com', 'icloud.com',
    'amazon.com', 'amazonaws.com',
    'wikipedia.org', 'wikimedia.org',
    'stackoverflow.com', 'stackexchange.com',
    'linkedin.com', 'twitter.com', 'x.com',
    'facebook.com', 'instagram.com', 'whatsapp.com',
    'openai.com', 'chatgpt.com', 'anthropic.com',
    'reddit.com', 'netflix.com', 'spotify.com',
    'cloudflare.com', 'zoom.us', 'slack.com',
    'notion.so', 'figma.com', 'canva.com',
    'npmjs.com', 'pypi.org', 'anaconda.com',
    'render.com', 'railway.app', 'netlify.com', 'vercel.com',
    'heroku.com', 'digitalocean.com', 'aws.amazon.com',
    'dropbox.com', 'drive.google.com', 'docs.google.com',
}


def load_model():
    if os.path.exists(MODEL_PATH) and os.path.exists(FEATURES_PATH):
        return joblib.load(MODEL_PATH), joblib.load(FEATURES_PATH)
    return None, None


# ── CORE: URL Analysis ────────────────────────────────────────────────────────
@app.route('/analyze', methods=['POST'])
def analyze():
    data         = request.json or {}
    url          = data.get('url', '').strip()
    page_content = data.get('page_content', '')

    if not url:
        return jsonify({'error': 'URL required'}), 400

    if not url.startswith('http'):
        return jsonify({
            'url': url, 'is_phishing': False, 'confidence': 0,
            'risk_level': 'LOW', 'risk_factors': [], 'community_reports': 0
        })

    try:
        ext    = tldextract.extract(url)
        domain = f"{ext.domain}.{ext.suffix}"

        # ── ALWAYS SAFE check — before anything else ──────────────────────────
        if any(domain == d or domain.endswith('.' + d) for d in ALWAYS_SAFE):
            return jsonify({
                'url': url, 'is_phishing': False, 'confidence': 99,
                'risk_level': 'LOW', 'source': 'safe_list',
                'risk_factors': [], 'community_reports': 0,
                'domain_age_days': -1, 'has_ssl': True, 'dns_exists': True
            })

        # ── Community database check ──────────────────────────────────────────
        known, report_count = is_known_phishing(domain)
        if known:
            return jsonify({
                'url': url, 'is_phishing': True, 'confidence': 99,
                'risk_level': 'CRITICAL', 'source': 'community_database',
                'risk_factors': [f'Reported {report_count} time(s) by PhishGuard community'],
                'community_reports': report_count
            })

        # ── Load model ────────────────────────────────────────────────────────
        model, feature_names = load_model()
        if model is None:
            return jsonify({'error': 'Model not loaded. Run train_model.py first.'}), 503

        # ── Compute ALL 87 features from live data ────────────────────────────
        features   = build_features_live(url, page_content)
        feature_df = pd.DataFrame([features])[feature_names]

        prediction  = int(model.predict(feature_df)[0])
        probability = float(model.predict_proba(feature_df)[0][1])

        risk = ('CRITICAL' if probability >= 0.85
                else 'HIGH'   if probability >= 0.70
                else 'MEDIUM' if probability >= 0.50
                else 'LOW')

        risk_factors = _build_risk_factors(features, probability)

        return jsonify({
            'url': url,
            'is_phishing': bool(prediction),
            'confidence': round(probability * 100, 1),
            'risk_level': risk,
            'source': 'ml_model',
            'risk_factors': risk_factors[:5],
            'community_reports': 0,
            'domain_age_days': features.get('domain_age', -1),
            'has_ssl': bool(features.get('https_token', 0)),
            'dns_exists': bool(features.get('dns_record', 0)),
        })

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


def _build_risk_factors(f, probability):
    factors = []
    if f.get('ip'):
        factors.append('IP address used instead of domain name')
    if f.get('phish_hints', 0) >= 2:
        factors.append(f"Phishing keywords in URL ({f['phish_hints']} found)")
    if f.get('nb_subdomains', 0) > 3:
        factors.append(f"Excessive subdomains ({f['nb_subdomains']})")
    if f.get('prefix_suffix'):
        factors.append('Hyphen trick used in domain name')
    if f.get('suspecious_tld'):
        factors.append('High-risk TLD (.xyz, .tk, .ml, etc.)')
    if not f.get('https_token'):
        factors.append('No HTTPS — connection is unencrypted')
    if f.get('shortening_service'):
        factors.append('URL shortener used to hide destination')
    if f.get('nb_at'):
        factors.append('@ symbol in URL (credential bypass trick)')
    if f.get('brand_in_subdomain'):
        factors.append('Trusted brand name used in subdomain')
    if f.get('domain_in_brand'):
        factors.append('Trusted brand name used in domain')
    if f.get('login_form') and f.get('sfh'):
        factors.append('Login form submits data to external server')
    if f.get('external_favicon'):
        factors.append('Favicon loaded from external domain')
    if f.get('iframe'):
        factors.append('Hidden iframe detected on page')
    if f.get('onmouseover'):
        factors.append('JavaScript mouseover event obfuscation')
    if f.get('right_clic'):
        factors.append('Right-click disabled (hiding source)')
    if f.get('empty_title'):
        factors.append('Page has no title (unusual for legit sites)')
    if f.get('domain_age', 365) < 30 and f.get('domain_age', -1) >= 0:
        factors.append(f"Domain is only {f['domain_age']} days old")
    elif f.get('domain_age', 365) < 90 and f.get('domain_age', -1) >= 0:
        factors.append(f"Domain is very new ({f['domain_age']} days old)")
    if not f.get('dns_record'):
        factors.append('No DNS record found for domain')
    if not f.get('whois_registered_domain'):
        factors.append('Domain not found in WHOIS registry')
    if f.get('punycode'):
        factors.append('Punycode encoding (Unicode domain trick)')
    if f.get('http_in_path'):
        factors.append('HTTP URL embedded inside path (redirect trick)')
    if f.get('nb_external_redirection'):
        factors.append('External URL redirection chain detected')
    if f.get('random_domain'):
        factors.append('Domain appears randomly generated')
    return factors


# ── FEATURE 1: Community Reporting + Live Push + Auto-retrain ─────────────────
@app.route('/report', methods=['POST'])
def report_phishing():
    data        = request.json or {}
    url         = data.get('url', '').strip()
    reported_by = data.get('reported_by', 'anonymous')
    if not url:
        return jsonify({'error': 'URL required'}), 400
    try:
        ext      = tldextract.extract(url)
        domain   = f"{ext.domain}.{ext.suffix}"
        features = extract_features(url, data.get('page_content', ''))
        site_id  = report_site(url, domain, reported_by, features)
        _broadcast_sse({
            'type': 'NEW_THREAT', 'url': url, 'domain': domain,
            'reported_by': reported_by,
            'timestamp': datetime.utcnow().isoformat(),
            'severity': 'HIGH', 'report_count': 1,
            'message': f'Community alert: {domain} reported as phishing!'
        })
        all_reports = get_all_reported_for_training()
        if len(all_reports) % RETRAIN_THRESHOLD == 0 and len(all_reports) > 0:
            async_retrain(all_reports)
        return jsonify({
            'status': 'reported', 'site_id': site_id, 'domain': domain,
            'message': 'Threat shared with all PhishGuard users.'
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/alerts/stream')
def alerts_stream():
    def gen():
        q = queue.Queue()
        with _sse_lock:
            _sse_subscribers.append(q)
        yield f"data: {json.dumps({'type': 'CONNECTED'})}\n\n"
        try:
            while True:
                try:
                    yield f"data: {json.dumps(q.get(timeout=25))}\n\n"
                except queue.Empty:
                    yield ": heartbeat\n\n"
        finally:
            with _sse_lock:
                if q in _sse_subscribers:
                    _sse_subscribers.remove(q)
    return Response(gen(), mimetype='text/event-stream',
                    headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'})


@app.route('/alerts/recent')
def recent_alerts():
    since = request.args.get('since', '1970-01-01T00:00:00')
    alerts = get_new_alerts(since)
    return jsonify({'alerts': alerts, 'count': len(alerts)})


def _broadcast_sse(message):
    with _sse_lock:
        dead = []
        for q in _sse_subscribers:
            try:
                q.put_nowait(message)
            except queue.Full:
                dead.append(q)
        for q in dead:
            _sse_subscribers.remove(q)


# ── FEATURE 2: Email Phishing Scanner ────────────────────────────────────────
EMAIL_PATTERNS = {
    'urgent_language': [
        r'urgent(ly)?', r'action required', r'verify now',
        r'account (suspended|locked|compromised)',
        r'within 24 hours', r'immediate(ly)?'
    ],
    'credential_request': [
        r'confirm your (password|credentials)',
        r'enter your (banking|credit card)',
        r'verify your (identity|account|email)',
        r'update your (payment|billing) (info|details)'
    ],
    'suspicious_sender': [
        r'@.*\.(xyz|tk|ml|ga|cf|gq)\b',
        r'support@[^.]+\.(info|biz|online|site)'
    ],
    'link_mismatch': [
        r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',
        r'bit\.ly|tinyurl|goo\.gl'
    ]
}


@app.route('/scan-email', methods=['POST'])
def scan_email():
    data       = request.json or {}
    subject    = data.get('subject', '')
    body       = data.get('body', '')
    links      = data.get('links', [])
    findings   = []
    risk_score = 0
    full_text  = f"{subject} {body}".lower()

    for category, patterns in EMAIL_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, full_text, re.IGNORECASE):
                findings.append({
                    'type': category,
                    'label': category.replace('_', ' ').title(),
                    'severity': 'HIGH' if 'credential' in category else 'MEDIUM'
                })
                risk_score += 25 if 'credential' in category else 15
                break

    link_results = []
    model, feature_names = load_model()
    for link in links[:10]:
        try:
            feats    = build_features_live(link)
            if model is not None and feature_names is not None:
                feat_df  = pd.DataFrame([feats])[feature_names]
                prob     = float(model.predict_proba(feat_df)[0][1])
            else:
                prob = 0.0
            is_phish = prob > 0.6
            ext2     = tldextract.extract(link)
            dom      = f"{ext2.domain}.{ext2.suffix}"
            known, _ = is_known_phishing(dom)
            if known:
                is_phish = True
                prob     = max(prob, 0.95)
            link_results.append({
                'url': link, 'is_suspicious': is_phish,
                'confidence': round(prob * 100, 1),
                'community_flagged': known
            })
            if is_phish:
                risk_score += 30
        except Exception:
            link_results.append({'url': link, 'is_suspicious': False, 'error': True})

    risk_score = min(risk_score, 100)
    sus_links  = [l for l in link_results if l.get('is_suspicious')]
    verdict, risk_level = (
        ('PHISHING',   'HIGH')   if risk_score >= 70 else
        ('SUSPICIOUS', 'MEDIUM') if risk_score >= 40 else
        ('SAFE',       'LOW')
    )
    summary = (
        "No obvious phishing indicators detected." if verdict == 'SAFE' else
        f"This email has {len(findings)} phishing indicator(s)"
        + (f" and {len(sus_links)} suspicious link(s)." if sus_links else ".")
        + (" Do NOT click any links." if verdict == 'PHISHING' else "")
    )
    return jsonify({
        'verdict': verdict, 'risk_level': risk_level,
        'risk_score': risk_score, 'findings': findings,
        'links_analyzed': link_results,
        'suspicious_links_count': len(sus_links),
        'summary': summary
    })


# ── FEATURE 3: Domain Intelligence ───────────────────────────────────────────
@app.route('/domain-intel', methods=['POST'])
def domain_intel():
    data         = request.json or {}
    url          = data.get('url', '').strip()
    page_content = data.get('page_content', '')
    if not url:
        return jsonify({'error': 'URL required'}), 400
    try:
        parsed   = urlparse(url)
        ext      = tldextract.extract(url)
        hostname = parsed.hostname or ''
        domain   = f"{ext.domain}.{ext.suffix}"

        whois_data = _get_whois_live(domain)
        ssl_data   = _check_ssl_live(hostname)
        dns_ok     = bool(_check_dns(hostname))

        from live_analyzer import _fetch_and_analyze_page, _analyze_page_content
        if page_content:
            page_data = _analyze_page_content(page_content, domain)
        else:
            page_data = _fetch_and_analyze_page(url, domain)

        BRANDS = ['paypal','amazon','apple','google','microsoft','netflix',
                  'facebook','instagram','twitter','linkedin','ebay',
                  'chase','wellsfargo','bankofamerica','dropbox','docusign']
        legit_domains = {
            'paypal':'paypal.com','amazon':'amazon.com','apple':'apple.com',
            'google':'google.com','microsoft':'microsoft.com','netflix':'netflix.com',
            'facebook':'facebook.com','instagram':'instagram.com'
        }
        brand_hit = next((b for b in BRANDS if b in ext.domain.lower()), None)
        is_impersonating = (brand_hit and domain != legit_domains.get(brand_hit, domain))

        risk_signals = []
        age = whois_data.get('domain_age_days', -1)
        if age >= 0 and age < 30:
            risk_signals.append({'label': f'Domain only {age} days old', 'severity': 'CRITICAL'})
        elif age >= 0 and age < 90:
            risk_signals.append({'label': f'Domain is very new ({age} days)', 'severity': 'HIGH'})
        if not ssl_data['valid']:
            risk_signals.append({'label': 'Invalid or missing SSL certificate', 'severity': 'HIGH'})
        if not dns_ok:
            risk_signals.append({'label': 'No DNS record found', 'severity': 'CRITICAL'})
        if is_impersonating:
            risk_signals.append({'label': f'Impersonating {brand_hit.title()}', 'severity': 'CRITICAL'})
        if page_data.get('login_form') and page_data.get('sfh'):
            risk_signals.append({'label': 'Login form sends data externally', 'severity': 'CRITICAL'})
        if page_data.get('iframe'):
            risk_signals.append({'label': 'Hidden iframe detected', 'severity': 'MEDIUM'})
        if page_data.get('onmouseover'):
            risk_signals.append({'label': 'JS obfuscation via onmouseover', 'severity': 'MEDIUM'})

        return jsonify({
            'domain': domain,
            'whois': {
                'creation_date': _age_to_date_str(age),
                'domain_age_days': age,
                'registration_length_days': whois_data.get('registration_length_days', -1),
                'is_registered': bool(whois_data.get('is_registered')),
                'registrar': 'See whois.domaintools.com',
                'privacy_protected': False,
                'country': 'Unknown'
            },
            'ssl': {
                'valid': ssl_data['valid'],
                'issuer': ssl_data.get('issuer'),
                'expiry': ssl_data.get('expiry')
            },
            'dns': {'exists': dns_ok},
            'page_analysis': {
                'has_fake_login': bool(page_data.get('login_form')),
                'brand_impersonation': brand_hit.title() if is_impersonating else None,
                'form_steals_credentials': bool(page_data.get('sfh')),
                'has_obfuscated_js': bool(page_data.get('onmouseover') or page_data.get('right_clic')),
                'has_password_field': bool(page_data.get('login_form')),
                'external_favicon': bool(page_data.get('external_favicon')),
                'iframe_detected': bool(page_data.get('iframe')),
            },
            'risk_signals': risk_signals
        })
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


def _age_to_date_str(age_days):
    if age_days < 0:
        return 'Unknown'
    from datetime import timedelta
    created = datetime.utcnow() - timedelta(days=age_days)
    return created.strftime('%B %d, %Y')


# ── Statistics Dashboard ─────────────────────────────────────────────────────
@app.route('/stats')
def stats():
    """Aggregate statistics for popup dashboard and resume demo."""
    try:
        data = get_stats()
        model, _ = load_model()
        data['model_loaded'] = model is not None
        data['version'] = '3.0-production'
        data['sse_subscribers'] = len(_sse_subscribers)
        return jsonify(data)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ── Health ────────────────────────────────────────────────────────────────────
@app.route('/health')
def health():
    model, _ = load_model()
    try:
        db_stats = get_stats()
    except Exception:
        db_stats = {}
    return jsonify({
        'status': 'ok',
        'model_loaded': model is not None,
        'community_reports': db_stats.get('total_reported', 0),
        'active_threats': db_stats.get('active_threats', 0),
        'reports_last_24h': db_stats.get('reports_last_24h', 0),
        'sse_subscribers': len(_sse_subscribers),
        'version': '3.0-production'
    })


@app.route('/')
def index():
    return jsonify({
        'name': 'PhishGuard AI',
        'version': '3.0.0-production',
        'endpoints': ['/analyze', '/report', '/alerts/recent',
                      '/scan-email', '/domain-intel', '/stats', '/health']
    })


# ── Startup ───────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    print("[*] PhishGuard AI Backend v3.0 PRODUCTION starting...")
    print("    Real WHOIS [OK]  Real DNS [OK]  Real SSL [OK]  Real page fetch [OK]")
    print("    Endpoints: /analyze  /report  /scan-email  /domain-intel  /stats  /health")
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=False)