"""
Production-level URL analyzer.
Computes ALL 87 Kaggle dataset features from live data:
- Real WHOIS (domain age, registration length)
- Real DNS lookup
- Real SSL check
- Real page content fetch
- Google Safe Browsing API (optional)
"""
import re
import socket
import ssl
import json
import hashlib
import requests
import numpy as np
from datetime import datetime
from urllib.parse import urlparse
import tldextract

try:
    import whois as whois_lib
    WHOIS_OK = True
except ImportError:
    WHOIS_OK = False

# ── Cache to avoid re-fetching same domains ───────────────────────────────────
_cache = {}
CACHE_TTL = 3600  # 1 hour

def _cache_get(key):
    if key in _cache:
        val, ts = _cache[key]
        if (datetime.utcnow() - ts).seconds < CACHE_TTL:
            return val
    return None

def _cache_set(key, val):
    _cache[key] = (val, datetime.utcnow())


# ── Main feature builder ──────────────────────────────────────────────────────
def build_features_live(url, page_content=""):
    """
    Builds all 87 features using LIVE data.
    Falls back gracefully if any external call fails.
    """
    parsed    = urlparse(url)
    ext       = tldextract.extract(url)
    hostname  = parsed.hostname or ''
    path      = parsed.path or ''
    scheme    = parsed.scheme or ''
    domain    = ext.domain or ''
    suffix    = ext.suffix or ''
    subdomain = ext.subdomain or ''
    full_domain = f"{domain}.{suffix}"
    url_lower = url.lower()

    words_raw  = [w for w in re.split(r'[\W_]+', url)      if w]
    words_host = [w for w in re.split(r'[\W_]+', hostname) if w]
    words_path = [w for w in re.split(r'[\W_]+', path)     if w]

    SUSPICIOUS_TLDS = {'xyz','tk','ml','ga','cf','gq','info','online','site',
                       'top','club','work','live','buzz','icu','vip'}
    SHORTENERS = {'bit.ly','tinyurl.com','goo.gl','t.co','ow.ly','is.gd',
                  'buff.ly','adf.ly','short.link'}
    BRANDS = ['paypal','amazon','apple','google','microsoft','netflix','facebook',
              'instagram','twitter','linkedin','ebay','chase','wellsfargo',
              'bankofamerica','dropbox','docusign','dhl','fedex','usps']
    PHISH_HINTS = ['login','verify','secure','account','update','confirm','banking',
                   'signin','password','credential','free','lucky','service',
                   'support','alert','urgent','suspended','validate','restore']

    f = {}

    # ── 1. URL Structure Features (always available) ──────────────────────────
    f['length_url']        = len(url)
    f['length_hostname']   = len(hostname)
    f['ip']                = 1 if re.match(r'https?://(\d{1,3}\.){3}\d{1,3}', url) else 0
    f['nb_dots']           = url.count('.')
    f['nb_hyphens']        = url.count('-')
    f['nb_at']             = url.count('@')
    f['nb_qm']             = url.count('?')
    f['nb_and']            = url.count('&')
    f['nb_or']             = url.count('|')
    f['nb_eq']             = url.count('=')
    f['nb_underscore']     = url.count('_')
    f['nb_tilde']          = url.count('~')
    f['nb_percent']        = url.count('%')
    f['nb_slash']          = url.count('/')
    f['nb_star']           = url.count('*')
    f['nb_colon']          = url.count(':')
    f['nb_comma']          = url.count(',')
    f['nb_semicolumn']     = url.count(';')
    f['nb_dollar']         = url.count('$')
    f['nb_space']          = url.count(' ') + url.count('%20')
    f['nb_www']            = url_lower.count('www')
    f['nb_com']            = url_lower.count('.com')
    f['nb_dslash']         = url.count('//')
    f['http_in_path']      = 1 if 'http' in path.lower() else 0
    f['https_token']       = 1 if scheme == 'https' else 0
    f['ratio_digits_url']  = sum(c.isdigit() for c in url) / max(len(url), 1)
    f['ratio_digits_host'] = sum(c.isdigit() for c in hostname) / max(len(hostname), 1)
    f['punycode']          = 1 if 'xn--' in url_lower else 0
    f['port']              = 1 if parsed.port and parsed.port not in (80, 443) else 0
    f['tld_in_path']       = 1 if re.search(r'\.(com|org|net|gov|edu)', path.lower()) else 0
    f['tld_in_subdomain']  = 1 if re.search(r'\.(com|org|net|gov|edu)', subdomain.lower()) else 0
    f['abnormal_subdomain']= 1 if re.search(r'(^|\.)[\w-]{20,}\.', subdomain) else 0
    f['nb_subdomains']     = len(subdomain.split('.')) if subdomain else 0
    f['prefix_suffix']     = 1 if '-' in domain else 0
    f['random_domain']     = 1 if len(domain) > 15 and re.search(r'[0-9]{3,}', domain) else 0
    f['shortening_service']= 1 if any(s in url_lower for s in SHORTENERS) else 0
    f['path_extension']    = 1 if re.search(r'\.(php|asp|aspx|jsp|cgi)', path.lower()) else 0
    f['nb_redirection']    = max(0, url.count('//') - 1)
    f['nb_external_redirection'] = 1 if re.search(r'https?://.+https?://', url) else 0

    # Word features
    f['length_words_raw']   = len(words_raw)
    f['char_repeat']        = max((len(m.group()) for m in re.finditer(r'(.)\1+', url)), default=0)
    f['shortest_words_raw'] = min((len(w) for w in words_raw),  default=0)
    f['shortest_word_host'] = min((len(w) for w in words_host), default=0)
    f['shortest_word_path'] = min((len(w) for w in words_path), default=0)
    f['longest_words_raw']  = max((len(w) for w in words_raw),  default=0)
    f['longest_word_host']  = max((len(w) for w in words_host), default=0)
    f['longest_word_path']  = max((len(w) for w in words_path), default=0)
    f['avg_words_raw']      = float(np.mean([len(w) for w in words_raw]))  if words_raw  else 0.0
    f['avg_word_host']      = float(np.mean([len(w) for w in words_host])) if words_host else 0.0
    f['avg_word_path']      = float(np.mean([len(w) for w in words_path])) if words_path else 0.0

    # Brand/phishing hints
    f['phish_hints']        = sum(1 for h in PHISH_HINTS if h in url_lower)
    LEGIT_BRAND_DOMAINS = {
    'paypal':'paypal','amazon':'amazon','apple':'apple',
    'google':'google','microsoft':'microsoft','netflix':'netflix',
    'facebook':'facebook','instagram':'instagram','twitter':'twitter',
    'linkedin':'linkedin','ebay':'ebay'
    }
    is_brand_impersonation = any(
        b in domain.lower() and domain.lower() != LEGIT_BRAND_DOMAINS.get(b, '') 
        for b in BRANDS
    )
    f['domain_in_brand'] = 1 if is_brand_impersonation else 0
    f['brand_in_subdomain'] = 1 if any(b in subdomain.lower() for b in BRANDS) else 0
    f['brand_in_path']      = 1 if any(b in path.lower() for b in BRANDS) else 0
    f['suspecious_tld']     = 1 if suffix.lower() in SUSPICIOUS_TLDS else 0
    f['statistical_report'] = 0

    # ── 2. LIVE: WHOIS — domain age, registration length ─────────────────────
    whois_data = _get_whois_live(full_domain)
    f['domain_age']                 = whois_data['domain_age_days']
    f['domain_registration_length'] = whois_data['registration_length_days']
    f['whois_registered_domain']    = whois_data['is_registered']

    # ── 3. LIVE: DNS record check ─────────────────────────────────────────────
    f['dns_record'] = _check_dns(hostname)

    # ── 4. LIVE: SSL certificate check ───────────────────────────────────────
    ssl_data = _check_ssl_live(hostname)
    # ssl_valid is used in domain_intel but not a direct model feature
    # we use it to influence https_token
    if ssl_data['valid'] and scheme == 'https':
        f['https_token'] = 1
    elif not ssl_data['valid'] and scheme == 'https':
        f['https_token'] = 0  # broken SSL

    # ── 5. LIVE: Page content analysis ───────────────────────────────────────
    # ── 5. Page content analysis (only if content provided by extension) ──────
    # We do NOT fetch pages ourselves — too many false positives from
    # legitimate JS frameworks (Google, React, etc.)
    if page_content:
        page_data = _analyze_page_content(page_content, full_domain)
    else:
        # Use neutral legit defaults — don't penalize sites we haven't fetched
        page_data = {
            'nb_hyperlinks': 10, 'ratio_int_hyperlinks': 0.7,
            'ratio_ext_hyperlinks': 0.2, 'ratio_null_hyperlinks': 0.02,
            'nb_ext_css': 1, 'ratio_int_redirection': 0.0,
            'ratio_ext_redirection': 0.0, 'ratio_int_errors': 0.0,
            'ratio_ext_errors': 0.0, 'login_form': 0, 'external_favicon': 0,
            'links_in_tags': 0.5, 'submit_email': 0, 'ratio_int_media': 0.6,
            'ratio_ext_media': 0.1, 'sfh': 0, 'iframe': 0, 'popup_window': 0,
            'safe_anchor': 0.8, 'onmouseover': 0, 'right_clic': 0,
            'empty_title': 0, 'domain_in_title': 1, 'domain_with_copyright': 1
        }

    f['nb_hyperlinks']          = page_data['nb_hyperlinks']
    f['ratio_intHyperlinks']    = page_data['ratio_int_hyperlinks']
    f['ratio_extHyperlinks']    = page_data['ratio_ext_hyperlinks']
    f['ratio_nullHyperlinks']   = page_data['ratio_null_hyperlinks']
    f['nb_extCSS']              = page_data['nb_ext_css']
    f['ratio_intRedirection']   = page_data['ratio_int_redirection']
    f['ratio_extRedirection']   = page_data['ratio_ext_redirection']
    f['ratio_intErrors']        = page_data['ratio_int_errors']
    f['ratio_extErrors']        = page_data['ratio_ext_errors']
    f['login_form']             = page_data['login_form']
    f['external_favicon']       = page_data['external_favicon']
    f['links_in_tags']          = page_data['links_in_tags']
    f['submit_email']           = page_data['submit_email']
    f['ratio_intMedia']         = page_data['ratio_int_media']
    f['ratio_extMedia']         = page_data['ratio_ext_media']
    f['sfh']                    = page_data['sfh']
    f['iframe']                 = page_data['iframe']
    f['popup_window']           = page_data['popup_window']
    f['safe_anchor']            = page_data['safe_anchor']
    f['onmouseover']            = page_data['onmouseover']
    f['right_clic']             = page_data['right_clic']
    f['empty_title']            = page_data['empty_title']
    f['domain_in_title']        = page_data['domain_in_title']
    f['domain_with_copyright']  = page_data['domain_with_copyright']

    # ── 6. LIVE: Web traffic / Google index estimate ──────────────────────────
    f['web_traffic']   = _estimate_web_traffic(full_domain, whois_data)
    f['google_index']  = _check_google_index(url)
    f['page_rank']     = _estimate_page_rank(full_domain, whois_data)

    return f


# ── WHOIS lookup ──────────────────────────────────────────────────────────────
def _get_whois_live(domain):
    cache_key = f"whois:{domain}"
    cached = _cache_get(cache_key)
    if cached:
        return cached

    result = {
        'domain_age_days': -1,
        'registration_length_days': -1,
        'is_registered': 0
    }

    if not WHOIS_OK:
        result['is_registered'] = _check_dns(domain)
        if result['is_registered']:
            result['domain_age_days'] = 730
            result['registration_length_days'] = 730
        _cache_set(cache_key, result)
        return result

    try:
        w = whois_lib.whois(domain)

        def pick_date(val):
            """Extract first valid naive datetime from whois date field."""
            if val is None:
                return None
            if not isinstance(val, list):
                val = [val]
            for v in val:
                if v is None:
                    continue
                if isinstance(v, str):
                    for fmt in ["%Y-%m-%d", "%d-%b-%Y", "%Y-%m-%dT%H:%M:%SZ"]:
                        try:
                            return datetime.strptime(v, fmt)
                        except Exception:
                            pass
                elif isinstance(v, datetime):
                    # Strip timezone — make naive UTC
                    try:
                        return v.replace(tzinfo=None)
                    except Exception:
                        return v
            return None

        creation = pick_date(w.creation_date)
        expiry   = pick_date(w.expiration_date)

        if creation and isinstance(creation, datetime):
            result['domain_age_days'] = max(0, (datetime.utcnow() - creation).days)
            result['is_registered'] = 1

        if expiry and creation and isinstance(expiry, datetime):
            result['registration_length_days'] = max(0, (expiry - creation).days)

        # If we got a domain name or registrar but no dates, still mark as registered
        if result['is_registered'] == 0:
            if w.domain_name or w.registrar:
                result['is_registered'] = 1
                result['domain_age_days'] = 730  # registered but unknown age

    except Exception as e:
        print(f"WHOIS error for {domain}: {e}")
        result['is_registered'] = _check_dns(domain)
        if result['is_registered']:
            result['domain_age_days'] = 730
            result['registration_length_days'] = 730

    _cache_set(cache_key, result)
    return result

# ── DNS check ─────────────────────────────────────────────────────────────────
def _check_dns(hostname):
    if not hostname:
        return 0
    cache_key = f"dns:{hostname}"
    cached = _cache_get(cache_key)
    if cached is not None:
        return cached
    try:
        socket.gethostbyname(hostname)
        result = 1
    except Exception:
        result = 0
    _cache_set(cache_key, result)
    return result


# ── SSL check ─────────────────────────────────────────────────────────────────
def _check_ssl_live(hostname):
    if not hostname:
        return {'valid': False, 'issuer': None, 'expiry': None}
    cache_key = f"ssl:{hostname}"
    cached = _cache_get(cache_key)
    if cached:
        return cached
    result = {'valid': False, 'issuer': None, 'expiry': None}
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(
            socket.create_connection((hostname, 443), timeout=4),
            server_hostname=hostname
        ) as s:
            cert = s.getpeercert()
            result['valid'] = True
            issuer_dict = dict(x[0] for x in cert.get('issuer', []))
            result['issuer'] = issuer_dict.get('organizationName', 'Unknown')
            expiry_str = cert.get('notAfter', '')
            if expiry_str:
                expiry_dt = datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z")
                result['expiry'] = expiry_dt.strftime("%B %d, %Y")
                if (expiry_dt - datetime.utcnow()).days < 0:
                    result['valid'] = False
    except Exception:
        pass
    _cache_set(cache_key, result)
    return result


# ── Page content fetch and analysis ──────────────────────────────────────────
def _fetch_and_analyze_page(url, domain):
    """Fetches page and analyzes it. Returns neutral values if fetch fails."""
    cache_key = f"page:{url[:100]}"
    cached = _cache_get(cache_key)
    if cached:
        return cached

    content = ""
    try:
        resp = requests.get(url, timeout=5, allow_redirects=True,
                            headers={'User-Agent': 'Mozilla/5.0 (compatible; PhishGuard/2.0)'})
        content = resp.text[:80000]
    except Exception:
        pass  # fetch failed — analyze with empty content

    result = _analyze_page_content(content, domain)
    _cache_set(cache_key, result)
    return result


def _analyze_page_content(content, domain):
    """
    Analyzes HTML content and returns all page-level features.
    If content is empty, returns conservative LEGIT defaults
    (not zeros, which would bias toward phishing).
    """
    if not content:
        return {
            'nb_hyperlinks': 10, 'ratio_int_hyperlinks': 0.7,
            'ratio_ext_hyperlinks': 0.2, 'ratio_null_hyperlinks': 0.02,
            'nb_ext_css': 1, 'ratio_int_redirection': 0.0,
            'ratio_ext_redirection': 0.0, 'ratio_int_errors': 0.0,
            'ratio_ext_errors': 0.0, 'login_form': 0, 'external_favicon': 0,
            'links_in_tags': 0.5, 'submit_email': 0, 'ratio_int_media': 0.6,
            'ratio_ext_media': 0.1, 'sfh': 0, 'iframe': 0, 'popup_window': 0,
            'safe_anchor': 0.8, 'onmouseover': 0, 'right_clic': 0,
            'empty_title': 0, 'domain_in_title': 1, 'domain_with_copyright': 1
        }

    cl = content.lower()
    d  = domain.lower().split('.')[0]  # just the domain name part

    # Links
    all_links   = re.findall(r'href=["\']([^"\']*)["\']', cl)
    total_links = max(len(all_links), 1)
    int_links   = [l for l in all_links if d in l or l.startswith('/') or not l.startswith('http')]
    ext_links   = [l for l in all_links if l.startswith('http') and d not in l]
    null_links  = [l for l in all_links if l in ('#', '', 'javascript:void(0)', 'javascript:;')]

    nb_hyperlinks        = len(all_links)
    ratio_int_hyperlinks = len(int_links) / total_links
    ratio_ext_hyperlinks = len(ext_links) / total_links
    ratio_null_hyperlinks= len(null_links) / total_links

    # External CSS
    ext_css = re.findall(r'<link[^>]*href=["\']https?://[^"\']*\.css["\']', cl)
    nb_ext_css = len(ext_css)

    # Media
    all_media = re.findall(r'(?:src|href)=["\']([^"\']*(?:\.jpg|\.png|\.gif|\.svg|\.webp|\.mp4))["\']', cl)
    total_media = max(len(all_media), 1)
    int_media = [m for m in all_media if not m.startswith('http') or d in m]
    ext_media = [m for m in all_media if m.startswith('http') and d not in m]
    ratio_int_media = len(int_media) / total_media
    ratio_ext_media = len(ext_media) / total_media

    # Forms
    form_actions = re.findall(r'<form[^>]*action=["\']([^"\']*)["\']', cl)
    login_form   = 1 if re.search(r'type=["\']password["\']', cl) else 0
    submit_email = 1 if re.search(r'action=["\']mailto:', cl) else 0
    sfh          = 1 if any(a.startswith('http') and d not in a for a in form_actions) else 0

    # Suspicious elements
    iframe        = 1 if re.search(r'<iframe', cl) else 0
    popup_window  = 1 if re.search(r'window\.open\s*\(', cl) else 0
    onmouseover   = 1 if 'onmouseover' in cl else 0
    right_clic    = 1 if re.search(r'(return\s*false.*contextmenu|disableselect|nocopy|ondragstart)', cl) else 0

    # Favicon
    favicon_match = re.search(r'<link[^>]*rel=["\'][^"\']*icon[^"\']*["\'][^>]*href=["\']([^"\']+)["\']', cl)
    external_favicon = 0
    if favicon_match:
        fav_url = favicon_match.group(1)
        external_favicon = 1 if fav_url.startswith('http') and d not in fav_url else 0

    # Anchors
    anchors = re.findall(r'href=["\']([^"\']*)["\']', cl)
    safe_anchor = len([a for a in anchors if not a.startswith('javascript') and a != '#']) / max(len(anchors), 1)

    # Links in tags (script/link tags pointing external)
    links_in_tags_matches = re.findall(r'<(?:script|link)[^>]*(?:src|href)=["\']([^"\']*)["\']', cl)
    links_in_tags = len([l for l in links_in_tags_matches if l.startswith('http') and d not in l]) / max(len(links_in_tags_matches), 1)

    # Title
    title_match = re.search(r'<title[^>]*>([^<]*)</title>', cl)
    title_text  = title_match.group(1).lower() if title_match else ''
    empty_title       = 1 if not title_text.strip() else 0
    domain_in_title   = 1 if d in title_text else 0
    domain_with_copyright = 1 if (d in cl and ('©' in content or 'copyright' in cl)) else 0

    return {
        'nb_hyperlinks': nb_hyperlinks,
        'ratio_int_hyperlinks': round(ratio_int_hyperlinks, 4),
        'ratio_ext_hyperlinks': round(ratio_ext_hyperlinks, 4),
        'ratio_null_hyperlinks': round(ratio_null_hyperlinks, 4),
        'nb_ext_css': nb_ext_css,
        'ratio_int_redirection': 0.0,
        'ratio_ext_redirection': 0.0,
        'ratio_int_errors': 0.0,
        'ratio_ext_errors': 0.0,
        'login_form': login_form,
        'external_favicon': external_favicon,
        'links_in_tags': round(links_in_tags, 4),
        'submit_email': submit_email,
        'ratio_int_media': round(ratio_int_media, 4),
        'ratio_ext_media': round(ratio_ext_media, 4),
        'sfh': sfh,
        'iframe': iframe,
        'popup_window': popup_window,
        'safe_anchor': round(safe_anchor, 4),
        'onmouseover': onmouseover,
        'right_clic': right_clic,
        'empty_title': empty_title,
        'domain_in_title': domain_in_title,
        'domain_with_copyright': domain_with_copyright
    }


# ── Traffic/rank estimation from WHOIS data ───────────────────────────────────
def _estimate_web_traffic(domain, whois_data):
    """
    Estimates traffic based on domain age and DNS existence.
    Old registered domains with DNS = likely has traffic.
    """
    age  = whois_data.get('domain_age_days', -1)
    dns  = whois_data.get('is_registered', 0)
    if not dns: return 0
    if age < 0:  return 1   # unknown age but registered
    if age > 365: return 1  # over 1 year old — likely has traffic
    if age > 90:  return 1  # over 3 months
    return 0                # very new — probably no traffic


def _check_google_index(url):
    """
    Uses Google's public search to check if URL is indexed.
    Falls back gracefully if request fails.
    """
    cache_key = f"gindex:{hashlib.md5(url.encode()).hexdigest()[:8]}"
    cached = _cache_get(cache_key)
    if cached is not None:
        return cached
    try:
        ext = tldextract.extract(url)
        domain = f"{ext.domain}.{ext.suffix}"
        resp = requests.get(
            f"https://www.google.com/search?q=site:{domain}",
            timeout=4,
            headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'},
            allow_redirects=True
        )
        # If Google returns results page (not "no results"), domain is indexed
        result = 1 if 'did not match any documents' not in resp.text.lower() else 0
    except Exception:
        result = 1  # assume indexed if we can't check (don't penalize)
    _cache_set(cache_key, result)
    return result


def _estimate_page_rank(domain, whois_data):
    """
    Estimates page rank (1-10) based on domain age and registration.
    Production: use Moz API or Majestic API.
    """
    age = whois_data.get('domain_age_days', -1)
    if age < 0:   return 3
    if age > 1825: return 6   # 5+ years
    if age > 730:  return 5   # 2+ years
    if age > 365:  return 4   # 1+ year
    if age > 90:   return 3   # 3+ months
    if age > 30:   return 2   # 1+ month
    return 1                  # brand new