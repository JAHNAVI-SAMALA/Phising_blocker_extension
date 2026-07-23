import re
import tldextract
import urllib.parse
from urllib.parse import urlparse

def extract_features(url, page_content=""):
    features = {}
    parsed = urlparse(url)
    ext = tldextract.extract(url)

    # --- URL-based features ---
    features['url_length'] = len(url)
    features['num_dots'] = url.count('.')
    features['num_hyphens'] = url.count('-')
    features['num_at'] = url.count('@')
    features['num_slashes'] = url.count('/')
    features['num_digits'] = sum(c.isdigit() for c in url)
    features['has_ip'] = int(bool(re.match(
        r'https?://(\d{1,3}\.){3}\d{1,3}', url)))
    features['has_https'] = int(parsed.scheme == 'https')
    features['subdomain_count'] = len(ext.subdomain.split('.')) if ext.subdomain else 0
    features['domain_length'] = len(ext.domain)
    features['path_length'] = len(parsed.path)
    features['query_length'] = len(parsed.query)
    features['has_suspicious_words'] = int(bool(re.search(
        r'(login|verify|secure|account|update|confirm|banking|paypal|ebay|amazon|signin)',
        url.lower())))
    features['double_slash_redirect'] = int('//' in parsed.path)
    features['has_port'] = int(bool(parsed.port))
    features['tld_in_path'] = int(bool(re.search(
        r'\.(com|org|net|gov)', parsed.path)))
    features['url_entropy'] = _entropy(url)
    features['num_special_chars'] = sum(not c.isalnum() for c in url)

    # --- Page content features ---
    if page_content:
        content_lower = page_content.lower()
        features['has_password_field'] = int('type="password"' in content_lower or
                                              "type='password'" in content_lower)
        features['has_login_form'] = int('login' in content_lower or 'signin' in content_lower)
        features['external_links_ratio'] = _external_links_ratio(page_content, ext.domain)
        features['has_favicon_mismatch'] = int(_favicon_mismatch(page_content, ext.domain))
        features['num_iframes'] = content_lower.count('<iframe')
        features['has_obfuscated_js'] = int('eval(' in content_lower or 'unescape(' in content_lower)
        features['form_action_external'] = int(_form_action_external(page_content, ext.domain))
    else:
        for k in ['has_password_field','has_login_form','external_links_ratio',
                  'has_favicon_mismatch','num_iframes','has_obfuscated_js','form_action_external']:
            features[k] = 0

    return features

def _entropy(s):
    import math
    from collections import Counter
    counts = Counter(s)
    total = len(s)
    return -sum((c/total) * math.log2(c/total) for c in counts.values()) if total else 0

def _external_links_ratio(content, domain):
    links = re.findall(r'href=["\']([^"\']+)["\']', content)
    if not links: return 0.0
    external = sum(1 for l in links if domain not in l and l.startswith('http'))
    return external / len(links)

def _favicon_mismatch(content, domain):
    favicon = re.search(r'<link[^>]*rel=["\'](?:shortcut )?icon["\'][^>]*href=["\']([^"\']+)["\']', content)
    if favicon:
        return domain not in favicon.group(1)
    return False

def _form_action_external(content, domain):
    actions = re.findall(r'<form[^>]*action=["\']([^"\']+)["\']', content)
    for action in actions:
        if action.startswith('http') and domain not in action:
            return True
    return False