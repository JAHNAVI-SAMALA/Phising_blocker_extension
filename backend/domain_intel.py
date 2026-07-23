"""
Domain Intelligence - WHOIS, age, SSL, and visual analysis
Used for the threat summary card shown to users.
"""
import re
import ssl
import socket
import requests
from datetime import datetime
from urllib.parse import urlparse
import tldextract

# ── Try python-whois (install: pip install python-whois) ──────────────────
try:
    import whois as whois_lib
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False

def get_domain_intelligence(url, page_content=""):
    """
    Returns a rich intelligence report for the threat summary card.
    """
    parsed = urlparse(url)
    ext = tldextract.extract(url)
    domain = f"{ext.domain}.{ext.suffix}"
    hostname = parsed.hostname or domain

    report = {
        "domain": domain,
        "full_url": url,
        "whois": get_whois_info(domain),
        "ssl": get_ssl_info(hostname),
        "page_analysis": analyze_page(page_content, domain),
        "risk_signals": [],
        "generated_at": datetime.utcnow().isoformat()
    }

    # Aggregate risk signals
    if report["whois"]["domain_age_days"] is not None:
        if report["whois"]["domain_age_days"] < 30:
            report["risk_signals"].append({
                "icon": "🆕",
                "label": "Very New Domain",
                "detail": f"Created only {report['whois']['domain_age_days']} days ago",
                "severity": "HIGH"
            })
        elif report["whois"]["domain_age_days"] < 90:
            report["risk_signals"].append({
                "icon": "📅",
                "label": "New Domain",
                "detail": f"Created {report['whois']['domain_age_days']} days ago",
                "severity": "MEDIUM"
            })

    if not report["ssl"]["valid"]:
        report["risk_signals"].append({
            "icon": "🔓",
            "label": "Invalid/Missing SSL",
            "detail": report["ssl"].get("error", "No HTTPS encryption"),
            "severity": "HIGH"
        })

    if report["page_analysis"]["has_fake_login"]:
        report["risk_signals"].append({
            "icon": "🎭",
            "label": "Fake Login Page Detected",
            "detail": "Password field + suspicious brand impersonation found",
            "severity": "CRITICAL"
        })

    if report["page_analysis"]["brand_impersonation"]:
        report["risk_signals"].append({
            "icon": "👤",
            "label": f"Impersonating: {report['page_analysis']['brand_impersonation']}",
            "detail": "Page content mimics a trusted brand but domain doesn't match",
            "severity": "CRITICAL"
        })

    if report["page_analysis"]["has_obfuscated_js"]:
        report["risk_signals"].append({
            "icon": "🔍",
            "label": "Obfuscated JavaScript",
            "detail": "Hidden/encoded scripts detected — common in phishing kits",
            "severity": "HIGH"
        })

    if report["page_analysis"]["form_steals_credentials"]:
        report["risk_signals"].append({
            "icon": "🕵️",
            "label": "Credential Harvesting Form",
            "detail": "Form submits to external domain — your data would be stolen",
            "severity": "CRITICAL"
        })

    return report


def get_whois_info(domain):
    result = {
        "domain": domain,
        "creation_date": None,
        "expiry_date": None,
        "registrar": None,
        "domain_age_days": None,
        "country": None,
        "privacy_protected": False,
        "error": None
    }

    if not WHOIS_AVAILABLE:
        result["error"] = "python-whois not installed"
        return result

    try:
        w = whois_lib.whois(domain)

        # Handle list returns from some TLDs
        def pick(val):
            if isinstance(val, list): return val[0]
            return val

        creation = pick(w.creation_date)
        expiry = pick(w.expiration_date)

        if creation:
            if isinstance(creation, str):
                for fmt in ["%Y-%m-%d", "%d-%b-%Y", "%Y-%m-%dT%H:%M:%SZ"]:
                    try:
                        creation = datetime.strptime(creation, fmt)
                        break
                    except ValueError:
                        pass

            if isinstance(creation, datetime):
                result["creation_date"] = creation.strftime("%B %d, %Y")
                result["domain_age_days"] = (datetime.utcnow() - creation).days

        if expiry and isinstance(expiry, datetime):
            result["expiry_date"] = expiry.strftime("%B %d, %Y")

        result["registrar"] = pick(w.registrar) or "Unknown"
        result["country"] = pick(w.country) if hasattr(w, 'country') else None

        # Privacy protection check
        name = str(pick(w.name) or "").lower()
        result["privacy_protected"] = any(kw in name for kw in
            ["privacy", "redacted", "whoisguard", "protect", "proxy"])

    except Exception as e:
        result["error"] = str(e)

    return result


def get_ssl_info(hostname):
    result = {
        "valid": False,
        "issuer": None,
        "expiry": None,
        "error": None
    }
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(
            socket.create_connection((hostname, 443), timeout=5),
            server_hostname=hostname
        ) as s:
            cert = s.getpeercert()
            result["valid"] = True
            # Issuer
            issuer_dict = dict(x[0] for x in cert.get('issuer', []))
            result["issuer"] = issuer_dict.get('organizationName', 'Unknown')
            # Expiry
            expiry_str = cert.get('notAfter', '')
            if expiry_str:
                expiry_dt = datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z")
                result["expiry"] = expiry_dt.strftime("%B %d, %Y")
                days_left = (expiry_dt - datetime.utcnow()).days
                result["days_until_expiry"] = days_left
                if days_left < 0:
                    result["valid"] = False
                    result["error"] = "Certificate expired"
    except ssl.SSLCertVerificationError as e:
        result["error"] = f"SSL verification failed: {str(e)[:60]}"
    except Exception as e:
        result["error"] = str(e)[:80]
    return result


# Major brands commonly impersonated in phishing
BRAND_PATTERNS = {
    "PayPal": ["paypal", "pay-pal", "paypai", "paypa1"],
    "Amazon": ["amazon", "amaz0n", "amazzon", "amzon"],
    "Apple": ["apple", "icloud", "appleid", "app1e"],
    "Google": ["google", "g00gle", "gogle", "googIe"],
    "Microsoft": ["microsoft", "m1crosoft", "microsft", "office365", "outlook365"],
    "Netflix": ["netflix", "netf1ix", "net-flix", "netfliix"],
    "Bank of America": ["bankofamerica", "bofa", "bank-of-america"],
    "Chase": ["chase", "jpmorgan", "chaseonline"],
    "Facebook": ["facebook", "faceb00k", "face-book", "meta-login"],
    "Instagram": ["instagram", "instagr4m", "insta-gram"],
    "DHL": ["dhl-delivery", "dhl-track", "dhl-parcel"],
}

def analyze_page(content, domain):
    if not content:
        return {
            "has_fake_login": False,
            "has_password_field": False,
            "brand_impersonation": None,
            "has_obfuscated_js": False,
            "form_steals_credentials": False,
            "suspicious_elements": []
        }

    cl = content.lower()
    domain_lower = domain.lower()

    has_password = bool(re.search(r'type=["\']password["\']', cl))
    has_username = bool(re.search(r'(name|id)=["\']?(user|email|login|username)', cl))
    has_submit = bool(re.search(r'type=["\']submit["\']|<button[^>]*>.*?(log\s*in|sign\s*in|submit)', cl))

    # Detect brand impersonation: brand mentioned in page but not in domain
    brand_impersonation = None
    for brand, patterns in BRAND_PATTERNS.items():
        brand_in_page = any(p in cl for p in patterns)
        brand_in_domain = any(p in domain_lower for p in [brand.lower().replace(" ", "")] + patterns[:1])
        if brand_in_page and not brand_in_domain:
            brand_impersonation = brand
            break

    # Check form action points externally
    form_actions = re.findall(r'<form[^>]*action=["\']([^"\']*)["\']', cl)
    form_steals = any(
        action.startswith('http') and domain_lower not in action
        for action in form_actions
    )

    # Obfuscated JS signals
    obfuscated = bool(re.search(r'eval\s*\(|unescape\s*\(|String\.fromCharCode|\\x[0-9a-f]{2}', cl))

    # Suspicious meta/title
    suspicious_title = bool(re.search(
        r'<title[^>]*>.*?(login|verify|secure|account|bank|payment).*?</title>', cl))

    has_fake_login = has_password and (brand_impersonation or form_steals or has_username)

    elements = []
    if has_password: elements.append("Password input field")
    if has_username: elements.append("Username/email input field")
    if form_steals: elements.append("Form submits to external server")
    if bool(re.search(r'<iframe', cl)): elements.append("Hidden iframes present")
    if obfuscated: elements.append("Obfuscated JavaScript")
    if suspicious_title: elements.append("Suspicious page title")

    return {
        "has_fake_login": has_fake_login,
        "has_password_field": has_password,
        "brand_impersonation": brand_impersonation,
        "has_obfuscated_js": obfuscated,
        "form_steals_credentials": form_steals,
        "suspicious_elements": elements
    }
