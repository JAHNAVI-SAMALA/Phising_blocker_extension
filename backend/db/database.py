"""
PhishGuard Database Layer
SQLite for development; swap to PostgreSQL for production.
"""
import sqlite3
import json
from datetime import datetime
import os

# Works both locally and on Render
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'phishguard.db')
def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_conn()
    c = conn.cursor()

    # Community-reported phishing sites
    c.execute('''CREATE TABLE IF NOT EXISTS reported_sites (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        url TEXT NOT NULL,
        domain TEXT NOT NULL,
        reported_by TEXT DEFAULT 'anonymous',
        report_count INTEGER DEFAULT 1,
        verified INTEGER DEFAULT 0,
        label INTEGER DEFAULT 1,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        features TEXT,
        whois_data TEXT
    )''')

    # Global threat alerts (pushed to all users)
    c.execute('''CREATE TABLE IF NOT EXISTS threat_alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        url TEXT NOT NULL,
        domain TEXT NOT NULL,
        threat_type TEXT DEFAULT 'phishing',
        severity TEXT DEFAULT 'HIGH',
        summary TEXT,
        report_count INTEGER DEFAULT 1,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        is_active INTEGER DEFAULT 1
    )''')

    # Model retraining log
    c.execute('''CREATE TABLE IF NOT EXISTS retrain_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        triggered_at TEXT DEFAULT CURRENT_TIMESTAMP,
        new_samples INTEGER,
        accuracy_before REAL,
        accuracy_after REAL,
        status TEXT DEFAULT 'pending'
    )''')

    # User sessions (for SSE push notifications)
    c.execute('''CREATE TABLE IF NOT EXISTS active_users (
        session_id TEXT PRIMARY KEY,
        last_seen TEXT DEFAULT CURRENT_TIMESTAMP
    )''')

    conn.commit()
    conn.close()
    print("[OK] Database initialized")

def report_site(url, domain, reported_by, features=None, whois_data=None):
    conn = get_conn()
    c = conn.cursor()

    # Check if already reported
    c.execute('SELECT id, report_count FROM reported_sites WHERE domain = ?', (domain,))
    existing = c.fetchone()

    if existing:
        new_count = existing['report_count'] + 1
        c.execute('UPDATE reported_sites SET report_count = ?, verified = ? WHERE id = ?',
                  (new_count, 1 if new_count >= 3 else 0, existing['id']))
        site_id = existing['id']
    else:
        c.execute('''INSERT INTO reported_sites
                     (url, domain, reported_by, features, whois_data)
                     VALUES (?, ?, ?, ?, ?)''',
                  (url, domain, reported_by,
                   json.dumps(features or {}),
                   json.dumps(whois_data or {})))
        site_id = c.lastrowid

    # Add to threat alerts if report_count >= 2
    c.execute('SELECT report_count FROM reported_sites WHERE id = ?', (site_id,))
    row = c.fetchone()
    if row and row['report_count'] >= 2:
        upsert_threat_alert(c, url, domain, row['report_count'])

    conn.commit()
    conn.close()
    return site_id

def upsert_threat_alert(cursor, url, domain, report_count):
    cursor.execute('SELECT id FROM threat_alerts WHERE domain = ?', (domain,))
    existing = cursor.fetchone()
    if existing:
        cursor.execute('UPDATE threat_alerts SET report_count = ? WHERE id = ?',
                       (report_count, existing['id']))
    else:
        cursor.execute('''INSERT INTO threat_alerts (url, domain, report_count, severity)
                          VALUES (?, ?, ?, ?)''',
                       (url, domain, report_count,
                        'CRITICAL' if report_count >= 5 else 'HIGH'))

def get_new_alerts(since_timestamp):
    conn = get_conn()
    c = conn.cursor()
    c.execute('''SELECT * FROM threat_alerts
                 WHERE created_at > ? AND is_active = 1
                 ORDER BY created_at DESC LIMIT 50''',
              (since_timestamp,))
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return rows

def get_all_reported_for_training():
    conn = get_conn()
    c = conn.cursor()
    c.execute('SELECT url, features, label FROM reported_sites WHERE features IS NOT NULL')
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return rows

def is_known_phishing(domain):
    conn = get_conn()
    c = conn.cursor()
    c.execute('''SELECT report_count FROM reported_sites
                 WHERE domain = ? AND (verified = 1 OR report_count >= 2)''',
              (domain,))
    row = c.fetchone()
    conn.close()
    return row is not None, row['report_count'] if row else 0

def log_retrain(new_samples, acc_before, acc_after, status='done'):
    conn = get_conn()
    c = conn.cursor()
    c.execute('''INSERT INTO retrain_log (new_samples, accuracy_before, accuracy_after, status)
                 VALUES (?, ?, ?, ?)''',
              (new_samples, acc_before, acc_after, status))
    conn.commit()
    conn.close()

def get_stats():
    """Returns aggregate statistics for the /stats endpoint and popup dashboard."""
    conn = get_conn()
    c = conn.cursor()

    c.execute('SELECT COUNT(*) as total FROM reported_sites')
    total_reported = c.fetchone()['total']

    c.execute('SELECT COUNT(*) as total FROM threat_alerts WHERE is_active = 1')
    active_threats = c.fetchone()['total']

    c.execute('''SELECT COUNT(*) as total FROM reported_sites
                 WHERE created_at >= datetime("now", "-24 hours")''')
    reports_24h = c.fetchone()['total']

    c.execute('''SELECT domain, report_count, severity, created_at
                 FROM threat_alerts WHERE is_active = 1
                 ORDER BY report_count DESC LIMIT 5''')
    top_threats = [dict(r) for r in c.fetchall()]

    c.execute('''SELECT new_samples, accuracy_before, accuracy_after, triggered_at
                 FROM retrain_log ORDER BY triggered_at DESC LIMIT 1''')
    last_retrain = c.fetchone()
    last_retrain = dict(last_retrain) if last_retrain else None

    conn.close()
    return {
        'total_reported': total_reported,
        'active_threats': active_threats,
        'reports_last_24h': reports_24h,
        'top_threats': top_threats,
        'last_retrain': last_retrain,
    }


# Note: init_db() is called explicitly by app.py on startup.
# Do NOT call it here to avoid double initialization on import.
