"""
PhishLock Security Suite — Flask Backend
Rule-based heuristic analysis of submitted URL text and message text.
No network requests are made to submitted URLs.
"""

import re
import math
import sqlite3
import json

from pathlib import Path
from datetime import datetime, timezone
from urllib.parse import urlparse
from flask import Flask, request, jsonify

app = Flask(__name__, static_folder='.', static_url_path='')



# ---------------------------------------------------------------------------
# SQLite Database Setup
# ---------------------------------------------------------------------------

DATABASE_PATH = Path(__file__).resolve().parent / 'phishlock.db'


def get_db_connection():
    """Create a connection to the SQLite database."""
    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def init_database():
    """Create the scan history table if it does not exist."""
    connection = get_db_connection()

    try:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                scan_type TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                risk_level TEXT NOT NULL,
                indicators TEXT NOT NULL,
                recommendations TEXT NOT NULL,
                timestamp TEXT NOT NULL
            )
        """)

        connection.commit()
        print(f"Database ready: {DATABASE_PATH}")

    finally:
        connection.close()


def save_scan(target, scan_type, risk_score, risk_level,
              indicators, recommendations, timestamp):
    """Save an analysis result to the database."""
    connection = get_db_connection()

    try:
        cursor = connection.execute("""
            INSERT INTO scan_history (
                target,
                scan_type,
                risk_score,
                risk_level,
                indicators,
                recommendations,
                timestamp
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            target,
            scan_type,
            risk_score,
            risk_level,
            json.dumps(indicators),
            json.dumps(recommendations),
            timestamp
        ))

        connection.commit()
        return cursor.lastrowid

    finally:
        connection.close()

DISCLAIMER = (
    "This assessment is produced by transparent rule-based heuristics applied "
    "to the text of the submitted input. No network requests were made to any "
    "submitted URL. HTTPS alone does not guarantee safety. Results are "
    "indicative and must be verified by a qualified security professional."
)


# ---------------------------------------------------------------------------
# CORS — manual implementation (no flask-cors dependency)
# ---------------------------------------------------------------------------

import os

@app.after_request
def add_cors_headers(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
    return response


@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def serve_frontend(path):
    """Serve static frontend assets or index.html for root/SPA routes."""
    if path and os.path.exists(os.path.join(app.root_path, path)):
        return app.send_static_file(path)
    return app.send_static_file('index.html')


# ---------------------------------------------------------------------------
# Health endpoint
# ---------------------------------------------------------------------------

@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({
        'status': 'ok',
        'service': 'PhishLock Security Suite',
        'version': '1.0.0',
        'mode': 'rule-based heuristic analysis'
    })


# ---------------------------------------------------------------------------
# URL analysis endpoint
# ---------------------------------------------------------------------------

# High-abuse TLDs — statistically over-represented in phishing registrations
HIGH_ABUSE_TLDS = {'.xyz', '.top', '.tk', '.ml', '.cf', '.gq', '.click',
                   '.loan', '.icu', '.buzz', '.work', '.live', '.zip', '.mov'}

# Sensitive path tokens that commonly appear in credential-harvesting pages
PATH_TOKENS = ['verify', 'login', 'account', 'secure', 'update', 'confirm',
               'password', 'signin', 'banking', 'credential', 'auth', 'reset']

# Brands that are frequently impersonated; mapping to their canonical domains
BRAND_CANONICAL = {
    'paypal':    'paypal.com',
    'chase':     'chase.com',
    'apple':     'apple.com',
    'icloud':    'icloud.com',
    'google':    'google.com',
    'microsoft': 'microsoft.com',
    'amazon':    'amazon.com',
    'netflix':   'netflix.com',
    'wellsfargo':'wellsfargo.com',
    'bankofamerica': 'bankofamerica.com',
}

# Homoglyph / typosquatting signatures for well-known brands
HOMOGLYPH_PATTERNS = [
    (r'paypa[1l!][^a-z]', 'PayPal homoglyph/typosquat'),
    (r'micros[0o]ft',      'Microsoft homoglyph'),
    (r'g[0o]{2}gle',       'Google homoglyph'),
    (r'app[1l!]e[^t]',     'Apple homoglyph'),
    (r'amaz[0o]n',         'Amazon homoglyph'),
    (r'netfl[1i!]x',       'Netflix homoglyph'),
]

_IP_RE = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
_PORT_RE = re.compile(r':(\d+)$')


def _clamp(value, lo=0, hi=100):
    return max(lo, min(hi, value))


def analyze_url_text(raw_url):
    """
    Evaluate a URL string against structural and lexical heuristics.
    Returns (risk_score, indicators, recommendations).
    Each indicator: {title, description, signal, weight}
    """
    indicators = []
    score = 0

    url = raw_url.strip()
    url_lower = url.lower()

    # --- Parse with stdlib (no network calls) ---
    try:
        parsed = urlparse(url if '://' in url else 'http://' + url)
    except Exception:
        parsed = None

    scheme   = parsed.scheme.lower() if parsed else ''
    netloc   = parsed.netloc.lower() if parsed else url_lower
    path     = parsed.path.lower()   if parsed else ''
    hostname = parsed.hostname or netloc.split('/')[0] if parsed else ''
    port     = parsed.port if parsed else None

    # Strip port from hostname for TLD checks
    host_no_port = hostname.split(':')[0] if hostname else ''

    # 1. Insecure protocol (HTTP)
    if scheme == 'http':
        w = 15
        score += w
        indicators.append({
            'title':       'Insecure Protocol (HTTP)',
            'description': (
                'Traffic is transmitted in plaintext without TLS encryption. '
                'Legitimate financial and authentication portals use HTTPS, '
                'though HTTPS alone does not guarantee a site is trustworthy.'
            ),
            'signal': 'insecure_protocol',
            'weight': w
        })

    # 2. IP address as host
    if host_no_port and _IP_RE.match(host_no_port):
        w = 25
        score += w
        indicators.append({
            'title':       'IP Address Used as Hostname',
            'description': (
                f'Host "{host_no_port}" is a numeric IP address. Phishing pages '
                'commonly use raw IPs to avoid registering a recognisable domain.'
            ),
            'signal': 'ip_host',
            'weight': w
        })

    # 3. High-abuse TLD
    matched_tld = next((t for t in HIGH_ABUSE_TLDS if host_no_port.endswith(t)), None)
    if matched_tld:
        w = 20
        score += w
        indicators.append({
            'title':       f'High-Abuse Top-Level Domain ({matched_tld})',
            'description': (
                f'The domain uses "{matched_tld}", a TLD disproportionately '
                'registered for disposable phishing infrastructure. This is a '
                'signal, not definitive proof of malice.'
            ),
            'signal': 'high_abuse_tld',
            'weight': w
        })

    # 4. Brand impersonation — brand keyword in domain that is NOT the canonical domain
    brand_flags = []
    for brand, canonical in BRAND_CANONICAL.items():
        if brand in host_no_port and not host_no_port.endswith(canonical):
            brand_flags.append(brand)
    if brand_flags:
        w = 25
        score += w
        indicators.append({
            'title':       f'Brand Impersonation in Domain ({", ".join(brand_flags)})',
            'description': (
                f'The domain contains the brand name(s) "{", ".join(brand_flags)}" '
                'but does not match the canonical registered domain. This is a '
                'common technique to create false legitimacy.'
            ),
            'signal': 'brand_impersonation',
            'weight': w
        })

    # 5. Homoglyph / typosquatting
    homoglyph_hits = []
    for pattern, label in HOMOGLYPH_PATTERNS:
        if re.search(pattern, url_lower):
            homoglyph_hits.append(label)
    if homoglyph_hits:
        w = 20
        score += w
        indicators.append({
            'title':       'Homoglyph / Typosquatting Substitution',
            'description': (
                f'Character substitution patterns detected: {"; ".join(homoglyph_hits)}. '
                'Adversaries substitute visually similar characters (e.g. "0" for "o", '
                '"1" for "l") to spoof trusted brands.'
            ),
            'signal': 'homoglyph',
            'weight': w
        })

    # 6. Suspicious path tokens (cap contribution at 20)
    matched_tokens = [t for t in PATH_TOKENS if t in path]
    if matched_tokens:
        w = min(len(matched_tokens) * 5, 20)
        score += w
        indicators.append({
            'title':       f'Sensitive Path Tokens ({", ".join(matched_tokens[:4])})',
            'description': (
                'The URL path contains terms associated with credential-harvesting '
                'pages. Multiple chained tokens increase suspicion.'
            ),
            'signal': 'suspicious_path',
            'weight': w
        })

    # 7. Excess subdomains (>= 4 dot-delimited segments in hostname)
    if host_no_port:
        segments = host_no_port.split('.')
        if len(segments) >= 4:
            w = 15
            score += w
            indicators.append({
                'title':       f'Deep Subdomain Stacking ({len(segments)} segments)',
                'description': (
                    'Adversaries prefix a legitimate brand name as a subdomain of '
                    'a disposable domain (e.g. paypal.support.example.xyz) to '
                    'create visual ambiguity in address bars.'
                ),
                'signal': 'deep_subdomain',
                'weight': w
            })

    # 8. Unusually long URL
    if len(url) > 100:
        w = 10
        score += w
        indicators.append({
            'title':       f'Excessive URL Length ({len(url)} characters)',
            'description': (
                'Unusually long URLs can obscure the true destination and are '
                'sometimes used to bury suspicious tokens beyond the visible area.'
            ),
            'signal': 'long_url',
            'weight': w
        })

    # 9. Non-standard port
    if port and port not in (80, 443):
        w = 10
        score += w
        indicators.append({
            'title':       f'Non-Standard Port ({port})',
            'description': (
                f'URL specifies port {port}. Legitimate public-facing services '
                'typically use standard ports (80/443).'
            ),
            'signal': 'nonstandard_port',
            'weight': w
        })

    score = _clamp(score)
    risk_level = _classify(score)
    recommendations = _url_recommendations(risk_level, indicators)

    return score, risk_level, indicators, recommendations


def _classify(score):
    if score >= 65:
        return 'CRITICAL'
    if score >= 35:
        return 'SUSPICIOUS'
    return 'LOW_RISK'


def _url_recommendations(risk_level, indicators):
    recs = []
    signals = {i['signal'] for i in indicators}

    if risk_level == 'CRITICAL':
        recs.append('Do not submit credentials, OTP codes, or payment details to this URL.')
        recs.append('If you have already interacted, rotate affected credentials immediately from a known-safe device.')
        recs.append('Report the URL to your security team or the appropriate abuse channel.')
    elif risk_level == 'SUSPICIOUS':
        recs.append('Exercise caution. Verify the domain matches the official registered address of the service.')
        recs.append('Navigate to the service directly via a saved bookmark rather than following this link.')
    else:
        recs.append('No high-risk structural indicators were detected in this URL text.')
        recs.append('Continue exercising standard security hygiene regardless of this result.')

    if 'brand_impersonation' in signals or 'homoglyph' in signals:
        recs.append('Carefully inspect the full domain character-by-character against the official domain.')
    if 'insecure_protocol' in signals:
        recs.append('Note: HTTPS is expected for any site requesting authentication. HTTP is insufficient.')

    return recs


# ---------------------------------------------------------------------------
# Message analysis endpoint
# ---------------------------------------------------------------------------

URGENCY_TOKENS = [
    'urgent', 'immediately', 'within 24 hours', 'within 48 hours',
    'act now', 'suspended', 'locked', 'terminate', 'arrest',
    'expires today', 'final notice', 'warning'
]

THREAT_TOKENS = [
    'legal action', 'law enforcement', 'criminal charges', 'warrant',
    'prosecution', 'court order'
]

CREDENTIAL_PHRASES = [
    'verify your identity', 'confirm your account', 'enter your password',
    'provide your ssn', 'enter your pin', 'confirm your details',
    'update your account', 'reactivate your account'
]

FINANCIAL_REDIRECT = [
    'wire transfer', 'gift card', 'bitcoin', 'crypto payment', 'send money to',
    'buy gift cards', 'pay in bitcoin', 'western union', 'money gram'
]

PRIZE_LURE = [
    'congratulations', 'you have won', 'lottery', 'claim your prize',
    'selected winner', 'prize notification', 'you are selected'
]

PERSONAL_INFO = [
    'social security', 'ssn', 'date of birth', 'credit card number',
    'cvv', 'bank account number', 'routing number', 'passport number'
]

SENDER_MISMATCH = [
    'do not reply to this email', 'do not respond to this email',
    'noreply@', 'no-reply@', 'donotreply@'
]


def _count_uppercase_word_ratio(text):
    words = text.split()
    if not words:
        return 0.0
    upper_words = [w for w in words if w.isupper() and len(w) > 1]
    return len(upper_words) / len(words)


def analyze_message_text(text):
    """
    Evaluate a message string against social-engineering heuristics.
    Returns (risk_score, indicators, recommendations).
    """
    indicators = []
    score = 0
    normalized = text.lower()

    # 1. Urgency tokens (cap at +30)
    matched_urgency = [t for t in URGENCY_TOKENS if t in normalized]
    if matched_urgency:
        w = min(len(matched_urgency) * 8, 30)
        score += w
        indicators.append({
            'title':       f'High-Pressure Urgency Markers ({len(matched_urgency)} matched)',
            'description': (
                f'Tokens detected: {", ".join(matched_urgency[:4])}. '
                'Social engineering campaigns manufacture artificial time pressure '
                'to bypass rational verification. Legitimate organisations rarely '
                'threaten immediate account termination via unsolicited messages.'
            ),
            'signal': 'urgency',
            'weight': w
        })

    # 2. Threat language
    matched_threat = [t for t in THREAT_TOKENS if t in normalized]
    if matched_threat:
        w = 15
        score += w
        indicators.append({
            'title':       'Explicit Threat Language',
            'description': (
                f'Message contains coercive threat language: '
                f'"{", ".join(matched_threat[:3])}". '
                'Government agencies and financial institutions do not initiate '
                'enforcement contact via SMS or email.'
            ),
            'signal': 'threat_language',
            'weight': w
        })

    # 3. Credential harvesting phrases
    matched_cred = [p for p in CREDENTIAL_PHRASES if p in normalized]
    if matched_cred:
        w = 20
        score += w
        indicators.append({
            'title':       'Credential Harvesting Phrasing',
            'description': (
                f'Message prompts the recipient to: {"; ".join(matched_cred[:3])}. '
                'This is a core social-engineering technique used to capture '
                'authentication factors.'
            ),
            'signal': 'credential_request',
            'weight': w
        })

    # 4. Embedded URLs — suspicious TLD adds extra weight
    has_url = 'http://' in normalized or 'https://' in normalized
    if has_url:
        w = 10
        score += w
        indicators.append({
            'title':       'Embedded Action URL',
            'description': (
                'Message directs the recipient to resolve an external link rather '
                'than navigating via an official application or saved bookmark.'
            ),
            'signal': 'embedded_url',
            'weight': w
        })
        # Extra weight for high-abuse TLD in embedded URL
        suspicious_in_url = any(tld in normalized for tld in HIGH_ABUSE_TLDS)
        if suspicious_in_url:
            w2 = 15
            score += w2
            indicators.append({
                'title':       'High-Abuse TLD in Embedded URL',
                'description': (
                    'The embedded link uses a top-level domain commonly associated '
                    'with disposable phishing infrastructure.'
                ),
                'signal': 'embedded_url_tld',
                'weight': w2
            })

    # 5. Financial redirection (explicitly requesting money/crypto — NOT merely mentioning banks)
    matched_fin = [t for t in FINANCIAL_REDIRECT if t in normalized]
    if matched_fin:
        w = 20
        score += w
        indicators.append({
            'title':       f'Financial Redirection Request ({", ".join(matched_fin[:3])})',
            'description': (
                'Message explicitly requests a financial transaction via an '
                'unverifiable channel (wire transfer, gift card, or cryptocurrency). '
                'This is the defining characteristic of business email compromise '
                'and advance-fee fraud. Merely mentioning a bank or account number '
                'does not trigger this indicator.'
            ),
            'signal': 'financial_redirect',
            'weight': w
        })

    # 6. Prize / lottery bait
    matched_prize = [t for t in PRIZE_LURE if t in normalized]
    if matched_prize:
        w = 20
        score += w
        indicators.append({
            'title':       'Advance-Fee / Prize Solicitation',
            'description': (
                'Message claims the recipient has won a prize or lottery without '
                'any prior entry. Subsequent steps typically request a processing '
                'fee or personal identification.'
            ),
            'signal': 'prize_lure',
            'weight': w
        })

    # 7. Request for sensitive personal information
    matched_personal = [t for t in PERSONAL_INFO if t in normalized]
    if matched_personal:
        w = 20
        score += w
        indicators.append({
            'title':       f'Sensitive Personal Information Requested ({", ".join(matched_personal[:3])})',
            'description': (
                'Message solicits government identifiers or financial account '
                'numbers. Legitimate organisations do not request this information '
                'via unsolicited messages.'
            ),
            'signal': 'personal_info_request',
            'weight': w
        })

    # 8. Excessive capitalisation (>20% of words fully uppercase)
    upper_ratio = _count_uppercase_word_ratio(text)
    if upper_ratio > 0.20:
        w = 10
        score += w
        indicators.append({
            'title':       f'Excessive Capitalisation ({round(upper_ratio * 100)}% uppercase words)',
            'description': (
                'A high proportion of fully-capitalised words is a stylistic marker '
                'common in mass-distributed phishing templates.'
            ),
            'signal': 'excessive_caps',
            'weight': w
        })

    # 9. Sender mismatch cues
    matched_sender = [t for t in SENDER_MISMATCH if t in normalized]
    if matched_sender:
        w = 5
        score += w
        indicators.append({
            'title':       'Sender Mismatch / No-Reply Cue',
            'description': (
                'Message contains a no-reply address or instruction not to respond, '
                'which may indicate mass-mailing infrastructure or an attempt to '
                'prevent recipient verification via reply.'
            ),
            'signal': 'sender_mismatch',
            'weight': w
        })

    score = _clamp(score)
    risk_level = _classify(score)
    recommendations = _message_recommendations(risk_level, indicators)

    return score, risk_level, indicators, recommendations


def _message_recommendations(risk_level, indicators):
    recs = []
    signals = {i['signal'] for i in indicators}

    if risk_level == 'CRITICAL':
        recs.append('Do not reply, click embedded links, or call numbers provided in this message.')
        recs.append('Verify the sender independently using contact details from official sources, not this message.')
        recs.append('Forward SMS phishing to your carrier\'s spam reporting number (7726 in the US/UK).')
    elif risk_level == 'SUSPICIOUS':
        recs.append('Exercise heightened caution. Confirm the request through a verified, out-of-band channel.')
        recs.append('Review the full message headers (if email) to verify SPF, DKIM, and DMARC alignment.')
    else:
        recs.append('No high-risk social-engineering indicators were detected in this message text.')
        recs.append('Maintain standard vigilance for unexpected communications requesting action.')

    if 'financial_redirect' in signals:
        recs.append('Wire transfers, gift card purchases, and cryptocurrency payments are irreversible — verify any request before acting.')
    if 'credential_request' in signals:
        recs.append('Never provide passwords or one-time codes in response to an unsolicited message.')
    if 'prize_lure' in signals:
        recs.append('You cannot win a lottery you did not enter. Requests for a "processing fee" are advance-fee fraud.')

    return recs


# ---------------------------------------------------------------------------
# Flask route handlers
# ---------------------------------------------------------------------------

@app.route('/api/analyze-url', methods=['POST', 'OPTIONS'])
def api_analyze_url():
    if request.method == 'OPTIONS':
        return '', 204

    data = request.get_json(silent=True) or {}
    url = data.get('url', '').strip()

    if not url:
        return jsonify({'error': 'A URL is required.', 'code': 'MISSING_INPUT'}), 400

    if len(url) > 2000:
        return jsonify({'error': 'Input exceeds the maximum permitted length (2000 characters).', 'code': 'INPUT_TOO_LONG'}), 400

    score, risk_level, indicators, recommendations = analyze_url_text(url)

    return jsonify({
        'risk_score':       score,
        'risk_level':       risk_level,
        'target':           url,
        'vector_type':      'URI',
        'indicators':       indicators,
        'recommendations':  recommendations,
        'disclaimer':       DISCLAIMER,
        'timestamp':        datetime.now(timezone.utc).isoformat()
    })


@app.route('/api/analyze-message', methods=['POST', 'OPTIONS'])
def api_analyze_message():
    if request.method == 'OPTIONS':
        return '', 204

    data = request.get_json(silent=True) or {}
    message = data.get('message', '').strip()

    if not message:
        return jsonify({'error': 'Message content is required.', 'code': 'MISSING_INPUT'}), 400

    if len(message) < 10:
        return jsonify({'error': 'Message is too short for meaningful analysis (minimum 10 characters).', 'code': 'INPUT_TOO_SHORT'}), 400

    if len(message) > 10000:
        return jsonify({'error': 'Input exceeds the maximum permitted length (10,000 characters).', 'code': 'INPUT_TOO_LONG'}), 400

    score, risk_level, indicators, recommendations = analyze_message_text(message)

    return jsonify({
        'risk_score':       score,
        'risk_level':       risk_level,
        'target':           message[:120] + ('...' if len(message) > 120 else ''),
        'vector_type':      'Message',
        'indicators':       indicators,
        'recommendations':  recommendations,
        'disclaimer':       DISCLAIMER,
        'timestamp':        datetime.now(timezone.utc).isoformat()
    })


# ---------------------------------------------------------------------------

# Initialize SQLite database on startup
try:
    init_database()
except Exception as e:
    print(f"Database initialization warning: {e}")

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug_mode = os.environ.get('FLASK_ENV') == 'development'
    print(f'PhishLock Security Suite — starting on port {port}')
    app.run(debug=debug_mode, host='0.0.0.0', port=port)