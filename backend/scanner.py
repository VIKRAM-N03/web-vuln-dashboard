import requests
import ssl
import socket
import datetime
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup

TIMEOUT = 10

SECURITY_HEADERS = {
    "Content-Security-Policy": {
        "severity": "High",
        "description": "Content-Security-Policy (CSP) header is missing. This allows attackers to inject malicious scripts into your pages (XSS attacks).",
        "fix": "Add 'Content-Security-Policy: default-src self;' to your server's HTTP response headers."
    },
    "X-Frame-Options": {
        "severity": "Medium",
        "description": "X-Frame-Options header is missing. Your site can be embedded in iframes, enabling Clickjacking attacks.",
        "fix": "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN' to your HTTP response headers."
    },
    "Strict-Transport-Security": {
        "severity": "High",
        "description": "HSTS (HTTP Strict Transport Security) header is missing. Browsers may connect over insecure HTTP.",
        "fix": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' to your HTTPS response headers."
    },
    "X-Content-Type-Options": {
        "severity": "Low",
        "description": "X-Content-Type-Options header is missing. Browsers may MIME-sniff responses, leading to security issues.",
        "fix": "Add 'X-Content-Type-Options: nosniff' to your HTTP response headers."
    },
    "Referrer-Policy": {
        "severity": "Low",
        "description": "Referrer-Policy header is missing. Sensitive URL information may leak to third-party sites.",
        "fix": "Add 'Referrer-Policy: strict-origin-when-cross-origin' to your HTTP response headers."
    },
    "Permissions-Policy": {
        "severity": "Low",
        "description": "Permissions-Policy header is missing. Browser features like camera/microphone are not restricted.",
        "fix": "Add 'Permissions-Policy: geolocation=(), microphone=(), camera=()' to restrict browser feature access."
    }
}

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    '"><script>alert(1)</script>',
    "javascript:alert(1)",
    "<img src=x onerror=alert(1)>",
]

SQLI_PAYLOADS = [
    "'",
    "' OR '1'='1",
    "1; DROP TABLE users--",
    "' OR 1=1--",
]

SQLI_ERRORS = [
    "sql syntax", "mysql_fetch", "ora-01756", "unclosed quotation",
    "sqlite_error", "pg_query", "syntax error", "sql error",
    "database error", "odbc error", "microsoft ole db",
]

SENSITIVE_PATHS = [
    "/admin", "/admin/", "/backup", "/config",
    "/.env", "/wp-admin", "/phpmyadmin", "/.git",
    "/api/users", "/uploads", "/logs", "/debug"
]


def check_security_headers(url):
    findings = []
    try:
        response = requests.get(url, timeout=TIMEOUT, verify=False)
        headers = {k.lower(): v for k, v in response.headers.items()}

        for header, info in SECURITY_HEADERS.items():
            if header.lower() not in headers:
                findings.append({
                    "vuln_type": f"Missing Header: {header}",
                    "severity": info["severity"],
                    "description": info["description"],
                    "fix": info["fix"]
                })
    except Exception:
        pass
    return findings


def check_ssl(url):
    findings = []
    parsed = urlparse(url)
    hostname = parsed.hostname

    if parsed.scheme != "https":
        findings.append({
            "vuln_type": "No HTTPS",
            "severity": "Critical",
            "description": f"The site is served over HTTP, not HTTPS. All data transferred (including passwords and form data) is sent in plain text and can be intercepted.",
            "fix": "Configure your web server with a valid SSL/TLS certificate and redirect all HTTP traffic to HTTPS."
        })
        return findings

    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
            s.settimeout(TIMEOUT)
            s.connect((hostname, 443))
            cert = s.getpeercert()

        expire_str = cert.get("notAfter", "")
        if expire_str:
            expire_date = datetime.datetime.strptime(expire_str, "%b %d %H:%M:%S %Y %Z")
            days_left = (expire_date - datetime.datetime.utcnow()).days
            if days_left < 0:
                findings.append({
                    "vuln_type": "SSL Certificate Expired",
                    "severity": "Critical",
                    "description": f"The SSL certificate expired {abs(days_left)} day(s) ago. Browsers will show a security warning to all visitors.",
                    "fix": "Renew your SSL certificate immediately. Services like Let's Encrypt offer free, auto-renewing certificates."
                })
            elif days_left < 30:
                findings.append({
                    "vuln_type": "SSL Certificate Expiring Soon",
                    "severity": "Medium",
                    "description": f"The SSL certificate expires in {days_left} day(s). If not renewed, visitors will see security warnings.",
                    "fix": "Renew your SSL certificate before it expires. Consider setting up auto-renewal."
                })
    except ssl.SSLError as e:
        findings.append({
            "vuln_type": "SSL Error",
            "severity": "Critical",
            "description": f"SSL/TLS error detected: {str(e)[:120]}. The connection is not secure.",
            "fix": "Check your server's SSL configuration. Ensure you're using TLS 1.2 or 1.3 and a valid certificate."
        })
    except Exception:
        pass

    return findings


def check_xss(url):
    findings = []
    try:
        response = requests.get(url, timeout=TIMEOUT, verify=False)
        soup = BeautifulSoup(response.text, "html.parser")
        forms = soup.find_all("form")

        for form in forms[:3]:
            action = form.get("action", url)
            method = form.get("method", "get").lower()
            full_action = urljoin(url, action)
            inputs = form.find_all("input")

            for payload in XSS_PAYLOADS[:2]:
                data = {}
                for inp in inputs:
                    name = inp.get("name")
                    if name:
                        data[name] = payload

                try:
                    if method == "post":
                        r = requests.post(full_action, data=data, timeout=TIMEOUT, verify=False)
                    else:
                        r = requests.get(full_action, params=data, timeout=TIMEOUT, verify=False)

                    if payload in r.text:
                        findings.append({
                            "vuln_type": "Reflected XSS",
                            "severity": "High",
                            "description": f"A form at '{full_action}' reflects user input without sanitization. An attacker could inject malicious JavaScript that executes in victims' browsers.",
                            "fix": "Sanitize and escape all user input before displaying it. Use a library like DOMPurify on the frontend and html.escape() in Python on the backend. Enable Content-Security-Policy headers."
                        })
                        return findings
                except Exception:
                    continue
    except Exception:
        pass
    return findings


def check_sqli(url):
    findings = []
    try:
        response = requests.get(url, timeout=TIMEOUT, verify=False)
        soup = BeautifulSoup(response.text, "html.parser")
        forms = soup.find_all("form")

        for form in forms[:3]:
            action = form.get("action", url)
            method = form.get("method", "get").lower()
            full_action = urljoin(url, action)
            inputs = form.find_all("input")

            for payload in SQLI_PAYLOADS[:2]:
                data = {}
                for inp in inputs:
                    name = inp.get("name")
                    if name:
                        data[name] = payload

                try:
                    if method == "post":
                        r = requests.post(full_action, data=data, timeout=TIMEOUT, verify=False)
                    else:
                        r = requests.get(full_action, params=data, timeout=TIMEOUT, verify=False)

                    response_lower = r.text.lower()
                    for err in SQLI_ERRORS:
                        if err in response_lower:
                            findings.append({
                                "vuln_type": "SQL Injection",
                                "severity": "Critical",
                                "description": f"A form at '{full_action}' appears vulnerable to SQL injection. Database error messages were returned in response to malformed input, exposing backend structure.",
                                "fix": "Use parameterized queries or prepared statements instead of string concatenation. Never expose raw database errors to users. Use an ORM like SQLAlchemy."
                            })
                            return findings
                except Exception:
                    continue
    except Exception:
        pass
    return findings


def check_sensitive_paths(url):
    findings = []
    exposed = []

    for path in SENSITIVE_PATHS:
        try:
            target = url.rstrip("/") + path
            r = requests.get(target, timeout=5, verify=False, allow_redirects=False)
            if r.status_code == 200:
                exposed.append(path)
        except Exception:
            continue

    if exposed:
        findings.append({
            "vuln_type": "Sensitive Paths Exposed",
            "severity": "High",
            "description": f"The following sensitive paths are publicly accessible: {', '.join(exposed)}. These may expose admin panels, configuration files, or source code.",
            "fix": "Restrict access to sensitive paths using server configuration (e.g., .htaccess or nginx rules). Require authentication for admin areas. Remove unused endpoints."
        })
    return findings


def check_cookies(url):
    findings = []
    try:
        response = requests.get(url, timeout=TIMEOUT, verify=False)
        for cookie in response.cookies:
            issues = []
            if not cookie.secure:
                issues.append("missing Secure flag")
            if not cookie.has_nonstandard_attr("HttpOnly"):
                issues.append("missing HttpOnly flag")
            if not cookie.has_nonstandard_attr("SameSite"):
                issues.append("missing SameSite attribute")

            if issues:
                findings.append({
                    "vuln_type": f"Insecure Cookie: {cookie.name}",
                    "severity": "Medium",
                    "description": f"Cookie '{cookie.name}' has security issues: {', '.join(issues)}. This can expose session tokens to theft via XSS or network interception.",
                    "fix": "Set cookies with Secure, HttpOnly, and SameSite=Strict flags. Example: Set-Cookie: session=abc; Secure; HttpOnly; SameSite=Strict"
                })
    except Exception:
        pass
    return findings


def run_scan(url):
    import warnings
    warnings.filterwarnings("ignore")

    all_findings = []
    all_findings += check_ssl(url)
    all_findings += check_security_headers(url)
    all_findings += check_xss(url)
    all_findings += check_sqli(url)
    all_findings += check_sensitive_paths(url)
    all_findings += check_cookies(url)

    return all_findings
