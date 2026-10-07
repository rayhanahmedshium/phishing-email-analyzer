"""
Phishing Email Analyzer
-----------------------
Reads a saved email (.eml file), checks it for common phishing signs, and
gives it a risk score with an explanation for each finding.

Checks:
  - Sender: display name pretends to be a brand the address doesn't match;
    Reply-To or Return-Path goes to a different domain
  - Authentication: SPF, DKIM, or DMARC failures in the headers
  - Links: link text shows one site but points to another; raw IP links;
    URL shorteners; punycode (look-alike) domains
  - Content: urgent or threatening language
  - Attachments: risky file types and double extensions (invoice.pdf.exe)

Usage:
    python analyzer.py samples/phish_account_suspended.eml
    python analyzer.py samples/*.eml
"""

import argparse
import email
import ipaddress
import re
from dataclasses import dataclass, field
from email import policy
from email.utils import parseaddr
from html.parser import HTMLParser
from urllib.parse import urlparse

URL_SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "rb.gy", "cutt.ly"}

RISKY_EXTENSIONS = {".exe", ".scr", ".js", ".vbs", ".bat", ".cmd", ".ps1", ".jar",
                    ".iso", ".img", ".hta", ".lnk", ".docm", ".xlsm", ".html", ".htm"}

# Words that often appear in sender names but aren't brand names, so the
# display-name check should ignore them.
GENERIC_SENDER_WORDS = {
    "support", "team", "service", "services", "security", "alert", "alerts",
    "notice", "account", "accounts", "billing", "payable", "payments", "bank",
    "customer", "help", "desk", "info", "admin", "mail", "notification",
    "notifications", "noreply", "reply", "department", "office", "online",
}

URGENT_PHRASES = [
    "verify your account", "account suspended", "account will be closed",
    "unusual activity", "unusual sign-in", "confirm your identity",
    "immediately", "within 24 hours", "urgent", "act now", "final notice",
    "update your payment", "password expires", "click here",
]


@dataclass
class Finding:
    category: str
    detail: str
    points: int


@dataclass
class Report:
    subject: str
    sender: str
    findings: list = field(default_factory=list)

    @property
    def score(self):
        return min(100, sum(f.points for f in self.findings))

    @property
    def verdict(self):
        if self.score >= 60:
            return "LIKELY PHISHING"
        if self.score >= 30:
            return "SUSPICIOUS"
        return "PROBABLY SAFE"


class LinkCollector(HTMLParser):
    """Collects (href, visible text) pairs from <a> tags in HTML email bodies."""

    def __init__(self):
        super().__init__()
        self.links = []
        self._href = None
        self._text = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self._href = dict(attrs).get("href", "")
            self._text = []

    def handle_data(self, data):
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            self.links.append((self._href, "".join(self._text).strip()))
            self._href = None


def domain_of(address):
    """'Name <user@mail.example.com>' -> 'mail.example.com'"""
    _, addr = parseaddr(address or "")
    return addr.rpartition("@")[2].lower()


def base_domain(host):
    """'login.secure.example.com' -> 'example.com' (simple version, ignores co.uk-style suffixes)."""
    parts = host.lower().strip(".").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host.lower()


def host_of(url):
    host = urlparse(url if "://" in url else "http://" + url).hostname
    return (host or "").lower()


def is_ip(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def get_bodies(msg):
    """Return (plain_text, html) from the message, joining all parts."""
    plain, html = [], []
    for part in msg.walk():
        if part.get_content_maintype() == "multipart" or part.get_filename():
            continue
        ctype = part.get_content_type()
        try:
            content = part.get_content()
        except (LookupError, ValueError):
            continue
        if ctype == "text/plain":
            plain.append(content)
        elif ctype == "text/html":
            html.append(content)
    return "\n".join(plain), "\n".join(html)


def check_sender(msg, report):
    from_header = msg.get("From", "")
    display, _ = parseaddr(from_header)
    from_dom = domain_of(from_header)

    # Display name contains a word that looks like a brand, but the domain doesn't.
    for word in re.findall(r"[A-Za-z]{4,}", display):
        if word.lower() in GENERIC_SENDER_WORDS:
            continue
        if word.lower() not in from_dom:
            report.findings.append(Finding(
                "Sender", f"Display name mentions '{word}' but the address is @{from_dom}", 20))
            break

    reply_dom = domain_of(msg.get("Reply-To", ""))
    if reply_dom and base_domain(reply_dom) != base_domain(from_dom):
        report.findings.append(Finding(
            "Sender", f"Replies go to @{reply_dom}, not the sender's domain @{from_dom}", 20))

    return_dom = domain_of(msg.get("Return-Path", ""))
    if return_dom and base_domain(return_dom) != base_domain(from_dom):
        report.findings.append(Finding(
            "Sender", f"Return-Path domain @{return_dom} differs from From domain", 10))


def check_authentication(msg, report):
    results = " ".join(msg.get_all("Authentication-Results", [])).lower()
    for mech in ("spf", "dkim", "dmarc"):
        m = re.search(rf"{mech}=(\w+)", results)
        if m and m.group(1) in {"fail", "softfail", "none", "permerror"}:
            report.findings.append(Finding(
                "Authentication", f"{mech.upper()} check result: {m.group(1)}", 15))


def check_links(html, plain, report):
    collector = LinkCollector()
    collector.feed(html)
    links = collector.links + [(u, "") for u in re.findall(r"https?://[^\s<>\"]+", plain)]

    seen = set()
    for href, text in links:
        host = host_of(href)
        if not host or (href, text) in seen:
            continue
        seen.add((href, text))

        shown = re.search(r"(?:https?://)?([\w-]+(?:\.[\w-]+)+)", text)
        if shown and "." in shown.group(1) and base_domain(shown.group(1)) != base_domain(host):
            report.findings.append(Finding(
                "Links", f"Link text shows '{shown.group(1)}' but actually goes to '{host}'", 25))
        if is_ip(host):
            report.findings.append(Finding("Links", f"Link points to a raw IP address: {host}", 20))
        if host in URL_SHORTENERS:
            report.findings.append(Finding("Links", f"Link uses a URL shortener that hides the destination: {host}", 10))
        if "xn--" in host:
            report.findings.append(Finding("Links", f"Punycode domain (possible look-alike characters): {host}", 20))


def check_language(subject, plain, html, report):
    text = " ".join([subject, plain, re.sub(r"<[^>]+>", " ", html)]).lower()
    hits = [p for p in URGENT_PHRASES if p in text]
    if hits:
        report.findings.append(Finding(
            "Content", f"Pressure language: {', '.join(hits[:4])}", min(20, 5 * len(hits))))


def check_attachments(msg, report):
    for part in msg.walk():
        name = part.get_filename()
        if not name:
            continue
        lower = name.lower()
        ext = "." + lower.rsplit(".", 1)[-1] if "." in lower else ""
        if lower.count(".") >= 2 and ext in RISKY_EXTENSIONS:
            report.findings.append(Finding("Attachments", f"Double extension hides the real file type: {name}", 30))
        elif ext in RISKY_EXTENSIONS:
            report.findings.append(Finding("Attachments", f"Risky attachment type: {name}", 25))


def analyze_message(msg):
    report = Report(subject=str(msg.get("Subject", "")), sender=str(msg.get("From", "")))
    plain, html = get_bodies(msg)
    check_sender(msg, report)
    check_authentication(msg, report)
    check_links(html, plain, report)
    check_language(report.subject, plain, html, report)
    check_attachments(msg, report)
    return report


def analyze_file(path):
    with open(path, "rb") as f:
        msg = email.message_from_binary_file(f, policy=policy.default)
    return analyze_message(msg)


def print_report(path, report):
    print("=" * 60)
    print(f"File    : {path}")
    print(f"From    : {report.sender}")
    print(f"Subject : {report.subject}")
    print(f"Verdict : {report.verdict}  (risk score {report.score}/100)")
    print("-" * 60)
    if not report.findings:
        print("No phishing indicators found.")
    for f in report.findings:
        print(f"[{f.category:<14}] +{f.points:<3} {f.detail}")
    print()


def main():
    parser = argparse.ArgumentParser(description="Analyze .eml files for phishing indicators.")
    parser.add_argument("files", nargs="+", help="one or more .eml files")
    args = parser.parse_args()
    for path in args.files:
        print_report(path, analyze_file(path))


if __name__ == "__main__":
    main()
