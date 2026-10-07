import email
import sys
from email import policy
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from analyzer import analyze_file, analyze_message, base_domain, host_of


def make(raw):
    return email.message_from_string(raw.strip() + "\n", policy=policy.default)


def categories(report):
    return [f.category for f in report.findings]


def test_sample_phish_is_flagged():
    assert analyze_file(ROOT / "samples/phish_account_suspended.eml").verdict == "LIKELY PHISHING"


def test_sample_attachment_phish_is_flagged():
    report = analyze_file(ROOT / "samples/phish_invoice_attachment.eml")
    assert "Attachments" in categories(report)
    assert report.verdict == "LIKELY PHISHING"


def test_sample_legit_email_is_clean():
    report = analyze_file(ROOT / "samples/legit_statement_ready.eml")
    assert report.findings == []


def test_brand_in_display_name_but_not_domain():
    msg = make("""
From: "Contoso Payments" <help@random-site.example.org>
Subject: hi
Content-Type: text/plain

hello
""")
    details = " ".join(f.detail for f in analyze_message(msg).findings)
    assert "Contoso" in details


def test_mismatched_link_text():
    msg = make("""
From: a@example.com
Subject: hi
Content-Type: text/html

<a href="http://evil.example.net/x">www.example.com</a>
""")
    assert any("actually goes to" in f.detail for f in analyze_message(msg).findings)


def test_matching_link_text_not_flagged():
    msg = make("""
From: a@example.com
Subject: hi
Content-Type: text/html

<a href="https://shop.example.com/cart">www.example.com</a>
""")
    assert analyze_message(msg).findings == []


def test_punycode_domain_flagged():
    msg = make("""
From: a@example.com
Subject: hi
Content-Type: text/plain

Visit https://xn--exmple-cua.com/login
""")
    assert any("Punycode" in f.detail for f in analyze_message(msg).findings)


def test_reply_to_mismatch():
    msg = make("""
From: a@example.com
Reply-To: b@other.example.net
Subject: hi
Content-Type: text/plain

hello
""")
    assert "Sender" in categories(analyze_message(msg))


def test_helpers():
    assert base_domain("login.secure.example.com") == "example.com"
    assert host_of("https://Example.COM/path") == "example.com"
