# Phishing Email Analyzer

A Python tool that inspects saved email files (`.eml`) for signs of phishing and explains each warning it finds, with an overall risk score.

## Why I built this

Phishing is still the most common way attackers get into organizations. Security teams triage reported emails every day by checking the same things: who really sent it, where the links really go, and whether the attachment is dangerous. This tool automates that checklist and shows its reasoning, so a person can quickly confirm or overrule the verdict.

## What it checks

| Category | Indicator | Why it matters |
|---|---|---|
| Sender | Display name uses a brand the address doesn't match | Attackers set the name to "Contoso Payments" while sending from any domain |
| Sender | Reply-To or Return-Path on a different domain | Replies get routed to the attacker |
| Authentication | SPF, DKIM, or DMARC fail | The sending server isn't authorized for that domain |
| Links | Visible link text shows one site, real link goes to another | The classic phishing trick |
| Links | Raw IP address, URL shortener, or punycode (`xn--`) domain | Hides the real destination or imitates a real domain with look-alike characters |
| Content | Urgent or threatening phrases | Pressure makes people act before thinking |
| Attachments | Executable or macro files, double extensions like `invoice.pdf.exe` | Common malware delivery methods |

Each finding adds points. 60+ is **LIKELY PHISHING**, 30-59 is **SUSPICIOUS**, under 30 is **PROBABLY SAFE**.

## Example output

```
============================================================
File    : samples/phish_account_suspended.eml
From    : Northwind Bank Security <no-reply@northwind-alerts.example.net>
Subject : URGENT: Your account has been suspended
Verdict : LIKELY PHISHING  (risk score 100/100)
------------------------------------------------------------
[Sender        ] +20  Replies go to @freemail.example.org, not the sender's domain @northwind-alerts.example.net
[Sender        ] +10  Return-Path domain @bulk-mailer.example.org differs from From domain
[Authentication] +15  SPF check result: fail
[Authentication] +15  DKIM check result: none
[Authentication] +15  DMARC check result: fail
[Links         ] +25  Link text shows 'www.northwindbank.example' but actually goes to '198.51.100.23'
[Links         ] +20  Link points to a raw IP address: 198.51.100.23
[Links         ] +10  Link uses a URL shortener that hides the destination: bit.ly
[Content       ] +20  Pressure language: verify your account, account will be closed, unusual activity, immediately
```

The legitimate sample email (`legit_statement_ready.eml`) scores 0 with no findings.

## How to run

The analyzer uses only the Python standard library.

```bash
python analyzer.py samples/phish_account_suspended.eml
python analyzer.py samples/*.eml

pip install pytest
python -m pytest tests
```

To test a real email: in Gmail open the message, choose **More (⋮) > Download message**; in Outlook use **File > Save As**. Then run the analyzer on that `.eml` file.

## How it works

- Python's `email` module parses headers, bodies, and attachments, including multipart messages.
- An `HTMLParser` subclass collects every `<a>` tag's `href` and visible text so the two can be compared.
- Each check is a separate function that adds `Finding` objects (category, explanation, points) to a `Report`, which makes it easy to add new checks.

## Sample data

The `samples/` folder holds three hand-written emails: a credential-phishing message, a malicious-attachment message, and a legitimate one. They use a fictional bank and reserved example domains (RFC 2606) and IP ranges (RFC 5737).

## Limitations and next steps

- `base_domain()` takes the last two parts of a hostname, so it treats `example.co.uk` as `co.uk`. A production version would use the Public Suffix List.
- It doesn't yet detect look-alike domains that use swapped letters (`paypa1.com`). Comparing domains with edit distance against a list of known brands would catch these.
- Possible additions: check link domains against threat intelligence feeds, extract and hash attachments for VirusTotal lookup.

## Skills used

Python, email protocols (SMTP headers, MIME), SPF/DKIM/DMARC, HTML parsing, phishing indicator analysis, pytest
