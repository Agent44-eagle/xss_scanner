# XSS Scanner (Async)

## 📌 Description
XSS Scanner (Advanced Python Tool)

XSS Scanner is an advanced Python tool designed for automated detection of Reflected, Stored, and basic DOM-based XSS vulnerabilities. It supports multiple payload encodings, concurrent requests, and provides risk classification with evidence snippets.

## Features

GET & POST Injection: Automatically injects payloads into URL parameters and POST data.

Multiple Payload Encodings: Supports URL encoding, HTML escaping, Unicode escaping, and double encodings.

DOM Analysis: Uses requests_html to render JavaScript and detect input fields for potential XSS injection.

Risk Classification: Categorizes findings as HIGH, MEDIUM, or LOW risk with snippets from responses.

Concurrent Scanning: Uses multithreading (ThreadPoolExecutor) to speed up scanning across multiple URLs and payloads.

Advanced Detection Variants: Generates multiple detection variants for each payload to improve detection accuracy even if payloads are encoded or partially escaped.

Color-Coded Output: Highlights findings in the terminal for easy identification.

## Notes

DOM-based XSS detection is basic; for full JS coverage, use Selenium or Playwright integration.

Designed for penetration testing learning, bug bounty programs, and security research.

⚠️ Only test on websites you have explicit permission to scan.
---

## ⚙️ Installation

```bash
git clone https://github.com/Agent44-eagle/xss_scanner.git
cd xss_scanner
pip install -r requirements.txt
create file urls.txt and put urls 

---

## 🚀 Run the scanner

Simply provide your URLs file and payloads file, then run:

```bash
python sonik.py -l urls.txt -p moon.txt





