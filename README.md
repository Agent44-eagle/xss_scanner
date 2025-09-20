# XSS Scanner (Advanced Python Tool)

## 📌 Description
Short description
A practical Python XSS scanner that injects payloads into URL parameters (GET/POST), generates multiple encoded variants, renders simple JavaScript-powered pages for basic DOM inspection, and performs robust detection by decoding and matching multiple payload forms. Outputs colorized, prioritized findings with evidence snippets.

Key features

GET & POST parameter injection for every query parameter found.

Multiple payload encodings: original, URL-encoded, HTML-escaped, Unicode-escaped, double encodings.

Advanced detection variants: automatic URL-decoding, HTML-unescape, unicode-escape decoding, and many derived variants for robust matching.

Basic DOM inspection via requests_html (renders pages and lists input elements).

Concurrent scanning using ThreadPoolExecutor for faster testing across many targets.

Detection logic that matches encoded/decoded payloads inside responses (reduces false negatives).

Colorized terminal output with clear evidence snippets and simple risk classification (HIGH / MEDIUM / LOW/escaped).

Safe failure handling and timeouts to avoid hanging requests.
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







