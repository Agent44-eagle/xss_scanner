# XSS Scanner (Async)

## 📌 Description
This project provides a simple and fast tool to detect **XSS (Cross-Site Scripting)** vulnerabilities using:
- **GET / POST requests**.
- **Asynchronous requests (FuturesSession)** to speed up testing for large numbers of URLs.
- **Response Analysis** with risk categorization:
  - **HIGH** → Critical, directly exploitable.
  - **MEDIUM** → Potentially exploitable.
  - **LOW/IGNORED** → Encoded/escaped payloads (less dangerous, reduces false positives).

---

## ⚙️ Installation

```bash
git clone https://github.com/Agent44-eagle/xss_scanner.git
cd xss_scanner
pip install -r requirements.txt

---

## 🚀 Run the scanner

Simply provide your URLs file and payloads file, then run:

```bash
python sonik.py -l urls.txt -p payloads.txt



