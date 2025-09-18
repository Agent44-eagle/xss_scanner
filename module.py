import html
import re
import urllib.parse
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, Style, init
from requests_html import HTMLSession
import requests

init(autoreset=True)

# ----------------- Load payloads / URLs -----------------
def load_payloads(file_path):
    with open(file_path, "r", encoding="utf-8") as f:
        return [p.strip() for p in f if p.strip()]

def load_urls(file_path):
    urls = []
    with open(file_path, "r", encoding="utf-8") as f_in:
        for line in f_in:
            url = line.strip()
            if not url:
                continue
            parsed = urlparse(url)
            if parsed.query:
                urls.append(url)
    return urls

# ----------------- DOM Scanner -----------------
def scanner_Dom(urls):
    session = HTMLSession()
    for url in urls:
        try:
            r = session.get(url, timeout=10)
            r.html.render(sleep=1)
            print(f"\nScanning {url}")
            for input_el in r.html.find("input"):
                print("Input found:", input_el.attrs)
        except Exception as e:
            print(f"Error with {url}: {e}")

# ----------------- Encoding Variants -----------------
def generate_encodings(payload):
    return [
        payload,
        urllib.parse.quote(payload),
        html.escape(payload),
        ''.join([f'\\u{ord(c):04x}' for c in payload])
    ]

def _generate_detection_variants(s):
    variants = set([s])
    u = s
    for _ in range(3):
        uu = urllib.parse.unquote(u)
        if uu == u:
            break
        u = uu
        variants.add(u)
    variants.add(html.unescape(s))
    try:
        variants.add(bytes(s, "utf-8").decode("unicode_escape"))
    except Exception:
        pass
    for base in list(variants):
        variants.add(urllib.parse.quote(base, safe=''))
        variants.add(html.escape(base))
        variants.add(''.join([f'\\u{ord(c):04x}' for c in base]))
        variants.add(urllib.parse.quote(urllib.parse.quote(base, safe=''), safe=''))
    return {x for x in variants if x}

def decode_unicode_escapes(s):
    try:
        return bytes(s, "utf-8").decode("unicode_escape")
    except Exception:
        return s

def fully_decode_url(s):
    u = s
    for _ in range(3):
        uu = urllib.parse.unquote(u)
        if uu == u:
            break
        u = uu
    return u

# ----------------- Scanner XSS -----------------
def scanner_xss(urls, payloads, max_workers=10):
    results = []

    def send_request(rtype, url, data=None, payload_value=None):
        try:
            if rtype == "GET":
                response = requests.get(url, timeout=10)
            else:
                response = requests.post(url, data=data, timeout=10)
            results.append({
                "type": rtype,
                "url": url,
                "payload": payload_value,
                "status": response.status_code,
                "content": response.text
            })
            color = Fore.RED if response.status_code == 200 else Fore.CYAN
            print(color + f"[+] {rtype} {url} Status: {response.status_code}" + Style.RESET_ALL)
        except Exception as e:
            print(Fore.RED + f"[X] {rtype} request error: {e}" + Style.RESET_ALL)

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = []
        for url in urls:
            parsed = urllib.parse.urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            query_params = urllib.parse.parse_qs(parsed.query)
            for param in query_params:
                for payload in payloads:
                    for encoded_payload in generate_encodings(payload):
                        query_params[param][0] = encoded_payload
                        new_query = urllib.parse.urlencode(query_params, doseq=True)
                        inject_url = f"{base_url}?{new_query}"
                        futures.append(executor.submit(send_request, "GET", inject_url, None, encoded_payload))
                        post_data = {p: (encoded_payload if p == param else query_params[p][0]) for p in query_params}
                        futures.append(executor.submit(send_request, "POST", base_url, post_data, encoded_payload))
        for _ in as_completed(futures):
            pass
    return results

# ----------------- Analysis -----------------
def analysis_response(results, payloads):
    for r in results:
        content_raw = r.get("content", "")
        content_full = decode_unicode_escapes(content_raw)
        url = r.get("url")
        payload_used = (r.get("payload") or "").strip()
        if not payload_used:
            continue

        payload_decoded = decode_unicode_escapes(fully_decode_url(payload_used))
        variants = _generate_detection_variants(payload_decoded)
        found_variant = None
        for v in variants:
            if v in content_full:
                found_variant = v
                break
        if not found_variant:
            continue

        idx = content_full.find(found_variant)
        if idx != -1:
            start = max(idx - 50, 0)
            end = min(idx + len(found_variant) + 50, len(content_full))
            snippet = content_full[start:end].replace('\n', ' ').replace('\r', '')
        else:
            snippet = ""

        # تحديد مستوى الخطورة
        high_patterns = [
            r"<script[^>]*?>.*?" + re.escape(found_variant) + r".*?</script>",
            r"on\w+\s*=\s*['\"].*?" + re.escape(found_variant) + r".*?['\"]",
            r"href\s*=\s*['\"]javascript:.*?" + re.escape(found_variant) + r".*?['\"]",
            r"style\s*=\s*['\"].*?expression\(.*?" + re.escape(found_variant) + r".*?\).*?['\"]",
            r"(src|data)\s*=\s*['\"]data:text/html.*?" + re.escape(found_variant) + r".*?['\"]",
            r"var\s+\w+\s*=\s*['\"].*?" + re.escape(found_variant) + r".*?['\"]"
        ]
        high_risk = any(re.search(p, content_full, re.IGNORECASE | re.DOTALL) for p in high_patterns)
        low_risk = (re.escape(html.escape(payload_used)) in content_full) or ('\\' + payload_used) in content_full
        medium_risk = not high_risk and not low_risk

        # تحديد لون الطباعة
        if high_risk:
            color_main = Fore.RED
        elif medium_risk:
            color_main = Fore.YELLOW
        else:
            color_main = Fore.MAGENTA

        # تمييز الـ payload داخل snippet
        snippet_colored = snippet.replace(found_variant, color_main + found_variant + Style.RESET_ALL)

        # تحديد ترميز payload
        encoding_label = "unknown"
        try:
            decoded_once = urllib.parse.unquote(payload_used)
            if found_variant == payload_used:
                encoding_label = "original"
            elif decoded_once == payload_used:
                encoding_label = "url-decoded"
            elif html.unescape(found_variant) == payload_used:
                encoding_label = "html-unescaped"
            elif found_variant.startswith("\\u"):
                encoding_label = "unicode-escaped"
            elif urllib.parse.quote(payload_used, safe='') == found_variant:
                encoding_label = "url-encoded"
            elif html.escape(payload_used) == found_variant:
                encoding_label = "html-escaped"
        except Exception:
            pass

        # الطباعة النهائية
        print(color_main + f"[DETECTED] Payload detected (encoded as: {encoding_label}): {payload_used} in {url}" + Style.RESET_ALL)
        print(Fore.YELLOW + f" Evidence snippet: ...{snippet_colored}..." + Style.RESET_ALL)
