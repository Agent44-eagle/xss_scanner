import html
import re
import urllib.parse
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, Style
from requests_html import HTMLSession
import requests


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


def generate_encodings(payload):
    encoded_payloads = [
        payload,  # original
        urllib.parse.quote(payload),  # URL encoded
        html.escape(payload),  # HTML encoded
        ''.join([f'\\u{ord(c):04x}' for c in payload])  # Unicode encoded
    ]
    return encoded_payloads


def _generate_detection_variants(s):
    variants = set()
    variants.add(s)

    try:
        u = s
        for _ in range(3):
            uu = urllib.parse.unquote(u)
            if uu == u:
                break
            u = uu
            variants.add(u)
    except Exception:
        pass

    try:
        he = html.unescape(s)
        variants.add(he)
    except Exception:
        pass

    try:
        ue = bytes(s, "utf-8").decode("unicode_escape")
        variants.add(ue)
    except Exception:
        pass

    base_candidates = list(variants)
    for base in base_candidates:
        try:
            variants.add(urllib.parse.quote(base, safe=''))
        except Exception:
            pass
        try:
            variants.add(html.escape(base))
        except Exception:
            pass
        try:
            unicode_esc = ''.join([f'\\u{ord(c):04x}' for c in base])
            variants.add(unicode_esc)
        except Exception:
            pass
        try:
            variants.add(urllib.parse.quote(urllib.parse.quote(base, safe=''), safe=''))
        except Exception:
            pass

    for v in list(variants):
        if len(v) > 6:
            variants.add(v[:6])
            variants.add(v[-6:])

    return {x for x in variants if x is not None and x != ""}

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
                "content": response.text.lower()
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
                        # GET
                        query_params[param][0] = encoded_payload
                        new_query = urllib.parse.urlencode(query_params, doseq=True)
                        inject_url = f"{base_url}?{new_query}"
                        futures.append(executor.submit(send_request, "GET", inject_url, None, encoded_payload))

                        # POST
                        post_data = {p: (encoded_payload if p == param else query_params[p][0]) for p in query_params}
                        futures.append(executor.submit(send_request, "POST", base_url, post_data, encoded_payload))

        # انتظار جميع الـ futures
        for _ in as_completed(futures):
            pass

    return results

def analysis_response(results, payloads):
    for r in results:
        content_raw = r.get("content", "")
        content_compact = re.sub(r'\s+', '', content_raw).lower()
        content_full = content_raw.lower()

        url = r.get("url")
        payload_used = (r.get("payload") or "").strip()
        payload_l = payload_used.lower()

        variants = _generate_detection_variants(payload_used)

        found_variant = None
        found_in = None  # 'compact' or 'full'

        for v in variants:
            v_low = v.lower()
            if v_low in content_compact:
                found_variant = v
                found_in = "compact"
                break
            if v_low in content_full:
                found_variant = v
                found_in = "full"
                break

        if not found_variant:
            continue

        high_risk = medium_risk = low_risk = False
        escaped_payload_for_regex = re.escape(found_variant)

        high_patterns = [
            r"<script[^>]*?>.*?" + escaped_payload_for_regex + r".*?</script>",
            r"on\w+\s*=\s*['\"].*?" + escaped_payload_for_regex + r".*?['\"]",
            r"href\s*=\s*['\"]javascript:.*?" + escaped_payload_for_regex + r".*?['\"]",
            r"style\s*=\s*['\"].*?expression\(.*?" + escaped_payload_for_regex + r".*?\).*?['\"]",
            r"(src|data)\s*=\s*['\"]data:text/html.*?" + escaped_payload_for_regex + r".*?['\"]",
            r"var\s+\w+\s*=\s*['\"].*?" + escaped_payload_for_regex + r".*?['\"]"
        ]

        match_snippet = ""

        if re.search(re.escape(html.escape(found_variant)), content_full) or ('\\' + found_variant) in content_full:
            low_risk = True

        for pattern in high_patterns:
            match = re.search(pattern, content_full, re.IGNORECASE | re.DOTALL)
            if match:
                high_risk = True
                start = max(match.start() - 60, 0)
                end = min(match.end() + 60, len(content_full))
                match_snippet = content_full[start:end]
                break

        if not high_risk and not low_risk:
            medium_risk = True
            idx = content_full.find(found_variant.lower())
            if idx != -1:
                start = max(idx - 60, 0)
                end = min(idx + len(found_variant) + 60, len(content_full))
                match_snippet = content_full[start:end]

        encoding_label = "unknown"
        try:
            if found_variant == payload_used:
                encoding_label = "original"
            elif urllib.parse.unquote(found_variant) == payload_used:
                encoding_label = "url-decoded"
            elif html.unescape(found_variant) == payload_used:
                encoding_label = "html-unescaped"
            elif found_variant.startswith("\\u"):
                encoding_label = "unicode-escaped"
            elif urllib.parse.quote(payload_used, safe='') == found_variant:
                encoding_label = "url-encoded"
            elif html.escape(payload_used) == found_variant:
                encoding_label = "html-escaped"
            else:
                if urllib.parse.unquote(found_variant) != found_variant:
                    encoding_label = "some-url-encoding"
        except Exception:
            encoding_label = "detected-variant"

        if high_risk:
            print(Fore.RED + f"[HIGH] Payload detected (encoded as: {encoding_label}): {payload_used} in {url}" + Style.RESET_ALL)
            print(Fore.YELLOW + f" Evidence snippet: {match_snippet}" + Style.RESET_ALL)
        elif medium_risk:
            print(Fore.YELLOW + f"[MEDIUM] Payload detected (encoded as: {encoding_label}): {payload_used} in {url}" + Style.RESET_ALL)
            print(Fore.CYAN + f" Evidence snippet: {match_snippet}" + Style.RESET_ALL)
        elif low_risk:
            print(Fore.MAGENTA + f"[LOW/ESCAPED] Payload detected (encoded/escaped as: {encoding_label}): {payload_used} in {url}" + Style.RESET_ALL)
            print(Fore.CYAN + f" Evidence snippet: {match_snippet}" + Style.RESET_ALL)
