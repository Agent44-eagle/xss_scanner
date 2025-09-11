import html
import re
import argparse
from colorama import Fore, Style
import urllib.parse
from urllib.parse import urlparse
from requests_futures.sessions import FuturesSession


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
            if parsed.query:  # only keep urls with params
                urls.append(url)
    return urls


def scanner_xss(urls, payloads):
    session = FuturesSession(max_workers=20)
    futures = []

    for url in urls:
        parsed = urllib.parse.urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        query_params = urllib.parse.parse_qs(parsed.query)

        for param in query_params:
            for payload in payloads:
                query_params[param][0] = payload
                new_query = urllib.parse.urlencode(query_params, doseq=True)
                inject_url = f"{base_url}?{new_query}"

                # GET
                future_get = session.get(inject_url, timeout=10)
                futures.append((future_get, "GET", inject_url))

                # POST
                post_data = {p: (payload if p == param else query_params[p][0]) for p in query_params}
                future_post = session.post(base_url, data=post_data, timeout=10)
                futures.append((future_post, "POST", base_url, post_data))

    for item in futures:
        future, rtype = item[0], item[1]

        try:
            response = future.result()
            if rtype == "GET":
                with open("response_get.txt", "a", encoding="utf-8") as out:
                    out.write(f"\n====Response GET: {item[2]}====\n")
                    out.write(f"Status: {response.status_code}\n")
                    out.write(response.text[:1000] + "\n")
                print(f"[+] GET {item[2]} Status: {response.status_code}")
            else:  # POST
                post_data = item[3]
                with open("response_post.txt", "a", encoding="utf-8") as out:
                    out.write(f"\n====Response POST: {item[2]}====\n")
                    out.write(f"Data: {post_data}\n")
                    out.write(f"Status: {response.status_code}\n")
                    out.write(response.text[:1000] + "\n")
                print(f"[+] POST {item[2]} Status: {response.status_code}")
        except Exception as e:
            print(Fore.RED + f"[X] {rtype} request error: {e}" + Style.RESET_ALL)


def analysis_response(payloads):
    with open("response_post.txt", "r", encoding="utf-8") as f_post, \
         open("response_get.txt", "r", encoding="utf-8") as f_get:

        post_content = f_post.read().lower()
        get_content = f_get.read().lower()

    post_content = html.unescape(re.sub(r'\s+', '', post_content).strip())
    get_content = html.unescape(re.sub(r'\s+', '', get_content).strip())

    responses = [{"type": "POST", "content": post_content},
                 {"type": "GET", "content": get_content}]

    for r in responses:
        content = r["content"]
        print(f"\n---Analyzing {r['type']} responses---")
        for payload in payloads:
            payload_lower = payload.lower()
            if payload_lower not in content:
                continue

            high_risk = medium_risk = low_risk = False

            high_patterns = [
                r"<script.*?>.*?" + re.escape(payload_lower) + r".*?</script>",
                r"on\w+\s*=\s*['\"].*?" + re.escape(payload_lower) + r".*?['\"]",
                r'href\s*=\s*["\']javascript:.*?' + re.escape(payload_lower),
                r'style\s*=\s*["\'].*?expression\(.*?' + re.escape(payload_lower) + r'.*?\).*?["\']',
                r'(src|data)\s*=\s*["\']data:text/html.*?' + re.escape(payload_lower) + r'.*?["\']',
                r'var\s+\w+\s*=\s*["\'].*?' + re.escape(payload_lower) + r'.*?["\']'
            ]

            # Low risk
            if re.search(re.escape(html.escape(payload_lower)), content) or '\\' + payload_lower in content:
                low_risk = True

            # High risk
            for pattern in high_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    high_risk = True
                    break

            # Medium fallback
            if not high_risk and not low_risk:
                medium_risk = True

            if high_risk:
            print(Fore.RED + f"[HIGH] {r['type']} | {r['url']} | Status: {r['status']} | Payload: {r['payload']}" + Style.RESET_ALL)
        elif medium_risk:
            print(Fore.YELLOW + f"[MEDIUM] {r['type']} | {r['url']} | Status: {r['status']} | Payload: {r['payload']}" + Style.RESET_ALL)
        elif low_risk:
            print(Fore.GREEN + f"[LOW/IGNORED] {r['type']} | {r['url']} | Status: {r['status']} | Payload: {r['payload']}" + Style.RESET_ALL)

            
