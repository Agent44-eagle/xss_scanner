import html
import re
import urllib.parse
from urllib.parse import urlparse
from requests_futures.sessions import FuturesSession
from colorama import Fore, Style


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


def scanner_xss(urls, payloads):
    session = FuturesSession(max_workers=20)
    futures = []
    results = []

    for url in urls:
        parsed = urllib.parse.urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        query_params = urllib.parse.parse_qs(parsed.query)

        for param in query_params:
            for payload in payloads:
                query_params[param][0] = payload
                new_query = urllib.parse.urlencode(query_params, doseq=True)
                inject_url = f"{base_url}?{new_query}"

                # GET request
                future_get = session.get(inject_url, timeout=10)
                futures.append((future_get, "GET", inject_url, payload))

                # POST request
                post_data = {p: (payload if p == param else query_params[p][0]) for p in query_params}
                future_post = session.post(base_url, data=post_data, timeout=10)
                futures.append((future_post, "POST", base_url, payload))

    # Collect responses
    for item in futures:
        future, rtype, target_url, payload = item[0], item[1], item[2], item[3]
        try:
            response = future.result()
            results.append({
                "type": rtype,
                "url": target_url,
                "payload": payload,
                "content": response.text.lower()
            })
            print(f"[+] {rtype} {target_url} Status: {response.status_code}")
        except Exception as e:
            print(Fore.RED + f"[X] {rtype} request error: {e}" + Style.RESET_ALL)

    return results


def analysis_response(results, payloads):
    for r in results:
        content = html.unescape(re.sub(r'\s+', '', r["content"]).strip())
        url = r["url"]
        payload = r["payload"].lower()

        if payload not in content:
            continue

        high_risk = medium_risk = low_risk = False

        high_patterns = [
            r"<script.*?>.*?" + re.escape(payload) + r".*?</script>",
            r"on\w+\s*=\s*['\"].*?" + re.escape(payload) + r".*?['\"]",
            r'href\s*=\s*["\']javascript:.*?' + re.escape(payload),
            r'style\s*=\s*["\'].*?expression\(.*?' + re.escape(payload) + r'.*?\).*?["\']',
            r'(src|data)\s*=\s*["\']data:text/html.*?' + re.escape(payload) + r'.*?["\']',
            r'var\s+\w+\s*=\s*["\'].*?' + re.escape(payload) + r'.*?["\']'
        ]

        # Low risk
        if re.search(re.escape(html.escape(payload)), content) or '\\' + payload in content:
            low_risk = True

        # High risk
        match_snippet = ""
        for pattern in high_patterns:
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                high_risk = True
                start = max(match.start() - 30, 0)
                end = min(match.end() + 30, len(content))
                match_snippet = content[start:end]
                break

        # Medium fallback
        if not high_risk and not low_risk:
            medium_risk = True
            snippet_index = content.find(payload)
            if snippet_index != -1:
                start = max(snippet_index - 30, 0)
                end = min(snippet_index + len(payload) + 30, len(content))
                match_snippet = content[start:end]

        # Print results with URL + snippet
        if high_risk:
            print(Fore.RED + f"[HIGH] Payload detected: {payload} in {url}\n  Evidence: {match_snippet}" + Style.RESET_ALL)
        elif medium_risk:
            print(Fore.YELLOW + f"[MEDIUM] Payload detected: {payload} in {url}\n  Evidence: {match_snippet}" + Style.RESET_ALL)
        elif low_risk:
            print(Fore.GREEN + f"[LOW/IGNORED] Payload detected (encoded/escaped): {payload} in {url}" + Style.RESET_ALL)

