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
    session =HTMLSession()
    for url in urls : 
       try : 
          r =session.get(url , timeout=10) 
          r.html.render(sleep=1)
          print(f"\nScanning {url}")
          for input_el in r.html.find("input"):
               print("Input found:", input_el.attrs)
       except Exception as e:
            print(f"Error with {url}: {e}")
    

def generate_encodings(payload):
    encoded_payloads = [
        payload,                        # original
        urllib.parse.quote(payload),     # URL encoded
        html.escape(payload),            # HTML encoded
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

    # html unescape
    try:
        he = html.unescape(s)
        variants.add(he)
    except Exception:
        pass

    # محاولة فك unicode-escape sequences مثل \u003c
    try:
        # ملاحظة: decode('unicode_escape') يمكن يفسر sequences مثل \uXXXX
        ue = bytes(s, "utf-8").decode("unicode_escape")
        variants.add(ue)
    except Exception:
        pass


    base_candidates = list(variants)  # شامل كل اللي لقينا
    for base in base_candidates:
        # URL encoded
        try:
            variants.add(urllib.parse.quote(base, safe=''))
        except Exception:
            pass
        # HTML escaped
        try:
            variants.add(html.escape(base))
        except Exception:
            pass
        # Unicode escaped \uXXXX 
        try:
            unicode_esc = ''.join([f'\\u{ord(c):04x}' for c in base])
            variants.add(unicode_esc)
        except Exception:
            pass
        # double URL encode
        try:
            variants.add(urllib.parse.quote(urllib.parse.quote(base, safe=''), safe=''))
        except Exception:
            pass

    
    for v in list(variants):
        if len(v) > 6:
            variants.add(v[:6])
            variants.add(v[-6:])

    #
    return {x for x in variants if x is not None and x != ""}


def analysis_response(results, payloads):
    
    
    
    for r in results:
        
        content_raw = r.get("content", "")

        content_compact = re.sub(r'\s+', '', content_raw).lower()
        content_full = content_raw.lower()

        url = r.get("url")
        payload_used = (r.get("payload") or "").strip()
        payload_l = payload_used.lower()

        
        variants = _generate_detection_variants(payload_used)

        #
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
