#!/usr/bin/env python3
import argparse
import json
from colorama import Fore, Style
from module import load_payloads, load_urls, scanner_xss, analysis_response, scanner_Dom

def save_results_json(results, path):
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(results, f, ensure_ascii=False, indent=2)
        print(Fore.GREEN + f"[+] Saved raw results to {path}" + Style.RESET_ALL)
    except Exception as e:
        print(Fore.RED + f"[X] Failed to save results to {path}: {e}" + Style.RESET_ALL)

def main():
    parser = argparse.ArgumentParser(description="Sonik XSS Scanner (Threaded)")
    parser.add_argument("-l", "--list", required=True, help="File containing list of URLs")
    parser.add_argument("-p", "--moon", default="moon.txt", help="File containing payloads (wordlist)")
    parser.add_argument("-w", "--workers", type=int, default=10, help="Max worker threads (default: 10)")
    parser.add_argument("-t", "--timeout", type=int, default=10, help="Request timeout seconds (default: 10)")
    parser.add_argument("--render-dom", action="store_true", help="Enable JS rendering in DOM scanner (if implemented)")
    parser.add_argument("--out", help="Save raw scanner results to JSON file (optional)")
    parser.add_argument("--no-post", action="store_true", help="Disable POST requests (only GET)")
    parser.add_argument("--no-get", action="store_true", help="Disable GET requests (only POST)")
    args = parser.parse_args()

    print(Fore.BLUE + "Welcome to Sonik XSS Scanner" + Style.RESET_ALL)

    # load payloads & urls
    try:
        payloads = load_payloads(args.moon)
        urls = load_urls(args.list)
    except Exception as e:
        print(Fore.RED + f"[X] Error loading files: {e}" + Style.RESET_ALL)
        return

    if not urls:
        print(Fore.RED + "[X] No URLs loaded. Exiting." + Style.RESET_ALL)
        return
    if not payloads:
        print(Fore.RED + "[X] No payloads loaded. Exiting." + Style.RESET_ALL)
        return

    print(Fore.CYAN + "[*] Starting XSS scanner..." + Style.RESET_ALL)

    # scanner_xss should accept workers & timeout and flags for GET/POST.
    # (If your scanner_xss signature is different, adapt the call accordingly.)
    try:
        results = scanner_xss(
            urls,
            payloads,
            max_workers=args.workers,
            request_timeout=args.timeout,
            enable_get=not args.no_get,
            enable_post=not args.no_post
        )
    except TypeError:
        # backwards compat: older signature without kwargs
        results = scanner_xss(urls, payloads, max_workers=args.workers)

    # save raw results if requested
    if args.out:
        save_results_json(results, args.out)

    print(Fore.GREEN + "[~] Starting DOM-based analysis..." + Style.RESET_ALL)
    try:
        # scanner_Dom may accept a render flag — adapt if your implementation differs
        try:
            scanner_Dom(urls, render=args.render_dom)
        except TypeError:
            # fallback if scanner_Dom only accepts urls
            scanner_Dom(urls)
    except Exception as e:
        print(Fore.RED + f"[X] DOM scanner error: {e}" + Style.RESET_ALL)

    print(Fore.CYAN + "[*] Requests finished. Starting response analysis..." + Style.RESET_ALL)

    try:
        analysis_response(results, payloads)
    except Exception as e:
        print(Fore.RED + f"[X] Analysis error: {e}" + Style.RESET_ALL)

    print(Fore.GREEN + "[*] Analysis finished." + Style.RESET_ALL)


if __name__ == "__main__":
    main()



