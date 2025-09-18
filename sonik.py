#!/usr/bin/env python3
import argparse
from colorama import Fore, Style, init as colorama_init
from module import load_payloads, load_urls, scanner_xss, analysis_response, scanner_Dom

# تهيئة الألوان
colorama_init(autoreset=True)

def main():
    parser = argparse.ArgumentParser(description="Sonik XSS Scanner (Threaded)")
    parser.add_argument("-l", "--list", required=True, help="File containing list of URLs")
    parser.add_argument("-p", "--moon", default="moon.txt", help="File containing payloads")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of worker threads for requests (default: 10)")
    args = parser.parse_args()

    print(Fore.BLUE + "Welcome to Sonik XSS Scanner" + Style.RESET_ALL)

    # تحميل الـ payloads و URLs
    payloads = load_payloads(args.moon)
    urls = load_urls(args.list)

    if not urls:
        print(Fore.RED + "[!] No URLs found. Exiting." + Style.RESET_ALL)
        return

    if not payloads:
        print(Fore.RED + "[!] No payloads found. Exiting." + Style.RESET_ALL)
        return

    print(Fore.CYAN + "[*] Starting XSS scanner..." + Style.RESET_ALL)
    # تمرير عدد الخيوط إلى scanner_xss (تأكد أن الدالة تقبل max_workers)
    results = scanner_xss(urls, payloads, max_workers=args.threads)

    print(Fore.GREEN + "[~] Starting DOM-based analysis..." + Style.RESET_ALL)
    scanner_Dom(urls)

    print(Fore.CYAN + "[*] Requests finished. Starting response analysis..." + Style.RESET_ALL)
    analysis_response(results, payloads)

    print(Fore.GREEN + "[*] Analysis finished." + Style.RESET_ALL)


if __name__ == "__main__":
    main()
