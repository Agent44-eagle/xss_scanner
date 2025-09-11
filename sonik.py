import argparse
from colorama import Fore, Style
from module import load_payloads, load_urls, scanner_xss, analysis_response


def main():
    parser = argparse.ArgumentParser(description="XSS Scanner Tool (Asynchronous)")
    parser.add_argument("-l", "--list", required=True, help="File containing list of URLs")
    parser.add_argument("-p", "--payloads", default="payloads.txt", help="File containing payloads")
    args = parser.parse_args()

    print(Fore.BLUE + "Welcome to Sonik XSS Scanner" + Style.RESET_ALL)

    payloads = load_payloads(args.payloads)
    urls = load_urls(args.list)

    print(Fore.CYAN + "[*] Starting XSS scanner..." + Style.RESET_ALL)
    scanner_xss(urls, payloads)

    print(Fore.CYAN + "[*] Requests finished. Starting response analysis..." + Style.RESET_ALL)
    analysis_response(payloads)

    print(Fore.GREEN + "[*] Analysis finished." + Style.RESET_ALL)

    
if __name__ == "__main__":

    main()
