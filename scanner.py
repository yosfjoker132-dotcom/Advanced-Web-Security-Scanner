import socket
import sys
from urllib.parse import urlparse
import requests

# Terminal Colors
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
RESET = "\033[0m"

def print_banner():
    print(f"{BLUE}===================================================={RESET}")
    print(f"{GREEN}   Advanced Web Security & Vulnerability Scanner    {RESET}")
    print(f"{BLUE}===================================================={RESET}\n")

def clean_target_url(target):
    if not target.startswith("http://") and not target.startswith("https://"):
        target = "http://" + target
    parsed = urlparse(target)
    domain = parsed.netloc or parsed.path
    if domain.startswith("www."):
        domain = domain[4:]
    return target, domain

def get_ip_and_active_devices(domain):
    print(f"{YELLOW}[*] Resolving IP address and checking host info...{RESET}")
    try:
        ip = socket.gethostbyname(domain)
        print(f" -> Target IP: {GREEN}{ip}{RESET}")

        try:
            host_info = socket.gethostbyaddr(ip)
            print(f" -> Host/Server Info: {GREEN}{host_info[0]}{RESET}")
        except Exception:
            print(f"{RED}[x] Network devices hidden: Target is protected behind a Cloud Proxy / WAF.{RESET}")

        return ip
    except socket.gaierror:
        print(f"{RED}[!] Error: Failed to resolve target IP address.{RESET}")
        return None

def scan_ports(ip):
    print(f"\n{YELLOW}[*] Starting Port Scanning...{RESET}")
    common_ports = {
        21: "FTP (File Transfer)",
        22: "SSH (Secure Shell)",
        80: "HTTP (Web)",
        443: "HTTPS (Secure Web)",
        3306: "MySQL (Database)",
        8080: "HTTP Proxy"
    }

    open_ports = []
    for port, service in common_ports.items():
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1.0)
        result = sock.connect_ex((ip, port))
        if result == 0:
            print(f" -> Port {GREEN}{port}{RESET} ({service}): {GREEN}OPEN{RESET}")
            open_ports.append(port)
        sock.close()

    if not open_ports:
        print(f" -> All common ports are closed or filtered.")
    return open_ports

def check_waf_and_server(target_url):
    print(f"\n{YELLOW}[*] Analyzing Server and WAF protection...{RESET}")
    try:
        response = requests.get(target_url, timeout=5)
        headers = response.headers

        server = headers.get('Server', 'Unknown / Hidden')
        print(f" -> Server Stack: {GREEN}{server}{RESET}")

        waf_detected = False
        waf_signatures = {
            "cloudflare": "Cloudflare WAF",
            "aws": "AWS WAF",
            "imperva": "Imperva / Incapsula",
            "akamai": "Akamai WAF",
            "sucuri": "Sucuri WAF"
        }

        for header_key, header_val in headers.items():
            for sig, waf_name in waf_signatures.items():
                if sig in header_key.lower() or sig in str(header_val).lower():
                    print(f" -> Detected WAF: {GREEN}{waf_name}{RESET}")
                    waf_detected = True
                    break

        if not waf_detected:
            print(f" -> WAF: {RED}No major WAF signature detected.{RESET}")

        return headers
    except requests.RequestException as e:
        print(f"{RED}[!] Failed to fetch target headers: {e}{RESET}")
        return {}

def analyze_vulnerabilities(headers, open_ports):
    print(f"\n{YELLOW}[*] Vulnerability Assessment & Remediation Report:{RESET}")
    vulns_found = 0

    if "Content-Security-Policy" not in headers:
        vulns_found += 1
        print(f"\n{RED}[!] Vulnerability: Missing Content-Security-Policy (CSP){RESET}")
        print("   - Risk: Increases susceptibility to Cross-Site Scripting (XSS).")
        print(f"   - {GREEN}Remediation:{RESET} Implement a strong CSP header on your server.")

    if "X-Frame-Options" not in headers:
        vulns_found += 1
        print(f"\n{RED}[!] Vulnerability: Missing X-Frame-Options{RESET}")
        print("   - Risk: Exposes the site to Clickjacking attacks.")
        print(f"   - {GREEN}Remediation:{RESET} Add `X-Frame-Options: SAMEORIGIN` header.")

    if 21 in open_ports:
        vulns_found += 1
        print(f"\n{RED}[!] Vulnerability: FTP Port (21) is open to the public{RESET}")
        print("   - Risk: Unencrypted file transfers expose credentials.")
        print(f"   - {GREEN}Remediation:{RESET} Close port 21 and use SFTP (port 22) via SSH.")

    if vulns_found == 0:
        print(f"{GREEN} -> Excellent! No common vulnerabilities found in the quick scan.{RESET}")

def main():
    print_banner()
    target_input = input("Enter target URL (e.g., example.com): ").strip()
    if not target_input:
        print("No target provided!")
        return

    target_url, domain = clean_target_url(target_input)
    print(f"\nInitiating deep scan on: {BLUE}{domain}{RESET}\n")

    ip = get_ip_and_active_devices(domain)
    if ip:
        open_ports = scan_ports(ip)
        headers = check_waf_and_server(target_url)
        analyze_vulnerabilities(headers, open_ports)

if __name__ == "__main__":
    main()

