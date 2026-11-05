import socket
import sys
from urllib.parse import urlparse
import requests

# ألوان للتنسيق في التيرمينال
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
    print(f"{YELLOW}[*] جاري استخراج الـ IP وفحص الأجهزة المترابطة...{RESET}")
    try:
        ip = socket.gethostbyname(domain)
        print(f" -> IP الموقع الرئيسي: {GREEN}{ip}{RESET}")

        # محاولة التعرف على الأجهزة المرتبطة/الاسم العكسي (Reverse DNS)
        try:
            host_info = socket.gethostbyaddr(ip)
            print(f" -> الأجهزة/المستضيف المكتشف: {GREEN}{host_info[0]}{RESET}")
        except Exception:
            print(
                f"{RED}[x] تعذر تحديد أجهزة الشبكة الداخلية: الموقع يعمل خلف سيرفر سحابي (Cloud Proxy) أو جدار حماية يخفي تفاصيل السيرفرات الحقيقية.{RESET}"
            )

        return ip
    except socket.gaierror:
        print(f"{RED}[!] خطأ: تعذر الوصول إلى عنوان الـ IP للموقع.{RESET}")
        return None


def scan_ports(ip):
    print(f"\n{YELLOW}[*] جاري فحص المنافذ (Port Scanning)...{RESET}")
    common_ports = {
        21: "FTP (نقل الملفات)",
        22: "SSH (التحكم عن بعد)",
        80: "HTTP (الويب)",
        443: "HTTPS (الويب المشفر)",
        3306: "MySQL (قاعدة البيانات)",
        8080: "HTTP Proxy",
    }

    open_ports = []
    for port, service in common_ports.items():
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1.0)
        result = sock.connect_ex((ip, port))
        if result == 0:
            print(f" -> البورت {GREEN}{port}{RESET} ({service}): {GREEN}مفتوح{RESET}")
            open_ports.append(port)
        sock.close()

    if not open_ports:
        print(f" -> جميع البورتات الشائعة مغلقة أو محمية.")
    return open_ports


def check_waf_and_server(target_url):
    print(f"\n{YELLOW}[*] جاري فحص نوع السيرفر وجدار الحماية (WAF)...{RESET}")
    try:
        response = requests.get(target_url, timeout=5)
        headers = response.headers

        # كشف نوع السيرفر
        server = headers.get("Server", "غير معروف / مخفي")
        print(f" -> نوع السيرفر (Server Stack): {GREEN}{server}{RESET}")

        # كشف جدار الحماية WAF
        waf_detected = False
        waf_signatures = {
            "cloudflare": "Cloudflare WAF",
            "aws": "AWS WAF",
            "imperva": "Imperva / Incapsula",
            "akamai": "Akamai WAF",
            "sucuri": "Sucuri WAF",
        }

        for header_key, header_val in headers.items():
            for sig, waf_name in waf_signatures.items():
                if sig in header_key.lower() or sig in str(header_val).lower():
                    print(
                        f" -> جدار الحماية المكتشف (WAF): {GREEN}{waf_name}{RESET}"
                    )
                    waf_detected = True
                    break

        if not waf_detected:
            print(
                f" -> جدار الحماية: {RED}لم يتم كشف جدار حماية شهير (قد يكون جدار عادي أو غير محمي بالكامل){RESET}"
            )

        return headers
    except requests.RequestException as e:
        print(f"{RED}[!] تعذر جلب هيدرز الموقع: {e}{RESET}")
        return {}


def analyze_vulnerabilities(headers, open_ports):
    print(
        f"\n{YELLOW}[*] تقرير الثغرات الأمنية والنصائح لترقيعها (Vulnerabilities & Solutions):{RESET}"
    )
    vulns_found = 0

    # 1. ثغرة غياب Content-Security-Policy
    if "Content-Security-Policy" not in headers:
        vulns_found += 1
        print(f"\n{RED}[!] ثغرة: غياب هيدر Content-Security-Policy (CSP){RESET}")
        print(
            "   - الخطورة: تزيد من احتمال ثغرات الـ Cross-Site Scripting (XSS)."
        )
        print(
            f"   - {GREEN}الحل لترقيع الثغرة:{RESET} قم بإضافة هيدر CSP في السيرفر لتحديد المصادر المسموح بتنفيذ الأكواد منها."
        )

    # 2. ثغرة غياب X-Frame-Options
    if "X-Frame-Options" not in headers:
        vulns_found += 1
        print(f"\n{RED}[!] ثغرة: غياب هيدر X-Frame-Options{RESET}")
        print(
            "   - الخطورة: تعريض الموقع لثغرات Clickjacking (تضمين الموقع داخل Iframe خبيث)."
        )
        print(
            f"   - {GREEN}الحل لترقيع الثغرة:{RESET} أضف `X-Frame-Options: SAMEORIGIN` في إعدادات السيرفر."
        )

    # 3. خطورة البورتات المفتوحة والحساسة
    if 21 in open_ports:
        vulns_found += 1
        print(f"\n{RED}[!] ثغرة: بورت FTP (21) مفتوح لعامة الإنترنت{RESET}")
        print(
            "   - الخطورة: نقل البيانات يتم بدون تشفير، مما يعرض بيانات الدخول للاختراق."
        )
        print(
            f"   - {GREEN}الحل لترقيع الثغرة:{RESET} أغلق بورت 21 واستخدم SFTP (بورت 22) التابع لـ SSH."
        )

    if vulns_found == 0:
        print(f"{GREEN} -> ممتاز! لم يتم العثور على ثغرات شائعة في الفحص السريع.{RESET}")


def main():
    print_banner()
    target_input = input("أدخل رابط الموقع للفحص (مثال: example.com): ").strip()
    if not target_input:
        print("لم يتم إدخال رابط!")
        return

    target_url, domain = clean_target_url(target_input)
    print(f"\nبدء الفحص الشامل على: {BLUE}{domain}{RESET}\n")

    ip = get_ip_and_active_devices(domain)
    if ip:
        open_ports = scan_ports(ip)
        headers = check_waf_and_server(target_url)
        analyze_vulnerabilities(headers, open_ports)


if __name__ == "__main__":
    main()
