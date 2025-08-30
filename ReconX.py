import socket
import requests
import whois
import subprocess

def get_ip(domain):
    try:
        ip = socket.gethostbyname(domain)
        print(f"[+] IP Address: {ip}")
    except Exception as e:
        print(f"[-] Could not get IP: {e}")

def get_headers(domain):
    try:
        url = "http://" + domain
        response = requests.get(url, timeout=5)
        print("\n[+] Server Headers:")
        for key, value in response.headers.items():
            print(f"    {key}: {value}")
    except Exception as e:
        print(f"[-] Could not fetch headers: {e}")

def get_whois(domain):
    try:
        info = whois.whois(domain)
        print("\n[+] Whois Information:")
        for key, value in info.items():
            print(f"    {key}: {value}")
    except Exception as e:
        print(f"[-] Whois lookup failed: {e}")

def get_subdomains(domain):
    try:
        print("\n[+] Subdomain lookup with dig:")
        result = subprocess.check_output(["dig", f"*.{domain}", "+short"], text=True)
        if result.strip():
            print(result)
        else:
            print("    No subdomains found (try brute force with a wordlist).")
    except Exception as e:
        print(f"[-] Subdomain check failed: {e}")

if __name__ == "__main__":
    domain = input("Enter domain (example.com): ").strip()
    print("\n===== Website Information Gatherer =====\n")
    get_ip(domain)
    get_headers(domain)
    get_whois(domain)
    get_subdomains(domain)
