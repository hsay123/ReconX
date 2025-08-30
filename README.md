# 🔎 ReconX

ReconX is a **Website Information Gathering Tool** written in Python.  
It helps security researchers and network admins collect useful reconnaissance details about a target domain.  

---

## ⚡ Features
- 🌍 Get **IP address** of a domain  
- 📡 Fetch **server response headers**  
- 🔐 Retrieve **Whois information**  
- 🛰️ Perform **basic subdomain lookup** (via `dig`)  

---

## 📦 Dependencies

You need the following installed:

- Python 3.x  
- [Requests](https://pypi.org/project/requests/)  
- [Python-Whois](https://pypi.org/project/python-whois/)  
- `dnsutils` (for the `dig` command)  

---

## 🚀 Installation

Clone the repo and install dependencies:

```bash
# Clone repository
git clone https://github.com/YourUser/ReconX.git
cd ReconX

# Install Python dependencies
pip install requests python-whois

# Install dig (Linux only)
sudo apt install dnsutils -y

 Usage

Run the tool:
python3 reconx.py

When prompted, enter a domain:

Enter domain (example.com): google.com

📌 Example Output
===== Website Information Gatherer =====

[+] IP Address: 142.250.183.14

[+] Server Headers:
    Content-Type: text/html; charset=ISO-8859-1
    Date: Sat, 30 Aug 2025 18:15:00 GMT
    Server: gws

[+] Whois Information:
    registrar: MarkMonitor Inc.
    creation_date: 1997-09-15
    expiry_date: 2028-09-14
    ...

[+] Subdomain lookup with dig:
    No subdomains found (try brute force with a wordlist).

🖥️ Shortcuts

Copy & paste these commands for quick setup:

# Clone repo
git clone https://github.com/YourUser/ReconX.git && cd ReconX

# Install requirements
pip install requests python-whois && sudo apt install dnsutils -y

# Run the tool
python3 reconx.py

⚠️ Disclaimer

This tool is for educational purposes and authorized testing only.
Do not use it on domains you don’t own or have explicit permission to scan.

