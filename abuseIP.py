import os
import json
import requests
from langchain.schema import Document
from langchain_community.vectorstores import Chroma
from langchain_community.embeddings import OllamaEmbeddings

# ===== Configuration =====
API_KEY = 'c7ead50ad1d48031f835f4a890dcd9581fae97acafdb1ae2ec1492a4d6e8a0ed43c376ac8773b51f'
ABUSE_CATEGORIES = {
    1: "DNS Compromise", 2: "DNS Poisoning", 3: "Fraud Orders", 4: "DDoS Attack",
    5: "FTP Brute-Force", 6: "Ping of Death", 7: "Phishing", 8: "Fraud VoIP",
    9: "Open Proxy", 10: "Web Spam", 11: "Email Spam", 12: "Blog Spam",
    13: "VPN IP", 14: "Port Scan", 15: "Hacking", 16: "SQL Injection",
    17: "Spoofing", 18: "Brute Force", 19: "Bad Web Bot", 20: "Exploited Host",
    21: "Web App Attack", 22: "SSH", 23: "IoT Targeted"
}

def map_categories(category_ids):
    return [ABUSE_CATEGORIES.get(cid, f"Unknown ({cid})") for cid in category_ids]

# ===== Process alert IP from Wazuh and call AbuseIPDB API =====
def process_abuseip_alert_file(ip: str):
    # Create report and vectorstore directories
    embedding = OllamaEmbeddings(model="llama3")
    vectorstore_dir = "chroma_abuse_vectors"
    os.makedirs("abuseip_reports", exist_ok=True)
    os.makedirs(vectorstore_dir, exist_ok=True)
    vectorstore = Chroma(persist_directory=vectorstore_dir, embedding_function=embedding)

    url = 'https://api.abuseipdb.com/api/v2/check'
    querystring = {'ipAddress': ip, 'maxAgeInDays': '90', 'verbose': 'true'}
    headers = {'Accept': 'application/json', 'Key': API_KEY}
    response = requests.get(url, headers=headers, params=querystring)

    if response.status_code != 200:
        print(f"[!] Error calling AbuseIPDB API for IP {ip}: {response.status_code}")
        return

    d = response.json().get("data", {})

    score = d.get("abuseConfidenceScore", 0)
    if score >= 75:
        status = "Malicious"
        conclusion = "DANGEROUS IOC (multiple abuse reports)"
    elif score >= 25:
        status = "Suspicious"
        conclusion = "SUSPICIOUS IOC (needs monitoring)"
    elif score ==0:
        status = "Clean"
        conclusion = "Clean IOC (no abuse reports)"
    else:
        status = "Unknown / Low risk"
        conclusion = "CONTINUE MONITORING"

    ip_version = f"IPv{d.get('ipVersion', '?')}"
    ip_public = d.get("isPublic", "N/A")
    isp = d.get('isp', 'Unknown ISP')
    usage = d.get('usageType', 'Unknown Usage')
    country = f"{d.get('countryName', 'Unknown')} ({d.get('countryCode', 'N/A')})"
    total = d.get('totalReports', 0)
    users = d.get('numDistinctUsers', 0)
    last = d.get('lastReportedAt', 'N/A')
    domain = d.get('domain', 'N/A')
    hostnames = ", ".join(d.get('hostnames', [])) or "None"
    tor = "Yes" if d.get('isTor') else "No"

    # ===== Create report content =====
    content = f"[IP] {ip}\n"
    content += f"- IP Version: {ip_version} | Public: {ip_public}\n"
    content += f"- ISP: {isp} ({usage})\n"
    content += f"- Geo Location: {country}\n"
    content += f"- Reported {total} times by {users} distinct users\n"
    content += f"- Abuse Confidence Score: {score}% → Classification: {status}\n"
    content += f"- Last reported at: {last}\n"
    content += f"- Related Domain: {domain}\n"
    content += f"- Hostnames: {hostnames}\n"
    content += f"- TOR usage: {tor}\n"


    content += f"\n=>  Conclusion: {conclusion}\n"

    # ===== Save report and embed to vectorstore =====
    report_path = f"abuseip_reports/{ip}_abuse.txt"
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(content)
    print(f"[✔] AbuseIPDB report saved at: {report_path}")

    doc = Document(page_content=content, metadata={"ip": ip})
    vectorstore.add_documents([doc])
    vectorstore.persist()
    print(f"[✔] Embedded and stored vector for IP {ip} in {vectorstore_dir}")
