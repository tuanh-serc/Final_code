import os
import json
import requests
from langchain_core.documents import Document
from langchain_community.vectorstores import Chroma
from langchain_community.embeddings import OllamaEmbeddings

API_KEY = "2ada968c0f5961dbf983667392d09726f6e6695417c2e95f0640f83f57bf2c0e".strip()
HEADERS = {"x-apikey": API_KEY}
BASE_URL = "https://www.virustotal.com/api/v3"

def get_vt_ip_data(ip_value):
    url = f"{BASE_URL}/ip_addresses/{ip_value}"
    res = requests.get(url, headers=HEADERS)
    if res.status_code != 200:
        print(f"[!] Error fetching data for IP {ip_value}: {res.status_code}")
        return None

    data = res.json()
    result = {
        "ioc_type": "ip",
        "ioc_value": ip_value,
        "attributes": data.get("data", {}).get("attributes", {}),
        "crowdsourced_info": {},
        "relationships": {}
    }

    for key in result["attributes"]:
        if key.startswith("crowdsourced"):
            result["crowdsourced_info"][key] = result["attributes"][key]

    rel_types = ["communicating_files", "contacted_domains", "contacted_urls", "contacted_ips"]
    for rel in rel_types:
        rel_url = f"{url}/{rel}"
        rel_resp = requests.get(rel_url, headers=HEADERS)
        if rel_resp.status_code == 200:
            rel_data = rel_resp.json()
            result["relationships"][rel] = rel_data.get("data", [])[:15]

    return result

def evaluate_ip_ioc(vt_result):
    ioc_value = vt_result["ioc_value"]
    attrs = vt_result.get("attributes", {})
    rels = vt_result.get("relationships", {})
    votes = attrs.get("total_votes", {})
    analysis_stats = attrs.get("last_analysis_stats", {})
    last_results = attrs.get("last_analysis_results", {})
    reputation = attrs.get("reputation", 0)
    malicious_av = analysis_stats.get("malicious", 0)
    country = attrs.get("country", "Unknown")
    asn_owner = attrs.get("as_owner", "Unknown")

    summary = f"[IP] {ioc_value}\n"
    summary += f"- Detected by: {malicious_av} AV engines\n"
    summary += f"- Reputation score: {reputation}\n"
    summary += f"- Location: {country}, Network owner: {asn_owner}\n"

    if last_results:
        flagged_engines = [
            f"{engine}: {res['category']}"
            for engine, res in last_results.items()
            if res.get("category") == "malicious"
        ]
        if flagged_engines:
            summary += "- AV engines flagged as malicious:\n  - " + "\n  - ".join(flagged_engines[:10]) + "\n"

    relation_display_names = {
        "communicating_files": "Communicating Files",
        "contacted_domains": "Contacted Domains",
        "contacted_urls": "Contacted URLs",
        "contacted_ips": "Contacted IPs"
    }

    for rel_type, display_name in relation_display_names.items():
        rel_list = rels.get(rel_type, [])
        if rel_list:
            summary += f"{display_name} ({len(rel_list)}):\n"
            for item in rel_list[:5]:
                domain_id = item.get("id", "unknown")
                summary += f"  - {domain_id}\n"

    if malicious_av >= 3:
        conclusion = "DANGEROUS IOC (Malicious IP)"
    elif malicious_av > 0:
        conclusion = "SUSPICIOUS IOC (Requires monitoring)"
    else:
        conclusion = "CLEAN IOC"

    summary += f"\n=> Final Assessment: {conclusion}\n"
    return summary

def process_ip_alert_file(ip: str):
    embedding = OllamaEmbeddings(model="llama3")
    vectorstore_dir = "chroma_vt_vectors"
    os.makedirs("output", exist_ok=True)
    os.makedirs(vectorstore_dir, exist_ok=True)
    vectorstore = Chroma(persist_directory=vectorstore_dir, embedding_function=embedding)

    ip_data = get_vt_ip_data(ip)
    if not ip_data:
        print(f"[!] No VirusTotal data found for IP: {ip}")
        return

    evaluation = evaluate_ip_ioc(ip_data)
    report_path = f"output/{ip}_vt.txt"
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(evaluation)
    print(f"[✔] VT report saved: {report_path}")

    doc = Document(page_content=evaluation, metadata={"ip": ip})
    vectorstore.add_documents([doc])
    vectorstore.persist()
    print(f"[✔] Embedded and stored vector for IP: {ip}")
