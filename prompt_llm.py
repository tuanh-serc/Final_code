import os
import json
import re
from langchain_community.vectorstores import Chroma
from langchain_community.embeddings import OllamaEmbeddings
from langchain_core.prompts import PromptTemplate
from langchain_community.llms import Ollama
from checkip import is_private_ip
from prompt_xss import full_prompt_template as xss_template
from prompt_ssh import full_prompt_template as ssh_template  


# ===== Khởi tạo các PromptTemplate =====
prompt_xss = PromptTemplate(
    input_variables=["vt_context", "abuse_context", "mitre_context", "alert_context"],
    template=xss_template
)

prompt_ssh = PromptTemplate(
     input_variables=["vt_context", "abuse_context", "mitre_context", "alert_context"],
     template=ssh_template
 )

def extract_ips_from_text(text):
    return list(set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)))


def choose_prompt(norm_alert: dict):
    desc = norm_alert.get("description", "").lower()
    log = norm_alert.get("full_log", "").lower()

    if "xss" in desc or "<script" in log or "alert(" in log:
        return prompt_xss
    elif "ssh" in desc or "invalid user" in log:
         return prompt_ssh
    else:
        return prompt_xss

def run_llm(prompt, vt_context, abuse_context, mitre_context="No MITRE data.", alert_context=""):
    llm = Ollama(model="llama3")
    full_prompt = prompt.format(
        vt_context=vt_context,
        abuse_context=abuse_context,
        mitre_context=mitre_context,
        alert_context=alert_context
    )
    return llm.invoke(full_prompt)

def format_alert_context_ssh(alert: dict) -> str:
    src_ip = alert.get("srcip", "")
    ip_type = "Private" if is_private_ip(src_ip) else "Public"
    previous_output = alert.get("previous_output", "")
    additional_ips = extract_ips_from_text(previous_output)
    unique_ips = set([src_ip] + additional_ips)

    fields = {
        "Agent": f"{alert.get('agent_name')} ({alert.get('agent_ip')})",
        "Timestamp": alert.get("timestamp"),
        "Frequency": alert.get("frequency", "N/A"),
        "Rule Description": alert.get("description"),
        "Rule Level": alert.get("level"),
        "Source IP": f"{src_ip} ({ip_type})",
        "Other IPs seen in log": ", ".join(ip for ip in unique_ips if ip != src_ip) or "None",
        "Previous Output": previous_output if previous_output else "N/A",
        "Destination User": alert.get("destination_user", "N/A"),
        "Full Log": alert.get("full_log"),
        "MITRE ID": ", ".join(alert.get("mitre_id", [])),
        "MITRE Technique": ", ".join(alert.get("mitre_technique", [])),
        "MITRE Tactic": ", ".join(alert.get("mitre_tactic", [])),
    }
    return "\n".join(f"- {k}: {v}" for k, v in fields.items() if v)


def format_alert_context_xss(alert: dict) -> str:
    src_ip = alert.get("srcip", "")
    ip_type = "Private" if is_private_ip(src_ip) else "Public"

    fields = {
        "Agent": f"{alert.get('agent_name')} ({alert.get('agent_ip')})",
        "Timestamp": alert.get("timestamp"),
        "URL": alert.get("url", "N/A"),
        "Protocol": alert.get("protocol", "N/A"),
        "Rule Description": alert.get("description"),
        "Rule Level": alert.get("level"),
        "Status Code": alert.get("status_code", "Unknown"),
        "Frequency": alert.get("frequency", "N/A"),
        "Source IP": f"{src_ip} ({ip_type})",
        "Full Log": alert.get("full_log"),
        "MITRE ID": ", ".join(alert.get("mitre_id", [])),
        "MITRE Technique": ", ".join(alert.get("mitre_technique", [])),
        "MITRE Tactic": ", ".join(alert.get("mitre_tactic", []))
    }
    return "\n".join(f"- {k}: {v}" for k, v in fields.items() if v)

def load_context(ip_main, vt_vectorstore, abuse_vectorstore, mitre_vectorstore=None, mitre_ids=None, whitelist_vectorstore=None, all_ips=None):
    if all_ips is None:
        all_ips = [ip_main]

    vt_contexts = []
    abuse_contexts = []
    whitelist_contexts = []

    # Truy vấn VT, AbuseIPDB, Whitelist cho từng IP
    for ip in all_ips:
        query = f"IP {ip} có nằm trong whitelist không?"

        vt_docs = vt_vectorstore.similarity_search(query, k=1, filter={"ip": ip})
        abuse_docs = abuse_vectorstore.similarity_search(query, k=1, filter={"ip": ip})
        whitelist_docs = []
        if whitelist_vectorstore:
            whitelist_docs = whitelist_vectorstore.similarity_search(query, k=1, filter={"ip": ip})

        if vt_docs:
            vt_contexts.append(f"[VT for {ip}]\n" + vt_docs[0].page_content.strip())

        if abuse_docs:
            abuse_contexts.append(f"[AbuseIPDB for {ip}]\n" + abuse_docs[0].page_content.strip())

        if whitelist_docs:
            whitelist_contexts.append(f"[Whitelist for {ip}]\n" + whitelist_docs[0].page_content.strip())

    # MITRE
    mitre_docs = []
    if mitre_vectorstore and mitre_ids:
        for mitre_id in mitre_ids:
            docs = mitre_vectorstore.similarity_search(mitre_id, k=1, filter={"id": mitre_id})
            mitre_docs.extend(docs)

    vt_context = "\n\n".join(vt_contexts) if vt_contexts else "No VirusTotal data."
    abuse_context = "\n\n".join(abuse_contexts) if abuse_contexts else "No AbuseIPDB data."
    mitre_context = "\n\n".join([doc.page_content for doc in mitre_docs]) if mitre_docs else "No MITRE data."

    # Gộp whitelist vào vt_context để LLM phân tích dễ hơn
    if whitelist_contexts:
        vt_context += "\n\n" + "\n\n".join(whitelist_contexts)

    return vt_context, abuse_context, mitre_context
