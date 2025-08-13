import os
import json
import queue
import threading
import hashlib
from datetime import datetime
import time

from VT import process_ip_alert_file
from abuseIP import process_abuseip_alert_file
from mitre import format_mitre_chunks
from regex_ioc import follow_alerts
from prompt_llm import ( 
    choose_prompt, extract_ips_from_text, prompt_ssh, run_llm, load_context, format_alert_context_ssh, format_alert_context_xss
)
from push_to_opensearch import push_alert_to_opensearch

from langchain_chroma import Chroma
from langchain_community.embeddings import OllamaEmbeddings

def get_vectorstores():
    embedding = OllamaEmbeddings(model="llama3")
    return {
        "embedding": embedding,
        "vt": Chroma(persist_directory="chroma_vt_vectors", embedding_function=embedding),
        "abuse": Chroma(persist_directory="chroma_abuse_vectors", embedding_function=embedding),
        "mitre": Chroma(persist_directory="chroma_mitre_vectors", embedding_function=embedding),
        "whitelist": Chroma(persist_directory="chroma_whitelist_vectors", embedding_function=embedding)   
    }

def ensure_ip_in_vectorstore(ip, vectorstore, process_fn, name=""):
    docs = vectorstore._collection.get(where={"ip": ip})
    if docs["documents"]:
        print(f"[Skip] IP {ip} already exists in {name} vectorstore.")
    else:
        process_fn(ip)

def ensure_mitre_vectors(mitre_ids, mitre_vectorstore, mitre_json_file):
    missing_ids = []
    for mitre_id in mitre_ids:
        results = mitre_vectorstore.similarity_search("dummy", k=1, filter={"id": mitre_id})
        if not results:
            missing_ids.append(mitre_id)

    if missing_ids:
        print(f"{len(missing_ids)} new MITRE techniques detected. Embedding...")
        format_mitre_chunks(mitre_json_file, missing_ids)
    else:
        print("All required MITRE techniques already embedded.")

def hash_alert(alert: dict) -> str:
    alert_json = json.dumps(alert, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(alert_json.encode("utf-8")).hexdigest()

def alert_producer(alert_queue):
    for norm_alert, raw_alert in follow_alerts():
        alert_queue.put((norm_alert, raw_alert))

def alert_consumer(alert_queue, vectorstores, mitre_json_file):
    seen_hashes = set()

    while True:
        norm_alert, raw_alert = alert_queue.get()
        ip_target = norm_alert.get("srcip")
        if not ip_target:
            continue

        alert_hash = hash_alert(norm_alert)
        if alert_hash in seen_hashes:
            continue
        seen_hashes.add(alert_hash)

        start_time = time.time()

        vt_vectorstore = vectorstores["vt"]
        abuse_vectorstore = vectorstores["abuse"]
        mitre_vectorstore = vectorstores["mitre"]
        whitelist_vectorstore = vectorstores["whitelist"]

        previous_output = norm_alert.get("previous_output", "")
        additional_ips = extract_ips_from_text(previous_output)
        all_ips = set([ip_target] + additional_ips)
        print(f"\n Processing alert for IPs: {', '.join(sorted(all_ips))}")

        for ip in all_ips:
            ensure_ip_in_vectorstore(ip, vt_vectorstore, process_ip_alert_file, "VT")
            ensure_ip_in_vectorstore(ip, abuse_vectorstore, process_abuseip_alert_file, "AbuseIPDB")

        mitre_ids = norm_alert.get("mitre_id", [])
        ensure_mitre_vectors(mitre_ids, mitre_vectorstore, mitre_json_file)

        vt_context,abuse_context, mitre_context = load_context(
            ip_target, vt_vectorstore, abuse_vectorstore, mitre_vectorstore, mitre_ids,
            whitelist_vectorstore=whitelist_vectorstore, all_ips=list(all_ips)
        )
        prompt_obj = choose_prompt(norm_alert)

        if prompt_obj == prompt_ssh:
            alert_context = format_alert_context_ssh(norm_alert)
        else:
            alert_context = format_alert_context_xss(norm_alert)
        chosen_prompt = choose_prompt(norm_alert)

        print(" Running LLM analysis...")
        chosen_prompt = choose_prompt(norm_alert)

        result = run_llm(
            prompt=chosen_prompt,
            vt_context=vt_context,
            abuse_context=abuse_context,
            mitre_context=mitre_context,
            alert_context=alert_context
        )


        raw_alert["llm_result"] = result
        push_alert_to_opensearch(raw_alert)

        end_time = time.time()
        print(f" Alert processed in {end_time - start_time:.2f} seconds.")

def main():
    mitre_json_file = "enterprise-attack.json"
    vectorstores = get_vectorstores()

    alert_queue = queue.Queue()
    threading.Thread(target=alert_producer, args=(alert_queue,), daemon=True).start()
    alert_consumer(alert_queue, vectorstores, mitre_json_file)

if __name__ == "__main__":
    main()
