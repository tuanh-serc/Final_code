import os
import json
from typing import List
from langchain.schema import Document
from langchain_community.vectorstores import Chroma
from langchain_community.embeddings import OllamaEmbeddings

def load_mitre_ids(file_path: str) -> List[str]:
    if not os.path.exists(file_path):
        print(f"Không tìm thấy file danh sách ID: {file_path}")
        return []
    with open(file_path, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip()]

def format_mitre_chunks(path: str, ids_to_include: List[str]):
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    embedding = OllamaEmbeddings(model="llama3")
    vectorstore_dir = "chroma_mitre_vectors"
    os.makedirs("mitre_reports", exist_ok=True)
    os.makedirs(vectorstore_dir, exist_ok=True)

    for obj in data.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue

        ext_id = next((r.get("external_id") for r in obj.get("external_references", []) if "external_id" in r), "No-ID")
        if ext_id not in ids_to_include:
            continue

        name = obj.get("name", "Unknown")
        desc = obj.get("description", "").strip().replace("\n", " ")
        tactics = [p.get("phase_name") for p in obj.get("kill_chain_phases", [])]
        tactic_str = ", ".join(tactics) if tactics else "Không rõ"
        ext_url = next((r.get("url") for r in obj.get("external_references", []) if "url" in r), "")

        summary = f"[MITRE] {ext_id} - {name}\n"
        summary += f"- tactics: {tactic_str}\n"
        summary += f"- description: {desc}...\n"
        summary += f"- ext_url: {ext_url}\n"

        metadata = {
            "id": ext_id,
            "name": name,
            "tactic": tactic_str,
            "url": ext_url
        }

        doc = Document(page_content=summary, metadata=metadata)

        report_path = f"mitre_reports/{ext_id}.txt"
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(summary)
            f.write("\n\n--- Metadata ---\n")
            for key, value in metadata.items():
                f.write(f"{key}: {value}\n")

        print(f"[✔] Đã lưu báo cáo: {report_path}")

        vectorstore = Chroma.from_documents([doc], embedding=embedding, persist_directory=vectorstore_dir)
        vectorstore.persist()
        print(f"[✔] Đã embed và lưu vector cho {ext_id} vào {vectorstore_dir}")
