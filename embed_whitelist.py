import os
from langchain_core.documents import Document
from langchain_community.vectorstores import Chroma
from langchain_community.embeddings import OllamaEmbeddings

# ===== Danh sách IP whitelist (bạn có thể đọc từ file thay vì hardcode) =====
whitelist_ips = [
    "192.168.80.1"
]

# ===== Mô tả kèm theo để LLM hiểu =====
def create_doc(ip):
    content = f"[WHITELIST] IP {ip} is a trusted IP address authorized in the environment.\n"
    content += "This IP is not associated with any known malicious behavior and is part of the approved infrastructure.\n"
    content += "=> If this IP appears in an alert and no other evidence of attack is found, it's likely a FALSE POSITIVE.\n"
    return Document(page_content=content, metadata={"ip": ip})

# ===== Thư mục lưu vectorstore cho whitelist =====
vectorstore_dir = "chroma_whitelist_vectors"
os.makedirs(vectorstore_dir, exist_ok=True)

# ===== Embedding và lưu =====
embedding = OllamaEmbeddings(model="llama2")
vectorstore = Chroma(persist_directory=vectorstore_dir, embedding_function=embedding)

docs = [create_doc(ip) for ip in whitelist_ips]
vectorstore.add_documents(docs)
vectorstore.persist()

print(f"[✔] Đã embed và lưu {len(docs)} IP whitelist vào vectorstore: {vectorstore_dir}")
