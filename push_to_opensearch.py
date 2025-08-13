from opensearchpy import OpenSearch
from datetime import datetime

# ===== Kết nối OpenSearch =====
client = OpenSearch(
    hosts=[{"host": "localhost", "port": 9200}],
    http_auth=("admin", "Tuanhung2003."),
    use_ssl=True,
    verify_certs=False,
    ssl_show_warn=False
)

# ===== Hàm gửi alert lên OpenSearch =====
def push_alert_to_opensearch(alert: dict):
    """
    Gửi alert gốc (raw alert) đã thêm trường `llm_result` lên OpenSearch.
    Để tránh lỗi metadata (_index, _id, _version...), alert sẽ được bọc trong "original_alert"
    """
    # Gói alert gốc vào trường "original_alert"
    safe_alert = {
        "original_alert": alert,
        "@timestamp": alert.get("@timestamp", datetime.utcnow().isoformat() + "Z")
    }

    # Tên index theo ngày
    index_name = "wazuh-llm-alerts-" + datetime.utcnow().strftime("%Y.%m.%d")

    try:
        response = client.index(index=index_name, body=safe_alert)
        print(f"[✔] Push alert to OpenSearch sucessfully with ID: {response['_id']}")
    except Exception as e:
        print(f"[!] Lỗi khi gửi alert lên OpenSearch: {e}")

