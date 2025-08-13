import os
import time
import json
from datetime import datetime

def normalize_alert(alert: dict) -> dict:
    src = alert.get('_source', alert)  # ✅ sửa ở đây
    rule = src.get('rule', {})
    data = src.get('data', {})
    agent = src.get('agent', {})



#Biến norm chứa các trường cần thiết để lưu trữ vào vectorstore
    norm = {
        "description": rule.get("description"), # lấy trường description của trường rule (vd: possible sshd bruteforce )
        "groups": rule.get("groups", []), # lấy trường group trong rule (vd: web, web attack)
        "mitre_id": rule.get("mitre", {}).get("id", []), # lấy trường id mitre trong rule
        "mitre_technique": rule.get("mitre", {}).get("technique", []), # lấy trường technique của mitre trong rule
        "mitre_tactic": rule.get("mitre", {}).get("tactic", []),
        "level": rule.get("level"), # lấy trường level của rule
        "url": data.get("url"), # lấy trường url 
        "protocol": data.get("protocol"), # lấy trường protocol
        "srcip": data.get("srcip"), # lấy trường source ip
        "destination_user": data.get("dstuser"), # lấy trường destination user
        "status_code": data.get("status_code"), # lấy trường status code
        "frequency": rule.get("frequency"), # lấy trường frequency, nếu không có thì để mặc định là 1
        "full_log": src.get("full_log"), # lấy trường full log
        "previous_output": src.get("previous_output"), # lấy trường previous output
        "agent_name": agent.get("name"), # lấy trường name của agent
        "agent_ip": agent.get("ip"), # lấy trường ip của agent
        "timestamp": src.get("timestamp") # lấy trường timestamp
    }

    # Chuyển timestamp về datetime ISO nếu cần
    try:
        if norm["timestamp"]: # nếu có timestamp chuyển sang định dạng ISO
            norm["timestamp"] = datetime.fromisoformat( # python k hỗ trợ giờ theo dang zulu
                norm["timestamp"].replace("Z", "+00:00") # thay thế timestamp dạng UTC(Z) thành +00:00
            ).isoformat()
    except Exception:
        pass

    return norm


def follow_alerts(input_path: str = "/var/ossec/logs/alerts/alerts.json"):
    with open(input_path, 'r', encoding='utf-8') as f_in:
        f_in.seek(0, os.SEEK_END)
        buffer = ""
        line_count = 0
        max_lines = 20

        while True:
            line = f_in.readline()
            if not line:
                time.sleep(0.1)
                continue

            buffer += line
            line_count += 1

            try:
                alert = json.loads(buffer.strip())
                buffer = ""
                line_count = 0
            except json.JSONDecodeError:
                if line_count >= max_lines:
                    print("Bỏ alert bị lỗi hoặc quá dài:\n", buffer.strip())
                    buffer = ""
                    line_count = 0
                continue

            src = alert.get("_source", alert)
            rule = src.get("rule", {})
           # if rule.get("level", 0) <= 6:
            #    buffer = ""
            #    line_count = 0
            #    continue

            norm = normalize_alert(alert)
            yield norm, alert
