# =====================  STRICT XSS PROMPT (English) =====================

section_1_document_and_mitre = """
DOCUMENT:
Below is technical threat intelligence data gathered from sources such as VirusTotal, AbuseIPDB, etc.

VirusTotal Context:
{vt_context}

AbuseIPDB Context:
{abuse_context}

Wazuh Alert : The raw log 
{alert_context}

MITRE CONTEXT:
Additional threat behavior mappings from the MITRE ATT&CK framework (if any).

{mitre_context}
""".strip()

section_2_question_1 = """
SECTION 1 – Identify Attack Type from Logs

Objective:
- Determine whether this is a **real** XSS attack based on the **presence of a malicious payload**.  
- Simply accessing a vulnerable endpoint (e.g., /DVWA/vulnerabilities) without payload does **NOT** qualify as XSS.

Valid XSS payload indicators (must contain at least one of these patterns in URL/parameters/headers/body):
  <script>, </script>, alert(, onerror=, onload=, onmouseover=, javascript:, data:text/html, "><, '+alert(, document.cookie, window.location, eval( ), decodeURIComponent( ), String.fromCharCode(

Requirements:
- Extract and quote at least one **actual log line or payload** as Evidence (no vague descriptions).
- If **no valid payload** is found:
  - Set Identified attack type: Uncertain
  - Indicate in Explanation that **no XSS payload** was present.

Required format:
Status code: [integer or "Unknown"]
Identified attack type: [XSS / Uncertain]   # Only choose XSS when valid payload is present
Scan behavior detected: [Yes / No / Uncertain]
Evidence: "[log snippet or payload]"
Explanation: [brief technical reasoning]
""".strip()

section_7_question_2 = """
SECTION 2 – MITRE Technique Analysis

Rules:
- Only map to a MITRE technique if there is a **valid XSS payload** (e.g., T1190 for exploiting a public-facing application or T1059.007 – JavaScript).
- If there is no payload, answer "None" and explain why.

Required format:
Technique name (if applicable): [Txxxx – Technique Name or "None"]
Matching description: "[quoted MITRE description or 'None']"
Explanation: [why it matches or doesn't match]
""".strip()

section_3_question_2 = """
SECTION 3 – Evaluate IP Maliciousness

Questions:
- Is the IP considered malicious?
- What is the threat level of this IP?
- Which AV engines flagged the IP as malicious?
- What is the Abuse Confidence Score and classification?
- Number of distinct user reports and recent activity?
- Is there TOR usage or association with known malicious domains?

Required format:
Number of AV engines (malicious): [integer]  
Reputation score: [integer]  
Abuse Confidence Score: [%]  
Reported [integer] times by [integer] distinct users 
Country / ISP: [country, ISP]  
Associated domain(s): [domain or "None"]  
IP summary: [Malicious IP / Clean IP / Uncertain]  
Threat level: [High / Medium / Low]  
Explanation: [brief justification]
""".strip()

section_4_question_3 = """
SECTION 4 – Overall Alert Evaluation

MANDATORY CLASSIFICATION RULE:
- If **no valid XSS payload** is present in the Evidence (SECTION 1) ⇒ **cannot** conclude TP. Must classify as **FP** (if clearly benign) or **Escalate** (if suspicious but inconclusive).
- Only conclude TP if a valid payload exists **and** MITRE mapping is relevant.
- Merely accessing a vulnerable endpoint or returning HTTP 200 is **not sufficient** for TP.

Required format:
Alert conclusion: [TP / FP / Escalate]
Explanation: [brief reasoning following the above rule, referencing Evidence/Payload]
IP classification: [Private / Public]
If private: Signs of compromise? [Yes / No / Uncertain]
Key supporting evidence: "[payload or specific log line]"
Explanation: [brief]
""".strip()

section_5_question_4 = """
SECTION 5 – Recommended Action

Guidelines:
- If **no payload**, prefer "Monitor" or "No action" and recommend **rule tuning** to reduce false positives.
- If payload is present, recommend "Create rule" or "Escalate" depending on severity and context.

Required format:
Action: [Block IP / Create rule / Monitor / Escalate / No action]
Priority level: [High / Medium / Low]
Justification: [1–2 sentences, directly linked to the Evidence]
""".strip()

section_6_instructions = """
INSTRUCTIONS:
- Use only the provided context; do not speculate.
- **You must** cite a valid XSS payload if concluding XSS. If no payload, **you must not** conclude TP.
- Evidence must be an exact excerpt from logs/payloads (no vague paraphrasing).
- Answer **all 5 sections** in the exact required format; do not add extra keys.
- Be concise, technical, and follow the exact structure.
""".strip()

#====== Combine into full prompt ======
full_prompt_template = (
   section_1_document_and_mitre + "\n\nQUESTION:\n" +
   section_6_instructions + "\n\n" +
   section_2_question_1 + "\n\n" +
   section_7_question_2 + "\n\n" +
   section_3_question_2 + "\n\n" +
   section_4_question_3 + "\n\n" +
   section_5_question_4 + "\n\n"
)
