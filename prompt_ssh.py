section_1_document_and_mitre = """
DOCUMENT:
Below is technical threat intelligence data gathered from sources such as VirusTotal, AbuseIPDB, etc.

VirusTotal Context:
{vt_context}

AbuseIPDB Context:
{abuse_context}

Wazuh Alert (raw log):
{alert_context}

MITRE CONTEXT:
Additional threat behavior mappings from the MITRE ATT&CK framework (if any).

{mitre_context}
""".strip()

section_2_question_1 = """
SECTION 1 – Identify Attack Type from Logs

Questions:
- Based on the log and context, what category of attack does this behavior fall into?
- What specific evidence indicates that this is a real brute-force attack rather than a false positive?
- How many failed login attempts are observed?
- Are the attempts from a single source IP or multiple?
- Extract and list all source IP addresses seen in the logs. #add this line
- Are there signs of automation or aggressive scanning?

Instructions:
- Use the required format only.
- Do not speculate beyond the provided data.
- Extract actual evidence from logs or context.

Required:
- Answer: Yes / No / Uncertain
- Source IP: [IP or "Unknown"]
- Unique IPs observed: [comma-separated IPs] # this line
- Number of unique IPs: [integer] # this line
- Multiple targets: [Yes / No / Uncertain]
- Identified attack type: [Brute-force / Other / Uncertain]
- Evidence: "[log line or extract]"
- Explanation: [reason]
""".strip()

section_3_question_2 = """
SECTION 2 – MITRE Technique Analysis

Questions:
- Does any MITRE technique match the observed brute-force behavior?
- Quote the MITRE description and explain the match.

Required format:
Technique name (if applicable): [T1110 – Brute Force]
Matching description: "[quoted MITRE description]"
Explanation: [reason why this MITRE applies]
""".strip()

section_4_question_3 = """
SECTION 3 – Evaluate IP Maliciousness

Questions:
- How many source IPs are involved in this alert?
- For each unique IP seen in the log, evaluate whether it is malicious or clean.
- Use evidence from VirusTotal, AbuseIPDB, and whitelist if available.
- If there is only one IP, you only need to evaluate it once.

Instructions:
- If only one IP is involved, provide a single analysis.
- If multiple IPs are observed, repeat the format for each IP.
- Use actual context data provided (do not speculate).

Required format:
Number of source Ips in this alert: [integer]
If only one IP, use this block one time.
Else if multiple IPs, repeat the above block for each IP.
IP Address: [IP address]  
Whitelisted: [Yes / No]  
Number of AV engines (malicious): [integer]  
Reputation score: [integer]  
Abuse Confidence Score: [%]  
Reported [integer] times by [integer] distinct users  
Country / ISP: [country, ISP]  
Associated domain(s): [domain or "None"]  
IP summary: [Malicious IP / Clean IP / Whitelisted / Uncertain]  
Threat level: [High / Medium / Low]  
Explanation: [reason]

""".strip()

section_5_question_4 = """
SECTION 4 – Overall Alert Evaluation

Questions:
- Is this alert a True Positive, False Positive, or Escalate?
- If the IP is private, could it be a misconfigured script or internal scan?

Required format:
Alert conclusion: [TP / FP / Escalate]
Explanation: [why this is (not) an actual brute-force]
IP classification: [Private / Public]
If private: Signs of compromise? [Yes / No / Uncertain]
Key supporting evidence: "[log or context]"
""".strip()

section_6_question_5 = """
SECTION 5 – Recommended Action

Questions:
- Should the IP be blocked or monitored?
- Should additional detection rules be tuned?

Required format:
Action: [Block IP / Create rule / Monitor / Escalate / No action]
Priority level: [High / Medium / Low]
Justification: [1–2 sentences]
""".strip()

section_6_instructions = """
INSTRUCTIONS:
- Analyze each section precisely.
- Only use provided context.
- Do not speculate.
- Answer **ALL 5 sections** using the required format.
- Stick strictly to the example structure.
""".strip()

full_prompt_template = (
   section_1_document_and_mitre + "\n\nQUESTION:\n" +
   section_6_instructions + "\n\n" +
   section_2_question_1 + "\n\n" +
   section_3_question_2 + "\n\n" +
   section_4_question_3 + "\n\n" +
   section_5_question_4 + "\n\n" +
   section_6_question_5 + "\n"
)



