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
Questions:
- Based on the log and context, what category of attack does this behavior fall into?
- What specific evidence indicates that this is a real attack rather than a false positive?
- Are there any signs of XSS payloads? (e.g., contains <script>, alert(), javascript:...)
- Are there signs of scanning activity?
- Status code: ?
Instructions:
- You must answer using only the required keys below.
- Do not speculate beyond the log provided.
- You must extract actual evidence from the input (e.g., log line or payload).
- All answers must follow the required field name exactly.
- For all Yes/No/Uncertain answers, write only one of them without explanation inline.
- Do not add extra commentary.
- You must explain the technical details used in the explanation line.

Required:
- Answer: Yes / No / Uncertain
- Provide at least one log line or payload as evidence.
- Briefly explain your reasoning.


Required format:
Status code: [integer or "Unknown"]
Identified attack type: [XSS / Brute-force / Uncertain]
Scan behavior detected: [Yes / No / Uncertain]
Evidence: "[log snippet or payload]"
Explanation: [reason]
""".strip()
section_7_question_2 = """
SECTION 2 – MITRE Technique Analysis
Questions:
- Does any MITRE technique match the observed behavior?
- Which specific MITRE description aligns with the behavior?
Required:
- If a match is found, quote the MITRE description and explain the match.
- If no match, explain why.
- Re-evaluate the payload to see if it truly matches the MITRE technique in the alert. If it does, explain why; if it doesn't, explain why.

Required format:
Technique name (if applicable): [Txxxx – Technique Name]
Matching description: "[quoted MITRE description]"
Explanation: [reason]
"""    
section_3_question_2 = """

SECTION 3 – Evaluate IP Maliciousness
Questions:
- Is the IP considered a malicious IP?
- What is the threat level of this IP?
- Which AV engines flagged the IP as malicious?
- What is the Abuse Confidence Score and classification?
- Number of distinct user reports and recent activity?
- Is there TOR usage or involvement with known malicious domains?

Required format:
Number of AV engines (malicious): [integer]  
Reputation score: [integer]  
Abuse Confidence Score: [%]  
Reported [integer] times by [integer] distinct users 
Country / ISP: [country, ISP]  
Associated domain(s): [domain or "None"]  
IP summary: [Malicious IP / Clean IP / Uncertain]  
Threat level: [High / Medium / Low]  
Explanation: [brief justification, e.g., “Flagged by 9 AVs and 100% abuse score.”]

""".strip()

section_4_question_3 = """
SECTION 4 – Overall Alert Evaluation


Step 4 – Conclude the overall classification of this alert:


Questions:
- Is this alert a True Positive, False Positive, or requires escalation? 
- Is the IP internal (private)? If yes, could it be compromised?

Instructions:
- Based on the complete technical and contextual data provided, along with your prior observations, determine whether this is a true positive or a false positive. Justify your conclusion by referencing the key evidence from earlier sections.
- You must explain the technical details used in the explanation line.

Required format:
Alert conclusion: [TP / FP / Escalate]
Explanation: [brief reason for conclusion]
IP classification: [Private / Public]
If private: Signs of compromise? [Yes / No / Uncertain]
Key supporting evidence: "[payload or context]"
Explanation: [brief]

""".strip()

section_5_question_4 = """
SECTION 5 – Recommended Action


Step 5 – Recommend appropriate response:


Questions:
- Should the IP be blocked?
- Should a rule be created / monitoring enabled / alert escalated?


Required format:
Action: [Block IP / Create rule / Monitor / Escalate / No action]
Priority level: [High / Medium / Low]
Justification: [1–2 sentences]
""".strip()

section_6_instructions = """
INSTRUCTIONS:
- Analyze each question precisely and concisely.
- Only base your answer on the information provided above.
- Do NOT speculate or invent information that is not in the context.
- You must answer **ALL 5 sections** in order, using the required format for each.
- Do not skip any section even if you believe earlier sections already answer the alert.
- Do NOT answer in Q&A format.
- You MUST follow the example output structure exactly.
- Do NOT reuse example values. Extract actual values from context.

""".strip()

#====== Combine to full prompt ======

full_prompt_template = (
   section_1_document_and_mitre + "\n\nQUESTION:\n" +
   
   section_6_instructions + "\n\n" +
   section_2_question_1 + "\n\n" +
   section_7_question_2 + "\n\n" +
   section_3_question_2 + "\n\n" +
   section_4_question_3 + "\n\n" +
   section_5_question_4 + "\n\n"
)
