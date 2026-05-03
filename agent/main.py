import os
import hashlib
import datetime
from dotenv import load_dotenv
from openai import AzureOpenAI

load_dotenv()

client = AzureOpenAI(
    azure_endpoint=os.getenv("AZURE_OPENAI_ENDPOINT"),
    api_key=os.getenv("AZURE_OPENAI_KEY"),
    api_version="2024-12-01-preview"
)

def read_log_file(filepath):
    with open(filepath, 'r') as f:
        return f.read()

def chunk_logs(log_content, chunk_size=50):
    lines = log_content.strip().split('\n')
    chunks = []
    for i in range(0, len(lines), chunk_size):
        chunks.append('\n'.join(lines[i:i+chunk_size]))
    return chunks

def call_azure_openai(prompt, max_tokens=1000):
    response = client.chat.completions.create(
        model=os.getenv("AZURE_OPENAI_DEPLOYMENT"),
        messages=[{"role": "user", "content": prompt}],
        max_tokens=max_tokens
    )
    return response.choices[0].message.content

def generate_report_id(log_filepath):
    hash_input = (log_filepath + datetime.datetime.now().strftime('%Y%m%d')).encode()
    return 'FR-2026-' + hashlib.md5(hash_input).hexdigest()[:4].upper()

def build_analysis_prompt(log_chunk):
    return f"""
    You are a senior digital forensic analyst. Analyze the following Windows
    Event Log entries and reason through them step by step.

    For each suspicious event you identify:
    1. State the timestamp and Event ID
    2. Explain what this event means in plain language
    3. Identify the MITRE ATT&CK tactic and technique it maps to
    4. Rate the severity as Low, Medium, or High
    5. Explain your reasoning

    Log entries:
    {log_chunk}

    Think step by step. If an event is benign, say so and move on.
    Only flag events that are genuinely suspicious.
    """

def build_report_prompt(all_findings, report_id):
    return f"""
    You are a senior digital forensic analyst writing a formal investigation report.
    Based on the following findings, produce a structured report with exactly these sections.
    Do not use markdown. No hashtags, no asterisks, no backticks.
    Use plain text only with section headers exactly as shown in capitals.

    CLASSIFICATION: CONFIDENTIAL
    REPORT ID: {report_id}
    DATE: {datetime.datetime.now().strftime('%B %d, %Y')}
    ANALYST: LogIQ Forensic AI Agent

    WHAT HAPPENED AND WHEN

    Response Coordinator: LogIQ Forensic AI Agent
    Nature of Incident: [1 sentence summary of the attack type]
    When Did It Occur: [date, start time, end time, timezone from the logs]
    IT Resources at Risk: [list affected systems, hostnames, accounts]
    Business Processes Affected: [what business functions were disrupted]
    Severity: [Critical / High / Medium / Low with one sentence justification]
    Third Parties Involved: [external IPs, C2 servers, or none]
    PII at Risk: [yes or no, describe what data may have been exposed]
    Cybersecurity Risks: [identity theft, lateral movement, data loss, etc.]
    Geographic Regions: [based on log hostnames and IPs]
    Business Owners and Stakeholders: [affected accounts and system owners]

    WHAT WAS THE ROOT CAUSE

    Cause of Incident: [how the attack started]
    How Do We Know: [which log events prove this]
    Confidence Level: [High / Medium / Low with reason]
    Connections to Past Incidents: [none identified or relevant patterns]

    ATTACK TIMELINE
    List each event as a pipe-separated row in this exact format with no extra text:
    TIMESTAMP | EVENT ID | DESCRIPTION
    Example:
    2026-04-15 08:14:32 UTC | 4688 | Malicious executable launched by cmd.exe

    MITRE ATT&CK MAPPING
    List each finding as a pipe-separated row in this exact format:
    TACTIC | TECHNIQUE ID | TECHNIQUE NAME | SEVERITY
    Example:
    Initial Access | T1566.001 | Spearphishing Attachment | High

    WHAT WAS AND REMAINS TO BE DONE

    Identification: [how the incident was detected]
    Containment: [immediate steps to limit scope]
    Eradication: [steps to remove attacker presence]
    Recovery: [steps to restore normal operations]

    LESSONS LEARNED

    People: [training or awareness improvements]
    Process: [policy or procedure changes needed]
    Technology: [tooling or monitoring improvements]

    RECOMMENDED NEXT STEPS
    [Numbered list of prioritized actions with responsible party]

    ANALYST NOTES
    [Caveats, limitations of the analysis, areas needing human review]

    Findings to analyze:
    {all_findings}
    """

def run_agent(log_filepath):
    print(f"Starting forensic analysis of: {log_filepath}")

    print("Step 1: Reading log file...")
    log_content = read_log_file(log_filepath)

    print("Step 2: Chunking logs for analysis...")
    chunks = chunk_logs(log_content)
    print(f"Log split into {len(chunks)} chunks")

    print("Step 3: Analyzing each chunk...")
    all_findings = []
    for i, chunk in enumerate(chunks):
        print(f"  Analyzing chunk {i+1} of {len(chunks)}...")
        prompt = build_analysis_prompt(chunk)
        finding = call_azure_openai(prompt)
        all_findings.append(finding)

    print("Step 4: Generating forensic report...")
    report_id = generate_report_id(log_filepath)
    report_prompt = build_report_prompt('\n\n'.join(all_findings), report_id)
    final_report = call_azure_openai(report_prompt, max_tokens=4000)

    print("Step 5: Analysis complete.")
    return final_report

if __name__ == "__main__":
    report = run_agent('data/sample_log.txt')
    print("\n" + "="*50)
    print("FORENSIC REPORT")
    print("="*50)
    print(report)