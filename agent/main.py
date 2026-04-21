import json
import os

def read_log_file(filepath):
    """
    Read a log file and return its contents as a string.
    In production this will parse EVTX files.
    For now reads a plain text or JSON log file.
    """
    with open(filepath, 'r') as f:
        return f.read()

def chunk_logs(log_content, chunk_size=50):
    """
    Split log content into manageable chunks for the agent.
    The agent processes logs in chunks to handle large files.
    """
    lines = log_content.strip().split('\n')
    chunks = []
    for i in range(0, len(lines), chunk_size):
        chunks.append('\n'.join(lines[i:i+chunk_size]))
    return chunks

def call_azure_openai(prompt):
    """
    Call Azure OpenAI with the given prompt.
    PLACEHOLDER: returns dummy response until Azure access is restored.
    """
    # TODO: replace with actual Azure OpenAI call
    # from openai import AzureOpenAI
    # client = AzureOpenAI(
    #     azure_endpoint=os.getenv("AZURE_OPENAI_ENDPOINT"),
    #     api_key=os.getenv("AZURE_OPENAI_KEY"),
    #     api_version="2024-02-01"
    # )
    # response = client.chat.completions.create(
    #     model="gpt-4o",
    #     messages=[{"role": "user", "content": prompt}]
    # )
    # return response.choices[0].message.content

    return """
    PLACEHOLDER RESPONSE:
    Suspicious event detected at 14:32:01
    Event ID 4688: New process created - cmd.exe spawned by winword.exe
    Possible technique: T1059.003 - Command and Scripting Interpreter
    Tactic: Execution
    Severity: High
    """

def build_analysis_prompt(log_chunk):
    """
    Build the prompt that instructs the agent how to reason through logs.
    This is where your forensic domain knowledge goes.
    """
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

def build_report_prompt(all_findings):
    """
    Build the final report from all individual findings.
    """
    return f"""
    You are a senior digital forensic analyst writing a formal investigation report.
    Based on the following findings from a log analysis, produce a structured report with:

    1. EXECUTIVE SUMMARY: 2-3 sentences describing what happened
    2. ATTACK TIMELINE: Chronological list of events with timestamps
    3. MITRE ATT&CK MAPPING: Table of tactics and techniques identified
    4. NARRATIVE: Plain language explanation of the attack from start to finish
    5. RECOMMENDED NEXT STEPS: What the investigator should do next

    Findings:
    {all_findings}

    Write this report so that a non-technical manager can understand it,
    but include enough technical detail for a junior analyst to act on it.
    """

def run_agent(log_filepath):
    """
    Main agent loop. This is the agentic behaviour:
    the agent plans, reasons across multiple steps, and produces output.
    """
    print(f"Starting forensic analysis of: {log_filepath}")
    
    # Step 1: Read the log file
    print("Step 1: Reading log file...")
    log_content = read_log_file(log_filepath)
    
    # Step 2: Chunk the logs
    print("Step 2: Chunking logs for analysis...")
    chunks = chunk_logs(log_content)
    print(f"Log split into {len(chunks)} chunks")
    
    # Step 3: Analyze each chunk
    print("Step 3: Analyzing each chunk...")
    all_findings = []
    for i, chunk in enumerate(chunks):
        print(f"  Analyzing chunk {i+1} of {len(chunks)}...")
        prompt = build_analysis_prompt(chunk)
        finding = call_azure_openai(prompt)
        all_findings.append(finding)
    
    # Step 4: Generate final report
    print("Step 4: Generating forensic report...")
    report_prompt = build_report_prompt('\n\n'.join(all_findings))
    final_report = call_azure_openai(report_prompt)
    
    # Step 5: Return structured output
    print("Step 5: Analysis complete.")
    return final_report

if __name__ == "__main__":
    # Test with a sample log file
    # Create a dummy log file for testing
    sample_log = """
    2026-04-21 14:30:00 EventID=4624 Account=SYSTEM LogonType=3
    2026-04-21 14:31:15 EventID=4688 ProcessName=cmd.exe ParentProcess=winword.exe
    2026-04-21 14:31:16 EventID=4688 ProcessName=powershell.exe ParentProcess=cmd.exe
    2026-04-21 14:32:00 EventID=4698 TaskName=WindowsUpdate ScheduledBy=UNKNOWN
    2026-04-21 14:33:10 EventID=4625 Account=Administrator FailureReason=WrongPassword
    2026-04-21 14:33:11 EventID=4625 Account=Administrator FailureReason=WrongPassword
    2026-04-21 14:33:12 EventID=4625 Account=Administrator FailureReason=WrongPassword
    2026-04-21 14:33:13 EventID=4624 Account=Administrator LogonType=3
    """
    
    with open('data/sample_log.txt', 'w') as f:
        f.write(sample_log)
    
    report = run_agent('data/sample_log.txt')
    print("\n" + "="*50)
    print("FORENSIC REPORT")
    print("="*50)
    print(report)