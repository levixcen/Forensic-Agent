import os
import asyncio
import re
from dotenv import load_dotenv
from openai import AzureOpenAI

load_dotenv()

client = AzureOpenAI(
    azure_endpoint=os.getenv("AZURE_OPENAI_ENDPOINT"),
    api_key=os.getenv("AZURE_OPENAI_KEY"),
    api_version="2024-12-01-preview"
)

SUSPICIOUS_EVENT_IDS = {
    '4624', '4625', '4626', '4627', '4648', '4649',
    '4688', '4689', '4697', '4698', '4699', '4700',
    '4701', '4702', '4720', '4722', '4724', '4728',
    '4732', '4756', '4768', '4769', '4776', '4778',
    '4779', '4794', '4798', '4799', '7045', '1102',
    '4663', '4670', '4672', '4673', '4674', '4675',
}

def read_log_file(filepath):
    with open(filepath, 'r', errors='ignore') as f:
        return f.read()


def smart_filter(log_content):
    """
    Filter log content to keep only lines/blocks containing suspicious Event IDs.

    Handles three formats:
      1. Plain text:  EventID=4688  or  Event ID: 4688
      2. XML (EVTX-converted):  <EventID>4688</EventID>
                                <EventID Qualifiers="">4688</EventID>
      3. JSON:  "id":"4688"

    For XML files the entire <Event>...</Event> block is treated as one unit
    so that context (username, timestamp, process name) is preserved.
    """
    # --- Detect XML format ---
    is_xml = bool(re.search(r'<Event\b', log_content, re.IGNORECASE))

    if is_xml:
        return _filter_xml_blocks(log_content)
    else:
        return _filter_plain_lines(log_content)


def _filter_xml_blocks(log_content):
    """Split on <Event> boundaries and keep blocks whose EventID is suspicious."""
    # Split into individual <Event>…</Event> blocks
    blocks = re.split(r'(?=<Event[\s>])', log_content)
    total = len(blocks)
    filtered = []

    # Matches: <EventID>4688</EventID>  or  <EventID Qualifiers="...">4688</EventID>
    xml_eid_pattern = re.compile(
        r'<EventID[^>]*>\s*(\d+)\s*</EventID>', re.IGNORECASE
    )

    for block in blocks:
        m = xml_eid_pattern.search(block)
        if m and m.group(1) in SUSPICIOUS_EVENT_IDS:
            filtered.append(block.strip())

    if not filtered:
        # Fallback: return all non-empty blocks
        filtered = [b.strip() for b in blocks if b.strip()]

    print(f"Smart filter (XML): {total} blocks -> {len(filtered)} suspicious blocks")
    return filtered


def _filter_plain_lines(log_content):
    """Original line-based filter for plain text / key=value logs."""
    lines = log_content.strip().split('\n')
    total = len(lines)
    filtered = []

    patterns = []
    for eid in SUSPICIOUS_EVENT_IDS:
        # Covers:  EventID=4688  EventId: 4688  "id":"4688"  id>4688
        patterns.append(re.compile(
            rf'(?:[Ee]vent\s*[Ii][Dd]|[Ii][Dd])[\s=:\>"]*{re.escape(eid)}\b'
        ))

    for line in lines:
        if any(p.search(line) for p in patterns):
            filtered.append(line)

    if not filtered:
        filtered = lines  # Fallback: keep everything

    print(f"Smart filter (plain): {total} lines -> {len(filtered)} suspicious lines")
    return filtered


def chunk_logs(lines, chunk_size=200):
    chunks = []
    for i in range(0, len(lines), chunk_size):
        chunks.append('\n'.join(lines[i:i + chunk_size]))
    return chunks


def call_azure_openai(prompt):
    response = client.chat.completions.create(
        model=os.getenv("AZURE_OPENAI_DEPLOYMENT"),
        messages=[{"role": "user", "content": prompt}],
        max_tokens=1000
    )
    return response.choices[0].message.content


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


def build_report_prompt(all_findings):
    return f"""
You are a senior forensic investigator at a top-tier SOC. Generate a high-fidelity SANS-style forensic report.

### FORMATTING RULES ###
1. Use EXACTLY the headers below in all caps.
2. Use professional, clinical language.
3. Use Markdown tables for the MITRE ATT&CK MAPPING section.
4. Use bold text for key indicators (IPs, File Names, Usernames).
5. Use a chronological bulleted list for the ATTACK TIMELINE.

### REPORT START ###

WHAT HAPPENED AND WHEN
[Summarize the incident clearly, including the scope and duration.]

WHAT WAS THE ROOT CAUSE
[Explain the initial access vector and how the vulnerability was exploited.]

ATTACK TIMELINE
[List events chronologically with timestamps in bold.]

MITRE ATT&CK MAPPING
| Tactic | Technique | ID | Details |
| :--- | :--- | :--- | :--- |
| [Tactic Name] | [Technique] | [T-ID] | [Evidence from logs] |

WHAT WAS AND REMAINS TO BE DONE
[List containment and eradication steps taken or needed.]

LESSONS LEARNED
[Explain why the detection was delayed or how the attack bypassed security.]

RECOMMENDED NEXT STEPS
[Provide 3-5 actionable security hardening steps.]

ANALYST NOTES
[Additional technical observations.]

### DATA TO PROCESS ###
{all_findings}
"""


async def analyze_chunk_async(chunk, semaphore, idx, total):
    async with semaphore:
        print(f"  Analyzing chunk {idx + 1} of {total}...")
        loop = asyncio.get_event_loop()
        prompt = build_analysis_prompt(chunk)
        finding = await loop.run_in_executor(None, call_azure_openai, prompt)
        return finding


async def analyze_all_chunks_async(chunks):
    semaphore = asyncio.Semaphore(5)
    tasks = [
        analyze_chunk_async(chunk, semaphore, i, len(chunks))
        for i, chunk in enumerate(chunks)
    ]
    findings = await asyncio.gather(*tasks)
    return list(findings)


def run_agent(log_filepath):
    print(f"Starting forensic analysis of: {log_filepath}")

    print("Step 1: Reading log file...")
    log_content = read_log_file(log_filepath)

    print("Step 2: Smart filtering suspicious events...")
    filtered_lines = smart_filter(log_content)

    print("Step 3: Chunking filtered logs...")
    chunks = chunk_logs(filtered_lines, chunk_size=200)
    print(f"Processing {len(chunks)} chunks in parallel...")

    print("Step 4: Analyzing chunks in parallel...")
    all_findings = asyncio.run(analyze_all_chunks_async(chunks))

    print("Step 5: Generating forensic report...")
    combined = '\n\n'.join(all_findings)
    report_prompt = build_report_prompt(combined)
    final_report = call_azure_openai(report_prompt)

    print("Step 6: Analysis complete.")
    return final_report


if __name__ == "__main__":
    report = run_agent('data/sample_log.txt')
    print("\n" + "=" * 50)
    print("FORENSIC REPORT")
    print("=" * 50)
    print(report)