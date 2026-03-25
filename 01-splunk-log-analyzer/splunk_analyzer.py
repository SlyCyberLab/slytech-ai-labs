#!/usr/bin/env python3
"""
Splunk Security Log Analyzer
Pulls recent Windows Security events from Splunk and uses
the Anthropic API to generate a triage summary with MITRE ATT&CK mapping.

Author: Emsly S. (SlyCyberLab)
Blog: blog.slytech.us
GitHub: github.com/SlyCyberLab
"""

import json
import os
import sys
from datetime import datetime
import requests
import anthropic

# ── Configuration ─────────────────────────────────────────────────────────────

SPLUNK_HOST = "https://localhost:8089"
SPLUNK_USER = "admin"
SPLUNK_PASSWORD = os.environ.get("SPLUNK_PASSWORD")
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY")

# Event codes we care about for security triage
SECURITY_EVENT_CODES = [
    "4624",  # Successful logon
    "4625",  # Failed logon
    "4634",  # Logoff
    "4648",  # Logon with explicit credentials
    "4720",  # User account created
    "4726",  # User account deleted
    "4776",  # Credential validation
    "4688",  # Process creation
    "4698",  # Scheduled task created
    "4732",  # Member added to security group
]

# How far back to look
TIME_WINDOW = "-7d"

# Max events to send to AI (keep cost and context manageable)
MAX_EVENTS = 50

# Output file
OUTPUT_FILE = f"triage_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"


# ── Splunk Query ───────────────────────────────────────────────────────────────

def fetch_splunk_events():
    """
    Query Splunk REST API for recent security events.
    Returns a list of cleaned event dictionaries.
    """

    # Build the SPL search
    # Filter to only our target event codes
    event_code_filter = " OR ".join([f'EventCode="{code}"' for code in SECURITY_EVENT_CODES])
    search_query = f"""
    search index=* earliest={TIME_WINDOW}
    ({event_code_filter})
    | eval priority=case(
        EventCode="4625", 1,
        EventCode="4648", 2,
        EventCode="4720", 3,
        EventCode="4726", 4,
        EventCode="4732", 5,
        EventCode="4698", 6,
        EventCode="4688", 7,
        1=1, 8
    )
    | sort priority _time
    | table _time host source EventCode Message
    | head {MAX_EVENTS}
"""

    print(f"[*] Querying Splunk for last {TIME_WINDOW} of security events...")

    try:
        response = requests.post(
            f"{SPLUNK_HOST}/services/search/jobs/export",
            auth=(SPLUNK_USER, SPLUNK_PASSWORD),
            data={
                "search": search_query,
                "output_mode": "json",
            },
            verify=False,  # Self-signed cert in lab environment
            timeout=30
        )
        response.raise_for_status()

    except requests.exceptions.ConnectionError:
        print("[!] Cannot connect to Splunk. Is it running?")
        sys.exit(1)
    except requests.exceptions.Timeout:
        print("[!] Splunk query timed out.")
        sys.exit(1)

    # Parse the response — one JSON object per line
    events = []
    for line in response.text.strip().split("\n"):
        if not line:
            continue
        try:
            obj = json.loads(line)
            result = obj.get("result", {})
            if result:
                # Clean up the Message field
                message = result.get("Message", "")
                message = message.replace("\r\n", " ").replace("\t", " ")
                # Collapse multiple spaces
                while "  " in message:
                    message = message.replace("  ", " ")

                events.append({
                    "time": result.get("_time", ""),
                    "host": result.get("host", ""),
                    "source": result.get("source", ""),
                    "event_code": result.get("EventCode", ""),
                    "message": message.strip()
                })
        except json.JSONDecodeError:
            continue

    print(f"[*] Retrieved {len(events)} events.")
    return events


# ── Format Events for AI ───────────────────────────────────────────────────────

def format_events_for_analysis(events):
    """
    Convert event list into a clean, readable block for the AI prompt.
    """
    if not events:
        return "No events found."

    formatted = []
    for i, event in enumerate(events, 1):
        formatted.append(
            f"Event {i}:\n"
            f"  Time: {event['time']}\n"
            f"  Host: {event['host']}\n"
            f"  Source: {event['source']}\n"
            f"  Event Code: {event['event_code']}\n"
            f"  Message: {event['message'][:500]}"  # Cap message length
        )

    return "\n\n".join(formatted)


# ── Anthropic Analysis ─────────────────────────────────────────────────────────

def analyze_with_ai(events_text):
    """
    Send formatted events to Claude for security triage analysis.
    Returns the AI response as a string.
    """

    print("[*] Sending events to Anthropic API for analysis...")

    client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)

    # This prompt is the core of the tool.
    # It tells Claude exactly what role to play and what output format to produce.
    system_prompt = """You are a senior SOC analyst performing security event triage.
You analyze Windows Security Event logs and produce structured triage reports.

For each analysis, you must:
1. Identify the most suspicious or notable events
2. Group related events that may indicate a pattern
3. Map findings to MITRE ATT&CK techniques where applicable
4. Assign a triage priority: CRITICAL, HIGH, MEDIUM, LOW, or INFORMATIONAL
5. Recommend a specific next action for each finding

Be direct and specific. Do not summarize benign noise in detail.
Focus on what a SOC analyst needs to act on."""

    user_prompt = f"""Analyze the following Windows Security events from a domain controller 
in a lab environment (domain: SLYTECH.US, host: dc01).

Produce a structured triage report with the following sections:
- EXECUTIVE SUMMARY (2-3 sentences max)
- KEY FINDINGS (prioritized list with MITRE ATT&CK mapping)
- RECOMMENDED ACTIONS
- NOISE ASSESSMENT (what can be safely ignored and why)

EVENTS:
{events_text}"""

    try:
        message = client.messages.create(
            model="claude-opus-4-5",
            max_tokens=1500,
            messages=[
                {"role": "user", "content": user_prompt}
            ],
            system=system_prompt
        )
        return message.content[0].text

    except anthropic.AuthenticationError:
        print("[!] Invalid Anthropic API key. Check your ANTHROPIC_API_KEY environment variable.")
        sys.exit(1)
    except anthropic.RateLimitError:
        print("[!] Anthropic rate limit hit. Wait a moment and try again.")
        sys.exit(1)


# ── Output ─────────────────────────────────────────────────────────────────────

def save_report(events_text, analysis, event_count):
    """
    Save the full report to a text file.
    """
    report = f"""
SPLUNK SECURITY LOG ANALYZER
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Events Analyzed: {event_count}
Time Window: {TIME_WINDOW}
{'='*60}

AI TRIAGE ANALYSIS
{'='*60}
{analysis}

{'='*60}
RAW EVENTS ANALYZED
{'='*60}
{events_text}
"""
    with open(OUTPUT_FILE, "w") as f:
        f.write(report)

    print(f"[*] Report saved to {OUTPUT_FILE}")


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    print("\n" + "="*60)
    print("  SPLUNK SECURITY LOG ANALYZER")
    print("  SlyCyberLab | blog.slytech.us")
    print("="*60 + "\n")

    # Validate environment variables
    if not SPLUNK_PASSWORD:
        print("[!] SPLUNK_PASSWORD environment variable not set.")
        print("    Run: export SPLUNK_PASSWORD='yourpassword'")
        sys.exit(1)

    if not ANTHROPIC_API_KEY:
        print("[!] ANTHROPIC_API_KEY environment variable not set.")
        print("    Run: export ANTHROPIC_API_KEY='your-api-key'")
        print("    Get one at: console.anthropic.com")
        sys.exit(1)

    # Step 1: Pull events from Splunk
    events = fetch_splunk_events()

    if not events:
        print("[!] No matching security events found in the last hour.")
        print("    Try expanding the time window in the script (TIME_WINDOW variable).")
        sys.exit(0)

    # Step 2: Format for AI
    events_text = format_events_for_analysis(events)

    # Step 3: AI analysis
    analysis = analyze_with_ai(events_text)

    # Step 4: Display and save
    print("\n" + "="*60)
    print("  TRIAGE REPORT")
    print("="*60)
    print(analysis)

    save_report(events_text, analysis, len(events))

    print("\n[+] Analysis complete.")


if __name__ == "__main__":
    main()
