# Splunk Security Log Analyzer

An AI-assisted SOC triage tool that pulls Windows Security events from Splunk 
and uses the Anthropic API (Claude) to generate structured triage reports with 
MITRE ATT&CK mapping.

Built and documented at [blog.slytech.us](https://blog.slytech.us).

---

## What It Does

1. Connects to Splunk REST API and queries for security-relevant Windows event codes
2. Priority-sorts events so failed logons and suspicious activity surface first
3. Sends formatted events to Claude for analysis
4. Returns a structured report with executive summary, prioritized findings, 
   MITRE ATT&CK mapping, recommended actions, and noise assessment
5. Saves a timestamped report file locally for documentation

## Event Codes Monitored

| Code | Description |
|------|-------------|
| 4625 | Failed logon |
| 4648 | Logon with explicit credentials |
| 4720 | User account created |
| 4726 | User account deleted |
| 4732 | Member added to security group |
| 4698 | Scheduled task created |
| 4688 | Process creation |
| 4624 | Successful logon |
| 4634 | Logoff |
| 4776 | Credential validation |

---

## Requirements

- Splunk Enterprise with Windows Security events indexed
- Universal Forwarder on monitored endpoints
- Python 3.10+
- Anthropic API key (get one at [console.anthropic.com](https://console.anthropic.com))
```bash
pip install anthropic requests
```

---

## Setup

1. Clone the repo and navigate to the project folder:
```bash
git clone https://github.com/SlyCyberLab/slytech-ai-labs.git
cd slytech-ai-labs/01-splunk-log-analyzer
```

2. Set your credentials as environment variables. Never hardcode these:
```bash
export SPLUNK_PASSWORD="your_splunk_admin_password"
export ANTHROPIC_API_KEY="your_anthropic_api_key"
```

3. Run the analyzer:
```bash
python3 splunk_analyzer.py
```

See `.env.example` for all required variables.

---

## Sample Output
```
CRITICAL — Active Brute-Force Attack from "kali-attack"
  Target: win11-002 | Source: 10.0.0.213
  13 failed logons in ~4 seconds
  MITRE ATT&CK: T1110.001 (Brute Force: Password Guessing)

HIGH — Sustained Credential Testing from "DARKSHELL"
  Target: win11-002 | Source: 10.0.0.100
  20+ failed logons across 26 hours
  MITRE ATT&CK: T1110.001
```

---

## Configuration

Edit these variables at the top of `splunk_analyzer.py` to match your environment:

| Variable | Default | Description |
|----------|---------|-------------|
| `SPLUNK_HOST` | `https://localhost:8089` | Splunk REST API endpoint |
| `SPLUNK_USER` | `admin` | Splunk username |
| `TIME_WINDOW` | `-7d` | How far back to query |
| `MAX_EVENTS` | `50` | Max events sent to AI per run |

---

## Author

Emsly S.
[blog.slytech.us](https://blog.slytech.us) | 
[github.com/SlyCyberLab](https://github.com/SlyCyberLab)
