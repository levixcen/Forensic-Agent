# Devlog

## Day 1 - April 21 2026

**What I am building:**
An AI-powered post-incident forensic reconstruction agent that ingests 
Windows Event Logs, reasons through attack sequences autonomously, maps 
findings to MITRE ATT&CK, and generates structured investigation reports 
using Azure OpenAI.

**Why this problem:**
After a year in cybersecurity, I noticed that post-incident investigation 
requires analysts to manually reconstruct entire attack sequences from 
thousands of raw log lines, a process that demands senior-level expertise 
most teams in Southeast Asia simply do not have access to. While general 
AI tools can analyze logs, none produce structured, framework-grounded 
forensic reports that investigators can directly use or submit. This agent 
fills that gap.

**What I did today:**
- Set up GitHub repo and folder structure
- Wrote README with project overview
- Writing agent skeleton with placeholder Azure OpenAI calls
- Drafting architecture diagram

**Blockers:**
- Azure access not working yet, using placeholder logic for now

**Tomorrow:**
- Sort Azure access
- Replace placeholder with real Azure OpenAI call
- Test agent with sample log file