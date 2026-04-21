# LogIQ

An AI-powered post-incident forensic reconstruction agent that ingests Windows Event Logs, 
autonomously reasons through attack sequences, maps findings to the MITRE ATT&CK framework, 
and generates structured investigation reports using Azure OpenAI.

## Problem
Post-incident forensic investigation is done manually by senior experts 
who are expensive and scarce, especially in Southeast Asia. Junior analysts 
have the tools but not the expertise to interpret what they are seeing.

## Solution
An agentic assistant that ingests raw log files, reasons through them 
step by step, maps every finding to MITRE ATT&CK, and produces a 
structured report any analyst can use or hand to a client.

## Tech Stack
- Azure OpenAI (GPT-4o via Azure AI Foundry)
- Azure AI Search (MITRE ATT&CK knowledge base)
- Azure App Service (deployment)
- Flask (web interface)
- Python

## Architecture
See docs/architecture.md

## How to Run


## Risk and Safety
