# Neural Firewall

> *"The agents that guard the agents."*

**AI Security Middleware** — Multi-agent prompt injection detection and prevention system built with Google ADK, FastMCP, and Gemini 1.5 Flash.

---

## What It Does

Neural Firewall sits between any user input and any AI agent, running a 5-stage security pipeline to detect and block prompt injection attacks before they reach your system.

```
User Input
    |
    v
[1] Intake Agent        — Decodes obfuscation (base64, unicode tricks, zero-width chars)
    |
    v
[2] Inspection Agent    — Classifies threat type, scores severity 0.0-1.0
    |
    v
[3] Probe Agent         — Self-adversarially challenges the inspection result
    |
    v (if score >= 0.75)
[4] HITL Gate           — Human-in-the-Loop: pauses pipeline, awaits human decision
    |
    v
[5] Output Sanitizer    — Inspects agent response before it reaches the user
    |
    v
Safe Output
```

---

## Attack Types Detected

| Attack | Example | Detection |
|--------|---------|-----------|
| Direct Injection | "Ignore all previous instructions..." | Semantic + pattern |
| Indirect Injection | Malicious text hidden in documents | Pre-tool-call inspection |
| Token Smuggling | Base64/Unicode encoded payloads | Normalization layer |
| Role-Play Jailbreak | "You are now DAN..." | Intent classification |
| Tool-Call Hijacking | Tricking agent to misuse its own tools | Output pre-validation |

---

## Tech Stack (100% Free)

- **Agent Framework:** Google ADK (Python)
- **LLM:** Gemini 1.5 Flash (Google AI Studio free tier)
- **Threat Intelligence:** Custom FastMCP Server
- **Memory:** ADK Session State + SQLite (aiosqlite)
- **Backend API:** FastAPI + Uvicorn
- **Frontend:** Vanilla HTML/CSS/JS (AMOLED dark theme)
- **Deployment:** Google Cloud Run (free tier)

---

## Project Structure

```
neural-firewall/
|-- agents/              # 5 ADK security agents
|-- pipeline/            # SequentialAgent orchestration
|-- mcp_server/          # FastMCP threat intelligence server
|-- memory/              # SQLite session state manager
|-- api/                 # FastAPI backend (4 routes)
|-- frontend/            # Web UI with HITL modal
|-- tests/               # 20+ real attack test cases
```

---

## Quick Start

```bash
# 1. Clone repo
git clone https://github.com/YOUR_USERNAME/neural-firewall.git
cd neural-firewall

# 2. Create virtual environment
python -m venv .venv
.venv\Scripts\activate.bat

# 3. Install dependencies
pip install -r requirements.txt

# 4. Add your Gemini API key
# Create .env file:
# GEMINI_API_KEY=your_key_here

# 5. Run the MCP server (separate terminal)
python mcp_server/server.py

# 6. Run the API backend
python -m uvicorn api.main:app --host 127.0.0.1 --port 8000 --reload

# 7. Open frontend/index.html in browser
```

---

## Course Concepts Demonstrated

| Concept | Implementation |
|---------|---------------|
| Multi-Agent System (ADK) | 5-agent SequentialAgent pipeline |
| MCP Server | FastMCP threat intelligence server |
| Human-in-the-Loop | HITL gate with SQLite + frontend modal |
| Agent Memory | Session state tracks attack patterns |

---

## Capstone Project

**Course:** 5-Day AI Agents Intensive Vibe Coding Course with Google (Kaggle)
**Track:** Agents for Business / Freestyle
**Deadline:** July 6, 2026

---

*Built with Google ADK | Kaggle AI Agents Intensive 2026*
