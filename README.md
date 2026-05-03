# WazuhBot — AI-Powered Security Operations Assistant

WazuhBot is an AI-driven cybersecurity assistant built on top of [Wazuh](https://wazuh.com/), an open-source SIEM and XDR platform. It gives security analysts a natural-language interface to their Wazuh deployment — letting them investigate threats, understand alerts, and get remediation guidance through a conversation instead of manually navigating dashboards and logs.

---

## Why WazuhBot?

Security analysts working with SIEM platforms face two persistent problems:

**Information overload.** Wazuh produces thousands of alerts daily. Most are noise. Finding the alerts that actually matter, cross-referencing them with agent data, and understanding the attack pattern behind them takes significant time and expertise.

**Expertise gap.** Not every analyst has deep knowledge of every attack type. Knowing that an alert fired is one thing — knowing what it means, how serious it is, and what to do about it is another.

WazuhBot addresses both. It connects directly to your Wazuh Manager and Indexer, queries live data on your behalf, and uses a local LLM (no data leaves your network) combined with a curated security knowledge base to give you context-aware, actionable answers. Ask it "what happened on this agent in the last hour?" and it will query Wazuh, interpret the results, and explain what it found in plain language.

---

## What WazuhBot Can Do

- **Answer security questions in natural language** — "Are there any brute force attempts in the last 24 hours?" or "What is the severity of rule 5712?"
- **Investigate alerts** — pulls live alert data from Wazuh Indexer (OpenSearch) and explains what triggered them
- **Identify network anomalies** — an ML model trained on the NF-UQ-NIDS-v2 dataset classifies network flows as benign or a specific attack type (DoS, DDoS, port scan, brute force, etc.)
- **Suggest remediations** — backed by a knowledge base of Wazuh active response playbooks and defense hardening guides
- **Monitor your environment** — a Sentinel dashboard shows live agent status, recent alerts, and rule summaries
- **Remember conversations** — full chat history is stored per user so you can revisit past investigations
- **Support multiple analysts** — each user connects their own Wazuh credentials; everything is encrypted at rest

---

## How It Works

WazuhBot is made up of five components that work together:

```
You (Browser)
    │
    ▼
Express API  ──────────────────── MySQL (users, chat history)
    │
    ├──► Chatbot Service (Python)
    │         │
    │         ├── Ollama LLM (qwen2.5:3b, runs locally)
    │         ├── ChromaDB RAG (security knowledge base)
    │         └── MCP Bridge ──► Wazuh Manager API + Indexer
    │
    └──► ML Inference Service (Python)
              └── Random Forest classifier (network anomaly detection)
```

When you send a message, the chatbot service decides whether to answer from the knowledge base, query your Wazuh deployment via the MCP bridge, run an ML prediction, or a combination of all three. The LLM synthesises the results into a single coherent response.

All LLM inference runs locally via Ollama — no API keys, no data sent to third parties.

---

## Prerequisites

Before starting, make sure you have the following installed:

- [Node.js](https://nodejs.org/) >= 18
- [Python](https://www.python.org/) >= 3.11
- [MySQL](https://dev.mysql.com/downloads/) 8.0
- [Ollama](https://ollama.com/) with the `qwen2.5:3b` model

```bash
# Install the LLM model (one-time)
ollama pull qwen2.5:3b
```

You also need a running Wazuh deployment (Manager + Indexer) reachable from the machine running WazuhBot. Each user provides their own Wazuh credentials at signup.

---

## Setup

### 1. Database

Create the MySQL database and a user for the application:

```sql
CREATE DATABASE wazuhbot;
CREATE USER 'your_db_user'@'localhost' IDENTIFIED BY 'your_password';
GRANT ALL PRIVILEGES ON wazuhbot.* TO 'your_db_user'@'localhost';
FLUSH PRIVILEGES;
```

The application creates all tables automatically on first start.

### 2. Environment file

Create `backend and frontend/Backend/.env`:

```env
PORT=5000

DB_HOST=localhost
DB_PORT=3306
DB_NAME=wazuhbot
DB_USER=your_db_user
DB_PASSWORD=your_password

JWT_SECRET=replace_with_a_long_random_secret

GMAIL_USER=your-email@gmail.com
GMAIL_APP_PASSWORD=your-gmail-app-password
```

### 3. Install dependencies

```bash
# Node.js API
cd "backend and frontend/Backend"
npm install

# Frontend
cd "backend and frontend/Frontend"
npm install

# Python chatbot service
cd Backend/chatbot
pip install -r requirements.txt

# Python ML service
cd Backend/ml_service
pip install -r requirements.txt

# MCP server
cd MCP
pip install -e .
```

### 4. Build the knowledge base index (one-time)

```bash
cd Backend/chatbot
python build_vectorstore.py
```

This processes the security knowledge base documents (attack explanations, remediation playbooks, Wazuh architecture, defense hardening guides) and stores them in ChromaDB for fast retrieval during conversations.

---

## Running WazuhBot

Start each component in a separate terminal. The order below is recommended.

```bash
# Terminal 1 — ML inference service
cd Backend/ml_service
python inference_server.py
```

```bash
# Terminal 2 — Chatbot service (LLM + RAG + Wazuh bridge)
cd Backend/chatbot
python chatbot_server.py
```

```bash
# Terminal 3 — Express API gateway
cd "backend and frontend/Backend"
npm start
```

```bash
# Terminal 4 — Frontend
cd "backend and frontend/Frontend"
npm run dev
```

Then open **http://localhost:5173** in your browser.

Register an account with your Wazuh Manager IP, Indexer IP, and credentials. WazuhBot will connect to your instance and you can start chatting immediately.

> The Wazuh MCP bridge launches automatically in the background when you send your first message — you do not need to start it manually.

---

## ML Anomaly Detection

The anomaly detection model is a Random Forest classifier trained on the [NF-UQ-NIDS-v2](https://research.unsw.edu.au/projects/network-based-intrusion-detection) dataset — a large-scale network flow dataset with over 40 features covering both benign traffic and a wide range of attack categories including DoS, DDoS, port scanning, brute force, and more.

Pre-trained model artifacts are included in `output/`. To retrain from scratch, place the dataset CSV in `dataset/` and run all cells in `train_model_v3.ipynb`.

---

## Knowledge Base

The chatbot's RAG system is grounded in a curated set of security documents:

- **Wazuh Architecture** — how Wazuh agents, managers, and the indexer fit together
- **Wazuh Rules** — rule categories, severity levels, and how to interpret them
- **Attack Explanations** — what common attack patterns look like in Wazuh alerts
- **Remediation Playbooks** — step-by-step response procedures for common threats
- **Active Response** — how to use Wazuh's built-in active response to block attacks automatically
- **Defense Hardening** — host and network hardening recommendations surfaced during investigations

These documents live in `Backend/chatbot/knowledge/` and can be extended with your own organisation's runbooks.

---

## Project Structure

```
Webapp/
├── backend and frontend/
│   ├── Backend/          # Node.js Express API (port 5000)
│   └── Frontend/         # Vite.js web UI (port 5173)
├── Backend/
│   ├── chatbot/          # Python chatbot service (port 5002)
│   └── ml_service/       # Python ML inference service (port 5001)
├── MCP/                  # Wazuh MCP server (launched as subprocess)
├── dataset/              # NF-UQ-NIDS-v2 training data
├── output/               # Trained ML model artifacts
└── train_model_v3.ipynb  # Model training notebook
```
