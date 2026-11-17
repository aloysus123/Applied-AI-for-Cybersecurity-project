# Local AI-Assisted Hybrid Code Vulnerability Scanner

> **IT2527 Applied AI for Cybersecurity** — Proof-of-Concept (PoC)  
> An air-gapped, defense-in-depth vulnerability triage and remediation system combining deterministic SAST (`Bandit`) with local LLM reasoning (`Qwen 2.5 Coder`) and Retrieval-Augmented Generation (`ChromaDB`).

---

## Table of Contents
- [Problem Statement](#problem-statement)
- [Proposed Solution](#proposed-solution)
- [System Architecture & Pipeline](#system-architecture--pipeline)
- [Technology Stack](#technology-stack)
- [Defense-in-Depth Security Controls](#defense-in-depth-security-controls)
- [Prerequisites](#prerequisites)
- [Setup & Installation](#setup--installation)
- [Usage Workflow](#usage-workflow)
- [Team Allocation (Scenario A)](#team-allocation-scenario-a)
- [References](#references)

---

## Problem Statement
Security operations and development teams face severe **alert fatigue** when relying on traditional Static Application Security Testing (SAST) tools. While deterministic scanners detect surface-level flaws, they frequently generate high volumes of false positives without providing actionable remediation context.

Conversely, while cloud-based Large Language Models (LLMs) excel at analyzing code semantics and generating fixes, uploading proprietary corporate source code to third-party cloud APIs violates strict data privacy policies and creates an unacceptable risk of **intellectual property (IP) leakage**.

---

## Proposed Solution
This project delivers a completely **air-gapped, hybrid vulnerability scanner** that pairs deterministic SAST screening with a local AI reasoning engine—operating 100% on local hardware to guarantee **zero IP leakage**.

1. **Deterministic SAST Screening (`Bandit`):** Scans target Python source code locally to pinpoint exact line numbers, CWE classifications, and baseline severity/confidence ratings without guesswork.
2. **Grounded Knowledge Retrieval (`RAG`):** Uses a local vector database (`ChromaDB`) to cross-reference Bandit's findings against curated **OWASP Top 10** guidelines, **NVD** reference data, and verified remediation patch datasets.
3. **Local AI Triage & Remediation (`Qwen 2.5 Coder`):** Feeds the structured SAST findings and retrieved security context into a locally hosted `qwen2.5-coder` model via **Ollama**. The model filters out false positives, contextualizes CVSS risk severity, and generates secure, context-aware code patches.

---

## System Architecture & Pipeline

```text
[ User / Developer ]
        │  (HTTPS / TLS via Nginx)
        ▼
[ Web Portal (Streamlit / Flask) ] ──► RBAC, Rate Limiting & Input Sanitization
        │
        ├──► 1. [ Bandit SAST Engine ] ──► Flags CWE, Line Numbers & Baseline Severity
        │
        ├──► 2. [ ChromaDB (AES-256) ] ──► Retrieves OWASP Top 10, NVD & Patch Context
        │
        └──► 3. [ Ollama (qwen2.5-coder) ] ──► Filters False Positives, Explains CVSS Risk & Generates Patch
```

---

## Technology Stack

| Component | Technology | Purpose |
| :--- | :--- | :--- |
| **Static Analysis (SAST)** | Bandit | Deterministic Python AST-based vulnerability scanning |
| **Local AI Engine** | Ollama (`qwen2.5-coder:7b` / `3b`) | Local semantic code triage, risk contextualization, and patch generation |
| **Vector Database (RAG)** | ChromaDB | Local semantic storage for OWASP Top 10, NVD, and patch datasets |
| **Web Frontend / API** | Python (Streamlit / Flask) | User interface and backend orchestration |
| **Security & Infrastructure** | Nginx, Docker, AES-256 | Reverse proxy with TLS, network isolation, and encryption at rest |

---

## Defense-in-Depth Security Controls
To protect the local AI pipeline against adversarial threats and unauthorized access, security controls are enforced across three architectural layers:

### 1. Application Layer
* **Prompt Injection Defense:** Input sanitization scrubbing untrusted code comments and Bandit outputs before LLM prompt assembly.
* **Output Encoding:** Safe rendering of generated explanations and code diffs to prevent Cross-Site Scripting (XSS).
* **Access & Abuse Controls:** Role-Based Access Control (RBAC) authentication and per-user LLM query rate-limiting.

### 2. Data & Storage Layer
* **Encryption at Rest:** AES-256 encryption protecting the ChromaDB vector store and local NVD/OWASP knowledge datasets.
* **Secret Management:** Secure environment variable handling without hardcoded credentials.
* **Log Privacy:** Masked application logging to prevent sensitive source code snippets from leaking into system logs.

### 3. System & Network Layer
* **Container Hardening:** Multi-container deployment running with least-privilege, non-root container users.
* **TLS Enforcement:** Nginx reverse proxy terminating local HTTPS/TLS connections.
* **Network Isolation:** Internal Docker bridge networking restricting Ollama API access exclusively to the backend service.

---

## Prerequisites
* **Operating System:** Linux, Windows (WSL2), or macOS
* **Hardware:** Minimum 32GB System RAM; Dedicated GPU (6GB+ VRAM recommended for `qwen2.5-coder:7b`, or 4GB VRAM for `qwen2.5-coder:3b`)
* **Software:** Python 3.10+, Docker, Docker Compose, [Ollama](https://ollama.com/)

---

## Setup & Installation

### 1. Install and Start Ollama
Download and install Ollama from [ollama.com](https://ollama.com/), then pull the Qwen 2.5 Coder model:

```bash
# Recommended for 6GB+ VRAM
ollama run qwen2.5-coder:7b

# Alternative for 4GB VRAM hardware profiles
# ollama run qwen2.5-coder:3b
```

### 2. Clone the Repository

```bash
git clone https://github.com/your-org/local-ai-vuln-scanner.git
cd local-ai-vuln-scanner
```

### 3. Environment Setup
Create a virtual environment and install dependencies (including `bandit` and `chromadb`):

```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 4. Initialize the RAG Vector Database
Ingest the OWASP Top 10 guidelines, NVD reference records, and remediation patch datasets into the encrypted local ChromaDB instance:

```bash
python scripts/ingest_dataset.py
```

### 5. Launch the Application Stack
Build and start the isolated services (Web UI, Bandit Worker, ChromaDB, Nginx Reverse Proxy) using Docker Compose:

```bash
docker-compose up --build
```

Access the web portal securely at `https://localhost:8443`.

---

## Usage Workflow
1. **Authenticate:** Log in to the web portal using authorized RBAC credentials.
2. **Submit Code:** Paste a Python code snippet or upload a `.py` file into the scanner interface.
3. **Hybrid Scan & Triage:**
   * **Bandit** executes an initial static scan to flag potential vulnerabilities.
   * **ChromaDB** retrieves matching OWASP Top 10 rules, NVD severity references, and secure coding patterns.
   * **Qwen 2.5 Coder** evaluates the surrounding code context to suppress false positives, explain contextual risk, and generate a remediated code diff.
4. **Review & Export:** Inspect the prioritized vulnerability report, CVSS risk context, and copy or export the suggested patch.

---

## Team Allocation (Scenario A)

| Member | Role | Core Responsibilities |
| :--- | :--- | :--- |
| **Aloysius** | Local AI Solution Lead | Web UI, Bandit integration, Ollama orchestration, and RAG pipeline |
| **Kieran** | Application Security Specialist | RBAC authentication, prompt injection sanitization, output encoding, and rate limiting |
| **Seth** | Data & Storage Security Specialist | ChromaDB AES-256 encryption at rest, secret management, and masked logging |
| **Jayden** | System & Network Security Specialist | Dockerization (non-root), Nginx TLS reverse proxy, and internal network isolation |

---

## References
* [Qwen2.5-Coder-7B Model Card (Hugging Face)](https://huggingface.co/Qwen/Qwen2.5-Coder-7B)
* [NIST National Vulnerability Database (NVD)](https://nvd.nist.gov/general)
* [Bandit Python SAST Documentation](https://bandit.readthedocs.io/)
