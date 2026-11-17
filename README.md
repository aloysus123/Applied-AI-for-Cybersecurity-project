# Local AI-Assisted Hybrid Code Vulnerability Scanner

## Problem Statement
Security operations and development teams face severe **alert fatigue** when relying on traditional Static Application Security Testing (SAST) tools. While deterministic scanners catch surface-level flaws, they frequently generate high volumes of false positives without providing actionable remediation context. 

Conversely, while cloud-based Large Language Models (LLMs) excel at analyzing code semantics and generating fixes, uploading proprietary corporate source code to third-party cloud APIs violates strict data privacy policies and creates an unacceptable risk of **intellectual property (IP) leakage**.

## Proposed Solution
Developed as a Proof-of-Concept (PoC) for **IT2527 Applied AI for Cybersecurity**[cite: 1, 2], this project delivers a completely **air-gapped, hybrid vulnerability scanner** that pairs deterministic SAST screening with a Local AI reasoning engine.

1. **Deterministic SAST Screening (`Bandit`):** Scans target Python source code locally to pinpoint exact line numbers, CWE classifications, and baseline severity/confidence ratings without guesswork.
2. **Grounded Knowledge Retrieval (`RAG`):** Uses a local vector database (`ChromaDB`) to cross-reference Bandit's findings against curated **OWASP Top 10** guidelines, **NVD** reference data, and verified remediation patch datasets[cite: 2].
3. **Local AI Triage & Remediation (`Qwen 2.5 Coder`):** Feeds the structured SAST findings and retrieved security context into a locally hosted `qwen2.5-coder` model via **Ollama**. The model filters out false positives, contextualizes CVSS risk severity, and generates secure, context-aware code patches—operating 100% on local hardware to guarantee **zero IP leakage**[cite: 2].

---

## Technology Stack
* **Static Analysis (SAST):** Bandit (Python AST-based security linter)
* **Local AI Engine:** [Ollama](https://ollama.com/) running `qwen2.5-coder:7b` (or `qwen2.5-coder:3b` for 4GB VRAM profiles)[cite: 2]
* **Vector Database (RAG):** ChromaDB[cite: 2]
* **UI / Frontend:** Python (Streamlit / Flask)[cite: 2]
* **Security Infrastructure:** Nginx (Reverse Proxy), Docker & Docker Compose, AES-256 Data Encryption

## Defense-in-Depth Architecture
To protect the local AI pipeline against adversarial threats[cite: 2], security controls are enforced across three architectural layers[cite: 2]:

1. **Application Layer[cite: 2]:** Input sanitization against direct and indirect prompt injection (scrubbing untrusted code comments and Bandit outputs before LLM ingestion), output encoding, Role-Based Access Control (RBAC), and LLM query rate-limiting.
2. **Data & Storage Layer[cite: 2]:** AES-256 encryption at rest for the ChromaDB vector store and local NVD/OWASP datasets, secure environment variable management, and masked application logging.
3. **System & Network Layer[cite: 2]:** Containerized deployment with non-root privileges, Nginx reverse proxy enforcing local TLS/SSL, and internal Docker network isolation restricting Ollama API access exclusively to the backend.

## Prerequisites
* **OS:** Linux / Windows (WSL2) / macOS
* **Hardware:** Minimum 32GB RAM; Dedicated GPU (6GB+ VRAM recommended for `7b`, or 4GB VRAM for `3b`)
* **Software:** Python 3.10+, Docker, Docker Compose, Ollama

## Setup & Installation

### 1. Install and Start Ollama
Download and install Ollama from [ollama.com](https://ollama.com/), then pull the Qwen 2.5 Coder model:
```bash
ollama run qwen2.5-coder:7b
# For 4GB VRAM hardware profiles, use the 3B model instead:
# ollama run qwen2.5-coder:3b
2. Clone the Repository
Bash
git clone [https://github.com/your-org/local-ai-vuln-scanner.git](https://github.com/your-org/local-ai-vuln-scanner.git)
cd local-ai-vuln-scanner
3. Environment Setup
Create a virtual environment and install dependencies (including bandit and chromadb):

Bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
4. Vector Database Initialization
Ingest the OWASP Top 10, NVD reference records, and remediation patch datasets into the encrypted local ChromaDB instance:

Bash
python scripts/ingest_dataset.py
5. Run the Application
Start the isolated application stack (Frontend, Bandit Worker, ChromaDB, Ollama Bridge, Nginx Proxy) using Docker Compose:

Bash
docker-compose up --build
Access the web portal securely at https://localhost:8443.

Usage Workflow
Authenticate: Log in to the web portal using authorized RBAC credentials.

Submit Code: Paste a Python code snippet or upload a .py file into the scanner interface.

Hybrid Scan & Triage:

Bandit executes an initial static scan to flag potential vulnerabilities.

ChromaDB retrieves matching OWASP Top 10 rules, NVD severity references, and secure coding patterns.

Qwen 2.5 Coder evaluates the code context to suppress false positives, explain contextual risk, and generate a remediated code diff.

Review & Patch: Inspect the prioritized vulnerability report, CVSS risk context, and copy or export the suggested patch.

Team Allocation (Scenario A)
Aloysius – Local AI Solution Lead (Web UI, Bandit Integration, Ollama & RAG Pipeline)   
26S2 IT2527 Project Guide.pdf

Kieran – Application Security Specialist (RBAC, Prompt Injection Defense, Rate Limiting)   
26S2 IT2527 Project Guide.pdf

Seth – Data & Storage Security Specialist (ChromaDB AES-256 Encryption, Secret Management)   
26S2 IT2527 Project Guide.pdf

Jayden – System & Network Security Specialist (Dockerization, Nginx TLS Proxy, Network Isolation)   
26S2 IT2527 Project Guide.pdf

References
Qwen2.5-Coder-7B Model Card (Hugging Face)

NIST National Vulnerability Database (NVD)

Bandit Python SAST Documentation
