# Local AI-Assisted Code Vulnerability Scanner

## Project Overview
This project is a Proof-of-Concept (PoC) for the **IT2527 Applied AI for Cybersecurity** module. It is a completely offline, local AI solution designed to scan developer code snippets for security vulnerabilities (e.g., OWASP Top 10) and provide grounded, accurate remediation advice. 

To ensure data privacy and operational security, this solution relies entirely on local hardware, avoiding third-party cloud APIs. It utilizes a Retrieval-Augmented Generation (RAG) pipeline backed by curated vulnerability patch datasets to ensure the AI's recommendations are factually anchored.

## Technology Stack
*   **AI Engine:** [Ollama](https://ollama.com/) running `qwen2.5-coder` (optimized for 4GB VRAM/32GB RAM hardware profiles).
*   **UI/Frontend:** Python (Streamlit / Flask)
*   **Vector Database (RAG):** ChromaDB / FAISS
*   **Security Infrastructure:** Nginx (Reverse Proxy), Docker, AES-256 Data Encryption.

## Defense-in-Depth Architecture
This solution incorporates security controls across three critical layers to protect the AI pipeline:

1.  **Application Layer:** Input sanitization against prompt injection, output encoding, user authentication (RBAC), and LLM query rate-limiting.
2.  **Data & Storage Layer:** AES-256 encryption at rest for the RAG vector database, secure environment variable management, and masked application logging.
3.  **System & Network Layer:** Containerized deployment with non-root privileges, Nginx reverse proxy enforcing local TLS/SSL, and firewall isolation restricting Ollama API access exclusively to the backend.

## Prerequisites
*   OS: Linux / Windows (WSL2) / macOS
*   Hardware: Minimum 32GB RAM, Dedicated GPU (NVIDIA T400 4GB or better recommended).
*   Software: Python 3.10+, Docker, Docker Compose, Ollama.

## Setup & Installation

### 1. Install and Start Ollama
Download and install Ollama from [ollama.com](https://ollama.com/).
Pull the Qwen 2.5 Coder model:
```bash
ollama run qwen2.5-coder:3b
# Or use the 7b model if hardware permits: ollama run qwen2.5-coder:7b
```

### 2. Clone the Repository
```bash
git clone https://github.com/your-org/local-ai-vuln-scanner.git
cd local-ai-vuln-scanner
```

### 3. Environment Setup
Create a virtual environment and install dependencies:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 4. Vector Database Initialization
Run the ingestion script to populate the local RAG database with the vulnerability patch dataset:
```bash
python scripts/ingest_dataset.py
```

### 5. Run the Application
Start the secure application stack (UI, Proxy, DB) using Docker Compose:
```bash
docker-compose up --build
```
The application will be accessible at `https://localhost:8443`.

## Usage
1. Log in to the portal using your authorized credentials.
2. Paste the target code snippet (Python, Java, JavaScript, C++) into the scanner interface.
3. The system will retrieve similar known vulnerabilities from the vector DB and prompt `qwen2.5-coder` to analyze your code.
4. Review the generated vulnerability report and suggested code patches.

## Team Allocation (Scenario A)
*   **Aloysius** - Local AI Solution Lead (UI, Ollama, RAG Pipeline)
*   **Kieran** - Application Security Specialist (RBAC, Prompt Injection Defense, Rate Limiting)
*   **Seth** - Data & Storage Security Specialist (Vector DB Encryption, Secret Management)
*   **Jayden** - System & Network Security Specialist (Dockerization, Nginx, Network Isolation)

links:
https://huggingface.co/Qwen/Qwen2.5-Coder-7B
https://nvd.nist.gov/general
