# 🛡️ Threat Intelligence Platform

A high-performance **FastAPI** backend for a collaborative Cyber Threat Intelligence (CTI) platform. This service handles continuous monitoring and data ingestion from external collectors (Telegram, Bing News), orchestrates AI triage and IoC extraction via **Google Gemma 2** or **Groq LLaMA/Qwen**, and provides a unified Analyst Dashboard for real-time alerting.

---

## ✨ Features

- **Continuous OSINT Polling:** Fetches structured RSS/Atom feeds from Bing News and Telegram (via RSS-Bridge) dynamically.
- **AI-Powered Triage:** Configurable AI engine. Choose between **Google Gemma 2** (via AI Studio) or **Groq (Qwen/LLaMA)** for rapid-fire threat parsing.
- **Scenario Matching Engine:** Pass specific alert scenarios (e.g., `"US drops bomb on Iran"`) and the AI will use Chain-of-Thought reasoning to detect strict logical matches and ignore hallucinated noise.
- **Alert Log & Popups:** The UI tracks active sessions, triggers OS-level notifications, and logs verified threats instantly.
- **Light/Dark Mode UI:** Built-in Tailwind dashboard with full memory persistence.

---

## 🏗️ Quickstart / Deployment

The application is fully containerized and production-ready.

### Option 1: Docker (Recommended)
```bash
# 1. Clone the repository
git clone <repo-url>
cd Threat\ Intel

# 2. Add your API Keys
cp .env.example .env
# Edit .env and insert your GEMINI_API_KEY and GROQ_API_KEY

# 3. Spin up the container
docker-compose up -d --build
```
*The dashboard will be available at `http://localhost:8000`*

### Option 2: Local Python Environment
```bash
# 1. Set up virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. Set up environment variables
cp .env.example .env

# 4. Run the Uvicorn ASGI server
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

---

## 📡 API Contract

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/api/v1/analyze` | Ingest raw chatter from scrapers for asynchronous Gemma/Groq analysis. |

**Example cURL Payload:**
```bash
curl -X 'POST' \
  'http://localhost:8000/api/v1/analyze' \
  -H 'Content-Type: application/json' \
  -d '{
  "source_type": "bing",
  "query": "ransomware",
  "scenarios": ["data breach of a major healthcare provider"],
  "limit": 5,
  "provider": "groq"
}'
```

---

## 🔐 Environment Variables

The project uses a `.env` file for secrets. 
* `GEMINI_API_KEY`: Generates analysis via Google's `gemma-2-27b-it` / `gemma-2-9b-it` endpoints.
* `GROQ_API_KEY`: Generates ultra-fast analysis via `qwen/qwen3.8-27b` / `allam-2-7b`.

*(Note: If no keys are provided, the backend falls back to a simulated Mock Mode for UI testing).*
