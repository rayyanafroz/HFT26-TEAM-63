# ShadowLens (working title)
### AI Shadow IT & Agentic Data Exfiltration Scanner

CBIT Hacktoberfest '26 · Team PowerPuff Girls (TEAM-63) · Domain: AI Security & Data Privacy · Difficulty: Advanced

ShadowLens is a local, passive desktop app. It finds which AI tools are running on a machine (OpenAI, Anthropic, Ollama, Hugging Face and more), automatically inspects the text it can legitimately read (AI tool transcripts and local model traffic, plus uploaded logs) for leaked secrets and personal data, flags risky autonomous-agent behavior (shell commands, sensitive file reads), and shows everything on a privacy-first local dashboard with an explainable risk score. It needs no SSL decryption and no agent installed on other machines, and it states clearly what it cannot see.

**Everything about how we build it is in [SOT.md](SOT.md).** Read that file first.

## Quickstart

```
git clone https://github.com/rayyanafroz/HFT26-TEAM-63.git && cd HFT26-TEAM-63
py -3.11 -m venv .venv
.venv\Scripts\python -m pip install -r requirements.txt
copy .env.example .env
.venv\Scripts\python -m shadowlens                         # opens the desktop window (--browser: use http://127.0.0.1:8787)
```

Windows 10/11 is the supported platform (macOS/Linux: best effort). The code is being built; this will work once the backend skeleton is merged.

## Attribution

Third-party libraries and their licenses will be listed here before submission (FastAPI, uvicorn, pydantic, PyYAML, psutil, httpx, dpkt, Chart.js, and any public secret-pattern sets used as reference).

---

# Hackathon information (from the official starter)

## Team

| Attribute | Details |
| :--- | :--- |
| **Team Name** | **PowerPuff Girls** |
| **Team Number** | `TEAM-63` (`HFT26-TEAM-63`) |
| **Registration ID** | `HFEST26-TKZFEDTW` |
| **Problem Track** | **#4 AI Shadow IT & Agentic Data Exfiltration Scanner** |
| **Domain** | `AI Security & Data Privacy` |
| **Team Leader** | Afzal Hashmi Syed (afzalsyed.hs@gmail.com) |
| **Institution** | Muffakham Jah College of Engineering and Technology |

| # | Name | Email | Institution |
| :--- | :--- | :--- | :--- |
| 1 | Soha Alam Khan | sohaalam0123@gmaiil.com | Muffakham Jah College of Engineering and Technology |
| 2 | Misbah Hussain | misbahhussain1007@gmail.com | Muffakham Jah College of Engineering and Technology |
| 3 | Saleha Baseer | salehabaseer@gmail.com | Muffakham Jah College of Engineering and Technology |
| 4 | Rayyan Ahmed | rayyanafroz.ahmed1233@gmail.com | Muffakham Jah College of Engineering and Technology |

## Contribution and submission workflow

Work on feature branches in this fork; never commit directly to `main`. The final submission is a pull request from this fork's `main` to the upstream repository's `main`.

- **PR title:** `[SUBMISSION] TEAM-63 - PowerPuff Girls - AI Shadow IT & Agentic Data Exfiltration Scanner`
- **PR description:** solution overview and approach · architecture and tech stack · local setup and installation · demo video / live URL · key screenshots

## Rules and code of conduct

* **Upstream protection:** do not push directly to the upstream repository's main branch. Evaluation is on the submitted pull request.
* **Original work:** all code must be developed during the hackathon. Open-source libraries are welcome with proper attribution.
* **Code freeze:** the final pull request must be submitted before the official deadline.
