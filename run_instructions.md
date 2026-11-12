# Run Instructions (Local, Safe)

## Prereqs
- Python 3.10+
- pip

## Install
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

## Start server
uvicorn app.main:app --reload --port 8000

## Endpoints
- POST /tasks -> submit a task for the agent to plan and (safely) simulate execution
- GET /logs -> view structured JSON logs (for demo)
- POST /tests/rt-01 -> run a safe red-team simulation (hallucination detection) in sandbox

All tests are safe, local-only, and use canned test data.

## Auto-demo walkthrough script (`run_demo.py`)

This repository includes a convenience walkthrough script `run_demo.py` that will call the local demo endpoints and collect sanitized evidence results in `redteam/results/`.

### Usage

1. Ensure you are in the project root (where `app/`, `run_instructions.md` are located).
2. Create and activate a Python virtual environment, install deps, and `requests`:
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt requests
```
3. Run the demo script. If you already started the server separately (via `uvicorn app.main:app --reload --port 8000`), run:
```bash
python run_demo.py --base-url http://localhost:8000
```
Alternatively, let the script start the dev server for you (development only):
```bash
python run_demo.py --base-url http://localhost:8000 --start-server
```
4. After completion, evidence will be saved under `redteam/results/collected_evidence_<ts>.json`.

**Notes & safety:** The script only calls local endpoints in this starter repo and redacts obvious tokens before saving evidence. Do not use `--start-server` on production systems.

---

## Data, retrieval and detection (Blue: Vaishnavi)

- Use Python 3.10 to 3.12. The pinned pydantic 1.10 does not run on 3.13.
- Set `TRUSTISSUES_ADMIN_TOKEN` (16+ characters) before starting the server to enable the `/admin/*` routes.
- The first start creates `logs/rag.db` with the seed refund policy and synthetic customers.
- Tests: `pip install -r requirements-dev.txt` then `python -m pytest -q`.
- Detection evidence: `python blueteam/data_and_detection/run_detection_eval.py`.
- Details and integration notes: `blueteam/data_and_detection/README.md`.
