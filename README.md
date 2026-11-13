# TrustIssues

A browser-based refund-support agent you can trust with your money. Customers submit refund requests and an AI agent handles them, but the refund decision is made by code outside the AI: no refund over $100, no more than $500 a week, and every action is logged. All data is synthetic.

CSEN 296 AI Governance and Cybersecurity, Fall 2026, Team 6.

## Run it

    python3 -m venv .venv && source .venv/bin/activate
    pip install -r requirements.txt
    echo "ANTHROPIC_API_KEY=your-key" > .env
    export TRUSTISSUES_ADMIN_TOKEN="a-token-of-16-or-more-characters"
    uvicorn app.main:app --port 8000

Then open http://localhost:8000. See `run_instructions.md` for more.

## Folders

- `app/` the service and agents
- `blueteam/` defenses and findings
- `redteam/` attack tests and evidence
- `threat_model/` the threat model
- `tests/` automated tests
