"""quick check: loads ANTHROPIC_API_KEY from .env and makes one call to Claude.

never prints the key for obvious reasons.

run it with: .venv\Scripts\python scripts\check_claude.py

P.S: If you are not using an ANTHROPIC API key then this will not work on your end. 
Talk to me if you really cannot use ANTHROPIC. 
"""

import os
import sys
from pathlib import Path

import anthropic
from dotenv import load_dotenv

MODEL = "claude-opus-5-5"

load_dotenv(Path(__file__).resolve().parent.parent / ".env")

if not os.getenv("ANTHROPIC_API_KEY"):
    print("key loaded: no")
    sys.exit(1)
print("key loaded: yes")

client = anthropic.Anthropic()

try:
    response = client.beta.messages.create(
        model=MODEL,
        max_tokens=1024,
        # if Opus 5.5 refuses because of a safety classifier, the API retries on a fallback model
        betas=["server-side-fallback-2026-07-01"],
        fallbacks="default",
        messages=[{"role": "user", "content": "Say hello in one short sentence."}],
    )
except anthropic.AuthenticationError:
    print("error: API key was rejected (401)")
    sys.exit(1)
except anthropic.PermissionDeniedError:
    print("error: key lacks permission for this model (403)")
    sys.exit(1)
except anthropic.NotFoundError as e:
    print(f"error: not found (404): {e.message}")
    sys.exit(1)
except anthropic.RateLimitError:
    print("error: rate limited (429)")
    sys.exit(1)
except anthropic.APIStatusError as e:
    print(f"error: API returned {e.status_code}: {e.message}")
    sys.exit(1)
except anthropic.APIConnectionError as e:
    print(f"error: could not reach the API: {e}")
    sys.exit(1)

if response.stop_reason == "refusal":
    print(f"refused: {response.stop_details}")
    sys.exit(1)

text = "".join(b.text for b in response.content if b.type == "text")
print(f"model:  {response.model}")
print(f"reply:  {text}")
print(f"tokens: {response.usage.input_tokens} in / {response.usage.output_tokens} out")
print(f"request id: {response._request_id}")
