"""Vercel entrypoint. Vercel looks for an `app` object in a file like this at the repo root.

The service itself is app/main.py; this only re-exports it. (It cannot be called app.py, which would
collide with the app/ package.)
"""
from app.main import app  # noqa: F401
