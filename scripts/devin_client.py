"""
devin_client.py
---------------
Thin wrapper around the Devin service-user API.

HOW THIS WORKS:
  We authenticate with a **service user token** (not an API key).
  The token is stored in the DEVIN_SERVICE_TOKEN secret and sent as
  a Bearer token in every request.

TODO markers below show the only lines you need to change once Devin
publishes its final endpoint paths. The rest of the business logic in
intake.py stays untouched.
"""

import os
import json
import logging
import requests

# --------------- Setup ---------------
logger = logging.getLogger(__name__)

DEVIN_SERVICE_TOKEN = os.environ.get("DEVIN_SERVICE_TOKEN", "")
DEVIN_API_BASE_URL = os.environ.get("DEVIN_API_BASE_URL", "https://api.devin.ai")

# Reusable session with the service-user Bearer token.
_session = requests.Session()
_session.headers.update(
    {
        "Authorization": f"Bearer {DEVIN_SERVICE_TOKEN}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
)

# ------------------------------------------------------------------
# TODO: Update these paths when Devin publishes final API docs.
#       Only change the strings below — no other code needs editing.
# ------------------------------------------------------------------
_TRIAGE_ENDPOINT = "sessions"
_FIX_TASK_ENDPOINT = "sessions"
_POLL_TASK_ENDPOINT = "sessions/{session_id}"


# --------------- Helpers ---------------

def _url(path: str) -> str:
    """Build a full Devin API URL."""
    return f"{DEVIN_API_BASE_URL.rstrip('/')}{path}"


def _parse_json_from_text(text: str) -> dict:
    """
    Attempt to extract a JSON object from Devin's response text.
    Handles cases where Devin wraps the JSON in markdown fences.
    Raises ValueError if no valid JSON is found.
    """
    # Strip markdown code fences if present.
    cleaned = text.strip()
    if cleaned.startswith("```"):
        # Remove opening fence (with optional language tag) and closing fence.
        lines = cleaned.split("\n")
        # Drop first line (```json) and last line (```)
        lines = [l for l in lines if not l.strip().startswith("```")]
        cleaned = "\n".join(lines).strip()

    return json.loads(cleaned)  # raises ValueError / JSONDecodeError on failure


# --------------- Public API ---------------

def triage_issue(prompt: str) -> dict:
    """
    Send a triage prompt to Devin and return the parsed JSON triage result.

    Returns:
        dict with triage fields (summary, category, severity, …)

    Raises:
        ValueError  – if Devin's response is not valid JSON.
        requests.HTTPError – on HTTP failures.
    """
    logger.info("Sending triage prompt to Devin (%d chars)", len(prompt))

    payload = {
        "prompt": prompt,
        # TODO: add any extra fields the Devin API requires, e.g.:
        # "idempotency_key": "...",
    }

    resp = _session.post(_url(_TRIAGE_ENDPOINT), json=payload)
    resp.raise_for_status()

    data = resp.json()

    # Devin may return the structured answer in different fields.
    # TODO: adjust the key below once you know the real response shape.
    raw_text = data.get("structured_output") or data.get("output") or data.get("result", "")

    triage = _parse_json_from_text(raw_text)
    logger.info("Triage result parsed successfully")
    return triage


def create_fix_task(
    prompt: str,
    repo_full_name: str,
    branch_name: str,
    issue_number: int,
) -> dict:
    """
    Ask Devin to implement a fix and open a PR.

    Returns:
        dict with at least {"session_id": str, "status": str}

    Raises:
        requests.HTTPError – on HTTP failures.
    """
    logger.info(
        "Creating Devin fix task for %s#%s (branch %s)",
        repo_full_name, issue_number, branch_name,
    )

    payload = {
        "prompt": prompt,
        # TODO: add any extra fields required, e.g.:
        # "repository": repo_full_name,
        # "branch": branch_name,
    }

    resp = _session.post(_url(_FIX_TASK_ENDPOINT), json=payload)
    resp.raise_for_status()

    result = resp.json()
    # Normalise the response so callers always get session_id + status.
    return {
        "session_id": result.get("session_id") or result.get("id", "unknown"),
        "status": result.get("status", "queued"),
        "url": result.get("url", ""),
    }


def poll_task(session_id: str) -> dict:
    """
    (Optional) Poll for the status of a running Devin session/task.

    Returns:
        dict with at least {"status": str, "pr_url": str | None}
    """
    logger.info("Polling Devin task %s", session_id)

    url = _url(_POLL_TASK_ENDPOINT.format(session_id=session_id))
    resp = _session.get(url)
    resp.raise_for_status()

    result = resp.json()
    return {
        "status": result.get("status", "unknown"),
        "pr_url": result.get("pr_url") or result.get("pull_request_url"),
    }
