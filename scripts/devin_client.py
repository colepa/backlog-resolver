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
import time
import logging
import requests
import openai

# --------------- Setup ---------------
logger = logging.getLogger(__name__)

DEVIN_SERVICE_TOKEN = os.environ.get("DEVIN_SERVICE_TOKEN", "")
DEVIN_API_BASE_URL = os.environ.get("DEVIN_API_BASE_URL", "https://api.devin.ai")
DEVIN_ORG_ID = os.environ.get("DEVIN_ORG_ID", "")  # e.g. "cole-paris-demo"

# OpenAI client for structured extraction fallback.
_openai_client = openai.OpenAI(api_key=os.environ.get("OPENAI_API_KEY", ""))

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
# Devin v3 Organization API endpoints.
# Docs: https://docs.devin.ai  (org scope)
# The service-user token identifies the org — no org name in the URL.
# ------------------------------------------------------------------
_TRIAGE_ENDPOINT = "/v3/organizations/{org_id}/sessions"
_FIX_TASK_ENDPOINT = "/v3/organizations/{org_id}/sessions"
_POLL_TASK_ENDPOINT = "/v3/organizations/{org_id}/sessions/{session_id}"


_POLL_INTERVAL_SECS = 5
_MAX_POLL_SECS = 300
_TERMINAL_STATUSES = {"finished", "stopped", "failed", "error"}


# --------------- Helpers ---------------

def _url(path: str, **kwargs) -> str:
    """Build a full Devin API URL, filling in {org_id} and any extras."""
    filled = path.format(org_id=DEVIN_ORG_ID, **kwargs)
    return f"{DEVIN_API_BASE_URL.rstrip('/')}{filled}"


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


# --------------- Extraction fallback ---------------

_EXTRACTION_PROMPT = """\
Extract structured triage data from the text below. Return ONLY valid JSON
matching this schema exactly (no extra keys, no comments):

{{
  "summary": "<one-sentence summary>",
  "category": "bug" | "feature" | "chore",
  "severity": "low" | "medium" | "high" | "critical",
  "effort": "S" | "M" | "L",
  "confidence": <float 0-1>,
  "needs_info": [<list of strings>],
  "repro_steps": [<list of strings>],
  "suggested_labels": [<list of strings>],
  "recommended_next_action": "ask_for_info" | "ready_for_dev" | "defer" | "devin_fix",
  "devin_fix_plan": [<list of strings>],
  "risks": [<list of strings>]
}}

If a field cannot be determined, use a sensible default (empty list, "medium",
0.5, etc.).  Do NOT invent information that isn't in the text.

Text:
---
{raw_text}
---
"""


def extract_triage_fields(raw_text: str) -> dict:
    """
    Use OpenAI to extract structured triage JSON from Devin's free-text response.
    This is a fallback for when Devin does not return parseable JSON directly.

    Raises:
        ValueError – if extraction still fails to produce valid JSON.
    """
    logger.info("Running OpenAI extraction fallback (%d chars of input)", len(raw_text))

    resp = _openai_client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {"role": "user", "content": _EXTRACTION_PROMPT.format(raw_text=raw_text)}
        ],
        temperature=0,
        response_format={"type": "json_object"},
    )

    content = resp.choices[0].message.content
    result = json.loads(content)  # guaranteed valid JSON by response_format
    logger.info("Extraction fallback succeeded")
    return result


# --------------- Session polling ---------------

def _poll_session_until_done(session_id: str, timeout: int = _MAX_POLL_SECS) -> dict:
    """
    Poll a Devin session until it reaches a terminal state.
    Returns the full session response dict.

    Raises:
        TimeoutError – if the session does not finish within *timeout* seconds.
        requests.HTTPError – on HTTP failures.
    """
    url = _url(_POLL_TASK_ENDPOINT, session_id=session_id)
    deadline = time.monotonic() + timeout

    while time.monotonic() < deadline:
        resp = _session.get(url)
        resp.raise_for_status()
        data = resp.json()
        status = data.get("status", "").lower()
        logger.info("Session %s status: %s", session_id, status)

        if status in _TERMINAL_STATUSES:
            return data

        time.sleep(_POLL_INTERVAL_SECS)

    raise TimeoutError(f"Session {session_id} did not complete within {timeout}s")


# --------------- Public API ---------------

def triage_issue(prompt: str) -> dict:
    """
    Send a triage prompt to Devin and return the parsed JSON triage result.

    Returns:
        dict with triage fields (summary, category, severity, …)

    Raises:
        ValueError  – if Devin's response is not valid JSON.
        requests.HTTPError – on HTTP failures.
        TimeoutError – if the Devin session does not complete in time.
    """
    logger.info("Sending triage prompt to Devin (%d chars)", len(prompt))

    payload = {
        "prompt": prompt,
        # TODO: add any extra fields the Devin API requires, e.g.:
        # "idempotency_key": "...",
    }

    # 1. Create the Devin session.
    resp = _session.post(_url(_TRIAGE_ENDPOINT), json=payload)
    resp.raise_for_status()
    create_data = resp.json()

    session_id = create_data.get("session_id") or create_data.get("id")
    if not session_id:
        raise ValueError(f"Devin session creation returned no session_id: {create_data}")
    logger.info("Created Devin triage session: %s", session_id)

    # 2. Poll until the session reaches a terminal state.
    data = _poll_session_until_done(session_id)

    # 3. Extract the triage output text.
    # Devin may return the structured answer in different fields.
    # TODO: adjust the key below once you know the real response shape.
    raw_text = data.get("structured_output") or data.get("output") or data.get("result", "")

    if not raw_text:
        # No recognized output field — pass the full response so the
        # extraction fallback has something meaningful to work with.
        raw_text = json.dumps(data)
        logger.warning(
            "No recognized output field in session response; using full response body"
        )

    try:
        triage = _parse_json_from_text(raw_text)
    except (ValueError, json.JSONDecodeError) as exc:
        # Attach the raw text so callers can attempt extraction fallback.
        exc.raw_text = raw_text
        raise
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

    url = _url(_POLL_TASK_ENDPOINT, session_id=session_id)
    resp = _session.get(url)
    resp.raise_for_status()

    result = resp.json()
    return {
        "status": result.get("status", "unknown"),
        "pr_url": result.get("pr_url") or result.get("pull_request_url"),
    }
