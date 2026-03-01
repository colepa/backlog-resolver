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


def _validate_config() -> None:
    """Fail fast with a clear message if required env vars are missing."""
    missing = []
    if not DEVIN_SERVICE_TOKEN:
        missing.append("DEVIN_SERVICE_TOKEN")
    if not DEVIN_ORG_ID:
        missing.append("DEVIN_ORG_ID")
    if missing:
        raise RuntimeError(
            f"Missing required environment variable(s): {', '.join(missing)}. "
            "Check your GitHub Actions secrets configuration."
        )
    # Masked diagnostics — never log the full token.
    token_preview = DEVIN_SERVICE_TOKEN[:4] + "…" if len(DEVIN_SERVICE_TOKEN) > 4 else "(short)"
    logger.info(
        "Devin config — base_url=%s  org_id=%s  token=%s (len=%d)",
        DEVIN_API_BASE_URL, DEVIN_ORG_ID, token_preview, len(DEVIN_SERVICE_TOKEN),
    )


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
# POST and GET both require {org_id} in the path.
_SESSIONS_ENDPOINT = "/v3/organizations/{org_id}/sessions"
_MESSAGES_ENDPOINT = "/v3/organizations/{org_id}/sessions/{session_id}/messages"


_POLL_INTERVAL_SECS = 5
_MAX_POLL_SECS = 300
_TERMINAL_STATUSES = {"finished", "completed", "stopped", "failed", "error"}


# --------------- Helpers ---------------

def _url(path: str, **kwargs) -> str:
    """Build a full Devin API URL, filling in {org_id} and any extras."""
    filled = path.format(org_id=DEVIN_ORG_ID, **kwargs)
    return f"{DEVIN_API_BASE_URL.rstrip('/')}{filled}"


def _raise_with_details(resp: requests.Response) -> None:
    """Call raise_for_status but include the response body in the error for diagnostics."""
    try:
        resp.raise_for_status()
    except requests.HTTPError as exc:
        # Capture the response body — APIs often include a reason in JSON.
        body = ""
        try:
            body = resp.text[:500]
        except Exception:
            pass
        logger.error(
            "HTTP %s from %s %s — body: %s",
            resp.status_code, resp.request.method, resp.url, body,
        )
        raise requests.HTTPError(
            f"{resp.status_code} {resp.reason} for {resp.url} — response: {body}",
            response=resp,
        ) from exc


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

def _get_session(session_id: str) -> dict | None:
    """
    Fetch a single Devin session by ID from the list endpoint.
    The single-session GET returns 403 for service-user tokens,
    so we list and filter instead.
    """
    url = _url(_SESSIONS_ENDPOINT)
    resp = _session.get(url)
    _raise_with_details(resp)
    data = resp.json()
    # The v3 API returns sessions under the "sessions" key.
    items = data.get("sessions") or data.get("items") or []
    for item in items:
        if item.get("session_id") == session_id:
            return item
    return None


def _get_session_messages(session_id: str) -> list[dict]:
    """
    Fetch messages for a Devin session.
    Returns a list of message dicts (may be empty).
    Each message has: created_at, event_id, message, source.
    """
    url = _url(_MESSAGES_ENDPOINT, session_id=session_id)
    resp = _session.get(url)
    _raise_with_details(resp)
    data = resp.json()
    return data.get("items") or []


def _find_devin_response(messages: list[dict]) -> str | None:
    """
    Walk messages (newest-first) and return the first response from Devin.
    Per the API docs, each message has 'source' and 'message' fields.
    """
    for msg in reversed(messages):
        if msg.get("source") != "devin":
            continue
        body = msg.get("message", "")
        if body.strip():
            return body.strip()
    return None


def _poll_session_until_done(
    session_id: str,
    timeout: int = _MAX_POLL_SECS,
) -> tuple[dict, str]:
    """
    Poll a Devin session's messages until Devin responds or the session
    reaches a terminal status.

    Returns:
        (session_dict, devin_response_text)

    Raises:
        TimeoutError – if no response within *timeout* seconds.
        requests.HTTPError – on HTTP failures.
    """
    logger.info("Polling session %s messages (timeout=%ds)", session_id, timeout)
    deadline = time.monotonic() + timeout

    while time.monotonic() < deadline:
        # Check messages for a Devin response.
        try:
            messages = _get_session_messages(session_id)
            logger.info("Session %s: %d message(s)", session_id, len(messages))
            devin_text = _find_devin_response(messages)
            if devin_text:
                logger.info(
                    "Session %s: found Devin response (%d chars)",
                    session_id, len(devin_text),
                )
                # Grab session metadata too (best-effort).
                session_data = _get_session(session_id) or {}
                return session_data, devin_text
        except Exception as exc:
            logger.warning("Messages poll error for %s: %s", session_id, exc)

        # Also check if the session reached a terminal status (e.g. failed).
        try:
            session_data = _get_session(session_id)
            if session_data:
                status = session_data.get("status", "").lower()
                if status in _TERMINAL_STATUSES:
                    logger.info("Session %s reached terminal status: %s", session_id, status)
                    return session_data, ""
        except Exception:
            pass

        time.sleep(_POLL_INTERVAL_SECS)

    raise TimeoutError(f"Session {session_id} did not produce a response within {timeout}s")


# --------------- Public API ---------------

def preflight_auth_check() -> None:
    """
    Validate that required Devin env vars are present.
    We skip a network call because the Devin API returns 403 on GET
    with org_id and 404 without it — the POST to create a session
    is the real auth check.

    Raises:
        RuntimeError – if required env vars are missing.
    """
    _validate_config()
    logger.info("Preflight config check passed")


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
    _validate_config()
    logger.info("Sending triage prompt to Devin (%d chars)", len(prompt))

    # Track raw response data so we can attach it to any exception for the
    # OpenAI extraction fallback in intake.py.
    _last_response_body = ""

    try:
        payload = {
            "prompt": prompt,
            # TODO: add any extra fields the Devin API requires, e.g.:
            # "idempotency_key": "...",
        }

        # 1. Create the Devin session.
        #    Disable auto-redirects so requests doesn't strip the Auth header
        #    if the API returns a 3xx pointing at the new session URL.
        url = _url(_SESSIONS_ENDPOINT)
        logger.info("POST %s", url)
        resp = _session.post(url, json=payload, allow_redirects=False)
        _last_response_body = resp.text
        logger.info(
            "POST response: status=%s location=%s body=%.300s",
            resp.status_code, resp.headers.get("Location", "(none)"), _last_response_body,
        )

        # If the API redirects (e.g. 303 See Other), follow manually with auth.
        if resp.is_redirect or resp.status_code in (201, 303):
            redirect_url = resp.headers.get("Location")
            if redirect_url and resp.status_code in (301, 302, 303, 307, 308):
                logger.info("Following redirect to %s", redirect_url)
                resp = _session.get(redirect_url)  # _session keeps auth headers
                _last_response_body = resp.text

        _raise_with_details(resp)
        create_data = resp.json()
        logger.info("Session creation response keys: %s", list(create_data.keys()))

        # --- Diagnostic: dump session creation response so we can find auth/polling hints ---
        for key, val in create_data.items():
            preview = str(val)[:200] if val is not None else "None"
            logger.info(
                "SESSION CREATE  key=%-25s  type=%-10s  preview=%s",
                key, type(val).__name__, preview,
            )
        # --- End diagnostic ---

        session_id = create_data.get("session_id") or create_data.get("id")
        if not session_id:
            raise ValueError(f"Devin session creation returned no session_id: {create_data}")
        logger.info("Created Devin triage session: %s", session_id)

        # 2. Poll messages until Devin responds.
        data, raw_text = _poll_session_until_done(session_id)
        _last_response_body = raw_text or json.dumps(data)

        if not raw_text:
            # Terminal status reached but no message content found.
            # Fall back to session-level fields or full response body.
            raw_text = (
                data.get("structured_output")
                or data.get("output")
                or data.get("result")
                or json.dumps(data)
            )
            logger.warning(
                "No Devin message found; falling back to session data (%d chars)",
                len(raw_text),
            )

        logger.info("Raw triage text (%d chars): %.300s", len(raw_text), raw_text)

        triage = _parse_json_from_text(raw_text)
        logger.info("Triage result parsed successfully")
        return triage

    except (ValueError, json.JSONDecodeError) as exc:
        # Attach whatever response data we have so the caller's OpenAI
        # extraction fallback has something meaningful to work with.
        exc.raw_text = _last_response_body
        logger.error(
            "triage_issue failed (%s). Attached raw_text (%d chars): %.300s",
            exc, len(_last_response_body), _last_response_body,
        )
        raise


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
    _validate_config()
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

    resp = _session.post(_url(_SESSIONS_ENDPOINT), json=payload)
    _raise_with_details(resp)

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
    _validate_config()
    logger.info("Polling Devin task %s", session_id)

    result = _get_session(session_id)
    if result is None:
        return {"status": "unknown", "pr_url": None}

    pr_url = None
    for pr in result.get("pull_requests", []):
        pr_url = pr.get("url") or pr.get("html_url")
        if pr_url:
            break

    return {
        "status": result.get("status", "unknown"),
        "pr_url": pr_url,
    }
