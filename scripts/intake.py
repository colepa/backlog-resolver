"""
intake.py – Single entrypoint for the Issue Intake workflow
-----------------------------------------------------------
This script is called by the GitHub Actions workflow whenever an issue
is opened, edited, or reopened.  It:

  1. Fetches the issue + recent comments from GitHub.
  2. Sends a triage prompt to Devin → gets structured JSON back.
  3. Posts a "Triage Report" comment and applies labels.
  4. If the triage recommends a Devin fix (and safety checks pass),
     queues Devin to implement the fix and open a PR.

Environment variables (set by the workflow):
  GITHUB_TOKEN        – default Actions token
  DEVIN_SERVICE_TOKEN – Devin service-user token
  DEVIN_API_BASE_URL  – base URL for Devin API
  DEVIN_FIX_ENABLED   – "true" (default) or "false"
  ISSUE_NUMBER        – the issue that triggered the workflow
  REPO_FULL_NAME      – "owner/repo"
"""

import os
import re
import sys
import json
import logging

# -- Our helper modules (same `scripts/` package) --
from scripts.github_client import (
    get_issue,
    get_issue_comments,
    get_issue_labels,
    add_labels,
    post_comment,
)
from scripts.devin_client import triage_issue, create_fix_task, extract_triage_fields
from scripts.prompt_templates import TRIAGE_PROMPT, FIX_PROMPT

# --------------- Logging ---------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("intake")

# --------------- Config from env ---------------
ISSUE_NUMBER = int(os.environ.get("ISSUE_NUMBER", "0"))
REPO_FULL_NAME = os.environ.get("REPO_FULL_NAME", "")
DEVIN_FIX_ENABLED = os.environ.get("DEVIN_FIX_ENABLED", "true").lower() == "true"


# ====================================================================
# Helper functions
# ====================================================================

def _slugify(text: str, max_len: int = 40) -> str:
    """Turn arbitrary text into a short, branch-safe slug."""
    slug = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return slug[:max_len]


def _format_comments_for_prompt(comments: list[dict]) -> str:
    """Convert a list of GitHub comment dicts into readable text."""
    if not comments:
        return "(no comments yet)"
    lines = []
    for c in comments:
        user = c.get("user", {}).get("login", "unknown")
        body = c.get("body", "").strip()
        lines.append(f"**@{user}:** {body}")
    return "\n\n".join(lines)


def _build_triage_comment(triage: dict) -> str:
    """
    Build a nice Markdown comment from the triage dict.
    This is what gets posted on the issue.
    """
    # Helper to render a list field as bullet points.
    def bullets(items: list) -> str:
        if not items:
            return "_none_"
        return "\n".join(f"- {item}" for item in items)

    severity = triage.get("severity", "unknown")
    confidence_pct = int(triage.get("confidence", 0) * 100)

    return f"""\
## 🔍 Triage Report

| Field | Value |
|-------|-------|
| **Category** | `{triage.get('category', '?')}` |
| **Severity** | `{severity}` |
| **Effort** | `{triage.get('effort', '?')}` |
| **Confidence** | {confidence_pct}% |
| **Next action** | `{triage.get('recommended_next_action', '?')}` |

### Summary
{triage.get('summary', 'N/A')}

### Reproduction Steps
{bullets(triage.get('repro_steps', []))}

### Needs More Info
{bullets(triage.get('needs_info', []))}

### Suggested Labels
{bullets(triage.get('suggested_labels', []))}

### Risks
{bullets(triage.get('risks', []))}

### Devin Fix Plan
{bullets(triage.get('devin_fix_plan', []))}

---
_Automated triage by Devin service user._
"""


def _compute_labels(triage: dict) -> list[str]:
    """Decide which labels to apply based on the triage result."""
    labels: list[str] = ["devin:triaged"]

    # Priority label from severity.
    severity_map = {
        "low": "prio:low",
        "medium": "prio:med",
        "high": "prio:high",
        "critical": "prio:critical",
    }
    sev = triage.get("severity", "").lower()
    if sev in severity_map:
        labels.append(severity_map[sev])

    # Effort label.
    effort = triage.get("effort", "").upper()
    if effort in ("S", "M", "L"):
        labels.append(f"effort:{effort}")

    # Needs-info label.
    if triage.get("needs_info"):
        labels.append("needs-info")

    # Devin-fix label.
    if triage.get("recommended_next_action") == "devin_fix":
        labels.append("devin:fix")

    return labels


def _should_auto_fix(triage: dict) -> bool:
    """
    Return True only when ALL safety conditions are met:
      - recommended_next_action == "devin_fix"
      - effort == "S"
      - confidence >= 0.7
      - needs_info is empty
      - DEVIN_FIX_ENABLED is true
    """
    if not DEVIN_FIX_ENABLED:
        logger.info("Auto-fix is disabled via DEVIN_FIX_ENABLED=false")
        return False

    action = triage.get("recommended_next_action")
    effort = triage.get("effort", "").upper()
    confidence = float(triage.get("confidence", 0))
    needs_info = triage.get("needs_info", [])

    ok = (
        action == "devin_fix"
        and effort == "S"
        and confidence >= 0.7
        and len(needs_info) == 0
    )
    logger.info(
        "Auto-fix check: action=%s effort=%s confidence=%.2f needs_info=%s → %s",
        action, effort, confidence, needs_info, ok,
    )
    return ok


# ====================================================================
# Main orchestration
# ====================================================================

def run() -> None:
    """Main entry point — called at the bottom of this file."""

    # ---- 0. Validate env ----
    if not ISSUE_NUMBER or not REPO_FULL_NAME:
        logger.error("ISSUE_NUMBER and REPO_FULL_NAME must be set. Exiting.")
        sys.exit(1)

    logger.info("=== Issue Intake: %s#%s ===", REPO_FULL_NAME, ISSUE_NUMBER)

    # ---- 1. Loop guard: skip if already triaged ----
    existing_labels = get_issue_labels(REPO_FULL_NAME, ISSUE_NUMBER)
    if "devin:triaged" in existing_labels:
        logger.info("Issue already has 'devin:triaged' label — skipping.")
        return

    # ---- 2. Fetch issue data ----
    issue = get_issue(REPO_FULL_NAME, ISSUE_NUMBER)
    title = issue.get("title", "(no title)")
    body = issue.get("body", "") or ""

    comments_raw = get_issue_comments(REPO_FULL_NAME, ISSUE_NUMBER, limit=10)
    comments_text = _format_comments_for_prompt(comments_raw)

    # ---- 3. Build prompt & call Devin for triage ----
    prompt = TRIAGE_PROMPT.format(
        title=title,
        body=body,
        comments=comments_text,
    )

    try:
        triage = triage_issue(prompt)
    except (ValueError, json.JSONDecodeError) as exc:
        # Devin returned something that is not valid JSON.
        # Fall back to OpenAI extraction from the raw response.
        logger.warning("Triage JSON parse failed: %s — trying OpenAI extraction", exc)
        try:
            raw_text = getattr(exc, "raw_text", "") or str(exc)
            triage = extract_triage_fields(raw_text)
        except Exception as extract_exc:
            logger.error("OpenAI extraction also failed: %s", extract_exc)
            post_comment(
                REPO_FULL_NAME,
                ISSUE_NUMBER,
                "⚠️ **Triage failed** — Devin returned invalid JSON and "
                "the OpenAI extraction fallback also failed. "
                "A maintainer will triage this issue manually.",
            )
            return
    except TimeoutError as exc:
        logger.error("Triage session timed out: %s", exc)
        post_comment(
            REPO_FULL_NAME,
            ISSUE_NUMBER,
            f"⚠️ **Triage failed** — Devin session timed out. Error: `{exc}`",
        )
        return
    except Exception as exc:
        logger.error("Triage request failed: %s", exc)
        post_comment(
            REPO_FULL_NAME,
            ISSUE_NUMBER,
            f"⚠️ **Triage failed** — could not reach Devin service. Error: `{exc}`",
        )
        return

    # ---- 4. Post triage comment & labels ----
    comment_body = _build_triage_comment(triage)
    post_comment(REPO_FULL_NAME, ISSUE_NUMBER, comment_body)

    labels = _compute_labels(triage)
    add_labels(REPO_FULL_NAME, ISSUE_NUMBER, labels)
    logger.info("Triage complete. Labels applied: %s", labels)

    # ---- 5. Auto-fix (only when safe) ----
    if not _should_auto_fix(triage):
        logger.info("Auto-fix conditions not met — done.")
        return

    logger.info("Auto-fix conditions met — queuing Devin fix task.")

    branch_name = f"devin/fix-{ISSUE_NUMBER}-{_slugify(title)}"
    fix_plan_text = "\n".join(
        f"{i+1}. {step}" for i, step in enumerate(triage.get("devin_fix_plan", []))
    )

    fix_prompt = FIX_PROMPT.format(
        repo_full_name=REPO_FULL_NAME,
        issue_number=ISSUE_NUMBER,
        title=title,
        body=body,
        summary=triage.get("summary", ""),
        fix_plan=fix_plan_text,
        branch_name=branch_name,
    )

    try:
        task = create_fix_task(
            prompt=fix_prompt,
            repo_full_name=REPO_FULL_NAME,
            branch_name=branch_name,
            issue_number=ISSUE_NUMBER,
        )
        session_id = task.get("session_id", "unknown")
        status = task.get("status", "unknown")
        task_url = task.get("url", "")

        status_msg = (
            f"🤖 **Queued Devin fix** (session `{session_id}`, status: `{status}`)\n\n"
            f"Branch: `{branch_name}`\n"
        )
        if task_url:
            status_msg += f"Track progress: {task_url}\n"
        status_msg += (
            "\nA PR will be opened automatically. "
            "Please review before merging."
        )
        post_comment(REPO_FULL_NAME, ISSUE_NUMBER, status_msg)
        logger.info("Fix task created: session=%s status=%s", session_id, status)

    except Exception as exc:
        logger.error("Failed to create Devin fix task: %s", exc)
        post_comment(
            REPO_FULL_NAME,
            ISSUE_NUMBER,
            f"⚠️ **Auto-fix failed** — could not create Devin task. Error: `{exc}`",
        )


# --------------- Script entrypoint ---------------
if __name__ == "__main__":
    run()
