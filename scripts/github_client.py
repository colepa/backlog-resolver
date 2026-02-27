"""
github_client.py
----------------
Thin wrapper around the GitHub REST API.
Uses the `requests` library and a GITHUB_TOKEN from the environment.
"""

import os
import logging
import requests

# --------------- Setup ---------------
logger = logging.getLogger(__name__)

GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")
GITHUB_API = "https://api.github.com"

# Reusable session so every request carries auth headers.
_session = requests.Session()
_session.headers.update(
    {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
)


# --------------- Helpers ---------------

def _url(path: str) -> str:
    """Build a full GitHub API URL from a path like /repos/{owner}/{repo}/..."""
    return f"{GITHUB_API}{path}"


def _check(response: requests.Response) -> dict:
    """Raise on HTTP errors and return JSON body."""
    response.raise_for_status()
    # Some endpoints return 204 No Content (e.g., label creation).
    if response.status_code == 204:
        return {}
    return response.json()


# --------------- Public API ---------------

def get_issue(repo: str, issue_number: int) -> dict:
    """
    Fetch a single issue by number.
    `repo` is "owner/repo" format, e.g. "acme/widgets".
    Returns the full issue JSON from GitHub.
    """
    logger.info("Fetching issue #%s from %s", issue_number, repo)
    resp = _session.get(_url(f"/repos/{repo}/issues/{issue_number}"))
    return _check(resp)


def get_issue_comments(repo: str, issue_number: int, limit: int = 10) -> list[dict]:
    """
    Fetch up to `limit` most recent comments on an issue.
    Returns a list of comment dicts (each has 'user.login' and 'body').
    """
    logger.info("Fetching up to %d comments for issue #%s", limit, issue_number)
    resp = _session.get(
        _url(f"/repos/{repo}/issues/{issue_number}/comments"),
        params={"per_page": limit, "direction": "desc"},
    )
    return _check(resp)


def get_issue_labels(repo: str, issue_number: int) -> list[str]:
    """Return a list of label names currently on the issue."""
    issue = get_issue(repo, issue_number)
    return [label["name"] for label in issue.get("labels", [])]


def add_labels(repo: str, issue_number: int, labels: list[str]) -> None:
    """
    Add one or more labels to an issue.
    Labels that don't exist on the repo yet will be auto-created by GitHub.
    """
    if not labels:
        return
    logger.info("Adding labels %s to issue #%s", labels, issue_number)
    resp = _session.post(
        _url(f"/repos/{repo}/issues/{issue_number}/labels"),
        json={"labels": labels},
    )
    _check(resp)


def post_comment(repo: str, issue_number: int, body: str) -> dict:
    """Post a comment on the given issue. Returns the created comment JSON."""
    logger.info("Posting comment on issue #%s (%d chars)", issue_number, len(body))
    resp = _session.post(
        _url(f"/repos/{repo}/issues/{issue_number}/comments"),
        json={"body": body},
    )
    return _check(resp)
