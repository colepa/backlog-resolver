"""
prompt_templates.py
-------------------
All the text prompts we send to Devin live here.
If you need to tweak wording, this is the only file to edit.
"""

# ------------------------------------------------------------------
# TRIAGE PROMPT
# Sent to Devin so it returns a structured JSON triage of the issue.
# The {placeholders} are filled in at runtime by intake.py.
# ------------------------------------------------------------------
TRIAGE_PROMPT = """\
You are a senior software engineer triaging a GitHub issue.

## Issue
**Title:** {title}
**Body:**
{body}

## Recent Comments (up to 10)
{comments}

## Instructions
Analyze this issue and return ONLY a JSON object (no markdown fences, no
extra text) that matches this schema exactly:

{{
  "summary": "<one-sentence summary>",
  "category": "bug" | "feature" | "chore",
  "severity": "low" | "medium" | "high" | "critical",
  "effort": "S" | "M" | "L",
  "confidence": <float 0-1, how confident you are in the triage>,
  "needs_info": [<list of questions if anything is unclear, else empty>],
  "repro_steps": [<reproduction steps if applicable, else empty>],
  "suggested_labels": [<extra labels you recommend>],
  "recommended_next_action": "ask_for_info" | "ready_for_dev" | "defer" | "devin_fix",
  "devin_fix_plan": [<step-by-step plan if you recommend devin_fix, else empty>],
  "risks": [<potential risks or side-effects of fixing this>]
}}

Rules:
- Pick "devin_fix" ONLY when the fix is small, well-defined, and low-risk.
- confidence should reflect how sure you are about the category AND the fix plan.
- If you lack information, set recommended_next_action to "ask_for_info" and
  list your questions in needs_info.
- Return ONLY valid JSON. No extra keys. No comments.
"""

# ------------------------------------------------------------------
# FIX PROMPT
# Sent to Devin when we ask it to implement a fix and open a PR.
# ------------------------------------------------------------------
FIX_PROMPT = """\
You are a senior software engineer. Implement a fix for the following
GitHub issue and open a pull request.

## Repository
{repo_full_name}

## Issue #{issue_number}: {title}
{body}

## Triage Summary
{summary}

## Fix Plan
{fix_plan}

## Instructions
1. Check out the repository.
2. Create a new branch named: {branch_name}
3. Implement the fix following the plan above.
4. If the repo has tests, add or update tests for your change.
   If there are no tests, still make the fix but explain the risk in
   the PR description.
5. Commit with a clear message referencing #{issue_number}.
6. Open a pull request against the default branch with:
   - Title: "fix: {title} (#{issue_number})"
   - Body that explains what changed, why, and any risks.
   - Reference "Closes #{issue_number}" so the issue auto-closes on merge.
7. Do NOT push directly to main. Always open a PR.
"""
