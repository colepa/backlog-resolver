# Backlog Resolver – GitHub Issue Intake & Auto-Fix

A lightweight GitHub Actions automation that triages every new issue with
[Devin](https://devin.ai) and, when it's safe, queues Devin to open a PR
with a fix. Humans always review before anything is merged.

---

## How It Works

```
Issue opened / edited / reopened
        │
        ▼
┌──────────────────────┐
│  GitHub Actions       │
│  issue-intake.yml     │
└──────────┬───────────┘
           │  runs
           ▼
┌──────────────────────┐     ┌─────────────────┐
│  scripts/intake.py   │────▶│  Devin API       │
│  (orchestrator)      │◀────│  (service user)  │
└──────────┬───────────┘     └─────────────────┘
           │
           ▼
   GitHub Issue updated:
   • Triage Report comment
   • Labels applied
   • (optional) PR opened by Devin
```

### A) Triage (always runs)
1. Fetches the issue title, body, and up to 10 recent comments.
2. Sends a structured prompt to Devin asking for a JSON triage.
3. Posts a **Triage Report** comment on the issue.
4. Applies labels: `devin:triaged`, `prio:<severity>`, `effort:<S|M|L>`,
   and optionally `needs-info` or `devin:fix`.
5. **Loop guard** — if the issue already has `devin:triaged`, the workflow
   exits immediately so edits don't re-triage.

### B) Auto-Fix (only when safe)
If Devin recommends `devin_fix` **and** all of these are true:
- effort is **S** (small)
- confidence ≥ **0.7**
- no outstanding questions (`needs_info` is empty)
- `DEVIN_FIX_ENABLED` is not `false`

…then the script asks Devin to:
1. Create a branch `devin/fix-<issue#>-<slug>`.
2. Implement the fix (+ tests when possible).
3. Open a PR referencing the issue.

**Devin never pushes to main.** A human must review and merge every PR.

---

## Project Structure

```
.github/workflows/issue-intake.yml   # GitHub Actions workflow
scripts/
  __init__.py                         # makes scripts a package
  intake.py                           # main entrypoint / orchestrator
  github_client.py                    # thin GitHub REST API wrapper
  devin_client.py                     # thin Devin API wrapper (has TODOs)
  prompt_templates.py                 # all prompts sent to Devin
requirements.txt                      # Python dependencies
README.md                             # this file
```

---

## Setup

### 1. Create (or fork) this repository

Push these files to a GitHub repo.

### 2. Add secrets

Go to **Settings → Secrets and variables → Actions** and add:

| Secret | Description |
|--------|-------------|
| `DEVIN_SERVICE_TOKEN` | Devin service-user Bearer token |
| `DEVIN_API_BASE_URL` | Devin API base URL (e.g. `https://api.devin.ai`) |

`GITHUB_TOKEN` is provided automatically by GitHub Actions.

Optionally add `DEVIN_FIX_ENABLED` set to `false` if you want to disable
auto-fix and only use triage.

### 3. Create labels (optional)

The workflow auto-creates labels the first time, but you can pre-create
them in **Issues → Labels** for nicer colours:

`devin:triaged`, `devin:fix`, `prio:low`, `prio:med`, `prio:high`,
`prio:critical`, `effort:S`, `effort:M`, `effort:L`, `needs-info`

### 4. Test it

Open a new issue with a clear title and description. Within a minute you
should see:
- A **Triage Report** comment posted by the Actions bot.
- Labels applied to the issue.
- (If auto-fix triggered) a follow-up comment with the Devin session link.

---

## Running Locally (optional)

You can run the intake script locally for testing. Export the required env
vars, then:

```bash
# Install deps
pip install -r requirements.txt

# Set required environment variables
export GITHUB_TOKEN="ghp_your_token"
export DEVIN_SERVICE_TOKEN="your_devin_token"
export DEVIN_API_BASE_URL="https://api.devin.ai"
export REPO_FULL_NAME="your-org/your-repo"
export ISSUE_NUMBER="42"

# Run
python -m scripts.intake
```

---

## 2–3 Minute Demo Script

1. **Show the repo** — walk through the file structure
   (workflow → intake.py → helpers).
2. **Open a test issue** — e.g. title: _"Bug: login button unresponsive on
   mobile"_, body with a short description.
3. **Watch the Action run** — go to the Actions tab and show the logs.
4. **See the triage comment** — switch back to the issue. Point out the
   Triage Report table, labels, and the fix plan.
5. **Show the PR** _(if auto-fix triggered)_ — open the PR created by
   Devin, highlight the branch name, description, and the "Closes #N"
   reference.
6. **Emphasise guardrails** — Devin cannot merge; a human must review.

---

## TODOs / Known Limitations

- **Devin API endpoints** are stubbed with best-guess paths in
  `devin_client.py`. Update the `_TRIAGE_ENDPOINT`, `_FIX_TASK_ENDPOINT`,
  and `_POLL_TASK_ENDPOINT` constants once Devin publishes final docs.
- **Polling** for task completion (`poll_task`) is implemented but not
  called automatically. You could add a second workflow or a cron job to
  poll and update the issue when the PR is ready.
- **Rate limiting** — the script does not currently handle GitHub or Devin
  rate limits. For repos with very high issue volume, add retry/backoff
  logic.

---

## License

MIT — do whatever you want with it.
