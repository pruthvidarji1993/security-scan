# security-scan

Stack-aware security review for any project, with zero per-project setup. Point it
at a repo and it detects the stack (Next.js, React, Node API, Django, Flask,
FastAPI, PHP/Laravel, React Native, Docker), runs the right scanners, adds an AI
review of what scanners cannot see, and writes an HTML report mapped to OWASP Top 10.

Built on the `secure-review` skill in [`skill/`](skill/secure-review/SKILL.md).

## Quick start

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/pruthvidarji1993/security-scan/main/run.sh) /path/to/project
```

Run it with no path to scan the current directory. The script clones this repo to
`~/.cache/security-scan`, updates it on every run, and scans the project. Nothing is
added to, edited in, or committed to the scanned project.

Or from a clone:

```bash
git clone https://github.com/pruthvidarji1993/security-scan.git
./security-scan/run.sh /path/to/project
```

**Needs:** `python3` 3.10+ and `git`. Scanners install themselves on first use into
`~/.cache/secure-review`. The AI review needs the `claude` CLI, logged in; without it
you still get the scanner results.

**Output:** `reports/<date>/<project>/` containing `report.html` (client report),
`findings.txt` (developer list) and `reports/<date>/SUMMARY.md`.

## Scan many projects on a schedule

```bash
./setup.sh --schedule      # macOS: weekly, Mondays 09:00
```

Edit [`config.json`](config.json):

| key | meaning |
|---|---|
| `projects` | repos to always scan: an absolute path, or a folder name under a root |
| `roots` | folders searched for git repos (up to 3 levels deep). `[]` scans only `projects` |
| `exclude` | repo names or paths to skip (globs ok) |
| `max_repos_per_run` | cap per run; the rest roll over to the next run |
| `ai_review` | `false` = scanners only, no Claude usage |

New repos under `roots` are picked up automatically. Each run scans only repos whose
HEAD changed: a `diff` against the last scan, or a `full` scan for a new repo.
`python3 scan.py` with no argument does one run now. `python3 scan.py <path>` ignores
the config and always does a full scan of that path.

## Use it inside Claude Code

`./setup.sh` links the skill into `~/.claude/skills`, so `/secure-review [diff|full|deps]`
works in any project.

## Safety

- Scans local checkouts only. It never pulls, edits or commits to them.
- The AI review can read the repo and write only into its own report folder, and treats
  repo content as untrusted. If it fails, you still get scanner results.
- Secret values are never written to reports. `state.json`, `reports/` and `logs/` are
  gitignored.
- `run.sh` runs whatever is on `main` of this repo. Pin a tag if you need stable behavior.

## Tests

```bash
python3 scan.py --selftest
python3 skill/secure-review/scripts/secure_review.py selftest
```
