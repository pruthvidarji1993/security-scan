# security-scan

Stack-aware security review for any repo, with no per-project setup. It detects
Next.js, React, Node API, Django, Flask, FastAPI, PHP/Laravel, React Native and
Docker by itself, runs the right scanners, adds an AI review, and writes an HTML
report mapped to OWASP Top 10. Built on the `secure-review` skill in `skill/`.

Needs `python3` 3.10+ and `git`. For the AI review, the `claude` CLI, logged in.
Scanners install themselves on first use into `~/.cache/secure-review`.

## Scan one project

```bash
git clone https://github.com/pruthvidarji1993/security-scan.git
cd security-scan
python3 scan.py /path/to/your/project
```

Output: `reports/<date>/<project>/report.html` (client report), `findings.txt`
(developer list) and `reports/<date>/SUMMARY.md`.

## Scan everything, on a schedule

```bash
./setup.sh --schedule      # macOS: weekly, Mondays 09:00
```

Edit `config.json`:

| key | meaning |
|---|---|
| `roots` | folders searched for git repos (up to 3 levels deep) |
| `exclude` | repo names or paths to skip (globs ok) |
| `max_repos_per_run` | cap per run; the rest roll over to the next run |
| `ai_review` | `false` = scanners only, no Claude usage |

New repos under `roots` are picked up automatically. Each run scans only repos
whose HEAD changed (`diff` against the last scan; new repos get a `full` scan).
`python3 scan.py` with no argument does one run now.

## Use it inside Claude Code

`./setup.sh` links the skill to `~/.claude/skills`, so `/secure-review [diff|full|deps]`
works in any project.

## Safety

- Scans local checkouts only; it never pulls, edits or commits to them.
- The AI review can only read the repo and write into its own report folder, and
  treats repo content as untrusted. If it fails, you still get scanner results.
- Secret values are never written to reports. `state.json`, `reports/` and
  `logs/` are gitignored.
