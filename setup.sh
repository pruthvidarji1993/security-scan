#!/usr/bin/env bash
# One-time setup. Safe to re-run.
#   ./setup.sh            link the skill so `/secure-review` works in Claude Code
#   ./setup.sh --schedule also run scan.py weekly (macOS launchd, Mondays 09:00)
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"

command -v python3 >/dev/null || { echo "python3 3.10+ is required"; exit 1; }
command -v git >/dev/null || { echo "git is required"; exit 1; }
python3 "$HERE/scan.py" --selftest

mkdir -p "$HOME/.claude/skills"
ln -sfn "$HERE/skill/secure-review" "$HOME/.claude/skills/secure-review"
echo "skill linked: ~/.claude/skills/secure-review"

if [ "${1:-}" = "--schedule" ]; then
  [ "$(uname)" = "Darwin" ] || { echo "--schedule is macOS only; use cron elsewhere"; exit 1; }
  mkdir -p "$HERE/logs"
  PLIST="$HOME/Library/LaunchAgents/com.securityscan.weekly.plist"
  cat > "$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.securityscan.weekly</string>
  <key>ProgramArguments</key><array><string>$(command -v python3)</string><string>$HERE/scan.py</string></array>
  <key>WorkingDirectory</key><string>$HERE</string>
  <key>EnvironmentVariables</key><dict><key>PATH</key><string>$(dirname "$(command -v claude 2>/dev/null || echo /usr/bin/claude)"):/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin</string></dict>
  <key>StartCalendarInterval</key><dict><key>Weekday</key><integer>1</integer><key>Hour</key><integer>9</integer><key>Minute</key><integer>0</integer></dict>
  <key>StandardOutPath</key><string>$HERE/logs/scan.log</string>
  <key>StandardErrorPath</key><string>$HERE/logs/scan.log</string>
</dict></plist>
EOF
  launchctl unload "$PLIST" 2>/dev/null || true
  launchctl load "$PLIST"
  echo "scheduled weekly (Mon 09:00). Edit roots/exclude in config.json."
fi
