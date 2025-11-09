#!/bin/bash
cd "$(dirname "$0")"

# Rotate log if it gets too large (>10MB)
if [ -f logs/domain-monitor.log ] && [ $(stat -f%z logs/domain-monitor.log 2>/dev/null || stat -c%s logs/domain-monitor.log) -gt 10485760 ]; then
    mv logs/domain-monitor.log logs/domain-monitor.log.old
fi

echo "=== $(date) ===" >> logs/domain-monitor.log

# Set default limit, allow override via environment variable
DOMAIN_LIMIT=${DOMAIN_LIMIT:-50}

# Show output on screen if running interactively, log to file if running from cron
if [ -t 1 ]; then
    # Interactive - show on screen and log to file
    uv run python domain_monitor.py check --limit "$DOMAIN_LIMIT" 2>&1 | tee -a logs/domain-monitor.log
else
    # Non-interactive (cron) - log to file only
    uv run python domain_monitor.py check --limit "$DOMAIN_LIMIT" >> logs/domain-monitor.log 2>&1
fi
