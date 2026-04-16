# Abusive IP Checker + Cloudflare Blocker

Extracts unique IPs from nginx access logs, checks them against [AbuseIPDB](https://www.abuseipdb.com/) in parallel, and automatically blocks abusive ones via Cloudflare IP Access Rules. Optionally reports abusive IPs back to AbuseIPDB. Includes a cleanup script to remove expired rules.

## Features

- **Parallel checking** — auto-scaled thread pool for concurrent AbuseIPDB queries
- **JSON cache** — avoids repeated API calls, with automatic expiry and atomic writes
- **Cloudflare blocking** — blocks IPs at the edge before they reach your server
- **Nginx blocking** — optional local deny rules as fallback
- **AbuseIPDB reporting** — optionally report abusive IPs back to the community
- **Automatic cleanup** — removes expired block rules on a schedule
- **Dry run mode** — full analysis without blocking, reporting, or deleting anything
- **Configurable** — INI config file, all values overridable via CLI
- **Professional output** — colored terminal output via colorama, with `--no-color` for logs

## Scripts

| Script | Purpose |
|--------|---------|
| `check_abusive_ips.py` | Scan nginx logs, check IPs against AbuseIPDB, block abusive ones |
| `cleanup_rules.py` | Remove expired Cloudflare IP Access Rules |

## Requirements

- Python 3.9+
- Dependencies listed in `requirements.txt`

## Setup

```bash
# Install dependencies
pip install -r requirements.txt

# Create your config
cp config.ini.example config.ini
nano config.ini
```

Set your API keys in `config.ini`:

- **AbuseIPDB**: Free at https://www.abuseipdb.com/account/api (1,000 queries/day)
- **Cloudflare API Token**: Dashboard → My Profile → API Tokens → Create Token
  - Required permission: `Zone > Firewall Services > Edit`
- **Cloudflare Zone ID**: Dashboard → your domain → Overview → right column

## Usage

### check_abusive_ips.py

Scans nginx logs, queries AbuseIPDB, and blocks abusive IPs in Cloudflare.

```bash
# Dry run first (recommended)
python3 check_abusive_ips.py --dry-run

# Normal mode — blocks abusive IPs in Cloudflare
python3 check_abusive_ips.py

# Override config values from CLI
python3 check_abusive_ips.py --lines 20000 --threshold 50

# Only check IPs that appear 5+ times in the log
python3 check_abusive_ips.py --min-hits 5

# Custom config path
python3 check_abusive_ips.py --config /etc/abusive-checker/config.ini

# Disable colors (useful for cron logs)
python3 check_abusive_ips.py --no-color

# Debug logging
python3 check_abusive_ips.py --verbose
```

### cleanup_rules.py

Removes Cloudflare IP Access Rules older than N days. Shares `config.ini` with the checker. Reads defaults from the `[cleanup]` section; CLI flags override config values.

```bash
# Dry run — list what would be removed
python3 cleanup_rules.py --dry-run

# Remove rules using config.ini defaults (days and only_auto from [cleanup] section)
python3 cleanup_rules.py

# Override config: remove rules older than 7 days
python3 cleanup_rules.py --days 7

# Override config: only remove rules created by check_abusive_ips.py
python3 cleanup_rules.py --only-auto

# Combine flags
python3 cleanup_rules.py --only-auto --days 14

# Audit: list ALL rules in the zone
python3 cleanup_rules.py --dry-run --days 0
```

### query_rules.py

Queries active Cloudflare IP Access Rules. Useful for auditing blocked IPs when no local logs were kept.

```bash
# List all active rules
python3 query_rules.py

# Look up a specific IP
python3 query_rules.py --ip 1.2.3.4

# Substring match — useful for ranges
python3 query_rules.py --ip 192.168

# Show only block rules, sorted oldest-first
python3 query_rules.py --mode block --sort age

# Show only rules created by check_abusive_ips.py
python3 query_rules.py --only-auto

# Rules added in the last 7 days
python3 query_rules.py --days 7

# Rules older than 30 days (candidates for cleanup)
python3 query_rules.py --older-than 30

# Search by keyword in notes or IP
python3 query_rules.py --search "xmlrpc"

# Statistics summary only (no table)
python3 query_rules.py --stats --no-table

# Export filtered results
python3 query_rules.py --mode block --export csv
python3 query_rules.py --only-auto --export json --output blocked_auto.json
```

## AbuseIPDB Reporting

By default, the checker only queries AbuseIPDB to check IP scores. You can optionally enable **reporting** to contribute back to the community. When enabled, every IP that gets blocked is also reported to AbuseIPDB with the configured categories and a comment.

To enable, set `report = true` in `config.ini`:

```ini
[abuseipdb]
report = true
report_categories = 15
report_comment = Score: {score}%% | {country} | {isp} | Reports: {reports} | Type: {usage_type}
```

How it works:

- Reports are sent **after** blocking (Cloudflare/nginx), not during the parallel query phase
- Each IP is reported **once** — the `reported` flag is persisted in the JSON cache
- If AbuseIPDB returns a 15-minute cooldown (HTTP 422), the IP is marked as reported
- In `--dry-run` mode, nothing is reported
- Report failures don't affect the exit code — blocking is the priority

The `report_comment` is a template with placeholders. Available placeholders: `{score}`, `{country}`, `{isp}`, `{reports}`, `{usage_type}`, `{domain}`, `{is_tor}`. Use `%%` for a literal `%` sign (standard INI escaping).

## Automation (cron)

```cron
# Check and block abusive IPs every 4 hours
0 */4 * * * cd /root/abusive-ip-checker && python3 check_abusive_ips.py --no-color --threshold 75 >> /var/log/abusive_check.log 2>&1

# Clean up expired rules daily at 3 AM (uses [cleanup] config defaults)
0 3 * * * cd /root/abusive-ip-checker && python3 cleanup_rules.py --no-color >> /var/log/cleanup_rules.log 2>&1
```

## Configuration

Both scripts share the same `config.ini`. The checker uses all sections; the cleanup script uses `[cloudflare]` and `[cleanup]`.

| Section    | Key              | Default    | Description                                        |
|------------|------------------|------------|----------------------------------------------------|
| general    | log_file         | —          | Path to nginx access log                           |
| general    | lines            | 5000       | Number of log lines to analyze                     |
| general    | cache_file       | —          | Path to JSON cache file                            |
| general    | cache_expiry_days| 7          | Days before re-checking cached IPs                 |
| general    | workers          | auto       | Thread count: `auto` or fixed (2-20)               |
| general    | min_hits         | 3          | Min log appearances before checking an IP           |
| abuseipdb  | api_key          | —          | Your AbuseIPDB API key                             |
| abuseipdb  | threshold        | 30         | Min score to consider abusive (0-100)              |
| abuseipdb  | max_age_days     | 90         | Check reports from last N days                     |
| abuseipdb  | report           | false      | Report abusive IPs back to AbuseIPDB               |
| abuseipdb  | report_categories| 15         | Category IDs for reports (comma-separated)         |
| abuseipdb  | report_comment   | *(see below)* | Template for the report comment                 |
| cloudflare | api_token        | —          | Your Cloudflare API token                          |
| cloudflare | zone_id          | —          | Your Cloudflare Zone ID                            |
| cloudflare | block_method     | cloudflare | `cloudflare`, `nginx`, or `both`                   |
| nginx      | block_file       | —          | Path to nginx deny rules file                      |
| cleanup    | days             | 30         | Remove rules older than N days                     |
| cleanup    | only_auto        | false      | Only remove auto-blocked rules                     |

Default `report_comment`: `Score: {score}%% | {country} | {isp} | Reports: {reports} | Type: {usage_type}`

## Block Methods

- **cloudflare** (default) — Blocks at Cloudflare's edge. Requests never reach your server.
- **nginx** — Appends `deny` rules to a local nginx config. Requires reload after run.
- **both** — Blocks in both Cloudflare and nginx.

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Configuration error (missing config file, invalid keys) |
| 2 | Runtime/API error (network failures, blocked deletions) |

## Limits

- AbuseIPDB free plan: 1,000 queries/day
- Cloudflare free plan IP Access Rules: 50,000 per account
- Cleanup default: rules expire after 30 days (configurable via `[cleanup] days`)
