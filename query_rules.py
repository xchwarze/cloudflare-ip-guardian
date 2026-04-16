#!/usr/bin/env python3
"""
Cloudflare IP Access Rules Query Tool.

Query, filter, search and export the IP Access Rules currently active in a
Cloudflare zone. Useful when no local block logs were kept and you need to
audit or investigate what's blocked.

Usage:
    python3 query_rules.py                          # Show all rules (table)
    python3 query_rules.py --ip 1.2.3.4             # Look up a specific IP
    python3 query_rules.py --mode block             # Only block rules
    python3 query_rules.py --only-auto              # Only auto-blocked rules
    python3 query_rules.py --days 7                 # Rules created in last 7 days
    python3 query_rules.py --older-than 30          # Rules older than 30 days
    python3 query_rules.py --search "bad actor"     # Search in notes
    python3 query_rules.py --sort age               # Sort by age (oldest first)
    python3 query_rules.py --export csv             # Export to rules_export.csv
    python3 query_rules.py --export json            # Export to rules_export.json
    python3 query_rules.py --stats                  # Show statistics summary only
"""

from __future__ import annotations

import argparse
import configparser
import csv
import json
import logging
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests
from colorama import Fore, Style, init as colorama_init

# ─── Constants ───────────────────────────────────────────────────────────────

VERSION = "1.0.0"
EXIT_OK = 0
EXIT_CONFIG_ERROR = 1
EXIT_API_ERROR = 2

CLOUDFLARE_ACCESS_RULES_URL = (
    "https://api.cloudflare.com/client/v4/zones/{zone_id}/firewall/access_rules/rules"
)

AUTO_BLOCKED_PREFIX = "Auto-blocked"
PAGE_SIZE = 100

SORT_CHOICES = ("ip", "age", "mode", "created")
EXPORT_CHOICES = ("csv", "json")
MODE_COLORS = {
    "block":      Fore.RED,
    "challenge":  Fore.YELLOW,
    "js_challenge": Fore.YELLOW,
    "managed_challenge": Fore.CYAN,
    "whitelist":  Fore.GREEN,
    "allow":      Fore.GREEN,
}

logger = logging.getLogger("query_rules")


# ─── Exceptions ─────────────────────────────────────────────────────────────

class ConfigError(Exception):
    """Raised for configuration problems."""


class APIError(Exception):
    """Raised when the Cloudflare API returns an error."""


# ─── Data Structures ────────────────────────────────────────────────────────

@dataclass
class AccessRule:
    """A single Cloudflare IP Access Rule."""

    rule_id: str
    ip: str
    mode: str
    notes: str
    created_on: datetime
    is_auto: bool

    @property
    def age_days(self) -> int:
        delta = datetime.now(timezone.utc) - self.created_on
        return delta.days

    @property
    def created_str(self) -> str:
        return self.created_on.strftime("%Y-%m-%d %H:%M UTC")

    @classmethod
    def from_api(cls, data: dict) -> "AccessRule":
        config = data.get("configuration") or {}
        notes = data.get("notes") or ""
        created_str = data.get("created_on") or ""
        try:
            created_on = datetime.fromisoformat(created_str.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            created_on = datetime.now(timezone.utc)
        return cls(
            rule_id=data.get("id") or "",
            ip=config.get("value") or "??",
            mode=data.get("mode") or "??",
            notes=notes,
            created_on=created_on,
            is_auto=notes.startswith(AUTO_BLOCKED_PREFIX),
        )

    def to_dict(self) -> dict:
        return {
            "rule_id":    self.rule_id,
            "ip":         self.ip,
            "mode":       self.mode,
            "notes":      self.notes,
            "created_on": self.created_str,
            "age_days":   self.age_days,
            "is_auto":    self.is_auto,
        }


@dataclass
class QueryStats:
    total:      int = 0
    shown:      int = 0
    block:      int = 0
    challenge:  int = 0
    allow:      int = 0
    other:      int = 0
    auto:       int = 0
    manual:     int = 0
    oldest_days: int = 0
    newest_days: int = 0


# ─── Cloudflare Client ──────────────────────────────────────────────────────

class CloudflareClient:
    """HTTP client for Cloudflare IP Access Rules API."""

    def __init__(self, api_token: str, zone_id: str) -> None:
        self._zone_id = zone_id
        self._session = requests.Session()
        self._session.headers.update({
            "Authorization": f"Bearer {api_token}",
            "Content-Type": "application/json",
        })

    def list_rules(self) -> list[AccessRule]:
        """Fetch all IP Access Rules, handling pagination."""
        rules: list[AccessRule] = []
        page = 1

        while True:
            try:
                resp = self._session.get(
                    CLOUDFLARE_ACCESS_RULES_URL.format(zone_id=self._zone_id),
                    params={"page": page, "per_page": PAGE_SIZE},
                    timeout=30,
                )
                resp.raise_for_status()
                body = resp.json()

                if not isinstance(body, dict):
                    raise APIError(f"Unexpected response type on page {page}")

                if not body.get("success"):
                    errors = body.get("errors", [])
                    msg = "Unknown"
                    if errors:
                        first = errors[0]
                        msg = first.get("message", str(first)) if isinstance(first, dict) else str(first)
                    raise APIError(f"Cloudflare API error: {msg}")

                items = body.get("result", [])
                if not items:
                    break

                for item in items:
                    rules.append(AccessRule.from_api(item))

                result_info = body.get("result_info", {})
                if page >= result_info.get("total_pages", 1):
                    break
                page += 1

            except requests.HTTPError as exc:
                resp_obj = exc.response
                detail = ""
                if resp_obj is not None:
                    try:
                        body = resp_obj.json()
                        cf_errors = body.get("errors", [])
                        if cf_errors:
                            first = cf_errors[0]
                            detail = first.get("message", str(first)) if isinstance(first, dict) else str(first)
                    except Exception:
                        pass
                raise APIError(
                    f"HTTP {resp_obj.status_code if resp_obj is not None else '?'} on page {page}"
                    + (f": {detail}" if detail else f": {exc}")
                ) from exc

            except (requests.RequestException, ValueError) as exc:
                raise APIError(f"Network error (page {page}): {exc}") from exc

        return rules

    def close(self) -> None:
        self._session.close()


# ─── Filtering & Sorting ─────────────────────────────────────────────────────

def apply_filters(
    rules: list[AccessRule],
    *,
    ip: str | None,
    mode: str | None,
    only_auto: bool,
    days: int | None,
    older_than: int | None,
    search: str | None,
) -> list[AccessRule]:
    """Apply all CLI filters to a rule list."""
    now = datetime.now(timezone.utc)
    result = rules

    if ip:
        result = [r for r in result if ip.strip() in r.ip]

    if mode:
        result = [r for r in result if r.mode.lower() == mode.lower()]

    if only_auto:
        result = [r for r in result if r.is_auto]

    if days is not None:
        cutoff = now - timedelta(days=days)
        result = [r for r in result if r.created_on >= cutoff]

    if older_than is not None:
        cutoff = now - timedelta(days=older_than)
        result = [r for r in result if r.created_on < cutoff]

    if search:
        needle = search.lower()
        result = [r for r in result if needle in r.notes.lower() or needle in r.ip.lower()]

    return result


def apply_sort(rules: list[AccessRule], sort: str) -> list[AccessRule]:
    if sort == "ip":
        return sorted(rules, key=lambda r: r.ip)
    if sort == "age":
        return sorted(rules, key=lambda r: r.created_on)          # oldest first
    if sort == "mode":
        return sorted(rules, key=lambda r: r.mode)
    if sort == "created":
        return sorted(rules, key=lambda r: r.created_on, reverse=True)  # newest first
    return rules


# ─── Console Output ─────────────────────────────────────────────────────────

class Console:

    @staticmethod
    def header(args: argparse.Namespace) -> None:
        print()
        print(f"{Fore.CYAN}══════════════════════════════════════════════{Style.RESET_ALL}")
        print(f"{Fore.CYAN}  Cloudflare IP Rules Query Tool v{VERSION}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}══════════════════════════════════════════════{Style.RESET_ALL}")
        print()

        filters: list[str] = []
        if args.ip:
            filters.append(f"IP contains '{args.ip}'")
        if args.mode:
            filters.append(f"mode={args.mode}")
        if args.only_auto:
            filters.append("auto-blocked only")
        if args.days is not None:
            filters.append(f"created in last {args.days} days")
        if args.older_than is not None:
            filters.append(f"older than {args.older_than} days")
        if args.search:
            filters.append(f"notes/IP contains '{args.search}'")

        if filters:
            print(f"  {Fore.YELLOW}Filters:{Style.RESET_ALL}  {', '.join(filters)}")
        else:
            print(f"  {Fore.YELLOW}Filters:{Style.RESET_ALL}  none (showing all rules)")

        sort_label = args.sort or "default (API order)"
        print(f"  {Fore.YELLOW}Sort:   {Style.RESET_ALL}  {sort_label}")
        print()

    @staticmethod
    def fetching() -> None:
        print(f"  {Fore.YELLOW}Fetching rules from Cloudflare...{Style.RESET_ALL}")

    @staticmethod
    def _mode_tag(rule: AccessRule) -> str:
        color = MODE_COLORS.get(rule.mode, Fore.WHITE)
        return f"{color}{rule.mode:<18}{Style.RESET_ALL}"

    @staticmethod
    def _auto_tag(rule: AccessRule) -> str:
        if rule.is_auto:
            return f" {Fore.CYAN}[auto]{Style.RESET_ALL}"
        return f" {Fore.WHITE}[manual]{Style.RESET_ALL}"

    @classmethod
    def table(cls, rules: list[AccessRule]) -> None:
        if not rules:
            print(f"  {Fore.YELLOW}No rules match the current filters.{Style.RESET_ALL}")
            return

        # Column widths
        ip_w    = max(len(r.ip) for r in rules)
        ip_w    = max(ip_w, 15)

        # Header
        header = (
            f"  {'IP':<{ip_w}}  {'MODE':<18}  {'AGE':>5}  {'CREATED':<20}  {'SOURCE':<8}  NOTES"
        )
        sep = "  " + "─" * (ip_w + 18 + 5 + 20 + 8 + 10 + 14)
        print(f"{Fore.WHITE}{header}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}{sep}{Style.RESET_ALL}")

        for rule in rules:
            color = MODE_COLORS.get(rule.mode, Fore.WHITE)
            auto_label = "auto  " if rule.is_auto else "manual"
            age_str = f"{rule.age_days}d"
            notes_short = rule.notes[:55] + ("…" if len(rule.notes) > 55 else "")

            print(
                f"  {Fore.WHITE}{rule.ip:<{ip_w}}{Style.RESET_ALL}  "
                f"{color}{rule.mode:<18}{Style.RESET_ALL}  "
                f"{Fore.WHITE}{age_str:>5}{Style.RESET_ALL}  "
                f"{Fore.WHITE}{rule.created_str:<20}{Style.RESET_ALL}  "
                f"{Fore.CYAN if rule.is_auto else Fore.WHITE}{auto_label:<8}{Style.RESET_ALL}  "
                f"{Fore.WHITE}{notes_short}{Style.RESET_ALL}"
            )

    @staticmethod
    def stats_block(stats: QueryStats, filtered: int) -> None:
        print()
        print(f"{Fore.CYAN}══════════════════════════════════════════════{Style.RESET_ALL}")
        print(f"{Fore.CYAN}  STATISTICS{Style.RESET_ALL}")
        print(f"{Fore.CYAN}══════════════════════════════════════════════{Style.RESET_ALL}")
        print()
        print(f"  Total rules in zone:    {Fore.YELLOW}{stats.total}{Style.RESET_ALL}")
        print(f"  Matching filters:       {Fore.YELLOW}{filtered}{Style.RESET_ALL}")
        print()
        print(f"  By mode:")
        print(f"    {Fore.RED}block{Style.RESET_ALL}              {stats.block}")
        print(f"    {Fore.YELLOW}challenge{Style.RESET_ALL}          {stats.challenge}")
        print(f"    {Fore.GREEN}allow/whitelist{Style.RESET_ALL}    {stats.allow}")
        if stats.other:
            print(f"    {Fore.WHITE}other{Style.RESET_ALL}              {stats.other}")
        print()
        print(f"  By origin:")
        print(f"    {Fore.CYAN}auto-blocked{Style.RESET_ALL}       {stats.auto}")
        print(f"    {Fore.WHITE}manual{Style.RESET_ALL}             {stats.manual}")
        if stats.total:
            print()
            print(f"  Age range:")
            print(f"    oldest:              {stats.oldest_days} days")
            print(f"    newest:              {stats.newest_days} days")
        print()

    @staticmethod
    def export_done(path: str, count: int, fmt: str) -> None:
        print()
        print(f"  {Fore.GREEN}✓ Exported {count} rules to {path} ({fmt.upper()}){Style.RESET_ALL}")
        print()


# ─── Export ──────────────────────────────────────────────────────────────────

def export_csv(rules: list[AccessRule], path: Path) -> None:
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["rule_id", "ip", "mode", "notes", "created_on", "age_days", "is_auto"])
        writer.writeheader()
        for rule in rules:
            writer.writerow(rule.to_dict())


def export_json(rules: list[AccessRule], path: Path) -> None:
    data = [rule.to_dict() for rule in rules]
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


# ─── Stats Builder ───────────────────────────────────────────────────────────

def build_stats(all_rules: list[AccessRule], filtered: list[AccessRule]) -> QueryStats:
    stats = QueryStats(total=len(all_rules))

    for r in all_rules:
        m = r.mode.lower()
        if m == "block":
            stats.block += 1
        elif "challenge" in m:
            stats.challenge += 1
        elif m in ("allow", "whitelist"):
            stats.allow += 1
        else:
            stats.other += 1

        if r.is_auto:
            stats.auto += 1
        else:
            stats.manual += 1

    if all_rules:
        ages = [r.age_days for r in all_rules]
        stats.oldest_days = max(ages)
        stats.newest_days = min(ages)

    stats.shown = len(filtered)
    return stats


# ─── Configuration ───────────────────────────────────────────────────────────

def load_config(path: str) -> configparser.ConfigParser:
    config = configparser.ConfigParser()
    config_path = Path(path)
    if not config_path.exists():
        raise ConfigError(
            f"Config file not found: {path}\n"
            f"This script shares config.ini with check_abusive_ips.py"
        )
    config.read(config_path)
    return config


def validate_config(config: configparser.ConfigParser) -> None:
    errors: list[str] = []
    token = config.get("cloudflare", "api_token", fallback="")
    zone  = config.get("cloudflare", "zone_id",   fallback="")
    if not token or token.startswith("YOUR_"):
        errors.append("Cloudflare API token not set  →  [cloudflare] api_token")
    if not zone or zone.startswith("YOUR_"):
        errors.append("Cloudflare Zone ID not set  →  [cloudflare] zone_id")
    if errors:
        raise ConfigError("Configuration errors:\n" + "\n".join(f"  • {e}" for e in errors))


def setup_logging(verbose: bool = False) -> None:
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        handlers=[logging.StreamHandler(sys.stderr)],
    )


# ─── CLI ─────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Query and inspect Cloudflare IP Access Rules.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  %(prog)s                             List all rules\n"
            "  %(prog)s --ip 1.2.3.4               Look up a specific IP\n"
            "  %(prog)s --mode block                Show only block rules\n"
            "  %(prog)s --only-auto                 Show only auto-blocked rules\n"
            "  %(prog)s --days 7                    Rules added in the last 7 days\n"
            "  %(prog)s --older-than 30             Rules older than 30 days\n"
            "  %(prog)s --search 'bad actor'        Search notes and IPs\n"
            "  %(prog)s --sort age                  Sort oldest-first\n"
            "  %(prog)s --export csv                Export to rules_export.csv\n"
            "  %(prog)s --export json               Export to rules_export.json\n"
            "  %(prog)s --stats                     Show statistics only\n"
            "  %(prog)s --mode block --export csv   Filter + export\n"
        ),
    )

    # ── Filters
    f = parser.add_argument_group("filters")
    f.add_argument("--ip",          metavar="ADDR",
                   help="Filter by IP address (substring match, e.g. '192.168' or '1.2.3.4')")
    f.add_argument("--mode",        metavar="MODE",
                   choices=["block", "challenge", "js_challenge", "managed_challenge", "whitelist", "allow"],
                   help="Filter by rule mode")
    f.add_argument("--only-auto",   action="store_true",
                   help=f"Show only rules whose notes start with '{AUTO_BLOCKED_PREFIX}'")
    f.add_argument("--days",        type=int, metavar="N",
                   help="Show rules created within the last N days")
    f.add_argument("--older-than",  type=int, metavar="N",
                   help="Show rules older than N days")
    f.add_argument("--search",      metavar="TEXT",
                   help="Search for TEXT in notes or IP address (case-insensitive)")

    # ── Output
    o = parser.add_argument_group("output")
    o.add_argument("--sort",    choices=SORT_CHOICES, metavar="FIELD",
                   help=f"Sort results by: {', '.join(SORT_CHOICES)}")
    o.add_argument("--stats",   action="store_true",
                   help="Show statistics summary (still shows table unless combined with --no-table)")
    o.add_argument("--no-table", action="store_true",
                   help="Skip the rules table (useful with --stats or --export)")
    o.add_argument("--export",  choices=EXPORT_CHOICES, metavar="FORMAT",
                   help="Export filtered rules to file (csv or json)")
    o.add_argument("--output",  metavar="FILE",
                   help="Output filename for --export (default: rules_export.{csv,json})")

    # ── General
    parser.add_argument("--config",   default="config.ini",
                        help="Path to configuration file (default: config.ini)")
    parser.add_argument("--no-color", action="store_true",
                        help="Disable colored output")
    parser.add_argument("--verbose",  action="store_true",
                        help="Enable debug logging")
    parser.add_argument("--version",  action="version", version=f"%(prog)s {VERSION}")

    return parser


def main() -> int:
    parser = build_parser()
    args   = parser.parse_args()

    colorama_init(strip=args.no_color)
    setup_logging(args.verbose)

    # Validate conflicting flags
    if args.days is not None and args.days < 0:
        print(f"{Fore.RED}--days cannot be negative{Style.RESET_ALL}", file=sys.stderr)
        return EXIT_CONFIG_ERROR
    if args.older_than is not None and args.older_than < 0:
        print(f"{Fore.RED}--older-than cannot be negative{Style.RESET_ALL}", file=sys.stderr)
        return EXIT_CONFIG_ERROR
    if args.days is not None and args.older_than is not None:
        print(f"{Fore.RED}--days and --older-than are mutually exclusive{Style.RESET_ALL}", file=sys.stderr)
        return EXIT_CONFIG_ERROR

    try:
        config = load_config(args.config)
        validate_config(config)
    except ConfigError as exc:
        print(f"{Fore.RED}{exc}{Style.RESET_ALL}", file=sys.stderr)
        return EXIT_CONFIG_ERROR

    client = CloudflareClient(
        config.get("cloudflare", "api_token"),
        config.get("cloudflare", "zone_id"),
    )

    try:
        Console.header(args)
        Console.fetching()

        try:
            all_rules = client.list_rules()
        except APIError as exc:
            print()
            print(f"  {Fore.RED}✗ {exc}{Style.RESET_ALL}")
            print()
            print(f"  {Fore.YELLOW}Check that your API token and Zone ID are correct")
            print(f"  and that the token has the 'Firewall: Read' permission.{Style.RESET_ALL}")
            print()
            return EXIT_API_ERROR

        print(f"  {Fore.GREEN}✓ Fetched {len(all_rules)} rules{Style.RESET_ALL}")
        print()

        # Apply filters & sort
        filtered = apply_filters(
            all_rules,
            ip=args.ip,
            mode=args.mode,
            only_auto=args.only_auto,
            days=args.days,
            older_than=args.older_than,
            search=args.search,
        )

        if args.sort:
            filtered = apply_sort(filtered, args.sort)

        # Table
        if not args.no_table:
            Console.table(filtered)

        # Stats
        stats = build_stats(all_rules, filtered)
        if args.stats or args.no_table:
            Console.stats_block(stats, len(filtered))
        else:
            # Brief count line
            print()
            print(
                f"  Showing {Fore.YELLOW}{len(filtered)}{Style.RESET_ALL} "
                f"of {Fore.YELLOW}{len(all_rules)}{Style.RESET_ALL} total rules."
            )
            print()

        # Export
        if args.export:
            ext      = args.export
            out_path = Path(args.output) if args.output else Path(f"rules_export.{ext}")
            if ext == "csv":
                export_csv(filtered, out_path)
            else:
                export_json(filtered, out_path)
            Console.export_done(str(out_path), len(filtered), ext)

        return EXIT_OK

    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Interrupted.{Style.RESET_ALL}")
        return EXIT_OK
    finally:
        client.close()


if __name__ == "__main__":
    sys.exit(main())
