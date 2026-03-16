#!/usr/bin/env python3
"""
Cloudflare IP Access Rules Cleanup.

Lists all IP Access Rules in a Cloudflare zone and removes those older
than a configurable number of days. Designed to run daily via cron to
prevent accumulation of stale block rules created by check_abusive_ips.py.

Usage:
    python3 cleanup_rules.py                    # Remove rules older than 30 days
    python3 cleanup_rules.py --days 7           # Remove rules older than 7 days
    python3 cleanup_rules.py --dry-run          # List what would be removed
    python3 cleanup_rules.py --dry-run --days 0 # List ALL rules (useful for audit)
    python3 cleanup_rules.py --only-auto        # Only remove auto-blocked rules
"""

from __future__ import annotations

import argparse
import configparser
import logging
import sys
from dataclasses import dataclass
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
DEFAULT_BAN_DAYS = 30
PAGE_SIZE = 100

logger = logging.getLogger("cleanup_rules")


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
        """Days since the rule was created."""
        delta = datetime.now(timezone.utc) - self.created_on
        return delta.days

    @classmethod
    def from_api(cls, data: dict) -> AccessRule:
        """Parse from Cloudflare API response."""
        config = data.get("configuration") or {}
        notes = data.get("notes") or ""
        created_str = data.get("created_on") or ""

        # Parse ISO 8601 datetime from Cloudflare
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


@dataclass
class CleanupStats:
    """Run statistics."""

    total_rules: int = 0
    expired: int = 0
    removed: int = 0
    skipped: int = 0
    errors: int = 0
    would_remove: int = 0


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
        """
        Fetch all IP Access Rules for the zone.

        Handles pagination automatically.
        """
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
                    raise APIError(
                        f"Unexpected API response type on page {page}: "
                        f"expected JSON object, got {type(body).__name__}"
                    )

                if not body.get("success"):
                    errors = body.get("errors", [])
                    if errors:
                        first = errors[0]
                        msg = first.get("message", str(first)) if isinstance(first, dict) else str(first)
                    else:
                        msg = "Unknown"
                    raise APIError(f"Cloudflare API error on page {page}: {msg}")

                items = body.get("result", [])
                if not items:
                    break

                for item in items:
                    rules.append(AccessRule.from_api(item))

                # Check pagination
                result_info = body.get("result_info", {})
                total_pages = result_info.get("total_pages", 1)

                if page >= total_pages:
                    break
                page += 1

            except requests.HTTPError as exc:
                resp = exc.response
                detail = ""
                if resp is not None:
                    try:
                        body = resp.json()
                        cf_errors = body.get("errors", [])
                        if cf_errors:
                            first = cf_errors[0]
                            detail = first.get("message", str(first)) if isinstance(first, dict) else str(first)
                    except (ValueError, KeyError, AttributeError):
                        pass
                raise APIError(
                    f"Cloudflare API returned HTTP {resp.status_code if resp is not None else '?'} "
                    f"on page {page}"
                    + (f": {detail}" if detail else f": {exc}")
                ) from exc

            except (requests.RequestException, ValueError) as exc:
                raise APIError(
                    f"Network error fetching rules (page {page}): {exc}"
                ) from exc

        return rules

    def delete_rule(self, rule_id: str) -> bool:
        """Delete a single IP Access Rule. Returns True on success."""
        try:
            url = f"{CLOUDFLARE_ACCESS_RULES_URL.format(zone_id=self._zone_id)}/{rule_id}"
            resp = self._session.delete(url, timeout=15)
            body = resp.json()

            if not isinstance(body, dict):
                logger.error("Failed to delete rule %s: unexpected response type", rule_id)
                return False

            if body.get("success"):
                return True

            errors = body.get("errors", [])
            if errors:
                first = errors[0]
                msg = first.get("message", str(first)) if isinstance(first, dict) else str(first)
            else:
                msg = "Unknown"
            logger.error("Failed to delete rule %s: %s", rule_id, msg)
            return False

        except (requests.RequestException, ValueError) as exc:
            logger.error("Failed to delete rule %s: %s", rule_id, exc)
            return False

    def close(self) -> None:
        self._session.close()


# ─── Console Output ─────────────────────────────────────────────────────────

class Console:
    """Handles formatted terminal output."""

    @staticmethod
    def header(dry_run: bool, days: int, only_auto: bool) -> None:
        print()
        print(f"{Fore.YELLOW}══════════════════════════════════════════════{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}  Cloudflare IP Access Rules Cleanup v{VERSION}{Style.RESET_ALL}")
        if dry_run:
            print(f"{Fore.MAGENTA}  ⚠  DRY RUN MODE — Nothing will be deleted{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}══════════════════════════════════════════════{Style.RESET_ALL}")
        print()
        mode = f"{Fore.MAGENTA}DRY RUN{Style.RESET_ALL}" if dry_run else f"{Fore.GREEN}ACTIVE{Style.RESET_ALL}"
        scope = "Auto-blocked only" if only_auto else "All rules"
        print(f"  Max age:   {days} days")
        print(f"  Scope:     {scope}")
        print(f"  Mode:      {mode}")
        print()

    @staticmethod
    def fetching() -> None:
        print(f"  {Fore.YELLOW}Fetching rules from Cloudflare...{Style.RESET_ALL}")

    @staticmethod
    def found(total: int, expired: int) -> None:
        print(f"  Total rules:   {Fore.YELLOW}{total}{Style.RESET_ALL}")
        print(f"  Expired:       {Fore.RED}{expired}{Style.RESET_ALL}")
        print()

    @staticmethod
    def would_remove(rule: AccessRule) -> None:
        auto_tag = f" {Fore.CYAN}[auto]{Style.RESET_ALL}" if rule.is_auto else ""
        print(
            f"  {Fore.MAGENTA}[DRY RUN] {rule.ip} — "
            f"{rule.age_days}d old | {rule.mode}{auto_tag} | "
            f"{rule.notes[:60]}{Style.RESET_ALL}"
        )

    @staticmethod
    def removed(rule: AccessRule) -> None:
        auto_tag = f" {Fore.CYAN}[auto]{Style.RESET_ALL}" if rule.is_auto else ""
        print(
            f"  {Fore.RED}[REMOVED] {rule.ip} — "
            f"{rule.age_days}d old | {rule.mode}{auto_tag} | "
            f"{rule.notes[:60]}{Style.RESET_ALL}"
        )

    @staticmethod
    def error(rule: AccessRule) -> None:
        print(f"  {Fore.RED}[ERROR] Failed to remove {rule.ip}{Style.RESET_ALL}")

    @staticmethod
    def summary(stats: CleanupStats, dry_run: bool) -> None:
        print()
        print(f"{Fore.YELLOW}══════════════════════════════════════════════{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}  SUMMARY{Style.RESET_ALL}")
        if dry_run:
            print(f"{Fore.MAGENTA}  ⚠  DRY RUN MODE — Nothing was deleted{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}══════════════════════════════════════════════{Style.RESET_ALL}")
        print()
        print(f"  Total rules in zone:       {Fore.YELLOW}{stats.total_rules}{Style.RESET_ALL}")
        print(f"  Expired (older than max):  {Fore.YELLOW}{stats.expired}{Style.RESET_ALL}")

        if dry_run:
            print(f"  {Fore.MAGENTA}Would remove:              {stats.would_remove}{Style.RESET_ALL}")
            print()
            print(f"  {Fore.MAGENTA}To actually remove, run without --dry-run{Style.RESET_ALL}")
        else:
            print(f"  {Fore.RED}Removed:                   {stats.removed}{Style.RESET_ALL}")

        if stats.skipped > 0:
            print(f"  {Fore.GREEN}Skipped (not in scope):    {stats.skipped}{Style.RESET_ALL}")
        if stats.errors > 0:
            print(f"  {Fore.RED}Errors:                    {stats.errors}{Style.RESET_ALL}")

        remaining = stats.total_rules - stats.removed
        print(f"  {Fore.YELLOW}Remaining after cleanup:   {remaining}{Style.RESET_ALL}")
        print()


# ─── Application ────────────────────────────────────────────────────────────

class RuleCleanup:
    """Main application for cleaning up expired IP Access Rules."""

    def __init__(self, client: CloudflareClient, days: int, only_auto: bool, dry_run: bool) -> None:
        self._client = client
        self._days = days
        self._only_auto = only_auto
        self._dry_run = dry_run
        self._stats = CleanupStats()
        self._cutoff = datetime.now(timezone.utc) - timedelta(days=days)

    def run(self) -> int:
        """Execute the cleanup pipeline."""
        Console.header(self._dry_run, self._days, self._only_auto)
        Console.fetching()

        try:
            rules = self._client.list_rules()
        except APIError as exc:
            print()
            print(f"  {Fore.RED}✗ {exc}{Style.RESET_ALL}")
            print()
            print(f"  {Fore.YELLOW}Check that your API token and Zone ID are correct")
            print(f"  and that the token has the required permissions.{Style.RESET_ALL}")
            print()
            return EXIT_API_ERROR

        if not rules:
            print(f"  {Fore.GREEN}No IP Access Rules found.{Style.RESET_ALL}")
            return EXIT_OK

        self._stats.total_rules = len(rules)

        # Identify expired rules
        expired = [r for r in rules if r.created_on < self._cutoff]
        self._stats.expired = len(expired)

        Console.found(len(rules), len(expired))

        if not expired:
            print(f"  {Fore.GREEN}No expired rules to clean up.{Style.RESET_ALL}")
            Console.summary(self._stats, self._dry_run)
            return EXIT_OK

        # Process expired rules
        for rule in sorted(expired, key=lambda r: r.created_on):
            # Filter by scope if --only-auto
            if self._only_auto and not rule.is_auto:
                self._stats.skipped += 1
                logger.debug("Skipping non-auto rule: %s (%s)", rule.ip, rule.notes[:40])
                continue

            if self._dry_run:
                Console.would_remove(rule)
                self._stats.would_remove += 1
            else:
                success = self._client.delete_rule(rule.rule_id)
                if success:
                    Console.removed(rule)
                    self._stats.removed += 1
                else:
                    Console.error(rule)
                    self._stats.errors += 1

        Console.summary(self._stats, self._dry_run)
        return EXIT_API_ERROR if self._stats.errors > 0 else EXIT_OK


# ─── Configuration ──────────────────────────────────────────────────────────

def load_config(path: str) -> configparser.ConfigParser:
    """Load config file (shared with check_abusive_ips.py)."""
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
    """Validate Cloudflare credentials are present."""
    errors: list[str] = []

    token = config.get("cloudflare", "api_token", fallback="")
    zone = config.get("cloudflare", "zone_id", fallback="")

    if not token or token.startswith("YOUR_"):
        errors.append("Cloudflare API token not set  →  [cloudflare] api_token")
    if not zone or zone.startswith("YOUR_"):
        errors.append("Cloudflare Zone ID not set  →  [cloudflare] zone_id")

    if errors:
        detail = "\n".join(f"  • {e}" for e in errors)
        raise ConfigError(f"Configuration errors:\n{detail}")


def setup_logging(verbose: bool = False) -> None:
    """Configure logger with stderr output."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        handlers=[logging.StreamHandler(sys.stderr)],
    )


# ─── CLI ────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    """Build and return the argument parser."""
    parser = argparse.ArgumentParser(
        description="Clean up expired Cloudflare IP Access Rules.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  %(prog)s --dry-run                  List what would be removed\n"
            "  %(prog)s --days 7                    Remove rules older than 7 days\n"
            "  %(prog)s --only-auto                 Only remove auto-blocked rules\n"
            "  %(prog)s --dry-run --days 0          Audit: list ALL rules\n"
        ),
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="List expired rules without deleting them",
    )
    parser.add_argument(
        "--days", type=int, default=None,
        help=f"Remove rules older than N days (default: {DEFAULT_BAN_DAYS}, overrides config)",
    )
    parser.add_argument(
        "--only-auto", action="store_true", default=None,
        help=f"Only remove rules with notes starting with '{AUTO_BLOCKED_PREFIX}' (overrides config)",
    )
    parser.add_argument(
        "--config", default="config.ini",
        help="Path to configuration file (default: config.ini)",
    )
    parser.add_argument(
        "--no-color", action="store_true",
        help="Disable colored output (useful for cron/log files)",
    )
    parser.add_argument(
        "--verbose", action="store_true",
        help="Enable debug logging",
    )
    parser.add_argument(
        "--version", action="version",
        version=f"%(prog)s {VERSION}",
    )
    return parser


def main() -> int:
    """Entry point."""
    parser = build_parser()
    args = parser.parse_args()

    colorama_init(strip=args.no_color)
    setup_logging(args.verbose)

    if args.days is not None and args.days < 0:
        print(f"{Fore.RED}--days cannot be negative (got {args.days}){Style.RESET_ALL}", file=sys.stderr)
        return EXIT_CONFIG_ERROR

    try:
        config = load_config(args.config)
        validate_config(config)
    except ConfigError as exc:
        print(f"{Fore.RED}{exc}{Style.RESET_ALL}", file=sys.stderr)
        return EXIT_CONFIG_ERROR

    # Resolve settings: CLI overrides config, config overrides hardcoded defaults
    days = args.days if args.days is not None else config.getint("cleanup", "days", fallback=DEFAULT_BAN_DAYS)
    only_auto = args.only_auto if args.only_auto is not None else config.getboolean("cleanup", "only_auto", fallback=False)

    if days < 0:
        print(f"{Fore.RED}days cannot be negative (got {days}){Style.RESET_ALL}", file=sys.stderr)
        return EXIT_CONFIG_ERROR

    client = CloudflareClient(
        config.get("cloudflare", "api_token"),
        config.get("cloudflare", "zone_id"),
    )

    try:
        app = RuleCleanup(client, days, only_auto, args.dry_run)
        return app.run()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Interrupted by user.{Style.RESET_ALL}")
        return EXIT_OK
    finally:
        client.close()


if __name__ == "__main__":
    sys.exit(main())
