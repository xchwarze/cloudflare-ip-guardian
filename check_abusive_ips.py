#!/usr/bin/env python3
"""
Abusive IP Checker + Cloudflare Blocker.

Extracts unique IPs from nginx access logs, checks them against AbuseIPDB
in parallel, and blocks abusive ones via Cloudflare IP Access Rules.
Optionally reports abusive IPs back to AbuseIPDB.

Usage:
    python3 check_abusive_ips.py                          # Normal mode
    python3 check_abusive_ips.py --dry-run                # Analyze only
    python3 check_abusive_ips.py --lines 20000            # More log lines
    python3 check_abusive_ips.py --threshold 50           # Higher threshold
    python3 check_abusive_ips.py --config /path/config.ini
"""

from __future__ import annotations

import argparse
import configparser
import json
import logging
import os
import re
import signal
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Optional

import requests
from colorama import Fore, Style, init as colorama_init

# ─── Constants ───────────────────────────────────────────────────────────────

VERSION = "1.0.0"
EXIT_OK = 0
EXIT_CONFIG_ERROR = 1
EXIT_RUNTIME_ERROR = 2

ABUSEIPDB_BASE_URL = "https://api.abuseipdb.com/api/v2/check"
ABUSEIPDB_REPORT_URL = "https://api.abuseipdb.com/api/v2/report"
CLOUDFLARE_ACCESS_RULES_URL = (
    "https://api.cloudflare.com/client/v4/zones/{zone_id}/firewall/access_rules/rules"
)

PRIVATE_IP_PATTERN = re.compile(
    r"^(127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|::1|fe80:|fd)"
)

# Basic IPv4/IPv6 format check — rejects garbage tokens from malformed log lines.
IP_FORMAT_PATTERN = re.compile(
    r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|[0-9a-fA-F:]{2,39})$"
)

DEFAULT_CONFIG = {
    "general": {
        "lines": "5000",
        "cache_expiry_days": "7",
        "workers": "auto",
        "min_hits": "3",
    },
    "abuseipdb": {
        "threshold": "30",
        "max_age_days": "90",
        "report": "false",
        "report_categories": "15",
    },
    "cloudflare": {
        "block_method": "cloudflare",
    },
}

# Hard ceiling for concurrent workers regardless of auto-calculation.
# AbuseIPDB free tier = 1000 queries/day; too many threads just causes
# connection churn without meaningful speed gain.
MAX_WORKERS = 20
MIN_WORKERS = 2

logger = logging.getLogger("abusive_ip_checker")


# ─── Exceptions ─────────────────────────────────────────────────────────────

class RateLimitError(Exception):
    """Raised when an API rate limit is hit."""


class ConfigError(Exception):
    """Raised for configuration problems."""


# ─── Data Structures ────────────────────────────────────────────────────────

class BlockMethod(Enum):
    """Available IP blocking methods."""

    CLOUDFLARE = "cloudflare"
    NGINX = "nginx"
    BOTH = "both"


class BlockStatus(Enum):
    """Result status for a block operation."""

    BLOCKED = "blocked"
    DUPLICATE = "duplicate"
    ERROR = "error"


@dataclass
class IPInfo:
    """AbuseIPDB lookup result for a single IP."""

    score: int = 0
    country: str = "??"
    isp: str = "Unknown"
    reports: int = 0
    usage_type: str = "Unknown"
    domain: str = ""
    is_tor: bool = False
    checked_at: str = ""
    reported: bool = False

    def to_dict(self) -> dict:
        """Serialize to dict for JSON cache storage."""
        return {
            "score": self.score,
            "country": self.country,
            "isp": self.isp,
            "reports": self.reports,
            "usage_type": self.usage_type,
            "domain": self.domain,
            "is_tor": self.is_tor,
            "checked_at": self.checked_at,
            "reported": self.reported,
        }

    @classmethod
    def from_dict(cls, data: dict) -> IPInfo:
        """Deserialize from cached JSON dict."""
        return cls(
            score=data.get("score", 0),
            country=data.get("country", "??"),
            isp=data.get("isp", "Unknown"),
            reports=data.get("reports", 0),
            usage_type=data.get("usage_type", "Unknown"),
            domain=data.get("domain", ""),
            is_tor=data.get("is_tor", False),
            checked_at=data.get("checked_at", ""),
            reported=data.get("reported", False),
        )


@dataclass
class BlockResult:
    """Result of a block operation."""

    status: BlockStatus
    message: str = ""


@dataclass
class Stats:
    """Run statistics."""

    total: int = 0
    checked: int = 0
    cached: int = 0
    abusive: int = 0
    clean: int = 0
    blocked_cf: int = 0
    blocked_nginx: int = 0
    would_block: int = 0
    reported: int = 0
    errors: int = 0


# ─── Cache Manager ──────────────────────────────────────────────────────────

class CacheManager:
    """JSON-based cache to avoid repeated AbuseIPDB queries."""

    def __init__(self, cache_file: str, expiry_days: int = 7) -> None:
        self._path = Path(cache_file)
        self._expiry_days = expiry_days
        self._data: dict[str, dict] = {}
        self._lock = threading.Lock()
        self._dirty = False
        self._load()

    def _load(self) -> None:
        if not self._path.exists():
            return
        try:
            loaded = json.loads(self._path.read_text(encoding="utf-8"))
            if not isinstance(loaded, dict):
                logger.warning("Cache file is not a JSON object, starting fresh.")
                loaded = {}
            self._data = loaded
        except (json.JSONDecodeError, IOError) as exc:
            logger.warning("Failed to load cache (%s), starting fresh.", exc)
            self._data = {}
        self._purge_expired()

    def _purge_expired(self) -> None:
        cutoff = (datetime.now() - timedelta(days=self._expiry_days)).isoformat()
        before = len(self._data)
        self._data = {
            ip: entry
            for ip, entry in self._data.items()
            if isinstance(entry, dict) and entry.get("checked_at", "") > cutoff
        }
        purged = before - len(self._data)
        if purged:
            logger.debug("Purged %d expired cache entries.", purged)

    def get(self, ip: str) -> Optional[IPInfo]:
        """Retrieve cached IP info, or None if not cached."""
        with self._lock:
            entry = self._data.get(ip)
        if entry is None:
            return None
        return IPInfo.from_dict(entry)

    def set(self, ip: str, info: IPInfo) -> None:
        """Store IP info in cache."""
        data = info.to_dict()
        data["checked_at"] = datetime.now().isoformat()
        with self._lock:
            self._data[ip] = data
            self._dirty = True

    def save(self) -> None:
        """Persist cache to disk. No-op if nothing changed since last save."""
        if not self._dirty:
            return

        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            with self._lock:
                payload = json.dumps(self._data, indent=2, ensure_ascii=False)
            # Atomic write: temp file + rename to avoid partial writes on crash
            tmp_path = self._path.with_suffix(".tmp")
            tmp_path.write_text(payload, encoding="utf-8")
            tmp_path.replace(self._path)
            self._dirty = False
            logger.debug("Cache saved: %d entries.", len(self._data))
        except IOError as exc:
            logger.error("Failed to save cache: %s", exc)

# ─── AbuseIPDB Client ──────────────────────────────────────────────────────

class AbuseIPDBClient:
    """HTTP client for the AbuseIPDB v2 API."""

    def __init__(self, api_key: str, max_age_days: int = 90) -> None:
        self._max_age_days = max_age_days
        self._api_key = api_key
        self._local = threading.local()

    def _get_session(self) -> requests.Session:
        """Return a thread-local session (one per thread)."""
        if not hasattr(self._local, "session"):
            self._local.session = requests.Session()
            self._local.session.headers.update({
                "Key": self._api_key,
                "Accept": "application/json",
            })
        return self._local.session

    def check(self, ip: str) -> IPInfo:
        """
        Query AbuseIPDB for a single IP.

        Raises:
            RateLimitError: On HTTP 429.
            requests.HTTPError: On other HTTP errors.
            requests.ConnectionError: On network failures.
        """
        session = self._get_session()
        resp = session.get(
            ABUSEIPDB_BASE_URL,
            params={"ipAddress": ip, "maxAgeInDays": self._max_age_days},
            timeout=15,
        )

        if resp.status_code == 429:
            raise RateLimitError("AbuseIPDB daily query limit reached.")

        resp.raise_for_status()
        data = resp.json().get("data", {})

        return IPInfo(
            score=data.get("abuseConfidenceScore", 0),
            country=data.get("countryCode", "??"),
            isp=data.get("isp", "Unknown"),
            reports=data.get("totalReports", 0),
            usage_type=data.get("usageType", "Unknown"),
            domain=data.get("domain", ""),
            is_tor=data.get("isTor", False),
        )

    def report(self, ip: str, categories: str, comment: str = "") -> bool:
        """
        Report an abusive IP to AbuseIPDB.

        Args:
            ip: The IP address to report.
            categories: Comma-separated category IDs (e.g. "15,18").
            comment: Optional description of the abuse.

        Returns:
            True on success, False on error.
        """
        session = self._get_session()
        try:
            resp = session.post(
                ABUSEIPDB_REPORT_URL,
                json={
                    "ip": ip,
                    "categories": categories,
                    "comment": comment[:1024],
                },
                timeout=15,
            )

            if resp.status_code == 429:
                logger.warning("AbuseIPDB rate limit hit while reporting %s.", ip)
                return False

            if resp.status_code == 422:
                logger.debug("AbuseIPDB rejected report for %s (already reported recently?).", ip)
                return True  # Not an error — IP was already reported in the cooldown window

            resp.raise_for_status()
            return True

        except (requests.RequestException, ValueError) as exc:
            logger.error("Failed to report %s to AbuseIPDB: %s", ip, exc)
            return False

    def close(self) -> None:
        """Close the thread-local session, if any."""
        session = getattr(self._local, "session", None)
        if session is not None:
            session.close()


# ─── Cloudflare Blocker ────────────────────────────────────────────────────

class CloudflareBlocker:
    """Blocks IPs via Cloudflare IP Access Rules API."""

    def __init__(self, api_token: str, zone_id: str) -> None:
        self._zone_id = zone_id
        self._session = requests.Session()
        self._session.headers.update({
            "Authorization": f"Bearer {api_token}",
            "Content-Type": "application/json",
        })

    def block(self, ip: str, note: str = "") -> BlockResult:
        """Create a block rule for the given IP."""
        try:
            resp = self._session.post(
                CLOUDFLARE_ACCESS_RULES_URL.format(zone_id=self._zone_id),
                json={
                    "mode": "block",
                    "configuration": {"target": "ip", "value": ip},
                    "notes": note[:500],
                },
                timeout=15,
            )
            body = resp.json()

            if body.get("success"):
                return BlockResult(BlockStatus.BLOCKED)

            errors = body.get("errors", [])
            if any("duplicate" in str(e).lower() for e in errors):
                return BlockResult(BlockStatus.DUPLICATE)

            if errors:
                first = errors[0]
                msg = first.get("message", str(first)) if isinstance(first, dict) else str(first)
            else:
                msg = "Unknown"
            return BlockResult(BlockStatus.ERROR, msg)

        except (requests.RequestException, ValueError) as exc:
            return BlockResult(BlockStatus.ERROR, str(exc))

    def close(self) -> None:
        self._session.close()


# ─── Nginx Blocker ──────────────────────────────────────────────────────────

class NginxBlocker:
    """Blocks IPs by appending deny rules to an nginx include file."""

    def __init__(self, block_file: str) -> None:
        self._path = Path(block_file)

    def block(self, ip: str, note: str = "") -> BlockResult:
        """Append a deny directive for the given IP."""
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            self._path.touch(exist_ok=True)

            if f"deny {ip};" in self._path.read_text(encoding="utf-8"):
                return BlockResult(BlockStatus.DUPLICATE)

            with open(self._path, "a", encoding="utf-8") as fh:
                fh.write(f"deny {ip};  # {note}\n")

            return BlockResult(BlockStatus.BLOCKED)

        except IOError as exc:
            return BlockResult(BlockStatus.ERROR, str(exc))


# ─── Log Parser ─────────────────────────────────────────────────────────────

class LogParser:
    """Extracts unique public IPs from nginx combined-format logs."""

    @staticmethod
    def extract(log_file: str, lines: int, min_hits: int = 1) -> list[str]:
        """
        Return sorted list of unique public IPs from the last *lines* of *log_file*.

        Only IPs that appear at least *min_hits* times are included.

        Raises:
            FileNotFoundError: If the log file does not exist.
            RuntimeError: If the tail command fails.
        """
        path = Path(log_file)
        if not path.exists():
            raise FileNotFoundError(f"Log file not found: {log_file}")

        result = subprocess.run(
            ["tail", "-n", str(lines), log_file],
            capture_output=True,
            text=True,
        )

        if result.returncode != 0:
            raise RuntimeError(f"tail command failed: {result.stderr.strip()}")

        hit_counts: dict[str, int] = {}
        for line in result.stdout.splitlines():
            parts = line.split(maxsplit=1)
            if not parts:
                continue
            ip = parts[0]
            if ip != "-" and IP_FORMAT_PATTERN.match(ip) and not PRIVATE_IP_PATTERN.match(ip):
                hit_counts[ip] = hit_counts.get(ip, 0) + 1

        total_unique = len(hit_counts)
        filtered = sorted(ip for ip, count in hit_counts.items() if count >= min_hits)

        logger.debug(
            "Extracted %d unique IPs from %d log lines (%d passed min_hits=%d).",
            total_unique, lines, len(filtered), min_hits,
        )
        return filtered


# ─── Console Output ─────────────────────────────────────────────────────────

class Console:
    """Handles formatted terminal output."""

    @staticmethod
    def header(dry_run: bool, config: dict) -> None:
        print()
        print(f"{Fore.YELLOW}══════════════════════════════════════════════{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}  Abusive IP Checker + Cloudflare Blocker v{VERSION}{Style.RESET_ALL}")
        if dry_run:
            print(f"{Fore.MAGENTA}  ⚠  DRY RUN MODE — Nothing will be blocked{Style.RESET_ALL}")

        print(f"{Fore.YELLOW}══════════════════════════════════════════════{Style.RESET_ALL}")
        print()

        mode = f"{Fore.MAGENTA}DRY RUN{Style.RESET_ALL}" if dry_run else f"{Fore.GREEN}ACTIVE{Style.RESET_ALL}"
        report = f"{Fore.GREEN}ON{Style.RESET_ALL}" if config.get("report") else f"{Fore.YELLOW}OFF{Style.RESET_ALL}"

        print(f"  Log:       {config['log_file']}")
        print(f"  Lines:     {config['lines']}")
        print(f"  Min hits:  {config['min_hits']}")
        print(f"  Threshold: {config['threshold']}%")
        print(f"  Workers:   {config['workers']}")
        print(f"  Method:    {config['block_method']}")
        print(f"  Report:    {report}")
        print(f"  Mode:      {mode}")
        print()

    @staticmethod
    def ip_found(count: int) -> None:
        print(f"  Unique IPs found: {Fore.YELLOW}{count}{Style.RESET_ALL}")
        print()

    @staticmethod
    def cached(ip: str, score: int) -> None:
        print(f"  [CACHE] {Fore.RED}{ip} — Score: {score}%{Style.RESET_ALL}")

    @staticmethod
    def abusive(ip: str, info: IPInfo) -> None:
        print(
            f"  {Fore.RED}[ABUSIVE] {ip} — Score: {info.score}% | "
            f"{info.country} | {info.isp} | Reports: {info.reports} | "
            f"Type: {info.usage_type}{Style.RESET_ALL}"
        )

    @staticmethod
    def clean(ip: str, info: IPInfo) -> None:
        print(f"  {Fore.GREEN}[OK] {ip} — Score: {info.score}% | {info.country}{Style.RESET_ALL}")

    @staticmethod
    def blocked_cf(status: BlockStatus, message: str = "") -> None:
        if status == BlockStatus.BLOCKED:
            print(f"    {Fore.CYAN}→ Blocked in Cloudflare{Style.RESET_ALL}")
        elif status == BlockStatus.DUPLICATE:
            print(f"    {Fore.YELLOW}→ Already blocked in Cloudflare{Style.RESET_ALL}")
        else:
            print(f"    {Fore.RED}→ Cloudflare error: {message}{Style.RESET_ALL}")

    @staticmethod
    def blocked_nginx(status: BlockStatus, message: str = "") -> None:
        if status == BlockStatus.BLOCKED:
            print(f"    {Fore.CYAN}→ Added to nginx blocklist{Style.RESET_ALL}")
        elif status == BlockStatus.DUPLICATE:
            print(f"    {Fore.YELLOW}→ Already in nginx blocklist{Style.RESET_ALL}")
        else:
            print(f"    {Fore.RED}→ Nginx error: {message}{Style.RESET_ALL}")

    @staticmethod
    def reported_ok(ip: str) -> None:
        print(f"    {Fore.CYAN}→ Reported to AbuseIPDB{Style.RESET_ALL}")

    @staticmethod
    def reported_skip(ip: str) -> None:
        print(f"    {Fore.YELLOW}→ Already reported to AbuseIPDB{Style.RESET_ALL}")

    @staticmethod
    def reported_fail(ip: str, message: str) -> None:
        print(f"    {Fore.RED}→ AbuseIPDB report failed: {message}{Style.RESET_ALL}")

    @staticmethod
    def error(ip: str, message: str) -> None:
        print(f"  {Fore.YELLOW}[!] {ip} — {message}{Style.RESET_ALL}")

    @staticmethod
    def rate_limit() -> None:
        print(f"  {Fore.RED}[!] AbuseIPDB rate limit reached. Stopping queries.{Style.RESET_ALL}")

    @staticmethod
    def summary(stats: Stats, dry_run: bool, block_method: BlockMethod, report_enabled: bool) -> None:
        print()
        print(f"{Fore.YELLOW}══════════════════════════════════════════════{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}  SUMMARY{Style.RESET_ALL}")
        if dry_run:
            print(f"{Fore.MAGENTA}  ⚠  DRY RUN MODE — Nothing was blocked{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}══════════════════════════════════════════════{Style.RESET_ALL}")
        print()
        print(f"  Unique IPs analyzed:       {Fore.YELLOW}{stats.total}{Style.RESET_ALL}")
        print(f"  Queried (new):             {Fore.YELLOW}{stats.checked}{Style.RESET_ALL}")
        print(f"  From cache:                {Fore.YELLOW}{stats.cached}{Style.RESET_ALL}")
        print(f"  {Fore.RED}Abusive found:             {stats.abusive}{Style.RESET_ALL}")

        if dry_run:
            print(f"  {Fore.MAGENTA}Would be blocked:          {stats.would_block}{Style.RESET_ALL}")
            print()
            print(f"  {Fore.MAGENTA}To actually block, run without --dry-run{Style.RESET_ALL}")
        else:
            if block_method in (BlockMethod.CLOUDFLARE, BlockMethod.BOTH):
                print(f"  {Fore.CYAN}Blocked in Cloudflare:     {stats.blocked_cf}{Style.RESET_ALL}")
            if block_method in (BlockMethod.NGINX, BlockMethod.BOTH):
                print(f"  {Fore.CYAN}Blocked in nginx:          {stats.blocked_nginx}{Style.RESET_ALL}")
            if report_enabled:
                print(f"  {Fore.CYAN}Reported to AbuseIPDB:     {stats.reported}{Style.RESET_ALL}")

        print(f"  {Fore.GREEN}Clean:                     {stats.clean}{Style.RESET_ALL}")

        if stats.errors > 0:
            print(f"  {Fore.RED}Errors:                    {stats.errors}{Style.RESET_ALL}")

        print()


# ─── Application ────────────────────────────────────────────────────────────

class AbusiveIPChecker:
    """Main application that orchestrates IP checking and blocking."""

    def __init__(self, config: configparser.ConfigParser, args: argparse.Namespace) -> None:
        self._dry_run = args.dry_run
        self._lines = args.lines if args.lines is not None else config.getint("general", "lines", fallback=5000)
        self._threshold = args.threshold if args.threshold is not None else config.getint("abuseipdb", "threshold", fallback=30)
        self._min_hits = args.min_hits if args.min_hits is not None else config.getint("general", "min_hits", fallback=3)
        self._log_file = config.get("general", "log_file")
        self._block_method = BlockMethod(config.get("cloudflare", "block_method", fallback="cloudflare"))

        # Workers: "auto" or explicit int
        workers_cfg = config.get("general", "workers", fallback="auto")
        self._workers_cfg = workers_cfg  # stored for display; actual count decided at runtime

        # Reporting: off by default, enable in config or CLI
        self._report_enabled = config.getboolean("abuseipdb", "report", fallback=False)
        self._report_categories = config.get("abuseipdb", "report_categories", fallback="15")
        # Default lives in fallback= (not DEFAULT_CONFIG) because configparser's
        # interpolation chokes on the literal % in "Score: {score}%".
        # In config.ini, users must write %% for a literal % (standard INI escaping).
        self._report_comment = config.get(
            "abuseipdb", "report_comment",
            fallback="Score: {score}% | {country} | {isp} | Reports: {reports} | Type: {usage_type}",
        )

        # Cache: loaded to memory on init, saved to disk on close()
        self._cache = CacheManager(
            config.get("general", "cache_file", fallback="/root/abusive_ips_cache.json"),
            config.getint("general", "cache_expiry_days", fallback=7),
        )
        self._abuseipdb = AbuseIPDBClient(
            config.get("abuseipdb", "api_key"),
            config.getint("abuseipdb", "max_age_days", fallback=90),
        )
        self._cf_blocker: Optional[CloudflareBlocker] = None
        self._nginx_blocker: Optional[NginxBlocker] = None

        if not self._dry_run:
            if self._block_method in (BlockMethod.CLOUDFLARE, BlockMethod.BOTH):
                self._cf_blocker = CloudflareBlocker(
                    config.get("cloudflare", "api_token"),
                    config.get("cloudflare", "zone_id"),
                )
            if self._block_method in (BlockMethod.NGINX, BlockMethod.BOTH):
                self._nginx_blocker = NginxBlocker(
                    config.get("nginx", "block_file",
                               fallback="/etc/nginx/conf.d/blocked_ips.conf"),
                )

        self._stats = Stats()
        self._rate_limit_event = threading.Event()
        self._rate_limit_lock = threading.Lock()

    @staticmethod
    def _calculate_workers(uncached_count: int, workers_cfg: str) -> int:
        """
        Determine the optimal number of threads.

        If workers_cfg is "auto", scale based on uncached IPs and CPU count.
        Otherwise, use the explicit value from config.
        """
        if workers_cfg.strip().lower() != "auto":
            try:
                return max(MIN_WORKERS, min(int(workers_cfg), MAX_WORKERS))
            except ValueError:
                logger.warning("Invalid workers value '%s', falling back to auto.", workers_cfg)

        if uncached_count == 0:
            return MIN_WORKERS

        # Scale: cpu_count * 2, capped by actual work and hard ceiling
        cpu_based = (os.cpu_count() or 4) * 2
        return max(MIN_WORKERS, min(uncached_count, cpu_based, MAX_WORKERS))

    def _query_ip(self, ip: str) -> tuple[str, Optional[IPInfo], Optional[str]]:
        """
        Query a single IP against AbuseIPDB. Returns (ip, info, error_message).

        Thread-safe: AbuseIPDB sessions are thread-local, cache.set()
        is protected by a lock, and rate limiting uses threading.Event.
        """
        if self._rate_limit_event.is_set():
            return ip, None, "Skipped (rate limited)"

        try:
            info = self._abuseipdb.check(ip)
            self._cache.set(ip, info)
            return ip, info, None
        except RateLimitError:
            with self._rate_limit_lock:
                if not self._rate_limit_event.is_set():
                    self._rate_limit_event.set()
                    Console.rate_limit()
            return ip, None, "Rate limit reached"
        except (requests.RequestException, ValueError) as exc:
            return ip, None, f"Query error: {exc}"

    def _block_ip(self, ip: str, info: IPInfo) -> None:
        """Execute block action(s) for a confirmed abusive IP."""
        note = (
            f"Auto-blocked | Score: {info.score}% | "
            f"{info.country} | {info.isp} | {datetime.now():%Y-%m-%d}"
        )

        if self._cf_blocker:
            result = self._cf_blocker.block(ip, note)
            Console.blocked_cf(result.status, result.message)
            if result.status in (BlockStatus.BLOCKED, BlockStatus.DUPLICATE):
                self._stats.blocked_cf += 1
            elif result.status == BlockStatus.ERROR:
                self._stats.errors += 1

        if self._nginx_blocker:
            result = self._nginx_blocker.block(ip, note)
            Console.blocked_nginx(result.status, result.message)
            if result.status in (BlockStatus.BLOCKED, BlockStatus.DUPLICATE):
                self._stats.blocked_nginx += 1
            elif result.status == BlockStatus.ERROR:
                self._stats.errors += 1

        if self._report_enabled:
            self._report_ip(ip, info)

    def _report_ip(self, ip: str, info: IPInfo) -> None:
        """Report an abusive IP to AbuseIPDB and mark it in cache."""
        if info.reported:
            Console.reported_skip(ip)
            return

        try:
            comment = self._report_comment.format(
                score=info.score,
                country=info.country,
                isp=info.isp,
                reports=info.reports,
                usage_type=info.usage_type,
                domain=info.domain,
                is_tor=info.is_tor,
            )
        except (KeyError, ValueError, IndexError) as exc:
            logger.warning("Bad report_comment template: %s. Using fallback.", exc)
            comment = f"Score: {info.score}% | {info.country} | {info.isp}"

        success = self._abuseipdb.report(ip, self._report_categories, comment)
        if success:
            Console.reported_ok(ip)
            self._stats.reported += 1
            info.reported = True
            self._cache.set(ip, info)
        else:
            Console.reported_fail(ip, "see log for details")

    def run(self) -> int:
        """
        Execute the full check-and-block pipeline.

        Flow:
            1. Extract unique IPs from the log.
            2. Separate cached from uncached IPs (cache is already in memory).
            3. Auto-calculate thread count based on uncached IPs.
            4. Query only uncached IPs in parallel via ThreadPoolExecutor.
            5. Process all results (cached + fresh) and block abusive IPs.
            6. Save cache to disk.

        Returns:
            Exit code (0 = success, 2 = runtime error).
        """
        # Extract IPs from log
        try:
            ips = LogParser.extract(self._log_file, self._lines, self._min_hits)
        except (OSError, RuntimeError) as exc:
            logger.error(str(exc))
            return EXIT_RUNTIME_ERROR

        self._stats.total = len(ips)

        if not ips:
            Console.header(self._dry_run, {
                "log_file": self._log_file,
                "lines": self._lines,
                "min_hits": self._min_hits,
                "threshold": self._threshold,
                "workers": 0,
                "block_method": self._block_method.value,
                "report": self._report_enabled,
            })
            Console.ip_found(0)
            return EXIT_OK

        # ── Phase 1: Separate cached from uncached ──────────────────────
        cached_results: list[tuple[str, IPInfo]] = []
        uncached_ips: list[str] = []

        for ip in ips:
            cached = self._cache.get(ip)
            if cached is not None:
                cached_results.append((ip, cached))
            else:
                uncached_ips.append(ip)

        self._stats.cached = len(cached_results)

        # ── Phase 2: Calculate workers ──────────────────────────────────
        workers = self._calculate_workers(len(uncached_ips), self._workers_cfg)

        Console.header(self._dry_run, {
            "log_file": self._log_file,
            "lines": self._lines,
            "min_hits": self._min_hits,
            "threshold": self._threshold,
            "workers": workers,
            "block_method": self._block_method.value,
            "report": self._report_enabled,
        })
        Console.ip_found(len(ips))

        logger.debug(
            "IPs: %d total, %d cached, %d to query with %d workers.",
            len(ips), len(cached_results), len(uncached_ips), workers,
        )

        # ── Phase 3: Process cached results ─────────────────────────────
        for ip, info in sorted(cached_results, key=lambda r: r[0]):
            if info.score >= self._threshold:
                Console.cached(ip, info.score)
                self._stats.abusive += 1

                if self._dry_run:
                    self._stats.would_block += 1
                else:
                    self._block_ip(ip, info)

        # ── Phase 4: Query uncached IPs in parallel ─────────────────────
        fresh_results: list[tuple[str, Optional[IPInfo], Optional[str]]] = []

        if uncached_ips:
            with ThreadPoolExecutor(max_workers=workers) as pool:
                futures = {pool.submit(self._query_ip, ip): ip for ip in uncached_ips}
                for future in as_completed(futures):
                    try:
                        fresh_results.append(future.result())
                    except Exception as exc:
                        failed_ip = futures[future]
                        logger.debug("Unexpected error for %s: %s", failed_ip, exc)
                        fresh_results.append((failed_ip, None, f"Unexpected error: {exc}"))

        # Sort for consistent output
        fresh_results.sort(key=lambda r: r[0])

        # ── Phase 5: Process fresh results ──────────────────────────────
        for ip, info, error in fresh_results:
            if error:
                Console.error(ip, error)
                self._stats.errors += 1
                continue

            if info is None:
                continue

            self._stats.checked += 1

            if info.score >= self._threshold:
                Console.abusive(ip, info)
                self._stats.abusive += 1

                if self._dry_run:
                    self._stats.would_block += 1
                else:
                    self._block_ip(ip, info)
            else:
                self._stats.clean += 1
                if info.score > 0:
                    Console.clean(ip, info)

        # ── Phase 6: Persist and report ─────────────────────────────────
        self._cache.save()
        Console.summary(self._stats, self._dry_run, self._block_method, self._report_enabled)

        if (
            not self._dry_run
            and self._nginx_blocker
            and self._stats.blocked_nginx > 0
        ):
            print(f"  {Fore.YELLOW}Don't forget to reload nginx:{Style.RESET_ALL}")
            print("  nginx -t && systemctl reload nginx")
            print()

        return EXIT_RUNTIME_ERROR if self._stats.errors > 0 else EXIT_OK

    def close(self) -> None:
        """Release HTTP sessions and persist cache to disk."""
        self._cache.save()
        self._abuseipdb.close()
        if self._cf_blocker:
            self._cf_blocker.close()


# ─── Configuration ──────────────────────────────────────────────────────────

def load_config(path: str) -> configparser.ConfigParser:
    """Load and return the INI config file, applying defaults."""
    config = configparser.ConfigParser()
    config.read_dict(DEFAULT_CONFIG)

    config_path = Path(path)
    if not config_path.exists():
        raise ConfigError(
            f"Config file not found: {path}\n"
            f"Create one from config.ini.example or specify path with --config"
        )

    config.read(config_path)
    return config


def validate_config(config: configparser.ConfigParser, dry_run: bool) -> None:
    """Validate required config values. Raises ConfigError on problems."""
    errors: list[str] = []

    if not config.has_option("general", "log_file"):
        errors.append("Log file path not set  →  [general] log_file")

    api_key = config.get("abuseipdb", "api_key", fallback="")
    if not api_key or api_key.startswith("YOUR_"):
        errors.append("AbuseIPDB API key not set  →  [abuseipdb] api_key")

    method = config.get("cloudflare", "block_method", fallback="cloudflare")
    valid_methods = {m.value for m in BlockMethod}
    if method not in valid_methods:
        errors.append(
            f"Invalid block_method '{method}'  →  [cloudflare] block_method "
            f"(must be one of: {', '.join(sorted(valid_methods))})"
        )

    if not dry_run and method in ("cloudflare", "both"):
        token = config.get("cloudflare", "api_token", fallback="")
        zone = config.get("cloudflare", "zone_id", fallback="")
        if not token or token.startswith("YOUR_"):
            errors.append("Cloudflare API token not set  →  [cloudflare] api_token")
        if not zone or zone.startswith("YOUR_"):
            errors.append("Cloudflare Zone ID not set  →  [cloudflare] zone_id")

    if errors:
        detail = "\n".join(f"  • {e}" for e in errors)
        raise ConfigError(
            f"Configuration errors:\n{detail}\n\n"
            f"Edit config.ini or use --dry-run to analyze only."
        )


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
        description="Check nginx log IPs against AbuseIPDB and block via Cloudflare.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  %(prog)s --dry-run                  Analyze only\n"
            "  %(prog)s --lines 20000               Scan more log lines\n"
            "  %(prog)s --threshold 50              Stricter threshold\n"
            "  %(prog)s --config /etc/checker.ini   Custom config path\n"
        ),
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Analyze only, do not block anything",
    )
    parser.add_argument(
        "--lines", type=int, default=None,
        help="Number of log lines to analyze (overrides config)",
    )
    parser.add_argument(
        "--threshold", type=int, default=None,
        help="Minimum abuse score to block, 0-100 (overrides config)",
    )
    parser.add_argument(
        "--min-hits", type=int, default=None,
        help="Minimum log appearances before checking an IP (overrides config, default: 3)",
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
    """Entry point. Returns process exit code."""
    parser = build_parser()
    args = parser.parse_args()

    colorama_init(strip=args.no_color)
    setup_logging(args.verbose)

    try:
        config = load_config(args.config)
        validate_config(config, args.dry_run)
    except ConfigError as exc:
        print(f"{Fore.RED}{exc}{Style.RESET_ALL}", file=sys.stderr)
        return EXIT_CONFIG_ERROR

    app = AbusiveIPChecker(config, args)

    # Ensure cache is saved on SIGTERM (e.g. killed by cron or systemd)
    def _handle_signal(signum: int, _frame) -> None:  # noqa: ANN001
        logger.info("Received signal %d, saving cache and exiting.", signum)
        app.close()
        # Use os._exit to avoid triggering the finally block (which calls close again)
        os._exit(EXIT_OK)

    signal.signal(signal.SIGTERM, _handle_signal)

    try:
        return app.run()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Interrupted by user.{Style.RESET_ALL}")
        return EXIT_OK
    finally:
        app.close()


if __name__ == "__main__":
    sys.exit(main())
