#!/usr/bin/env python3
"""
scan_tech_stack.py - flag Shopify, Klaviyo, Meta Pixel and GA4 on a list of domains
using the local webanalyze binary (Go port of Wappalyzer).

    domains_raw.csv (column "domain")  ->  domains_shopify.csv
    domain,is_shopify,has_klaviyo,has_meta_pixel,has_ga4,scan_status

No paid APIs, no third-party services, standard library only (Python 3.8+).

Usage:
    python3 scan_tech_stack.py --test        # first 3 domains, print parsed flags, no CSV
    python3 scan_tech_stack.py               # full run
    python3 scan_tech_stack.py --help        # all options

webanalyze behaviour this script relies on. Each point was verified against the
webanalyze v0.3.9 source and the compiled binary, so none of it is assumed:

1. `-output json` prints ONE JSON OBJECT PER LINE (NDJSON), not an array:
       {"hostname": "https://example.com",
        "matches": [{"app_name": "Shopify", "version": "",
                     "app": {"category_names": ["Ecommerce"], "cats": ["6"], ...},
                     "matches": [["<evidence>"]]}]}
   If nothing is detected you get "matches": []. If the fetch fails, stdout is empty.
2. Fetch failures (DNS, refused, TLS, timeout) still EXIT 0. The only signal is a
   "<url> error: Failed to retrieve: ..." line on stderr. A non-zero exit means a
   fatal problem, e.g. technologies.json is missing.
3. Boolean flags need "=". With `-search false`, Go's flag parser stops at "false"
   and silently ignores every later flag (-output json, -silent, -worker ...).
4. Cross-host redirects (example.com -> www.example.com) are NOT followed by
   default. `-redirect` follows one such hop, only when -search is true, and only
   when the target has the same registrable domain. The target comes back as an
   extra JSON line. Same-host redirects (http -> https, path) are always followed.
5. `webanalyze -update` keeps only the cookies/headers/meta/html/scripts/url rules
   and drops Wappalyzer's scriptSrc/js/dom rules. With the stock definitions,
   Klaviyo can never be detected, and the Meta Pixel and GA4 almost never are.
   EXTRA_FINGERPRINTS adds raw-HTML equivalents through webanalyze's own -apps flag.
"""
from __future__ import annotations

import argparse
import csv
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone

LOG = logging.getLogger("scan_tech_stack")
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

OUTPUT_COLUMNS = ["domain", "is_shopify", "has_klaviyo", "has_meta_pixel", "has_ga4", "scan_status"]
FLAG_COLUMNS = OUTPUT_COLUMNS[1:5]
FLAG_LABELS = {"is_shopify": "Shopify", "has_klaviyo": "Klaviyo",
               "has_meta_pixel": "Meta Pixel", "has_ga4": "GA4"}
STATUSES = ("OK", "EMPTY", "ERROR", "TIMEOUT")

TECH_FILE = "technologies.json"
AUGMENTED_FILE = "technologies.augmented.json"
REQUIRED_FLAGS = {"host", "output", "crawl", "silent", "worker", "search", "apps", "update"}
TEST_DOMAIN_COUNT = 3
MAX_CONSECUTIVE_CRASHES = 3  # non-zero exits in a row => systemic problem, abort

INSTALL_HELP = """\
webanalyze binary not found (looked for ./webanalyze, next to this script, and on PATH).

Install it (needs a recent Go toolchain from https://go.dev/dl/):
    go install -v github.com/rverton/webanalyze/cmd/webanalyze@latest
    export PATH="$PATH:$(go env GOPATH)/bin"     # go install puts it in ~/go/bin

or build it from a local clone:
    git clone https://github.com/rverton/webanalyze && cd webanalyze
    go build -o webanalyze ./cmd/webanalyze

or download a prebuilt release: https://github.com/rverton/webanalyze/releases

Then re-run, or point at it explicitly: --webanalyze /path/to/webanalyze"""

# --------------------------------------------------------------------------------------
# Supplemental fingerprints. They're merged into a copy of technologies.json and passed
# to webanalyze with -apps, so detection still happens inside the webanalyze binary.
# Each pattern is a raw-HTML equivalent of an upstream Wappalyzer scriptSrc/js/dom rule
# that `-update` throws away. All of them were checked against real Shopify storefront
# HTML (positives) and against github.com, pypi.org and a WooCommerce page (no false
# positives). Syntax is Go RE2; webanalyze adds (?i). `[\\/]` also matches the
# JSON-escaped "\/" that Shopify uses inside inline scripts.
# --------------------------------------------------------------------------------------
EXTRA_FINGERPRINTS = {
    "Shopify": {
        "html": [
            r"""Shopify\.shop\s*=\s*['"][\w.-]+\.myshopify\.com""",  # content_for_header
        ],
        # the upstream url rule is "^https?//..." (missing ':') so it never matches
        "url": [r"^https?://[^/]+\.myshopify\.com"],
    },
    "Klaviyo": {
        "html": [
            r"(?:static|a|fast|static-tracking|static-forms)\.klaviyo\.com",  # onsite JS / API
            r"shopify://apps/klaviyo",  # Shopify app-embed block marker
            r"\b_learnq\b",             # Klaviyo JS queue
            r"\b_klOnsite\b",           # official onsite snippet
        ],
    },
    "Facebook Pixel": {
        "html": [
            r"connect\.facebook\.net[\\/]+[\w-]+[\\/]+fbevents\.js",  # Meta base code
            r"""fbq\(\s*['"]init['"]""",                            # fbq('init', '<id>')
            r"facebook\.com[\\/]+tr[\\/]?\?id=",                      # <noscript> pixel
            r"pixel_type\W{1,16}facebook_pixel",                      # Shopify FB & IG web pixel
        ],
    },
    # A new entry, so that the brief's name rule ("Google Analytics 4") can match.
    "Google Analytics 4": {
        "cats": ["10"],  # Analytics
        "website": "https://developers.google.com/analytics/devguides/collection/ga4",
        "html": [
            r"googletagmanager\.com[\\/]+gtag[\\/]+js\?id=G-[A-Z0-9]{4,}",  # gtag.js + G- ID
            r"""gtag\(\s*['"]config['"]\s*,\s*['"]G-[A-Z0-9]{4,}""",       # gtag('config','G-')
            r"google_tag_ids[^\]]{0,200}?G-[A-Z0-9]{4,}",  # Shopify Google & YouTube web pixel
        ],
    },
}

# webanalyze prints fetch failures as "<url> error: <message>" on stderr.
_FETCH_ERROR_RE = re.compile(r"^(?P<url>\S+) error: (?P<msg>.+)$", re.MULTILINE)
_TIMEOUT_HINTS = ("timeout", "deadline exceeded")
_DNS_HINTS = ("no such host",)
# Regex fallback for output that is not valid JSON
_APP_NAME_RE = re.compile(r'"app_name"\s*:\s*"((?:[^"\\]|\\.)*)"')
_TEXT_ROW_RE = re.compile(r"^ {4}(?P<name>[^,\n]+), (?P<version>[^(\n]*?) ?\((?P<cats>[^)\n]*)\)\s*$",
                          re.MULTILINE)  # webanalyze's human-readable "-output stdout" rows
_FALLBACK_NAMES = ("Shopify", "Klaviyo", "Meta Pixel", "Facebook Pixel", "Google Analytics 4", "GA4")


# ======================================================================================
# Data classes
# ======================================================================================
@dataclass
class DomainEntry:
    host: str      # normalised host[:port] that gets scanned
    original: str  # value from the input CSV (whitespace-stripped), written to the output
    line: int


@dataclass
class DetectedApp:
    name: str
    categories: list = field(default_factory=list)
    version: str = ""


@dataclass
class Attempt:
    url: str
    command: list
    returncode: int | None  # None = killed by our timeout
    stdout: str
    stderr: str
    elapsed: float

    @property
    def timed_out(self) -> bool:
        return self.returncode is None


@dataclass
class ScanResult:
    entry: DomainEntry
    status: str = "ERROR"
    flags: dict = field(default_factory=lambda: dict.fromkeys(FLAG_COLUMNS, False))
    apps: list = field(default_factory=list)
    attempts: list = field(default_factory=list)
    records: list = field(default_factory=list)
    final_url: str = ""
    parse_mode: str = "json"
    note: str = ""

    def fail(self, status: str, note: str) -> "ScanResult":
        self.status, self.note = status, note
        self.flags = dict.fromkeys(FLAG_COLUMNS, False)  # brief: error/empty => all N
        return self


# ======================================================================================
# Small helpers
# ======================================================================================
def die(message: str, code: int = 1) -> None:
    sys.stderr.write(f"ERROR: {message}\n")
    sys.exit(code)


def yn(value: bool) -> str:
    return "Y" if value else "N"


def one_line(text: str) -> str:
    return " | ".join(part.strip() for part in (text or "").strip().splitlines() if part.strip())


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _to_text(data) -> str:
    if data is None:
        return ""
    if isinstance(data, bytes):
        return data.decode("utf-8", "replace")
    return data


def _console_arrow() -> str:
    try:
        "\u2192".encode(sys.stdout.encoding or "ascii")
        return "\u2192"
    except (UnicodeEncodeError, LookupError):
        return "->"


ARROW = _console_arrow()


# ======================================================================================
# Input
# ======================================================================================
_SCHEME_RE = re.compile(r"^(?:https?:)?//", re.IGNORECASE)
_LABEL_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")


def normalize_domain(raw: str):
    """Return (host[:port], "") for a usable domain, or (None, reason)."""
    value = (raw or "").strip()
    if not value:
        return None, "empty value"
    value = _SCHEME_RE.sub("", value)  # strip http:// or https://
    if "://" in value:
        return None, "unsupported URL scheme"
    host = re.split(r"[/?#]", value, maxsplit=1)[0]  # drop path/query: -crawl 0 scans the root page
    if "@" in host:
        return None, "contains '@' (an email address?)"
    if not host or any(ch.isspace() for ch in host):
        return None, "contains whitespace"
    host = host.lower().rstrip(".")
    port = ""
    if ":" in host:
        host, _, port = host.partition(":")
        if not (port.isdigit() and 0 < int(port) < 65536):
            return None, "invalid port"
    try:
        host = host.encode("idna").decode("ascii")  # IDN -> punycode
    except UnicodeError:
        return None, "invalid domain name"
    labels = host.split(".")
    if (len(host) > 253 or len(labels) < 2 or not all(_LABEL_RE.match(label) for label in labels)
            or not (labels[-1].isalpha() or labels[-1].startswith("xn--"))):
        return None, "not a valid domain name"
    return (f"{host}:{port}" if port else host), ""


def read_domains(path: str):
    """Read, validate and de-duplicate the 'domain' column. Exits 1 if nothing is scannable."""
    if not os.path.isfile(path):
        die(f"input file not found: {path}")
    entries, first_seen = [], {}
    rows = duplicates = malformed = 0
    # utf-8-sig: Excel exports start with a BOM, which would turn "domain" into "\ufeffdomain"
    with open(path, newline="", encoding="utf-8-sig") as fh:
        reader = csv.DictReader(fh)
        if not reader.fieldnames:
            die(f"{path} is empty: expected a header row with a 'domain' column.")
        column = next((f for f in reader.fieldnames if f and f.strip().lower() == "domain"), None)
        if column is None:
            die(f"{path} has no 'domain' column (columns found: {', '.join(map(str, reader.fieldnames))}).")
        while True:
            try:
                row = next(reader)
            except StopIteration:
                break
            except csv.Error as exc:
                malformed += 1
                LOG.warning("line %d: unreadable CSV row (%s), skipped", reader.line_num, exc)
                continue
            rows += 1
            line, raw = reader.line_num, row.get(column)
            if raw is None or not raw.strip():
                malformed += 1
                LOG.warning("line %d: empty 'domain' value, skipped", line)
                continue
            host, reason = normalize_domain(raw)
            if host is None:
                malformed += 1
                LOG.warning("line %d: malformed domain %r (%s), skipped", line, raw.strip(), reason)
                continue
            if host in first_seen:
                duplicates += 1
                LOG.warning("line %d: duplicate domain %r (same as line %d), skipped",
                            line, raw.strip(), first_seen[host])
                continue
            first_seen[host] = line
            entries.append(DomainEntry(host=host, original=raw.strip(), line=line))
    if rows == 0:
        die(f"{path} has a header but 0 data rows. Nothing to scan.")
    if not entries:
        die(f"{path}: none of its {rows} rows contain a valid domain. Nothing to scan.")
    LOG.info("%s: %d rows -> %d unique domains (%d duplicates, %d empty/malformed skipped)",
             path, rows, len(entries), duplicates, malformed)
    return entries


# ======================================================================================
# webanalyze setup
# ======================================================================================
def find_webanalyze(explicit: str | None) -> str:
    names = ["webanalyze.exe", "webanalyze"] if os.name == "nt" else ["webanalyze"]
    candidates = [explicit, shutil.which(explicit) or ""] if explicit else (
        [os.path.join(os.getcwd(), n) for n in names]
        + [os.path.join(SCRIPT_DIR, n) for n in names]
        + [shutil.which("webanalyze") or ""])
    for candidate in candidates:
        if candidate and os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return os.path.abspath(candidate)
    if explicit:
        die(f"--webanalyze {explicit!r} is not an executable file.\n\n{INSTALL_HELP}")
    die(INSTALL_HELP)
    return ""  # unreachable


def probe_flags(binary: str) -> set:
    """Run `webanalyze -h` and return the flag names this build supports."""
    try:
        proc = subprocess.run([binary, "-h"], capture_output=True, text=True,
                              encoding="utf-8", errors="replace", timeout=20)
    except (OSError, subprocess.TimeoutExpired) as exc:
        die(f"cannot execute {binary}: {exc}\n\n{INSTALL_HELP}")
    flags = set(re.findall(r"^\s+-([A-Za-z][\w-]*)", proc.stdout + proc.stderr, re.MULTILINE))
    missing = REQUIRED_FLAGS - flags
    if missing:
        die(f"{binary} does not look like webanalyze (missing flags: {', '.join(sorted(missing))}).")
    return flags


def update_fingerprints(binary: str, workdir: str) -> bool:
    """Run `webanalyze -update` once. It writes technologies.json into its working directory."""
    LOG.info("Running `webanalyze -update` (downloads the latest technologies.json) ...")
    try:
        proc = subprocess.run([binary, "-update"], cwd=workdir, capture_output=True, text=True,
                              encoding="utf-8", errors="replace", timeout=180)
    except subprocess.TimeoutExpired:
        LOG.warning("`webanalyze -update` timed out after 180s; using the existing %s", TECH_FILE)
        return False
    if proc.returncode != 0:
        LOG.warning("`webanalyze -update` failed (exit %d): %s; using the existing %s",
                    proc.returncode, one_line(proc.stderr)[:200], TECH_FILE)
        return False
    LOG.info("Fingerprints updated: %s", os.path.join(workdir, TECH_FILE))
    return True


def locate_technologies(workdir: str, binary: str) -> str:
    """Same lookup order as webanalyze itself: ./, the binary's folder, $HOME."""
    for folder in (workdir, os.path.dirname(binary), os.path.expanduser("~")):
        path = os.path.join(folder, TECH_FILE)
        if os.path.isfile(path):
            return path
    die(f"no {TECH_FILE} found in {workdir}, {os.path.dirname(binary)} or ~. "
        f"Run `webanalyze -update` (needs internet access) and try again.")
    return ""  # unreachable


def build_augmented_apps(base_path: str, out_path: str) -> str:
    """Write base technologies.json + EXTRA_FINGERPRINTS to out_path (atomic)."""
    try:
        with open(base_path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError) as exc:
        die(f"cannot read {base_path}: {exc}")
    techs = data.get("technologies") if isinstance(data, dict) else None
    if not isinstance(techs, dict):
        die(f"{base_path} has an unexpected format (no 'technologies' object).")
    for name, extra in EXTRA_FINGERPRINTS.items():
        entry = techs.setdefault(name, {})
        for key, value in extra.items():
            if isinstance(value, list):
                current = entry.get(key)
                current = [] if current is None else [current] if isinstance(current, str) else list(current)
                entry[key] = current + [v for v in value if v not in current]
            else:
                entry.setdefault(key, value)
    tmp_path = out_path + ".tmp"
    with open(tmp_path, "w", encoding="utf-8") as fh:
        json.dump(data, fh)
    os.replace(tmp_path, out_path)
    return out_path


# ======================================================================================
# Running webanalyze + parsing its output
# ======================================================================================
class Webanalyze:
    def __init__(self, binary: str, apps_file: str, follow_redirects: bool, user_agent: str | None):
        self.binary, self.apps_file = binary, apps_file
        self.follow_redirects, self.user_agent = follow_redirects, user_agent

    def command(self, url: str) -> list:
        cmd = [self.binary, "-host", url, "-output", "json", "-crawl", "0", "-silent",
               "-worker", "1", "-apps", self.apps_file]
        # Bool flags MUST use "=": "-search false" would end flag parsing (see docstring #3).
        cmd += ["-search=true", "-redirect"] if self.follow_redirects else ["-search=false"]
        if self.user_agent:
            cmd += ["-header", f"User-Agent: {self.user_agent}"]
        return cmd

    def run(self, url: str, timeout: float) -> Attempt:
        cmd = self.command(url)
        LOG.debug("exec: %s", " ".join(cmd))
        started = time.monotonic()
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8",
                                  errors="replace", timeout=timeout)
            return Attempt(url, cmd, proc.returncode, proc.stdout, proc.stderr,
                           time.monotonic() - started)
        except subprocess.TimeoutExpired as exc:  # run() already killed the child
            return Attempt(url, cmd, None, _to_text(exc.stdout), _to_text(exc.stderr),
                           time.monotonic() - started)


def parse_json_lines(stdout: str):
    """Split NDJSON output into (records, unparseable_lines)."""
    records, bad = [], []
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except ValueError:
            bad.append(line)
            continue
        if isinstance(obj, dict) and "matches" in obj:
            records.append(obj)
        elif isinstance(obj, list):  # tolerate a bare array of matches
            records.append({"hostname": "", "matches": obj})
        else:
            bad.append(line)
    return records, bad


def apps_from_records(records) -> list:
    """Collect detected technologies from every JSON line (original page + redirect target)."""
    apps = {}
    for record in records:
        for match in record.get("matches") or []:
            if not isinstance(match, dict):
                continue
            app = match.get("app") if isinstance(match.get("app"), dict) else {}
            name = str(match.get("app_name") or match.get("name") or app.get("name") or "").strip()
            if not name:
                continue
            cats = app.get("category_names") or match.get("categories") or match.get("category_names") or []
            cats = [c.get("name", "") if isinstance(c, dict) else str(c) for c in cats]
            found = apps.setdefault(name.lower(), DetectedApp(name=name))
            found.categories = sorted(set(found.categories) | {c for c in cats if c})
            found.version = found.version or str(match.get("version") or "")
    return list(apps.values())


def apps_from_raw_text(raw: str) -> list:
    """Regex fallback for output that is not valid JSON (truncated, text format, ...)."""
    names = []
    for escaped in _APP_NAME_RE.findall(raw):
        try:
            names.append(json.loads(f'"{escaped}"'))
        except ValueError:
            names.append(escaped)
    if names:
        return [DetectedApp(name=n) for n in dict.fromkeys(names)]
    rows = [DetectedApp(m.group("name").strip(), [c.strip() for c in m.group("cats").split(",") if c.strip()],
                        m.group("version").strip()) for m in _TEXT_ROW_RE.finditer(raw)]
    if rows:
        return rows
    # last resort, as the brief asks: plain substring search for the technology names
    return [DetectedApp(name=label) for label in _FALLBACK_NAMES if label.lower() in raw.lower()]


def classify(apps, ecommerce_as_shopify: bool = False) -> dict:
    """Map detected technologies to the four Y/N flags (case-insensitive)."""
    names = [a.name.lower() for a in apps]
    is_shopify = any("shopify" in n for n in names)
    if ecommerce_as_shopify:  # the brief's original rule; also flags WooCommerce, Magento, ...
        is_shopify = is_shopify or any(c.strip().lower() == "ecommerce" for a in apps for c in a.categories)
    return {
        "is_shopify": is_shopify,
        "has_klaviyo": any("klaviyo" in n for n in names),
        "has_meta_pixel": any("meta pixel" in n or "facebook pixel" in n for n in names),
        "has_ga4": any("google analytics 4" in n or "ga4" in n for n in names)
        or any(a.name.lower() == "google analytics" and "ga4" in a.version.lower() for a in apps),
    }


def fetch_errors(stderr: str) -> list:
    return [m.group("msg").strip() for m in _FETCH_ERROR_RE.finditer(stderr or "")]


def scan_domain(wa: Webanalyze, entry: DomainEntry, timeout: float, ecommerce_as_shopify: bool) -> ScanResult:
    """Scan one domain: https:// first, one http:// retry on connection errors, `timeout` seconds total."""
    result = ScanResult(entry=entry)
    deadline = time.monotonic() + timeout
    for scheme in ("https", "http"):
        url = f"{scheme}://{entry.host}"
        remaining = deadline - time.monotonic()
        if remaining < 1:
            return result.fail("TIMEOUT", f"{timeout:g}s budget used up before the {scheme}:// retry")
        attempt = wa.run(url, remaining)
        result.attempts.append(attempt)
        if attempt.timed_out:
            return result.fail("TIMEOUT", f"no result within {timeout:g}s")
        if attempt.returncode != 0:
            return result.fail("ERROR", f"webanalyze exited with code {attempt.returncode}")

        records, bad_lines = parse_json_lines(attempt.stdout)
        errors = fetch_errors(attempt.stderr)
        if records or bad_lines:
            if records:
                if bad_lines:
                    LOG.debug("%s: ignored %d non-JSON stdout line(s)", entry.host, len(bad_lines))
                result.apps, result.parse_mode = apps_from_records(records), "json"
            else:
                result.apps, result.parse_mode = apps_from_raw_text(attempt.stdout), "regex-fallback"
            result.records = records
            result.flags = classify(result.apps, ecommerce_as_shopify)
            result.status = "OK" if result.apps else "EMPTY"
            result.final_url = next((r.get("hostname") for r in records if r.get("hostname")
                                     and r["hostname"].rstrip("/") != url.rstrip("/")), "")
            if errors:  # e.g. the redirect target failed but the first response was analysed
                result.note = f"partial result: {errors[0]}"
            return result
        if not errors:
            return result.fail("ERROR", "webanalyze produced no output")
        message = errors[0]
        is_dns_error = any(h in message.lower() for h in _DNS_HINTS)
        if scheme == "https" and "failed to retrieve" in message.lower() and not is_dns_error:
            LOG.debug("%s: https failed (%s), retrying with http://", entry.host, message)
            continue
        status = "TIMEOUT" if any(h in message.lower() for h in _TIMEOUT_HINTS) else "ERROR"
        return result.fail(status, message)
    return result  # unreachable


# ======================================================================================
# Output: error log, progress, test-mode report
# ======================================================================================
class ErrorLog:
    """Append-only scan_errors.log, one tab-separated line per problem:
    time  level  domain  exit=<code>  status=<status>  tried=<urls>  <first 200 chars of stderr>"""

    def __init__(self, path: str, test_mode: bool):
        self.path, self.count = path, 0
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(f"# run started {utc_now()}{' (--test)' if test_mode else ''}\n")

    def write(self, level: str, result: ScanResult, detail: str) -> None:
        self.count += 1
        last = result.attempts[-1] if result.attempts else None
        exit_code = "n/a" if last is None else ("killed-by-timeout" if last.timed_out else last.returncode)
        tried = ",".join(a.url for a in result.attempts) or "-"
        line = "\t".join([utc_now(), level, result.entry.host, f"exit={exit_code}",
                          f"status={result.status}", f"tried={tried}", one_line(detail)[:200]])
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")

    def record(self, result: ScanResult) -> None:
        last = result.attempts[-1] if result.attempts else None
        if result.status in ("ERROR", "TIMEOUT"):
            stderr = last.stderr if last is not None else ""
            self.write("ERROR", result, stderr if stderr.strip() else f"(stderr empty) {result.note}")
        if result.parse_mode == "regex-fallback":
            self.write("WARN", result, "JSON parsing failed, used the regex fallback; stdout: "
                       + (last.stdout if last is not None else ""))
        if result.note.startswith("partial result"):
            self.write("WARN", result, result.note)


def progress_line(index: int, total: int, result: ScanResult) -> str:
    flags = ", ".join(f"{FLAG_LABELS[c]}: {yn(result.flags[c])}" for c in FLAG_COLUMNS)
    return f"[{index}/{total}] {result.entry.host} {ARROW} {flags} ({result.status})"


def json_preview(records, max_matches: int) -> str:
    """The real JSON structure (first line), one match per row, bulky app-definition fields trimmed."""
    record = records[0]
    matches = record.get("matches") or []
    rows = []
    for match in matches[:max_matches]:
        app = match.get("app") or {}
        evidence = [[str(s)[:60] for s in group[:2]] for group in (match.get("matches") or [])[:1]]
        rows.append(f'  {{"app_name": {json.dumps(match.get("app_name"))}, '
                    f'"version": {json.dumps(match.get("version"))}, '
                    f'"app": {{"cats": {json.dumps(app.get("cats"))}, '
                    f'"category_names": {json.dumps(app.get("category_names"))}, ...}}, '
                    f'"matches": {json.dumps(evidence)}}}')
    if len(matches) > max_matches:
        rows.append(f"  ... +{len(matches) - max_matches} more matches")
    head = f'{{"hostname": {json.dumps(record.get("hostname"))}, "matches": ['
    tail = "]}" + (f"   (+{len(records) - 1} more JSON line: redirect target/original)"
                   if len(records) > 1 else "")
    return "\n".join([head, ",\n".join(rows), tail]) if rows else head + tail


def print_test_report(index: int, total: int, result: ScanResult, verbose: bool) -> None:
    scanned_as = "" if result.entry.original == result.entry.host else f" (scanned as {result.entry.host})"
    print(f"\n=== [{index}/{total}] {result.entry.original}{scanned_as} ===")
    for attempt in result.attempts:
        rc = "killed (timeout)" if attempt.timed_out else f"exit {attempt.returncode}"
        lines = len([l for l in attempt.stdout.splitlines() if l.strip()])
        print(f"  command : {' '.join(attempt.command)}")
        print(f"  result  : {rc}, {attempt.elapsed:.1f}s, {lines} line(s) on stdout"
              + (f", stderr: {one_line(attempt.stderr)[:150]}" if attempt.stderr.strip() else ""))
    if result.final_url:
        print(f"  redirect: followed to {result.final_url}")
    if result.records:
        print("  raw JSON (first line, app definitions trimmed):")
        preview = json_preview(result.records, max_matches=100 if verbose else 3)
        print("\n".join("    " + line for line in preview.splitlines()))
    if result.apps:
        apps = ", ".join(sorted((a.name for a in result.apps), key=str.lower))
        print(f"  detected: {len(result.apps)} technologies ({result.parse_mode}): {apps}")
    elif result.status == "EMPTY":
        print("  detected: nothing (\"matches\": [])")
    if result.note:
        print(f"  note    : {result.note}")
    flags = "  ".join(f"{c}={yn(result.flags[c])}" for c in FLAG_COLUMNS)
    print(f"  PARSED  : {flags}  scan_status={result.status}")


def prepare_resume(path: str) -> set:
    """--resume: keep the OK/EMPTY rows of an earlier output CSV and return their hosts.
    ERROR/TIMEOUT rows are dropped from the file, so those domains get scanned again."""
    if not os.path.isfile(path) or os.path.getsize(path) == 0:
        return set()
    with open(path, newline="", encoding="utf-8-sig") as fh:
        reader = csv.DictReader(fh)
        if reader.fieldnames != OUTPUT_COLUMNS:
            die(f"--resume: {path} does not have the expected columns {OUTPUT_COLUMNS}.")
        keep = [row for row in reader if row.get("scan_status") in ("OK", "EMPTY")]
    tmp_path = path + ".tmp"
    with open(tmp_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=OUTPUT_COLUMNS)
        writer.writeheader()
        writer.writerows(keep)
    os.replace(tmp_path, path)
    return {host for host, _ in (normalize_domain(row["domain"]) for row in keep) if host}


# ======================================================================================
# CLI
# ======================================================================================
def parse_args(argv=None):
    p = argparse.ArgumentParser(
        description="Flag Shopify / Klaviyo / Meta Pixel / GA4 on a list of domains with webanalyze.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    p.add_argument("--input", default="domains_raw.csv", help="input CSV with a 'domain' column")
    p.add_argument("--output", default="domains_shopify.csv", help="output CSV")
    p.add_argument("--error-log", default="scan_errors.log", help="append-only error log")
    p.add_argument("--webanalyze", metavar="PATH", help="webanalyze binary (default: ./webanalyze, then PATH)")
    p.add_argument("--test", action="store_true",
                   help=f"scan only the first {TEST_DOMAIN_COUNT} domains, print parsed flags and raw "
                        "JSON structure, do NOT write the CSV")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="progress line for every domain (default: every 10) plus debug logging")
    p.add_argument("--delay", type=float, default=2.0, help="seconds to sleep between domains")
    p.add_argument("--timeout", type=float, default=30.0,
                   help="seconds per domain (shared by the https attempt and the http retry)")
    p.add_argument("--no-update", action="store_true", help="skip `webanalyze -update` (reuse technologies.json)")
    p.add_argument("--strict-host", action="store_true",
                   help="use -search=false: do NOT follow example.com -> www.example.com redirects")
    p.add_argument("--ecommerce-as-shopify", action="store_true",
                   help="also set is_shopify=Y when ANY 'Ecommerce'-category technology is found "
                        "(the brief's original rule; flags WooCommerce, Magento, BigCommerce ...)")
    p.add_argument("--no-augment", action="store_true",
                   help="use the stock technologies.json only (Klaviyo / Meta Pixel / GA4 will be ~always N)")
    p.add_argument("--user-agent", help="send this User-Agent via webanalyze -header (default: Go-http-client)")
    p.add_argument("--resume", action="store_true",
                   help="continue an interrupted run: keep OK/EMPTY rows already in --output, "
                        "re-scan everything else, append to the file")
    args = p.parse_args(argv)
    if args.delay < 0 or args.timeout <= 0:
        p.error("--delay must be >= 0 and --timeout > 0")
    return args


def main(argv=None) -> int:
    args = parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(levelname)s: %(message)s", stream=sys.stderr)

    entries = read_domains(args.input)
    binary = find_webanalyze(args.webanalyze)
    supported = probe_flags(binary)
    follow_redirects = not args.strict_host
    if follow_redirects and "redirect" not in supported:
        LOG.warning("this webanalyze build has no -redirect flag, so cross-host redirects will NOT be followed")
        follow_redirects = False
    if args.user_agent and "header" not in supported:
        die("--user-agent needs a webanalyze build that supports the -header flag.")

    workdir = os.getcwd()
    updated = False if args.no_update else update_fingerprints(binary, workdir)
    base_apps = locate_technologies(workdir, binary)
    age_days = (time.time() - os.path.getmtime(base_apps)) / 86400
    if age_days > 7:
        LOG.warning("%s is %.0f days old. Fingerprints may be outdated (run without --no-update).",
                    base_apps, age_days)
    apps_file = base_apps if args.no_augment else build_augmented_apps(
        base_apps, os.path.join(workdir, AUGMENTED_FILE))
    wa = Webanalyze(binary, apps_file, follow_redirects, args.user_agent)

    targets = entries[:TEST_DOMAIN_COUNT] if args.test else entries
    appending = False
    if args.resume and not args.test:
        done = prepare_resume(args.output)
        appending = os.path.isfile(args.output) and os.path.getsize(args.output) > 0
        targets = [e for e in targets if e.host not in done]
        LOG.info("--resume: %d domains already done (OK/EMPTY) in %s, %d to scan "
                 "(ERROR/TIMEOUT rows are retried)", len(done), args.output, len(targets))

    print(f"webanalyze   : {binary}")
    print(f"fingerprints : {base_apps}{' (updated now)' if updated else ''}"
          + ("" if args.no_augment else f" + supplemental -> {os.path.basename(apps_file)}"))
    print("redirects    : " + ("follow same-domain redirects (-search=true -redirect)" if follow_redirects
                               else "not followed (-search=false)"))
    print(f"domains      : {len(targets)} to scan" + (" (--test: first 3, no CSV written)" if args.test else
                                                     f" -> {args.output}"))
    if not targets:
        print("Nothing left to scan.")
        return 0

    errlog = ErrorLog(args.error_log, args.test)
    out_fh = writer = None
    if not args.test:
        out_fh = open(args.output, "a" if appending else "w", newline="", encoding="utf-8")
        writer = csv.writer(out_fh)
        if not appending:
            writer.writerow(OUTPUT_COLUMNS)

    counts = dict.fromkeys(STATUSES, 0)
    detected = dict.fromkeys(FLAG_COLUMNS, 0)
    crashes = scanned = 0
    started = time.monotonic()
    total = len(targets)
    try:
        for index, entry in enumerate(targets, start=1):
            result = scan_domain(wa, entry, args.timeout, args.ecommerce_as_shopify)
            scanned += 1
            counts[result.status] += 1
            for column in FLAG_COLUMNS:
                detected[column] += result.flags[column]
            errlog.record(result)
            if writer is not None:
                writer.writerow([entry.original] + [yn(result.flags[c]) for c in FLAG_COLUMNS] + [result.status])
                out_fh.flush()  # rows survive a crash or Ctrl-C (see --resume)

            if args.test:
                print_test_report(index, total, result, args.verbose)
            else:
                if result.status in ("ERROR", "TIMEOUT"):
                    LOG.warning("%s: %s (%s)", entry.host, result.status, result.note[:160])
                if args.verbose or index % 10 == 0 or index == total:
                    print(progress_line(index, total, result), flush=True)

            last = result.attempts[-1] if result.attempts else None
            crashes = crashes + 1 if (last is not None and last.returncode not in (0, None)) else 0
            if crashes >= MAX_CONSECUTIVE_CRASHES:
                LOG.error("webanalyze exited non-zero %d times in a row; aborting. Last stderr: %s",
                          crashes, one_line(last.stderr)[:200])
                return 1
            if index < total and args.delay > 0:
                time.sleep(args.delay)  # politeness between domains
    except KeyboardInterrupt:
        print(f"\nInterrupted after {scanned}/{total} domains."
              + ("" if args.test else f" Rows so far are in {args.output}; re-run with --resume to continue."))
        return 130
    finally:
        if out_fh is not None:
            out_fh.close()

    minutes, seconds = divmod(int(time.monotonic() - started), 60)
    print(f"\nDone: {scanned} domains in {minutes}m{seconds:02d}s"
          + (" (--test, no CSV written)" if args.test else f" -> {args.output}"))
    print("  status  : " + "  ".join(f"{s}={counts[s]}" for s in STATUSES))
    print("  detected: " + "  ".join(f"{FLAG_LABELS[c]}={detected[c]}" for c in FLAG_COLUMNS))
    if errlog.count:
        print(f"  {errlog.count} problem(s) logged to {args.error_log}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
