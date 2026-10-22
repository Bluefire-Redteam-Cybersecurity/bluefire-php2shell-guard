#!/usr/bin/env python3
"""Bluefire Redteam — PHP2Shell Guard.

Defensive exposure check, interim remediation, and request firewall for
CVE-2026-109618 and CVE-2026-109619.

Checker and defensive edge policy. The only complete fix is a patched PHP
build plus a worker restart. This tool does not send attack traffic and
does not test exploitability. See README for the disclaimer and LICENSE
for the MIT terms.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import threading
from collections import Counter
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Iterable
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parent

CVE_OOM = "CVE-2026-109618"
CVE_STALE = "CVE-2026-109619"
CVES = (CVE_OOM, CVE_STALE)
ADVISORY = "https://www.php.net/archive/2026.php#2026-10-21-5"
SITE = "https://bluefire-redteam.com"
CONTACT = "contact@bluefire-redteam.com"
CTA = f"Need this checked across your hosts? {SITE}"

# Minimum patched release on each branch the PHP project still ships.
PATCHED_MIN = {
    (8, 5): (8, 5, 12),
    (8, 4): (8, 4, 27),
    (8, 3): (8, 3, 36),
    (8, 2): (8, 2, 35),
}
# Branches that received a source-only backport, not a release.
BACKPORT_BRANCHES = {(7, 4), (8, 0), (8, 1)}
FIX_MARKERS = (
    "GHSA-w8hw-w9fx-j79w",
    "GHSA-6wmf-4rv5-p3rp",
    CVE_OOM,
    CVE_STALE,
)

# Edge limits. These match the PHP advisory's interim guidance:
# cap decoded body size, multipart complexity, and the upload-progress feature.
DEFAULT_MAX_BODY = 8 * 1024 * 1024
DEFAULT_MAX_PARTS = 32
DEFAULT_MAX_PART_HEADERS = 16
DEFAULT_MAX_NESTING = 8
DEFAULT_MAX_FIELDS = 1000


@dataclass
class Policy:
    max_body: int = DEFAULT_MAX_BODY
    max_parts: int = DEFAULT_MAX_PARTS
    max_part_headers: int = DEFAULT_MAX_PART_HEADERS
    max_nesting: int = DEFAULT_MAX_NESTING
    max_fields: int = DEFAULT_MAX_FIELDS
    post_max_label: str = "8M"


@dataclass
class Check:
    name: str
    status: str  # pass, fail, info
    observed: str
    expected: str
    detail: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class VersionVerdict:
    raw: str
    status: str  # patched, vulnerable, unsupported, review, unknown
    fixed_in: str | None
    detail: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class LogSignal:
    confidence: str
    title: str
    detail: str
    samples: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class RequestVerdict:
    action: str  # allow, block
    reasons: list[str]
    detail: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


def version_tuple(raw: str) -> tuple[int, ...] | None:
    match = re.search(r"(\d+)\.(\d+)\.(\d+)", raw or "")
    if not match:
        return None
    return tuple(int(part) for part in match.groups())


def dotted(version: tuple[int, ...]) -> str:
    return ".".join(str(part) for part in version)


def classify_version(raw: str, vendor_fix_noted: bool = False) -> VersionVerdict:
    parsed = version_tuple(raw)
    if parsed is None:
        return VersionVerdict(raw or "", "unknown", None, "No PHP version could be read.")

    branch = parsed[:2]
    if vendor_fix_noted:
        return VersionVerdict(
            dotted(parsed),
            "patched",
            None,
            "A changelog or package note names the PHP2Shell fixes. "
            "Confirm the running workers were restarted on that build.",
        )

    if branch in PATCHED_MIN:
        fixed = PATCHED_MIN[branch]
        if parsed >= fixed:
            return VersionVerdict(
                dotted(parsed),
                "patched",
                dotted(fixed),
                f"This {branch[0]}.{branch[1]} release is at or above {dotted(fixed)}.",
            )
        return VersionVerdict(
            dotted(parsed),
            "vulnerable",
            dotted(fixed),
            f"Upgrade this branch to {dotted(fixed)} or newer, then restart every PHP worker.",
        )

    if branch in BACKPORT_BRANCHES:
        return VersionVerdict(
            dotted(parsed),
            "unsupported",
            None,
            "The PHP project does not ship a release for this branch. "
            "A minimal source backport exists for 7.4, 8.0, and 8.1. "
            "Treat the host as exposed unless the vendor changelog names both CVEs "
            "and the workers have been restarted.",
        )

    if parsed < (8, 2, 0):
        return VersionVerdict(
            dotted(parsed),
            "unsupported",
            None,
            "This branch is outside the versions the PHP project patched. Plan an upgrade.",
        )

    return VersionVerdict(
        dotted(parsed),
        "review",
        None,
        "This version is newer than the branches listed in the October 2026 advisory. "
        "Confirm the release notes include both GitHub advisories.",
    )


def parse_ini(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(";") or stripped.startswith("#"):
            continue
        if "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        values[key.strip().lower()] = value.strip().split(";")[0].strip().strip("\"'")
    return values


def parse_phpinfo(text: str) -> dict[str, str]:
    """Accept `php -i` lines: name => local => master."""
    values: dict[str, str] = {}
    for line in text.splitlines():
        if "=>" not in line:
            continue
        parts = [part.strip() for part in line.split("=>")]
        if len(parts) >= 2 and re.fullmatch(r"[A-Za-z0-9_.]+", parts[0]):
            values[parts[0].lower()] = parts[1]
    return values


def load_config(path: Path) -> dict[str, str]:
    text = path.read_text(encoding="utf-8", errors="replace")
    if "=>" in text and "=" not in text.splitlines()[0]:
        parsed = parse_phpinfo(text)
        if parsed:
            return parsed
    ini = parse_ini(text)
    info = parse_phpinfo(text)
    ini.update(info)
    return ini


def parse_size(raw: str | None) -> int | None:
    if raw is None:
        return None
    text = raw.strip().lower()
    if text in {"", "-1", "unlimited"}:
        return -1
    match = re.fullmatch(r"(\d+)\s*([kmg])?b?", text)
    if not match:
        return None
    value = int(match.group(1))
    unit = match.group(2)
    if unit == "k":
        return value * 1024
    if unit == "m":
        return value * 1024 * 1024
    if unit == "g":
        return value * 1024 * 1024 * 1024
    return value


def truthy(raw: str | None) -> bool | None:
    if raw is None:
        return None
    value = raw.strip().lower()
    if value in {"1", "on", "true", "yes"}:
        return True
    if value in {"0", "off", "false", "no"}:
        return False
    return None


def audit_config(config: dict[str, str], version: VersionVerdict | None) -> list[Check]:
    checks: list[Check] = []

    memory = config.get("memory_limit")
    memory_bytes = parse_size(memory)
    if memory_bytes == -1:
        checks.append(Check(
            "memory_limit",
            "pass",
            memory or "-1",
            "-1, enforced with php_admin_value",
            "Removes the controllable per-request limit called out for CVE-2026-109618. "
            "This is not a complete fix. Do not use RLIMIT_AS or RLIMIT_DATA. "
            "A cgroup memory.max around each worker is the safer availability cap.",
        ))
    else:
        checks.append(Check(
            "memory_limit",
            "fail",
            memory or "(not set; PHP default is 128M)",
            "-1 enforced outside the application",
            "A finite memory_limit is the predictable path described in the advisory. "
            "Set it to -1 with php_admin_value or php_admin_flag so a script cannot turn it back on.",
        ))

    progress = truthy(config.get("session.upload_progress.enabled"))
    if progress is False:
        checks.append(Check(
            "session.upload_progress.enabled",
            "pass",
            "Off",
            "Off, set before request parsing",
            "Closes the confirmed session path for CVE-2026-109619. "
            "ini_set() and .user.ini are too late. Restart workers after the change.",
        ))
    else:
        observed = config.get("session.upload_progress.enabled", "(not set; PHP default is On)")
        checks.append(Check(
            "session.upload_progress.enabled",
            "fail",
            observed,
            "Off",
            "The upload-progress feature is a confirmed path for CVE-2026-109619. Turn it off and restart workers.",
        ))

    post = parse_size(config.get("post_max_size"))
    upload = parse_size(config.get("upload_max_filesize"))
    if post is None:
        checks.append(Check(
            "post_max_size",
            "fail",
            config.get("post_max_size", "(not set; PHP default is 8M)"),
            "8M, or 32M when uploads are required",
            "Keep the decoded body small and enforce the same cap at the web server.",
        ))
    elif post == -1 or post > 32 * 1024 * 1024:
        checks.append(Check(
            "post_max_size",
            "fail",
            config.get("post_max_size", ""),
            "8M, or at most 32M",
            "The advisory's interim cap is 8M without uploads and 32M with uploads.",
        ))
    elif post > 8 * 1024 * 1024:
        checks.append(Check(
            "post_max_size",
            "info",
            config.get("post_max_size", ""),
            "8M unless this vhost must accept larger uploads",
            "Within the advisory's 32M ceiling. Confirm this site really needs uploads that large.",
        ))
    else:
        checks.append(Check(
            "post_max_size",
            "pass",
            config.get("post_max_size", ""),
            "8M or smaller",
            "Matches the tighter interim cap.",
        ))

    if upload is not None and post is not None and upload != -1 and post != -1 and upload > post:
        checks.append(Check(
            "upload_max_filesize",
            "fail",
            config.get("upload_max_filesize", ""),
            "lower than post_max_size",
            "upload_max_filesize must stay below post_max_size.",
        ))
    elif upload == -1 or (upload is not None and upload > 32 * 1024 * 1024):
        checks.append(Check(
            "upload_max_filesize",
            "fail",
            config.get("upload_max_filesize", ""),
            "at or below post_max_size",
            "Cap upload size at the same edge limit as the request body.",
        ))
    else:
        checks.append(Check(
            "upload_max_filesize",
            "pass" if upload is not None else "info",
            config.get("upload_max_filesize", "(not set)"),
            "lower than post_max_size",
            "Keep uploads inside the body cap.",
        ))

    nesting = config.get("max_input_nesting_level")
    try:
        nesting_n = int(nesting) if nesting is not None else None
    except ValueError:
        nesting_n = None
    if nesting_n is None or nesting_n > 16:
        checks.append(Check(
            "max_input_nesting_level",
            "fail",
            nesting or "(not set; PHP default is 64)",
            "8",
            "Deep input names multiply work during request parsing. Cap them.",
        ))
    else:
        checks.append(Check(
            "max_input_nesting_level",
            "pass",
            nesting or "",
            "8 or lower",
            "Nesting cap is in place.",
        ))

    on_85 = version is not None and version.raw.startswith("8.5.")
    backtrace = truthy(config.get("fatal_error_backtraces"))
    if on_85 and backtrace is not False:
        checks.append(Check(
            "fatal_error_backtraces",
            "fail",
            config.get("fatal_error_backtraces", "(not set)"),
            "Off on PHP 8.5",
            "The advisory names fatal_error_backtraces as a confirmed path for CVE-2026-109619 on PHP 8.5.",
        ))
    elif on_85:
        checks.append(Check(
            "fatal_error_backtraces",
            "pass",
            "Off",
            "Off",
            "Fatal-backtrace path is disabled.",
        ))

    return checks


def overall_status(version: VersionVerdict | None, checks: list[Check]) -> str:
    failed = any(item.status == "fail" for item in checks)
    if version is None:
        return "INCOMPLETE" if not checks else "EXPOSED"
    if version.status == "patched":
        return "PATCHED_WITH_GAPS" if failed else "PATCHED"
    if version.status == "review" and not failed:
        return "REVIEW"
    return "EXPOSED"


def changelog_names_fix(path: Path | None) -> bool:
    if path is None or not path.is_file():
        return False
    text = path.read_text(encoding="utf-8", errors="replace")
    return all(marker in text for marker in (CVE_OOM, CVE_STALE)) or all(
        marker in text for marker in FIX_MARKERS[:2]
    )


def read_php_version(php_bin: str) -> str | None:
    import subprocess

    try:
        result = subprocess.run(
            [php_bin, "-v"],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    match = re.search(r"PHP\s+(\d+\.\d+\.\d+)", result.stdout)
    return match.group(1) if match else None


def fetch_powered_by(url: str, timeout: float = 5.0) -> str | None:
    request = Request(url, method="GET", headers={"User-Agent": "Bluefire-PHP2Shell-Guard"})
    try:
        with urlopen(request, timeout=timeout) as response:
            header = response.headers.get("X-Powered-By")
    except (HTTPError, URLError, TimeoutError, ValueError):
        return None
    if not header:
        return None
    match = re.search(r"(\d+\.\d+\.\d+)", header)
    return match.group(1) if match else None


LOG_RE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[[^\]]+\] "(?P<method>[A-Z]+) (?P<uri>[^" ]*)(?: [^"]*)?" '
    r"(?P<status>\d{3}) (?P<size>\S+)"
)


def scan_log(path: Path, burst: int = 5) -> list[LogSignal]:
    progress_hits: list[str] = []
    long_hits: list[str] = []
    deep_hits: list[str] = []
    errors: Counter[str] = Counter()
    skipped = 0
    parsed = 0

    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        match = LOG_RE.match(line)
        if not match:
            if line.strip():
                skipped += 1
            continue
        parsed += 1
        ip = match.group("ip")
        method = match.group("method")
        uri = match.group("uri")
        status = int(match.group("status"))
        sample = f"{ip} {method} {uri[:180]} {status}"
        if re.search(r"PHP_SESSION_UPLOAD_PROGRESS", uri, re.I):
            progress_hits.append(sample)
        if len(uri) > 4096:
            long_hits.append(sample)
        if uri.count("[") >= DEFAULT_MAX_NESTING:
            deep_hits.append(sample)
        if method in {"POST", "PUT", "PATCH"} and status >= 500:
            errors[ip] += 1

    signals: list[LogSignal] = []
    if progress_hits:
        signals.append(LogSignal(
            "medium",
            "Session upload-progress parameter",
            "A request used PHP_SESSION_UPLOAD_PROGRESS. That feature is a confirmed path "
            "for CVE-2026-109619. This is a lead, not proof of compromise.",
            progress_hits[:5],
        ))
    if deep_hits:
        signals.append(LogSignal(
            "low",
            "Deep field names in the request line",
            "Request URIs contain deeply nested field names. Compare them with normal application traffic.",
            deep_hits[:5],
        ))
    if long_hits:
        signals.append(LogSignal(
            "low",
            "Unusually long request URI",
            "URIs over 4096 bytes are worth review alongside the edge body limits.",
            long_hits[:5],
        ))
    burst_ips = [ip for ip, count in errors.items() if count >= burst]
    if burst_ips:
        signals.append(LogSignal(
            "low",
            "Repeated server errors on write requests",
            f"{len(burst_ips)} address(es) produced at least {burst} HTTP 5xx responses "
            "to POST, PUT, or PATCH. Worker crashes can look like this. Correlate with PHP error logs.",
            burst_ips[:8],
        ))
    if parsed == 0:
        signals.append(LogSignal(
            "low",
            "No combined-format lines parsed",
            f"Skipped {skipped} non-empty line(s). Pass Apache or nginx combined access logs.",
        ))
    return signals


def _boundary(content_type: str) -> str | None:
    match = re.search(r'boundary\s*=\s*"?([^";]+)"?', content_type, re.I)
    if not match:
        return None
    return match.group(1).strip()


def _parts(body: bytes, boundary: str) -> list[bytes]:
    marker = b"--" + boundary.encode("latin1", "ignore")
    pieces = body.split(marker)
    parts: list[bytes] = []
    for piece in pieces[1:]:
        if piece.startswith(b"--"):
            break
        if piece.startswith(b"\r\n"):
            piece = piece[2:]
        elif piece.startswith(b"\n"):
            piece = piece[1:]
        if piece.endswith(b"\r\n"):
            piece = piece[:-2]
        elif piece.endswith(b"\n"):
            piece = piece[:-1]
        parts.append(piece)
    return parts


def _header_blob(part: bytes) -> str:
    if b"\r\n\r\n" in part:
        blob = part.split(b"\r\n\r\n", 1)[0]
    elif b"\n\n" in part:
        blob = part.split(b"\n\n", 1)[0]
    else:
        blob = part
    return blob.decode("latin1", "replace")


def inspect_request(
    method: str,
    target: str,
    headers: Iterable[tuple[str, str]] | dict[str, str],
    body: bytes,
    policy: Policy | None = None,
) -> RequestVerdict:
    policy = policy or Policy()
    if isinstance(headers, dict):
        pairs = list(headers.items())
    else:
        pairs = list(headers)
    lowered = {key.lower(): value for key, value in pairs}
    content_type = lowered.get("content-type", "")
    reasons: list[str] = []

    if re.search(r"PHP_SESSION_UPLOAD_PROGRESS", target or "", re.I):
        reasons.append("upload_progress_in_query")

    if "multipart/form-data" not in content_type.lower():
        if len(body) > policy.max_body:
            reasons.append("body_exceeds_policy")
        action = "block" if reasons else "allow"
        return RequestVerdict(action, reasons, "Non-multipart request.")

    if "content-length" not in lowered or lowered.get("content-length", "").strip() == "":
        reasons.append("multipart_without_content_length")
    else:
        try:
            announced = int(lowered["content-length"])
        except ValueError:
            announced = -1
        if announced < 0 or announced > policy.max_body or len(body) > policy.max_body:
            reasons.append("body_exceeds_policy")

    if "chunked" in lowered.get("transfer-encoding", "").lower():
        reasons.append("chunked_multipart")

    boundary = _boundary(content_type)
    if boundary is None:
        reasons.append("multipart_without_boundary")
        return RequestVerdict("block", reasons, "Multipart request rejected by edge policy.")

    parts = _parts(body, boundary)
    if body and not parts:
        reasons.append("malformed_multipart")
    if len(parts) > policy.max_parts:
        reasons.append("too_many_parts")

    deepest = 0
    for part in parts:
        blob = _header_blob(part)
        header_lines = [
            line for line in blob.splitlines()
            if line.strip() and not line[:1].isspace()
        ]
        if len(header_lines) > policy.max_part_headers:
            reasons.append("too_many_part_headers")
        name_match = re.search(r'name="([^"]*)"', blob, re.I)
        if name_match:
            deepest = max(deepest, name_match.group(1).count("["))
            if name_match.group(1).lower() == "php_session_upload_progress":
                reasons.append("upload_progress_field")
    if deepest >= policy.max_nesting:
        reasons.append("field_nesting_too_deep")
    if len(parts) > policy.max_fields:
        reasons.append("too_many_fields")

    # Preserve order while dropping duplicates.
    deduped: list[str] = []
    for reason in reasons:
        if reason not in deduped:
            deduped.append(reason)
    action = "block" if deduped else "allow"
    detail = "Multipart request rejected by edge policy." if action == "block" else "Within edge policy."
    return RequestVerdict(action, deduped, detail)


REASON_TEXT = {
    "upload_progress_in_query": "query uses PHP_SESSION_UPLOAD_PROGRESS",
    "upload_progress_field": "form field enables session upload progress",
    "multipart_without_content_length": "multipart request has no Content-Length",
    "body_exceeds_policy": "body is larger than the edge cap",
    "chunked_multipart": "chunked multipart request",
    "multipart_without_boundary": "multipart request has no boundary",
    "malformed_multipart": "multipart body could not be split",
    "too_many_parts": "too many multipart parts",
    "too_many_part_headers": "too many headers in a multipart part",
    "field_nesting_too_deep": "field names are nested too deeply",
    "too_many_fields": "too many fields",
}


def nginx_config(policy: Policy) -> str:
    megabytes = max(1, policy.max_body // (1024 * 1024))
    return f"""# Bluefire Redteam — PHP2Shell edge policy
# {CVE_OOM}  {CVE_STALE}
# Interim control. Upgrade PHP and restart every worker. This is not a complete fix.
# Maps belong in http {{ }}. The limit and the 403 belong in the server that reaches PHP.
# Test on a staging vhost before production. Tune the body size to what the site must accept.
# {CTA}

limit_req_zone $binary_remote_addr zone=bluefire_php2shell:10m rate=20r/s;

map $http_content_type $bf_php2shell_multipart {{
    default 0;
    "~*^multipart/form-data" 1;
}}

map $http_transfer_encoding $bf_php2shell_chunked {{
    default 0;
    "~*chunked" 1;
}}

map $content_length $bf_php2shell_no_length {{
    default 0;
    "" 1;
}}

map "$bf_php2shell_multipart:$bf_php2shell_chunked:$bf_php2shell_no_length" $bf_php2shell_block {{
    default 0;
    "~^1:1:" 1;
    "~^1:0:1" 1;
}}

client_max_body_size {megabytes}m;
client_header_buffer_size 8k;
large_client_header_buffers 4 8k;
client_header_timeout 10s;
client_body_timeout 15s;

# server context:
# limit_req zone=bluefire_php2shell burst=40 nodelay;
# if ($bf_php2shell_block) {{
#     return 403;
# }}
"""


def modsecurity_config(policy: Policy) -> str:
    return f"""# Bluefire Redteam — PHP2Shell ModSecurity policy
# {CVE_OOM}  {CVE_STALE}
# Interim control. Upgrade PHP and restart every worker.
# Soak with SecRuleEngine DetectionOnly on a copy of production traffic, then enforce.
# Local rule ids are in the 9001096xx range. Move them if they collide.
# {CTA}

SecRuleEngine DetectionOnly
SecRequestBodyAccess On
SecRequestBodyLimit {policy.max_body}
SecRequestBodyNoFilesLimit 1048576
SecRequestBodyLimitAction Reject

SecRule REQUEST_HEADERS:Content-Type "@rx (?i)^multipart/form-data" \\
    "id:900109618,phase:1,chain,deny,status:403,log,msg:'Bluefire PHP2Shell: multipart request has no Content-Length',tag:'{CVE_OOM}',tag:'bluefire'"
    SecRule &REQUEST_HEADERS:Content-Length "@eq 0"

SecRule REQUEST_HEADERS:Content-Type "@rx (?i)^multipart/form-data" \\
    "id:900109619,phase:1,chain,deny,status:403,log,msg:'Bluefire PHP2Shell: chunked multipart request',tag:'{CVE_OOM}',tag:'bluefire'"
    SecRule REQUEST_HEADERS:Transfer-Encoding "@rx (?i)chunked"

SecRule ARGS_NAMES|FILES_NAMES "@rx (?:\\[[^\\]]*\\]){{{policy.max_nesting},}}" \\
    "id:900109621,phase:2,deny,status:403,log,msg:'Bluefire PHP2Shell: input nesting is too deep',tag:'{CVE_OOM}',tag:'bluefire'"

SecRule ARGS_NAMES|REQUEST_URI "@rx (?i)PHP_SESSION_UPLOAD_PROGRESS" \\
    "id:900109622,phase:2,deny,status:403,log,msg:'Bluefire PHP2Shell: session upload progress',tag:'{CVE_STALE}',tag:'bluefire'"

SecRule MULTIPART_STRICT_ERROR "@eq 1" \\
    "id:900109623,phase:2,deny,status:403,log,msg:'Bluefire PHP2Shell: malformed multipart body',tag:'{CVE_OOM}',tag:'bluefire'"
"""


def interim_ini(policy: Policy) -> str:
    megabytes = max(1, policy.max_body // (1024 * 1024))
    return f"""; Bluefire Redteam — interim PHP2Shell hardening
; {CVE_OOM}  {CVE_STALE}
; Not a complete fix. Install PHP 8.5.12, 8.4.27, 8.3.36, or 8.2.35 and restart workers.
; Enforce these with php_admin_value / php_admin_flag so the application cannot override them.
; ini_set() and .user.ini run too late for the parsing paths in the advisory.
; {CTA}

memory_limit = -1
post_max_size = {megabytes}M
upload_max_filesize = 2M
max_file_uploads = 5
max_input_vars = {policy.max_fields}
max_input_nesting_level = {policy.max_nesting}
session.upload_progress.enabled = 0
; PHP 8.5 only. Leave this commented out on older branches, where the directive does not exist.
; fatal_error_backtraces = 0

; php-fpm pool (preferred over php.ini, because it cannot be overridden):
; php_admin_value[memory_limit] = -1
; php_admin_value[post_max_size] = {megabytes}M
; php_admin_value[upload_max_filesize] = 2M
; php_admin_value[max_input_nesting_level] = {policy.max_nesting}
; php_admin_flag[session.upload_progress.enabled] = off
; php_admin_flag[fatal_error_backtraces] = off

; Apache mod_php:
; php_admin_value memory_limit -1
; php_admin_value post_max_size {megabytes}M
; php_admin_flag session.upload_progress.enabled Off
"""


def fail2ban_filter() -> str:
    return f"""# Bluefire Redteam — PHP2Shell fail2ban filter
# Low-confidence signal. Review hits before a long ban.
# Matches the upload-progress parameter and a burst is handled by the nginx limit_req zone.
# {CTA}

[Definition]
failregex = ^<HOST> -\\S* \\S+ \\[[^\\]]+\\] "(?:POST|PUT|PATCH) [^"]*PHP_SESSION_UPLOAD_PROGRESS[^"]*" (?:500|502|503|403)\\b
ignoreregex =
"""


def write_rules(directory: Path, policy: Policy) -> list[Path]:
    directory.mkdir(parents=True, exist_ok=True)
    files = {
        "nginx-php2shell.conf": nginx_config(policy),
        "modsecurity-php2shell.conf": modsecurity_config(policy),
        "php2shell-interim.ini": interim_ini(policy),
        "fail2ban-php2shell.conf": fail2ban_filter(),
    }
    written: list[Path] = []
    for name, content in files.items():
        path = directory / name
        path.write_text(content, encoding="utf-8")
        written.append(path)
    return written


def remediation_lines(version: VersionVerdict | None) -> list[str]:
    lines = [
        "1. Upgrade the PHP runtime. Distro packages are the right path when they name both CVEs.",
        "   Upstream releases: 8.5.12, 8.4.27, 8.3.36, 8.2.35.",
        "   PHP 8.2 is end of life on 31 December 2026. Move to 8.3 or newer after this patch.",
        "   PHP 8.1 and older: use a vendor backport, or the PHP project's source backports for 7.4, 8.0, and 8.1.",
        "2. Restart every worker. A package install does nothing until php-fpm, Apache, or LiteSpeed reloads.",
        "   sudo systemctl restart php8.3-fpm    # use the service you actually run",
        "   sudo systemctl restart apache2",
        "3. Prove the running build, not the package on disk:",
        "   php -v",
        "   and the same version inside a web request (a temporary phpinfo, then remove it).",
        "4. Until that restart is done, enforce the interim ini and the nginx or ModSecurity policy.",
        "   memory_limit=-1 must be an admin value. Do not set RLIMIT_AS or RLIMIT_DATA.",
        "   Prefer a cgroup memory.max that kills only the worker that exceeded it.",
        "5. After the upgrade, keep the edge body limits. They are ordinary hardening.",
        f"6. Advisory: {ADVISORY}",
    ]
    if version and version.fixed_in and version.status != "patched":
        lines.insert(1, f"   This host should move from {version.raw} to {version.fixed_in} or newer.")
    return lines


def render_text(
    version: VersionVerdict | None,
    checks: list[Check],
    signals: list[LogSignal],
    sapi: str | None,
    color: bool,
) -> str:
    class Paint:
        def __init__(self, enabled: bool) -> None:
            self.enabled = enabled

        def _w(self, code: str, text: str) -> str:
            if not self.enabled:
                return text
            return f"\033[{code}m{text}\033[0m"

        def title(self, text: str) -> str:
            return self._w("1;34", text)

        def good(self, text: str) -> str:
            return self._w("32", text)

        def bad(self, text: str) -> str:
            return self._w("1;31", text)

        def warn(self, text: str) -> str:
            return self._w("33", text)

        def dim(self, text: str) -> str:
            return self._w("2", text)

    paint = Paint(color and sys.stdout.isatty())
    status = overall_status(version, checks)
    tone = {
        "PATCHED": paint.good,
        "PATCHED_WITH_GAPS": paint.warn,
        "REVIEW": paint.warn,
        "INCOMPLETE": paint.warn,
    }.get(status, paint.bad)

    rows = [
        paint.title("Bluefire Redteam  ·  PHP2Shell Guard"),
        paint.dim(f"{CVE_OOM}   {CVE_STALE}   CVSS v4.0 9.2"),
        "",
        f"Decision   {tone(status)}",
    ]
    if sapi:
        risk = "highest" if sapi == "mod_php" else "in scope"
        rows.append(f"SAPI       {sapi} ({risk})")
    if version:
        label = version.status.upper()
        rows.append(f"PHP        {version.raw}   {label}")
        if version.fixed_in:
            rows.append(f"Fixed in   {version.fixed_in}")
        rows.append(paint.dim(version.detail))
    if checks:
        rows.append("")
        rows.append(paint.title("Configuration"))
        for item in checks:
            mark = {"pass": paint.good("PASS"), "fail": paint.bad("FAIL"), "info": paint.warn("NOTE")}[item.status]
            rows.append(f"  {mark}  {item.name} = {item.observed}")
            rows.append(paint.dim(f"        expected: {item.expected}"))
    if signals:
        rows.append("")
        rows.append(paint.title("Log signals"))
        for signal in signals:
            rows.append(f"  [{signal.confidence}] {signal.title}")
            rows.append(paint.dim(f"        {signal.detail}"))
            for sample in signal.samples:
                rows.append(paint.dim(f"        - {sample}"))
    rows.append("")
    rows.append(paint.title("Remediation"))
    rows.extend(remediation_lines(version))
    rows.append("")
    rows.append(paint.dim(
        "Interim controls reduce exposure. They do not close every path. "
        "A hidden X-Powered-By header is not evidence of a patch."
    ))
    rows.append("")
    rows.append(paint.title("Bluefire Redteam"))
    rows.append("Offensive security from Ahmedabad, Singapore, and New York.")
    rows.append(CTA)
    return "\n".join(rows)


def render_markdown(
    version: VersionVerdict | None,
    checks: list[Check],
    signals: list[LogSignal],
    sapi: str | None,
) -> str:
    status = overall_status(version, checks)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        "# Bluefire Redteam — PHP2Shell exposure report",
        "",
        f"Prepared {now}.",
        "",
        f"**Decision: {status}**",
        "",
        "This is an exposure and hardening review for CVE-2026-109618 and CVE-2026-109619. "
        "It does not test exploitability and it is not evidence that an attacker succeeded.",
        "",
        "## Version",
        "",
    ]
    if version:
        lines.append(f"- Observed: `{version.raw}`")
        lines.append(f"- Status: `{version.status}`")
        if version.fixed_in:
            lines.append(f"- Fixed in: `{version.fixed_in}`")
        lines.append(f"- Note: {version.detail}")
    else:
        lines.append("- No PHP version was supplied.")
    if sapi:
        lines.append(f"- SAPI: `{sapi}`")
        if sapi == "mod_php":
            lines.append("- mod_php is the highest-risk setup in the PHP advisory.")
    lines.extend(["", "## Configuration", "", "| Check | Status | Observed | Expected |", "|---|---|---|---|"])
    for item in checks:
        observed = item.observed.replace("|", "\\|")
        expected = item.expected.replace("|", "\\|")
        lines.append(f"| `{item.name}` | {item.status} | {observed} | {expected} |")
    if not checks:
        lines.append("| — | — | No ini or phpinfo supplied | — |")
    lines.extend(["", "## Log signals", ""])
    if not signals:
        lines.append("No access log was supplied. Access logs miss most of these requests. The edge policy is the control that can see them.")
    for signal in signals:
        lines.append(f"- **{signal.title}** ({signal.confidence}). {signal.detail}")
        for sample in signal.samples:
            lines.append(f"  - `{sample}`")
    lines.extend(["", "## Remediation", ""])
    for line in remediation_lines(version):
        lines.append(line if line[:1].isdigit() else f"  {line.strip()}")
    lines.extend([
        "",
        "## Edge policy",
        "",
        "Generate deployable files with `php2shell_guard.py rules --out rules`.",
        "",
        "- nginx rejects chunked multipart requests and multipart requests with no Content-Length, and caps the body.",
        "- ModSecurity starts in DetectionOnly. Enforce it after a traffic soak.",
        "- fail2ban watches for the upload-progress parameter on failed write requests.",
        "- The local firewall demo applies the same multipart caps in process.",
        "",
        "## Compliance mapping",
        "",
        "| Framework | Control | How this helps |",
        "|---|---|---|",
        "| ISO/IEC 27001:2022 | A.8.8 | Identifies a technical vulnerability and records the fix |",
        "| PCI DSS 4.0 | 6.3.3 | Drives installation of a critical security patch |",
        "| PCI DSS 4.0 | 6.4.2 | Adds an automated control in front of a public web application |",
        "| NIST CSF 2.0 | ID.RA-01 | Records the vulnerable asset and the observed version |",
        "| NIST CSF 2.0 | PR.PS-02 | Checks that the runtime is on a maintained release |",
        "",
        "## Limits",
        "",
        "- A patched package that has not been loaded into the workers is still exposed.",
        "- Vendor builds sometimes keep an older version number and carry the fix. Pass `--changelog` when the package note names both CVEs.",
        "- `memory_limit=-1` removes one path and can make an allocation failure harder to reach. The PHP project still says the upgrade is the only complete fix.",
        "- Log hits are leads for an investigation. They are not an incident declaration.",
        "",
        "## Disclaimer",
        "",
        "Checker and defensive edge policy. This report is not proof of compromise or of safety, "
        "and it is not legal advice. The tool is provided as-is under the MIT License.",
        "",
        "## See also",
        "",
        "- [Ivanti Connect Secure check](https://github.com/Bluefire-Redteam-Cybersecurity/bluefire-ivanti-ics-guard)",
        "- [SharePoint CVE-2025-53770 toolkit](https://github.com/Bluefire-Redteam-Cybersecurity/bluefire-sharepoint-cve-2025-53770)",
        "- [Nx s1ngularity check](https://github.com/Bluefire-Redteam-Cybersecurity/bluefire-nx-s1ngularity-check)",
        "",
        "## Bluefire Redteam",
        "",
        "Bluefire Redteam is an offensive security firm. The work is red teaming, penetration testing, "
        "and AI security testing, delivered from Ahmedabad, Singapore, and New York.",
        "",
        f"This note is a point-in-time exposure check. To run it across a fleet, write to [{CONTACT}](mailto:{CONTACT}) "
        f"or start at [{SITE}]({SITE}).",
        "",
    ])
    return "\n".join(lines)


class FirewallHandler(BaseHTTPRequestHandler):
    policy = Policy()

    def _verdict(self) -> RequestVerdict:
        length_header = self.headers.get("Content-Length")
        try:
            announced = int(length_header) if length_header else 0
        except ValueError:
            announced = 0
        if announced > self.policy.max_body:
            return RequestVerdict("block", ["body_exceeds_policy"], "Announced body exceeds the edge cap.")
        body = self.rfile.read(announced) if announced else b""
        pairs = list(self.headers.items())
        return inspect_request(self.command, self.path, pairs, body, self.policy)

    def _respond(self, verdict: RequestVerdict) -> None:
        payload = {
            "product": "Bluefire PHP2Shell Guard",
            "action": verdict.action,
            "reasons": verdict.reasons,
            "summary": [REASON_TEXT.get(reason, reason) for reason in verdict.reasons],
            "cves": list(CVES),
            "by": "Bluefire Redteam",
            "site": SITE,
        }
        raw = json.dumps(payload).encode("utf-8")
        code = 403 if verdict.action == "block" else 200
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("X-Bluefire-PHP2Shell", verdict.action)
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self) -> None:  # noqa: N802
        self._respond(self._verdict())

    def do_POST(self) -> None:  # noqa: N802
        self._respond(self._verdict())

    def do_PUT(self) -> None:  # noqa: N802
        self._respond(self._verdict())

    def log_message(self, fmt: str, *args) -> None:
        sys.stderr.write("php2shell-guard %s\n" % (fmt % args))


def serve_firewall(host: str, port: int, policy: Policy) -> None:
    FirewallHandler.policy = policy
    server = ThreadingHTTPServer((host, port), FirewallHandler)
    print(f"Bluefire PHP2Shell firewall listening on http://{host}:{port}")
    print("POST a multipart request. Over-limit requests return 403. Ctrl+C stops the demo.")
    print(CTA)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        server.server_close()


def gather(args: argparse.Namespace) -> tuple[VersionVerdict | None, list[Check], list[LogSignal]]:
    vendor_fix = changelog_names_fix(Path(args.changelog)) if getattr(args, "changelog", None) else False
    raw_version = getattr(args, "php_version", None)
    if raw_version is None and getattr(args, "php_bin", None):
        raw_version = read_php_version(args.php_bin)
    if raw_version is None and getattr(args, "url", None):
        raw_version = fetch_powered_by(args.url)
    version = classify_version(raw_version, vendor_fix) if raw_version else None
    if version is None and vendor_fix:
        version = VersionVerdict("vendor-backport", "patched", None, "Changelog names both CVEs.")

    checks: list[Check] = []
    ini_path = getattr(args, "ini", None)
    if ini_path:
        checks = audit_config(load_config(Path(ini_path)), version)

    signals: list[LogSignal] = []
    log_path = getattr(args, "logs", None)
    if log_path:
        signals = scan_log(Path(log_path), burst=getattr(args, "burst", 5))
    return version, checks, signals


def cmd_audit(args: argparse.Namespace) -> int:
    version, checks, signals = gather(args)
    payload = {
        "decision": overall_status(version, checks),
        "version": version.to_dict() if version else None,
        "checks": [item.to_dict() for item in checks],
        "signals": [item.to_dict() for item in signals],
        "sapi": args.sapi,
    }
    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        print(render_text(version, checks, signals, args.sapi, color=not args.no_color))
    status = payload["decision"]
    if status == "PATCHED":
        return 0
    if status == "PATCHED_WITH_GAPS":
        return 3
    return 2


def cmd_logs(args: argparse.Namespace) -> int:
    signals = scan_log(Path(args.logs), burst=args.burst)
    if args.json:
        print(json.dumps([item.to_dict() for item in signals], indent=2))
    else:
        print(render_text(None, [], signals, None, color=not args.no_color))
    return 2 if signals else 0


def cmd_rules(args: argparse.Namespace) -> int:
    policy = Policy(max_body=args.max_body_mb * 1024 * 1024, max_nesting=args.max_nesting)
    written = write_rules(Path(args.out), policy)
    for path in written:
        print(path)
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    version, checks, signals = gather(args)
    document = render_markdown(version, checks, signals, args.sapi)
    if args.out:
        Path(args.out).write_text(document, encoding="utf-8")
        print(f"Wrote {args.out}")
    else:
        print(document)
    status = overall_status(version, checks)
    return 0 if status == "PATCHED" else 2


def cmd_firewall(args: argparse.Namespace) -> int:
    if args.host not in {"127.0.0.1", "localhost", "::1"} and not args.allow_public:
        print("Refusing a non-loopback bind. Pass --allow-public if this host should listen more widely.", file=sys.stderr)
        return 1
    policy = Policy(
        max_body=args.max_body_mb * 1024 * 1024,
        max_parts=args.max_parts,
        max_part_headers=args.max_part_headers,
        max_nesting=args.max_nesting,
    )
    serve_firewall(args.host, args.port, policy)
    return 0


def cmd_demo(_args: argparse.Namespace) -> int:
    vulnerable_ini = ROOT / "fixtures" / "php.ini.vulnerable"
    log_path = ROOT / "fixtures" / "access.log"
    version = classify_version("8.3.30")
    checks = audit_config(load_config(vulnerable_ini), version)
    signals = scan_log(log_path)
    print(render_text(version, checks, signals, "mod_php", color=True))
    print()
    print("Demo fixture is supposed to be EXPOSED.")
    print("Next: python3 php2shell_guard.py firewall --host 127.0.0.1 --port 8088")
    print("      python3 php2shell_guard.py rules --out rules")
    return 0


def _http_status(port: int, body: bytes, content_type: str) -> int:
    request = Request(
        f"http://127.0.0.1:{port}/upload",
        data=body,
        headers={"Content-Type": content_type},
        method="POST",
    )
    try:
        with urlopen(request, timeout=3) as response:
            return response.status
    except HTTPError as error:
        return error.code


def selftest() -> int:
    failures: list[str] = []

    def expect(condition: bool, message: str) -> None:
        if not condition:
            failures.append(message)

    expect(classify_version("8.3.30").status == "vulnerable", "8.3.30 should be vulnerable")
    expect(classify_version("8.3.36").status == "patched", "8.3.36 should be patched")
    expect(classify_version("8.2.35").status == "patched", "8.2.35 should be patched")
    expect(classify_version("8.2.34").status == "vulnerable", "8.2.34 should be vulnerable")
    expect(classify_version("8.4.27").status == "patched", "8.4.27 should be patched")
    expect(classify_version("8.5.11").status == "vulnerable", "8.5.11 should be vulnerable")
    expect(classify_version("8.5.12").status == "patched", "8.5.12 should be patched")
    expect(classify_version("8.1.31").status == "unsupported", "8.1 should be unsupported")
    expect(classify_version("7.4.33").status == "unsupported", "7.4 should be unsupported")
    expect(classify_version("8.3.30", vendor_fix_noted=True).status == "patched", "changelog should override")
    expect(classify_version("PHP 8.4.20 (cli)").raw == "8.4.20", "version parser should accept php -v text")

    vulnerable = audit_config(load_config(ROOT / "fixtures" / "php.ini.vulnerable"), classify_version("8.3.30"))
    hardened = audit_config(load_config(ROOT / "fixtures" / "php.ini.hardened"), classify_version("8.3.36"))
    expect(any(item.name == "memory_limit" and item.status == "fail" for item in vulnerable), "vulnerable ini")
    expect(any(item.name == "session.upload_progress.enabled" and item.status == "fail" for item in vulnerable), "progress on")
    expect(all(item.status == "pass" for item in hardened if item.name in {"memory_limit", "session.upload_progress.enabled", "post_max_size"}), "hardened ini")
    expect(overall_status(classify_version("8.3.30"), hardened) == "EXPOSED", "hardening is not a patch")
    expect(overall_status(classify_version("8.3.36"), hardened) == "PATCHED", "patched and hardened")

    signals = scan_log(ROOT / "fixtures" / "access.log", burst=5)
    titles = " ".join(item.title for item in signals)
    expect("upload-progress" in titles, "log should see upload progress")
    expect("server errors" in titles, "log should see the 5xx burst")

    policy = Policy()
    small = (
        b'--bf\r\nContent-Disposition: form-data; name="a"\r\n\r\nhello\r\n--bf--\r\n'
    )
    allowed = inspect_request(
        "POST",
        "/upload",
        {"Content-Type": "multipart/form-data; boundary=bf", "Content-Length": str(len(small))},
        small,
        policy,
    )
    expect(allowed.action == "allow", f"small form should pass, got {allowed.reasons}")

    missing = inspect_request(
        "POST",
        "/upload",
        {"Content-Type": "multipart/form-data; boundary=bf"},
        small,
        policy,
    )
    expect(missing.action == "block" and "multipart_without_content_length" in missing.reasons, "missing length")

    extra = "".join(f"X-Test-{i}: 1\r\n" for i in range(20))
    fat = (
        f"--bf\r\n{extra}Content-Disposition: form-data; name=\"a\"\r\n\r\nhi\r\n--bf--\r\n"
    ).encode()
    blocked = inspect_request(
        "POST",
        "/upload",
        {"Content-Type": "multipart/form-data; boundary=bf", "Content-Length": str(len(fat))},
        fat,
        policy,
    )
    expect("too_many_part_headers" in blocked.reasons, "header cap")

    progress = inspect_request(
        "POST",
        "/upload?PHP_SESSION_UPLOAD_PROGRESS=1",
        {"Content-Type": "application/x-www-form-urlencoded", "Content-Length": "1"},
        b"a",
        policy,
    )
    expect(progress.action == "block", "query progress parameter")

    nginx = nginx_config(policy)
    modsec = modsecurity_config(policy)
    expect(CVE_OOM in nginx and CVE_STALE in nginx and "client_max_body_size 8m" in nginx, "nginx rules")
    expect("DetectionOnly" in modsec and "PHP_SESSION_UPLOAD_PROGRESS" in modsec, "modsecurity rules")
    expect(r"(?:\[[^\]]*\]){8,}" in modsec, "nesting regex should be valid PCRE")
    expect("memory_limit = -1" in interim_ini(policy), "ini snippet")

    FirewallHandler.policy = policy
    server = ThreadingHTTPServer(("127.0.0.1", 0), FirewallHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        port = server.server_address[1]
        expect(_http_status(port, small, "multipart/form-data; boundary=bf") == 200, "live allow")
        expect(_http_status(port, fat, "multipart/form-data; boundary=bf") == 403, "live block")
    finally:
        server.shutdown()
        server.server_close()

    if failures:
        print("SELFTEST FAILED")
        for item in failures:
            print(f"  - {item}")
        return 1
    print(f"SELFTEST OK  ({CVE_OOM}, {CVE_STALE})")
    return 0


def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--no-color", action="store_true", help="Plain text, no ANSI color")
    parser = argparse.ArgumentParser(
        prog="php2shell_guard.py",
        description="Bluefire Redteam defensive guard for PHP2Shell (CVE-2026-109618, CVE-2026-109619).",
        parents=[common],
    )
    sub = parser.add_subparsers(dest="command", required=True)

    audit = sub.add_parser("audit", parents=[common], help="Check a PHP version and ini against the advisory")
    audit.add_argument("--php-version", help="Version string, for example 8.3.30")
    audit.add_argument("--php-bin", help="Path to a php binary. Runs php -v only.")
    audit.add_argument("--url", help="Single GET to read X-Powered-By. Not an exploit check.")
    audit.add_argument("--ini", help="php.ini or php -i output")
    audit.add_argument("--changelog", help="Package changelog. Both CVE ids mark a vendor backport as patched.")
    audit.add_argument("--logs", help="Optional combined access log")
    audit.add_argument("--burst", type=int, default=5)
    audit.add_argument("--sapi", choices=["mod_php", "fpm", "cgi", "frankenphp", "litespeed"])
    audit.add_argument("--json", action="store_true")
    audit.set_defaults(func=cmd_audit)

    logs = sub.add_parser("logs", parents=[common], help="Look for defensive leads in a combined access log")
    logs.add_argument("logs")
    logs.add_argument("--burst", type=int, default=5)
    logs.add_argument("--json", action="store_true")
    logs.set_defaults(func=cmd_logs)

    rules = sub.add_parser("rules", help="Write nginx, ModSecurity, ini, and fail2ban files")
    rules.add_argument("--out", default="rules")
    rules.add_argument("--max-body-mb", type=int, default=8)
    rules.add_argument("--max-nesting", type=int, default=DEFAULT_MAX_NESTING)
    rules.set_defaults(func=cmd_rules)

    report = sub.add_parser("report", help="Write a client-facing markdown report")
    report.add_argument("--php-version")
    report.add_argument("--php-bin")
    report.add_argument("--url")
    report.add_argument("--ini")
    report.add_argument("--changelog")
    report.add_argument("--logs")
    report.add_argument("--burst", type=int, default=5)
    report.add_argument("--sapi", choices=["mod_php", "fpm", "cgi", "frankenphp", "litespeed"])
    report.add_argument("--out")
    report.set_defaults(func=cmd_report)

    wall = sub.add_parser("firewall", help="Run the local request filter demo")
    wall.add_argument("--host", default="127.0.0.1")
    wall.add_argument("--port", type=int, default=8088)
    wall.add_argument("--allow-public", action="store_true")
    wall.add_argument("--max-body-mb", type=int, default=8)
    wall.add_argument("--max-parts", type=int, default=DEFAULT_MAX_PARTS)
    wall.add_argument("--max-part-headers", type=int, default=DEFAULT_MAX_PART_HEADERS)
    wall.add_argument("--max-nesting", type=int, default=DEFAULT_MAX_NESTING)
    wall.set_defaults(func=cmd_firewall)

    demo = sub.add_parser("demo", parents=[common], help="Run the bundled exposed fixture for a live walkthrough")
    demo.set_defaults(func=cmd_demo)

    test = sub.add_parser("selftest", help="Run the built-in checks")
    test.set_defaults(func=lambda _args: selftest())
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
