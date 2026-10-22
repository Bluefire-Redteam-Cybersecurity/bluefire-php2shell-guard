# Bluefire Redteam — PHP2Shell Guard

Defensive exposure check, interim remediation, and a request firewall for the October 2026 PHP runtime bugs.

Bluefire Redteam is a global offensive security firm. We do red teaming, penetration testing, and AI security testing. This tool is a working example of how we turn a fresh advisory into something an operator can run the same day.

- **CVE-2026-109618** — remote code execution via out-of-memory corruption
- **CVE-2026-109619** — remote code execution via stale worker state

Both are CVSS v4.0 9.2. They are in PHP itself, so WordPress, Drupal, Magento, Laravel, and custom apps are exposed when the runtime underneath them is unpatched. The highest-risk setup in the PHP advisory is Apache `mod_php`.

The only complete fix is a patched PHP build and a restart of every worker. This repository is a checker and a defensive edge policy. It does not send exploit traffic.

| Branch | Fixed release |
|---|---|
| 8.5 | 8.5.12 |
| 8.4 | 8.4.27 |
| 8.3 | 8.3.36 |
| 8.2 | 8.2.35 (end of life 31 December 2026) |

PHP 8.1 and older do not get a normal release. Vendor backports and the PHP project's source backports for 7.4, 8.0, and 8.1 are the remaining options. Pass `--changelog` when a package note names both CVEs but the version number did not move.

Advisory: <https://www.php.net/archive/2026.php#2026-10-21-5>

## Show it in three commands

From this directory:

```bash
python3 php2shell_guard.py selftest
python3 php2shell_guard.py demo
python3 php2shell_guard.py report \
  --php-version 8.3.30 \
  --ini fixtures/php.ini.vulnerable \
  --sapi mod_php \
  --logs fixtures/access.log \
  --out /tmp/php2shell-report.md
```

`demo` audits a deliberately exposed fixture and prints the remediation a client would receive. `selftest` checks the version matrix, the ini audit, the log leads, and the live filter.

## Audit a real host

```bash
python3 php2shell_guard.py audit --php-bin php --ini /etc/php/8.3/fpm/php.ini --sapi fpm
python3 php2shell_guard.py audit --php-version 8.2.28 --changelog /usr/share/doc/php8.2/changelog.Debian.gz
python3 php2shell_guard.py audit --url https://www.example.com --sapi mod_php
```

`--url` sends one GET and reads `X-Powered-By`. A missing header is not a clean bill of health.

Exit codes: `0` patched, `3` patched with leftover config gaps, `2` exposed, `1` usage error.

## Firewall

The local filter is the live demo. It binds to loopback and judges requests. It is not a reverse proxy.

```bash
python3 php2shell_guard.py firewall --host 127.0.0.1 --port 8088
```

A normal small form is allowed. Multipart requests with no `Content-Length`, chunked multipart requests, part-header floods, deep field names, bodies over 8 MB, and `PHP_SESSION_UPLOAD_PROGRESS` are rejected with `403`.

Deploy the same policy in front of PHP:

```bash
python3 php2shell_guard.py rules --out rules
```

That writes four files:

- `rules/nginx-php2shell.conf` — body cap, rate limit, reject chunked multipart and multipart with no length
- `rules/modsecurity-php2shell.conf` — same ideas, shipped in `DetectionOnly` until you soak traffic
- `rules/php2shell-interim.ini` — admin-enforced interim PHP settings
- `rules/fail2ban-php2shell.conf` — low-confidence ban filter for the upload-progress parameter

Put the nginx maps in `http {}` and the `limit_req` plus the `403` in the server that talks to PHP. Test on staging. Sites that legitimately accept large uploads should raise `--max-body-mb` and keep the new cap at the proxy and in `post_max_size`.

## Interim PHP settings

These reduce exposure. PHP says they are not a complete fix.

- `memory_limit=-1`, set with `php_admin_value`, so the app cannot turn a finite limit back on
- `session.upload_progress.enabled=0` before request parsing, then restart workers
- `post_max_size` of 8M, or 32M when uploads are required, with `upload_max_filesize` below it
- `max_input_nesting_level=8`
- On PHP 8.5, `fatal_error_backtraces=0`

Do not use `RLIMIT_AS` or `RLIMIT_DATA`. Those can force the allocation failure the advisory warns about. If you need an availability cap, use a cgroup `memory.max` that kills only the worker.

## What a client still has to do

1. Install the distro package or the upstream release that contains both fixes.
2. Restart php-fpm, Apache, FrankenPHP, or LiteSpeed.
3. Confirm the version inside a web request, then remove any temporary `phpinfo` page.
4. Leave the edge body limits in place after the patch.

Remi's repository did not ship packages on release day. Hosts that depend on it need distro packages or a source build.

## See also

Other Bluefire Redteam checkers:

- [Ivanti Connect Secure check](https://github.com/Bluefire-Redteam-Cybersecurity/bluefire-ivanti-ics-guard) — CVE-2026-104935
- [SharePoint CVE-2025-53770 toolkit](https://github.com/Bluefire-Redteam-Cybersecurity/bluefire-sharepoint-cve-2025-53770)
- [Nx s1ngularity check](https://github.com/Bluefire-Redteam-Cybersecurity/bluefire-nx-s1ngularity-check)

## Disclaimer

This repository is a checker plus a local request filter and configuration snippets. It compares a PHP version and settings with the PHP advisory, and it can reject oversized or malformed multipart requests. It does not send exploit traffic. A result is not proof that a host was compromised, and it is not proof that a host is safe.

Use it only on systems you are authorized to assess. The report is not legal advice and it does not replace the PHP advisory. The software is provided as-is, without warranty, under the [MIT License](LICENSE).

## Work with Bluefire Redteam

If you want this check run across a real estate, or a red team that starts from the bugs your scanners already know about, start at [bluefire-redteam.com](https://bluefire-redteam.com) or write to [contact@bluefire-redteam.com](mailto:contact@bluefire-redteam.com).
