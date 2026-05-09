#!/usr/bin/env python3
from __future__ import annotations

import argparse
from collections import Counter
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import time
import tomllib
from dataclasses import dataclass
from datetime import date, datetime, time as dt_time, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib import error as urlerror, parse, request

CONFIG_PATH = Path("/etc/braiins-monitor/config.json")
STATE_PATH = Path("/var/lib/braiins-monitor/state.json")
DB_PATH = Path("/var/lib/braiins-monitor/incidents.sqlite")
UTC = timezone.utc
TS_FMT = "%a %Y-%m-%d %H:%M:%S %Z"
DEFAULT_GROUP_ALERT_PATTERNS = [
    r"^system:.*:state$",
    r"^system:.*:port:\d+$",
    r"^bot:[^:]+:service$",
    r"^bot:[^:]+:gateway_port$",
    r"^bot:[^:]+:gmail_port$",
    r"^bot:[^:]+:required_port:\d+$",
    r"^bot:[^:]+:config_read$",
    r"^bot:[^:]+:config_invalid$",
    r"^provider:anthropic:status:overall$",
    r"^provider:anthropic:component:.*$",
    r"^provider:anthropic:incident:.*$",
]


@dataclass
class Issue:
    issue_id: str
    severity: str
    component: str
    summary: str
    detail: str

    def to_state(self, now_iso: str, first_seen: str | None = None) -> dict[str, Any]:
        return {
            "severity": self.severity,
            "component": self.component,
            "summary": self.summary,
            "detail": self.detail,
            "first_seen": first_seen or now_iso,
            "last_seen": now_iso,
        }


def now_utc() -> datetime:
    return datetime.now(UTC)


def iso_z(dt: datetime) -> str:
    return dt.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_iso_z(value: str) -> datetime:
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    return datetime.fromisoformat(value).astimezone(UTC)


def parse_systemd_timestamp(value: str | None) -> datetime | None:
    if not value or value in {"n/a", ""}:
        return None
    try:
        return datetime.strptime(value, TS_FMT).replace(tzinfo=UTC)
    except ValueError:
        return None


def run(cmd: list[str], check: bool = True) -> str:
    proc = subprocess.run(
        cmd,
        cwd="/tmp",
        text=True,
        capture_output=True,
    )
    if check and proc.returncode != 0:
        raise RuntimeError(f"command failed ({proc.returncode}): {' '.join(cmd)}\n{proc.stderr.strip()}")
    return proc.stdout


def load_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    return json.loads(path.read_text())


def save_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
    os.replace(tmp, path)


def open_db() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            issue_id TEXT NOT NULL,
            severity TEXT NOT NULL,
            component TEXT NOT NULL,
            summary TEXT NOT NULL,
            detail TEXT NOT NULL,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            resolved_at TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_incidents_issue_open
            ON incidents(issue_id, resolved_at);
        CREATE INDEX IF NOT EXISTS idx_incidents_first_seen
            ON incidents(first_seen);
        CREATE INDEX IF NOT EXISTS idx_incidents_resolved_at
            ON incidents(resolved_at);
        CREATE TABLE IF NOT EXISTS daily_reports (
            report_date TEXT PRIMARY KEY,
            sent_at TEXT NOT NULL,
            chat_id TEXT NOT NULL
        );
        """
    )
    conn.commit()


def backfill_active_issues(conn: sqlite3.Connection, active_issues: dict[str, dict[str, Any]]) -> None:
    for issue_id, item in active_issues.items():
        row = conn.execute(
            "SELECT id FROM incidents WHERE issue_id = ? AND resolved_at IS NULL ORDER BY id DESC LIMIT 1",
            (issue_id,),
        ).fetchone()
        if row is not None:
            continue
        conn.execute(
            """
            INSERT INTO incidents (issue_id, severity, component, summary, detail, first_seen, last_seen, resolved_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, NULL)
            """,
            (
                issue_id,
                str(item.get("severity", "warning")),
                str(item.get("component", "unknown")),
                str(item.get("summary", "active")),
                str(item.get("detail", "")),
                str(item.get("first_seen", iso_z(now_utc()))),
                str(item.get("last_seen", iso_z(now_utc()))),
            ),
        )
    conn.commit()


def sync_active_issues_sqlite(conn: sqlite3.Connection, active_issues: dict[str, dict[str, Any]]) -> None:
    for issue_id, item in active_issues.items():
        values = (
            str(item.get("severity", "warning")),
            str(item.get("component", "unknown")),
            str(item.get("summary", "active")),
            str(item.get("detail", "")),
            str(item.get("last_seen", iso_z(now_utc()))),
            issue_id,
        )
        row = conn.execute(
            "SELECT id FROM incidents WHERE issue_id = ? AND resolved_at IS NULL ORDER BY id DESC LIMIT 1",
            (issue_id,),
        ).fetchone()
        if row is None:
            conn.execute(
                """
                INSERT INTO incidents (issue_id, severity, component, summary, detail, first_seen, last_seen, resolved_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, NULL)
                """,
                (
                    issue_id,
                    str(item.get("severity", "warning")),
                    str(item.get("component", "unknown")),
                    str(item.get("summary", "active")),
                    str(item.get("detail", "")),
                    str(item.get("first_seen", iso_z(now_utc()))),
                    str(item.get("last_seen", iso_z(now_utc()))),
                ),
            )
        else:
            conn.execute(
                """
                UPDATE incidents
                   SET severity = ?, component = ?, summary = ?, detail = ?, last_seen = ?
                 WHERE id = (
                    SELECT id FROM incidents
                     WHERE issue_id = ? AND resolved_at IS NULL
                     ORDER BY id DESC LIMIT 1
                 )
                """,
                values,
            )
    conn.commit()


def resolve_issues_sqlite(conn: sqlite3.Connection, resolved: list[dict[str, Any]], now_iso: str) -> None:
    for item in resolved:
        issue_id = str(item.get("issue_id", "")).strip()
        if not issue_id:
            continue
        conn.execute(
            """
            UPDATE incidents
               SET severity = ?,
                   component = ?,
                   summary = ?,
                   detail = ?,
                   last_seen = ?,
                   resolved_at = ?
             WHERE id = (
                SELECT id FROM incidents
                 WHERE issue_id = ? AND resolved_at IS NULL
                 ORDER BY id DESC LIMIT 1
             )
            """,
            (
                str(item.get("severity", "warning")),
                str(item.get("component", "unknown")),
                str(item.get("summary", "resolved")),
                str(item.get("detail", "")),
                now_iso,
                now_iso,
                issue_id,
            ),
        )
    conn.commit()


def daily_report_sent(conn: sqlite3.Connection, report_date: str) -> bool:
    row = conn.execute("SELECT 1 FROM daily_reports WHERE report_date = ?", (report_date,)).fetchone()
    return row is not None


def mark_daily_report_sent(conn: sqlite3.Connection, report_date: str, sent_at: str, chat_id: str) -> None:
    conn.execute(
        """
        INSERT INTO daily_reports (report_date, sent_at, chat_id)
        VALUES (?, ?, ?)
        ON CONFLICT(report_date) DO UPDATE SET sent_at = excluded.sent_at, chat_id = excluded.chat_id
        """,
        (report_date, sent_at, chat_id),
    )
    conn.commit()


def collect_daily_report_data_sqlite(conn: sqlite3.Connection, report_day: date) -> dict[str, Any]:
    start = datetime.combine(report_day, dt_time.min, tzinfo=UTC)
    end = start + timedelta(days=1)
    start_iso = iso_z(start)
    end_iso = iso_z(end)

    opened_events = [
        dict(row)
        for row in conn.execute(
            """
            SELECT issue_id, severity, component, summary, detail, first_seen
              FROM incidents
             WHERE first_seen >= ? AND first_seen < ?
             ORDER BY first_seen, id
            """,
            (start_iso, end_iso),
        ).fetchall()
    ]
    resolved_events = [
        dict(row)
        for row in conn.execute(
            """
            SELECT issue_id, severity, component, summary, detail, resolved_at
              FROM incidents
             WHERE resolved_at IS NOT NULL AND resolved_at >= ? AND resolved_at < ?
             ORDER BY resolved_at, id
            """,
            (start_iso, end_iso),
        ).fetchall()
    ]
    active_by_end = {
        row["issue_id"]: dict(row)
        for row in conn.execute(
            """
            SELECT issue_id, severity, component, summary, detail, first_seen, last_seen
              FROM incidents
             WHERE first_seen < ?
               AND (resolved_at IS NULL OR resolved_at >= ?)
             ORDER BY severity DESC, component, summary
            """,
            (end_iso, end_iso),
        ).fetchall()
    }

    opened_by_severity = Counter(str(item.get("severity", "warning")) for item in opened_events)
    resolved_by_severity = Counter(str(item.get("severity", "warning")) for item in resolved_events)
    opened_by_component = Counter(str(item.get("component", "unknown")) for item in opened_events)

    return {
        "opened_events": opened_events,
        "resolved_events": resolved_events,
        "opened_by_severity": opened_by_severity,
        "resolved_by_severity": resolved_by_severity,
        "opened_by_component": opened_by_component,
        "active_by_end": active_by_end,
    }


def systemctl_show(unit: str) -> dict[str, str]:
    out = run([
        "systemctl",
        "show",
        unit,
        "-p",
        "ActiveState",
        "-p",
        "SubState",
        "-p",
        "Result",
        "-p",
        "ExecMainStartTimestamp",
        "-p",
        "ExecMainExitTimestamp",
        "-p",
        "MainPID",
    ])
    return parse_key_values(out)


def ensure_user_manager(uid: int) -> None:
    subprocess.run(["systemctl", "start", f"user@{uid}.service"], cwd="/tmp", stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def user_systemctl_show(user: str, uid: int, unit: str) -> dict[str, str]:
    ensure_user_manager(uid)
    env_cmd = [
        "runuser",
        "-u",
        user,
        "--",
        "env",
        f"XDG_RUNTIME_DIR=/run/user/{uid}",
        f"DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{uid}/bus",
        "systemctl",
        "--user",
        "show",
        unit,
        "-p",
        "ActiveState",
        "-p",
        "SubState",
        "-p",
        "Result",
        "-p",
        "ExecMainStartTimestamp",
        "-p",
        "MainPID",
        "-p",
        "MemoryCurrent",
        "-p",
        "NRestarts",
    ]
    out = run(env_cmd)
    return parse_key_values(out)


def fetch_json(url: str, timeout: int = 10) -> Any:
    req = request.Request(url, headers={"User-Agent": "braiins-monitor/1.0"})
    with request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def parse_key_values(text: str) -> dict[str, str]:
    data: dict[str, str] = {}
    for line in text.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        data[key] = value
    return data


def get_listening_ports() -> set[int]:
    out = run(["ss", "-H", "-ltnp"], check=False)
    ports: set[int] = set()
    for line in out.splitlines():
        m = re.search(r":(\d+)\b", line)
        if m:
            try:
                ports.add(int(m.group(1)))
            except ValueError:
                pass
    return ports


def journal_user(uid: int, since: str, unit: str) -> str:
    return run([
        "journalctl",
        f"_SYSTEMD_USER_UNIT={unit}",
        f"_UID={uid}",
        "--since",
        since,
        "--no-pager",
        "-o",
        "cat",
    ], check=False)


def count_matches(text: str, patterns: list[str]) -> int:
    total = 0
    for pattern in patterns:
        total += len(re.findall(pattern, text, flags=re.MULTILINE))
    return total


def unique_matches(text: str, pattern: str, limit: int = 5) -> list[str]:
    found = []
    for match in re.findall(pattern, text, flags=re.MULTILINE):
        item = match if isinstance(match, str) else " ".join(match)
        if item not in found:
            found.append(item)
        if len(found) >= limit:
            break
    return found


def gibibytes(num_bytes: int) -> float:
    return num_bytes / (1024 ** 3)


def read_meminfo() -> dict[str, int]:
    data: dict[str, int] = {}
    for line in Path("/proc/meminfo").read_text().splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        parts = value.strip().split()
        if not parts:
            continue
        try:
            amount = int(parts[0])
        except ValueError:
            continue
        unit = parts[1] if len(parts) > 1 else "kB"
        if unit == "kB":
            amount *= 1024
        data[key] = amount
    return data


def extract_openrouter_model_id(model_ref: Any) -> str | None:
    if not isinstance(model_ref, str):
        return None
    model_ref = model_ref.strip()
    if not model_ref.startswith("openrouter/"):
        return None
    model_id = model_ref.split("/", 1)[1].strip()
    if not model_id or model_id == "auto":
        return None
    return model_id


def bot_runtime(bot: dict[str, Any]) -> str:
    return str(bot.get("runtime", "openclaw")).strip().lower() or "openclaw"


def bot_service_unit(bot: dict[str, Any]) -> str:
    return str(bot.get("service_unit", "openclaw-gateway.service")).strip() or "openclaw-gateway.service"


def bot_config_path(bot: dict[str, Any]) -> Path:
    explicit = str(bot.get("config_path", "")).strip()
    if explicit:
        return Path(explicit)
    user = bot["user"]
    runtime = bot_runtime(bot)
    if runtime == "nullclaw":
        return Path(f"/home/{user}/.nullclaw/config.json")
    if runtime == "zeroclaw":
        return Path(f"/home/{user}/.zeroclaw/config.toml")
    return Path(f"/home/{user}/.openclaw/openclaw.json")


def bot_config_format(bot: dict[str, Any]) -> str:
    explicit = str(bot.get("config_format", "")).strip().lower()
    if explicit:
        return explicit
    return "toml" if bot_config_path(bot).suffix.lower() == ".toml" else "json"


def bot_auth_profiles_path(bot: dict[str, Any]) -> Path | None:
    explicit = str(bot.get("auth_profiles_path", "")).strip()
    if explicit:
        return Path(explicit)
    if bot_runtime(bot) == "openclaw":
        return Path(f"/home/{bot['user']}/.openclaw/agents/main/agent/auth-profiles.json")
    return None


def iter_bot_model_refs(bot: dict[str, Any], cfg: dict[str, Any]) -> list[str]:
    refs: list[str] = []
    runtime = bot_runtime(bot)
    if runtime == "openclaw":
        model_cfg = (((cfg.get("agents") or {}).get("defaults") or {}).get("model") or {})
        refs.extend(ref for ref in [model_cfg.get("primary"), *(model_cfg.get("fallbacks") or [])] if isinstance(ref, str))
    elif runtime == "nullclaw":
        model_cfg = (((cfg.get("agents") or {}).get("defaults") or {}).get("model") or {})
        primary = model_cfg.get("primary")
        if isinstance(primary, str):
            refs.append(primary)
        fallback_cfg = ((cfg.get("reliability") or {}).get("model_fallbacks") or [])
        if isinstance(fallback_cfg, list):
            for item in fallback_cfg:
                if not isinstance(item, dict):
                    continue
                model = item.get("model")
                if isinstance(model, str):
                    refs.append(model)
                fallbacks = item.get("fallbacks") or []
                if isinstance(fallbacks, list):
                    refs.extend(ref for ref in fallbacks if isinstance(ref, str))
    elif runtime == "zeroclaw":
        default_model = cfg.get("default_model")
        if isinstance(default_model, str):
            refs.append(default_model)
        model_fallbacks = ((cfg.get("reliability") or {}).get("model_fallbacks") or {})
        if isinstance(model_fallbacks, dict):
            for values in model_fallbacks.values():
                if isinstance(values, list):
                    refs.extend(ref for ref in values if isinstance(ref, str))
    refs.extend(ref for ref in (bot.get("openrouter_models") or []) if isinstance(ref, str))
    return refs


def extract_bot_gmail_watch(bot: dict[str, Any], cfg: dict[str, Any]) -> tuple[str | None, int | None]:
    override_account = str(bot.get("gmail_account", "")).strip() or None
    override_port = bot.get("gmail_port")
    if override_port not in {None, ""}:
        try:
            return override_account, int(override_port)
        except (TypeError, ValueError):
            return override_account, None

    runtime = bot_runtime(bot)
    if runtime == "openclaw":
        gmail_cfg = (((cfg.get("hooks") or {}).get("gmail") or {}).get("serve") or {})
        gmail_port = gmail_cfg.get("port")
        gmail_account = ((cfg.get("hooks") or {}).get("gmail") or {}).get("account")
        try:
            return (override_account or gmail_account or None), (int(gmail_port) if gmail_port not in {None, ""} else None)
        except (TypeError, ValueError):
            return (override_account or gmail_account or None), None

    return override_account, None


def iter_bot_required_ports(bot: dict[str, Any]) -> list[tuple[int, str]]:
    items = bot.get("required_ports") or []
    ports: list[tuple[int, str]] = []
    for item in items:
        if isinstance(item, int):
            ports.append((item, f"required port {item}"))
            continue
        if isinstance(item, dict):
            port = item.get("port")
            try:
                port_num = int(port)
            except (TypeError, ValueError):
                continue
            label = str(item.get("label", f"required port {port_num}")).strip() or f"required port {port_num}"
            ports.append((port_num, label))
    return ports


def collect_openrouter_models(config: dict[str, Any]) -> dict[str, set[str]]:
    model_to_bots: dict[str, set[str]] = {}
    for bot in config.get("bots", []):
        cfg = read_bot_config(bot)
        if cfg.get("_read_error"):
            continue
        ignored = {
            extract_openrouter_model_id(ref)
            for ref in (bot.get("ignore_openrouter_models") or [])
            if extract_openrouter_model_id(ref)
        }
        for ref in iter_bot_model_refs(bot, cfg):
            model_id = extract_openrouter_model_id(ref)
            if not model_id:
                continue
            if model_id in ignored:
                continue
            model_to_bots.setdefault(model_id, set()).add(bot["label"])
    return model_to_bots


def resolve_openrouter_api_key(config: dict[str, Any]) -> str | None:
    env_key = os.environ.get("BRAIINS_MONITOR_OPENROUTER_API_KEY", "").strip()
    if env_key:
        return env_key
    for bot in config.get("bots", []):
        explicit = str(bot.get("openrouter_api_key", "")).strip()
        if explicit:
            return explicit
        path = bot_auth_profiles_path(bot)
        if path is None:
            continue
        try:
            data = load_json(path, {})
        except Exception:
            continue
        profiles = data.get("profiles") or {}
        preferred = ((data.get("lastGood") or {}).get("openrouter") or "").strip()
        if preferred:
            profile = profiles.get(preferred) or {}
            key = str(profile.get("key", "")).strip()
            if profile.get("provider") == "openrouter" and key:
                return key
        for profile in profiles.values():
            if not isinstance(profile, dict):
                continue
            key = str(profile.get("key", "")).strip()
            if profile.get("provider") == "openrouter" and key:
                return key
    return None


def http_get_json(url: str, headers: dict[str, str] | None = None) -> dict[str, Any]:
    req = request.Request(
        url,
        headers={"Accept": "application/json", **(headers or {})},
        method="GET",
    )
    try:
        with request.urlopen(req, timeout=20) as resp:
            return json.loads(resp.read().decode())
    except urlerror.HTTPError as exc:
        body = exc.read().decode(errors="replace").strip()
        detail = body if body else exc.reason
        raise RuntimeError(f"HTTP {exc.code}: {detail}") from exc
    except Exception as exc:
        raise RuntimeError(str(exc)) from exc


def openrouter_get_json(path: str, api_key: str) -> dict[str, Any]:
    return http_get_json(
        f"https://openrouter.ai{path}",
        headers={"Authorization": f"Bearer {api_key}"},
    )


def anthropic_status_severity(value: str) -> str | None:
    normalized = str(value or "").strip().lower().replace(" ", "_")
    if normalized in {"", "operational", "all_systems_operational", "none", "resolved"}:
        return None
    if normalized in {"degraded_performance", "minor", "partial_outage", "under_maintenance", "maintenance", "investigating", "identified", "monitoring"}:
        return "warning"
    if normalized in {"major_outage", "major", "critical"}:
        return "critical"
    return "warning"


def watched_anthropic_service(name: str, watched_terms: list[str]) -> bool:
    haystack = str(name or "").strip().lower()
    return any(term in haystack for term in watched_terms)


def check_anthropic_status(config: dict[str, Any]) -> list[Issue]:
    issues: list[Issue] = []
    status_cfg = config.get("anthropic_status") or {}
    if status_cfg.get("enabled", True) is False:
        return issues

    summary_url = str(status_cfg.get("summary_url", "https://status.claude.com/api/v2/summary.json")).strip()
    watched_terms = [
        str(term).strip().lower()
        for term in (status_cfg.get("watched_services") or [
            "claude.ai",
            "platform.claude.com",
            "console.anthropic.com",
            "claude api",
            "api.anthropic.com",
            "claude code",
            "claude for government",
        ])
        if str(term).strip()
    ]

    try:
        payload = http_get_json(summary_url)
    except Exception as exc:
        issues.append(Issue(
            issue_id="provider:anthropic:status:poll_failed",
            severity="warning",
            component="Anthropic status",
            summary="Anthropic status poll failed",
            detail=str(exc),
        ))
        return issues

    overall = payload.get("status") or {}
    overall_desc = str(overall.get("description", "")).strip() or "unknown"
    overall_indicator = str(overall.get("indicator", "")).strip() or "unknown"
    overall_severity = anthropic_status_severity(overall_indicator) or anthropic_status_severity(overall_desc)
    if overall_severity:
        issues.append(Issue(
            issue_id="provider:anthropic:status:overall",
            severity=overall_severity,
            component="Anthropic status",
            summary=f"Claude overall status is {overall_desc}",
            detail=f"indicator={overall_indicator}",
        ))

    for component in payload.get("components") or []:
        if not isinstance(component, dict):
            continue
        name = str(component.get("name", "")).strip()
        if not name or not watched_anthropic_service(name, watched_terms):
            continue
        status = str(component.get("status", "")).strip() or "unknown"
        severity = anthropic_status_severity(status)
        if not severity:
            continue
        slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-") or "component"
        issues.append(Issue(
            issue_id=f"provider:anthropic:component:{slug}",
            severity=severity,
            component=name,
            summary=f"Anthropic component status is {status.replace('_', ' ')}",
            detail=f"reported by {summary_url}",
        ))

    for incident in payload.get("incidents") or []:
        if not isinstance(incident, dict):
            continue
        incident_id = str(incident.get("id", "")).strip() or "unknown"
        name = str(incident.get("name", "Unnamed incident")).strip()
        status = str(incident.get("status", "unknown")).strip()
        impact = str(incident.get("impact", "unknown")).strip()
        components = incident.get("components") or []
        component_names = []
        for component in components:
            if isinstance(component, dict):
                component_names.append(str(component.get("name", "")).strip())
        related = [c for c in component_names if watched_anthropic_service(c, watched_terms)]
        if not related:
            continue
        severity = anthropic_status_severity(impact) or anthropic_status_severity(status)
        if not severity:
            continue
        issues.append(Issue(
            issue_id=f"provider:anthropic:incident:{incident_id}",
            severity=severity,
            component="Anthropic incident",
            summary=f"{name} [{status}]",
            detail=f"impact={impact}; components={', '.join(related)}",
        ))
    return issues


def check_openrouter_models(config: dict[str, Any]) -> list[Issue]:
    issues: list[Issue] = []
    model_to_bots = collect_openrouter_models(config)
    if not model_to_bots:
        return issues

    api_key = resolve_openrouter_api_key(config)
    if not api_key:
        issues.append(Issue(
            issue_id="provider:openrouter:key_missing",
            severity="warning",
            component="openrouter",
            summary="OpenRouter model availability could not be checked",
            detail="no OpenRouter API key found in monitor env or bot auth profiles",
        ))
        return issues

    try:
        payload = openrouter_get_json("/api/v1/models/user", api_key)
    except Exception as exc:
        issues.append(Issue(
            issue_id="provider:openrouter:poll_failed",
            severity="warning",
            component="openrouter",
            summary="OpenRouter model availability poll failed",
            detail=str(exc),
        ))
        return issues

    visible_models = {
        str(item.get("id", "")).strip()
        for item in (payload.get("data") or [])
        if isinstance(item, dict) and str(item.get("id", "")).strip()
    }
    if not visible_models:
        issues.append(Issue(
            issue_id="provider:openrouter:empty_models",
            severity="warning",
            component="openrouter",
            summary="OpenRouter returned no visible models",
            detail="the /api/v1/models/user response was empty for the current API key",
        ))
        return issues

    for model_id, bot_labels in sorted(model_to_bots.items()):
        if model_id in visible_models:
            continue
        issues.append(Issue(
            issue_id=f"provider:openrouter:model:{model_id}:missing",
            severity="warning",
            component="openrouter",
            summary=f"OpenRouter model {model_id} is unavailable",
            detail=(
                f"/api/v1/models/user does not list this model; "
                f"configured for {', '.join(sorted(bot_labels))}"
            ),
        ))
    return issues


def check_resources(config: dict[str, Any]) -> list[Issue]:
    issues: list[Issue] = []
    resources = config.get("resources", {})

    memory_cfg = resources.get("memory", {})
    memory_threshold = float(memory_cfg.get("threshold_pct", 80))
    try:
        meminfo = read_meminfo()
        total = int(meminfo["MemTotal"])
        available = int(meminfo.get("MemAvailable", meminfo.get("MemFree", 0)))
        used = max(total - available, 0)
        used_pct = (used / total) * 100 if total else 0.0
        if used_pct >= memory_threshold:
            issues.append(Issue(
                issue_id="resource:memory:high",
                severity="warning",
                component="system memory",
                summary="system memory usage is high",
                detail=(
                    f"using {used_pct:.1f}% of RAM "
                    f"({gibibytes(used):.1f} GiB / {gibibytes(total):.1f} GiB), "
                    f"threshold={memory_threshold:.1f}%"
                ),
            ))
    except Exception as exc:
        issues.append(Issue(
            issue_id="resource:memory:read_error",
            severity="warning",
            component="system memory",
            summary="system memory usage could not be checked",
            detail=str(exc),
        ))

    disks = resources.get("disks")
    if not disks:
        disks = [{"path": "/", "label": "root filesystem", "threshold_pct": 80}]
    for disk in disks:
        path = str(disk.get("path", "/"))
        label = str(disk.get("label", path))
        threshold = float(disk.get("threshold_pct", 80))
        try:
            usage = shutil.disk_usage(path)
            used_pct = (usage.used / usage.total) * 100 if usage.total else 0.0
            if used_pct >= threshold:
                issues.append(Issue(
                    issue_id=f"resource:disk:{path}:high",
                    severity="warning",
                    component=label,
                    summary=f"{label} usage is high",
                    detail=(
                        f"using {used_pct:.1f}% of disk "
                        f"({gibibytes(usage.used):.1f} GiB / {gibibytes(usage.total):.1f} GiB), "
                        f"threshold={threshold:.1f}%"
                    ),
                ))
        except Exception as exc:
            issues.append(Issue(
                issue_id=f"resource:disk:{path}:read_error",
                severity="warning",
                component=label,
                summary=f"{label} usage could not be checked",
                detail=str(exc),
            ))
    return issues


def check_system_services(config: dict[str, Any], ports: set[int]) -> list[Issue]:
    issues: list[Issue] = []
    for svc in config.get("system_services", []):
        if svc.get("user"):
            user = str(svc["user"])
            uid = int(run(["id", "-u", user]).strip())
            show = user_systemctl_show(user, uid, svc["unit"])
        else:
            show = systemctl_show(svc["unit"])
        active = show.get("ActiveState", "unknown")
        sub = show.get("SubState", "unknown")
        if svc.get("kind", "daemon") == "timer":
            if active != "active" or sub not in {"waiting", "running", "elapsed"}:
                issues.append(Issue(
                    issue_id=f"system:{svc['unit']}:state",
                    severity="critical",
                    component=svc["label"],
                    summary=f"{svc['label']} is not waiting",
                    detail=f"state={active}/{sub}",
                ))
            continue
        if svc.get("kind") == "oneshot":
            result = show.get("Result", "unknown")
            exit_ts = parse_systemd_timestamp(show.get("ExecMainExitTimestamp"))
            stale_after = svc.get("stale_after_minutes")
            if result not in {"success", ""}:
                issues.append(Issue(
                    issue_id=f"system:{svc['unit']}:result",
                    severity="critical",
                    component=svc["label"],
                    summary=f"{svc['label']} last run failed",
                    detail=f"result={result}",
                ))
            elif stale_after and exit_ts and now_utc() - exit_ts > timedelta(minutes=stale_after):
                issues.append(Issue(
                    issue_id=f"system:{svc['unit']}:stale",
                    severity="warning",
                    component=svc["label"],
                    summary=f"{svc['label']} looks stale",
                    detail=f"last successful run at {iso_z(exit_ts)}",
                ))
            continue
        if active != "active" or sub != "running":
            issues.append(Issue(
                issue_id=f"system:{svc['unit']}:state",
                severity="critical",
                component=svc["label"],
                summary=f"{svc['label']} is not running",
                detail=f"state={active}/{sub}",
            ))
        port = svc.get("port")
        if port and port not in ports:
            issues.append(Issue(
                issue_id=f"system:{svc['unit']}:port:{port}",
                severity="critical",
                component=svc["label"],
                summary=f"{svc['label']} is not listening on {port}",
                detail=f"expected port {port} missing from ss",
            ))
        health_url = str(svc.get("health_url", "")).strip()
        if health_url:
            try:
                payload = fetch_json(health_url)
                expected = svc.get("health_expect", {})
                for key, value in expected.items():
                    if payload.get(key) != value:
                        raise RuntimeError(f"expected {key}={value!r}, got {payload.get(key)!r}")
            except Exception as exc:
                issues.append(Issue(
                    issue_id=f"system:{svc['unit']}:health",
                    severity="critical",
                    component=svc["label"],
                    summary=f"{svc['label']} health check failed",
                    detail=str(exc),
                ))
    return issues


def read_bot_config(bot: dict[str, Any]) -> dict[str, Any]:
    path = bot_config_path(bot)
    try:
        raw = path.read_text()
        fmt = bot_config_format(bot)
        if fmt == "toml":
            return tomllib.loads(raw)
        return json.loads(raw)
    except Exception as exc:
        return {"_read_error": str(exc)}


def check_bots(config: dict[str, Any], ports: set[int]) -> list[Issue]:
    issues: list[Issue] = []
    recent_window = config.get("recent_window_minutes", 15)
    start_grace_seconds = int(config.get("bot_start_grace_seconds", 90))
    for bot in config.get("bots", []):
        user = bot["user"]
        uid = int(run(["id", "-u", user]).strip())
        service_unit = bot_service_unit(bot)
        show = user_systemctl_show(user, uid, service_unit)
        active = show.get("ActiveState", "unknown")
        sub = show.get("SubState", "unknown")
        start_ts = parse_systemd_timestamp(show.get("ExecMainStartTimestamp"))
        service_start = iso_z(start_ts) if start_ts else iso_z(now_utc() - timedelta(minutes=recent_window))
        service_age = (now_utc() - start_ts).total_seconds() if start_ts else None
        in_start_grace = service_age is not None and service_age < start_grace_seconds
        component = bot["label"]
        if active != "active" or sub != "running":
            issues.append(Issue(
                issue_id=f"bot:{user}:service",
                severity="critical",
                component=component,
                summary=f"{component} gateway is not running",
                detail=f"unit={service_unit} state={active}/{sub}",
            ))
            continue
        gateway_port = int(bot["gateway_port"])
        if not in_start_grace and gateway_port not in ports:
            issues.append(Issue(
                issue_id=f"bot:{user}:gateway_port",
                severity="critical",
                component=component,
                summary=f"{component} gateway port is down",
                detail=f"expected listener on {gateway_port}",
            ))
        if not in_start_grace:
            for required_port, label in iter_bot_required_ports(bot):
                if required_port in ports:
                    continue
                issues.append(Issue(
                    issue_id=f"bot:{user}:required_port:{required_port}",
                    severity="critical",
                    component=component,
                    summary=f"{component} {label} is down",
                    detail=f"expected listener on {required_port}",
                ))
        cfg = read_bot_config(bot)
        if cfg.get("_read_error"):
            issues.append(Issue(
                issue_id=f"bot:{user}:config_read",
                severity="critical",
                component=component,
                summary=f"{component} config could not be read",
                detail=cfg["_read_error"],
            ))
            continue
        gmail_account, gmail_port = extract_bot_gmail_watch(bot, cfg)
        if not in_start_grace and gmail_account and gmail_port and int(gmail_port) not in ports:
            issues.append(Issue(
                issue_id=f"bot:{user}:gmail_port",
                severity="critical",
                component=component,
                summary=f"{component} Gmail watcher is not listening",
                detail=f"expected listener on {gmail_port} for {gmail_account}",
            ))

        logs_since_start = journal_user(uid, service_start, service_unit)
        logs_recent = journal_user(uid, iso_z(now_utc() - timedelta(minutes=recent_window)), service_unit)

        if re.search(r"Failed to read config|Config invalid|EACCES: permission denied", logs_since_start):
            issues.append(Issue(
                issue_id=f"bot:{user}:config_invalid",
                severity="critical",
                component=component,
                summary=f"{component} started with an unreadable or invalid config",
                detail="matched Failed to read config / Config invalid / EACCES after current service start",
            ))
        unknown_models = unique_matches(logs_since_start, r"Unknown model: ([^\n\"]+)")
        if unknown_models:
            issues.append(Issue(
                issue_id=f"bot:{user}:unknown_model",
                severity="critical",
                component=component,
                summary=f"{component} hit an unknown model error",
                detail=", ".join(unknown_models),
            ))
        if re.search(r"gog serve failed to bind|bind: address already in use|listen tcp 127\.0\.0\.1:\d+: bind: address already in use", logs_since_start):
            issues.append(Issue(
                issue_id=f"bot:{user}:bind_conflict",
                severity="warning",
                component=component,
                summary=f"{component} has a local port bind conflict",
                detail="matched gog serve failed to bind / address already in use after current service start",
            ))

        if count_matches(logs_recent, [r"HTTP 429 rate_limit_error", r"API rate limit reached"]) >= 5:
            issues.append(Issue(
                issue_id=f"bot:{user}:rate_limit_storm",
                severity="warning",
                component=component,
                summary=f"{component} is hitting repeated model rate limits",
                detail=f"5+ rate-limit errors in the last {recent_window} minutes",
            ))
        if count_matches(logs_recent, [r"Network request for 'sendMessage' failed", r"final reply failed", r"network error: Network request for 'getUpdates' failed"]) >= 3:
            issues.append(Issue(
                issue_id=f"bot:{user}:telegram_network",
                severity="warning",
                component=component,
                summary=f"{component} is seeing repeated Telegram transport errors",
                detail=f"3+ Telegram send/update failures in the last {recent_window} minutes",
            ))
        if count_matches(logs_recent, [r"failed updating session meta"]) >= 50:
            issues.append(Issue(
                issue_id=f"bot:{user}:session_lock_storm",
                severity="warning",
                component=component,
                summary=f"{component} is thrashing on the session store lock",
                detail=f"50+ session lock failures in the last {recent_window} minutes",
            ))
        if count_matches(logs_recent, [r"delivery-recovery"]) >= 20:
            issues.append(Issue(
                issue_id=f"bot:{user}:delivery_recovery",
                severity="warning",
                component=component,
                summary=f"{component} is replaying a delivery backlog",
                detail=f"20+ delivery-recovery events in the last {recent_window} minutes",
            ))
        if count_matches(logs_recent, [r"BOT_COMMANDS_TOO_MUCH"]) >= 1:
            issues.append(Issue(
                issue_id=f"bot:{user}:bot_commands_too_much",
                severity="warning",
                component=component,
                summary=f"{component} hit Telegram command registration limits",
                detail="BOT_COMMANDS_TOO_MUCH seen in recent logs",
            ))
        if count_matches(logs_recent, [r"fetch failed"]) >= 30:
            issues.append(Issue(
                issue_id=f"bot:{user}:fetch_failed_storm",
                severity="warning",
                component=component,
                summary=f"{component} is seeing repeated fetch failures",
                detail=f"30+ fetch failures in the last {recent_window} minutes",
            ))
    return issues


def build_message(title: str, new_issues: list[Issue], resolved: list[dict[str, Any]]) -> str:
    lines = [f"{title}, {iso_z(now_utc())}"]
    if new_issues:
        lines.append("")
        lines.append("New issues:")
        for issue in sorted(new_issues, key=lambda x: (x.severity, x.component, x.summary)):
            lines.append(f"- [{issue.severity}] {issue.component}: {issue.summary}. {issue.detail}")
    if resolved:
        lines.append("")
        lines.append("Resolved:")
        for item in sorted(resolved, key=lambda x: (x.get("component", ""), x.get("summary", ""))):
            lines.append(f"- {item.get('component', 'unknown')}: {item.get('summary', 'resolved')}")
    return "\n".join(lines)


def issue_id_matches_patterns(issue_id: str, patterns: list[str]) -> bool:
    return any(re.search(pattern, issue_id) for pattern in patterns)


def group_alert_patterns(config: dict[str, Any]) -> list[str]:
    raw = config.get("group_alert_issue_id_patterns")
    if not isinstance(raw, list) or not raw:
        return DEFAULT_GROUP_ALERT_PATTERNS
    return [str(item).strip() for item in raw if str(item).strip()]


def record_event_history(state: dict[str, Any], now_iso: str, new_issues: list[Issue], resolved: list[dict[str, Any]]) -> None:
    history = state.setdefault("event_history", [])
    if not isinstance(history, list):
        history = []
        state["event_history"] = history
    for issue in new_issues:
        history.append({
            "ts": now_iso,
            "kind": "opened",
            "issue_id": issue.issue_id,
            "severity": issue.severity,
            "component": issue.component,
            "summary": issue.summary,
        })
    for item in resolved:
        history.append({
            "ts": now_iso,
            "kind": "resolved",
            "issue_id": item.get("issue_id", ""),
            "severity": item.get("severity", "warning"),
            "component": item.get("component", "unknown"),
            "summary": item.get("summary", "resolved"),
        })


def prune_event_history(state: dict[str, Any], now: datetime, retention_days: int) -> None:
    history = state.get("event_history")
    if not isinstance(history, list):
        state["event_history"] = []
        return
    cutoff = now - timedelta(days=max(retention_days, 1))
    kept: list[dict[str, Any]] = []
    for item in history:
        if not isinstance(item, dict):
            continue
        try:
            event_ts = parse_iso_z(str(item.get("ts", "")))
        except Exception:
            continue
        if event_ts >= cutoff:
            kept.append(item)
    state["event_history"] = kept


def parse_daily_report_time(value: str) -> dt_time:
    raw = (value or "00:00").strip()
    try:
        hour_str, minute_str = raw.split(":", 1)
        hour = int(hour_str)
        minute = int(minute_str)
        if not (0 <= hour <= 23 and 0 <= minute <= 59):
            raise ValueError
        return dt_time(hour=hour, minute=minute, tzinfo=UTC)
    except Exception:
        return dt_time(hour=0, minute=0, tzinfo=UTC)


def format_counter(counter: Counter[str], order: tuple[str, ...] = ("critical", "warning")) -> str:
    parts: list[str] = []
    for key in order:
        count = counter.get(key)
        if count:
            parts.append(f"{key} {count}")
    for key in sorted(counter):
        if key in order:
            continue
        parts.append(f"{key} {counter[key]}")
    return ", ".join(parts) if parts else "none"


def collect_daily_report_data(state: dict[str, Any], report_day: date, current_active: dict[str, dict[str, Any]]) -> dict[str, Any]:
    start = datetime.combine(report_day, dt_time.min, tzinfo=UTC)
    end = start + timedelta(days=1)
    history = state.get("event_history", [])

    opened_events: list[dict[str, Any]] = []
    resolved_events: list[dict[str, Any]] = []
    prior_events: list[dict[str, Any]] = []
    for item in history if isinstance(history, list) else []:
        if not isinstance(item, dict):
            continue
        try:
            event_ts = parse_iso_z(str(item.get("ts", "")))
        except Exception:
            continue
        if start <= event_ts < end:
            if item.get("kind") == "opened":
                opened_events.append(item)
            elif item.get("kind") == "resolved":
                resolved_events.append(item)
        if event_ts < end:
            prior_events.append(item)

    active_by_end: dict[str, dict[str, Any]] = {}
    for issue_id, item in current_active.items():
        try:
            first_seen = parse_iso_z(str(item.get("first_seen", "")))
        except Exception:
            continue
        if first_seen < end:
            active_by_end[issue_id] = {
                "issue_id": issue_id,
                "severity": item.get("severity", "warning"),
                "component": item.get("component", "unknown"),
                "summary": item.get("summary", "active"),
                "first_seen": item.get("first_seen", ""),
            }

    for item in sorted(prior_events, key=lambda x: x.get("ts", "")):
        issue_id = str(item.get("issue_id", "")).strip()
        if not issue_id:
            continue
        if item.get("kind") == "opened":
            active_by_end[issue_id] = {
                "issue_id": issue_id,
                "severity": item.get("severity", "warning"),
                "component": item.get("component", "unknown"),
                "summary": item.get("summary", "active"),
                "first_seen": item.get("ts", ""),
            }
        elif item.get("kind") == "resolved":
            active_by_end.pop(issue_id, None)

    opened_by_severity = Counter(str(item.get("severity", "warning")) for item in opened_events)
    resolved_by_severity = Counter(str(item.get("severity", "warning")) for item in resolved_events)
    opened_by_component = Counter(str(item.get("component", "unknown")) for item in opened_events)

    return {
        "opened_events": opened_events,
        "resolved_events": resolved_events,
        "opened_by_severity": opened_by_severity,
        "resolved_by_severity": resolved_by_severity,
        "opened_by_component": opened_by_component,
        "active_by_end": active_by_end,
    }


def build_daily_report(report_day: date, data: dict[str, Any], now_iso: str, component_limit: int, active_limit: int) -> str:
    opened_events = data["opened_events"]
    resolved_events = data["resolved_events"]
    active_by_end = data["active_by_end"]
    opened_by_severity = data["opened_by_severity"]
    resolved_by_severity = data["resolved_by_severity"]
    opened_by_component = data["opened_by_component"]

    lines = [f"Braiins monitor daily report for {report_day.isoformat()}, sent {now_iso}"]
    lines.append("")
    lines.append(f"- Opened incidents: {len(opened_events)} ({format_counter(opened_by_severity)})")
    lines.append(f"- Resolved incidents: {len(resolved_events)} ({format_counter(resolved_by_severity)})")
    lines.append(f"- Still active at end of day: {len(active_by_end)}")

    if opened_by_component:
        lines.append("- Components with the most new incidents:")
        for component, count in opened_by_component.most_common(max(component_limit, 1)):
            lines.append(f"  - {component}: {count}")

    if active_by_end:
        lines.append("- Active issues at end of day:")
        active_items = sorted(
            active_by_end.values(),
            key=lambda item: (str(item.get("severity", "")) != "critical", str(item.get("component", "")), str(item.get("summary", ""))),
        )
        for item in active_items[: max(active_limit, 1)]:
            lines.append(f"  - [{item.get('severity', 'warning')}] {item.get('component', 'unknown')}: {item.get('summary', 'active')}")
        if len(active_items) > max(active_limit, 1):
            lines.append(f"  - ... and {len(active_items) - max(active_limit, 1)} more")

    if not opened_events and not resolved_events and not active_by_end:
        lines.append("- No incidents were recorded.")

    return "\n".join(lines)


def maybe_send_daily_report(
    conn: sqlite3.Connection,
    token: str,
    config: dict[str, Any],
    now: datetime,
    now_iso: str,
    dry_run: bool,
) -> bool:
    report_cfg = config.get("daily_report") or {}
    if report_cfg.get("enabled", True) is False:
        return False

    chat_id = str(report_cfg.get("chat_id") or config.get("telegram_warning_dm_chat_id", "")).strip()
    if not chat_id:
        return False

    report_time = parse_daily_report_time(str(report_cfg.get("time_utc", "00:00")))
    if now.time() < report_time.replace(tzinfo=None):
        return False

    report_day = (now.date() - timedelta(days=1))
    report_key = report_day.isoformat()
    if daily_report_sent(conn, report_key):
        return False

    data = collect_daily_report_data_sqlite(conn, report_day)
    text = build_daily_report(
        report_day,
        data,
        now_iso,
        int(report_cfg.get("component_limit", 8)),
        int(report_cfg.get("active_limit", 8)),
    )
    if dry_run:
        print(text)
        return False

    send_telegram(token, chat_id, text)
    mark_daily_report_sent(conn, report_key, now_iso, chat_id)
    return True


def should_stabilize_retry(issues: list[Issue]) -> bool:
    for issue in issues:
        if issue.issue_id.endswith(":service"):
            return True
        if issue.issue_id.endswith(":gateway_port") or issue.issue_id.endswith(":gmail_port"):
            return True
        if issue.issue_id.startswith("system:") and (issue.issue_id.endswith(":state") or ":port:" in issue.issue_id):
            return True
    return False


def collect_issues(config: dict[str, Any]) -> list[Issue]:
    ports = get_listening_ports()
    return (
        check_resources(config)
        + check_system_services(config, ports)
        + check_bots(config, ports)
        + check_anthropic_status(config)
        + check_openrouter_models(config)
    )


def send_routed_notifications(token: str, config: dict[str, Any], new_issues: list[Issue], resolved: list[dict[str, Any]]) -> None:
    critical_chat_id = str(config.get("telegram_chat_id", "")).strip()
    warning_chat_id = str(config.get("telegram_warning_dm_chat_id", "")).strip()
    group_patterns = group_alert_patterns(config)

    group_new = [
        issue
        for issue in new_issues
        if issue.severity == "critical" and issue_id_matches_patterns(issue.issue_id, group_patterns)
    ]
    group_resolved = [
        item
        for item in resolved
        if item.get("severity") == "critical" and issue_id_matches_patterns(str(item.get("issue_id", "")), group_patterns)
    ]

    if critical_chat_id and (group_new or group_resolved):
        send_telegram(token, critical_chat_id, build_message("Braiins monitor critical alert", group_new, group_resolved))
    if warning_chat_id and (new_issues or resolved):
        send_telegram(token, warning_chat_id, build_message("Braiins monitor update", new_issues, resolved))


def send_telegram(token: str, chat_id: str, text: str) -> None:
    payload = parse.urlencode({
        "chat_id": chat_id,
        "text": text,
        "disable_web_page_preview": "true",
    }).encode()
    req = request.Request(
        f"https://api.telegram.org/bot{token}/sendMessage",
        data=payload,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    with request.urlopen(req, timeout=20) as resp:
        data = json.loads(resp.read().decode())
    if not data.get("ok"):
        raise RuntimeError(f"Telegram send failed: {data}")


def get_me(token: str) -> dict[str, Any]:
    with request.urlopen(f"https://api.telegram.org/bot{token}/getMe", timeout=20) as resp:
        data = json.loads(resp.read().decode())
    if not data.get("ok"):
        raise RuntimeError(f"Telegram getMe failed: {data}")
    return data["result"]


def get_chat(token: str, chat_id: str) -> dict[str, Any]:
    q = parse.urlencode({"chat_id": chat_id})
    with request.urlopen(f"https://api.telegram.org/bot{token}/getChat?{q}", timeout=20) as resp:
        data = json.loads(resp.read().decode())
    if not data.get("ok"):
        raise RuntimeError(f"Telegram getChat failed: {data}")
    return data["result"]


def main() -> int:
    parser = argparse.ArgumentParser(description="Braiins monitor")
    parser.add_argument("--dry-run", action="store_true", help="do not send Telegram messages")
    parser.add_argument("--announce-existing", action="store_true", help="send current issues even on first run")
    parser.add_argument("--validate-telegram", action="store_true", help="only validate Telegram token and chat access")
    parser.add_argument("--force-daily-report", metavar="YYYY-MM-DD", help="print or send the daily report for a specific UTC date")
    args = parser.parse_args()

    token = os.environ.get("BRAIINS_MONITOR_BOT_TOKEN", "").strip()
    if not token:
        raise SystemExit("BRAIINS_MONITOR_BOT_TOKEN is not set")

    config = load_json(CONFIG_PATH, {})
    critical_chat_id = str(config.get("telegram_chat_id", "")).strip()
    warning_chat_id = str(config.get("telegram_warning_dm_chat_id", "")).strip()
    if not critical_chat_id:
        raise SystemExit("telegram_chat_id missing in config")

    if args.validate_telegram:
        me = get_me(token)
        payload = {"me": me, "critical_chat": get_chat(token, critical_chat_id)}
        if warning_chat_id:
            payload["warning_chat"] = get_chat(token, warning_chat_id)
        print(json.dumps(payload, indent=2))
        return 0

    state = load_json(STATE_PATH, {"initialized": False, "active_issues": {}})
    db = open_db()
    try:
        init_db(db)
        backfill_active_issues(db, state.get("active_issues", {}))
    except Exception:
        db.close()
        raise
    issues = collect_issues(config)
    retry_seconds = int(config.get("stabilization_retry_seconds", 20))
    if retry_seconds > 0 and should_stabilize_retry(issues):
        time.sleep(retry_seconds)
        issues = collect_issues(config)
    current = {issue.issue_id: issue for issue in issues}
    now = now_utc()
    now_iso = iso_z(now)

    if not state.get("initialized"):
        if args.dry_run:
            print(f"baseline would initialize with {len(current)} active issues")
            if args.announce_existing and current:
                sync_active_issues_sqlite(db, {k: v.to_state(now_iso) for k, v in current.items()})
                print(build_message("Braiins monitor baseline", list(current.values()), []))
            db.close()
            return 0
        state["initialized"] = True
        state["active_issues"] = {k: v.to_state(now_iso) for k, v in current.items()}
        state["last_run"] = now_iso
        sync_active_issues_sqlite(db, state["active_issues"])
        save_json(STATE_PATH, state)
        print(f"baseline initialized with {len(current)} active issues")
        if args.announce_existing and current:
            send_routed_notifications(token, config, list(current.values()), [])
        db.close()
        return 0

    previous: dict[str, dict[str, Any]] = state.get("active_issues", {})
    new_ids = [key for key in current if key not in previous]
    resolved_ids = [key for key in previous if key not in current]

    next_state: dict[str, dict[str, Any]] = {}
    for key, issue in current.items():
        first_seen = previous.get(key, {}).get("first_seen")
        next_state[key] = issue.to_state(now_iso, first_seen=first_seen)

    had_changes = False
    if new_ids or resolved_ids:
        had_changes = True
        new_issues = [current[key] for key in new_ids]
        resolved = [{**previous[key], "issue_id": key} for key in resolved_ids]
        if args.dry_run:
            group_patterns = group_alert_patterns(config)
            group_new = [
                issue
                for issue in new_issues
                if issue.severity == "critical" and issue_id_matches_patterns(issue.issue_id, group_patterns)
            ]
            group_resolved = [
                item
                for item in resolved
                if item.get("severity") == "critical" and issue_id_matches_patterns(str(item.get("issue_id", "")), group_patterns)
            ]
            if group_new or group_resolved:
                print(build_message("Braiins monitor critical alert", group_new, group_resolved))
            print(build_message("Braiins monitor update", new_issues, resolved))
        else:
            send_routed_notifications(token, config, new_issues, resolved)

    next_state_for_report = next_state
    sync_active_issues_sqlite(db, next_state_for_report)
    resolve_issues_sqlite(db, resolved if new_ids or resolved_ids else [], now_iso)
    if args.force_daily_report:
        report_day = date.fromisoformat(args.force_daily_report)
        report_data = collect_daily_report_data_sqlite(db, report_day)
        report_text = build_daily_report(
            report_day,
            report_data,
            now_iso,
            int((config.get("daily_report") or {}).get("component_limit", 8)),
            int((config.get("daily_report") or {}).get("active_limit", 8)),
        )
        if args.dry_run:
            print(report_text)
        else:
            report_chat_id = str((config.get("daily_report") or {}).get("chat_id") or config.get("telegram_warning_dm_chat_id", "")).strip()
            if report_chat_id:
                send_telegram(token, report_chat_id, report_text)
        if args.dry_run:
            db.close()
            return 0

    daily_report_sent_now = maybe_send_daily_report(db, token, config, now, now_iso, args.dry_run)

    if not args.dry_run:
        state["active_issues"] = next_state
        state["last_run"] = now_iso
        save_json(STATE_PATH, state)
    db.close()
    if not had_changes and not daily_report_sent_now:
        print("no changes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
