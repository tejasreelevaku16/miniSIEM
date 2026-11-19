"""
Mini-SIEM detection engine.

Applies security detection rules to parsed LogEvent telemetry:
- AUTH-001: Brute-force login detection (T1110)
- AUTH-002: Failed login followed by successful login (T1078)
- AUTH-003: Repeated suspicious login activity / Password spraying (T1110.003)
- AUTH-004: Login outside configured working hours (T1078)
- FW-001: Port scan detection (T1046)
- WEB-001: High request volume anomaly (T1499)

Maintains complete separation of detection logic from storage and presentation.
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Optional

from app.services.csv_parser import LogEvent
from app.services.mitre_mapper import get_technique, map_rule_to_mitre


@dataclass
class Alert:
    """Represents a security alert produced by detection rules."""

    source_ip: str
    failure_count: int
    window_start: datetime
    window_end: datetime
    severity: str
    description: str
    targeted_usernames: list[str]
    rule_id: str = "AUTH-001"
    rule_name: str = "Brute-Force Login Detection"
    mitre_attack_id: Optional[str] = "T1110"
    mitre_attack_name: Optional[str] = "Brute Force"
    recommended_action: str = "Consider blocking/throttling IP at the firewall"


def determine_severity(failure_count: int) -> str:
    """
    Assign a severity rating based on event count.

    CRITICAL: 10 or more failures.
    HIGH: 5 or more failures.
    MEDIUM: 3 or 4 failures.
    LOW: fewer than 3.
    """
    if failure_count >= 10:
        return "CRITICAL"
    if failure_count >= 5:
        return "HIGH"
    if failure_count >= 3:
        return "MEDIUM"
    return "LOW"


def _is_failed_login(event: LogEvent) -> bool:
    """Helper to detect if an event represents a failed authentication attempt."""
    et = event.event_type.upper()
    oc = event.outcome.lower()
    return et == "LOGIN_FAILED" or (et == "LOGIN" and oc in ("failure", "blocked"))


def _is_successful_login(event: LogEvent) -> bool:
    """Helper to detect if an event represents a successful authentication."""
    et = event.event_type.upper()
    oc = event.outcome.lower()
    return et == "LOGIN_SUCCESS" or (et == "LOGIN" and oc == "success")


# ============================================================
# RULE AUTH-001: Brute-Force Login Detection (T1110)
# ============================================================

def detect_brute_force(
    events: list[LogEvent],
    threshold: int = 5,
    window_minutes: int = 10,
) -> list[Alert]:
    """
    AUTH-001: Detect 5 or more failed logins from the same source IP within 10 minutes.

    Supports custom thresholds/windows to preserve backward compatibility
    with earlier tests (e.g. threshold=3, window_minutes=5).
    """
    window_delta = timedelta(minutes=window_minutes)
    failed_events = [e for e in events if _is_failed_login(e)]

    events_by_ip: dict[str, list[LogEvent]] = {}
    for event in failed_events:
        events_by_ip.setdefault(event.source_ip, []).append(event)

    alerts: list[Alert] = []

    for source_ip, ip_events in events_by_ip.items():
        ip_events.sort(key=lambda e: e.timestamp)
        i = 0
        n = len(ip_events)

        while i < n:
            start_event = ip_events[i]
            window_limit = start_event.timestamp + window_delta

            window_cluster: list[LogEvent] = []
            for j in range(i, n):
                if ip_events[j].timestamp <= window_limit:
                    window_cluster.append(ip_events[j])
                else:
                    break

            if len(window_cluster) >= threshold:
                first_event = window_cluster[0]
                last_event = window_cluster[-1]
                failure_count = len(window_cluster)
                severity = determine_severity(failure_count)
                targeted_users = sorted(set(e.username for e in window_cluster if e.username))
                duration_seconds = max(1, int((last_event.timestamp - first_event.timestamp).total_seconds()))

                tech = map_rule_to_mitre("AUTH-001")
                mitre_id = tech.technique_id if tech else "T1110"
                mitre_name = tech.name if tech else "Brute Force"
                rec = tech.soc_recommendation if tech else "Block IP at perimeter."

                description = (
                    f"Possible Brute-Force attack: {failure_count} failed logins detected "
                    f"within {duration_seconds}s (window: {window_minutes}m)."
                )

                alerts.append(Alert(
                    source_ip=source_ip,
                    failure_count=failure_count,
                    window_start=first_event.timestamp,
                    window_end=last_event.timestamp,
                    severity=severity,
                    description=description,
                    targeted_usernames=targeted_users,
                    rule_id="AUTH-001",
                    rule_name="Brute-Force Login Detection",
                    mitre_attack_id=mitre_id,
                    mitre_attack_name=mitre_name,
                    recommended_action=rec,
                ))

                i += len(window_cluster)
            else:
                i += 1

    alerts.sort(key=lambda a: a.window_start)
    return alerts


# ============================================================
# RULE AUTH-002: Failed Login Followed by Success (T1078)
# ============================================================

def detect_failed_then_success(
    events: list[LogEvent],
    window_minutes: int = 15,
) -> list[Alert]:
    """
    AUTH-002: Detect suspicious login sequences for the same user and source IP
    where 1 or more failed logins are immediately followed by a successful login.

    Indicates potential credential guessing that ultimately compromised the account.
    """
    window_delta = timedelta(minutes=window_minutes)
    auth_events = [e for e in events if _is_failed_login(e) or _is_successful_login(e)]

    # Group by (source_ip, username)
    grouped: dict[tuple[str, str], list[LogEvent]] = {}
    for event in auth_events:
        if event.source_ip and event.username:
            grouped.setdefault((event.source_ip, event.username), []).append(event)

    alerts: list[Alert] = []

    for (source_ip, username), user_events in grouped.items():
        user_events.sort(key=lambda e: e.timestamp)

        failures_in_window: list[LogEvent] = []

        for event in user_events:
            if _is_failed_login(event):
                # Clean up failures that are older than window_delta
                failures_in_window = [
                    f for f in failures_in_window
                    if event.timestamp - f.timestamp <= window_delta
                ]
                failures_in_window.append(event)
            elif _is_successful_login(event):
                # Valid failures within window preceding this success?
                recent_failures = [
                    f for f in failures_in_window
                    if event.timestamp >= f.timestamp and event.timestamp - f.timestamp <= window_delta
                ]

                if recent_failures:
                    first_failure = recent_failures[0]
                    failure_count = len(recent_failures)
                    duration_s = max(1, int((event.timestamp - first_failure.timestamp).total_seconds()))

                    tech = map_rule_to_mitre("AUTH-002")
                    mitre_id = tech.technique_id if tech else "T1078"
                    mitre_name = tech.name if tech else "Valid Accounts"
                    rec = (
                        tech.soc_recommendation if tech
                        else "Review post-login session, verify with user, and consider credential reset."
                    )

                    severity = "HIGH" if failure_count >= 3 else "MEDIUM"
                    description = (
                        f"Suspicious login sequence: {failure_count} failed login(s) followed by "
                        f"SUCCESSFUL login for user '{username}' from {source_ip} within {duration_s}s."
                    )

                    alerts.append(Alert(
                        source_ip=source_ip,
                        failure_count=failure_count + 1,
                        window_start=first_failure.timestamp,
                        window_end=event.timestamp,
                        severity=severity,
                        description=description,
                        targeted_usernames=[username],
                        rule_id="AUTH-002",
                        rule_name="Failed Login Followed by Success",
                        mitre_attack_id=mitre_id,
                        mitre_attack_name=mitre_name,
                        recommended_action=rec,
                    ))

                    # Reset tracking to avoid duplicate alerts for the same burst
                    failures_in_window.clear()

    alerts.sort(key=lambda a: a.window_start)
    return alerts


# ============================================================
# RULE AUTH-003: Repeated Suspicious Login Activity (T1110.003)
# ============================================================

def detect_repeated_suspicious_logins(
    events: list[LogEvent],
    user_spray_threshold: int = 3,
    window_minutes: int = 15,
) -> list[Alert]:
    """
    AUTH-003: Identify repeated failures across multiple distinct usernames
    from the same source IP (password spraying / reconnaissance).
    """
    window_delta = timedelta(minutes=window_minutes)
    failed_events = [e for e in events if _is_failed_login(e)]

    by_ip: dict[str, list[LogEvent]] = {}
    for event in failed_events:
        by_ip.setdefault(event.source_ip, []).append(event)

    alerts: list[Alert] = []

    for source_ip, ip_events in by_ip.items():
        ip_events.sort(key=lambda e: e.timestamp)
        i = 0
        n = len(ip_events)

        while i < n:
            start_event = ip_events[i]
            window_limit = start_event.timestamp + window_delta

            cluster: list[LogEvent] = []
            for j in range(i, n):
                if ip_events[j].timestamp <= window_limit:
                    cluster.append(ip_events[j])
                else:
                    break

            distinct_users = sorted(set(e.username for e in cluster if e.username))

            # Trigger if distinct users >= threshold
            if len(distinct_users) >= user_spray_threshold:
                first_event = cluster[0]
                last_event = cluster[-1]
                failure_count = len(cluster)
                duration_s = max(1, int((last_event.timestamp - first_event.timestamp).total_seconds()))

                tech = map_rule_to_mitre("AUTH-003")
                mitre_id = tech.technique_id if tech else "T1110.003"
                mitre_name = tech.name if tech else "Brute Force: Password Spraying"
                rec = tech.soc_recommendation if tech else "Apply IP block and audit targeted accounts."

                severity = "HIGH" if len(distinct_users) >= 5 else "MEDIUM"
                description = (
                    f"Repeated suspicious login activity: {len(distinct_users)} distinct user accounts "
                    f"targeted ({', '.join(distinct_users)}) with {failure_count} failures "
                    f"from {source_ip} within {duration_s}s."
                )

                alerts.append(Alert(
                    source_ip=source_ip,
                    failure_count=failure_count,
                    window_start=first_event.timestamp,
                    window_end=last_event.timestamp,
                    severity=severity,
                    description=description,
                    targeted_usernames=distinct_users,
                    rule_id="AUTH-003",
                    rule_name="Repeated Suspicious Login Activity",
                    mitre_attack_id=mitre_id,
                    mitre_attack_name=mitre_name,
                    recommended_action=rec,
                ))

                i += len(cluster)
            else:
                i += 1

    alerts.sort(key=lambda a: a.window_start)
    return alerts


# ============================================================
# RULE AUTH-004: Login Outside Working Hours (T1078)
# ============================================================

def detect_outside_working_hours(
    events: list[LogEvent],
    start_hour: int = 8,
    end_hour: int = 18,
    include_weekends: bool = True,
) -> list[Alert]:
    """
    AUTH-004: Detect successful logins occurring outside configured business hours.

    Demonstration rule: Highlights abnormal timing for SOC inspection.
    Configurable: start_hour (default 08:00), end_hour (default 18:00).
    """
    alerts: list[Alert] = []
    successful_events = [e for e in events if _is_successful_login(e)]

    for event in successful_events:
        hour = event.timestamp.hour
        is_weekend = event.timestamp.weekday() >= 5  # 5=Saturday, 6=Sunday

        is_off_hours = False
        reason = ""

        if hour < start_hour or hour >= end_hour:
            is_off_hours = True
            reason = f"outside business hours ({start_hour:02d}:00 - {end_hour:02d}:00)"
        elif include_weekends and is_weekend:
            is_off_hours = True
            reason = "during weekend hours"

        if is_off_hours:
            username = event.username or "unknown"
            tech = map_rule_to_mitre("AUTH-004")
            mitre_id = tech.technique_id if tech else "T1078"
            mitre_name = tech.name if tech else "Valid Accounts"

            # Elevated severity if admin/root
            is_privileged = username.lower() in ("admin", "administrator", "root")
            severity = "MEDIUM" if is_privileged else "LOW"

            description = (
                f"Off-hours authentication: User '{username}' logged in successfully "
                f"at {event.timestamp.strftime('%H:%M:%S')} ({reason}) from {event.source_ip}."
            )

            alerts.append(Alert(
                source_ip=event.source_ip,
                failure_count=1,
                window_start=event.timestamp,
                window_end=event.timestamp,
                severity=severity,
                description=description,
                targeted_usernames=[username],
                rule_id="AUTH-004",
                rule_name="Login Outside Working Hours",
                mitre_attack_id=mitre_id,
                mitre_attack_name=mitre_name,
                recommended_action=(
                    "Verify with user if off-hours login was legitimate. Note: Basic demonstration rule."
                ),
            ))

    alerts.sort(key=lambda a: a.window_start)
    return alerts


# ============================================================
# RULE FW-001: Port Scan Detection (T1046)
# ============================================================

def detect_port_scan(
    events: list[LogEvent],
    port_threshold: int = 5,
    window_minutes: int = 5,
) -> list[Alert]:
    """
    FW-001: Detect repeated connection attempts to different destination ports
    from the same source IP.

    Requirement: Only activates if 'dest_port' field is populated in telemetry.
    Does NOT fabricate data if fields are missing.
    """
    # Guard: check if required dest_port telemetry exists
    events_with_ports = [e for e in events if getattr(e, "dest_port", None) is not None]
    if not events_with_ports:
        return []

    window_delta = timedelta(minutes=window_minutes)

    by_ip: dict[str, list[LogEvent]] = {}
    for e in events_with_ports:
        by_ip.setdefault(e.source_ip, []).append(e)

    alerts: list[Alert] = []

    for source_ip, ip_events in by_ip.items():
        ip_events.sort(key=lambda e: e.timestamp)
        i = 0
        n = len(ip_events)

        while i < n:
            start_event = ip_events[i]
            window_limit = start_event.timestamp + window_delta

            cluster: list[LogEvent] = []
            for j in range(i, n):
                if ip_events[j].timestamp <= window_limit:
                    cluster.append(ip_events[j])
                else:
                    break

            distinct_ports = {e.dest_port for e in cluster if e.dest_port is not None}

            if len(distinct_ports) >= port_threshold:
                first_event = cluster[0]
                last_event = cluster[-1]
                duration_s = max(1, int((last_event.timestamp - first_event.timestamp).total_seconds()))

                tech = map_rule_to_mitre("FW-001")
                mitre_id = tech.technique_id if tech else "T1046"
                mitre_name = tech.name if tech else "Network Service Discovery"
                rec = tech.soc_recommendation if tech else "Block IP at perimeter firewall."

                severity = "HIGH" if len(distinct_ports) >= 10 else "MEDIUM"
                description = (
                    f"Port scan detected: {source_ip} probed {len(distinct_ports)} distinct "
                    f"destination ports ({', '.join(str(p) for p in sorted(distinct_ports)[:8])}...) "
                    f"within {duration_s}s."
                )

                alerts.append(Alert(
                    source_ip=source_ip,
                    failure_count=len(cluster),
                    window_start=first_event.timestamp,
                    window_end=last_event.timestamp,
                    severity=severity,
                    description=description,
                    targeted_usernames=[],
                    rule_id="FW-001",
                    rule_name="Port Scan Detection",
                    mitre_attack_id=mitre_id,
                    mitre_attack_name=mitre_name,
                    recommended_action=rec,
                ))

                i += len(cluster)
            else:
                i += 1

    alerts.sort(key=lambda a: a.window_start)
    return alerts


# ============================================================
# RULE WEB-001: High Request Volume (T1499)
# ============================================================

def detect_high_web_request_volume(
    events: list[LogEvent],
    request_threshold: int = 30,
    window_minutes: int = 1,
) -> list[Alert]:
    """
    WEB-001: Detect unusually high web request volume from a single source IP.

    Requirement: Only activates if web telemetry fields ('request_path', 'status_code',
    or source == 'web') are present. Does NOT fabricate data if missing.
    """
    # Guard: check if web telemetry exists
    web_events = [
        e for e in events
        if (
            getattr(e, "request_path", None) is not None
            or getattr(e, "status_code", None) is not None
            or getattr(e, "source", "").lower() in ("web", "apache", "nginx", "iis")
        )
    ]
    if not web_events:
        return []

    window_delta = timedelta(minutes=window_minutes)

    by_ip: dict[str, list[LogEvent]] = {}
    for e in web_events:
        by_ip.setdefault(e.source_ip, []).append(e)

    alerts: list[Alert] = []

    for source_ip, ip_events in by_ip.items():
        ip_events.sort(key=lambda e: e.timestamp)
        i = 0
        n = len(ip_events)

        while i < n:
            start_event = ip_events[i]
            window_limit = start_event.timestamp + window_delta

            cluster: list[LogEvent] = []
            for j in range(i, n):
                if ip_events[j].timestamp <= window_limit:
                    cluster.append(ip_events[j])
                else:
                    break

            if len(cluster) >= request_threshold:
                first_event = cluster[0]
                last_event = cluster[-1]
                duration_s = max(1, int((last_event.timestamp - first_event.timestamp).total_seconds()))

                tech = map_rule_to_mitre("WEB-001")
                mitre_id = tech.technique_id if tech else "T1499"
                mitre_name = tech.name if tech else "Endpoint Denial of Service"
                rec = tech.soc_recommendation if tech else "Enable WAF rate limiting and challenge client."

                severity = "HIGH" if len(cluster) >= request_threshold * 2 else "MEDIUM"
                description = (
                    f"High request volume detected: {len(cluster)} HTTP requests from {source_ip} "
                    f"within {duration_s}s (threshold: {request_threshold}/min)."
                )

                alerts.append(Alert(
                    source_ip=source_ip,
                    failure_count=len(cluster),
                    window_start=first_event.timestamp,
                    window_end=last_event.timestamp,
                    severity=severity,
                    description=description,
                    targeted_usernames=[],
                    rule_id="WEB-001",
                    rule_name="High Request Volume",
                    mitre_attack_id=mitre_id,
                    mitre_attack_name=mitre_name,
                    recommended_action=rec,
                ))

                i += len(cluster)
            else:
                i += 1

    alerts.sort(key=lambda a: a.window_start)
    return alerts


# ============================================================
# COMPREHENSIVE DETECTOR ORCHESTRATOR
# ============================================================

def run_all_detection_rules(
    events: list[LogEvent],
    working_hours_config: Optional[dict] = None,
) -> list[Alert]:
    """
    Executes all detection rules against parsed events and aggregates alerts.
    """
    wh_cfg = working_hours_config or {"start_hour": 8, "end_hour": 18, "include_weekends": True}

    all_alerts: list[Alert] = []

    # 1. AUTH-001
    all_alerts.extend(detect_brute_force(events, threshold=5, window_minutes=10))

    # 2. AUTH-002
    all_alerts.extend(detect_failed_then_success(events, window_minutes=15))

    # 3. AUTH-003
    all_alerts.extend(detect_repeated_suspicious_logins(events, user_spray_threshold=3, window_minutes=15))

    # 4. AUTH-004
    all_alerts.extend(detect_outside_working_hours(
        events,
        start_hour=wh_cfg.get("start_hour", 8),
        end_hour=wh_cfg.get("end_hour", 18),
        include_weekends=wh_cfg.get("include_weekends", True),
    ))

    # 5. FW-001 (only if firewall telemetry exists)
    all_alerts.extend(detect_port_scan(events, port_threshold=5, window_minutes=5))

    # 6. WEB-001 (only if web telemetry exists)
    all_alerts.extend(detect_high_web_request_volume(events, request_threshold=30, window_minutes=1))

    all_alerts.sort(key=lambda a: a.window_start)
    return all_alerts
