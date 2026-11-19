"""
Mini-SIEM MITRE ATT&CK Mapping Module.

Maps detected security anomalies to real-world MITRE ATT&CK techniques,
providing tactics, technique names, explanations, and SOC analyst playbooks.
"""

from dataclasses import dataclass
from typing import Optional


@dataclass
class MitreTechnique:
    """Represents a MITRE ATT&CK framework technique definition."""

    technique_id: str
    name: str
    tactic: str
    description: str
    soc_recommendation: str
    reference_url: str


# Catalog of supported MITRE ATT&CK techniques supported by Mini-SIEM detections
MITRE_TECHNIQUES: dict[str, MitreTechnique] = {
    "T1110": MitreTechnique(
        technique_id="T1110",
        name="Brute Force",
        tactic="Credential Access",
        description=(
            "Adversaries may use brute force techniques to attempt authentication "
            "by guessing passwords through repetitive automated attempts."
        ),
        soc_recommendation=(
            "Temporarily block or rate-limit the source IP address at the firewall/WAF. "
            "Verify whether targeted accounts experienced lockout. Check for multi-factor "
            "authentication (MFA) enforcement on affected endpoints."
        ),
        reference_url="https://attack.mitre.org/techniques/T1110/",
    ),
    "T1110.001": MitreTechnique(
        technique_id="T1110.001",
        name="Brute Force: Password Guessing",
        tactic="Credential Access",
        description=(
            "Adversaries attempt many passwords against a single user account or a small set "
            "of accounts to gain unauthorized access."
        ),
        soc_recommendation=(
            "Enforce account lockout policies, verify IP reputation against threat intelligence feeds, "
            "and alert the account owner to review recent access attempts."
        ),
        reference_url="https://attack.mitre.org/techniques/T1110/001/",
    ),
    "T1110.003": MitreTechnique(
        technique_id="T1110.003",
        name="Brute Force: Password Spraying",
        tactic="Credential Access",
        description=(
            "Adversaries use a single or small list of commonly used passwords against many different "
            "user accounts to evade single-account lockout thresholds."
        ),
        soc_recommendation=(
            "Analyze source IP reputation, inspect user-agent strings for automated tools (e.g. Hydra, curl), "
            "and reset compromised passwords if spray attempts succeeded."
        ),
        reference_url="https://attack.mitre.org/techniques/T1110/003/",
    ),
    "T1078": MitreTechnique(
        technique_id="T1078",
        name="Valid Accounts",
        tactic="Defense Evasion, Persistence, Privilege Escalation, Initial Access",
        description=(
            "Adversaries may obtain and use credentials of existing accounts following successful "
            "brute force, credential stuffing, or phishing."
        ),
        soc_recommendation=(
            "Immediately notify user, revoke active session tokens, mandate password change with MFA reset, "
            "and audit all actions performed during the post-authentication session."
        ),
        reference_url="https://attack.mitre.org/techniques/T1078/",
    ),
    "T1046": MitreTechnique(
        technique_id="T1046",
        name="Network Service Discovery",
        tactic="Discovery",
        description=(
            "Adversaries may attempt to get a listing of services running on remote hosts "
            "by conducting port scans to find vulnerable entry points."
        ),
        soc_recommendation=(
            "Block source IP at network perimeter firewall. Ensure closed ports drop packets instead "
            "of responding with RST to slow reconnaissance. Verify firewall ACL rules."
        ),
        reference_url="https://attack.mitre.org/techniques/T1046/",
    ),
    "T1499": MitreTechnique(
        technique_id="T1499",
        name="Endpoint Denial of Service",
        tactic="Impact",
        description=(
            "Adversaries may perform service exhausting attacks, such as HTTP floods or heavy request volume, "
            "to degrade or deny service availability on target servers."
        ),
        soc_recommendation=(
            "Engage CDN/WAF rate-limiting, challenge suspicious clients with CAPTCHA/proof-of-work at perimeter, "
            "and scale web tier or drop offending IP traffic."
        ),
        reference_url="https://attack.mitre.org/techniques/T1499/",
    ),
}


def get_technique(technique_id: str) -> Optional[MitreTechnique]:
    """Retrieve MITRE technique information by technique ID."""
    return MITRE_TECHNIQUES.get(technique_id.strip().upper())


def map_rule_to_mitre(rule_id: str) -> Optional[MitreTechnique]:
    """
    Maps detection rule ID to its canonical MITRE ATT&CK technique.
    """
    rule_map = {
        "AUTH-001": "T1110",
        "AUTH-002": "T1078",
        "AUTH-003": "T1110.003",
        "AUTH-004": "T1078",
        "FW-001": "T1046",
        "WEB-001": "T1499",
    }
    technique_id = rule_map.get(rule_id.strip().upper())
    return get_technique(technique_id) if technique_id else None
