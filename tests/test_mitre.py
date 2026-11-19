"""
Unit tests for MITRE ATT&CK Mapping Module (app/services/mitre_mapper.py).
"""

import unittest
from app.services.mitre_mapper import get_technique, map_rule_to_mitre


class TestMitreMapper(unittest.TestCase):
    """Test suite for MITRE ATT&CK technique lookups and rule mapping."""

    def test_known_technique_lookup(self):
        """Verify known techniques return structured details."""
        tech = get_technique("T1110")
        self.assertIsNotNone(tech)
        self.assertEqual(tech.technique_id, "T1110")
        self.assertEqual(tech.name, "Brute Force")
        self.assertEqual(tech.tactic, "Credential Access")
        self.assertIn("rate-limit", tech.soc_recommendation.lower())

    def test_subtechnique_lookup(self):
        """Verify sub-techniques like T1110.003 (Password Spraying) resolve."""
        tech = get_technique("T1110.003")
        self.assertIsNotNone(tech)
        self.assertEqual(tech.name, "Brute Force: Password Spraying")

    def test_rule_to_mitre_mapping(self):
        """Verify each detection rule correctly maps to its canonical technique."""
        self.assertEqual(map_rule_to_mitre("AUTH-001").technique_id, "T1110")
        self.assertEqual(map_rule_to_mitre("AUTH-002").technique_id, "T1078")
        self.assertEqual(map_rule_to_mitre("AUTH-003").technique_id, "T1110.003")
        self.assertEqual(map_rule_to_mitre("AUTH-004").technique_id, "T1078")
        self.assertEqual(map_rule_to_mitre("FW-001").technique_id, "T1046")
        self.assertEqual(map_rule_to_mitre("WEB-001").technique_id, "T1499")

    def test_unknown_technique_returns_none(self):
        """Verify non-existent technique returns None safely."""
        self.assertIsNone(get_technique("T9999"))
        self.assertIsNone(map_rule_to_mitre("UNKNOWN-RULE"))


if __name__ == "__main__":
    unittest.main()
