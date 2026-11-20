"""
Unit Tests for Apex Roll-up Engine v10 (Level 2b Campaign Aggregation & Governance)
Tests Parent Fingerprinting, Merkle Mountain Range (MMR), EU AI Act Justification,
and Invariant Dimension Drop Evaluation.
"""

import os
import sys
import unittest
from datetime import datetime, timezone
from unittest.mock import MagicMock

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from pipeline.rollup_engine import (
    compute_parent_fingerprint,
    compute_merkle_root_of_leaves,
    generate_eu_ai_act_justification,
    DEFAULT_ROLLUP_RULES,
    IMMUNE_INFRASTRUCTURE_IPS
)


class TestApexRollupEngine(unittest.TestCase):

    def test_default_rollup_rules_integrity(self):
        """Verify all 15 default rollup rules have valid definitions and cover key domains."""
        self.assertEqual(len(DEFAULT_ROLLUP_RULES), 15)
        categories = set()
        for rule in DEFAULT_ROLLUP_RULES:
            self.assertTrue(rule.name)
            self.assertTrue(rule.category_code)
            self.assertTrue(rule.category_domain)
            self.assertTrue(rule.drop_dimension)
            self.assertTrue(len(rule.invariant_fields) >= 1)
            self.assertTrue(rule.base_threshold >= 2)
            categories.add(rule.category_code)

        expected_categories = {
            "vuln_detected", "web_attack", "auth_bruteforce", "fim_change",
            "generic_rule", "web_client_error", "scan_vertical", "ids_signature",
            "firewall_deny", "sca_failed", "cloud_api_denied", "web_error_flood"
        }
        self.assertTrue(expected_categories.issubset(categories))

    def test_deterministic_parent_fingerprint(self):
        """Parent fingerprint must be deterministic across calls with identical invariants."""
        inv_a = {"tenant_id": "TENANT-1", "agent_name": "srv-web", "source_ip": "192.168.1.50"}
        inv_b = {"source_ip": "192.168.1.50", "tenant_id": "TENANT-1", "agent_name": "srv-web"}
        
        fp_a = compute_parent_fingerprint("Multi-Vector Web Attack", "web_attack", inv_a)
        fp_b = compute_parent_fingerprint("Multi-Vector Web Attack", "web_attack", inv_b)
        
        self.assertEqual(fp_a, fp_b)
        self.assertEqual(len(fp_a), 64)

    def test_parent_fingerprint_different_invariants(self):
        """Different invariant values must produce different parent fingerprints."""
        inv_a = {"tenant_id": "TENANT-1", "agent_name": "srv-web", "source_ip": "192.168.1.50"}
        inv_b = {"tenant_id": "TENANT-1", "agent_name": "srv-web", "source_ip": "192.168.1.51"}
        
        fp_a = compute_parent_fingerprint("Multi-Vector Web Attack", "web_attack", inv_a)
        fp_b = compute_parent_fingerprint("Multi-Vector Web Attack", "web_attack", inv_b)
        
        self.assertNotEqual(fp_a, fp_b)

    def test_compute_merkle_root_of_leaves(self):
        """Merkle root computation must be deterministic and order-invariant."""
        leaves_1 = ["APX-LG-001", "APX-LG-002", "APX-LG-003", "APX-LG-004"]
        leaves_2 = ["APX-LG-004", "APX-LG-001", "APX-LG-003", "APX-LG-002"]
        
        root_1 = compute_merkle_root_of_leaves(leaves_1)
        root_2 = compute_merkle_root_of_leaves(leaves_2)
        
        self.assertEqual(root_1, root_2)
        self.assertEqual(len(root_1), 64)

    def test_compute_merkle_root_empty(self):
        """Empty leaf set should return a valid hash without crashing."""
        root = compute_merkle_root_of_leaves([])
        self.assertEqual(len(root), 64)

    def test_generate_eu_ai_act_justification(self):
        """EU AI Act justification must contain required compliance fields."""
        just = generate_eu_ai_act_justification(
            rule_name="Multi-Vector Web Attack",
            category_code="web_attack",
            leaf_count=5,
            total_alerts=25,
            is_tainted=True,
            invariants={"tenant_id": "TENANT-1", "source_ip": "10.0.0.5"}
        )
        
        self.assertEqual(just["compliance"], "EU_AI_ACT_2024_ART_14")
        self.assertEqual(just["transparency_level"], "CAUSAL_DETERMINISTIC")
        self.assertEqual(just["constituent_leaf_count"], 5)
        self.assertEqual(just["total_aggregated_alerts"], 25)
        self.assertTrue(just["taint_assessment"]["is_tainted"])
        self.assertEqual(just["taint_assessment"]["escalation_policy"], "STRICT_UPWARD_PIN")
        self.assertTrue(just["blast_shield_verified"])

    def test_immune_infrastructure_ips(self):
        """Critical infrastructure IPs like 8.8.8.8 and 127.0.0.1 must be protected by blast-shield."""
        self.assertIn("8.8.8.8", IMMUNE_INFRASTRUCTURE_IPS)
        self.assertIn("127.0.0.1", IMMUNE_INFRASTRUCTURE_IPS)
        self.assertIn("1.1.1.1", IMMUNE_INFRASTRUCTURE_IPS)

    def test_merkle_root_accumulation_order_independent(self):
        """Accumulating new leaves into existing leaf set must produce deterministic Merkle root."""
        existing_leaves = ["APX-LG-001", "APX-LG-002", "APX-LG-003"]
        new_leaves = ["APX-LG-004"]
        
        all_leaves_ordered = sorted(existing_leaves + new_leaves)
        all_leaves_shuffled = sorted(new_leaves + existing_leaves)
        
        root1 = compute_merkle_root_of_leaves(all_leaves_ordered)
        root2 = compute_merkle_root_of_leaves(all_leaves_shuffled)
        
        self.assertEqual(root1, root2)
        # Verify root of 4 leaves is distinct from root of 3 leaves
        root_initial = compute_merkle_root_of_leaves(existing_leaves)
        self.assertNotEqual(root1, root_initial)


if __name__ == "__main__":
    unittest.main()
