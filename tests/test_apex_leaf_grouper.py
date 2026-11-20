"""
Unit Tests for Apex Leaf Grouper Engine (Level 2 Activity Groups)
Tests Join Test, Windowing, Continuation Lineage, Analyst Guard, and Bridge Merge logic.
"""

import os
import sys
import unittest
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from pipeline.leaf_grouper import (
    parse_window_seconds,
    parse_utc_timestamp,
    LeafGrouperEngine
)
from pipeline.category_catalog import APEX_32_CATEGORIES
from pipeline.fingerprint_engine import Fingerprint


class TestApexLeafGrouper(unittest.TestCase):

    def setUp(self):
        self.auth_cat = next(c for c in APEX_32_CATEGORIES if c.code == "auth_bruteforce")
        self.web_cat = next(c for c in APEX_32_CATEGORIES if c.code == "web_attack")
        self.mock_fp = Fingerprint(
            hash="test_fingerprint_hash_1234567890abcdef",
            quality="exact",
            body={"v": 8, "tenant": "TEST", "c": "auth_bruteforce", "t": "leaf", "p": {"agent": "server1"}},
            tracked_samples={"dst_port": [22]},
            tracked_distinct_counts={"dst_port": 1}
        )

    def test_parse_window_seconds(self):
        self.assertEqual(parse_window_seconds("10m"), 600)
        self.assertEqual(parse_window_seconds("1h"), 3600)
        self.assertEqual(parse_window_seconds("36h"), 129600)
        self.assertEqual(parse_window_seconds("14d"), 1209600)
        self.assertEqual(parse_window_seconds(None), 600)

    def test_parse_utc_timestamp(self):
        dt = parse_utc_timestamp("2026-11-11T10:00:00Z")
        self.assertEqual(dt.tzinfo, timezone.utc)
        self.assertEqual(dt.year, 2026)

    def test_process_alert_new_group_created(self):
        """When no open or closed group exists, a brand new group must be CREATED."""
        mock_cur = MagicMock()
        # Advisory lock execute
        # open groups query -> returns empty
        # closed groups query -> returns empty
        mock_cur.fetchall.side_effect = [
            [],  # open_groups
            []   # closed_cand
        ]

        now = datetime(2026, 11, 11, 10, 0, 0, tzinfo=timezone.utc)
        group_id, action = LeafGrouperEngine.process_alert(
            cur=mock_cur,
            alert_id="ALERT-001",
            event_time=now,
            tenant_id="TEST",
            category=self.auth_cat,
            fp=self.mock_fp,
            agent_name="server1",
            source_ip="192.168.1.100",
            target="root"
        )

        self.assertTrue(group_id.startswith("APX-LG-"))
        self.assertEqual(action, "CREATED")

    def test_process_alert_join_existing_open_group(self):
        """When an open group exists and event falls within window, alert should JOIN."""
        mock_cur = MagicMock()
        first_seen = datetime(2026, 11, 11, 10, 0, 0, tzinfo=timezone.utc)
        last_seen = datetime(2026, 11, 11, 10, 5, 0, tzinfo=timezone.utc)
        
        # open groups query -> returns existing open group
        mock_cur.fetchall.side_effect = [
            [(
                "APX-LG-EXISTING1", 8, first_seen, last_seen, 5,
                None, "APX-LG-ROOT1", "OPEN", None,
                600, 3600, {"dst_port": [22]}, {"dst_port": 1}
            )]
        ]

        # Event arrives 2 minutes after last_seen (within 10m window)
        event_time = datetime(2026, 11, 11, 10, 7, 0, tzinfo=timezone.utc)
        group_id, action = LeafGrouperEngine.process_alert(
            cur=mock_cur,
            alert_id="ALERT-002",
            event_time=event_time,
            tenant_id="TEST",
            category=self.auth_cat,
            fp=self.mock_fp,
            agent_name="server1",
            source_ip="192.168.1.100",
            target="root"
        )

        self.assertEqual(group_id, "APX-LG-EXISTING1")
        self.assertEqual(action, "JOINED")

    def test_process_alert_max_duration_continuation(self):
        """When event exceeds max duration, old group is closed and continuation group created with lineage."""
        mock_cur = MagicMock()
        first_seen = datetime(2026, 11, 11, 10, 0, 0, tzinfo=timezone.utc)
        last_seen = datetime(2026, 11, 11, 10, 55, 0, tzinfo=timezone.utc)
        
        # Candidate group has max_duration = 3600s (1h)
        mock_cur.fetchall.side_effect = [
            [(
                "APX-LG-HOUR1", 8, first_seen, last_seen, 50,
                None, "APX-LG-ROOT1", "OPEN", None,
                600, 3600, {"dst_port": [22]}, {"dst_port": 1}
            )],
            []  # closed_cand
        ]

        # Event arrives at 11:05 (1h 5m from first_seen -> exceeds 3600s max duration)
        event_time = datetime(2026, 11, 11, 11, 5, 0, tzinfo=timezone.utc)
        group_id, action = LeafGrouperEngine.process_alert(
            cur=mock_cur,
            alert_id="ALERT-003",
            event_time=event_time,
            tenant_id="TEST",
            category=self.auth_cat,
            fp=self.mock_fp,
            agent_name="server1",
            source_ip="192.168.1.100",
            target="root"
        )

        self.assertTrue(group_id.startswith("APX-LG-"))
        self.assertNotEqual(group_id, "APX-LG-HOUR1")
        self.assertEqual(action, "CREATED")

    def test_process_alert_pinning_below_threshold(self):
        """Alert with level < category.pin_level (e.g. lvl 5 < 12) must NOT be pinned."""
        mock_cur = MagicMock()
        mock_cur.fetchall.side_effect = [[], []]

        now = datetime(2026, 11, 11, 10, 0, 0, tzinfo=timezone.utc)
        LeafGrouperEngine.process_alert(
            cur=mock_cur,
            alert_id="ALERT-LOW-PIN",
            event_time=now,
            tenant_id="TEST",
            category=self.auth_cat,  # pin_level = 12
            fp=self.mock_fp,
            agent_name="server1",
            source_ip="192.168.1.100",
            target="root",
            rule_level=5  # below threshold 12
        )

        # Inspect the INSERT query params: is_pinned must be False
        insert_args = [call for call in mock_cur.execute.call_args_list if "INSERT INTO telemetry.alert_activity_groups" in str(call[0][0])]
        self.assertTrue(len(insert_args) > 0)
        inserted_params = insert_args[0][0][1]
        is_pinned_param = inserted_params[19]  # 20th parameter is is_pinned
        self.assertFalse(is_pinned_param, "Alert with level 5 should NOT be pinned for category with pin_level=12")

    def test_process_alert_pinning_above_threshold(self):
        """Alert with level >= category.pin_level (e.g. lvl 12 >= 12) MUST be pinned."""
        mock_cur = MagicMock()
        mock_cur.fetchall.side_effect = [[], []]

        now = datetime(2026, 11, 11, 10, 0, 0, tzinfo=timezone.utc)
        LeafGrouperEngine.process_alert(
            cur=mock_cur,
            alert_id="ALERT-HIGH-PIN",
            event_time=now,
            tenant_id="TEST",
            category=self.auth_cat,  # pin_level = 12
            fp=self.mock_fp,
            agent_name="server1",
            source_ip="192.168.1.100",
            target="root",
            rule_level=12  # meets threshold 12
        )

        insert_args = [call for call in mock_cur.execute.call_args_list if "INSERT INTO telemetry.alert_activity_groups" in str(call[0][0])]
        inserted_params = insert_args[0][0][1]
        is_pinned_param = inserted_params[19]
        self.assertTrue(is_pinned_param, "Alert with level 12 MUST be pinned for category with pin_level=12")

    def test_process_alert_pinning_sensitive_category_threshold_10(self):
        """Categories like priv_escalation with pin_level=10 must pin alerts with level 10+."""
        priv_cat = next(c for c in APEX_32_CATEGORIES if c.code == "priv_escalation")
        mock_cur = MagicMock()
        mock_cur.fetchall.side_effect = [[], []]

        now = datetime(2026, 11, 11, 10, 0, 0, tzinfo=timezone.utc)
        LeafGrouperEngine.process_alert(
            cur=mock_cur,
            alert_id="ALERT-PRIV-10",
            event_time=now,
            tenant_id="TEST",
            category=priv_cat,  # pin_level = 10
            fp=self.mock_fp,
            agent_name="server1",
            source_ip="192.168.1.100",
            target="root",
            rule_level=10  # meets threshold 10
        )

        insert_args = [call for call in mock_cur.execute.call_args_list if "INSERT INTO telemetry.alert_activity_groups" in str(call[0][0])]
        inserted_params = insert_args[0][0][1]
        is_pinned_param = inserted_params[19]
        self.assertTrue(is_pinned_param, "Alert with level 10 MUST be pinned for priv_escalation (pin_level=10)")

    def test_process_alert_joining_elevates_unpinned_group(self):
        """When an unpinned group receives a high-severity alert, the group becomes pinned."""
        mock_cur = MagicMock()
        first_seen = datetime(2026, 11, 11, 10, 0, 0, tzinfo=timezone.utc)
        last_seen = datetime(2026, 11, 11, 10, 5, 0, tzinfo=timezone.utc)

        # Candidate group has is_pinned = False (index 13)
        mock_cur.fetchall.side_effect = [
            [(
                "APX-LG-UNPINNED1", 8, first_seen, last_seen, 2,
                None, "APX-LG-ROOT1", "OPEN", None,
                600, 3600, {"dst_port": [22]}, {"dst_port": 1},
                False  # is_pinned currently False
            )]
        ]

        event_time = datetime(2026, 11, 11, 10, 6, 0, tzinfo=timezone.utc)
        LeafGrouperEngine.process_alert(
            cur=mock_cur,
            alert_id="ALERT-ELEVATE",
            event_time=event_time,
            tenant_id="TEST",
            category=self.auth_cat,
            fp=self.mock_fp,
            agent_name="server1",
            source_ip="192.168.1.100",
            target="root",
            rule_level=14  # level 14 >= 12 -> elevates group
        )

        update_args = [call for call in mock_cur.execute.call_args_list if "UPDATE telemetry.alert_activity_groups" in str(call[0][0])]
        self.assertTrue(len(update_args) > 0)
        updated_params = update_args[0][0][1]
        # In UPDATE query: (new_first, new_last, updated_count, json(samples), json(counts), peak_rate, is_spike, is_pinned, cand_id)
        is_pinned_param = updated_params[7]
        self.assertTrue(is_pinned_param, "Group should be elevated to is_pinned=True when receiving level 14 alert")


if __name__ == "__main__":
    unittest.main()
