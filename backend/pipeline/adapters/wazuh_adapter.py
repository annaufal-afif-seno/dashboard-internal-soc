"""
Wazuh Adapter Implementation (Mock & Live)
===========================================
Implements WazuhAdapterInterface for:
- Pulling alerts with cursor checkpoints
- Testing rules via wazuh-logtest
- Applying XML/CDB suppression per tenant with Git-based revision rollback
"""

import os
import glob
import json
import logging
import subprocess
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional, Tuple

from pipeline.adapters.base import WazuhAdapterInterface, AdapterStatus

logger = logging.getLogger(__name__)


class MockWazuhAdapter(WazuhAdapterInterface):
    """High-fidelity mock adapter for Wazuh testing and offline development."""

    def __init__(
        self,
        data_dir: Optional[str] = None,
        simulate_failure: bool = False,
        simulate_timeout: bool = False
    ):
        self.data_dir = data_dir or os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "data alert")
        self.simulate_failure = simulate_failure
        self.simulate_timeout = simulate_timeout
        self.deployed_rules: Dict[str, Dict[str, Any]] = {}
        self.revision_history: List[Dict[str, Any]] = []
        self._revision_counter = 1

    def health_check(self) -> AdapterStatus:
        if self.simulate_failure or self.simulate_timeout:
            return AdapterStatus(
                is_connected=False,
                component="WAZUH",
                mode="mock",
                endpoint="mock://wazuh-cluster-internal:55000",
                error_message="Simulated connection timeout" if self.simulate_timeout else "Simulated service unavailable"
            )
        return AdapterStatus(
            is_connected=True,
            component="WAZUH",
            mode="mock",
            endpoint="mock://wazuh-cluster-internal:55000"
        )

    def fetch_alerts(
        self,
        tenant_id: str = "DEFAULT",
        checkpoint_ts: Optional[datetime] = None,
        limit: int = 1000
    ) -> Tuple[List[Dict[str, Any]], Optional[datetime]]:
        """Simulate pulling alerts starting from checkpoint_ts."""
        if self.simulate_failure:
            raise ConnectionError("Wazuh Mock Adapter: Simulated cluster connection failure")
        if self.simulate_timeout:
            raise TimeoutError("Wazuh Mock Adapter: Simulated read timeout (15s exceeded)")

        json_files = sorted(glob.glob(os.path.join(self.data_dir, "**", "*.json*"), recursive=True))
        target_files = [f for f in json_files if "week" in f or "alerts" in f]
        
        alerts = []
        latest_ts = checkpoint_ts or datetime(2026, 7, 1, 0, 0, 0, tzinfo=timezone.utc)

        for fpath in target_files:
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        line_str = line.strip()
                        if not line_str:
                            continue
                        try:
                            record = json.loads(line_str)
                            # Parse timestamp
                            raw_ts = record.get("timestamp")
                            rec_dt = None
                            if raw_ts:
                                try:
                                    rec_dt = datetime.fromisoformat(raw_ts.replace("Z", "+00:00"))
                                except Exception:
                                    pass
                            
                            if rec_dt and checkpoint_ts and rec_dt <= checkpoint_ts:
                                continue  # Already processed in prior checkpoint
                                
                            alerts.append(record)
                            if rec_dt and (latest_ts is None or rec_dt > latest_ts):
                                latest_ts = rec_dt
                                
                            if len(alerts) >= limit:
                                return alerts, latest_ts
                        except json.JSONDecodeError:
                            continue
            except Exception as e:
                logger.warning(f"MockWazuhAdapter error reading {fpath}: {e}")

        return alerts, latest_ts

    def test_rule_logtest(self, log_sample: str, rule_xml: str) -> Dict[str, Any]:
        """Simulate wazuh-logtest output."""
        if self.simulate_failure:
            return {
                "valid": False,
                "output_level": 0,
                "rule_id": "0",
                "matched": False,
                "error": "wazuh-logtest daemon offline"
            }
        
        # Check basic XML structure
        if "<rule" not in rule_xml or "</rule>" not in rule_xml:
            return {
                "valid": False,
                "output_level": 0,
                "rule_id": "0",
                "matched": False,
                "error": "XML syntax error: Missing <rule> enclosure"
            }

        # Successful simulation
        return {
            "valid": True,
            "output_level": 0 if 'level="0"' in rule_xml else 5,
            "rule_id": "100999",
            "matched": True,
            "error": None
        }

    def deploy_rule_or_cdb(
        self,
        tenant_id: str,
        artifact_type: str,
        identifier: str,
        content: str
    ) -> Dict[str, Any]:
        """Record rule deployment with revision ID."""
        revision = f"rev_{self._revision_counter}"
        self._revision_counter += 1
        key = f"{tenant_id}_{artifact_type}_{identifier}"
        
        # Save snapshot for rollback
        prior = self.deployed_rules.get(key)
        self.revision_history.append({
            "key": key,
            "revision": revision,
            "prior_content": prior.get("content") if prior else None,
            "deployed_content": content,
            "deployed_at": datetime.now(timezone.utc).isoformat()
        })
        
        self.deployed_rules[key] = {
            "tenant_id": tenant_id,
            "artifact_type": artifact_type,
            "identifier": identifier,
            "content": content,
            "revision": revision,
            "active": True
        }
        return {"status": "SUCCESS", "revision": revision, "error": None}

    def rollback_rule_or_cdb(
        self,
        tenant_id: str,
        artifact_type: str,
        identifier: str,
        target_revision: Optional[str] = None
    ) -> bool:
        """Rollback rule to previous revision."""
        key = f"{tenant_id}_{artifact_type}_{identifier}"
        matching_revs = [h for h in self.revision_history if h["key"] == key]
        if not matching_revs:
            return False
            
        last_entry = matching_revs[-1]
        if last_entry["prior_content"] is not None:
            self.deployed_rules[key]["content"] = last_entry["prior_content"]
            self.deployed_rules[key]["revision"] = f"{last_entry['revision']}_reverted"
        else:
            if key in self.deployed_rules:
                del self.deployed_rules[key]
        return True


class LiveWazuhAdapter(WazuhAdapterInterface):
    """Production Live Adapter connecting to Wazuh Manager REST API and local wazuh-logtest."""

    def __init__(
        self,
        api_url: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        logtest_bin_path: Optional[str] = None,
        rules_git_dir: Optional[str] = None
    ):
        self.api_url = (api_url or os.getenv("WAZUH_API_URL", "https://localhost:55000")).rstrip("/")
        self.username = username or os.getenv("WAZUH_API_USER", "wazuh-wui")
        self.password = password or os.getenv("WAZUH_API_PASSWORD", "wazuh-wui")
        self.logtest_bin = logtest_bin_path or os.getenv("WAZUH_LOGTEST_BIN", "/var/ossec/bin/wazuh-logtest")
        self.rules_git_dir = rules_git_dir or os.getenv("WAZUH_RULES_DIR", "/var/ossec/etc/rules")
        self._jwt_token: Optional[str] = None
        self._token_expiry: Optional[datetime] = None

    def _get_auth_token(self) -> str:
        """Obtain JWT token from Wazuh API."""
        now = datetime.now(timezone.utc)
        if self._jwt_token and self._token_expiry and now < self._token_expiry:
            return self._jwt_token

        import requests
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
        resp = requests.post(
            f"{self.api_url}/security/user/authenticate",
            auth=(self.username, self.password),
            verify=False,
            timeout=10
        )
        if resp.status_code == 200:
            data = resp.json()
            self._jwt_token = data.get("data", {}).get("token")
            self._token_expiry = now + timedelta(minutes=14)
            return self._jwt_token
        raise ConnectionError(f"Failed to authenticate with Wazuh API: {resp.status_code} - {resp.text}")

    def health_check(self) -> AdapterStatus:
        try:
            token = self._get_auth_token()
            return AdapterStatus(
                is_connected=True,
                component="WAZUH",
                mode="live",
                endpoint=self.api_url
            )
        except Exception as e:
            return AdapterStatus(
                is_connected=False,
                component="WAZUH",
                mode="live",
                endpoint=self.api_url,
                error_message=str(e)
            )

    def fetch_alerts(
        self,
        tenant_id: str = "DEFAULT",
        checkpoint_ts: Optional[datetime] = None,
        limit: int = 1000
    ) -> Tuple[List[Dict[str, Any]], Optional[datetime]]:
        import requests
        token = self._get_auth_token()
        headers = {"Authorization": f"Bearer {token}"}
        
        params = {"limit": limit, "sort": "+timestamp"}
        if checkpoint_ts:
            params["q"] = f"timestamp>{checkpoint_ts.isoformat()}"

        resp = requests.get(
            f"{self.api_url}/alerts",
            headers=headers,
            params=params,
            verify=False,
            timeout=15
        )
        if resp.status_code == 200:
            data = resp.json().get("data", {}).get("affected_items", [])
            latest_ts = checkpoint_ts
            for alert in data:
                raw_ts = alert.get("timestamp")
                if raw_ts:
                    try:
                        dt = datetime.fromisoformat(raw_ts.replace("Z", "+00:00"))
                        if latest_ts is None or dt > latest_ts:
                            latest_ts = dt
                    except Exception:
                        pass
            return data, latest_ts
        raise RuntimeError(f"Wazuh fetch_alerts error: {resp.status_code} - {resp.text}")

    def test_rule_logtest(self, log_sample: str, rule_xml: str) -> Dict[str, Any]:
        """Execute local wazuh-logtest binary via subprocess."""
        if not os.path.exists(self.logtest_bin):
            return {
                "valid": False,
                "output_level": 0,
                "rule_id": "0",
                "matched": False,
                "error": f"wazuh-logtest binary not found at {self.logtest_bin}"
            }

        try:
            proc = subprocess.run(
                [self.logtest_bin, "-q"],
                input=log_sample.encode("utf-8"),
                capture_output=True,
                timeout=10
            )
            stdout = proc.stdout.decode("utf-8", errors="replace")
            stderr = proc.stderr.decode("utf-8", errors="replace")
            
            matched = "Phase 3: Completed filtering (rules)" in stdout
            level = 0
            if "Rule: " in stdout and "level " in stdout:
                try:
                    level = int(stdout.split("level ")[1].split(")")[0].strip())
                except Exception:
                    pass

            return {
                "valid": proc.returncode == 0,
                "output_level": level,
                "rule_id": "tested_rule",
                "matched": matched,
                "error": stderr if proc.returncode != 0 else None
            }
        except Exception as e:
            return {
                "valid": False,
                "output_level": 0,
                "rule_id": "0",
                "matched": False,
                "error": str(e)
            }

    def deploy_rule_or_cdb(
        self,
        tenant_id: str,
        artifact_type: str,
        identifier: str,
        content: str
    ) -> Dict[str, Any]:
        """Save XML rule or CDB list to filesystem with git commit tracking."""
        try:
            filename = f"tenant_{tenant_id}_{identifier}.xml" if artifact_type == "XML_RULE" else f"tenant_{tenant_id}_{identifier}.cdb"
            target_path = os.path.join(self.rules_git_dir, filename)
            os.makedirs(os.path.dirname(target_path), exist_ok=True)
            
            with open(target_path, "w", encoding="utf-8") as f:
                f.write(content)

            # Git commit for version tracking
            revision = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            try:
                subprocess.run(["git", "add", target_path], cwd=self.rules_git_dir, check=False)
                subprocess.run(["git", "commit", "-m", f"Deploy {artifact_type} {identifier} for {tenant_id} (rev {revision})"], cwd=self.rules_git_dir, check=False)
            except Exception:
                pass

            return {"status": "SUCCESS", "revision": revision, "error": None}
        except Exception as e:
            return {"status": "FAILED", "revision": "", "error": str(e)}

    def rollback_rule_or_cdb(
        self,
        tenant_id: str,
        artifact_type: str,
        identifier: str,
        target_revision: Optional[str] = None
    ) -> bool:
        try:
            filename = f"tenant_{tenant_id}_{identifier}.xml" if artifact_type == "XML_RULE" else f"tenant_{tenant_id}_{identifier}.cdb"
            target_path = os.path.join(self.rules_git_dir, filename)
            if os.path.exists(target_path):
                subprocess.run(["git", "checkout", "HEAD~1", "--", target_path], cwd=self.rules_git_dir, check=False)
                return True
        except Exception:
            pass
        return False
