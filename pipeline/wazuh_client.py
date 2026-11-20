"""
Wazuh Manager REST API Client (Port 55000)
===========================================
Handles direct native synchronization of:
- Wazuh Level="0" Drop Rules (XML) -> /var/ossec/etc/rules/{filename}
- Wazuh Constant Database (CDB) Lists -> /var/ossec/etc/lists/{filename}
- Rule validation & Manager service restart
"""

import os
import logging
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional

import requests
import urllib3
from dotenv import load_dotenv

load_dotenv()

# Disable SSL self-signed certificate warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger("wazuh.api_client")


class WazuhManagerAPI:
    def __init__(
        self,
        api_url: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        verify_ssl: Optional[bool] = None,
        enabled: Optional[bool] = None
    ):
        self.api_url = (api_url or os.getenv("WAZUH_API_URL", "https://127.0.0.1:55000")).rstrip("/")
        self.username = username or os.getenv("WAZUH_API_USER", "wazuh")
        self.password = (password or os.getenv("WAZUH_API_PASSWORD", "wazuh")).strip('"\'')
        
        if verify_ssl is not None:
            self.verify_ssl = verify_ssl
        else:
            self.verify_ssl = os.getenv("WAZUH_API_VERIFY_SSL", "false").lower() in ("true", "1", "yes")

        if enabled is not None:
            self.enabled = enabled
        else:
            self.enabled = os.getenv("WAZUH_API_ENABLED", "true").lower() in ("true", "1", "yes")

        self._token: Optional[str] = None
        self._token_expiry: Optional[datetime] = None

    def authenticate(self) -> str:
        """Obtain a JWT token from Wazuh API endpoint POST /security/user/authenticate."""
        now = datetime.now(timezone.utc)
        if self._token and self._token_expiry and now < self._token_expiry:
            return self._token

        url = f"{self.api_url}/security/user/authenticate"
        try:
            resp = requests.post(
                url,
                auth=(self.username, self.password),
                verify=self.verify_ssl,
                timeout=10
            )
            if resp.status_code == 200:
                data = resp.json()
                self._token = data.get("data", {}).get("token")
                self._token_expiry = now + timedelta(minutes=14)
                logger.info("Successfully authenticated with Wazuh API at %s", self.api_url)
                return self._token
            else:
                msg = f"Wazuh API auth failed ({resp.status_code}): {resp.text}"
                logger.error(msg)
                raise ConnectionError(msg)
        except requests.exceptions.RequestException as e:
            logger.error("Wazuh API connection error to %s: %s", url, e)
            raise ConnectionError(f"Cannot reach Wazuh API at {self.api_url}: {e}")

    def _get_headers(self, content_type: str = "application/json") -> Dict[str, str]:
        token = self.authenticate()
        return {
            "Authorization": f"Bearer {token}",
            "Content-Type": content_type
        }

    def deploy_xml_rule(self, filename: str, xml_content: str) -> Dict[str, Any]:
        """
        Upload custom XML suppression rule file via PUT /rules/files/{filename}.
        Files are placed in /var/ossec/etc/rules/{filename} on the Wazuh Manager.
        """
        if not filename.endswith(".xml"):
            filename = f"{filename}.xml"

        url = f"{self.api_url}/rules/files/{filename}?overwrite=true"
        headers = self._get_headers(content_type="application/octet-stream")
        
        try:
            resp = requests.put(
                url,
                headers=headers,
                data=xml_content.encode("utf-8"),
                verify=self.verify_ssl,
                timeout=15
            )
            if resp.status_code == 401:
                # Token expired, force renewal
                self._token = None
                headers = self._get_headers(content_type="application/octet-stream")
                resp = requests.put(
                    url,
                    headers=headers,
                    data=xml_content.encode("utf-8"),
                    verify=self.verify_ssl,
                    timeout=15
                )

            if resp.status_code in (200, 201):
                logger.info("Successfully uploaded XML rule %s to Wazuh Manager", filename)
                return {"status": "SUCCESS", "filename": filename, "data": resp.json()}
            else:
                logger.warning("Wazuh rule upload failed (%s): %s", resp.status_code, resp.text)
                return {"status": "FAILED", "filename": filename, "error": resp.text, "code": resp.status_code}
        except Exception as e:
            logger.error("Error uploading XML rule %s to Wazuh: %s", filename, e)
            return {"status": "ERROR", "filename": filename, "error": str(e)}

    def deploy_cdb_list(self, filename: str, cdb_content: str) -> Dict[str, Any]:
        """
        Upload CDB List file via PUT /lists/files/{filename}.
        Files are placed in /var/ossec/etc/lists/{filename} on the Wazuh Manager.
        """
        # Clean CDB content (Wazuh 4.x expects strictly key:value pairs without raw comment lines)
        valid_lines = [line.strip() for line in cdb_content.splitlines() if line.strip() and not line.strip().startswith("#") and ":" in line]
        payload_data = ("\n".join(valid_lines) + "\n" if valid_lines else cdb_content).encode("utf-8")

        url = f"{self.api_url}/lists/files/{filename}?overwrite=true"
        headers = self._get_headers(content_type="application/octet-stream")

        try:
            resp = requests.put(
                url,
                headers=headers,
                data=payload_data,
                verify=self.verify_ssl,
                timeout=15
            )
            if resp.status_code == 401:
                self._token = None
                headers = self._get_headers(content_type="application/octet-stream")
                resp = requests.put(
                    url,
                    headers=headers,
                    data=payload_data,
                    verify=self.verify_ssl,
                    timeout=15
                )

            if resp.status_code in (200, 201):
                logger.info("Successfully uploaded CDB List %s to Wazuh Manager", filename)
                return {"status": "SUCCESS", "filename": filename, "data": resp.json()}
            else:
                logger.warning("Wazuh CDB upload failed (%s): %s", resp.status_code, resp.text)
                return {"status": "FAILED", "filename": filename, "error": resp.text, "code": resp.status_code}
        except Exception as e:
            logger.error("Error uploading CDB list %s to Wazuh: %s", filename, e)
            return {"status": "ERROR", "filename": filename, "error": str(e)}

    def validate_rules(self) -> Dict[str, Any]:
        """Validate Wazuh Manager configuration via GET /manager/configuration/validation."""
        url = f"{self.api_url}/manager/configuration/validation"
        headers = self._get_headers()
        try:
            resp = requests.get(url, headers=headers, verify=self.verify_ssl, timeout=15)
            if resp.status_code == 200:
                return {"valid": True, "data": resp.json()}
            return {"valid": False, "error": resp.text}
        except Exception as e:
            return {"valid": False, "error": str(e)}

    def restart_manager(self) -> Dict[str, Any]:
        """Restart Wazuh Manager Analysisd engine via PUT /manager/restart."""
        url = f"{self.api_url}/manager/restart"
        headers = self._get_headers()
        try:
            resp = requests.put(url, headers=headers, verify=self.verify_ssl, timeout=20)
            if resp.status_code in (200, 202):
                logger.info("Wazuh Manager restart command issued successfully")
                return {"status": "SUCCESS", "data": resp.json()}
            return {"status": "FAILED", "error": resp.text}
        except Exception as e:
            logger.error("Error issuing Wazuh restart: %s", e)
            return {"status": "ERROR", "error": str(e)}

    def sync_tenant_policy(
        self,
        tenant_id: str,
        xml_content: Optional[str] = None,
        cdb_content: Optional[str] = None,
        restart: bool = True
    ) -> Dict[str, Any]:
        """
        Orchestrate deployment of tenant suppression policies directly to Wazuh Manager.
        """
        if not self.enabled:
            logger.info("Wazuh API sync is disabled via WAZUH_API_ENABLED=false")
            return {"status": "SKIPPED", "message": "Wazuh API sync disabled in configuration."}

        clean_tenant = tenant_id.lower().replace(" ", "_")
        results = {
            "status": "SUCCESS",
            "tenant_id": tenant_id,
            "actions": [],
            "errors": []
        }

        try:
            # 1. Deploy CDB List if present
            if cdb_content and cdb_content.strip():
                cdb_filename = f"asoc-whitelist-{clean_tenant}"
                cdb_res = self.deploy_cdb_list(cdb_filename, cdb_content)
                results["actions"].append({"type": "CDB_LIST", "filename": cdb_filename, "result": cdb_res})
                if cdb_res.get("status") != "SUCCESS":
                    results["errors"].append(f"CDB upload: {cdb_res.get('error')}")

            # 2. Deploy XML Rule if present
            if xml_content and xml_content.strip():
                xml_filename = f"asoc-suppression-{clean_tenant}.xml"
                xml_res = self.deploy_xml_rule(xml_filename, xml_content)
                results["actions"].append({"type": "XML_RULE", "filename": xml_filename, "result": xml_res})
                if xml_res.get("status") != "SUCCESS":
                    results["errors"].append(f"XML upload: {xml_res.get('error')}")

            # 3. Restart manager if any action was executed successfully
            if restart and results["actions"] and not results["errors"]:
                restart_res = self.restart_manager()
                results["actions"].append({"type": "RESTART_MANAGER", "result": restart_res})
                if restart_res.get("status") != "SUCCESS":
                    results["errors"].append(f"Restart: {restart_res.get('error')}")

            if results["errors"]:
                results["status"] = "PARTIAL" if len(results["errors"]) < len(results["actions"]) else "FAILED"

            return results
        except Exception as e:
            logger.error("Wazuh sync policy exception: %s", e)
            return {
                "status": "ERROR",
                "tenant_id": tenant_id,
                "error": str(e)
            }


# Singleton instance
wazuh_api_client = WazuhManagerAPI()
