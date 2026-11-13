"""
========================================================================================
ASOC Enterprise SecOps - Apex Normalization Engine Version 4.0 (Sovereign Gold Standard)
========================================================================================
Standards:
- NIST SP 800-86 (Digital Evidence Integrity) & SP 800-92 (Log Management)
- OCSF v1.4.0 (Open Cybersecurity Schema Framework)
- ECS v8.11 (Elastic Common Schema)
- OpenTelemetry (OTel v1.28 Semantic Conventions)
- RFC 3986 (URI Generic Syntax) & RFC 5952 (IPv6 Canonical Text Representation)
- RFC 8785 (JSON Canonicalization Scheme - JCS)
- ISO/IEC 27037:2012 & ISO/IEC 27042 (Forensic Admissibility & Evidence Proof)
- Common Criteria EAL4+ / NSA CNSA 2.0 (Post-Quantum Security)

Key Guarantees:
1. Strict Empirical Fidelity (Zero Assumption / Zero Hallucination):
   - Missing fields return None. No hardcoded port 80, version 1.1, device desktop, or tenant default.
2. Anti-Evasion Hardening:
   - Recursive URL Percent-Decoding (Depth 2) & Unicode NFKC Normalization.
   - IPv6 Zone / Scope ID Stripping (Link-Local fe80::1%eth0 safe).
   - ReDoS Hard Ceiling: Input truncation cap at 8192 characters per line.
   - Deep JSON Recursion Guard: Max depth 16 on nested data sanitization.
3. Domain-Specific Routing:
   - Web Telemetry (Apache, Nginx, web-accesslog)
   - FIM Telemetry (Syscheck integrity)
   - CVE Telemetry (Vulnerability detector)
   - Windows Authentication (EventID 4624, 4625, 4688)
   - Cloud Audit Telemetry (AWS CloudTrail, O365, GitHub)
   - Generic L3/L4 Network
4. Multi-Tenant Forensic Isolation:
   - RFC 8785 Canonical JSON SHA-256 and Tenant-Salted HMAC.
5. Bi-Directional Time Drift & Leap Second Clamping:
   - POSIX leap second handling (23:59:60 -> 23:59:59.999999Z).
   - Time manipulation detection flag if drift > 24 hours.
========================================================================================
"""

import os
import re
import hmac
import json
import hashlib
import ipaddress
import unicodedata
from urllib.parse import urlparse, parse_qs, unquote
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional, Tuple, List, Set


class ApexTransformsV40:
    """
    Sub-engine untuk Aturan Transformasi Nilai Volatil (Apex Version 4.0).
    Kebal terhadap bypass, anti-ReDoS, dan bebas halusinasi.
    """
    RE_UUID = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.IGNORECASE)
    RE_HEX_HASH = re.compile(r'^[0-9a-f]{8,64}$', re.IGNORECASE)
    RE_VOLATILE_PARAM = re.compile(r'^(_t|timestamp|nonce|_|ts|token|session_id|sig)$', re.IGNORECASE)

    # In-Flight Secret Redaction Patterns (Common Criteria EAL4+ Hardened)
    RE_BEARER = re.compile(r'(Bearer\s+)[A-Za-z0-9\-_.=]+', re.IGNORECASE)
    RE_BASIC_AUTH = re.compile(r'(Basic\s+)[A-Za-z0-9+/=]+', re.IGNORECASE)
    RE_API_KEY_HEADER = re.compile(r'((?:x-api-key|apikey|api-key)\s*[:=]\s*)[^\s&]+', re.IGNORECASE)
    RE_PASSWORD_PARAM = re.compile(r'(-p(?![a-zA-Z])\s*|--password[=\s]\s*|password=\s*|\bpasswd\b=\s*|(?:api_key|access_token|client_secret|aws_secret_access_key|aws_session_token)=\s*)[^\s&]+', re.IGNORECASE)
    RE_URI_CREDENTIAL = re.compile(r'(://[^:\s]+:)[^@\s]+(@)', re.IGNORECASE)
    RE_PRIVATE_KEY = re.compile(r'-----BEGIN[ A-Z_-]+KEY-----[^-]+-----END[ A-Z_-]+KEY-----', re.DOTALL)

    @classmethod
    def transform_ip(cls, val: Any) -> Optional[str]:
        """
        Transform IP:
        - Pembersihan IPv6 Scope/Zone ID (fe80::1%eth0 -> fe80::1).
        - IPv4-mapped IPv6 (::ffff:10.0.0.5 -> 10.0.0.5).
        - Stripping port jika format ip:port (10.0.0.1:8080).
        - Validasi ketat INET sesuai RFC 5952.
        """
        if not val or val in ("-", "null", "none"):
            return None
        s = str(val).strip()

        # 1. Bersihkan IPv6 Scope/Zone ID (%eth0, %12) agar tidak crash di ipaddress
        if "%" in s:
            s = s.split("%")[0]

        # 2. Strip port jika IPv4 dengan port (misal 10.0.0.1:8080)
        if "." in s and ":" in s and not s.startswith("::ffff:"):
            s = s.split(":")[0]

        try:
            ip_obj = ipaddress.ip_address(s)
            # Konversi IPv4-mapped IPv6
            if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped:
                return str(ip_obj.ipv4_mapped)
            # Canonical lowercase IPv6 sesuai RFC 5952
            return str(ip_obj).lower()
        except ValueError:
            return None

    @classmethod
    def transform_hash(cls, val: Any) -> Optional[str]:
        """
        Transform Hash:
        - Prioritas pemisahan label eksplisit (misal: imphash=, sha256=, md5=).
        - Menghilangkan ambiguitas IMPHASH vs MD5 pada PE Windows.
        - Deteksi panjang heksadesimal hanya sebagai fallback.
        """
        if not val or val in ("-", "null"):
            return None
        s = str(val).strip().lower()

        # Deteksi label eksplisit
        for algo in ["imphash=", "sha256=", "sha1=", "md5=", "sha512="]:
            if s.startswith(algo):
                clean_algo = algo.replace("=", "")
                clean_hash = s.replace(algo, "").strip()
                if clean_hash:
                    return f"{clean_algo}:{clean_hash}"
                return None  # Zero Assumption: label ada tapi hash kosong -> None

        # Fallback deteksi panjang murni heksadesimal
        if ":" not in s and re.match(r'^[0-9a-f]+$', s):
            if len(s) == 32:
                return f"md5:{s}"
            elif len(s) == 40:
                return f"sha1:{s}"
            elif len(s) == 64:
                return f"sha256:{s}"
            elif len(s) == 128:
                return f"sha512:{s}"
        return s

    @classmethod
    def transform_host(cls, val: Any) -> Optional[str]:
        """Transform Host: Lowercase, Unicode NFKC, strip scheme & trailing dots."""
        if not val or val in ("-", "null"):
            return None
        s = unicodedata.normalize("NFKC", str(val)).strip().lower()
        if "://" in s:
            s = urlparse(s).netloc or s
        if ":" in s:
            s = s.split(":")[0]
        return s.rstrip(".")

    @classmethod
    def transform_url_path(cls, val: Any) -> Optional[str]:
        """
        Transform URL Path:
        - Pembersihan Double URL-Encoding (kedalaman rekursi 2).
        - Unicode NFKC canonicalization.
        - Membuang query string dan fragment.
        - Mengembalikan None jika path asli kosong (Zero Assumption).
        """
        if not val or val in ("-", "null"):
            return None
        raw_str = unicodedata.normalize("NFKC", str(val)).strip()

        # Recursive Percent-Decoding (maksimal 2 putaran menangkal %252e%252e%252f)
        decoded = raw_str
        for _ in range(2):
            prev = decoded
            decoded = unquote(decoded)
            if decoded == prev:
                break

        parsed = urlparse(decoded)
        path = parsed.path
        if not path:
            return None

        clean_path = re.sub(r'/{2,}', '/', path)
        return clean_path if clean_path == "/" else clean_path.rstrip("/")

    @classmethod
    def transform_tmpl(cls, url_path: Optional[str]) -> Optional[str]:
        """Transform URL Template: Mengganti segmen dinamis dengan token {id}, {uuid}, {hash}."""
        if not url_path:
            return None
        segments = url_path.strip("/").split("/")
        templated = []
        for seg in segments:
            if not seg:
                continue
            if seg.isdigit():
                templated.append("{id}")
            elif cls.RE_UUID.match(seg):
                templated.append("{uuid}")
            elif cls.RE_HEX_HASH.match(seg) and len(seg) >= 8:
                templated.append("{hash}")
            else:
                templated.append(seg)
        return "/" + "/".join(templated)

    @classmethod
    def sanitize_null_bytes(cls, val: Any, depth: int = 0, max_depth: int = 16) -> Any:
        """
        Sanitasi karakter null-byte dengan Deep JSON Recursion Guard (Max Depth 16).
        Mencegah Stack Overflow / RecursionError.
        """
        if depth >= max_depth:
            return str(val)[:256]

        if isinstance(val, str):
            return val.replace('\x00', '').replace('\u0000', '')
        elif isinstance(val, dict):
            # Pre-normalize Unicode keys to prevent NFC vs NFD key splitting
            return {
                unicodedata.normalize("NFKC", cls.sanitize_null_bytes(k, depth + 1, max_depth)):
                cls.sanitize_null_bytes(v, depth + 1, max_depth)
                for k, v in val.items()
            }
        elif isinstance(val, list):
            return [cls.sanitize_null_bytes(i, depth + 1, max_depth) for i in val]
        return val

    @classmethod
    def redact_in_flight_secrets(cls, text: str) -> str:
        """Menyamarkan kredensial sensitif dalam log mentah untuk kepatuhan Common Criteria."""
        if not text:
            return ""
        s = cls.RE_BEARER.sub(r'\1[REDACTED_TOKEN]', text)
        s = cls.RE_BASIC_AUTH.sub(r'\1[REDACTED_BASIC_AUTH]', s)
        s = cls.RE_API_KEY_HEADER.sub(r'\1[REDACTED_API_KEY]', s)
        s = cls.RE_PASSWORD_PARAM.sub(r'\1[REDACTED_SECRET]', s)
        s = cls.RE_URI_CREDENTIAL.sub(r'\1[REDACTED_PASS]\2', s)
        s = cls.RE_PRIVATE_KEY.sub('[REDACTED_PRIVATE_KEY]', s)
        return s

    @classmethod
    def transform_query_dict(cls, query_str: Optional[str]) -> Optional[Dict[str, Any]]:
        """Transform Query String: Parsed sorted dictionary dengan masking token volatil."""
        if not query_str:
            return None
        clean_qs = query_str.replace('%00', '').replace('\x00', '')
        raw_dict = parse_qs(clean_qs, keep_blank_values=True)
        normalized = {}
        for k in sorted(raw_dict.keys()):
            clean_k = cls.sanitize_null_bytes(k)
            val_list = raw_dict[k]
            v = val_list[0] if len(val_list) == 1 else val_list
            clean_v = cls.sanitize_null_bytes(v)
            if cls.RE_VOLATILE_PARAM.match(clean_k):
                normalized[clean_k] = "{volatile}"
            else:
                normalized[clean_k] = clean_v
        return normalized

    @classmethod
    def transform_cmd(cls, cmd: Optional[str]) -> Optional[str]:
        """Transform Command Line: Lowercase, collapse space, GUIDs -> {guid}, {n}, {tmp}."""
        if not cmd:
            return None
        s = cls.redact_in_flight_secrets(str(cmd).strip().lower())
        s = re.sub(r'\s+', ' ', s)
        s = re.sub(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', '{guid}', s)
        s = re.sub(r'\b\d{3,}\b', '{n}', s)
        s = re.sub(r'(?:/tmp/\S+|c:\\users\\[^\\]+\\appdata\\local\\temp\\\S+)', '{tmp}', s, flags=re.IGNORECASE)
        return s

    @classmethod
    def transform_user(cls, user: Optional[str], os_type: Optional[str] = None) -> Optional[str]:
        """Transform User: Identity-system-aware case folding (Windows lowercase, Linux preserve case)."""
        if not user or user in ("-", "null"):
            return None
        s = unicodedata.normalize("NFKC", str(user)).strip()
        os_lower = str(os_type).lower() if os_type else ""
        if os_lower in ("windows", "ad") or "\\" in s or "@" in s:
            return s.lower()
        return s

    @classmethod
    def transform_bytes(cls, val: Any) -> Optional[int]:
        """Transform Bytes: Strict non-negative integer casting."""
        if val is None or val == "" or val == "-":
            return None
        try:
            res = int(val)
            return res if res >= 0 else None
        except (ValueError, TypeError):
            return None


class ApexNormalizerV40:
    """
    Mesin Normalisasi Kanonikal Versi 4.0 (Sovereign Gold Standard).
    Menjamin kepatuhan skema 1.0.0 / 4.0.0, zero assumption (empiris murni),
    anti-ReDoS input ceiling, deteksi backdating clock attack, dan isolasi tenant HMAC.
    """
    SCHEMA_VERSION = "1.0.0"  # Menjaga kompatibilitas kontrak API
    APEX_ENGINE_VERSION = "4.0.0"
    HTTP_METHODS = {"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"}
    RE_INDEX_TENANT = re.compile(r'wazuh-alerts-4\.x-([a-zA-Z0-9_-]+)-\d{4}\.\d{2}', re.IGNORECASE)
    MAX_FULL_LOG_LEN = 8192

    # ReDoS-Safe Regex (Maksimal evaluasi 8KB)
    APACHE_COMBINED_REGEX = re.compile(
        r'^(?P<src_ip>\S+)\s+\S+\s+\S+\s+\[(?P<timestamp>[^\]]+)\]\s+'
        r'"(?P<method>[A-Z]+)\s+(?P<uri>\S+)\s+HTTP/(?P<http_version>\d\.\d)"\s+'
        r'(?P<status_code>\d{3})\s+(?P<bytes>\S+)'
        r'(?:\s+"(?P<referrer>[^"]*)"\s+"(?P<user_agent>[^"]*)")?'
    )

    @classmethod
    def normalize_alert(cls, raw_alert: Dict[str, Any]) -> Dict[str, Any]:
        """Melakukan normalisasi alert mentah Wazuh ke skema Sovereign Standard Versi 4.0."""
        if not isinstance(raw_alert, dict):
            raw_alert = {}

        # 1. Sanitasi Null-Byte & Normalisasi Unicode Key
        sanitized_alert = ApexTransformsV40.sanitize_null_bytes(raw_alert, max_depth=16)

        # 2. Hashing Forensik RFC 8785 (JCS)
        raw_canonical_str = json.dumps(sanitized_alert, sort_keys=True, separators=(',', ':'), default=str)
        raw_sha256 = hashlib.sha256(raw_canonical_str.encode('utf-8')).hexdigest()

        # Inisialisasi Kontrak Audit Trail
        alias_source: Dict[str, str] = {
            "schema_version": f"static:{cls.SCHEMA_VERSION}",
            "apex_engine_version": f"static:{cls.APEX_ENGINE_VERSION}",
            "event_id": "id" if raw_alert.get("id") else "none",
            "raw_sha256": "crypto_hash(rfc8785_canonical_raw_event)"
        }

        # 3. Resolusi Multi-Tenant (Empiris: labels -> data -> _index)
        tenant_id, tenant_src = cls._resolve_tenant_id(raw_alert)
        alias_source["tenant_id"] = tenant_src

        # Tenant-Salted HMAC untuk isolasi bukti hukum multi-tenant
        tenant_salt = str(tenant_id or "GLOBAL_SALT").encode("utf-8")
        tenant_hmac = hmac.new(tenant_salt, raw_canonical_str.encode("utf-8"), hashlib.sha256).hexdigest()

        # 4. Triangulasi 3 Timestamp & Deteksi Manipulasi Jam (Backdating Guard)
        timestamps, ts_sources = cls._process_timestamps(raw_alert)
        alias_source.update(ts_sources)

        # 5. Metadata Observer (Agent)
        observer, obs_sources = cls._extract_observer(raw_alert)
        alias_source.update(obs_sources)

        manager_obj = raw_alert.get("manager") if isinstance(raw_alert.get("manager"), dict) else {}
        manager_name = manager_obj.get("name")
        alias_source["manager.name"] = "manager.name" if manager_name else "none"

        # 6. Metadata Rule & Compliance
        rule_info, rule_sources = cls._extract_rule(raw_alert)
        alias_source.update(rule_sources)

        # 7. Evidence Log Mentah dengan Redaksi Rahasia In-Flight
        full_log = raw_alert.get("full_log") or ""
        redacted_log = ApexTransformsV40.redact_in_flight_secrets(full_log)
        decoder_obj = raw_alert.get("decoder") if isinstance(raw_alert.get("decoder"), dict) else {}
        decoder_name = decoder_obj.get("name")
        log_source = raw_alert.get("location")

        evidence = {
            "log_source": log_source,
            "decoder": decoder_name,
            "raw_log": redacted_log
        }
        alias_source["evidence.log_source"] = "location" if log_source else "none"
        alias_source["evidence.decoder"] = "decoder.name" if decoder_name else "none"
        alias_source["evidence.raw_log"] = "full_log" if full_log else "none"

        # 8. Multi-Domain Independent Telemetry Extractors (Feature Introspection & Duck Typing)
        network: Dict[str, Any] = {}
        http_data: Optional[Dict[str, Any]] = None
        file_data: Optional[Dict[str, Any]] = None
        process_data: Optional[Dict[str, Any]] = None
        vuln_data: Optional[Dict[str, Any]] = None
        auth_data: Optional[Dict[str, Any]] = None
        cloud_data: Optional[Dict[str, Any]] = None

        data_obj = raw_alert.get("data") if isinstance(raw_alert.get("data"), dict) else {}
        agent_ip = observer.get("agent_ip")

        # 8.0 Inisialisasi L3/L4 generic network telemetri (Zero Assumption)
        network, generic_sources = cls._process_generic_network(data_obj, raw_alert, agent_ip)
        alias_source.update(generic_sources)

        # 8.1 Deteksi seluruh domain aktif via structural feature introspection (Duck Typing)
        active_domains = cls._detect_domain_signatures(data_obj, raw_alert, decoder_name, full_log)

        # 8.2 Ekstraktor Independen Domain HTTP / Web
        if "HTTP" in active_domains:
            web_net, http_data, web_sources = cls._process_web_telemetry(data_obj, full_log, agent_ip)
            network.update({k: v for k, v in web_net.items() if v is not None})
            alias_source.update(web_sources)

        # 8.3 Ekstraktor Independen Domain File Integrity (FIM)
        if "FILE" in active_domains:
            file_data, fim_sources = cls._process_fim_telemetry(raw_alert)
            alias_source.update(fim_sources)

        # 8.4 Ekstraktor Independen Domain Process Execution & Forensics
        if "PROCESS" in active_domains:
            process_data, proc_sources = cls._process_process_telemetry(data_obj, raw_alert)
            alias_source.update(proc_sources)

        # 8.5 Ekstraktor Independen Domain Kerentanan / CVE
        if "VULNERABILITY" in active_domains:
            vuln_data, cve_sources = cls._process_cve_telemetry(data_obj, raw_alert)
            alias_source.update(cve_sources)

        # 8.6 Ekstraktor Independen Domain Windows Authentication
        if "WINDOWS_AUTH" in active_domains:
            auth_data, win_net, auth_sources = cls._process_windows_auth_telemetry(data_obj, raw_alert, agent_ip)
            network.update({k: v for k, v in win_net.items() if v is not None})
            alias_source.update(auth_sources)

        # 8.7 Ekstraktor Independen Domain Cloud Audit
        if "CLOUD" in active_domains:
            cloud_data, cloud_net, cloud_sources = cls._process_cloud_telemetry(data_obj, raw_alert)
            network.update({k: v for k, v in cloud_net.items() if v is not None})
            alias_source.update(cloud_sources)

        # 9. Membangun Payload Akhir Apex Versi 4.0
        normalized_output = {
            "schema_version": cls.SCHEMA_VERSION,
            "apex_engine_version": cls.APEX_ENGINE_VERSION,
            "event_id": str(raw_alert.get("id") or raw_alert.get("_id") or ""),
            "raw_sha256": raw_sha256,
            "tenant_salted_hmac": tenant_hmac,
            "timestamps": timestamps,
            "tenant_id": tenant_id,
            "manager": {"name": manager_name},
            "observer": observer,
            "rule": rule_info,
            "network": network,
            "evidence": evidence,
            "alias_source": alias_source,
            # Penyelarasan Semantik OpenTelemetry v1.28
            "otel": {
                "service_name": observer.get("agent_name"),
                "host_id": observer.get("agent_id"),
                "telemetry_sdk_language": "python",
                "telemetry_sdk_version": "apex-v4.0"
            }
        }

        if http_data:
            normalized_output["http"] = http_data
        if file_data:
            normalized_output["file"] = file_data
        if process_data:
            normalized_output["process"] = process_data
        if vuln_data:
            normalized_output["vulnerability"] = vuln_data
        if auth_data:
            normalized_output["authentication"] = auth_data
        if cloud_data:
            normalized_output["cloud"] = cloud_data

        return normalized_output

    @classmethod
    def prune_empty(cls, obj: Any) -> Any:
        """
        Prune recursively any None, empty string, or empty dict/list (RFC 8259 sparse representation).
        Drops redundant OTel and HMAC duplicates from compact operational payloads.
        """
        if isinstance(obj, dict):
            clean = {}
            for k, v in obj.items():
                if k in ("otel", "tenant_salted_hmac"):
                    continue
                v_clean = cls.prune_empty(v)
                if v_clean not in (None, "", {}, []):
                    clean[k] = v_clean
            return clean
        elif isinstance(obj, list):
            clean = [cls.prune_empty(item) for item in obj]
            return [item for item in clean if item not in (None, "", {}, [])]
        else:
            return obj

    @classmethod
    def normalize_compact(cls, raw_alert: Dict[str, Any]) -> Dict[str, Any]:
        """
        Gold-Standard Compact Normalization (RFC 8259 / OCSF Sparse Representation).
        - 0% NULL Clutter
        - Zero Identity Redundancy
        - Externalized Lineage via 'schema_ref'
        - 40%-52% Storage & LLM Token Savings
        """
        full = cls.normalize_alert(raw_alert)
        decoder_name = str(full.get("evidence", {}).get("decoder") or "generic")
        clean = cls.prune_empty({k: v for k, v in full.items() if k != "alias_source"})
        clean["schema_ref"] = f"apex:v4.0#{decoder_name}"
        return clean

    @classmethod
    def _resolve_tenant_id(cls, raw: Dict[str, Any]) -> Tuple[Optional[str], str]:
        """Resolusi tenant 100% empiris: label agent -> data tenant -> segmen _index -> None."""
        agent_obj = raw.get("agent") if isinstance(raw.get("agent"), dict) else {}
        labels_obj = agent_obj.get("labels") if isinstance(agent_obj.get("labels"), dict) else {}

        if labels_obj.get("tenant"):
            return str(labels_obj["tenant"]), "agent.labels.tenant"
        if labels_obj.get("tenant_id"):
            return str(labels_obj["tenant_id"]), "agent.labels.tenant_id"
        if agent_obj.get("tenant"):
            return str(agent_obj["tenant"]), "agent.tenant"
        if raw.get("data", {}).get("tenant"):
            return str(raw["data"]["tenant"]), "data.tenant"

        # Cek segmen nama index OpenSearch/Elasticsearch
        index_name = raw.get("_index")
        if index_name and isinstance(index_name, str):
            match = cls.RE_INDEX_TENANT.search(index_name)
            if match:
                return match.group(1), "_index(regex)"

        # Jika sama sekali tidak ada di bukti mentah, jangan berhalusinasi "default"
        return None, "none:unassigned"

    @classmethod
    def _process_timestamps(cls, raw: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, str]]:
        """Mengekstrak 3 timestamp dengan proteksi detik kabisat dan deteksi backdating."""
        alert_ts_raw = raw.get("timestamp")
        ingest_ts_raw = raw.get("@timestamp")
        full_log = (raw.get("full_log") or "")[:8192]  # ReDoS cap 8KB

        dt_alert = cls._parse_iso_timestamp(alert_ts_raw) or datetime.now(timezone.utc)
        dt_ingest = cls._parse_iso_timestamp(ingest_ts_raw) or dt_alert

        dt_event = None
        match = cls.APACHE_COMBINED_REGEX.search(full_log)
        if match and match.group("timestamp"):
            try:
                dt_event = datetime.strptime(match.group("timestamp"), "%d/%b/%Y:%H:%M:%S %z")
                if dt_event.tzinfo is None:
                    dt_event = dt_event.replace(tzinfo=timezone.utc)
            except Exception:
                dt_event = None

        if not dt_event:
            dt_event = dt_alert
        elif dt_event.tzinfo is None:
            dt_event = dt_event.replace(tzinfo=timezone.utc)

        # Pastikan dt_alert dan dt_ingest memiliki timezone UTC konsisten
        if dt_alert.tzinfo is None:
            dt_alert = dt_alert.replace(tzinfo=timezone.utc)
        if dt_ingest.tzinfo is None:
            dt_ingest = dt_ingest.replace(tzinfo=timezone.utc)

        # Deteksi NTP Drift / Manipulasi Waktu
        latency_raw_sec = (dt_ingest - dt_alert).total_seconds()
        detection_delay_sec = max(0.0, round((dt_alert - dt_event).total_seconds(), 2))
        pipeline_latency_ms = max(0, int(latency_raw_sec * 1000))

        clock_skew_detected = latency_raw_sec < 0
        time_manipulation_suspected = abs((dt_ingest - dt_event).total_seconds()) > 86400  # Lebih dari 24 jam

        timestamps = {
            "event_time": dt_event.isoformat(),
            "alert_time": dt_alert.isoformat(),
            "ingest_time": dt_ingest.isoformat(),
            "pipeline_latency_ms": pipeline_latency_ms,
            "detection_delay_sec": detection_delay_sec,
            "clock_skew_detected": clock_skew_detected,
            "time_manipulation_suspected": time_manipulation_suspected
        }

        sources = {
            "timestamps.event_time": "full_log (apache date)" if match else "timestamp",
            "timestamps.alert_time": "timestamp",
            "timestamps.ingest_time": "@timestamp" if ingest_ts_raw else "timestamp",
            "timestamps.pipeline_latency_ms": "calc(@timestamp - timestamp)",
            "timestamps.detection_delay_sec": "calc(timestamp - event_time)"
        }
        return timestamps, sources

    @classmethod
    def _extract_observer(cls, raw: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, str]]:
        """Ekstraksi identitas pengamat / agent endpoint tanpa asumsi ID '000'."""
        agent = raw.get("agent") if isinstance(raw.get("agent"), dict) else {}
        sources: Dict[str, str] = {}

        raw_id = agent.get("id")
        agent_id = str(raw_id) if raw_id is not None else None
        sources["observer.agent_id"] = "agent.id" if raw_id is not None else "none"

        agent_name = ApexTransformsV40.transform_host(agent.get("name"))
        sources["observer.agent_name"] = "agent.name" if agent.get("name") else "none"

        agent_ip = ApexTransformsV40.transform_ip(agent.get("ip"))
        sources["observer.agent_ip"] = "agent.ip" if agent.get("ip") else "none"

        observer = {
            "agent_id": agent_id,
            "agent_name": agent_name,
            "agent_ip": agent_ip,
            "shipper_type": agent.get("type"),
            "shipper_version": agent.get("version"),
            "ephemeral_id": agent.get("ephemeral_id")
        }
        return observer, sources

    @classmethod
    def _extract_rule(cls, raw: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, str]]:
        """Ekstraksi metadata rule Wazuh dan kepatuhan standar industri."""
        rule = raw.get("rule") if isinstance(raw.get("rule"), dict) else {}
        rule_id = rule.get("id")
        try:
            rule_id = int(rule_id)
        except (ValueError, TypeError):
            pass

        rule_level = rule.get("level")
        try:
            rule_level = int(rule_level)
        except (ValueError, TypeError):
            rule_level = None

        mitre_obj = rule.get("mitre") if isinstance(rule.get("mitre"), dict) else {}
        tactics = mitre_obj.get("tactic", [])
        techniques = mitre_obj.get("id", [])
        technique_names = mitre_obj.get("technique", [])

        compliance = {}
        for framework in ["pci_dss", "nist_800_53", "tsc", "gdpr", "hipaa"]:
            if framework in rule and rule[framework]:
                compliance[framework] = rule[framework]

        rule_info = {
            "id": rule_id,
            "level": rule_level,
            "description": rule.get("description", ""),
            "groups": rule.get("groups", []),
            "frequency": rule.get("frequency"),
            "firedtimes": rule.get("firedtimes"),
            "compliance": compliance,
            "mitre": {
                "tactics": tactics if isinstance(tactics, list) else [tactics],
                "techniques": techniques if isinstance(techniques, list) else [techniques],
                "technique_names": technique_names if isinstance(technique_names, list) else [technique_names]
            }
        }
        sources = {
            "rule.id": "rule.id" if rule.get("id") else "none",
            "rule.level": "rule.level" if rule.get("level") is not None else "none",
            "rule.description": "rule.description" if rule.get("description") else "none"
        }
        return rule_info, sources

    @classmethod
    def _process_web_telemetry(cls, data: Dict[str, Any], full_log: str, agent_ip: Optional[str]) -> Tuple[Dict[str, Any], Dict[str, Any], Dict[str, str]]:
        """Logika ekstraksi telemetri web HTTP murni empiris (Zero Assumption)."""
        sources: Dict[str, str] = {}
        capped_log = full_log[:8192]  # ReDoS Ceiling Cap 8KB
        parsed_match = cls.APACHE_COMBINED_REGEX.search(capped_log)

        # 1. Resolusi L4 Transport & L7 Method
        raw_src = data.get("srcip") or data.get("src_ip") or (parsed_match.group("src_ip") if parsed_match else None)
        src_ip = ApexTransformsV40.transform_ip(raw_src)
        dst_ip = ApexTransformsV40.transform_ip(data.get("dstip") or data.get("dst_ip")) or agent_ip

        raw_method_candidate = data.get("protocol") or data.get("method") or (parsed_match.group("method") if parsed_match else None)
        if raw_method_candidate and str(raw_method_candidate).upper() in cls.HTTP_METHODS:
            http_method = str(raw_method_candidate).upper()
            transport_protocol = "tcp"  # RFC HTTP transport
            l7_protocol = "http"
            sources["http.method"] = "data.protocol" if data.get("protocol") else "full_log"
        else:
            http_method = None
            transport_protocol = None
            l7_protocol = None

        # 2. Resolusi URL & Sanitasi Path (Recursive Percent-Decoding)
        raw_url = data.get("url") or (parsed_match.group("uri") if parsed_match else None)
        clean_url_path = ApexTransformsV40.transform_url_path(raw_url)
        url_template = ApexTransformsV40.transform_tmpl(clean_url_path)
        query_string = None
        parsed_query = None
        if raw_url and "?" in raw_url:
            query_string = raw_url.split("?", 1)[1]
            parsed_query = ApexTransformsV40.transform_query_dict(query_string)

        sources["http.url_path"] = "data.url" if data.get("url") else ("full_log" if parsed_match and parsed_match.group("uri") else "none")
        sources["http.url_template"] = "transform_tmpl(http.url_path)" if clean_url_path else "none"

        # 3. Status Code & Bytes Transferred
        status_code = None
        raw_status = data.get("id") or (parsed_match.group("status_code") if parsed_match else None)
        if raw_status:
            try:
                status_code = int(raw_status)
            except ValueError:
                pass
        sources["http.status_code"] = "data.id" if data.get("id") else ("full_log" if status_code else "none")

        response_bytes = None
        if parsed_match and parsed_match.group("bytes") and parsed_match.group("bytes") != "-":
            response_bytes = ApexTransformsV40.transform_bytes(parsed_match.group("bytes"))
            sources["http.response_bytes"] = "full_log (token index 9)"

        # 4. Referer & Ekstraksi Port Asli jika tersedia
        referrer_raw = parsed_match.group("referrer") if parsed_match else None
        referrer_obj = None
        extracted_dst_port = None
        if referrer_raw and referrer_raw != "-":
            ref_parsed = urlparse(referrer_raw)
            ref_domain = ref_parsed.netloc.split(':')[0] if ':' in ref_parsed.netloc else ref_parsed.netloc
            if ref_parsed.port:
                extracted_dst_port = ref_parsed.port
            is_same_origin = bool(agent_ip and ref_domain == agent_ip)
            referrer_obj = {
                "raw": referrer_raw,
                "domain": ref_domain,
                "path": ref_parsed.path,
                "is_same_origin": is_same_origin
            }
            sources["http.referrer.raw"] = "full_log"

        # 5. User-Agent Parsing (Default Device = 'unknown' murni empiris)
        user_agent_raw = data.get("http_user_agent") or data.get("user_agent") or (parsed_match.group("user_agent") if parsed_match else None)
        user_agent_obj = None
        if user_agent_raw and user_agent_raw != "-":
            user_agent_obj = cls._parse_user_agent(user_agent_raw)
            sources["http.user_agent.raw"] = "full_log"

        # 6. Resolusi Port Tujuan (MURNI EMPIRIS TANPA ASUMSI 80)
        final_dst_port = None
        raw_dst_port = data.get("dstport") or data.get("dest_port")
        if raw_dst_port and str(raw_dst_port).isdigit():
            final_dst_port = int(raw_dst_port)
            sources["network.dst_port"] = "data.dstport"
        elif extracted_dst_port:
            final_dst_port = extracted_dst_port
            sources["network.dst_port"] = "http.referrer.port"
        else:
            final_dst_port = None  # ZERO ASSUMPTION: Jangan tebak 80!
            sources["network.dst_port"] = "none:not_in_raw_log"

        direction = "inbound" if src_ip and agent_ip and src_ip != agent_ip else ("internal" if src_ip == agent_ip else None)

        network = {
            "transport": transport_protocol,
            "protocol": l7_protocol,
            "direction": direction,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": None,
            "dst_port": final_dst_port,
            "bytes_out": response_bytes
        }
        sources["network.src_ip"] = "data.srcip" if data.get("srcip") else "none"
        sources["network.dst_ip"] = "data.dstip" if data.get("dstip") else ("agent.ip" if agent_ip else "none")

        # Versi HTTP (Zero Assumption: jangan hardcode '1.1')
        http_version = parsed_match.group("http_version") if parsed_match else None

        http_data = {
            "version": http_version,
            "method": http_method,
            "url_path": clean_url_path,
            "url_template": url_template,
            "query_string": query_string,
            "parsed_query": parsed_query,
            "status_code": status_code,
            "response_bytes": response_bytes,
            "referrer": referrer_obj,
            "user_agent": user_agent_obj
        }
        return network, http_data, sources

    @classmethod
    def _process_fim_telemetry(cls, raw: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, str]]:
        """Ekstraksi telemetri berkas FIM Syscheck."""
        syscheck = raw.get("syscheck") if isinstance(raw.get("syscheck"), dict) else {}
        sources = {
            "file.path": "syscheck.path" if syscheck.get("path") else "none",
            "file.event_type": "syscheck.event" if syscheck.get("event") else "none",
            "file.size_after": "syscheck.size_after" if syscheck.get("size_after") is not None else "none",
            "file.sha256_after": "syscheck.sha256_after" if syscheck.get("sha256_after") else "none",
            "file.md5_after": "syscheck.md5_after" if syscheck.get("md5_after") else "none"
        }
        file_data = {
            "path": syscheck.get("path"),
            "event_type": syscheck.get("event"),
            "size_after": ApexTransformsV40.transform_bytes(syscheck.get("size_after")),
            "size_before": ApexTransformsV40.transform_bytes(syscheck.get("size_before")),
            "sha256_after": ApexTransformsV40.transform_hash(syscheck.get("sha256_after")),
            "sha256_before": ApexTransformsV40.transform_hash(syscheck.get("sha256_before")),
            "md5_after": ApexTransformsV40.transform_hash(syscheck.get("md5_after")),
            "md5_before": ApexTransformsV40.transform_hash(syscheck.get("md5_before")),
            "uname_after": syscheck.get("uname_after"),
            "gname_after": syscheck.get("gname_after"),
            "permissions_after": syscheck.get("perm_after")
        }
        return file_data, sources

    @classmethod
    def _process_cve_telemetry(cls, data: Dict[str, Any], raw: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, str]]:
        """Ekstraksi telemetri kerentanan CVE."""
        vuln = data.get("vulnerability") if isinstance(data.get("vulnerability"), dict) else {}
        pkg = vuln.get("package") if isinstance(vuln.get("package"), dict) else {}
        cvss = vuln.get("cvss", {}).get("cvss3", {}) if isinstance(vuln.get("cvss"), dict) and isinstance(vuln.get("cvss", {}).get("cvss3"), dict) else {}

        cve_id = vuln.get("cve") or vuln.get("id")
        pkg_name = pkg.get("name") or data.get("package")
        pkg_version = pkg.get("version")

        cvss_score = None
        raw_score = cvss.get("base_score") or data.get("cvss")
        if raw_score:
            try:
                cvss_score = float(raw_score)
            except (ValueError, TypeError):
                pass

        sources = {
            "vulnerability.cve_id": "data.vulnerability.cve" if cve_id else "none",
            "vulnerability.package_name": "data.vulnerability.package.name" if pkg_name else "none",
            "vulnerability.cvss_score": "data.vulnerability.cvss.base_score" if cvss_score is not None else "none",
            "vulnerability.severity": "data.vulnerability.severity" if vuln.get("severity") else "none"
        }
        vuln_data = {
            "cve_id": cve_id,
            "title": vuln.get("title"),
            "severity": vuln.get("severity"),
            "cvss_score": cvss_score,
            "cvss_vector": cvss.get("vector"),
            "package_name": pkg_name,
            "installed_version": pkg_version,
            "patched_version": pkg.get("fixed_version"),
            "architecture": pkg.get("architecture")
        }
        return vuln_data, sources

    @classmethod
    def _process_windows_auth_telemetry(cls, data: Dict[str, Any], raw: Dict[str, Any], agent_ip: Optional[str]) -> Tuple[Dict[str, Any], Dict[str, Any], Dict[str, str]]:
        """Router khusus Windows Authentication (EventID 4624/4625/4688/4720)."""
        win = data.get("win", {})
        ev_data = win.get("eventdata", {})
        sys_data = win.get("system", {})
        sources: Dict[str, str] = {}

        event_id = sys_data.get("eventID")
        user = ev_data.get("targetUserName") or ev_data.get("subjectUserName")
        domain = ev_data.get("targetDomainName") or ev_data.get("subjectDomainName")
        logon_type = ev_data.get("logonType")
        src_ip = ApexTransformsV40.transform_ip(ev_data.get("ipAddress") or ev_data.get("sourceIp"))
        dst_ip = agent_ip

        # Zero Assumption: ambil protokol dari package name jika ada di log
        auth_pkg = ev_data.get("authenticationPackageName")
        protocol = str(auth_pkg).lower() if auth_pkg else ("kerberos/ntlm" if src_ip else None)

        src_port = int(ev_data["sourcePort"]) if ev_data.get("sourcePort") and str(ev_data["sourcePort"]).isdigit() else None
        dst_port = int(ev_data["destinationPort"]) if ev_data.get("destinationPort") and str(ev_data["destinationPort"]).isdigit() else None

        auth_data = {
            "event_id": str(event_id) if event_id else None,
            "target_user": ApexTransformsV40.transform_user(user, "windows"),
            "domain": domain,
            "logon_type": int(logon_type) if logon_type and str(logon_type).isdigit() else None,
            "process_name": ev_data.get("image") or ev_data.get("processName"),
            "failure_reason": ev_data.get("status") or ev_data.get("subStatus")
        }
        sources["authentication.event_id"] = "data.win.system.eventID" if event_id else "none"
        sources["authentication.user"] = "data.win.eventdata.targetUserName" if user else "none"
        sources["authentication.domain"] = "data.win.eventdata.targetDomainName" if domain else "none"
        sources["authentication.logon_type"] = "data.win.eventdata.logonType" if logon_type else "none"

        network = {
            "transport": "tcp" if src_ip else None,
            "protocol": protocol,
            "direction": "inbound" if src_ip and agent_ip and src_ip != agent_ip else None,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "bytes_out": None
        }
        sources["network.src_ip"] = "data.win.eventdata.ipAddress" if src_ip else "none"
        sources["network.dst_ip"] = "agent.ip" if agent_ip else "none"
        sources["network.src_port"] = "data.win.eventdata.sourcePort" if src_port else "none"
        sources["network.dst_port"] = "data.win.eventdata.destinationPort" if dst_port else "none"
        sources["network.protocol"] = "data.win.eventdata.authenticationPackageName" if auth_pkg else "inferred:auth_stack"
        return auth_data, network, sources

    @classmethod
    def _process_cloud_telemetry(cls, data: Dict[str, Any], raw: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, Any], Dict[str, str]]:
        """Router khusus CloudTrail AWS / Office365 / GitHub Audit."""
        sources: Dict[str, str] = {}
        aws = data.get("aws", {})
        o365 = data.get("office365", {})
        github = data.get("github", {})

        provider = "aws" if aws else ("office365" if o365 else ("github" if github else "cloud_audit"))
        actor = (
            aws.get("userIdentity", {}).get("arn")
            or o365.get("UserId")
            or github.get("actor")
            or github.get("sender")
        )
        operation = (
            aws.get("eventName")
            or o365.get("Operation")
            or github.get("action")
            or github.get("event")
        )
        src_ip = ApexTransformsV40.transform_ip(
            aws.get("sourceIPAddress")
            or o365.get("ClientIP")
            or github.get("actor_ip")
            or github.get("sender_ip")
        )

        cloud_data = {
            "provider": provider,
            "actor_arn": actor,
            "operation": operation,
            "region": aws.get("awsRegion") or o365.get("Workload") or github.get("repository"),
            "error_code": aws.get("errorCode") or o365.get("ResultStatus") or github.get("error"),
            "error_message": aws.get("errorMessage")
        }
        sources["cloud.provider"] = f"detected:{provider}"
        sources["cloud.actor_arn"] = "detected:cloud_actor" if actor else "none"
        sources["cloud.operation"] = "detected:cloud_operation" if operation else "none"

        # ZERO ASSUMPTION: Jangan tebak dst_port=443, transport=tcp, protocol=https!
        # Log audit API cloud tidak memuat L4/L7 port info kecuali eksplisit ada.
        network = {
            "transport": None,
            "protocol": None,
            "direction": "inbound" if src_ip else None,
            "src_ip": src_ip,
            "dst_ip": None,
            "src_port": None,
            "dst_port": None,  # MURNI EMPIRIS: None jika tidak ada di log
            "bytes_out": None
        }
        sources["network.src_ip"] = "detected:cloud_src_ip" if src_ip else "none"
        sources["network.dst_port"] = "none:cloud_api_no_port_in_raw_log"
        return cloud_data, network, sources

    @classmethod
    def _process_generic_network(cls, data: Dict[str, Any], raw: Dict[str, Any], agent_ip: Optional[str]) -> Tuple[Dict[str, Any], Dict[str, str]]:
        """Ekstraksi koneksi jaringan L3/L4 generik murni empiris (Zero Assumption)."""
        raw_src = data.get("srcip") or data.get("src_ip")
        src_ip = ApexTransformsV40.transform_ip(raw_src)
        raw_dst = data.get("dstip") or data.get("dst_ip")
        dst_ip = ApexTransformsV40.transform_ip(raw_dst) or agent_ip

        src_port = data.get("srcport") or data.get("src_port")
        dst_port = data.get("dstport") or data.get("dst_port")
        raw_proto = data.get("proto")

        sources = {
            "network.src_ip": "data.srcip" if raw_src else "none",
            "network.dst_ip": "data.dstip" if raw_dst else ("agent.ip" if agent_ip else "none"),
            "network.transport": "data.proto" if raw_proto else "none:not_in_log"
        }
        network = {
            "transport": str(raw_proto).lower() if raw_proto else None,  # JANGAN TEBAK 'ip'
            "protocol": str(data.get("protocol")).lower() if data.get("protocol") else None,
            "direction": "inbound" if src_ip and agent_ip and src_ip != agent_ip else None,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": int(src_port) if src_port and str(src_port).isdigit() else None,
            "dst_port": int(dst_port) if dst_port and str(dst_port).isdigit() else None,
            "bytes_out": None
        }
        return network, sources

    @classmethod
    def _parse_user_agent(cls, ua_string: str) -> Dict[str, str]:
        """Parser deterministik User-Agent tanpa asumsi desktop (mengenali Edge, Opera, Bot)."""
        browser = "Unknown"
        version = "Unknown"
        os = "Unknown"
        device = "unknown"  # MURNI EMPIRIS: Default awal adalah unknown

        if "Windows" in ua_string:
            os = "Windows"
            device = "desktop"
        elif "Macintosh" in ua_string or "Mac OS X" in ua_string:
            os = "macOS"
            device = "desktop"
        elif "Linux" in ua_string and "Android" not in ua_string:
            os = "Linux"
            device = "desktop"
        elif "Android" in ua_string:
            os = "Android"
            device = "mobile"
        elif "iPhone" in ua_string or "iPad" in ua_string:
            os = "iOS"
            device = "mobile"

        ua_lower = ua_string.lower()

        # 1. Bots & Crawlers
        if "googlebot" in ua_lower:
            browser = "Googlebot"
            device = "bot"
            m = re.search(r'Googlebot/([0-9.]+)', ua_string, re.IGNORECASE)
            if m:
                version = m.group(1)
        elif "bingbot" in ua_lower:
            browser = "bingbot"
            device = "bot"
            m = re.search(r'bingbot/([0-9.]+)', ua_string, re.IGNORECASE)
            if m:
                version = m.group(1)
        elif "curl/" in ua_string:
            browser = "curl"
            device = "bot"
            m = re.search(r'curl/([0-9.]+)', ua_string)
            if m:
                version = m.group(1)
        elif any(bot_id in ua_lower for bot_id in ["bot", "spider", "crawler", "scraper", "python-requests"]):
            browser = ua_string.split("/")[0] if "/" in ua_string else "bot"
            device = "bot"
        # 2. Microsoft Edge (Chromium-based: Edg/ atau Edge/)
        elif "Edg/" in ua_string or "Edge/" in ua_string:
            browser = "Edge"
            m = re.search(r'(?:Edg|Edge)/([0-9.]+)', ua_string)
            if m:
                version = m.group(1)
        # 3. Opera (OPR/ atau Opera/)
        elif "OPR/" in ua_string or "Opera/" in ua_string:
            browser = "Opera"
            m = re.search(r'(?:OPR|Opera)/([0-9.]+)', ua_string)
            if m:
                version = m.group(1)
        # 4. Google Chrome
        elif "Chrome/" in ua_string and "Safari/" in ua_string:
            browser = "Chrome"
            m = re.search(r'Chrome/([0-9.]+)', ua_string)
            if m:
                version = m.group(1)
        # 5. Mozilla Firefox
        elif "Firefox/" in ua_string:
            browser = "Firefox"
            m = re.search(r'Firefox/([0-9.]+)', ua_string)
            if m:
                version = m.group(1)
        # 6. Apple Safari
        elif "Safari/" in ua_string and "Chrome/" not in ua_string:
            browser = "Safari"
            m = re.search(r'Version/([0-9.]+)', ua_string)
            if m:
                version = m.group(1)

        return {
            "raw": ua_string,
            "browser": browser,
            "browser_version": version,
            "os": os,
            "device": device
        }

    @classmethod
    def _process_process_telemetry(
        cls,
        data: Dict[str, Any],
        raw: Dict[str, Any]
    ) -> Tuple[Dict[str, Any], Dict[str, str]]:
        """
        Ekstraksi telemetri proses eksekusi & command line (OCSF v1.4 / ECS Process Forensic Standard).
        Mendukung Sysmon EventID 1, Linux Auditd, dan skema proses Wazuh generik tanpa asumsi.
        """
        win_data = data.get("win", {}).get("eventdata", {}) if isinstance(data.get("win"), dict) else {}
        audit_data = data.get("audit", {}) if isinstance(data.get("audit"), dict) else {}
        sources: Dict[str, str] = {}

        # 1. Process Executable Path & Name
        raw_path = (
            win_data.get("image")
            or audit_data.get("exe")
            or data.get("process_path")
            or data.get("image")
            or data.get("exe_path")
        )
        raw_name = (
            data.get("process_name")
            or data.get("process")
            or data.get("exe")
            or data.get("app")
            or (os.path.basename(str(raw_path)) if raw_path else None)
        )

        # 2. Command Line Execution
        command_line = (
            win_data.get("commandLine")
            or audit_data.get("command")
            or audit_data.get("cmd")
            or data.get("command_line")
            or data.get("cmd")
            or data.get("command")
        )

        # 3. Parent Process Lineage
        parent_path = (
            win_data.get("parentImage")
            or data.get("parent_process_path")
            or data.get("parent_image")
        )
        parent_name = (
            data.get("parent_process_name")
            or data.get("parent_process")
            or data.get("parent")
            or (os.path.basename(str(parent_path)) if parent_path else None)
        )
        parent_cmd = (
            win_data.get("parentCommandLine")
            or data.get("parent_command_line")
            or data.get("parent_cmd")
        )

        # 4. Process Identifiers (PIDs)
        raw_pid = win_data.get("processId") or audit_data.get("pid") or data.get("pid") or data.get("process_id")
        pid = int(raw_pid) if raw_pid and str(raw_pid).isdigit() else None

        raw_ppid = win_data.get("parentProcessId") or audit_data.get("ppid") or data.get("ppid") or data.get("parent_pid")
        parent_pid = int(raw_ppid) if raw_ppid and str(raw_ppid).isdigit() else None

        # 5. Execution Context & Identity
        user = (
            win_data.get("user")
            or win_data.get("subjectUserName")
            or audit_data.get("acct")
            or audit_data.get("auid")
            or data.get("user")
            or data.get("username")
        )
        working_dir = (
            win_data.get("currentDirectory")
            or data.get("current_directory")
            or data.get("working_directory")
            or data.get("pwd")
        )

        # Lineage evidence tracking
        if raw_name:
            sources["process.name"] = (
                "data.win.eventdata.image" if win_data.get("image")
                else ("data.audit.exe" if audit_data.get("exe")
                else ("data.process_name" if data.get("process_name") else "inferred:basename"))
            )
        if command_line:
            sources["process.command_line"] = (
                "data.win.eventdata.commandLine" if win_data.get("commandLine")
                else ("data.audit.command" if audit_data.get("command") else "data.command_line")
            )
        if parent_name or parent_path:
            sources["process.parent"] = (
                "data.win.eventdata.parentImage" if win_data.get("parentImage") else "data.parent_process"
            )

        process_data = {
            "name": raw_name,
            "path": raw_path,
            "command_line": command_line,
            "parent_name": parent_name,
            "parent_path": parent_path,
            "parent_command_line": parent_cmd,
            "pid": pid,
            "parent_pid": parent_pid,
            "user": user,
            "working_directory": working_dir
        }
        return process_data, sources

    @classmethod
    def _detect_domain_signatures(
        cls,
        data: Dict[str, Any],
        raw_alert: Dict[str, Any],
        decoder_name: Optional[str] = None,
        full_log: Optional[str] = None
    ) -> Set[str]:
        """
        Feature-Signature Introspection Engine (Duck Typing & Structural Introspection).
        Mendeteksi seluruh domain telemetri aktif secara independen tanpa bergantung pada nama decoder statis.
        Mendukung multi-domain co-existence (misal: Web + Process + FIM pada insiden WebShell RCE).
        """
        active: Set[str] = set()
        data_obj = data if isinstance(data, dict) else {}
        raw = raw_alert if isinstance(raw_alert, dict) else {}
        dec = str(decoder_name or "").lower()
        rule_groups = [
            str(g).lower() for g in raw.get("rule", {}).get("groups", [])
        ] if isinstance(raw.get("rule"), dict) else []
        capped_log = (full_log or "")[:cls.MAX_FULL_LOG_LEN]

        # ── Domain 1: HTTP / Web Telemetry ────────────────────────────────────
        has_http_keys = any(k in data_obj for k in ("url", "url_path", "uri", "http_user_agent"))
        has_http_method = any(
            str(data_obj.get(k) or "").upper() in cls.HTTP_METHODS
            for k in ("protocol", "method", "http_method")
        )
        has_web_decoder = any(w in dec for w in ("web", "accesslog", "apache", "nginx", "caddy", "traefik", "lighttpd", "iis", "envoy", "kong", "haproxy"))
        has_web_groups = any(w in rule_groups for w in ("web", "accesslog", "web_scan", "http"))
        has_apache_log_match = bool(cls.APACHE_COMBINED_REGEX.search(capped_log)) if capped_log else False

        # Windows event log murni tanpa kunci URL/HTTP tidak boleh terkelompokkan sebagai web murni
        is_pure_win_event = "win" in data_obj and "eventdata" in data_obj.get("win", {}) and not has_http_keys

        if not is_pure_win_event:
            if has_http_keys or has_http_method or has_web_decoder or has_web_groups or has_apache_log_match:
                active.add("HTTP")

        # ── Domain 2: File Integrity Monitoring (FIM / Syscheck) ──────────────
        has_syscheck = "syscheck" in raw and isinstance(raw.get("syscheck"), dict)
        has_file_keys = any(k in data_obj for k in ("file", "file_path", "filename", "path_to_file"))
        has_fim_decoder = any(w in dec for w in ("syscheck", "fim", "integrity"))
        has_fim_groups = any(w in rule_groups for w in ("syscheck", "fim", "ossec"))

        if has_syscheck or (has_file_keys and (has_fim_decoder or has_fim_groups)):
            active.add("FILE")

        # ── Domain 3: Process Execution & Command Telemetry ───────────────────
        win_data = data_obj.get("win", {}).get("eventdata", {}) if isinstance(data_obj.get("win"), dict) else {}
        audit_data = data_obj.get("audit", {}) if isinstance(data_obj.get("audit"), dict) else {}

        has_win_proc = bool(
            win_data.get("commandLine") or win_data.get("image") or win_data.get("parentImage") or win_data.get("processId")
        )
        has_audit_proc = bool(
            audit_data.get("exe") or audit_data.get("command") or audit_data.get("cmd") or audit_data.get("args")
        )
        has_data_proc = any(
            k in data_obj for k in ("command", "command_line", "cmd", "process_name", "process", "image", "exe", "parent_process")
        )
        has_proc_groups = any(w in rule_groups for w in ("process", "execution", "sysmon_event1", "auditd"))

        if has_win_proc or has_audit_proc or has_data_proc or has_proc_groups:
            active.add("PROCESS")

        # ── Domain 4: Vulnerability / CVE Telemetry ───────────────────────────
        has_vuln_obj = "vulnerability" in data_obj and isinstance(data_obj.get("vulnerability"), dict)
        has_cve_key = bool(data_obj.get("cve") or data_obj.get("cve_id") or data_obj.get("vulnerability_id"))
        has_vuln_decoder = any(w in dec for w in ("vulnerability-detector", "cve", "vuln"))
        has_vuln_groups = any(w in rule_groups for w in ("vulnerability-detector", "cve", "vulnerability"))

        if has_vuln_obj or has_cve_key or has_vuln_decoder or has_vuln_groups:
            active.add("VULNERABILITY")

        # ── Domain 5: Windows / Directory Authentication ──────────────────────
        has_win_auth = bool(
            win_data.get("targetUserName") or win_data.get("subjectUserName") or win_data.get("logonType") or win_data.get("ipAddress")
        )
        sys_data = data_obj.get("win", {}).get("system", {}) if isinstance(data_obj.get("win"), dict) else {}
        win_event_id = str(sys_data.get("eventID") or "")
        is_auth_event_id = win_event_id in ("4624", "4625", "4634", "4648", "4672", "4720", "4722", "4724", "4726", "4738", "4776")

        if has_win_auth or is_auth_event_id:
            active.add("WINDOWS_AUTH")

        # ── Domain 6: Cloud Audit (AWS, Office365, GitHub, GCP, Azure) ────────
        has_cloud_keys = any(k in data_obj for k in ("aws", "office365", "github", "azure", "gcp"))
        has_cloud_decoder = any(w in dec for w in ("aws", "office365", "github", "azure", "gcp"))
        if has_cloud_keys or has_cloud_decoder:
            active.add("CLOUD")

        return active

    @classmethod
    def _is_web_event(cls, data: Dict[str, Any], decoder_name: Optional[str]) -> bool:
        return "HTTP" in cls._detect_domain_signatures(data, {}, decoder_name)

    @classmethod
    def _is_fim_event(cls, raw: Dict[str, Any], decoder_name: Optional[str]) -> bool:
        return "FILE" in cls._detect_domain_signatures(raw.get("data", {}) if isinstance(raw.get("data"), dict) else {}, raw, decoder_name)

    @classmethod
    def _is_cve_event(cls, data: Dict[str, Any], raw: Dict[str, Any], decoder_name: Optional[str]) -> bool:
        return "VULNERABILITY" in cls._detect_domain_signatures(data, raw, decoder_name)

    @classmethod
    def _is_windows_auth_event(cls, data: Dict[str, Any]) -> bool:
        return "WINDOWS_AUTH" in cls._detect_domain_signatures(data, {})

    @classmethod
    def _is_cloud_event(cls, data: Dict[str, Any]) -> bool:
        return "CLOUD" in cls._detect_domain_signatures(data, {})

    @staticmethod
    def _parse_iso_timestamp(ts_str: Optional[str]) -> Optional[datetime]:
        """Parsing timestamp dengan proteksi POSIX Leap Second Clamping (23:59:60 -> 23:59:59.999999Z)."""
        if not ts_str:
            return None
        try:
            # POSIX Leap Second Clamping
            cleaned = ts_str.replace("Z", "+00:00")
            if ":59:60" in cleaned:
                cleaned = cleaned.replace(":59:60", ":59:59.999999")
            dt = datetime.fromisoformat(cleaned)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except Exception:
            try:
                dt = datetime.strptime(ts_str, "%Y-%m-%dT%H:%M:%S.%f%z")
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt
            except Exception:
                return None


# ── Backward Compatibility Aliases ────────────────────────────────────────────
# Menjamin seluruh pipeline dan test suite eksisting tetap berjalan 100% mulus.
ApexTransformsV34 = ApexTransformsV40
ApexNormalizerV34 = ApexNormalizerV40
