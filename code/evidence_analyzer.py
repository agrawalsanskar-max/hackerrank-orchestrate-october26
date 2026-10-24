"""
code/evidence_analyzer.py - Forensic investigation module for Ghost Data Still Exists.
Parses multi-format evidence files (.sql, .json, .log, .txt, .pdf) adhering strictly to:
1. Temporal window: only files captured between requested_at and audit_at (requested_at <= captured_at <= audit_at).
2. Deep identifier matching (user_id, email, phone, email_hash, name).
3. Log trace correlation: connects multi-line log traces via trace_id.
4. Replication drift detection between primary databases and failover/regional/read replicas.
5. Active data flow detection and restore risk identification.
6. Proper classification of retained security audit logs vs surviving non-compliant records.
"""

from __future__ import annotations

import base64
import csv
import json
import re
import sqlite3
import zlib
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

try:
    from identity_resolver import IdentityCluster, _find_repo_root
except ImportError:
    from .identity_resolver import IdentityCluster, _find_repo_root


@dataclass
class EvidenceFinding:
    """Represents a forensic finding or verification fact discovered in evidence."""
    system_id: str
    resource_id: str
    phase: str  # 'FINDING' or 'VERIFICATION'
    operation: str  # REPORT_REMAINING_RECORD, REPORT_EXPOSED_PII, REPORT_ACTIVE_DATA_FLOW, REPORT_RESTORE_RISK, etc.
    state: str  # PRESENT, ABSENT, REDACTED, ANONYMIZED, ACTIVE, DISABLED, BLOCKED
    evidence_id: str
    timestamp: str = ""
    details: Dict[str, Any] = field(default_factory=dict)

    def to_step_dict(self, step_no: int = 1) -> Dict[str, Any]:
        return {
            "step_no": step_no,
            "phase": self.phase,
            "system_id": self.system_id,
            "resource_id": self.resource_id,
            "operation": self.operation,
            "state": self.state,
            "evidence_id": self.evidence_id,
        }


class EvidenceAnalyzer:
    """Forensic investigation engine that matches user identity clusters across evidence."""

    def __init__(self, dataset_dir: Optional[str] = None):
        if dataset_dir:
            self.dataset_dir = Path(dataset_dir)
        else:
            root = _find_repo_root()
            self.dataset_dir = root / "dataset"

        self.evidence_files_path = self.dataset_dir / "evidence_files.csv"
        self.evidence_manifest: List[Dict[str, str]] = []
        self._load_manifest()

    def _load_manifest(self):
        """Loads and sorts evidence files by captured_at timestamp."""
        if not self.evidence_files_path.exists():
            return
        with open(self.evidence_files_path, "r", encoding="utf-8") as f:
            self.evidence_manifest = list(csv.DictReader(f))
        # Sort chronologically by captured_at
        self.evidence_manifest.sort(key=lambda x: x.get("captured_at", ""))

    def get_eligible_evidence_files(
        self,
        audit_at: str,
        requested_at: Optional[str] = None
    ) -> List[Dict[str, str]]:
        """
        Returns evidence files captured between requested_at and audit_at cutoff.
        If requested_at is provided, filters out stale baseline files captured prior to deletion request.
        """
        eligible = []
        for ef in self.evidence_manifest:
            cap = ef.get("captured_at", "")
            if not cap:
                continue
            if cap > audit_at:
                continue
            if requested_at and cap < requested_at:
                continue
            eligible.append(ef)
        return eligible

    def extract_pdf_strings(self, file_path: Path) -> List[str]:
        """Extract text strings from PDF using pure standard library (ASCII85 + FlateDecode)."""
        strings = []
        try:
            with open(file_path, "rb") as f:
                data = f.read()

            # 1. ASCII85Decode + FlateDecode
            objs_a85 = re.findall(
                rb"<<.*?/Filter\s*\[\s*/ASCII85Decode\s*/FlateDecode\s*\].*?>>\s*stream\r?\n(.*?)endstream",
                data, re.DOTALL
            )
            for raw in objs_a85:
                try:
                    dec = base64.a85decode(raw.strip(), adobe=True)
                    decomp = zlib.decompress(dec)
                    found = re.findall(r"\((.*?)\)", decomp.decode("latin1"))
                    strings.extend(found)
                except Exception:
                    pass

            # 2. Plain FlateDecode
            objs_flate = re.findall(
                rb"<<.*?/Filter\s*/FlateDecode.*?>>\s*stream\r?\n(.*?)endstream",
                data, re.DOTALL
            )
            for raw in objs_flate:
                try:
                    decomp = zlib.decompress(raw.strip())
                    found = re.findall(r"\((.*?)\)", decomp.decode("latin1"))
                    strings.extend(found)
                except Exception:
                    pass
        except Exception:
            pass
        return strings

    def analyze_case(
        self,
        cluster: IdentityCluster,
        audit_at: str,
        requested_at: Optional[str] = None,
    ) -> List[EvidenceFinding]:
        """
        Forensically investigates all eligible evidence files for the user cluster up to audit_at.
        Returns all discovered findings (policy violations/surviving data) and verification evidence.
        """
        eligible_files = self.get_eligible_evidence_files(audit_at, requested_at)
        findings: List[EvidenceFinding] = []

        # Prepare normalized search terms
        emails_lower = {e.lower() for e in cluster.emails}
        user_ids = {uid for uid in cluster.user_ids}
        if cluster.primary_user_id and cluster.primary_user_id != "unknown":
            user_ids.add(cluster.primary_user_id)
        phones = {p.strip() for p in cluster.phones}
        hashes_lower = {h.lower() for h in cluster.email_hashes}
        names_lower = {n.lower() for n in cluster.names}

        all_ident_terms = emails_lower | user_ids | phones | hashes_lower

        # Evaluate evidence files in reverse chronological order (newest evidence first)
        for ef in reversed(eligible_files):
            file_id = ef["file_id"]
            rel_path = ef["file_path"]
            full_path = self.dataset_dir / rel_path
            origin = ef.get("origin", "")
            ext = full_path.suffix.lower()

            if not full_path.exists():
                continue

            # 1. SQL SNAPSHOTS (.sql)
            if ext == ".sql":
                self._parse_sql_evidence(
                    full_path, file_id, origin, all_ident_terms, emails_lower, user_ids, findings
                )

            # 2. JSON DOCUMENTS (.json)
            elif ext == ".json":
                self._parse_json_evidence(
                    full_path, file_id, origin, all_ident_terms, emails_lower, user_ids, findings
                )

            # 3. OPERATIONAL LOGS (.log)
            elif ext == ".log":
                self._parse_log_evidence(
                    full_path, file_id, origin, all_ident_terms, emails_lower, user_ids, findings
                )

            # 4. TEXT RECORDS (.txt)
            elif ext == ".txt":
                self._parse_text_evidence(
                    full_path, file_id, origin, all_ident_terms, emails_lower, user_ids, findings
                )

            # 5. PDF DOCUMENTS (.pdf)
            elif ext == ".pdf":
                self._parse_pdf_evidence(
                    full_path, file_id, origin, all_ident_terms, emails_lower, user_ids, findings
                )

        return findings

    def _parse_sql_evidence(
        self,
        full_path: Path,
        file_id: str,
        origin: str,
        all_terms: Set[str],
        emails_lower: Set[str],
        user_ids: Set[str],
        findings: List[EvidenceFinding],
    ):
        """Execute and analyze SQLite SQL snapshot exports for primary vs replica states."""
        try:
            with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                sql_script = f.read()

            conn = sqlite3.connect(":memory:")
            cursor = conn.cursor()
            
            clean_script = "\n".join(
                line for line in sql_script.splitlines()
                if not line.strip().startswith("--")
            )
            
            try:
                cursor.executescript(clean_script)
            except Exception:
                conn.close()
                self._parse_raw_text_for_sql(sql_script, file_id, origin, all_terms, emails_lower, user_ids, findings)
                return

            cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tables = [row[0] for row in cursor.fetchall()]

            # A. Check customer_profiles_primary vs customer_profiles_failover_replica
            if "customer_profiles_failover_replica" in tables:
                cursor.execute("SELECT resource_id, user_id, email, full_name, phone FROM customer_profiles_failover_replica")
                for r_id, u_id, em, name, ph in cursor.fetchall():
                    if (em and em.lower() in emails_lower) or (u_id and u_id in user_ids):
                        findings.append(EvidenceFinding(
                            system_id="account_service",
                            resource_id=r_id,
                            phase="FINDING",
                            operation="REPORT_REMAINING_RECORD",
                            state="PRESENT",
                            evidence_id=file_id,
                            details={"reason": "failover_replica_drift", "email": em, "user_id": u_id}
                        ))

            # B. Check customer_search_primary
            if "search_documents_primary" in tables:
                cursor.execute("SELECT resource_id, email, display_name FROM search_documents_primary")
                for r_id, em, name in cursor.fetchall():
                    if em and em.lower() in emails_lower:
                        findings.append(EvidenceFinding(
                            system_id="search_service",
                            resource_id=r_id,
                            phase="FINDING",
                            operation="REPORT_REMAINING_RECORD",
                            state="PRESENT",
                            evidence_id=file_id,
                            details={"email": em}
                        ))

            # C. Check customer_data_inventory tables (customer_data_inventory_*.sql)
            if "backup_restore_entries" in tables:
                cursor.execute("SELECT resource_id, customer_reference, customer_email, restore_allowed FROM backup_restore_entries")
                for r_id, u_id, em, r_allowed in cursor.fetchall():
                    if (em and em.lower() in emails_lower) or (u_id and u_id in user_ids):
                        if str(r_allowed) in ("1", "True", "true"):
                            findings.append(EvidenceFinding(
                                system_id="backup_service",
                                resource_id=r_id,
                                phase="FINDING",
                                operation="REPORT_RESTORE_RISK",
                                state="ACTIVE",
                                evidence_id=file_id,
                                details={"restore_allowed": True}
                            ))
                        else:
                            findings.append(EvidenceFinding(
                                system_id="backup_service",
                                resource_id=r_id,
                                phase="VERIFICATION",
                                operation="VERIFY_RESTORE_BLOCKED",
                                state="BLOCKED",
                                evidence_id=file_id,
                                details={"restore_allowed": False}
                            ))

            if "connector_subscriptions" in tables:
                cursor.execute("SELECT resource_id, customer_reference, customer_email, enabled FROM connector_subscriptions")
                for r_id, u_id, em, enabled in cursor.fetchall():
                    if (em and em.lower() in emails_lower) or (u_id and u_id in user_ids):
                        if str(enabled) in ("1", "True", "true"):
                            findings.append(EvidenceFinding(
                                system_id="integration_service",
                                resource_id=r_id,
                                phase="FINDING",
                                operation="REPORT_ACTIVE_DATA_FLOW",
                                state="ACTIVE",
                                evidence_id=file_id,
                                details={"enabled": True}
                            ))
                        else:
                            findings.append(EvidenceFinding(
                                system_id="integration_service",
                                resource_id=r_id,
                                phase="VERIFICATION",
                                operation="VERIFY_DATA_FLOW_DISABLED",
                                state="DISABLED",
                                evidence_id=file_id,
                                details={"enabled": False}
                            ))

            if "customer_search_documents" in tables:
                cursor.execute("SELECT resource_id, customer_reference, email FROM customer_search_documents")
                for r_id, u_id, em in cursor.fetchall():
                    if (em and em.lower() in emails_lower) or (u_id and u_id in user_ids):
                        findings.append(EvidenceFinding(
                            system_id="search_service",
                            resource_id=r_id,
                            phase="FINDING",
                            operation="REPORT_REMAINING_RECORD",
                            state="PRESENT",
                            evidence_id=file_id,
                            details={"email": em}
                        ))

            if "customer_profiles" in tables:
                cursor.execute("SELECT resource_id, customer_reference, email, account_status FROM customer_profiles")
                for r_id, u_id, em, status in cursor.fetchall():
                    if (em and em.lower() in emails_lower) or (u_id and u_id in user_ids):
                        findings.append(EvidenceFinding(
                            system_id="account_service",
                            resource_id=r_id,
                            phase="FINDING",
                            operation="REPORT_REMAINING_RECORD",
                            state="PRESENT",
                            evidence_id=file_id,
                            details={"status": status}
                        ))

            if "support_records" in tables:
                cursor.execute("SELECT resource_id, customer_reference, requester_email FROM support_records")
                for r_id, u_id, em in cursor.fetchall():
                    if (em and em.lower() in emails_lower) or (u_id and u_id in user_ids):
                        if em:
                            findings.append(EvidenceFinding(
                                system_id="support_platform",
                                resource_id=r_id,
                                phase="FINDING",
                                operation="REPORT_EXPOSED_PII",
                                state="PRESENT",
                                evidence_id=file_id,
                                details={"requester_email": em}
                            ))
                        else:
                            findings.append(EvidenceFinding(
                                system_id="support_platform",
                                resource_id=r_id,
                                phase="VERIFICATION",
                                operation="VERIFY_RECORD_REDACTED",
                                state="REDACTED",
                                evidence_id=file_id,
                            ))

            if "customer_exports" in tables:
                cursor.execute("SELECT resource_id, customer_reference, owner_email FROM customer_exports")
                for r_id, u_id, em in cursor.fetchall():
                    if (em and em.lower() in emails_lower) or (u_id and u_id in user_ids):
                        findings.append(EvidenceFinding(
                            system_id="export_service",
                            resource_id=r_id,
                            phase="FINDING",
                            operation="REPORT_REMAINING_RECORD",
                            state="PRESENT",
                            evidence_id=file_id,
                            details={"owner_email": em}
                        ))

            if "security_audit_records" in tables:
                cursor.execute("SELECT resource_id, subject_reference FROM security_audit_records")
                for r_id, u_id in cursor.fetchall():
                    if u_id and u_id in user_ids:
                        findings.append(EvidenceFinding(
                            system_id="security_service",
                            resource_id=r_id,
                            phase="VERIFICATION",
                            operation="VERIFY_RECORD_PRESENT",
                            state="PRESENT",
                            evidence_id=file_id,
                        ))

            # D. Generic table topology (customer_data_primary & customer_data_read_replica / regional)
            replica_tables = [t for t in tables if "replica" in t.lower() and t != "customer_profiles_failover_replica"]
            all_data_tables = ["customer_data_primary"] + replica_tables if "customer_data_primary" in tables else tables
            
            seen_generic_resources = set()
            for t in all_data_tables:
                cursor.execute(f"PRAGMA table_info({t});")
                col_names = [row[1] for row in cursor.fetchall()]
                if "record_json" in col_names and "origin_system" in col_names:
                    cursor.execute(f"SELECT resource_id, origin_system, record_json FROM {t}")
                    for r_id, orig_sys, rec_json_str in cursor.fetchall():
                        if r_id in seen_generic_resources:
                            continue
                        try:
                            rec_data = json.loads(rec_json_str)
                            dumped = json.dumps(rec_data).lower()
                            matched = any(term.lower() in dumped for term in all_terms)
                            if matched:
                                seen_generic_resources.add(r_id)
                                self._evaluate_generic_record(orig_sys, r_id, rec_data, file_id, findings, emails_lower, user_ids)
                        except Exception:
                            pass

            conn.close()
        except Exception:
            pass

    def _parse_raw_text_for_sql(
        self, text: str, file_id: str, origin: str,
        all_terms: Set[str], emails_lower: Set[str], user_ids: Set[str], findings: List[EvidenceFinding]
    ):
        """Fallback raw regex line parser for SQL files."""
        for line in text.splitlines():
            line_lower = line.lower()
            if any(term.lower() in line_lower for term in all_terms):
                res_match = re.search(r"'(account_\w+|search_\w+|analytics_\w+|support_\w+|export_\w+|data_flow_\w+|backup_\w+|audit_record_\w+|tombstone_\w+)'", line)
                if res_match:
                    res_id = res_match.group(1)
                    sys_id = self._system_from_resource_id(res_id)
                    findings.append(EvidenceFinding(
                        system_id=sys_id,
                        resource_id=res_id,
                        phase="FINDING",
                        operation="REPORT_REMAINING_RECORD",
                        state="PRESENT",
                        evidence_id=file_id,
                    ))

    def _parse_json_evidence(
        self,
        full_path: Path,
        file_id: str,
        origin: str,
        all_terms: Set[str],
        emails_lower: Set[str],
        user_ids: Set[str],
        findings: List[EvidenceFinding],
    ):
        """Parse structured JSON evidence files."""
        try:
            with open(full_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            # 1. service_resource_export (e.g. evidence_92)
            if "service_exports" in data:
                exports = data["service_exports"]
                
                # account_service
                for item in exports.get("account_service", {}).get("profile_lookups", []):
                    r_id = item.get("resource_id", "")
                    prof = item.get("profile")
                    status = item.get("status_code")
                    matched = False
                    if prof:
                        prof_dump = json.dumps(prof).lower()
                        matched = any(t.lower() in prof_dump for t in all_terms)
                    
                    if matched and prof:
                        findings.append(EvidenceFinding(
                            system_id="account_service",
                            resource_id=r_id,
                            phase="FINDING",
                            operation="REPORT_REMAINING_RECORD",
                            state="PRESENT",
                            evidence_id=file_id,
                        ))

                # analytics_platform
                for item in exports.get("analytics_platform", {}).get("profiles", []):
                    r_id = item.get("resource_id", "")
                    em = item.get("email")
                    ph = item.get("phone")
                    ref = item.get("customer_reference")
                    if (em and em.lower() in emails_lower) or (ref and ref in user_ids):
                        findings.append(EvidenceFinding(
                            system_id="analytics_platform",
                            resource_id=r_id,
                            phase="FINDING",
                            operation="REPORT_EXPOSED_PII",
                            state="PRESENT",
                            evidence_id=file_id,
                            details={"email": em, "phone": ph}
                        ))
                    elif ref and ref in user_ids and not em and not ph:
                        findings.append(EvidenceFinding(
                            system_id="analytics_platform",
                            resource_id=r_id,
                            phase="VERIFICATION",
                            operation="VERIFY_RECORD_ANONYMIZED",
                            state="ANONYMIZED",
                            evidence_id=file_id,
                        ))

                # backup_service
                for item in exports.get("backup_service", {}).get("restore_entries", []):
                    r_id = item.get("resource_id", "")
                    em = item.get("customer_email")
                    ref = item.get("customer_reference")
                    allowed = item.get("restore_allowed")
                    if (em and em.lower() in emails_lower) or (ref and ref in user_ids):
                        if allowed:
                            findings.append(EvidenceFinding(
                                system_id="backup_service",
                                resource_id=r_id,
                                phase="FINDING",
                                operation="REPORT_RESTORE_RISK",
                                state="ACTIVE",
                                evidence_id=file_id,
                            ))
                        else:
                            findings.append(EvidenceFinding(
                                system_id="backup_service",
                                resource_id=r_id,
                                phase="VERIFICATION",
                                operation="VERIFY_RESTORE_BLOCKED",
                                state="BLOCKED",
                                evidence_id=file_id,
                            ))

                # export_service
                for item in exports.get("export_service", {}).get("exports", []):
                    r_id = item.get("resource_id", "")
                    em = item.get("owner_email")
                    ref = item.get("customer_reference")
                    if (em and em.lower() in emails_lower) or (ref and ref in user_ids):
                        findings.append(EvidenceFinding(
                            system_id="export_service",
                            resource_id=r_id,
                            phase="FINDING",
                            operation="REPORT_REMAINING_RECORD",
                            state="PRESENT",
                            evidence_id=file_id,
                        ))

                # integration_service
                for item in exports.get("integration_service", {}).get("connectors", []):
                    r_id = item.get("resource_id", "")
                    em = item.get("customer_email")
                    ref = item.get("customer_reference")
                    enabled = item.get("enabled")
                    if (em and em.lower() in emails_lower) or (ref and ref in user_ids):
                        if enabled:
                            findings.append(EvidenceFinding(
                                system_id="integration_service",
                                resource_id=r_id,
                                phase="FINDING",
                                operation="REPORT_ACTIVE_DATA_FLOW",
                                state="ACTIVE",
                                evidence_id=file_id,
                            ))
                        else:
                            findings.append(EvidenceFinding(
                                system_id="integration_service",
                                resource_id=r_id,
                                phase="VERIFICATION",
                                operation="VERIFY_DATA_FLOW_DISABLED",
                                state="DISABLED",
                                evidence_id=file_id,
                            ))

                # search_service
                for item in exports.get("search_service", {}).get("index_queries", []):
                    r_id = item.get("resource_id", "")
                    q = item.get("query", "")
                    hits = item.get("hits", {}).get("documents", [])
                    matched_hits = [
                        doc for doc in hits
                        if any(t.lower() in json.dumps(doc).lower() for t in all_terms)
                    ]
                    if matched_hits or (q and any(t.lower() in q.lower() for t in all_terms)):
                        findings.append(EvidenceFinding(
                            system_id="search_service",
                            resource_id=r_id,
                            phase="FINDING",
                            operation="REPORT_REMAINING_RECORD",
                            state="PRESENT",
                            evidence_id=file_id,
                        ))

                # security_service
                for item in exports.get("security_service", {}).get("audit_records", []):
                    r_id = item.get("resource_id", "")
                    ref = item.get("subject_reference")
                    if ref and ref in user_ids:
                        findings.append(EvidenceFinding(
                            system_id="security_service",
                            resource_id=r_id,
                            phase="VERIFICATION",
                            operation="VERIFY_RECORD_PRESENT",
                            state="PRESENT",
                            evidence_id=file_id,
                        ))

                # support_platform
                for item in exports.get("support_platform", {}).get("tickets", []):
                    r_id = item.get("resource_id", "")
                    em = item.get("requester_email")
                    ref = item.get("customer_reference")
                    if (em and em.lower() in emails_lower) or (ref and ref in user_ids):
                        if em:
                            findings.append(EvidenceFinding(
                                system_id="support_platform",
                                resource_id=r_id,
                                phase="FINDING",
                                operation="REPORT_EXPOSED_PII",
                                state="PRESENT",
                                evidence_id=file_id,
                            ))
                        else:
                            findings.append(EvidenceFinding(
                                system_id="support_platform",
                                resource_id=r_id,
                                phase="VERIFICATION",
                                operation="VERIFY_RECORD_REDACTED",
                                state="REDACTED",
                                evidence_id=file_id,
                            ))

            # 2. customer_data_snapshot_bundle (e.g. evidence_51)
            elif "snapshots" in data:
                for snap in data.get("snapshots", []):
                    store = snap.get("data_store")
                    for rec in snap.get("records", []):
                        r_id = rec.get("resource_id", "")
                        sub = rec.get("subject_reference")
                        em = rec.get("email")
                        name = rec.get("name")
                        phone = rec.get("phone")
                        em_hash = rec.get("email_hash")
                        
                        if (sub and sub in user_ids) or (em and em.lower() in emails_lower):
                            if store == "identity_service":
                                if em or name or phone or em_hash:
                                    findings.append(EvidenceFinding(
                                        system_id="identity_service",
                                        resource_id=r_id,
                                        phase="FINDING",
                                        operation="REPORT_EXPOSED_PII",
                                        state="PRESENT",
                                        evidence_id=file_id,
                                        details={"exposed": {"name": name, "email": em, "phone": phone, "hash": em_hash}}
                                    ))
                                else:
                                    findings.append(EvidenceFinding(
                                        system_id="identity_service",
                                        resource_id=r_id,
                                        phase="VERIFICATION",
                                        operation="VERIFY_RECORD_REDACTED",
                                        state="REDACTED",
                                        evidence_id=file_id,
                                    ))
                            elif store == "security_service":
                                findings.append(EvidenceFinding(
                                    system_id="security_service",
                                    resource_id=r_id,
                                    phase="VERIFICATION",
                                    operation="VERIFY_RECORD_PRESENT",
                                    state="PRESENT",
                                    evidence_id=file_id,
                                ))

            # 3. customer_export_jobs (e.g. evidence_59)
            elif "collection" in data and data.get("collection") == "customer_export_jobs":
                for rec in data.get("records", []):
                    r_id = rec.get("resource_id", "")
                    owner = rec.get("owner_email", "")
                    if owner and owner.lower() in emails_lower:
                        if rec.get("download_available"):
                            findings.append(EvidenceFinding(
                                system_id="export_service",
                                resource_id=r_id,
                                phase="FINDING",
                                operation="REPORT_REMAINING_RECORD",
                                state="PRESENT",
                                evidence_id=file_id,
                            ))

            # 4. customer_analytics_reports (e.g. evidence_56)
            elif "collection" in data and data.get("collection") == "customer_analytics_reports":
                for rec in data.get("records", []):
                    r_id = rec.get("resource_id", "")
                    uid = rec.get("user_id")
                    em = rec.get("email")
                    if (em and em.lower() in emails_lower) or (uid and uid in user_ids):
                        if em:
                            findings.append(EvidenceFinding(
                                system_id="analytics_platform",
                                resource_id=r_id,
                                phase="FINDING",
                                operation="REPORT_EXPOSED_PII",
                                state="PRESENT",
                                evidence_id=file_id,
                            ))
                        else:
                            findings.append(EvidenceFinding(
                                system_id="analytics_platform",
                                resource_id=r_id,
                                phase="VERIFICATION",
                                operation="VERIFY_RECORD_ANONYMIZED",
                                state="ANONYMIZED",
                                evidence_id=file_id,
                            ))

        except Exception:
            pass

    def _parse_log_evidence(
        self,
        full_path: Path,
        file_id: str,
        origin: str,
        all_terms: Set[str],
        emails_lower: Set[str],
        user_ids: Set[str],
        findings: List[EvidenceFinding],
    ):
        """
        Parse structured service event logs with trace_id correlation across multi-line events.
        """
        try:
            with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()

            # First pass: collect and merge properties by trace_id
            trace_to_props: Dict[str, Dict[str, str]] = defaultdict(dict)
            user_matched_traces: Set[str] = set()
            standalone_events: List[Dict[str, str]] = []

            for line in lines:
                matches = re.findall(r'(\w+)=(?:"([^"]*)"|(\S+))', line)
                props = {k: (v_quoted if v_quoted else v_unquoted) for k, v_quoted, v_unquoted in matches}
                line_lower = line.lower()

                trace_id = props.get("trace_id", "")
                is_matched = any(term.lower() in line_lower for term in all_terms)

                if trace_id:
                    trace_to_props[trace_id].update(props)
                    if is_matched:
                        user_matched_traces.add(trace_id)
                elif is_matched:
                    standalone_events.append(props)

            # Gather unified target events
            target_events: List[Dict[str, str]] = list(standalone_events)
            for t_id in user_matched_traces:
                target_events.append(trace_to_props[t_id])

            # Process collected events
            seen_resources = set()
            for props in target_events:
                r_id = props.get("resource_id", "")
                service = props.get("service", "")
                event = props.get("event", "")

                if not r_id or r_id in seen_resources:
                    continue

                if not service:
                    service = self._system_from_resource_id(r_id)

                seen_resources.add(r_id)

                if event == "index_query_completed" and props.get("result") == "hit":
                    findings.append(EvidenceFinding(
                        system_id="search_service",
                        resource_id=r_id,
                        phase="FINDING",
                        operation="REPORT_REMAINING_RECORD",
                        state="PRESENT",
                        evidence_id=file_id,
                    ))

                elif service == "analytics_platform" and event == "contact_lookup_completed" and str(props.get("rows", "")) in ("1", "true"):
                    findings.append(EvidenceFinding(
                        system_id="analytics_platform",
                        resource_id=r_id,
                        phase="FINDING",
                        operation="REPORT_REMAINING_RECORD",
                        state="PRESENT",
                        evidence_id=file_id,
                    ))

                elif event in ("analytics_identity_scan",) or (
                    service == "analytics_platform" and (
                        (props.get("email") and props.get("email") != "null") or
                        (props.get("phone") and props.get("phone") != "null") or
                        props.get("matched_value")
                    )
                ):
                    findings.append(EvidenceFinding(
                        system_id="analytics_platform",
                        resource_id=r_id,
                        phase="FINDING",
                        operation="REPORT_EXPOSED_PII",
                        state="PRESENT",
                        evidence_id=file_id,
                    ))

                elif event == "analytics_profile_read_completed":
                    findings.append(EvidenceFinding(
                        system_id="analytics_platform",
                        resource_id=r_id,
                        phase="VERIFICATION",
                        operation="VERIFY_RECORD_ANONYMIZED",
                        state="ANONYMIZED",
                        evidence_id=file_id,
                    ))

                elif event in ("connector_heartbeat", "connector_config_read_completed"):
                    is_enabled = props.get("enabled", "").lower() in ("true", "1")
                    if is_enabled:
                        findings.append(EvidenceFinding(
                            system_id="integration_service",
                            resource_id=r_id,
                            phase="FINDING",
                            operation="REPORT_ACTIVE_DATA_FLOW",
                            state="ACTIVE",
                            evidence_id=file_id,
                        ))
                    else:
                        findings.append(EvidenceFinding(
                            system_id="integration_service",
                            resource_id=r_id,
                            phase="VERIFICATION",
                            operation="VERIFY_DATA_FLOW_DISABLED",
                            state="DISABLED",
                            evidence_id=file_id,
                        ))

                elif event in ("restore_candidate_evaluated", "restore_policy_read_completed"):
                    is_blocked = props.get("deletion_block", "").lower() == "true" or props.get("restore_allowed", "").lower() in ("false", "0")
                    if is_blocked:
                        findings.append(EvidenceFinding(
                            system_id="backup_service",
                            resource_id=r_id,
                            phase="VERIFICATION",
                            operation="VERIFY_RESTORE_BLOCKED",
                            state="BLOCKED",
                            evidence_id=file_id,
                        ))
                    else:
                        findings.append(EvidenceFinding(
                            system_id="backup_service",
                            resource_id=r_id,
                            phase="FINDING",
                            operation="REPORT_RESTORE_RISK",
                            state="ACTIVE",
                            evidence_id=file_id,
                        ))

                elif service == "support_replica" or "replica" in service:
                    if props.get("marker_found") == "false" or str(props.get("rows", "")) in ("1", "true") or event in ("contact_query_completed", "deletion_marker_check"):
                        findings.append(EvidenceFinding(
                            system_id="support_platform",
                            resource_id=r_id,
                            phase="FINDING",
                            operation="REPORT_REMAINING_RECORD",
                            state="PRESENT",
                            evidence_id=file_id,
                        ))

                elif event in ("message_pii_scan", "attachment_pii_scan") or (
                    service == "support_platform" and (
                        (props.get("requester_email") and props.get("requester_email") != "null") or
                        (props.get("requester_name") and props.get("requester_name") != "null") or
                        props.get("matched_value")
                    )
                ):
                    findings.append(EvidenceFinding(
                        system_id="support_platform",
                        resource_id=r_id,
                        phase="FINDING",
                        operation="REPORT_EXPOSED_PII",
                        state="PRESENT",
                        evidence_id=file_id,
                    ))

                elif event == "support_ticket_read_completed":
                    findings.append(EvidenceFinding(
                        system_id="support_platform",
                        resource_id=r_id,
                        phase="VERIFICATION",
                        operation="VERIFY_RECORD_REDACTED",
                        state="REDACTED",
                        evidence_id=file_id,
                    ))

                elif event == "audit_record_read_completed":
                    findings.append(EvidenceFinding(
                        system_id="security_service",
                        resource_id=r_id,
                        phase="VERIFICATION",
                        operation="VERIFY_RECORD_PRESENT",
                        state="PRESENT",
                        evidence_id=file_id,
                    ))

        except Exception:
            pass

    def _parse_text_evidence(
        self,
        full_path: Path,
        file_id: str,
        origin: str,
        all_terms: Set[str],
        emails_lower: Set[str],
        user_ids: Set[str],
        findings: List[EvidenceFinding],
    ):
        """Parse structured text handover notes (e.g. evidence_03)."""
        try:
            with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()

            for line in lines:
                line_lower = line.lower()
                if not any(term.lower() in line_lower for term in all_terms):
                    continue

                parts = [p.strip() for p in line.split("|")]
                if len(parts) >= 5:
                    sys_id = parts[1]
                    res_id = parts[2]
                    status = parts[4].upper()

                    # Security audit log being FOUND is a policy-required compliant retention!
                    if sys_id == "security_service":
                        findings.append(EvidenceFinding(
                            system_id=sys_id,
                            resource_id=res_id,
                            phase="VERIFICATION",
                            operation="VERIFY_RECORD_PRESENT",
                            state="PRESENT",
                            evidence_id=file_id,
                        ))
                    elif status in ("IDENTIFIABLE",):
                        findings.append(EvidenceFinding(
                            system_id=sys_id,
                            resource_id=res_id,
                            phase="FINDING",
                            operation="REPORT_EXPOSED_PII",
                            state="PRESENT",
                            evidence_id=file_id,
                        ))
                    elif status in ("FOUND",):
                        findings.append(EvidenceFinding(
                            system_id=sys_id,
                            resource_id=res_id,
                            phase="FINDING",
                            operation="REPORT_REMAINING_RECORD",
                            state="PRESENT",
                            evidence_id=file_id,
                        ))
                    elif status in ("ACTIVE",):
                        if sys_id == "backup_service":
                            findings.append(EvidenceFinding(
                                system_id=sys_id,
                                resource_id=res_id,
                                phase="FINDING",
                                operation="REPORT_RESTORE_RISK",
                                state="ACTIVE",
                                evidence_id=file_id,
                            ))
                        else:
                            findings.append(EvidenceFinding(
                                system_id=sys_id,
                                resource_id=res_id,
                                phase="FINDING",
                                operation="REPORT_ACTIVE_DATA_FLOW",
                                state="ACTIVE",
                                evidence_id=file_id,
                            ))
                    elif status in ("ANONYMIZED",):
                        findings.append(EvidenceFinding(
                            system_id=sys_id,
                            resource_id=res_id,
                            phase="VERIFICATION",
                            operation="VERIFY_RECORD_ANONYMIZED",
                            state="ANONYMIZED",
                            evidence_id=file_id,
                        ))
                    elif status in ("REDACTED",):
                        findings.append(EvidenceFinding(
                            system_id=sys_id,
                            resource_id=res_id,
                            phase="VERIFICATION",
                            operation="VERIFY_RECORD_REDACTED",
                            state="REDACTED",
                            evidence_id=file_id,
                        ))
                    elif status in ("BLOCKED",):
                        findings.append(EvidenceFinding(
                            system_id=sys_id,
                            resource_id=res_id,
                            phase="VERIFICATION",
                            operation="VERIFY_RESTORE_BLOCKED",
                            state="BLOCKED",
                            evidence_id=file_id,
                        ))
                    elif status in ("DISABLED",):
                        findings.append(EvidenceFinding(
                            system_id=sys_id,
                            resource_id=res_id,
                            phase="VERIFICATION",
                            operation="VERIFY_DATA_FLOW_DISABLED",
                            state="DISABLED",
                            evidence_id=file_id,
                        ))
        except Exception:
            pass

    def _parse_pdf_evidence(
        self,
        full_path: Path,
        file_id: str,
        origin: str,
        all_terms: Set[str],
        emails_lower: Set[str],
        user_ids: Set[str],
        findings: List[EvidenceFinding],
    ):
        """Parse text extracted from PDF documents (e.g. delivery attachments)."""
        strings = self.extract_pdf_strings(full_path)
        combined = " ".join(strings).lower()

        if any(term.lower() in combined for term in all_terms):
            res_match = re.search(r"\b(support_\w+|account_\w+|search_\w+)\b", combined)
            if res_match:
                res_id = res_match.group(1)
                sys_id = self._system_from_resource_id(res_id)
                findings.append(EvidenceFinding(
                    system_id=sys_id,
                    resource_id=res_id,
                    phase="FINDING",
                    operation="REPORT_REMAINING_RECORD",
                    state="PRESENT",
                    evidence_id=file_id,
                ))

    def _evaluate_generic_record(
        self,
        origin_sys: str,
        res_id: str,
        rec_data: Dict[str, Any],
        file_id: str,
        findings: List[EvidenceFinding],
        emails_lower: Set[str],
        user_ids: Set[str],
    ):
        """Evaluates generic JSON record for policy compliance."""
        sys_id = origin_sys or self._system_from_resource_id(res_id)
        
        if sys_id == "account_service":
            status = rec_data.get("account_status")
            if status != "DELETED":
                findings.append(EvidenceFinding(
                    system_id="account_service",
                    resource_id=res_id,
                    phase="FINDING",
                    operation="REPORT_REMAINING_RECORD",
                    state="PRESENT",
                    evidence_id=file_id,
                ))

        elif sys_id == "search_service":
            findings.append(EvidenceFinding(
                system_id="search_service",
                resource_id=res_id,
                phase="FINDING",
                operation="REPORT_REMAINING_RECORD",
                state="PRESENT",
                evidence_id=file_id,
            ))

        elif sys_id == "analytics_platform":
            em = rec_data.get("email")
            ph = rec_data.get("phone")
            if em or ph:
                findings.append(EvidenceFinding(
                    system_id="analytics_platform",
                    resource_id=res_id,
                    phase="FINDING",
                    operation="REPORT_EXPOSED_PII",
                    state="PRESENT",
                    evidence_id=file_id,
                ))
            else:
                findings.append(EvidenceFinding(
                    system_id="analytics_platform",
                    resource_id=res_id,
                    phase="VERIFICATION",
                    operation="VERIFY_RECORD_ANONYMIZED",
                    state="ANONYMIZED",
                    evidence_id=file_id,
                ))

        elif sys_id == "integration_service":
            enabled = rec_data.get("enabled")
            if enabled:
                findings.append(EvidenceFinding(
                    system_id="integration_service",
                    resource_id=res_id,
                    phase="FINDING",
                    operation="REPORT_ACTIVE_DATA_FLOW",
                    state="ACTIVE",
                    evidence_id=file_id,
                ))
            else:
                findings.append(EvidenceFinding(
                    system_id="integration_service",
                    resource_id=res_id,
                    phase="VERIFICATION",
                    operation="VERIFY_DATA_FLOW_DISABLED",
                    state="DISABLED",
                    evidence_id=file_id,
                ))

        elif sys_id == "backup_service":
            allowed = rec_data.get("restore_allowed")
            if allowed:
                findings.append(EvidenceFinding(
                    system_id="backup_service",
                    resource_id=res_id,
                    phase="FINDING",
                    operation="REPORT_RESTORE_RISK",
                    state="ACTIVE",
                    evidence_id=file_id,
                ))
            else:
                findings.append(EvidenceFinding(
                    system_id="backup_service",
                    resource_id=res_id,
                    phase="VERIFICATION",
                    operation="VERIFY_RESTORE_BLOCKED",
                    state="BLOCKED",
                    evidence_id=file_id,
                ))

        elif sys_id == "security_service":
            findings.append(EvidenceFinding(
                system_id="security_service",
                resource_id=res_id,
                phase="VERIFICATION",
                operation="VERIFY_RECORD_PRESENT",
                state="PRESENT",
                evidence_id=file_id,
            ))

    def _system_from_resource_id(self, res_id: str) -> str:
        """Helper to determine system_id from resource_id prefix."""
        prefix_map = {
            "account_": "account_service",
            "search_": "search_service",
            "analytics_": "analytics_platform",
            "support_": "support_platform",
            "export_": "export_service",
            "data_flow_": "integration_service",
            "backup_": "backup_service",
            "audit_record_": "security_service",
            "tombstone_": "identity_service",
        }
        for prefix, sys_name in prefix_map.items():
            if res_id.startswith(prefix):
                return sys_name
        return "unknown_service"
