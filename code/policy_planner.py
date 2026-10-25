"""Policy Planner for Ghost Data Still Exists.

Maps discovered findings to required policy actions according to deletion_rules.csv,
constructs complete ordered remediation plans and verification steps,
and handles compliant complete cases and account tombstones.
"""

from __future__ import annotations

import csv
import datetime
import glob
import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from evidence_analyzer import EvidenceAnalyzer
from identity_resolver import IdentityCluster, IdentityResolver
from intent_classifier import is_deletion_request
from serializer import renumber_steps, sort_steps


class PolicyPlanner:
    """Orchestrates intent classification, identity resolution, evidence forensics,
    and policy-driven remediation planning.
    """

    def __init__(self, dataset_dir: str = "dataset"):
        self.dataset_dir = Path(dataset_dir)
        self.resolver = IdentityResolver(
            str(self.dataset_dir / "user_identities.csv"),
            str(self.dataset_dir / "user_audit_log.csv"),
        )
        self.analyzer = EvidenceAnalyzer(str(self.dataset_dir))
        self.warnings: List[str] = []
        
        self.user_to_account: Dict[str, str] = {}
        self.email_to_account: Dict[str, str] = {}
        self.user_to_audit: Dict[str, str] = {}
        self.email_to_audit: Dict[str, str] = {}
        self.account_to_evidence: Dict[str, str] = {}
        self.audit_to_evidence: Dict[str, str] = {}
        self.file_path_to_id: Dict[str, str] = {}

        self._load_evidence_manifest()
        self._load_system_activity()
        self._build_forensic_entity_maps()

    def _load_evidence_manifest(self):
        ev_file = self.dataset_dir / "evidence_files.csv"
        if ev_file.exists():
            with open(ev_file, "r", encoding="utf-8") as f:
                for row in csv.DictReader(f):
                    norm_path = row.get("file_path", "").replace("\\", "/")
                    self.file_path_to_id[norm_path] = row.get("file_id", "")

    def _load_system_activity(self):
        act_file = self.dataset_dir / "system_activity.csv"
        if act_file.exists():
            with open(act_file, "r", encoding="utf-8") as f:
                self.activities = list(csv.DictReader(f))
        else:
            self.activities = []
        self.del_acts = [a for a in self.activities if a.get("source_system") == "deletion_worker"]

    def _build_forensic_entity_maps(self):
        """Forensically maps user identities and emails to account_service and security_service resources."""
        # 1. Base identity canonical mapping: user_01 -> account_001
        ident_file = self.dataset_dir / "user_identities.csv"
        if ident_file.exists():
            with open(ident_file, "r", encoding="utf-8") as f:
                for r in csv.DictReader(f):
                    uid = r.get("user_id", "")
                    m = re.match(r"user_(\d+)", uid)
                    if m:
                        n = int(m.group(1))
                        canonical_acc = f"account_{n:03d}" if n < 100 else f"account_{n}"
                        self.user_to_account[uid] = canonical_acc
                        if r.get("email"):
                            self.email_to_account[r["email"].strip().lower()] = canonical_acc

        # 2. SQL database snapshots
        for p in glob.glob(str(self.dataset_dir / "evidence/databases/*.sql")):
            rel_path = str(Path(p).relative_to(self.dataset_dir)).replace("\\", "/")
            fid = self.file_path_to_id.get(rel_path, "")
            try:
                with open(p, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        m_sql = re.findall(r"'(account_\d+)','(user_\d+)','[^']*','([^']*)'", line)
                        for acc, u, em in m_sql:
                            self.user_to_account[u] = acc
                            if em:
                                self.email_to_account[em.strip().lower()] = acc
                            if fid:
                                self.account_to_evidence[acc] = fid

                        m_json = re.findall(r'"resource_id":"(account_\d+)"[^\}]*"customer_reference":"(user_\d+)"', line)
                        for acc, u in m_json:
                            self.user_to_account[u] = acc
                            if fid:
                                self.account_to_evidence[acc] = fid

                        m_aud = re.findall(r'(user_\d+)[^\n\r]*(audit_record_\d+)', line)
                        for u, aud in m_aud:
                            self.user_to_audit[u] = aud
                            if fid:
                                self.audit_to_evidence[aud] = fid

                        m_aud2 = re.findall(r'(audit_record_\d+)[^\n\r]*(user_\d+)', line)
                        for aud, u in m_aud2:
                            self.user_to_audit[u] = aud
                            if fid:
                                self.audit_to_evidence[aud] = fid
            except Exception:
                pass

        # 3. Records JSON
        for p in glob.glob(str(self.dataset_dir / "evidence/records/*.json")):
            rel_path = str(Path(p).relative_to(self.dataset_dir)).replace("\\", "/")
            fid = self.file_path_to_id.get(rel_path, "")
            try:
                with open(p, "r", encoding="utf-8") as f:
                    data = json.load(f)
                if isinstance(data, dict) and "snapshots" in data:
                    for snap in data["snapshots"]:
                        ds = snap.get("data_store")
                        if ds == "account_service":
                            for r in snap.get("records", []):
                                ref = r.get("customer_reference")
                                rid = r.get("resource_id")
                                em = r.get("email")
                                if ref and rid:
                                    self.user_to_account[ref] = rid
                                if em and rid:
                                    self.email_to_account[em.lower()] = rid
                                if rid and fid:
                                    self.account_to_evidence[rid] = fid
                        elif ds == "security_service":
                            for r in snap.get("records", []):
                                sub = r.get("subject_reference")
                                rid = r.get("resource_id")
                                if sub and rid:
                                    self.user_to_audit[sub] = rid
                                if rid and fid:
                                    self.audit_to_evidence[rid] = fid
                if isinstance(data, dict) and "service_exports" in data:
                    sec = data["service_exports"].get("security_service", {})
                    for r in sec.get("audit_records", []):
                        sub = r.get("subject_reference")
                        rid = r.get("resource_id")
                        if sub and rid:
                            self.user_to_audit[sub] = rid
                        if rid and fid:
                            self.audit_to_evidence[rid] = fid
                    acc = data["service_exports"].get("account_service", {})
                    for r in acc.get("profile_lookups", []):
                        prof = r.get("profile")
                        rid = r.get("resource_id")
                        if isinstance(prof, dict) and rid:
                            ref = prof.get("customer_reference")
                            em = prof.get("email")
                            if ref:
                                self.user_to_account[ref] = rid
                            if em:
                                self.email_to_account[em.lower()] = rid
                        if rid and fid:
                            self.account_to_evidence[rid] = fid
            except Exception:
                pass

        # 4. Text Handover notes
        for p in glob.glob(str(self.dataset_dir / "evidence/records/*.txt")):
            rel_path = str(Path(p).relative_to(self.dataset_dir)).replace("\\", "/")
            fid = self.file_path_to_id.get(rel_path, "")
            try:
                with open(p, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        parts = [x.strip() for x in line.split("|")]
                        if len(parts) >= 6:
                            sys_id = parts[1].strip()
                            rid = parts[2].strip()
                            target = parts[5].strip()
                            if sys_id == "account_service" and rid.startswith("account_"):
                                if "@" in target:
                                    self.email_to_account[target.lower()] = rid
                                elif target.startswith("user_"):
                                    self.user_to_account[target] = rid
                                if fid:
                                    self.account_to_evidence[rid] = fid
                            elif sys_id == "security_service" and rid.startswith("audit_record_"):
                                if target.startswith("user_"):
                                    self.user_to_audit[target] = rid
                                elif "@" in target:
                                    self.email_to_audit[target.lower()] = rid
                                if fid:
                                    self.audit_to_evidence[rid] = fid
            except Exception:
                pass

        # 5. Logs (both JSON and structured text)
        for p in glob.glob(str(self.dataset_dir / "evidence/logs/*.log")):
            rel_path = str(Path(p).relative_to(self.dataset_dir)).replace("\\", "/")
            fid = self.file_path_to_id.get(rel_path, "")
            try:
                trace_acc: Dict[str, str] = {}
                trace_aud: Dict[str, str] = {}
                trace_u: Dict[str, str] = {}
                trace_e: Dict[str, str] = {}
                with open(p, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        idx = line.find("{")
                        if idx != -1:
                            try:
                                obj = json.loads(line[idx:].strip())
                                tr = obj.get("trace_id") or obj.get("requestId")
                                rid = obj.get("resource_id")
                                lk = obj.get("lookup_key")
                                sub = obj.get("subject_reference") or obj.get("subject_ref") or obj.get("customer_reference")
                                if rid and rid.startswith("account_"):
                                    if tr: trace_acc[tr] = rid
                                    if lk: self.email_to_account[lk.lower()] = rid
                                    if sub: self.user_to_account[sub] = rid
                                    if fid: self.account_to_evidence[rid] = fid
                                if rid and rid.startswith("audit_record_"):
                                    if tr: trace_aud[tr] = rid
                                    if lk and lk.startswith("user_"): self.user_to_audit[lk] = rid
                                    if sub: self.user_to_audit[sub] = rid
                                    if fid: self.audit_to_evidence[rid] = fid
                                if tr:
                                    if lk and "@" in lk: trace_e[tr] = lk.lower()
                                    if lk and lk.startswith("user_"): trace_u[tr] = lk
                                    if sub and sub.startswith("user_"): trace_u[tr] = sub
                            except Exception:
                                pass
                        else:
                            m_tr = re.search(r'(?:trace_id|requestId)=([^\s,"]+)', line)
                            tr = m_tr.group(1) if m_tr else None
                            m_a = re.search(r'resource_id=["\']?(account_\d+)', line)
                            m_aud = re.search(r'resource_id=["\']?(audit_record_\d+)', line)
                            m_u = re.search(r'(?:subject_ref|subject_reference|customer_reference|correlation_key)=["\']?(user_\d+)', line)
                            m_e = re.search(r'(?:lookup_key|correlation_key)=["\']?([\w\.-]+@[\w\.-]+)', line)
                            if m_a:
                                acc = m_a.group(1)
                                if tr: trace_acc[tr] = acc
                                if m_u: self.user_to_account[m_u.group(1)] = acc
                                if m_e: self.email_to_account[m_e.group(1).lower()] = acc
                                if fid: self.account_to_evidence[acc] = fid
                            if m_aud:
                                aud = m_aud.group(1)
                                if tr: trace_aud[tr] = aud
                                if m_u: self.user_to_audit[m_u.group(1)] = aud
                                if fid: self.audit_to_evidence[aud] = fid
                            if m_u and tr: trace_u[tr] = m_u.group(1)
                            if m_e and tr: trace_e[tr] = m_e.group(1).lower()

                for tr, acc in trace_acc.items():
                    if tr in trace_u: self.user_to_account[trace_u[tr]] = acc
                    if tr in trace_e: self.email_to_account[trace_e[tr]] = acc
                for tr, aud in trace_aud.items():
                    if tr in trace_u: self.user_to_audit[trace_u[tr]] = aud
                    if tr in trace_e: self.email_to_audit[trace_e[tr]] = aud
            except Exception:
                pass

        # 6. System Activity (LINK_RESOURCE_IDENTITY mappings)
        for act in self.activities:
            det = act.get("details", "")
            m_link = re.search(r"linked (account_\d+)[^\)]*\) to ([\w\.-]+@[\w\.-]+) and (user_\d+)", det)
            if m_link:
                a_id, em, u_id = m_link.group(1), m_link.group(2).lower(), m_link.group(3)
                self.user_to_account[u_id] = a_id
                self.email_to_account[em] = a_id

    def resolve_account_id(self, req: Dict[str, Any], cluster: IdentityCluster) -> str:
        """Determines the primary account_service resource_id strictly from cluster entities."""
        # 1. Resolve against cluster emails first (more specific in case of email overrides)
        for email in cluster.emails:
            em_norm = email.strip().lower()
            if em_norm in self.email_to_account and self.email_to_account[em_norm]:
                return self.email_to_account[em_norm]

        # 2. Resolve against cluster user_ids
        for uid in cluster.user_ids:
            if uid in self.user_to_account and self.user_to_account[uid]:
                return self.user_to_account[uid]
        if cluster.primary_user_id and cluster.primary_user_id in self.user_to_account and self.user_to_account[cluster.primary_user_id]:
            return self.user_to_account[cluster.primary_user_id]

        self.warnings.append(f"UNRESOLVED_ACCOUNT: case {req.get('case_id')} primary_user_id {cluster.primary_user_id}")
        return ""

    def resolve_audit_id(self, req: Dict[str, Any], cluster: IdentityCluster) -> str:
        """Determines the security_service audit_record strictly from cluster entities."""
        for uid in cluster.user_ids:
            if uid in self.user_to_audit and self.user_to_audit[uid]:
                return self.user_to_audit[uid]
        if cluster.primary_user_id and cluster.primary_user_id in self.user_to_audit and self.user_to_audit[cluster.primary_user_id]:
            return self.user_to_audit[cluster.primary_user_id]

        for email in cluster.emails:
            em_norm = email.strip().lower()
            if em_norm in self.email_to_audit and self.email_to_audit[em_norm]:
                return self.email_to_audit[em_norm]

        self.warnings.append(f"UNRESOLVED_AUDIT: case {req.get('case_id')} primary_user_id {cluster.primary_user_id}")
        return ""

    def _resolve_verification_evidence_id(
        self,
        resource_id: str,
        system_id: str,
        eligible_files: List[Dict[str, Any]],
    ) -> str:
        """Resolves legitimate evidence_id for a verification step matching entity schema and cutoff."""
        # 1. Direct evidence mapping for resource
        if system_id == "account_service" and resource_id in self.account_to_evidence:
            eid = self.account_to_evidence[resource_id]
            if any(f.get("file_id") == eid for f in eligible_files):
                return eid
        if system_id == "security_service" and resource_id in self.audit_to_evidence:
            eid = self.audit_to_evidence[resource_id]
            if any(f.get("file_id") == eid for f in eligible_files):
                return eid

        # 2. Check eligible files in reverse chronological order (newest snapshot closest to audit_at first)
        system_origins = {
            "account_service": [
                "service_readback_logs",
                "account_admin_portal",
                "customer_account_service",
                "customer_account_failover_replica_capture",
                "service_resource_export",
                "customer_data_inventory_capture",
                "records_assurance_snapshot_bundle",
                "central_observability_export",
                "account_history_service",
            ],
            "security_service": [
                "service_readback_logs",
                "security_audit_service",
                "security_service",
                "service_resource_export",
                "records_assurance_snapshot_bundle",
                "security_audit_ledger",
                "central_observability_export",
            ],
            "analytics_platform": [
                "service_readback_logs",
                "analytics_platform",
                "service_resource_export",
                "records_assurance_snapshot_bundle",
            ],
        }
        allowed_origins = system_origins.get(system_id, ["service_resource_export", "records_assurance_snapshot_bundle", "service_readback_logs"])
        for f in reversed(eligible_files):
            if f.get("origin") in allowed_origins:
                return f.get("file_id", "")

        self.warnings.append(f"UNRESOLVED_EVIDENCE: resource {resource_id} system {system_id}")
        return ""

    def plan_case(self, req: Dict[str, Any]) -> Tuple[str, List[Dict[str, Any]]]:
        """Main entry point: audits a single deletion request against forensics and policy.

        Returns (deletion_status, canonical_steps_list).
        """
        cid = req.get("case_id", "")
        email = req.get("email", "")
        req_text = req.get("request_text", "")
        audit_at = req.get("audit_at", "")
        requested_at = req.get("requested_at", "")

        # 1. Intent check
        if not is_deletion_request(req_text):
            return "NOT_APPLICABLE", []

        # 2. Identity resolution (cluster valid up to audit_at)
        cluster = self.resolver.resolve(email, audit_at)
        if not cluster:
            self.warnings.append(f"UNRESOLVED_CLUSTER: case {cid} email {email}")
            return "INCOMPLETE", []

        # 3. Evidence analysis
        raw_findings = self.analyzer.analyze_case(cluster, audit_at, requested_at)

        # Filter strictly finding operations
        findings = [
            f for f in raw_findings
            if f.operation in [
                "REPORT_REMAINING_RECORD",
                "REPORT_EXPOSED_PII",
                "REPORT_ACTIVE_DATA_FLOW",
                "REPORT_RESTORE_RISK",
            ]
        ]

        if findings:
            deletion_status = "INCOMPLETE"
            steps: List[Dict[str, Any]] = []

            # A. Phase 1: FINDINGS
            for f in findings:
                steps.append({
                    "phase": "FINDING",
                    "system_id": f.system_id,
                    "resource_id": f.resource_id,
                    "operation": f.operation,
                    "state": f.state,
                    "evidence_id": f.evidence_id,
                })

            # B. Phase 2: REMEDIATION & Phase 3: POST-REMEDIATION VERIFICATION
            rem_steps: List[Dict[str, Any]] = []
            ver_steps: List[Dict[str, Any]] = []
            seen_ver: Set[Tuple[str, str]] = set()

            for f in findings:
                op = f.operation
                sys_id = f.system_id
                res_id = f.resource_id

                if op == "REPORT_ACTIVE_DATA_FLOW":
                    rem_steps.append({
                        "phase": "REMEDIATION",
                        "system_id": sys_id,
                        "resource_id": res_id,
                        "operation": "DISABLE_DATA_FLOW",
                        "state": "DISABLED",
                        "evidence_id": "",
                    })
                    ver_steps.append({
                        "phase": "VERIFICATION",
                        "system_id": sys_id,
                        "resource_id": res_id,
                        "operation": "VERIFY_DATA_FLOW_DISABLED",
                        "state": "DISABLED",
                        "evidence_id": "",
                    })
                    seen_ver.add((sys_id, res_id))

                elif op == "REPORT_RESTORE_RISK":
                    rem_steps.append({
                        "phase": "REMEDIATION",
                        "system_id": sys_id,
                        "resource_id": res_id,
                        "operation": "BLOCK_RESTORE",
                        "state": "BLOCKED",
                        "evidence_id": "",
                    })
                    ver_steps.append({
                        "phase": "VERIFICATION",
                        "system_id": sys_id,
                        "resource_id": res_id,
                        "operation": "VERIFY_RESTORE_BLOCKED",
                        "state": "BLOCKED",
                        "evidence_id": "",
                    })
                    seen_ver.add((sys_id, res_id))

                elif op == "REPORT_REMAINING_RECORD":
                    rem_steps.append({
                        "phase": "REMEDIATION",
                        "system_id": sys_id,
                        "resource_id": res_id,
                        "operation": "DELETE_RECORD",
                        "state": "ABSENT",
                        "evidence_id": "",
                    })
                    ver_steps.append({
                        "phase": "VERIFICATION",
                        "system_id": sys_id,
                        "resource_id": res_id,
                        "operation": "VERIFY_RECORD_ABSENT",
                        "state": "ABSENT",
                        "evidence_id": "",
                    })
                    seen_ver.add((sys_id, res_id))

                elif op == "REPORT_EXPOSED_PII":
                    if sys_id == "analytics_platform":
                        rem_steps.append({
                            "phase": "REMEDIATION",
                            "system_id": sys_id,
                            "resource_id": res_id,
                            "operation": "ANONYMIZE_RECORD",
                            "state": "ANONYMIZED",
                            "evidence_id": "",
                        })
                        ver_steps.append({
                            "phase": "VERIFICATION",
                            "system_id": sys_id,
                            "resource_id": res_id,
                            "operation": "VERIFY_RECORD_ANONYMIZED",
                            "state": "ANONYMIZED",
                            "evidence_id": "",
                        })
                    else:
                        rem_steps.append({
                            "phase": "REMEDIATION",
                            "system_id": sys_id,
                            "resource_id": res_id,
                            "operation": "REDACT_RECORD",
                            "state": "REDACTED",
                            "evidence_id": "",
                        })
                        ver_steps.append({
                            "phase": "VERIFICATION",
                            "system_id": sys_id,
                            "resource_id": res_id,
                            "operation": "VERIFY_RECORD_REDACTED",
                            "state": "REDACTED",
                            "evidence_id": "",
                        })
                    seen_ver.add((sys_id, res_id))

            # Primary account profile absent check
            acc_id = self.resolve_account_id(req, cluster)
            if acc_id and ("account_service", acc_id) not in seen_ver:
                ver_steps.append({
                    "phase": "VERIFICATION",
                    "system_id": "account_service",
                    "resource_id": acc_id,
                    "operation": "VERIFY_RECORD_ABSENT",
                    "state": "ABSENT",
                    "evidence_id": "",
                })

            # Security audit log present check
            aud_id = self.resolve_audit_id(req, cluster)
            if aud_id and ("security_service", aud_id) not in seen_ver:
                ver_steps.append({
                    "phase": "VERIFICATION",
                    "system_id": "security_service",
                    "resource_id": aud_id,
                    "operation": "VERIFY_RECORD_PRESENT",
                    "state": "PRESENT",
                    "evidence_id": "",
                })

            all_steps = steps + rem_steps + ver_steps
            sorted_steps = sort_steps(all_steps)
            return deletion_status, renumber_steps(sorted_steps)

        else:
            deletion_status = "COMPLETE"
            ver_steps: List[Dict[str, Any]] = []

            # 1. Collect verification facts discovered in eligible evidence
            for f in raw_findings:
                if f.phase == "VERIFICATION":
                    ver_steps.append({
                        "phase": "VERIFICATION",
                        "system_id": f.system_id,
                        "resource_id": f.resource_id,
                        "operation": f.operation,
                        "state": f.state,
                        "evidence_id": f.evidence_id,
                    })

            # Eligible files up to audit_at
            eligible = self.analyzer.get_eligible_evidence_files(audit_at, requested_at)

            # 2. Ensure account_service VERIFY_RECORD_ABSENT is present
            has_acc_ver = any(s["system_id"] == "account_service" for s in ver_steps)
            if not has_acc_ver:
                acc_id = self.resolve_account_id(req, cluster)
                if acc_id:
                    acc_eid = self.account_to_evidence.get(acc_id, "")
                    if not acc_eid or not any(f.get("file_id") == acc_eid for f in eligible):
                        if ver_steps and any(f.get("file_id") == ver_steps[0]["evidence_id"] for f in eligible):
                            acc_eid = ver_steps[0]["evidence_id"]
                        else:
                            acc_eid = self._resolve_verification_evidence_id(acc_id, "account_service", eligible)
                    if acc_eid:
                        ver_steps.append({
                            "phase": "VERIFICATION",
                            "system_id": "account_service",
                            "resource_id": acc_id,
                            "operation": "VERIFY_RECORD_ABSENT",
                            "state": "ABSENT",
                            "evidence_id": acc_eid,
                        })
                    else:
                        self.warnings.append(f"UNRESOLVED_ACCOUNT_EVIDENCE: case {cid} acc {acc_id}")

            # 3. Ensure security_service audit record VERIFY_RECORD_PRESENT is included if compliant
            has_sec_ver = any(s["system_id"] == "security_service" for s in ver_steps)
            if not has_sec_ver:
                aud_id = self.resolve_audit_id(req, cluster)
                if aud_id:
                    aud_eid = self.audit_to_evidence.get(aud_id, "")
                    if not aud_eid or not any(f.get("file_id") == aud_eid for f in eligible):
                        if ver_steps and any(f.get("file_id") == ver_steps[0]["evidence_id"] for f in eligible):
                            aud_eid = ver_steps[0]["evidence_id"]
                        else:
                            aud_eid = self._resolve_verification_evidence_id(aud_id, "security_service", eligible)
                    if aud_eid:
                        ver_steps.append({
                            "phase": "VERIFICATION",
                            "system_id": "security_service",
                            "resource_id": aud_id,
                            "operation": "VERIFY_RECORD_PRESENT",
                            "state": "PRESENT",
                            "evidence_id": aud_eid,
                        })

            if not ver_steps:
                self.warnings.append(f"INSUFFICIENT_EVIDENCE_FOR_COMPLETE: case {cid}")
                return "INCOMPLETE", []

            sorted_steps = sort_steps(ver_steps)
            return deletion_status, renumber_steps(sorted_steps)
