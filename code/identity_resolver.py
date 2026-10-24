"""
code/identity_resolver.py - Resolves user emails and historical audit logs to complete IdentityClusters.
Finds primary user_id from current identities or historical audit changes prior to audit_at cutoff,
and accumulates all emails, phones, email_hashes, and names.
"""

from __future__ import annotations
import csv
import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Set, Any, Optional, Tuple


def _find_repo_root() -> Path:
    """Find repository root containing dataset directory."""
    cwd = Path.cwd()
    for candidate in [cwd, cwd.parent, Path(__file__).resolve().parent.parent]:
        if (candidate / "dataset" / "user_identities.csv").exists():
            return candidate
    return cwd


@dataclass
class IdentityCluster:
    primary_user_id: str
    user_ids: Set[str] = field(default_factory=set)
    emails: Set[str] = field(default_factory=set)
    phones: Set[str] = field(default_factory=set)
    email_hashes: Set[str] = field(default_factory=set)
    names: Set[str] = field(default_factory=set)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "primary_user_id": self.primary_user_id,
            "user_ids": sorted(list(self.user_ids)),
            "emails": sorted(list(self.emails)),
            "phones": sorted(list(self.phones)),
            "email_hashes": sorted(list(self.email_hashes)),
            "names": sorted(list(self.names)),
        }


def compute_sha256(text: str) -> str:
    """Compute standard lowercase SHA-256 hash of a string."""
    return hashlib.sha256(text.strip().lower().encode("utf-8")).hexdigest()


class IdentityResolver:
    """High-performance identity index and resolver."""

    def __init__(
        self,
        identities_path: Optional[str] = None,
        audit_log_path: Optional[str] = None,
    ):
        root = _find_repo_root()
        self.identities_path = Path(identities_path) if identities_path else (root / "dataset" / "user_identities.csv")
        self.audit_log_path = Path(audit_log_path) if audit_log_path else (root / "dataset" / "user_audit_log.csv")
        
        # In-memory indices
        self.identities_by_uid: Dict[str, Dict[str, str]] = {}
        self.current_email_to_uid: Dict[str, str] = {}
        self.audit_records_by_uid: Dict[str, List[Dict[str, str]]] = {}
        self.historical_email_to_uid: List[Tuple[str, str, str]] = []  # (email_lower, uid, event_time)

        self._load_data()


    def _load_data(self):
        """Pre-index identity and audit log tables."""
        if self.identities_path.exists():
            with open(self.identities_path, "r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    uid = row["user_id"]
                    self.identities_by_uid[uid] = row
                    email = row.get("email", "").strip().lower()
                    if email:
                        self.current_email_to_uid[email] = uid

        if self.audit_log_path.exists():
            with open(self.audit_log_path, "r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    uid = row["user_id"]
                    if uid not in self.audit_records_by_uid:
                        self.audit_records_by_uid[uid] = []
                    self.audit_records_by_uid[uid].append(row)

                    if row.get("field_name") == "email":
                        old_em = row.get("old_value", "").strip().lower()
                        new_em = row.get("new_value", "").strip().lower()
                        etime = row.get("event_time", "")
                        if old_em:
                            self.historical_email_to_uid.append((old_em, uid, etime))
                        if new_em:
                            self.historical_email_to_uid.append((new_em, uid, etime))

    def resolve(self, email: str, audit_at: str) -> Optional[IdentityCluster]:
        """
        Resolve a user identity cluster given request email and audit_at cutoff.
        """
        if not email:
            return None

        email_norm = email.strip().lower()
        primary_uid = None

        # 1. Match in current identities
        if email_norm in self.current_email_to_uid:
            primary_uid = self.current_email_to_uid[email_norm]

        # 2. Match in historical audit changes before audit_at
        if not primary_uid:
            for hist_email, uid, event_time in self.historical_email_to_uid:
                if hist_email == email_norm and event_time <= audit_at:
                    primary_uid = uid
                    break

        # Fallback: if not yet found, check historical regardless of event_time
        if not primary_uid:
            for hist_email, uid, _ in self.historical_email_to_uid:
                if hist_email == email_norm:
                    primary_uid = uid
                    break

        if not primary_uid:
            # Standalone unknown user fallback
            cluster = IdentityCluster(primary_user_id="unknown")
            cluster.emails.add(email.strip())
            cluster.email_hashes.add(compute_sha256(email))
            return cluster

        cluster = IdentityCluster(primary_user_id=primary_uid)
        cluster.user_ids.add(primary_uid)
        cluster.emails.add(email.strip())
        cluster.email_hashes.add(compute_sha256(email))

        # 3. Pull current attributes from user_identities.csv
        curr = self.identities_by_uid.get(primary_uid, {})
        curr_email = curr.get("email", "").strip()
        if curr_email:
            cluster.emails.add(curr_email)
            cluster.email_hashes.add(compute_sha256(curr_email))

        curr_hash = curr.get("email_hash", "").strip()
        if curr_hash:
            cluster.email_hashes.add(curr_hash)

        curr_phone = curr.get("phone", "").strip()
        if curr_phone:
            cluster.phones.add(curr_phone)

        curr_name = curr.get("name", "").strip()
        if curr_name:
            cluster.names.add(curr_name)

        # 4. Pull historical attributes from audit log (filtered by audit_at)
        audit_rows = self.audit_records_by_uid.get(primary_uid, [])
        for row in audit_rows:
            etime = row.get("event_time", "")
            if etime and etime > audit_at:
                continue

            field_name = row.get("field_name")
            old_val = row.get("old_value", "").strip()
            new_val = row.get("new_value", "").strip()

            if field_name == "email":
                if old_val:
                    cluster.emails.add(old_val)
                    cluster.email_hashes.add(compute_sha256(old_val))
                if new_val:
                    cluster.emails.add(new_val)
                    cluster.email_hashes.add(compute_sha256(new_val))
            elif field_name == "email_hash":
                if old_val:
                    cluster.email_hashes.add(old_val)
                if new_val:
                    cluster.email_hashes.add(new_val)
            elif field_name == "phone":
                if old_val:
                    cluster.phones.add(old_val)
                if new_val:
                    cluster.phones.add(new_val)
            elif field_name == "name":
                if old_val:
                    cluster.names.add(old_val)
                if new_val:
                    cluster.names.add(new_val)

        return cluster


if __name__ == "__main__":
    import json
    resolver = IdentityResolver()
    # Test on case_01
    c1 = resolver.resolve("amina.elmasri@gmail.com", "2026-09-03T11:30:00Z")
    print("Resolved case_01 cluster:")
    print(json.dumps(c1.to_dict() if c1 else {}, indent=2))
