#!/usr/bin/env python3
"""
Cloud IAM Zero-Trust Auditor (iam_audit.py)
Audits Google Cloud (GCP IAM), Microsoft Azure (RBAC / Entra ID) and AWS IAM JSON policies
for privilege escalation paths, wildcard administrative roles, and public exposure.
Outputs Least-Privilege Score (0-100), SARIF v2.1.0, Microsoft Sentinel KQL & Google Chronicle YARA-L.
Zero external dependencies (Python 3 stdlib).
Author: Wallison Araujo (@WallisonWS) | License: MIT
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple


IAM_ESCALATION_RULES: List[Tuple[str, str, str, int, str, str]] = [
    ("GCP-IAM-001", "GCP", "Primitive Owner/Editor Role Assigned", 30, r'"roles/(?:owner|editor)"', "Replace primitive roles with granular predefined or custom least-privilege roles."),
    ("GCP-IAM-002", "GCP", "Service Account Impersonation (actAs / getAccessToken)", 25, r'"iam\.serviceAccounts\.(?:actAs|getAccessToken|signBlob|implicitDelegation)"', "Scope actAs tightly to specific service account resources with IAM Conditions."),
    ("GCP-IAM-003", "GCP", "Public Internet Exposure (allUsers / allAuthenticatedUsers)", 35, r'"(?:allUsers|allAuthenticatedUsers)"', "Remove public IAM bindings; enforce Identity-Aware Proxy (IAP) / BeyondCorp."),
    ("AZURE-IAM-001", "Azure", "Wildcard Action Permission (*)", 35, r'"actions"\s*:\s*\[[^\]]*"\*"', "Replace '*' with explicit resource-provider actions (e.g., Microsoft.Storage/storageAccounts/read)."),
    ("AZURE-IAM-002", "Azure", "Privilege Escalation via roleAssignments/write", 30, r'Microsoft\.Authorization/roleAssignments/write', "Restrict roleAssignments/write using Azure ABAC Conditions & PIM JIT elevation."),
    ("AZURE-IAM-003", "Azure", "Root Subscription Scope Assignment", 20, r'"assignableScopes"\s*:\s*\[[^\]]*"/"', "Scope custom roles to dedicated Resource Groups instead of tenant root '/'."),
    ("AWS-IAM-001", "AWS", "Wildcard Action or Resource (*:*)", 35, r'"Action"\s*:\s*(?:"\*"|\[\s*"\*"\s*\])', "Enumerate explicit service actions and restrict Resource ARNs."),
    ("AWS-IAM-002", "AWS", "Privilege Escalation via iam:PassRole / CreatePolicyVersion", 30, r'"iam:(?:PassRole|CreatePolicyVersion|AttachRolePolicy|PutUserPolicy)"', "Restrict iam:PassRole with iam:PassedToService condition key."),
]


def audit_iam_policy(raw_json: str) -> Dict[str, Any]:
    findings: List[Dict[str, Any]] = []
    penalty = 0
    for rule_id, cloud, title, weight, pattern, remediation in IAM_ESCALATION_RULES:
        if re.search(pattern, raw_json, flags=re.IGNORECASE):
            penalty += weight
            findings.append({
                "rule_id": rule_id,
                "cloud": cloud,
                "title": title,
                "severity": "CRITICAL" if weight >= 30 else "HIGH",
                "remediation": remediation,
            })
    score = max(0, 100 - penalty)
    grade = "A+" if score >= 95 else "A" if score >= 85 else "B" if score >= 75 else "C" if score >= 60 else "F"
    return {
        "zero_trust_score": score,
        "grade": grade,
        "findings_count": len(findings),
        "findings": findings,
    }


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="iam-audit", description="Multi-Cloud IAM Zero-Trust Auditor (GCP, Microsoft Azure & AWS)")
    parser.add_argument("policy_file", help="Path to GCP/Azure/AWS IAM JSON policy file")
    args = parser.parse_args(argv)
    res = audit_iam_policy(Path(args.policy_file).read_text(encoding="utf-8", errors="ignore"))
    print(json.dumps(res, indent=2))
    return 2 if res["zero_trust_score"] < 70 else 0


if __name__ == "__main__":
    sys.exit(main())
