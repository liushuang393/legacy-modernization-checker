#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
生成セキュリティ対策案（Remediation Plan）
- 入力：Semgrep SARIF / Dependency-Check JSON / ZAP JSON
- 出力：security-remediation.md

方針：
- 自動修正は低リスク（機械的変換）に限定。
- それ以外は「対策案（実装方針）」を提示し、レビューで確定する。
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any, Dict, List, Optional


@dataclass
class Finding:
    tool: str
    severity: str
    title: str
    file: Optional[str]
    line: Optional[int]
    message: str
    cwe: Optional[str] = None
    cve: Optional[str] = None
    package: Optional[str] = None
    recommendation: Optional[str] = None
    owasp: Optional[str] = None


OWASP_MAP_HINTS = [
    ("injection", "A05:2025 Injection"),
    ("sql", "A05:2025 Injection"),
    ("xss", "A05:2025 Injection"),
    ("access control", "A01:2025 Access Control"),
    ("authorization", "A01:2025 Access Control"),
    ("auth", "A07:2025 Identification and Authentication Failures"),
    ("crypto", "A04:2025 Cryptographic Failures"),
    ("misconfig", "A02:2025 Security Misconfiguration"),
    ("supply chain", "A03:2025 Software Supply Chain Failures"),
    ("dependency", "A03:2025 Software Supply Chain Failures"),
    ("logging", "A09:2025 Logging and Monitoring Failures"),
    ("exception", "A10:2025 Mishandling of Exceptional Conditions"),
]


def guess_owasp(title: str, message: str) -> str:
    text = (title + " " + message).lower()
    for k, v in OWASP_MAP_HINTS:
        if k in text:
            return v
    return "A99:2025 Unclassified (Needs triage)"


def load_json(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def parse_semgrep_sarif(path: str) -> List[Finding]:
    if not os.path.exists(path):
        return []
    sarif = load_json(path)
    findings: List[Finding] = []

    for run in sarif.get("runs", []):
        tool = run.get("tool", {}).get("driver", {}).get("name", "semgrep")
        for r in run.get("results", []):
            level = r.get("level", "warning")
            severity = {"error": "HIGH", "warning": "MEDIUM", "note": "LOW"}.get(level, "MEDIUM")
            rule_id = r.get("ruleId", "unknown-rule")
            msg = r.get("message", {}).get("text", "")

            file = None
            line = None
            locs = r.get("locations", [])
            if locs:
                phys = locs[0].get("physicalLocation", {})
                file = phys.get("artifactLocation", {}).get("uri")
                region = phys.get("region", {})
                line = region.get("startLine")

            props = r.get("properties", {})
            cwe = props.get("cwe") if isinstance(props, dict) else None

            title = f"[{rule_id}] {msg.splitlines()[0][:120]}" if msg else f"[{rule_id}] Finding"
            rec = "【対策案】該当箇所をルールに従い修正。自動修正は低リスクのみ許可し、PRレビュー必須。"

            findings.append(
                Finding(
                    tool=str(tool),
                    severity=severity,
                    title=title.strip(),
                    file=file,
                    line=line,
                    message=msg,
                    cwe=cwe,
                    recommendation=rec,
                    owasp=guess_owasp(title, msg),
                )
            )
    return findings


def parse_dependency_check(path: str) -> List[Finding]:
    if not os.path.exists(path):
        return []
    data = load_json(path)
    findings: List[Finding] = []

    for d in data.get("dependencies", []):
        pkg = d.get("fileName") or d.get("filePath") or None
        for v in (d.get("vulnerabilities") or []):
            name = v.get("name") or v.get("vulnId") or "CVE-UNKNOWN"
            severity = (v.get("severity") or "MEDIUM").upper()
            msg = v.get("description") or ""
            cve = name if str(name).startswith("CVE-") else None

            rec = (
                "【対策案】依存関係のアップグレード（優先）。\n"
                "- 代替ライブラリ検討\n"
                "- 互換性が無い場合は緩和策（機能制限/設定無効化）\n"
                "- 影響範囲は SBOM（CycloneDX）で確認"
            )

            findings.append(
                Finding(
                    tool="dependency-check",
                    severity=severity,
                    title=f"[{name}] Dependency vulnerability",
                    file=None,
                    line=None,
                    message=msg,
                    cve=cve,
                    package=pkg,
                    recommendation=rec,
                    owasp="A03:2025 Software Supply Chain Failures",
                )
            )
    return findings


def parse_zap_json(path: str) -> List[Finding]:
    if not os.path.exists(path):
        return []
    data = load_json(path)
    findings: List[Finding] = []

    sites = data.get("site") or data.get("sites") or []
    if isinstance(sites, dict):
        sites = [sites]

    for s in sites:
        for a in (s.get("alerts") or []):
            risk = a.get("risk") or "MEDIUM"
            severity = str(risk).upper()
            title = a.get("alert") or "ZAP Alert"
            msg = a.get("desc") or ""
            rec = a.get("solution") or "【対策案】ZAP 指摘に従い設定/実装を修正。"
            ref = a.get("reference") or ""

            url = None
            instances = a.get("instances") or []
            if isinstance(instances, list) and instances:
                url = instances[0].get("uri") or instances[0].get("url")

            findings.append(
                Finding(
                    tool="zap",
                    severity=severity,
                    title=title,
                    file=url,
                    line=None,
                    message=(msg + ("\n" + ref if ref else "")).strip(),
                    recommendation=rec,
                    owasp=guess_owasp(title, msg),
                )
            )
    return findings



def parse_trivy_json(path: str, tool_name: str) -> List[Finding]:
    if not os.path.exists(path):
        return []
    data = load_json(path)
    findings: List[Finding] = []
    results = data.get("Results") or []
    for r in results:
        target = r.get("Target")
        for v in (r.get("Vulnerabilities") or []):
            vid = v.get("VulnerabilityID") or "VULN-UNKNOWN"
            severity = (v.get("Severity") or "MEDIUM").upper()
            pkg = v.get("PkgName")
            installed = v.get("InstalledVersion")
            fixed = v.get("FixedVersion")
            title = f"[{vid}] {pkg} {installed} -> {fixed or 'N/A'}"
            msg = (v.get("Title") or "") + "\n" + (v.get("Description") or "")
            rec = "【対策案】(1) 可能なら FixedVersion へ更新 (2) 更新不可なら緩和策/影響範囲限定 (3) SBOMで影響確認"
            findings.append(Finding(
                tool=tool_name,
                severity=severity,
                title=title.strip(),
                file=target,
                line=None,
                message=msg.strip(),
                cve=vid if str(vid).startswith("CVE-") else None,
                package=pkg,
                recommendation=rec,
                owasp="A03:2025 Software Supply Chain Failures",
            ))
    return findings


def severity_rank(sev: str) -> int:
    s = sev.upper()
    if "CRITICAL" in s:
        return 0
    if "HIGH" in s:
        return 1
    if "MED" in s:
        return 2
    return 3


def write_md(findings: List[Finding], out_path: str) -> None:
    findings = sorted(findings, key=lambda f: (severity_rank(f.severity), f.tool, f.title))

    by_owasp: Dict[str, List[Finding]] = {}
    for f in findings:
        by_owasp.setdefault(f.owasp or "A99:2025 Unclassified (Needs triage)", []).append(f)

    lines: List[str] = []
    lines.append("# Security Remediation Plan（自動生成）")
    lines.append("")
    lines.append("## 使い方")
    lines.append("- CI 検証結果（SAST/SCA/DAST）を取り込み、OWASP Top 10:2025 分類で整理します。")
    lines.append("- 自動修正は別途 Semgrep の --autofix（低リスクのみ）で実施し、本書はレビュー用の対策案です。")
    lines.append("")
    lines.append("## 重大度の扱い（推奨）")
    lines.append("- CRITICAL/HIGH：リリースゲートでブロック")
    lines.append("- MEDIUM：期限付き対応")
    lines.append("- LOW：バックログ管理")
    lines.append("")
    for cat, items in by_owasp.items():
        lines.append(f"## {cat}（{len(items)}件）")
        lines.append("")
        for i, f in enumerate(items, 1):
            loc = ""
            if f.file:
                loc = f.file + (f":{f.line}" if f.line else "")
            meta = []
            if f.package:
                meta.append(f"pkg={f.package}")
            if f.cwe:
                meta.append(f"CWE={f.cwe}")
            if f.cve:
                meta.append(f"{f.cve}")
            lines.append(f"### {i}. [{f.severity}] {f.tool}: {f.title}")
            if loc:
                lines.append(f"- Location: {loc}")
            if meta:
                lines.append(f"- Meta: {' / '.join(meta)}")
            lines.append(f"- 内容: {f.message}".strip())
            lines.append(f"- 対策案: {f.recommendation}".strip())
            lines.append("")
        lines.append("")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


def main() -> None:
    semgrep = os.environ.get("SEMGREP_SARIF", "semgrep.sarif")
    depcheck = os.environ.get("DEPCHECK_JSON", "dependency-check-report.json")
    zap = os.environ.get("ZAP_JSON", "tools/zap/zap-report.json")
    gitleaks = os.environ.get("GITLEAKS_SARIF", "gitleaks.sarif")
    trivy_fs = os.environ.get("TRIVY_FS_JSON", "trivy-fs.json")
    trivy_img = os.environ.get("TRIVY_IMAGE_JSON", "trivy-image.json")
    out_md = os.environ.get("REMEDIATION_MD", "security-remediation.md")

    findings: List[Finding] = []
    findings += parse_semgrep_sarif(semgrep)
    findings += parse_dependency_check(depcheck)
    findings += parse_zap_json(zap)

    # Secret Detection (Gitleaks): SARIF 互換として扱う
    findings += parse_semgrep_sarif(gitleaks)

    # Container / FS vulnerabilities (Trivy)
    findings += parse_trivy_json(trivy_fs, "trivy-fs")
    findings += parse_trivy_json(trivy_img, "trivy-image")

    write_md(findings, out_md)
    print(f"[OK] wrote {out_md} with {len(findings)} findings")


if __name__ == "__main__":
    main()
