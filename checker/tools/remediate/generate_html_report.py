#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
統合セキュリティレポート生成スクリプト
複数ツールの結果を1つのHTMLダッシュボードに統合

使用方法:
    python generate_html_report.py --input-dir reports/latest --output reports/latest/security-report.html
"""

import argparse
import json
import os
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

# Jinja2 がない場合は文字列テンプレートで代替
try:
    from jinja2 import Environment, FileSystemLoader
    HAS_JINJA2 = True
except ImportError:
    HAS_JINJA2 = False


@dataclass
class Finding:
    """検出結果を表すデータクラス"""
    tool: str
    severity: str
    title: str
    file: Optional[str] = None
    line: Optional[int] = None
    message: str = ""
    cwe: Optional[str] = None
    cve: Optional[str] = None
    package: Optional[str] = None
    recommendation: str = ""
    owasp: str = "A99:2025 Unclassified"
    id: str = field(default_factory=lambda: "")

    def __post_init__(self):
        if not self.id:
            # 一意なIDを生成（差分比較用）
            self.id = f"{self.tool}:{self.file or ''}:{self.line or ''}:{self.title[:50]}"


def load_json(path: str) -> Optional[Dict]:
    """JSONファイルを読み込む"""
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None


def guess_owasp(title: str, msg: str) -> str:
    """タイトルとメッセージからOWASP Top 10:2025カテゴリを推測"""
    text = (title + " " + msg).lower()
    mapping = [
        (["injection", "sql", "sqli", "command", "ldap", "xpath", "nosql"], "A05:2025 Injection"),
        (["auth", "password", "credential", "session", "token", "jwt"], "A01:2025 Broken Access Control"),
        (["crypto", "encrypt", "hash", "ssl", "tls", "certificate"], "A04:2025 Cryptographic Failures"),
        (["xss", "cross-site", "script", "html", "dom"], "A06:2025 XSS"),
        (["config", "misconfigur", "default", "debug", "verbose"], "A02:2025 Security Misconfiguration"),
        (["outdated", "vulnerable", "cve-", "dependency", "component"], "A03:2025 Software Supply Chain Failures"),
        (["deserial", "pickle", "yaml.load", "objectinput"], "A07:2025 Insecure Design"),
        (["log", "monitor", "audit", "trace"], "A08:2025 Security Logging Failures"),
        (["ssrf", "request forgery", "redirect", "forward"], "A09:2025 SSRF"),
        (["secret", "api.key", "hardcode", "leak"], "A02:2025 Security Misconfiguration"),
    ]
    for keywords, category in mapping:
        if any(kw in text for kw in keywords):
            return category
    return "A99:2025 Unclassified"


def parse_sarif(path: str, tool_name: str) -> List[Finding]:
    """SARIF形式のファイルをパース"""
    data = load_json(path)
    if not data:
        return []
    findings = []
    for run in data.get("runs", []):
        tool = run.get("tool", {}).get("driver", {}).get("name", tool_name)
        rules_map = {r.get("id"): r for r in run.get("tool", {}).get("driver", {}).get("rules", [])}
        for result in run.get("results", []):
            rule_id = result.get("ruleId", "unknown")
            msg = result.get("message", {}).get("text", "")
            severity = result.get("level", "warning").upper()
            if severity == "WARNING":
                severity = "MEDIUM"
            elif severity == "ERROR":
                severity = "HIGH"
            locs = result.get("locations", [])
            file_path, line = None, None
            if locs:
                phys = locs[0].get("physicalLocation", {})
                file_path = phys.get("artifactLocation", {}).get("uri")
                line = phys.get("region", {}).get("startLine")
            rule_info = rules_map.get(rule_id, {})
            props = rule_info.get("properties", {})
            owasp = props.get("owasp") or guess_owasp(rule_id, msg)
            findings.append(Finding(
                tool=str(tool),
                severity=severity,
                title=f"[{rule_id}] {msg.splitlines()[0][:100]}" if msg else f"[{rule_id}]",
                file=file_path,
                line=line,
                message=msg,
                cwe=props.get("cwe"),
                owasp=owasp,
                recommendation="ルールに従い修正。PRレビュー必須。"
            ))
    return findings


def parse_dependency_check(path: str) -> List[Finding]:
    """Dependency-Check JSONをパース"""
    data = load_json(path)
    if not data:
        return []
    findings = []
    for dep in data.get("dependencies", []):
        for vuln in dep.get("vulnerabilities", []):
            cve = vuln.get("name", "")
            severity = (vuln.get("severity") or "MEDIUM").upper()
            pkg = dep.get("fileName", "")
            desc = vuln.get("description", "")
            findings.append(Finding(
                tool="dependency-check",
                severity=severity,
                title=f"[{cve}] {pkg}",
                file=pkg,
                message=desc[:500],
                cve=cve,
                package=pkg,
                owasp="A03:2025 Software Supply Chain Failures",
                recommendation="脆弱性のないバージョンへ更新、または緩和策を適用"
            ))
    return findings


def parse_zap_json(path: str) -> List[Finding]:
    """ZAP JSONレポートをパース"""
    data = load_json(path)
    if not data:
        return []
    findings = []
    # ZAP JSON形式に対応
    for site in data.get("site", []):
        for alert in site.get("alerts", []):
            risk = alert.get("riskdesc", "MEDIUM").split()[0].upper()
            severity = {"HIGH": "HIGH", "MEDIUM": "MEDIUM", "LOW": "LOW", "INFORMATIONAL": "INFO"}.get(risk, "MEDIUM")
            findings.append(Finding(
                tool="zap",
                rule_id=alert.get("alertRef", "ZAP-" + str(alert.get("pluginid", "unknown"))),
                severity=severity,
                title=alert.get("name", "Unknown Alert"),
                description=alert.get("desc", ""),
                file_path=alert.get("uri", ""),
                line_number=0,
                recommendation=alert.get("solution", "詳細はZAPレポートを参照")
            ))
    return findings


def parse_trivy_json(path: str, tool_name: str) -> List[Finding]:
    """Trivy JSONをパース"""
    data = load_json(path)
    if not data:
        return []
    findings = []
    for result in data.get("Results", []):
        target = result.get("Target", "")
        for vuln in result.get("Vulnerabilities", []):
            vid = vuln.get("VulnerabilityID", "UNKNOWN")
            severity = (vuln.get("Severity") or "MEDIUM").upper()
            pkg = vuln.get("PkgName", "")
            installed = vuln.get("InstalledVersion", "")
            fixed = vuln.get("FixedVersion", "N/A")
            findings.append(Finding(
                tool=tool_name,
                severity=severity,
                title=f"[{vid}] {pkg} {installed} -> {fixed}",
                file=target,
                message=vuln.get("Description", "")[:500],
                cve=vid if vid.startswith("CVE-") else None,
                package=pkg,
                owasp="A03:2025 Software Supply Chain Failures",
                recommendation=f"バージョン {fixed} へ更新" if fixed != "N/A" else "緩和策を検討"
            ))
    return findings


def load_skipped_checks(input_dir: str) -> List[str]:
    """スキップされた検査一覧を読み込む"""
    skipped_file = Path(input_dir) / "skipped-checks.txt"
    if not skipped_file.exists():
        return []
    with open(skipped_file, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip()]


def collect_findings(input_dir: str) -> List[Finding]:
    """指定ディレクトリから全ての検出結果を収集"""
    findings = []
    base = Path(input_dir)

    # SARIF形式 - Semgrep（複数言語に対応）
    for sarif_file, tool in [
        ("semgrep-java.sarif", "semgrep"),
        ("semgrep-js.sarif", "semgrep"),
        ("semgrep-python.sarif", "semgrep"),
        ("semgrep-custom.sarif", "semgrep-custom"),
        ("gitleaks.sarif", "gitleaks"),
    ]:
        findings.extend(parse_sarif(str(base / sarif_file), tool))

    # Dependency-Check
    findings.extend(parse_dependency_check(str(base / "dependency-check-report.json")))

    # ZAP
    findings.extend(parse_zap_json(str(base / "zap-report.json")))

    # Trivy（SARIF形式で出力される）
    findings.extend(parse_sarif(str(base / "trivy.sarif"), "trivy"))

    return findings


def load_previous_findings(reports_dir: str, current_dir: str) -> List[Finding]:
    """前回の実行結果を読み込む（差分比較用）"""
    reports_path = Path(reports_dir)
    if not reports_path.exists():
        return []

    # 日付フォルダを取得してソート
    dirs = sorted([d for d in reports_path.iterdir() if d.is_dir() and d.name != "latest"], reverse=True)
    current_name = Path(current_dir).name

    for d in dirs:
        if d.name != current_name:
            # 前回のfindings.jsonがあれば読み込む
            cache_file = d / "findings_cache.json"
            if cache_file.exists():
                data = load_json(str(cache_file))
                if data:
                    return [Finding(**f) for f in data]
            # なければ再収集
            return collect_findings(str(d))
    return []


def calculate_diff(current: List[Finding], previous: List[Finding]) -> Dict[str, List[Finding]]:
    """現在と前回の差分を計算"""
    current_ids = {f.id for f in current}
    previous_ids = {f.id for f in previous}

    return {
        "new": [f for f in current if f.id not in previous_ids],
        "fixed": [f for f in previous if f.id not in current_ids],
        "ongoing": [f for f in current if f.id in previous_ids],
    }


def generate_stats(findings: List[Finding]) -> Dict[str, Any]:
    """統計情報を生成"""
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    tool_counts: Dict[str, int] = {}
    owasp_counts: Dict[str, int] = {}

    for f in findings:
        sev = f.severity.upper()
        if "CRITICAL" in sev:
            severity_counts["CRITICAL"] += 1
        elif "HIGH" in sev:
            severity_counts["HIGH"] += 1
        elif "MED" in sev:
            severity_counts["MEDIUM"] += 1
        elif "LOW" in sev:
            severity_counts["LOW"] += 1
        else:
            severity_counts["INFO"] += 1

        tool_counts[f.tool] = tool_counts.get(f.tool, 0) + 1
        owasp_counts[f.owasp] = owasp_counts.get(f.owasp, 0) + 1

    return {
        "total": len(findings),
        "severity": severity_counts,
        "by_tool": tool_counts,
        "by_owasp": dict(sorted(owasp_counts.items())),
    }


# インラインHTMLテンプレート（Jinja2不要で動作可能）
HTML_TEMPLATE = '''<!DOCTYPE html>
<html lang="ja">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Scan Report - {timestamp}</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
    <style>
        :root {{ --critical: #dc3545; --high: #fd7e14; --medium: #ffc107; --low: #28a745; --info: #17a2b8; }}
        body {{ background: #f8f9fa; }}
        .card {{ box-shadow: 0 2px 4px rgba(0,0,0,0.1); border: none; }}
        .stat-card {{ text-align: center; padding: 1.5rem; }}
        .stat-number {{ font-size: 2.5rem; font-weight: bold; }}
        .severity-critical {{ color: var(--critical); }}
        .severity-high {{ color: var(--high); }}
        .severity-medium {{ color: var(--medium); }}
        .severity-low {{ color: var(--low); }}
        .badge-critical {{ background: var(--critical); }}
        .badge-high {{ background: var(--high); }}
        .badge-medium {{ background: var(--medium); color: #000; }}
        .badge-low {{ background: var(--low); }}
        .diff-new {{ background: #ffe6e6; }}
        .diff-fixed {{ background: #e6ffe6; }}
        .finding-row {{ cursor: pointer; }}
        .finding-row:hover {{ background: #f0f0f0; }}
        .finding-detail {{ display: none; background: #fafafa; }}
        .chart-container {{ position: relative; height: 250px; }}
        .nav-tabs .nav-link.active {{ font-weight: bold; }}
        .filter-bar {{ background: #fff; padding: 1rem; border-radius: 8px; margin-bottom: 1rem; }}
    </style>
</head>
<body>
<div class="container-fluid py-4">
    <!-- ヘッダー -->
    <div class="row mb-4">
        <div class="col">
            <h1 class="h3"><i class="bi bi-shield-check"></i> Security Scan Report</h1>
            <p class="text-muted">Generated: {timestamp} | Project: {project_name}</p>
        </div>
    </div>

    <!-- サマリーカード -->
    <div class="row mb-4">
        <div class="col-md-2">
            <div class="card stat-card">
                <div class="stat-number">{total}</div>
                <div class="text-muted">Total Findings</div>
            </div>
        </div>
        <div class="col-md-2">
            <div class="card stat-card">
                <div class="stat-number severity-critical">{critical}</div>
                <div class="text-muted">Critical</div>
            </div>
        </div>
        <div class="col-md-2">
            <div class="card stat-card">
                <div class="stat-number severity-high">{high}</div>
                <div class="text-muted">High</div>
            </div>
        </div>
        <div class="col-md-2">
            <div class="card stat-card">
                <div class="stat-number severity-medium">{medium}</div>
                <div class="text-muted">Medium</div>
            </div>
        </div>
        <div class="col-md-2">
            <div class="card stat-card">
                <div class="stat-number severity-low">{low}</div>
                <div class="text-muted">Low</div>
            </div>
        </div>
        <div class="col-md-2">
            <div class="card stat-card">
                <div class="stat-number text-success">{fixed_count}</div>
                <div class="text-muted">Fixed (vs prev)</div>
            </div>
        </div>
    </div>

    <!-- スキップ警告 -->
    {skipped_section}

    <!-- 差分サマリー -->
    {diff_section}

    <!-- チャート -->
    <div class="row mb-4">
        <div class="col-md-4">
            <div class="card p-3">
                <h6>Severity Distribution</h6>
                <div class="chart-container"><canvas id="severityChart"></canvas></div>
            </div>
        </div>
        <div class="col-md-4">
            <div class="card p-3">
                <h6>By Tool</h6>
                <div class="chart-container"><canvas id="toolChart"></canvas></div>
            </div>
        </div>
        <div class="col-md-4">
            <div class="card p-3">
                <h6>OWASP Top 10:2025</h6>
                <div class="chart-container"><canvas id="owaspChart"></canvas></div>
            </div>
        </div>
    </div>

    <!-- 詳細テーブル -->
    <div class="card">
        <div class="card-header">
            <ul class="nav nav-tabs card-header-tabs" role="tablist">
                <li class="nav-item"><a class="nav-link active" data-bs-toggle="tab" href="#all">All ({total})</a></li>
                {tool_tabs}
            </ul>
        </div>
        <div class="card-body">
            <div class="filter-bar">
                <div class="row g-2">
                    <div class="col-md-3">
                        <select id="severityFilter" class="form-select form-select-sm">
                            <option value="">All Severities</option>
                            <option value="CRITICAL">Critical</option>
                            <option value="HIGH">High</option>
                            <option value="MEDIUM">Medium</option>
                            <option value="LOW">Low</option>
                        </select>
                    </div>
                    <div class="col-md-4">
                        <input type="text" id="searchFilter" class="form-control form-control-sm" placeholder="Search...">
                    </div>
                </div>
            </div>
            <div class="tab-content">
                <div class="tab-pane fade show active" id="all">
                    <table class="table table-sm" id="findingsTable">
                        <thead><tr><th>Severity</th><th>Tool</th><th>Title</th><th>File</th><th>OWASP</th></tr></thead>
                        <tbody>{findings_rows}</tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>
</div>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
<script>
// チャート描画
const severityData = {severity_json};
const toolData = {tool_json};
const owaspData = {owasp_json};

new Chart(document.getElementById('severityChart'), {{
    type: 'doughnut',
    data: {{
        labels: Object.keys(severityData),
        datasets: [{{ data: Object.values(severityData), backgroundColor: ['#dc3545','#fd7e14','#ffc107','#28a745','#17a2b8'] }}]
    }},
    options: {{ responsive: true, maintainAspectRatio: false }}
}});

new Chart(document.getElementById('toolChart'), {{
    type: 'bar',
    data: {{
        labels: Object.keys(toolData),
        datasets: [{{ label: 'Findings', data: Object.values(toolData), backgroundColor: '#0d6efd' }}]
    }},
    options: {{ responsive: true, maintainAspectRatio: false, indexAxis: 'y' }}
}});

new Chart(document.getElementById('owaspChart'), {{
    type: 'bar',
    data: {{
        labels: Object.keys(owaspData).map(k => k.split(' ')[0]),
        datasets: [{{ label: 'Findings', data: Object.values(owaspData), backgroundColor: '#6f42c1' }}]
    }},
    options: {{ responsive: true, maintainAspectRatio: false }}
}});

// 現在選択中のツールフィルター（空文字 = All）
let currentToolFilter = '';

// フィルタリング
document.getElementById('severityFilter').addEventListener('change', filterTable);
document.getElementById('searchFilter').addEventListener('input', filterTable);

// ツールタブのクリックイベント
document.querySelectorAll('.tool-filter-tab').forEach(tab => {{
    tab.addEventListener('click', function(e) {{
        e.preventDefault();
        // 全タブからactiveを除去
        document.querySelectorAll('.nav-tabs .nav-link').forEach(t => t.classList.remove('active'));
        // クリックされたタブをactive
        this.classList.add('active');
        // ツールフィルターを設定
        currentToolFilter = this.dataset.tool || '';
        filterTable();
    }});
}});

// Allタブのクリックイベント
document.querySelector('.nav-tabs .nav-link[href="#all"]').addEventListener('click', function(e) {{
    e.preventDefault();
    document.querySelectorAll('.nav-tabs .nav-link').forEach(t => t.classList.remove('active'));
    this.classList.add('active');
    currentToolFilter = '';
    filterTable();
}});

function filterTable() {{
    const sev = document.getElementById('severityFilter').value.toLowerCase();
    const search = document.getElementById('searchFilter').value.toLowerCase();
    const toolFilter = currentToolFilter.toLowerCase();
    document.querySelectorAll('#findingsTable tbody tr').forEach(row => {{
        const text = row.textContent.toLowerCase();
        const toolCell = row.querySelector('td:nth-child(2)')?.textContent.toLowerCase() || '';
        const sevMatch = !sev || text.includes(sev);
        const searchMatch = !search || text.includes(search);
        const toolMatch = !toolFilter || toolCell.includes(toolFilter);
        row.style.display = sevMatch && searchMatch && toolMatch ? '' : 'none';
    }});
}}
</script>
</body>
</html>'''



def severity_badge(sev: str) -> str:
    """重大度に応じたバッジHTMLを生成"""
    sev_upper = sev.upper()
    if "CRITICAL" in sev_upper:
        return '<span class="badge badge-critical">CRITICAL</span>'
    elif "HIGH" in sev_upper:
        return '<span class="badge badge-high">HIGH</span>'
    elif "MED" in sev_upper:
        return '<span class="badge badge-medium">MEDIUM</span>'
    elif "LOW" in sev_upper:
        return '<span class="badge badge-low">LOW</span>'
    return f'<span class="badge bg-secondary">{sev}</span>'


def generate_findings_rows(findings: List[Finding], diff: Dict[str, List[Finding]]) -> str:
    """検出結果のテーブル行を生成"""
    new_ids = {f.id for f in diff.get("new", [])}
    rows = []
    for f in sorted(findings, key=lambda x: (
        0 if "CRITICAL" in x.severity.upper() else
        1 if "HIGH" in x.severity.upper() else
        2 if "MED" in x.severity.upper() else 3,
        x.tool, x.title
    )):
        row_class = "diff-new" if f.id in new_ids else ""
        file_display = (f.file or "")[:50] + ("..." if f.file and len(f.file) > 50 else "")
        rows.append(f'''<tr class="{row_class}">
            <td>{severity_badge(f.severity)}</td>
            <td><code>{f.tool}</code></td>
            <td title="{f.message[:200]}">{f.title[:80]}</td>
            <td><small>{file_display}</small></td>
            <td><small>{f.owasp.split(" ")[0]}</small></td>
        </tr>''')
    return "\n".join(rows)


def generate_skipped_section(skipped: List[str]) -> str:
    """スキップされた検査の警告セクションを生成"""
    if not skipped:
        return ""
    items = "".join(f"<li>{s}</li>" for s in skipped)
    return f'''<div class="row mb-4">
        <div class="col-12">
            <div class="alert alert-warning" role="alert">
                <h6 class="alert-heading"><strong>⚠ 一部の検査がスキップされました</strong></h6>
                <p class="mb-1">以下の検査は実行されませんでした。報告書に漏れがある可能性があります。</p>
                <ul class="mb-0">{items}</ul>
            </div>
        </div>
    </div>'''


def generate_diff_section(diff: Dict[str, List[Finding]]) -> str:
    """差分セクションのHTMLを生成"""
    new_count = len(diff.get("new", []))
    fixed_count = len(diff.get("fixed", []))
    if new_count == 0 and fixed_count == 0:
        return ""
    return f'''<div class="row mb-4">
        <div class="col-12">
            <div class="card p-3">
                <h6>Changes from Previous Scan</h6>
                <div class="row">
                    <div class="col-md-6">
                        <span class="badge bg-danger">{new_count} New</span>
                        <span class="text-muted ms-2">新規検出</span>
                    </div>
                    <div class="col-md-6">
                        <span class="badge bg-success">{fixed_count} Fixed</span>
                        <span class="text-muted ms-2">修正済み</span>
                    </div>
                </div>
            </div>
        </div>
    </div>'''


def generate_tool_tabs(stats: Dict[str, Any]) -> str:
    """ツール別タブを生成（クリック可能なフィルタリングタブ）"""
    tabs = []
    for tool, count in stats.get("by_tool", {}).items():
        # data-tool属性を使用してJavaScriptでフィルタリング
        safe_tool_id = tool.replace("-", "_").replace(".", "_")
        tabs.append(
            f'<li class="nav-item">'
            f'<a class="nav-link tool-filter-tab" href="#" data-tool="{tool}" id="tab-{safe_tool_id}">'
            f'{tool} ({count})</a></li>'
        )
    return "\n".join(tabs)


def generate_html(findings: List[Finding], diff: Dict[str, List[Finding]],
                  stats: Dict[str, Any], output_path: str,
                  skipped: List[str] = None, project_name: str = "Project") -> None:
    """HTMLレポートを生成"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    skipped = skipped or []

    html = HTML_TEMPLATE.format(
        timestamp=timestamp,
        project_name=project_name,
        total=stats["total"],
        critical=stats["severity"]["CRITICAL"],
        high=stats["severity"]["HIGH"],
        medium=stats["severity"]["MEDIUM"],
        low=stats["severity"]["LOW"],
        fixed_count=len(diff.get("fixed", [])),
        skipped_section=generate_skipped_section(skipped),
        diff_section=generate_diff_section(diff),
        tool_tabs=generate_tool_tabs(stats),
        findings_rows=generate_findings_rows(findings, diff),
        severity_json=json.dumps(stats["severity"]),
        tool_json=json.dumps(stats["by_tool"]),
        owasp_json=json.dumps(stats["by_owasp"]),
    )

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"[OK] Generated HTML report: {output_path}")


def save_findings_cache(findings: List[Finding], output_dir: str) -> None:
    """検出結果をキャッシュとして保存（次回差分比較用）"""
    cache_path = Path(output_dir) / "findings_cache.json"
    with open(cache_path, "w", encoding="utf-8") as f:
        json.dump([asdict(f) for f in findings], f, ensure_ascii=False, indent=2)


def main() -> None:
    """メイン処理"""
    parser = argparse.ArgumentParser(description="統合セキュリティレポート生成")
    parser.add_argument("--input-dir", "-i", default=".", help="入力ディレクトリ（スキャン結果）")
    parser.add_argument("--output", "-o", default="security-report.html", help="出力HTMLファイル")
    parser.add_argument("--reports-dir", "-r", default="reports", help="レポート履歴ディレクトリ")
    parser.add_argument("--project-name", "-p", default="Security Scan", help="プロジェクト名")
    args = parser.parse_args()

    # 検出結果を収集
    findings = collect_findings(args.input_dir)
    print(f"[INFO] Collected {len(findings)} findings from {args.input_dir}")

    # スキップされた検査を読み込む
    skipped = load_skipped_checks(args.input_dir)
    if skipped:
        print(f"[WARN] {len(skipped)} checks were skipped")

    # 前回結果との差分を計算
    previous = load_previous_findings(args.reports_dir, args.input_dir)
    diff = calculate_diff(findings, previous)
    print(f"[INFO] Diff: {len(diff['new'])} new, {len(diff['fixed'])} fixed, {len(diff['ongoing'])} ongoing")

    # 統計情報を生成
    stats = generate_stats(findings)

    # HTMLレポートを生成
    output_path = args.output
    # 絶対パスでなく、かつ input_dir を含まない場合のみ結合
    if not os.path.isabs(output_path) and not output_path.startswith(args.input_dir):
        output_path = os.path.join(args.input_dir, output_path)
    # 出力ディレクトリが存在しない場合は作成
    output_dir = os.path.dirname(output_path)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir, exist_ok=True)
    generate_html(findings, diff, stats, output_path, skipped, args.project_name)

    # キャッシュを保存
    save_findings_cache(findings, args.input_dir)

    # サマリーを表示
    print("\n" + "=" * 50)
    print("Security Scan Summary")
    print("=" * 50)
    print(f"Total: {stats['total']} findings")
    print(f"  CRITICAL: {stats['severity']['CRITICAL']}")
    print(f"  HIGH:     {stats['severity']['HIGH']}")
    print(f"  MEDIUM:   {stats['severity']['MEDIUM']}")
    print(f"  LOW:      {stats['severity']['LOW']}")
    if skipped:
        print(f"\n[WARNING] Skipped checks: {len(skipped)}")
        for s in skipped:
            print(f"  - {s}")
    print("=" * 50)


if __name__ == "__main__":
    main()
