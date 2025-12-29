# Security Checker - Zero Invasion Security Scan Tool

OWASP Top 10:2025 準拠のセキュリティスキャンツール。  
**ゼロ侵入設計** - 対象プロジェクトへの変更は一切不要です。

## 📁 ディレクトリ構成

```
checker/
├── run_check.bat          # Windows用スクリプト
├── run_check.sh           # Linux/Mac用スクリプト
├── config/
│   └── .env.example       # 設定ファイルテンプレート
└── tools/
    ├── remediate/
    │   ├── generate_remediation.py   # 対策案生成
    │   └── generate_html_report.py   # HTMLレポート生成
    ├── semgrep/
    │   ├── .semgrep.yml              # Javaカスタムルール
    │   └── .semgrep-typescript.yml   # TSカスタムルール
    └── zap/
        └── automation.yaml           # ZAP設定
```

## 🚀 使い方

### 1. インストール

このフォルダを任意の場所にコピー（例：`D:\tools\security-checker`）

### 2. 設定（オプション）

```bash
cd checker/config
cp .env.example .env
# .env を編集（NVD_API_KEY など）
```

### 3. 実行

**Windows:**
```batch
D:\tools\security-checker\run_check.bat D:\workspace\your-project
```

**Linux/Mac:**
```bash
/opt/security-checker/run_check.sh /home/user/workspace/your-project
```

## 📊 検査項目（9ステップ）

| # | 検査 | ツール | 説明 |
|---|------|--------|------|
| 1 | Build | Maven/Gradle | ビルド & テスト |
| 2 | SCA | OWASP Dependency-Check | 依存ライブラリ脆弱性 |
| 3 | SBOM | CycloneDX | ソフトウェア部品表 |
| 4 | SAST | Semgrep | 静的コード解析 |
| 5 | DAST | ZAP | 動的アプリケーションテスト（オプション） |
| 6 | FS Scan | Trivy | ファイルシステムスキャン |
| 7 | Secrets | Gitleaks | 機密情報検出 |
| 8 | Remediation | Python | 対策案生成（Markdown） |
| 9 | Report | Python | HTMLダッシュボード生成 |

## 🔧 使用ツール詳細

### セキュリティスキャンツール（6種類）

| ツール | カテゴリ | 実行環境 | バージョン | 説明 |
|--------|----------|----------|------------|------|
| **OWASP Dependency-Check** | SCA | Maven Plugin | 12.1.0 | 依存ライブラリの既知脆弱性（CVE）を検出 |
| **CycloneDX** | SBOM | Maven Plugin | 2.9.1 | ソフトウェア部品表（BOM）を生成 |
| **Semgrep** | SAST | Docker | latest | Java/JS/TS/Python の静的コード解析 |
| **Trivy** | FS Scan | Docker | latest | ファイルシステム・コンテナの脆弱性スキャン |
| **Gitleaks** | Secrets | Docker | latest | シークレット（API Key、パスワード等）検出 |
| **OWASP ZAP** | DAST | Docker | latest | 動的アプリケーションセキュリティテスト（オプション） |

### 各ツールの検出対象

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ OWASP Dependency-Check                                                      │
│ ├── 対象: Maven/Gradle 依存ライブラリ（pom.xml, build.gradle）              │
│ ├── 検出: CVE、NVD データベース照合                                          │
│ └── 出力: dependency-check-report.json                                      │
├─────────────────────────────────────────────────────────────────────────────┤
│ Semgrep                                                                     │
│ ├── 対象: Java, JavaScript, TypeScript, Python ソースコード                  │
│ ├── 検出: セキュリティ脆弱性パターン、コード品質問題                          │
│ ├── ルール: p/java, p/javascript, p/typescript, p/python, p/security-audit │
│ └── 出力: semgrep-java.sarif, semgrep-js.sarif, semgrep-python.sarif        │
├─────────────────────────────────────────────────────────────────────────────┤
│ Trivy                                                                       │
│ ├── 対象: ファイルシステム全体、設定ファイル、Dockerfile                     │
│ ├── 検出: OS パッケージ脆弱性、設定ミス、シークレット                        │
│ └── 出力: trivy.sarif                                                       │
├─────────────────────────────────────────────────────────────────────────────┤
│ Gitleaks                                                                    │
│ ├── 対象: 全ファイル（Git履歴含まない --no-git モード）                      │
│ ├── 検出: API Key, Password, Token, 秘密鍵 等のハードコード                 │
│ └── 出力: gitleaks.sarif                                                    │
├─────────────────────────────────────────────────────────────────────────────┤
│ OWASP ZAP（オプション）                                                     │
│ ├── 対象: 実行中の Web アプリケーション                                      │
│ ├── 検出: XSS, SQLi, CSRF, セキュリティヘッダー欠落 等                       │
│ └── 出力: zap-report.json                                                   │
└─────────────────────────────────────────────────────────────────────────────┘
```

### OWASP Top 10:2025 との対応

| OWASP カテゴリ | 検出ツール |
|---------------|-----------|
| A01:2025 Access Control | Semgrep |
| A02:2025 Security Misconfiguration | Semgrep, Trivy |
| A03:2025 Software Supply Chain Failures | Dependency-Check, Trivy |
| A04:2025 Cryptographic Failures | Semgrep |
| A05:2025 Injection | Semgrep, ZAP |
| A06:2025 Insecure Design | Semgrep (カスタムルール) |
| A07:2025 Identification and Authentication | Semgrep, ZAP |
| A08:2025 Data Integrity Failures | Semgrep, Dependency-Check |
| A09:2025 Logging and Monitoring Failures | Semgrep (カスタムルール) |
| A10:2025 Server-Side Request Forgery | Semgrep, ZAP |

## 🔍 自動検出

スクリプトは対象プロジェクトのファイルを自動スキャンし、適切な検査を実行します：

- `pom.xml` → Maven プロジェクト（SCA, SBOM）
- `*.java` → Java SAST
- `*.js`, `*.ts` → JavaScript/TypeScript SAST
- `*.py` → Python SAST

## 📋 出力ファイル

レポートは対象プロジェクト配下に生成されます：

```
your-project/
└── security-reports/
    └── 2025-01-01_1200/
        ├── security-report.html         # HTMLダッシュボード（統合レポート）
        ├── security-remediation.md      # 対策案（Markdown）
        ├── findings_cache.json          # 差分比較用キャッシュ
        ├── dependency-check-report.json # SCA結果
        ├── sbom.json                    # ソフトウェア部品表
        ├── semgrep-java.sarif           # Java SAST結果
        ├── semgrep-js.sarif             # JS/TS SAST結果
        ├── semgrep-python.sarif         # Python SAST結果
        ├── semgrep-custom.sarif         # カスタムルール結果
        ├── trivy.sarif                  # FS/IaC スキャン結果
        └── gitleaks.sarif               # シークレット検出結果
```

### HTMLレポートへの取り込み

| ファイル | HTMLレポート | 説明 |
|----------|:------------:|------|
| `semgrep-*.sarif` | ✅ | コード脆弱性（SAST） |
| `gitleaks.sarif` | ✅ | シークレット漏洩検出 |
| `trivy.sarif` | ✅ | コンテナ/IaC脆弱性 |
| `dependency-check-report.json` | ✅ | 依存ライブラリ脆弱性（SCA） |
| `security-remediation.md` | ❌ | 修復ガイド（別ドキュメント） |
| `sbom.json` | ❌ | ソフトウェア部品表（SBOM） |
| `findings_cache.json` | ❌ | 差分比較用内部キャッシュ |

> **Note**: `security-remediation.md` は修復方法の解説ドキュメントとして別途参照してください。

### 検出結果サンプル（テスト実行時）

```
==================================================
Security Scan Summary
==================================================
Total: 144 findings
  CRITICAL: 0
  HIGH:     36
  MEDIUM:   108
  LOW:      0
==================================================

ツール別内訳:
  - Semgrep OSS:  87件（Java 81, JS/TS 1, Python 5）
  - Trivy:        36件
  - Gitleaks:     21件
```

## ⚙️ 設定オプション（.env）

```bash
# プロジェクト名（レポート用）
PROJECT_NAME=Security Check

# NVD API Key（高速化）
NVD_API_KEY=YOUR_API_KEY

# レポート出力ディレクトリ名
REPORT_OUTPUT_DIR=security-reports

# 重要度フィルタ
SEVERITY_FILTER=HIGH,CRITICAL

# Semgrep並列数
SEMGREP_JOBS=4

# テストスキップ
SKIP_TESTS=true

# DAST有効化
ENABLE_DAST=false
```

## 🔧 前提条件

- **Docker** - Semgrep, Trivy, Gitleaks, ZAP で使用
- **Python 3.8+** - レポート生成で使用
- **Java 17+** & **Maven 3.9+** - Maven プロジェクトの場合

## 🔑 NVD API Key（推奨）

Dependency-Check の高速化のため、NVD API Key の取得を推奨します：

1. https://nvd.nist.gov/developers/request-an-api-key にアクセス
2. メールアドレスを入力して申請（無料・数分で届く）
3. `config/.env` に設定：
   ```bash
   NVD_API_KEY=your-api-key-here
   ```

> ⚠️ API Key がない場合、初回実行時に NVD データベースのダウンロードで **30〜40分** かかります

## 🔄 GitLab CI/CD

GitLab CI で使用する場合：

```bash
# 1. checker フォルダを対象プロジェクトにコピー
cp -r checker/ /path/to/your-project/

# 2. .gitlab-ci.yml を対象プロジェクトのルートにコピー
cp checker/.gitlab-ci.yml /path/to/your-project/.gitlab-ci.yml
```

CI パイプラインは自動的に `checker/` ディレクトリを検査対象から除外します。

## ⚠️ 注意事項

- `checker/` ディレクトリ自体は検査対象から自動除外されます
- 初回実行時は Docker イメージのダウンロードに時間がかかります
- NVD API Key があると Dependency-Check が高速化されます

