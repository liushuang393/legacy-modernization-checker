# Legacy Modernization Checker

OWASP Top 10:2025 準拠のセキュリティ検査ツール

## 📁 ディレクトリ構成

```
.
├── checker/                 # 🔧 検査ツール本体（他プロジェクトにコピーして使用）
│   ├── run_check.bat        #    Windows 実行スクリプト
│   ├── run_check.sh         #    Linux/Mac 実行スクリプト
│   ├── .gitlab-ci.yml       #    GitLab CI 設定
│   └── tools/               #    Semgrep, ZAP, レポート生成
│
├── app-*/                   # 🧪 テスト用サンプルアプリ（Spring Boot）
│   ├── app-core/            #    ドメインモデル
│   ├── app-web/             #    REST API
│   ├── app-batch/           #    バッチ処理
│   └── app-security/        #    セキュリティ設定
│
└── test-vulnerabilities/    # 🧪 テスト用脆弱性サンプル
    ├── setup-test.bat       #    脆弱性ファイル配置
    └── cleanup-test.bat     #    脆弱性ファイル削除
```

## 🚀 使い方

### 検査ツールを使う

`checker/` フォルダを任意のプロジェクトにコピーして実行：

```bash
# Windows
checker\run_check.bat D:\workspace\legacy-modernization-starter-v2

# Linux/Mac
./checker/run_check.sh /mnt/d/workspace/legacy-modernization-starter-v2
```

詳細は [checker/README.md](checker/README.md) を参照。

## 🧪 テスト実行

このリポジトリ自体をテスト対象として検査する場合：

```bash
# 1. テスト用脆弱性を配置
test-vulnerabilities\setup-test.bat

# 2. 検査実行
checker\run_check.bat .

# 3. テスト用脆弱性を削除
test-vulnerabilities\cleanup-test.bat
```
