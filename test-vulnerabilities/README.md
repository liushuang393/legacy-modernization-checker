# テスト用脆弱性サンプル

このフォルダには、セキュリティチェックのテスト用に意図的に脆弱性を含むコードが配置されています。

## 使い方

```bash
# テスト準備（脆弱性ファイルを app-web/src にコピー）
./test-vulnerabilities/setup-test.sh

# セキュリティチェック実行
./scripts/run_checks_local.sh

# テスト後のクリーンアップ
./test-vulnerabilities/cleanup-test.sh
```

## 含まれる脆弱性

| カテゴリ | ファイル | 検出ツール |
|---------|---------|-----------|
| SQL Injection | SqlInjectionTest.java | Semgrep |
| XSS | XssVulnTest.java | Semgrep |
| Path Traversal | PathTraversalTest.java | Semgrep |
| Hardcoded Secret | HardcodedSecretTest.java | Gitleaks |
| Insecure Deserialization | DeserializationTest.java | Semgrep |
| Command Injection | CommandInjectionTest.java | Semgrep |

## 注意

- 本番環境には絶対にデプロイしないでください
- テスト後は必ず cleanup-test.sh を実行してください

