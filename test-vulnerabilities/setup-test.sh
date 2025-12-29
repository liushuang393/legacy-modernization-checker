#!/bin/bash
# =============================================================================
# テスト用脆弱性ファイルをプロジェクトにコピーするスクリプト
# =============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$SCRIPT_DIR")"

echo "========================================"
echo "セキュリティテスト準備"
echo "========================================"

# Java テストファイルのコピー先
JAVA_TEST_DIR="$ROOT/app-web/src/main/java/com/yourco/web/vulnsamples"

# TypeScript テストファイルのコピー先
TS_TEST_DIR="$ROOT/app-web/src/main/typescript/vulnsamples"

# ディレクトリ作成
mkdir -p "$JAVA_TEST_DIR"
mkdir -p "$TS_TEST_DIR"

# Java ファイルをコピー
echo "[1/3] Copying Java vulnerability test files..."
cp "$SCRIPT_DIR/java/"*.java "$JAVA_TEST_DIR/"
echo "  → $JAVA_TEST_DIR/"

# TypeScript ファイルをコピー
echo "[2/3] Copying TypeScript vulnerability test files..."
cp "$SCRIPT_DIR/typescript/"*.ts "$TS_TEST_DIR/"
echo "  → $TS_TEST_DIR/"

# ビルド確認（オプション）
echo "[3/3] Verifying build (optional)..."
cd "$ROOT"
if command -v mvn &> /dev/null; then
    if mvn -B -ntp compile -DskipTests -U > /dev/null 2>&1; then
        echo "  ✓ Build successful"
    else
        echo "  ⚠ Build failed - test files copied but may have compile errors"
    fi
else
    echo "  ⏭ Maven not found - skipping build verification"
fi

echo ""
echo "========================================"
echo "準備完了！"
echo "========================================"
echo ""
echo "テストファイル:"
echo "  - A01_BrokenAccessControl.java"
echo "  - A02_CryptographicFailures.java"
echo "  - A03_Injection.java"
echo "  - A04-A10 (OWASP Top 10)"
echo "  - AutofixExamples.java"
echo ""
echo "次のコマンドでセキュリティチェックを実行:"
echo "  ./checker/run_check.sh ."
echo ""
echo "テスト後のクリーンアップ:"
echo "  ./test-vulnerabilities/cleanup-test.sh"
echo "========================================"

