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

# ビルド確認
echo "[3/3] Verifying build..."
cd "$ROOT"
if mvn -B -ntp compile -DskipTests > /dev/null 2>&1; then
    echo "  ✓ Build successful"
else
    echo "  ✗ Build failed - please check errors"
    exit 1
fi

echo ""
echo "========================================"
echo "準備完了！"
echo "========================================"
echo ""
echo "次のコマンドでセキュリティチェックを実行:"
echo "  ./scripts/run_checks_local.sh"
echo ""
echo "テスト後のクリーンアップ:"
echo "  ./test-vulnerabilities/cleanup-test.sh"
echo "========================================"

