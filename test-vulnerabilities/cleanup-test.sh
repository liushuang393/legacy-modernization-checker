#!/bin/bash
# =============================================================================
# テスト用脆弱性ファイルを削除するスクリプト
# =============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$SCRIPT_DIR")"

echo "========================================"
echo "テストファイルのクリーンアップ"
echo "========================================"

# 削除対象ディレクトリ
JAVA_TEST_DIR="$ROOT/app-web/src/main/java/com/yourco/web/vulnsamples"
TS_TEST_DIR="$ROOT/app-web/src/main/typescript/vulnsamples"

# Java テストファイルの削除
if [ -d "$JAVA_TEST_DIR" ]; then
    echo "[1/2] Removing Java test files..."
    rm -rf "$JAVA_TEST_DIR"
    echo "  ✓ Removed: $JAVA_TEST_DIR"
else
    echo "[1/2] Java test directory not found (skipped)"
fi

# TypeScript テストファイルの削除
if [ -d "$TS_TEST_DIR" ]; then
    echo "[2/2] Removing TypeScript test files..."
    rm -rf "$TS_TEST_DIR"
    echo "  ✓ Removed: $TS_TEST_DIR"
else
    echo "[2/2] TypeScript test directory not found (skipped)"
fi

echo ""
echo "========================================"
echo "クリーンアップ完了！"
echo "========================================"
echo ""
echo "削除されたテストファイル:"
echo "  - A01_BrokenAccessControl.java"
echo "  - A02_CryptographicFailures.java"
echo "  - A03_Injection.java"
echo "  - A04_InsecureDesign.java"
echo "  - A05_SecurityMisconfiguration.java"
echo "  - A06_VulnerableComponents.java"
echo "  - A07_AuthenticationFailures.java"
echo "  - A08_DataIntegrityFailures.java"
echo "  - A09_LoggingFailures.java"
echo "  - A10_SSRF.java"
echo "  - AutofixExamples.java"
echo "  - SqlInjectionTest.java"
echo "  - XssVulnTest.java"
echo "  - CommandInjectionTest.java"
echo "  - DeserializationTest.java"
echo "  - HardcodedSecretTest.java"
echo "  - PathTraversalTest.java"
echo "  - (TypeScript files)"
echo "========================================"

