#!/usr/bin/env bash
set -euo pipefail

# ローカルで「持ち込みプロジェクト」を検証する最短手順
# 前提：
# - Java 21
# - Maven 3.9+
# - Docker（ZAP / Semgrep / Trivy 等で使用。無ければスキップ）
# - Python 3.12+（対策案生成用）

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# タイムスタンプ付き出力フォルダを作成
TIMESTAMP=$(date +"%Y-%m-%d_%H%M%S")
REPORT_DIR="$ROOT/reports/$TIMESTAMP"
mkdir -p "$REPORT_DIR"
echo "[INFO] Output directory: $REPORT_DIR"

# Docker 利用可否チェック
DOCKER_AVAILABLE=false
if command -v docker &>/dev/null && docker info &>/dev/null; then
  DOCKER_AVAILABLE=true
  echo "[INFO] Docker: available"
else
  echo "[WARN] Docker: not available - Docker-based scans will be skipped"
fi

# スキップされた検査を記録するファイル
SKIPPED_FILE="$REPORT_DIR/skipped-checks.txt"
: > "$SKIPPED_FILE"

# スキップ記録関数
skip_check() {
  local check_name="$1"
  local reason="$2"
  echo "[SKIP] $check_name - $reason"
  echo "$check_name: $reason" >> "$SKIPPED_FILE"
}

echo "[1/9] Build & Test"
(cd "$ROOT" && mvn -B -ntp test)

echo "[2/9] SCA (Dependency-Check)"
(cd "$ROOT" && mvn -B -ntp org.owasp:dependency-check-maven:check -Dformat=ALL)
f=$(find "$ROOT" -path "*/target/dependency-check-report.json" 2>/dev/null | head -n 1 || true)
if [ -n "$f" ]; then cp "$f" "$REPORT_DIR/dependency-check-report.json"; fi

echo "[3/9] SBOM (CycloneDX)"
(cd "$ROOT" && mvn -B -ntp org.cyclonedx:cyclonedx-maven-plugin:makeAggregateBom -Dcyclonedx.outputFormat=json)
f=$(find "$ROOT" -path "*/target/bom.json" 2>/dev/null | head -n 1 || true)
if [ -n "$f" ]; then cp "$f" "$REPORT_DIR/bom.json"; fi

echo "[4/9] SAST (Semgrep via Docker)"
if [ "$DOCKER_AVAILABLE" = true ]; then
  docker run --rm -v "$ROOT:/src" -w /src semgrep/semgrep \
    semgrep --config "p/java" --sarif --output "/src/reports/$TIMESTAMP/semgrep.sarif" || true
  docker run --rm -v "$ROOT:/src" -w /src semgrep/semgrep \
    semgrep --config tools/semgrep/.semgrep.yml --sarif --output "/src/reports/$TIMESTAMP/semgrep-custom.sarif" || true
else
  skip_check "SAST (Semgrep)" "Docker not available"
fi

echo "[5/9] Container Scan (Trivy)"
if [ "$DOCKER_AVAILABLE" = true ]; then
  docker run --rm -v "$ROOT:/src" -w /src aquasec/trivy:latest \
    fs --format json --output "/src/reports/$TIMESTAMP/trivy-fs.json" --severity HIGH,CRITICAL --exit-code 0 . || true

  if [ -f "$ROOT/Dockerfile" ]; then
    docker build -t app-scan:local "$ROOT"
    docker run --rm -v "$ROOT:/src" -w /src aquasec/trivy:latest \
      image --format json --output "/src/reports/$TIMESTAMP/trivy-image.json" --severity HIGH,CRITICAL --exit-code 0 app-scan:local || true
  elif [ -f "$ROOT/docker/app-web.Dockerfile" ]; then
    docker build -f "$ROOT/docker/app-web.Dockerfile" -t app-web-scan:local "$ROOT"
    docker run --rm -v "$ROOT:/src" -w /src aquasec/trivy:latest \
      image --format json --output "/src/reports/$TIMESTAMP/trivy-image.json" --severity HIGH,CRITICAL --exit-code 0 app-web-scan:local || true
  fi
else
  skip_check "Container Scan (Trivy)" "Docker not available"
fi

echo "[6/9] Secret Detection (Gitleaks)"
if [ "$DOCKER_AVAILABLE" = true ]; then
  docker run --rm -v "$ROOT:/repo" -w /repo zricethezav/gitleaks:latest \
    detect --redact --report-format sarif --report-path "reports/$TIMESTAMP/gitleaks.sarif" --exit-code 0 || true
else
  skip_check "Secret Detection (Gitleaks)" "Docker not available"
fi

echo "[7/9] DAST (ZAP)"
if [ "$DOCKER_AVAILABLE" = true ]; then
  ( cd "$ROOT" && mvn -B -ntp -pl app-web spring-boot:run -Dspring-boot.run.profiles=ci ) &
  APP_PID=$!
  trap 'kill $APP_PID 2>/dev/null || true' EXIT

  for i in $(seq 1 60); do curl -fsS http://localhost:8080/actuator/health && break || sleep 2; done
  docker run --network host --rm -v "$ROOT/tools/zap:/zap/wrk" zaproxy/zap-stable \
    zap.sh -cmd -autorun /zap/wrk/automation.yaml || true
  cp "$ROOT/tools/zap/zap-report.json" "$REPORT_DIR/" 2>/dev/null || true
  cp "$ROOT/tools/zap/zap-report.html" "$REPORT_DIR/" 2>/dev/null || true
else
  skip_check "DAST (ZAP)" "Docker not available"
fi

echo "[8/9] Generate remediation plan (Markdown)"
export SEMGREP_SARIF="$REPORT_DIR/semgrep.sarif"
export DEPCHECK_JSON="$REPORT_DIR/dependency-check-report.json"
export ZAP_JSON="$REPORT_DIR/zap-report.json"
export GITLEAKS_SARIF="$REPORT_DIR/gitleaks.sarif"
export TRIVY_FS_JSON="$REPORT_DIR/trivy-fs.json"
export TRIVY_IMAGE_JSON="$REPORT_DIR/trivy-image.json"
export REMEDIATION_MD="$REPORT_DIR/security-remediation.md"
python "$ROOT/tools/remediate/generate_remediation.py"

echo "[9/9] Generate HTML report"
python "$ROOT/tools/remediate/generate_html_report.py" \
  --input-dir "$REPORT_DIR" \
  --output "$REPORT_DIR/security-report.html" \
  --reports-dir "$ROOT/reports" \
  --project-name "Legacy Modernization"

# latestシンボリックリンクを更新
rm -f "$ROOT/reports/latest" 2>/dev/null || true
ln -sf "$TIMESTAMP" "$ROOT/reports/latest"

echo ""
echo "========================================"
echo "DONE. Reports saved to: $REPORT_DIR"
echo ""
echo "  - security-report.html  (Dashboard)"
echo "  - security-remediation.md"

# スキップされた検査があれば警告表示
if [ -s "$SKIPPED_FILE" ]; then
  echo ""
  echo "[WARNING] 以下の検査はスキップされました（報告書で漏れ判定の可能性あり）:"
  cat "$SKIPPED_FILE" | sed 's/^/  - /'
fi
echo "========================================"
