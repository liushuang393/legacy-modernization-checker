#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# Legacy Modernization Checker - セキュリティ検証スクリプト
# =============================================================================
# 使用方法:
#   1. scripts/.env.sample をコピーして scripts/.env を作成
#   2. プロジェクトに合わせて .env を編集
#   3. ./scripts/run_checks_local.sh を実行
#
# 前提：
# - Docker（Semgrep / ZAP / Trivy 等で使用。無ければスキップ）
# - Python 3.12+（対策案生成用）
# - （Maven プロジェクトの場合）Java 21 + Maven 3.9+
# - （npm プロジェクトの場合）Node.js 18+
# =============================================================================

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# -----------------------------------------------------------------------------
# 設定ファイル読み込み
# -----------------------------------------------------------------------------
load_config() {
  # デフォルト値を設定
  PROJECT_NAME="${PROJECT_NAME:-Security Check}"
  PROJECT_TYPE="${PROJECT_TYPE:-maven}"
  SCAN_PATHS="${SCAN_PATHS:-}"
  SCAN_EXCLUDE="${SCAN_EXCLUDE:-node_modules,dist,build,target,.git,vendor}"
  ENABLE_JAVA_SCAN="${ENABLE_JAVA_SCAN:-true}"
  ENABLE_TS_SCAN="${ENABLE_TS_SCAN:-true}"
  ENABLE_PYTHON_SCAN="${ENABLE_PYTHON_SCAN:-false}"
  BUILD_ROOT="${BUILD_ROOT:-.}"
  SKIP_TESTS="${SKIP_TESTS:-false}"
  NPM_ROOTS="${NPM_ROOTS:-}"
  ENABLE_DAST="${ENABLE_DAST:-true}"
  APP_START_CMD="${APP_START_CMD:-mvn -B -ntp spring-boot:run}"
  APP_START_DIR="${APP_START_DIR:-.}"
  APP_PORT="${APP_PORT:-8080}"
  HEALTH_CHECK_PATH="${HEALTH_CHECK_PATH:-/actuator/health}"
  APP_START_TIMEOUT="${APP_START_TIMEOUT:-60}"
  ZAP_TARGET_URLS="${ZAP_TARGET_URLS:-}"
  DOCKERFILES="${DOCKERFILES:-}"
  REPORT_OUTPUT_DIR="${REPORT_OUTPUT_DIR:-reports}"
  SEVERITY_FILTER="${SEVERITY_FILTER:-HIGH,CRITICAL}"
  SEMGREP_JAVA_RULES="${SEMGREP_JAVA_RULES:-tools/semgrep/.semgrep.yml}"
  SEMGREP_TS_RULES="${SEMGREP_TS_RULES:-tools/semgrep/.semgrep-typescript.yml}"
  ZAP_CONFIG="${ZAP_CONFIG:-tools/zap/automation.yaml}"
  DOCKER_SCAN_TAG="${DOCKER_SCAN_TAG:-security-scan:local}"
  SEMGREP_JOBS="${SEMGREP_JOBS:-4}"
}

# .env ファイルを読み込み（存在する場合）
if [ -f "$SCRIPT_DIR/.env" ]; then
  echo "[INFO] Loading config from: $SCRIPT_DIR/.env"
  set -a
  source "$SCRIPT_DIR/.env"
  set +a
else
  echo "[INFO] No .env file found, using defaults. Copy .env.sample to .env for customization."
fi

# 設定を適用
load_config

# タイムスタンプ付き出力フォルダを作成
TIMESTAMP=$(date +"%Y-%m-%d_%H%M%S")
REPORT_DIR="$ROOT/$REPORT_OUTPUT_DIR/$TIMESTAMP"
mkdir -p "$REPORT_DIR"
echo "[INFO] Project: $PROJECT_NAME"
echo "[INFO] Project type: $PROJECT_TYPE"
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

# -----------------------------------------------------------------------------
# [1/9] Build & Test
# -----------------------------------------------------------------------------
echo "[1/9] Build & Test"
BUILD_DIR="$ROOT/$BUILD_ROOT"

if [[ "$PROJECT_TYPE" == *"maven"* ]]; then
  if [ "$SKIP_TESTS" = "true" ]; then
    (cd "$BUILD_DIR" && mvn -B -ntp package -DskipTests)
  else
    (cd "$BUILD_DIR" && mvn -B -ntp test)
  fi
fi

if [[ "$PROJECT_TYPE" == *"npm"* ]] && [ -n "$NPM_ROOTS" ]; then
  IFS=',' read -ra NPM_DIRS <<< "$NPM_ROOTS"
  for npm_dir in "${NPM_DIRS[@]}"; do
    echo "[INFO] npm install in $npm_dir"
    (cd "$ROOT/$npm_dir" && npm ci && npm run build 2>/dev/null || npm run compile 2>/dev/null || true)
  done
fi

# -----------------------------------------------------------------------------
# [2/9] SCA (Dependency-Check)
# -----------------------------------------------------------------------------
echo "[2/9] SCA (Dependency-Check)"

if [[ "$PROJECT_TYPE" == *"maven"* ]]; then
  (cd "$BUILD_DIR" && mvn -B -ntp org.owasp:dependency-check-maven:check -Dformat=ALL) || true
  f=$(find "$BUILD_DIR" -path "*/target/dependency-check-report.json" 2>/dev/null | head -n 1 || true)
  if [ -n "$f" ]; then cp "$f" "$REPORT_DIR/dependency-check-report.json"; fi
fi

if [[ "$PROJECT_TYPE" == *"npm"* ]] && [ -n "$NPM_ROOTS" ]; then
  IFS=',' read -ra NPM_DIRS <<< "$NPM_ROOTS"
  for npm_dir in "${NPM_DIRS[@]}"; do
    echo "[INFO] npm audit in $npm_dir"
    (cd "$ROOT/$npm_dir" && npm audit --json > "$REPORT_DIR/npm-audit-$(basename $npm_dir).json" 2>/dev/null || true)
  done
fi

# -----------------------------------------------------------------------------
# [3/9] SBOM (CycloneDX)
# -----------------------------------------------------------------------------
echo "[3/9] SBOM (CycloneDX)"

if [[ "$PROJECT_TYPE" == *"maven"* ]]; then
  (cd "$BUILD_DIR" && mvn -B -ntp org.cyclonedx:cyclonedx-maven-plugin:makeAggregateBom -Dcyclonedx.outputFormat=json) || true
  f=$(find "$BUILD_DIR" -path "*/target/bom.json" 2>/dev/null | head -n 1 || true)
  if [ -n "$f" ]; then cp "$f" "$REPORT_DIR/bom.json"; fi
fi

if [[ "$PROJECT_TYPE" == *"npm"* ]] && [ -n "$NPM_ROOTS" ]; then
  if command -v npx &>/dev/null; then
    IFS=',' read -ra NPM_DIRS <<< "$NPM_ROOTS"
    for npm_dir in "${NPM_DIRS[@]}"; do
      echo "[INFO] SBOM for $npm_dir"
      (cd "$ROOT/$npm_dir" && npx @cyclonedx/cyclonedx-npm --output-file "$REPORT_DIR/bom-$(basename $npm_dir).json" 2>/dev/null || true)
    done
  fi
fi

# -----------------------------------------------------------------------------
# [4/9] SAST (Semgrep via Docker)
# -----------------------------------------------------------------------------
echo "[4/9] SAST (Semgrep via Docker)"
if [ "$DOCKER_AVAILABLE" = true ]; then
  REPORT_PATH="/src/$REPORT_OUTPUT_DIR/$TIMESTAMP"

  # Java スキャン
  if [ "$ENABLE_JAVA_SCAN" = "true" ]; then
    echo "[INFO] Scanning Java..."
    docker run --rm -v "$ROOT:/src" -w /src semgrep/semgrep \
      semgrep --config "p/java" --sarif --output "$REPORT_PATH/semgrep.sarif" --jobs "$SEMGREP_JOBS" || true
    if [ -f "$ROOT/$SEMGREP_JAVA_RULES" ]; then
      docker run --rm -v "$ROOT:/src" -w /src semgrep/semgrep \
        semgrep --config "$SEMGREP_JAVA_RULES" --sarif --output "$REPORT_PATH/semgrep-custom.sarif" --jobs "$SEMGREP_JOBS" || true
    fi
  fi

  # TypeScript/JavaScript スキャン
  if [ "$ENABLE_TS_SCAN" = "true" ]; then
    echo "[INFO] Scanning TypeScript/JavaScript..."
    docker run --rm -v "$ROOT:/src" -w /src semgrep/semgrep \
      semgrep --config "p/typescript" --config "p/javascript" --sarif --output "$REPORT_PATH/semgrep-ts.sarif" --jobs "$SEMGREP_JOBS" || true
    if [ -f "$ROOT/$SEMGREP_TS_RULES" ]; then
      docker run --rm -v "$ROOT:/src" -w /src semgrep/semgrep \
        semgrep --config "$SEMGREP_TS_RULES" --sarif --output "$REPORT_PATH/semgrep-ts-custom.sarif" --jobs "$SEMGREP_JOBS" || true
    fi
  fi

  # Python スキャン
  if [ "$ENABLE_PYTHON_SCAN" = "true" ]; then
    echo "[INFO] Scanning Python..."
    docker run --rm -v "$ROOT:/src" -w /src semgrep/semgrep \
      semgrep --config "p/python" --sarif --output "$REPORT_PATH/semgrep-python.sarif" --jobs "$SEMGREP_JOBS" || true
  fi
else
  skip_check "SAST (Semgrep)" "Docker not available"
fi

# -----------------------------------------------------------------------------
# [5/9] Container Scan (Trivy)
# -----------------------------------------------------------------------------
echo "[5/9] Container Scan (Trivy)"
if [ "$DOCKER_AVAILABLE" = true ]; then
  REPORT_PATH="/src/$REPORT_OUTPUT_DIR/$TIMESTAMP"

  # ファイルシステムスキャン
  docker run --rm -v "$ROOT:/src" -w /src aquasec/trivy:latest \
    fs --format json --output "$REPORT_PATH/trivy-fs.json" --severity "$SEVERITY_FILTER" --exit-code 0 . || true

  # Dockerfile スキャン（設定または自動検出）
  if [ -n "$DOCKERFILES" ]; then
    IFS=',' read -ra DOCKER_FILES <<< "$DOCKERFILES"
    for dockerfile in "${DOCKER_FILES[@]}"; do
      if [ -f "$ROOT/$dockerfile" ]; then
        echo "[INFO] Building and scanning: $dockerfile"
        docker build -f "$ROOT/$dockerfile" -t "$DOCKER_SCAN_TAG" "$ROOT" || continue
        docker run --rm -v "$ROOT:/src" -w /src aquasec/trivy:latest \
          image --format json --output "$REPORT_PATH/trivy-image.json" --severity "$SEVERITY_FILTER" --exit-code 0 "$DOCKER_SCAN_TAG" || true
      fi
    done
  else
    # 自動検出
    for df in "Dockerfile" "docker/Dockerfile" "docker/app-web.Dockerfile"; do
      if [ -f "$ROOT/$df" ]; then
        echo "[INFO] Auto-detected Dockerfile: $df"
        docker build -f "$ROOT/$df" -t "$DOCKER_SCAN_TAG" "$ROOT" || continue
        docker run --rm -v "$ROOT:/src" -w /src aquasec/trivy:latest \
          image --format json --output "$REPORT_PATH/trivy-image.json" --severity "$SEVERITY_FILTER" --exit-code 0 "$DOCKER_SCAN_TAG" || true
        break
      fi
    done
  fi
else
  skip_check "Container Scan (Trivy)" "Docker not available"
fi

# -----------------------------------------------------------------------------
# [6/9] Secret Detection (Gitleaks)
# -----------------------------------------------------------------------------
echo "[6/9] Secret Detection (Gitleaks)"
if [ "$DOCKER_AVAILABLE" = true ]; then
  docker run --rm -v "$ROOT:/repo" -w /repo zricethezav/gitleaks:latest \
    detect --redact --report-format sarif --report-path "$REPORT_OUTPUT_DIR/$TIMESTAMP/gitleaks.sarif" --exit-code 0 || true
else
  skip_check "Secret Detection (Gitleaks)" "Docker not available"
fi

# -----------------------------------------------------------------------------
# [7/9] DAST (ZAP)
# -----------------------------------------------------------------------------
echo "[7/9] DAST (ZAP)"
if [ "$DOCKER_AVAILABLE" = true ] && [ "$ENABLE_DAST" = "true" ]; then
  # アプリケーション起動
  echo "[INFO] Starting application: $APP_START_CMD"
  ( cd "$ROOT/$APP_START_DIR" && $APP_START_CMD ) &
  APP_PID=$!
  trap 'kill $APP_PID 2>/dev/null || true' EXIT

  # ヘルスチェック待機
  TARGET_URL="http://localhost:${APP_PORT}${HEALTH_CHECK_PATH}"
  echo "[INFO] Waiting for application at $TARGET_URL (timeout: ${APP_START_TIMEOUT}s)"
  for i in $(seq 1 "$APP_START_TIMEOUT"); do
    curl -fsS "$TARGET_URL" && break || sleep 2
  done

  # ZAP スキャン実行
  docker run --network host --rm -v "$ROOT/$(dirname $ZAP_CONFIG):/zap/wrk" zaproxy/zap-stable \
    zap.sh -cmd -autorun /zap/wrk/$(basename $ZAP_CONFIG) || true
  ZAP_OUTPUT_DIR="$ROOT/$(dirname $ZAP_CONFIG)"
  cp "$ZAP_OUTPUT_DIR/zap-report.json" "$REPORT_DIR/" 2>/dev/null || true
  cp "$ZAP_OUTPUT_DIR/zap-report.html" "$REPORT_DIR/" 2>/dev/null || true
elif [ "$ENABLE_DAST" != "true" ]; then
  skip_check "DAST (ZAP)" "Disabled in config (ENABLE_DAST=false)"
else
  skip_check "DAST (ZAP)" "Docker not available"
fi

# -----------------------------------------------------------------------------
# [8/9] Generate remediation plan (Markdown)
# -----------------------------------------------------------------------------
echo "[8/9] Generate remediation plan (Markdown)"
export SEMGREP_SARIF="$REPORT_DIR/semgrep.sarif"
export DEPCHECK_JSON="$REPORT_DIR/dependency-check-report.json"
export ZAP_JSON="$REPORT_DIR/zap-report.json"
export GITLEAKS_SARIF="$REPORT_DIR/gitleaks.sarif"
export TRIVY_FS_JSON="$REPORT_DIR/trivy-fs.json"
export TRIVY_IMAGE_JSON="$REPORT_DIR/trivy-image.json"
export REMEDIATION_MD="$REPORT_DIR/security-remediation.md"
python "$ROOT/tools/remediate/generate_remediation.py"

# -----------------------------------------------------------------------------
# [9/9] Generate HTML report
# -----------------------------------------------------------------------------
echo "[9/9] Generate HTML report"
python "$ROOT/tools/remediate/generate_html_report.py" \
  --input-dir "$REPORT_DIR" \
  --output "$REPORT_DIR/security-report.html" \
  --reports-dir "$ROOT/$REPORT_OUTPUT_DIR" \
  --project-name "$PROJECT_NAME"

# latest シンボリックリンクを更新
rm -f "$ROOT/$REPORT_OUTPUT_DIR/latest" 2>/dev/null || true
ln -sf "$TIMESTAMP" "$ROOT/$REPORT_OUTPUT_DIR/latest"

echo ""
echo "========================================"
echo "DONE: $PROJECT_NAME - Security Check Complete"
echo "========================================"
echo "Reports saved to: $REPORT_DIR"
echo ""
echo "  📊 security-report.html  (Dashboard)"
echo "  📝 security-remediation.md"

# スキップされた検査があれば警告表示
if [ -s "$SKIPPED_FILE" ]; then
  echo ""
  echo "⚠️  以下の検査はスキップされました:"
  cat "$SKIPPED_FILE" | sed 's/^/     - /'
fi
echo "========================================"
