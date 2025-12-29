#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# Security Checker - Zero Invasion Security Scan Tool
# Usage: run_check.sh TARGET_PROJECT_PATH
# Example: run_check.sh /home/user/workspace/my-project
# =============================================================================

TOOL_ROOT="$(cd "$(dirname "$0")" && pwd)"

# Check target project path (REQUIRED)
if [ -z "${1:-}" ]; then
  echo "[ERROR] Please specify target project path"
  echo ""
  echo "Usage: $0 TARGET_PROJECT_PATH"
  echo "Example: $0 /home/user/workspace/my-project"
  exit 1
fi

TARGET_ROOT="$(cd "$1" && pwd)"
if [ ! -d "$TARGET_ROOT" ]; then
  echo "[ERROR] Project not found: $TARGET_ROOT"
  exit 1
fi

# -----------------------------------------------------------------------------
# Load config from checker/config/.env
# -----------------------------------------------------------------------------
PROJECT_NAME="${PROJECT_NAME:-Security Check}"
ENABLE_JAVA_SCAN="false"
ENABLE_TS_SCAN="false"
ENABLE_PYTHON_SCAN="false"
ENABLE_DAST="${ENABLE_DAST:-false}"
SKIP_TESTS="${SKIP_TESTS:-true}"
REPORT_OUTPUT_DIR="${REPORT_OUTPUT_DIR:-security-reports}"
SEVERITY_FILTER="${SEVERITY_FILTER:-HIGH,CRITICAL}"
SEMGREP_JOBS="${SEMGREP_JOBS:-4}"

if [ -f "$TOOL_ROOT/config/.env" ]; then
  echo "[INFO] Loading config from: $TOOL_ROOT/config/.env"
  set -a
  while IFS='=' read -r key value || [ -n "$key" ]; do
    [[ "$key" =~ ^[[:space:]]*# ]] && continue
    [[ -z "$key" ]] && continue
    key=$(echo "$key" | tr -d '\r')
    value=$(echo "$value" | tr -d '\r')
    if [[ "$key" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]]; then
      export "$key=$value"
    fi
  done < "$TOOL_ROOT/config/.env"
  set +a
fi

# -----------------------------------------------------------------------------
# Auto-detect project type by scanning files
# -----------------------------------------------------------------------------
echo ""
echo "============================================================================="
echo "Security Checker - OWASP Top 10:2025"
echo "============================================================================="
echo "[INFO] Tool location: $TOOL_ROOT"
echo "[INFO] Target project: $TARGET_ROOT"
echo ""
echo "[INFO] Scanning project structure..."

HAS_MAVEN="false"
HAS_GRADLE="false"
HAS_NPM="false"

# Check build files
[ -f "$TARGET_ROOT/pom.xml" ] && HAS_MAVEN="true" && echo "[DETECT] pom.xml found - Maven project"
[ -f "$TARGET_ROOT/build.gradle" ] && HAS_GRADLE="true" && echo "[DETECT] build.gradle found - Gradle project"
[ -f "$TARGET_ROOT/package.json" ] && HAS_NPM="true" && echo "[DETECT] package.json found - Node.js project"

# Check source files (excluding checker directory itself)
cd "$TARGET_ROOT"
JAVA_COUNT=$(find . -name "*.java" -not -path "*/checker/*" -not -path "*/node_modules/*" -not -path "*/target/*" 2>/dev/null | wc -l)
JS_COUNT=$(find . -name "*.js" -not -path "*/checker/*" -not -path "*/node_modules/*" -not -path "*/dist/*" 2>/dev/null | wc -l)
TS_COUNT=$(find . -name "*.ts" -not -path "*/checker/*" -not -path "*/node_modules/*" -not -path "*/dist/*" 2>/dev/null | wc -l)
PY_COUNT=$(find . -name "*.py" -not -path "*/checker/*" -not -path "*/.venv/*" 2>/dev/null | wc -l)

[ "$JAVA_COUNT" -gt 0 ] && ENABLE_JAVA_SCAN="true" && echo "[DETECT] $JAVA_COUNT Java files found"
[ "$JS_COUNT" -gt 0 ] && ENABLE_TS_SCAN="true" && echo "[DETECT] $JS_COUNT JavaScript files found"
[ "$TS_COUNT" -gt 0 ] && ENABLE_TS_SCAN="true" && echo "[DETECT] $TS_COUNT TypeScript files found"
[ "$PY_COUNT" -gt 0 ] && ENABLE_PYTHON_SCAN="true" && echo "[DETECT] $PY_COUNT Python files found"

echo ""
echo "[CONFIG] Java scan: $ENABLE_JAVA_SCAN"
echo "[CONFIG] JS/TS scan: $ENABLE_TS_SCAN"
echo "[CONFIG] Python scan: $ENABLE_PYTHON_SCAN"
echo "[CONFIG] Maven build: $HAS_MAVEN"
echo ""

# -----------------------------------------------------------------------------
# Create report directory
# -----------------------------------------------------------------------------
TIMESTAMP=$(date +"%Y-%m-%d_%H%M")
REPORT_DIR="$TARGET_ROOT/$REPORT_OUTPUT_DIR/$TIMESTAMP"
mkdir -p "$REPORT_DIR"
echo "[INFO] Report output: $REPORT_DIR"
echo ""

# Docker path for reports
DOCKER_REPORT_PATH="$REPORT_OUTPUT_DIR/$TIMESTAMP"

# Semgrep exclude pattern (exclude checker directory)
SEMGREP_EXCLUDE="--exclude 'checker' --exclude 'node_modules' --exclude 'target' --exclude 'dist'"

# Docker check
DOCKER_AVAILABLE=false
if command -v docker &>/dev/null && docker info &>/dev/null; then
  DOCKER_AVAILABLE=true
  echo "[INFO] Docker: available"
else
  echo "[WARN] Docker: not available - Docker-based scans will be skipped"
fi

# =============================================================================
# [1/9] Build (Maven/Gradle)
# =============================================================================
echo "[1/9] Build"
if [ "$HAS_MAVEN" = "true" ]; then
  if [ "$SKIP_TESTS" = "true" ]; then
    # install コマンドを使用してマルチモジュールプロジェクトの依存関係をローカルリポジトリにインストール
    (cd "$TARGET_ROOT" && mvn -B -ntp install -DskipTests) || echo "[WARN] Build failed"
  else
    (cd "$TARGET_ROOT" && mvn -B -ntp install) || echo "[WARN] Build failed"
  fi
fi

# =============================================================================
# [2/9] SCA - Dependency Check (Zero invasion)
# =============================================================================
echo ""
echo "[2/9] SCA - Dependency Scanning"
DC_VERSION="12.1.0"
DC_OPTS="-Dformat=ALL -DossindexAnalyzerEnabled=false -DfailBuildOnCVSS=11 -DnvdApiDelay=3600"
if [ -n "${NVD_API_KEY:-}" ] && [ "$NVD_API_KEY" != "YOUR_API_KEY" ]; then
  echo "[INFO] Using NVD API Key"
  DC_OPTS="$DC_OPTS -DnvdApiKey=$NVD_API_KEY"
fi

if [ "$HAS_MAVEN" = "true" ]; then
  (cd "$TARGET_ROOT" && mvn -B -ntp org.owasp:dependency-check-maven:$DC_VERSION:check $DC_OPTS) || true
  f=$(find "$TARGET_ROOT" -path "*/target/dependency-check-report.json" 2>/dev/null | head -n 1 || true)
  [ -n "$f" ] && cp "$f" "$REPORT_DIR/dependency-check-report.json" && echo "[OK] dependency-check-report.json"
fi

# =============================================================================
# [3/9] SBOM Generation (Zero invasion)
# =============================================================================
echo ""
echo "[3/9] SBOM Generation"
CYCLONEDX_VERSION="2.9.1"

if [ "$HAS_MAVEN" = "true" ]; then
  (cd "$TARGET_ROOT" && mvn -B -ntp org.cyclonedx:cyclonedx-maven-plugin:$CYCLONEDX_VERSION:makeAggregateBom -Dcyclonedx.outputFormat=json) || true
  f=$(find "$TARGET_ROOT" -path "*/target/bom.json" 2>/dev/null | head -n 1 || true)
  [ -n "$f" ] && cp "$f" "$REPORT_DIR/sbom.json" && echo "[OK] sbom.json"
fi

# =============================================================================
# [4/9] SAST - Semgrep
# =============================================================================
echo ""
echo "[4/9] SAST - Semgrep"

if [ "$DOCKER_AVAILABLE" = true ]; then
  if [ "$ENABLE_JAVA_SCAN" = "true" ]; then
    echo "[INFO] Scanning Java files..."
    docker run --rm -v "$TARGET_ROOT:/src" -w /src semgrep/semgrep \
      semgrep --config p/java --config p/security-audit --sarif --output "/src/$DOCKER_REPORT_PATH/semgrep-java.sarif" \
      --exclude checker --exclude node_modules --exclude target --jobs "$SEMGREP_JOBS" --timeout 300 || true
    [ -f "$REPORT_DIR/semgrep-java.sarif" ] && echo "[OK] semgrep-java.sarif"

    # Custom rules
    if [ -f "$TOOL_ROOT/tools/semgrep/.semgrep.yml" ]; then
      echo "[INFO] Running custom Java rules..."
      docker run --rm -v "$TARGET_ROOT:/src" -v "$TOOL_ROOT/tools/semgrep:/rules" -w /src semgrep/semgrep \
        semgrep --config /rules/.semgrep.yml --sarif --output "/src/$DOCKER_REPORT_PATH/semgrep-custom.sarif" \
        --exclude checker --timeout 120 || true
    fi
  fi

  if [ "$ENABLE_TS_SCAN" = "true" ]; then
    echo "[INFO] Scanning JavaScript/TypeScript files..."
    docker run --rm -v "$TARGET_ROOT:/src" -w /src semgrep/semgrep \
      semgrep --config p/javascript --config p/typescript --sarif --output "/src/$DOCKER_REPORT_PATH/semgrep-js.sarif" \
      --exclude checker --exclude node_modules --jobs "$SEMGREP_JOBS" --timeout 300 || true
    [ -f "$REPORT_DIR/semgrep-js.sarif" ] && echo "[OK] semgrep-js.sarif"
  fi

  if [ "$ENABLE_PYTHON_SCAN" = "true" ]; then
    echo "[INFO] Scanning Python files..."
    docker run --rm -v "$TARGET_ROOT:/src" -w /src semgrep/semgrep \
      semgrep --config p/python --sarif --output "/src/$DOCKER_REPORT_PATH/semgrep-python.sarif" \
      --exclude checker --jobs "$SEMGREP_JOBS" --timeout 300 || true
    [ -f "$REPORT_DIR/semgrep-python.sarif" ] && echo "[OK] semgrep-python.sarif"
  fi
else
  echo "[SKIP] Semgrep - Docker not available"
fi

# =============================================================================
# [5/9] DAST - ZAP (Optional)
# =============================================================================
echo ""
echo "[5/9] DAST - ZAP"
if [ "$ENABLE_DAST" = "true" ] && [ "$DOCKER_AVAILABLE" = true ]; then
  echo "[INFO] DAST enabled - starting application..."
  # Requires APP_START_CMD in .env
else
  echo "[SKIP] DAST disabled (set ENABLE_DAST=true in .env to enable)"
fi

# =============================================================================
# [6/9] Filesystem Scan - Trivy
# =============================================================================
echo ""
echo "[6/9] Filesystem Scan - Trivy"
if [ "$DOCKER_AVAILABLE" = true ]; then
  docker run --rm -v "$TARGET_ROOT:/src" -w /src aquasec/trivy:latest \
    fs --format sarif --output "/src/$DOCKER_REPORT_PATH/trivy.sarif" --severity "$SEVERITY_FILTER" \
    --skip-dirs checker --skip-dirs node_modules --skip-dirs target . 2>/dev/null || true
  [ -f "$REPORT_DIR/trivy.sarif" ] && echo "[OK] trivy.sarif"
else
  echo "[SKIP] Trivy - Docker not available"
fi

# =============================================================================
# [7/9] Secret Detection - Gitleaks
# =============================================================================
echo ""
echo "[7/9] Secret Detection - Gitleaks"
if [ "$DOCKER_AVAILABLE" = true ]; then
  docker run --rm -v "$TARGET_ROOT:/repo" -w /repo zricethezav/gitleaks:latest \
    detect --redact --report-format sarif --report-path "/repo/$DOCKER_REPORT_PATH/gitleaks.sarif" --exit-code 0 --no-git 2>/dev/null || true
  [ -f "$REPORT_DIR/gitleaks.sarif" ] && echo "[OK] gitleaks.sarif"
else
  echo "[SKIP] Gitleaks - Docker not available"
fi

# =============================================================================
# [8/9] Generate Remediation Plan
# =============================================================================
echo ""
echo "[8/9] Generate Remediation Plan"
export SEMGREP_SARIF="$REPORT_DIR/semgrep-java.sarif"
export DEPCHECK_JSON="$REPORT_DIR/dependency-check-report.json"
export GITLEAKS_SARIF="$REPORT_DIR/gitleaks.sarif"
export TRIVY_FS_JSON="$REPORT_DIR/trivy.sarif"
export REMEDIATION_MD="$REPORT_DIR/security-remediation.md"

if [ -f "$TOOL_ROOT/tools/remediate/generate_remediation.py" ]; then
  python3 "$TOOL_ROOT/tools/remediate/generate_remediation.py" && echo "[OK] security-remediation.md" || echo "[WARN] Failed"
else
  echo "[SKIP] generate_remediation.py not found"
fi

# =============================================================================
# [9/9] Generate HTML Report
# =============================================================================
echo ""
echo "[9/9] Generate HTML Report"
if [ -f "$TOOL_ROOT/tools/remediate/generate_html_report.py" ]; then
  python3 "$TOOL_ROOT/tools/remediate/generate_html_report.py" \
    --input-dir "$REPORT_DIR" \
    --output "$REPORT_DIR/security-report.html" \
    --project-name "$PROJECT_NAME" && echo "[OK] security-report.html" || echo "[WARN] Failed"
else
  echo "[SKIP] generate_html_report.py not found"
fi

# Latest symlink
rm -f "$TARGET_ROOT/$REPORT_OUTPUT_DIR/latest" 2>/dev/null || true
ln -sf "$TIMESTAMP" "$TARGET_ROOT/$REPORT_OUTPUT_DIR/latest"

echo ""
echo "============================================================================="
echo "DONE: Security Check Complete"
echo "============================================================================="
echo "Reports saved to: $REPORT_DIR"
echo ""
ls -1 "$REPORT_DIR"
echo "============================================================================="
