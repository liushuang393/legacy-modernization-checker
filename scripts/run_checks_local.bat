@echo off
setlocal enabledelayedexpansion
chcp 65001 >nul

REM =============================================================================
REM Legacy Modernization Checker - セキュリティ検証スクリプト (Windows)
REM =============================================================================

REM プロジェクトルートディレクトリ
set ROOT=%~dp0..
set SCRIPT_DIR=%~dp0
cd /d %ROOT%

REM -----------------------------------------------------------------------------
REM 設定ファイル読み込み
REM -----------------------------------------------------------------------------
REM デフォルト値を設定
set PROJECT_NAME=Security Check
set PROJECT_TYPE=maven
set ENABLE_JAVA_SCAN=true
set ENABLE_TS_SCAN=true
set ENABLE_PYTHON_SCAN=false
set BUILD_ROOT=.
set SKIP_TESTS=false
set ENABLE_DAST=true
set APP_START_CMD=mvn -B -ntp spring-boot:run
set APP_START_DIR=.
set APP_PORT=8080
set HEALTH_CHECK_PATH=/actuator/health
set APP_START_TIMEOUT=60
set REPORT_OUTPUT_DIR=reports
set SEVERITY_FILTER=HIGH,CRITICAL
set SEMGREP_JAVA_RULES=tools/semgrep/.semgrep.yml
set SEMGREP_TS_RULES=tools/semgrep/.semgrep-typescript.yml
set ZAP_CONFIG=tools/zap/automation.yaml
set SEMGREP_JOBS=4

REM .env ファイルを読み込み（存在する場合）
if exist "%SCRIPT_DIR%.env" (
  echo [INFO] Loading config from: %SCRIPT_DIR%.env
  for /f "usebackq tokens=1,* delims==" %%a in ("%SCRIPT_DIR%.env") do (
    set "line=%%a"
    if not "!line:~0,1!"=="#" (
      set "%%a=%%b"
    )
  )
) else (
  echo [INFO] No .env file found, using defaults.
)

echo ======================================
echo %PROJECT_NAME% - Security Check
echo ======================================
echo [INFO] Project type: %PROJECT_TYPE%

REM タイムスタンプ付き出力フォルダを作成
for /f "tokens=1-3 delims=/ " %%a in ('date /t') do set DATESTAMP=%%a-%%b-%%c
for /f "tokens=1-2 delims=: " %%a in ('time /t') do set TIMESTAMP=%%a%%b
set REPORT_DIR=%REPORT_OUTPUT_DIR%\%DATESTAMP: =%%_%TIMESTAMP: =%
if not exist "%REPORT_DIR%" mkdir "%REPORT_DIR%"
echo [INFO] Output directory: %REPORT_DIR%

REM -----------------------------------------------------------------------------
REM [1/9] Build & Test
REM -----------------------------------------------------------------------------
echo [1/9] Build ^& Test
if "%SKIP_TESTS%"=="true" (
  call mvn -B -ntp package -DskipTests -f "%BUILD_ROOT%\pom.xml"
) else (
  call mvn -B -ntp test -f "%BUILD_ROOT%\pom.xml"
)
if errorlevel 1 goto ERROR

REM -----------------------------------------------------------------------------
REM [2/9] SCA - Dependency Check
REM -----------------------------------------------------------------------------
echo [2/9] Dependency Scanning
call mvn -B -ntp org.owasp:dependency-check-maven:check -Dformat=ALL -f "%BUILD_ROOT%\pom.xml"
for /f %%f in ('dir /s /b "%BUILD_ROOT%\target\dependency-check-report.json" 2^>nul') do (
  copy "%%f" "%REPORT_DIR%\dependency-check-report.json" >nul
  goto FOUND_DC
)
:FOUND_DC

REM -----------------------------------------------------------------------------
REM [3/9] SBOM
REM -----------------------------------------------------------------------------
echo [3/9] Generate SBOM
call mvn -B -ntp org.cyclonedx:cyclonedx-maven-plugin:makeAggregateBom -Dcyclonedx.outputFormat=json -f "%BUILD_ROOT%\pom.xml"
for /f %%f in ('dir /s /b "%BUILD_ROOT%\target\bom.json" 2^>nul') do (
  copy "%%f" "%REPORT_DIR%\bom.json" >nul
  goto FOUND_SBOM
)
:FOUND_SBOM

REM -----------------------------------------------------------------------------
REM [4/9] SAST - Semgrep (Docker)
REM -----------------------------------------------------------------------------
echo [4/9] SAST (Semgrep)

REM Java スキャン
if "%ENABLE_JAVA_SCAN%"=="true" (
  echo [INFO] Scanning Java...
  docker run --rm -v "%ROOT%:/src" -w /src semgrep/semgrep ^
    semgrep --config p/java --sarif --output /src/%REPORT_DIR%/semgrep.sarif --jobs %SEMGREP_JOBS%
  if exist "%ROOT%\%SEMGREP_JAVA_RULES%" (
    docker run --rm -v "%ROOT%:/src" -w /src semgrep/semgrep ^
      semgrep --config %SEMGREP_JAVA_RULES% --sarif --output /src/%REPORT_DIR%/semgrep-custom.sarif --jobs %SEMGREP_JOBS%
  )
)

REM TypeScript/JavaScript スキャン
if "%ENABLE_TS_SCAN%"=="true" (
  echo [INFO] Scanning TypeScript/JavaScript...
  docker run --rm -v "%ROOT%:/src" -w /src semgrep/semgrep ^
    semgrep --config p/typescript --config p/javascript --sarif --output /src/%REPORT_DIR%/semgrep-ts.sarif --jobs %SEMGREP_JOBS%
  if exist "%ROOT%\%SEMGREP_TS_RULES%" (
    docker run --rm -v "%ROOT%:/src" -w /src semgrep/semgrep ^
      semgrep --config %SEMGREP_TS_RULES% --sarif --output /src/%REPORT_DIR%/semgrep-ts-custom.sarif --jobs %SEMGREP_JOBS%
  )
)

REM -----------------------------------------------------------------------------
REM [5/9] DAST - ZAP
REM -----------------------------------------------------------------------------
echo [5/9] DAST (ZAP)
if "%ENABLE_DAST%"=="true" (
  echo [INFO] Starting application: %APP_START_CMD%
  pushd "%APP_START_DIR%"
  start /b %APP_START_CMD%
  popd
  echo [INFO] Waiting for application on port %APP_PORT%...
  timeout /t %APP_START_TIMEOUT% >nul

  docker run --network host --rm -v "%ROOT%\tools\zap:/zap/wrk" ^
    zaproxy/zap-stable zap.sh -cmd -autorun /zap/wrk/automation.yaml
  copy "tools\zap\zap-report.json" "%REPORT_DIR%\" >nul 2>&1
  copy "tools\zap\zap-report.html" "%REPORT_DIR%\" >nul 2>&1
) else (
  echo [SKIP] DAST disabled in config
)

REM -----------------------------------------------------------------------------
REM [6/9] Container Scan - Trivy
REM -----------------------------------------------------------------------------
echo [6/9] Container Scan (Trivy)
docker run --rm -v "%ROOT%:/src" -w /src aquasec/trivy:latest ^
  fs --format json --output /src/%REPORT_DIR%/trivy-fs.json --severity %SEVERITY_FILTER% .

REM -----------------------------------------------------------------------------
REM [7/9] Secret Detection - Gitleaks
REM -----------------------------------------------------------------------------
echo [7/9] Secret Detection (Gitleaks)
docker run --rm -v "%ROOT%:/repo" -w /repo zricethezav/gitleaks:latest ^
  detect --redact --report-format sarif --report-path %REPORT_DIR%/gitleaks.sarif --exit-code 0

REM -----------------------------------------------------------------------------
REM [8/9] Generate Remediation Plan (Markdown)
REM -----------------------------------------------------------------------------
echo [8/9] Generate remediation plan (Markdown)
set SEMGREP_SARIF=%REPORT_DIR%\semgrep.sarif
set DEPCHECK_JSON=%REPORT_DIR%\dependency-check-report.json
set ZAP_JSON=%REPORT_DIR%\zap-report.json
set GITLEAKS_SARIF=%REPORT_DIR%\gitleaks.sarif
set TRIVY_FS_JSON=%REPORT_DIR%\trivy-fs.json
set REMEDIATION_MD=%REPORT_DIR%\security-remediation.md
call python tools\remediate\generate_remediation.py

REM -----------------------------------------------------------------------------
REM [9/9] Generate HTML Report
REM -----------------------------------------------------------------------------
echo [9/9] Generate HTML report
call python tools\remediate\generate_html_report.py ^
  --input-dir "%REPORT_DIR%" ^
  --output "%REPORT_DIR%\security-report.html" ^
  --reports-dir "%REPORT_OUTPUT_DIR%" ^
  --project-name "%PROJECT_NAME%"

REM latestシンボリックリンクを更新（管理者権限が必要な場合あり）
if exist "%REPORT_OUTPUT_DIR%\latest" rmdir "%REPORT_OUTPUT_DIR%\latest" 2>nul
mklink /D "%REPORT_OUTPUT_DIR%\latest" "%REPORT_DIR%" 2>nul

echo.
echo ======================================
echo DONE: %PROJECT_NAME% - Security Check Complete
echo ======================================
echo Reports saved to: %REPORT_DIR%
echo.
echo   - security-report.html  (Dashboard)
echo   - security-remediation.md
echo ======================================
exit /b 0

:ERROR
echo ERROR occurred. Please check logs.
exit /b 1
