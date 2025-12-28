@echo off
setlocal enabledelayedexpansion
chcp 65001 >nul

echo ======================================
echo Legacy Modernization - Security Check
echo ======================================

REM プロジェクトルートディレクトリ
set ROOT=%~dp0..
cd /d %ROOT%

REM タイムスタンプ付き出力フォルダを作成
for /f "tokens=1-3 delims=/ " %%a in ('date /t') do set DATESTAMP=%%a-%%b-%%c
for /f "tokens=1-2 delims=: " %%a in ('time /t') do set TIMESTAMP=%%a%%b
set REPORT_DIR=reports\%DATESTAMP: =%%_%TIMESTAMP: =%
if not exist "%REPORT_DIR%" mkdir "%REPORT_DIR%"
echo [INFO] Output directory: %REPORT_DIR%

REM 1. Maven Test
echo [1/9] Build ^& Test
call mvn -B -ntp test
if errorlevel 1 goto ERROR

REM 2. SCA - Dependency Check
echo [2/9] Dependency Scanning
call mvn -B -ntp org.owasp:dependency-check-maven:check -Dformat=ALL
for /f %%f in ('dir /s /b target\dependency-check-report.json 2^>nul') do (
  copy "%%f" "%REPORT_DIR%\dependency-check-report.json" >nul
  goto FOUND_DC
)
:FOUND_DC

REM 3. SBOM
echo [3/9] Generate SBOM
call mvn -B -ntp org.cyclonedx:cyclonedx-maven-plugin:makeAggregateBom -Dcyclonedx.outputFormat=json
for /f %%f in ('dir /s /b target\bom.json 2^>nul') do (
  copy "%%f" "%REPORT_DIR%\bom.json" >nul
  goto FOUND_SBOM
)
:FOUND_SBOM

REM 4. SAST - Semgrep (Docker)
echo [4/9] SAST (Semgrep)
docker run --rm -v "%ROOT%:/src" -w /src semgrep/semgrep ^
  semgrep --config p/java --sarif --output /src/%REPORT_DIR%/semgrep.sarif

docker run --rm -v "%ROOT%:/src" -w /src semgrep/semgrep ^
  semgrep --config tools/semgrep/.semgrep.yml --sarif --output /src/%REPORT_DIR%/semgrep-custom.sarif

REM 5. DAST - ZAP
echo [5/9] DAST (ZAP)
start /b mvn -B -ntp -pl app-web spring-boot:run
echo Waiting for application...
timeout /t 30 >nul

docker run --network host --rm -v "%ROOT%\tools\zap:/zap/wrk" ^
  zaproxy/zap-stable zap.sh -cmd -autorun /zap/wrk/automation.yaml
copy "tools\zap\zap-report.json" "%REPORT_DIR%\" >nul 2>&1
copy "tools\zap\zap-report.html" "%REPORT_DIR%\" >nul 2>&1

REM 6. Container Scan - Trivy
echo [6/9] Container Scan (Trivy)
docker run --rm -v "%ROOT%:/src" -w /src aquasec/trivy:latest ^
  fs --format json --output /src/%REPORT_DIR%/trivy-fs.json --severity HIGH,CRITICAL .

REM 7. Secret Detection - Gitleaks
echo [7/9] Secret Detection (Gitleaks)
docker run --rm -v "%ROOT%:/repo" -w /repo zricethezav/gitleaks:latest ^
  detect --redact --report-format sarif --report-path %REPORT_DIR%/gitleaks.sarif --exit-code 0

REM 8. Generate Remediation Plan (Markdown)
echo [8/9] Generate remediation plan (Markdown)
set SEMGREP_SARIF=%REPORT_DIR%\semgrep.sarif
set DEPCHECK_JSON=%REPORT_DIR%\dependency-check-report.json
set ZAP_JSON=%REPORT_DIR%\zap-report.json
set GITLEAKS_SARIF=%REPORT_DIR%\gitleaks.sarif
set TRIVY_FS_JSON=%REPORT_DIR%\trivy-fs.json
set REMEDIATION_MD=%REPORT_DIR%\security-remediation.md
call python tools\remediate\generate_remediation.py

REM 9. Generate HTML Report
echo [9/9] Generate HTML report
call python tools\remediate\generate_html_report.py ^
  --input-dir "%REPORT_DIR%" ^
  --output "%REPORT_DIR%\security-report.html" ^
  --reports-dir reports ^
  --project-name "Legacy Modernization"

REM latestシンボリックリンクを更新（管理者権限が必要な場合あり）
if exist "reports\latest" rmdir "reports\latest" 2>nul
mklink /D "reports\latest" "%REPORT_DIR%" 2>nul

echo.
echo ======================================
echo DONE. Reports saved to: %REPORT_DIR%
echo.
echo   - security-report.html  (Dashboard)
echo   - security-remediation.md
echo ======================================
exit /b 0

:ERROR
echo ERROR occurred. Please check logs.
exit /b 1
