@echo off
setlocal enabledelayedexpansion
chcp 65001 >nul

REM =============================================================================
REM Security Checker - Zero Invasion Security Scan Tool
REM Usage: run_check.bat TARGET_PROJECT_PATH
REM Example: run_check.bat D:\workspace\my-project
REM =============================================================================

REM Tool installation directory
set "TOOL_ROOT=%~dp0"
set "TOOL_ROOT=%TOOL_ROOT:~0,-1%"

REM Check target project path (REQUIRED)
if "%~1"=="" (
  echo [ERROR] Please specify target project path
  echo.
  echo Usage: %~nx0 TARGET_PROJECT_PATH
  echo Example: %~nx0 D:\workspace\my-project
  exit /b 1
)

set "TARGET_ROOT=%~f1"
if not exist "%TARGET_ROOT%" (
  echo [ERROR] Project not found: %TARGET_ROOT%
  exit /b 1
)

REM JAVA_HOME auto-detection
set JAVA_HOME_VALID=false
if defined JAVA_HOME (
  if exist "%JAVA_HOME%\bin\java.exe" set JAVA_HOME_VALID=true
)
if "%JAVA_HOME_VALID%"=="false" (
  if exist "D:\pleiades\java\21\bin\java.exe" (
    set "JAVA_HOME=D:\pleiades\java\21"
  ) else if exist "C:\Program Files\Java\jdk-21\bin\java.exe" (
    set "JAVA_HOME=C:\Program Files\Java\jdk-21"
  )
)
if defined JAVA_HOME echo [INFO] JAVA_HOME=%JAVA_HOME%

REM -----------------------------------------------------------------------------
REM Load config from checker/config/.env
REM -----------------------------------------------------------------------------
set PROJECT_NAME=Security Check
set ENABLE_JAVA_SCAN=false
set ENABLE_TS_SCAN=false
set ENABLE_PYTHON_SCAN=false
set ENABLE_DAST=false
set SKIP_TESTS=true
set REPORT_OUTPUT_DIR=security-reports
set SEVERITY_FILTER=HIGH,CRITICAL
set SEMGREP_JOBS=4

if exist "%TOOL_ROOT%\config\.env" (
  echo [INFO] Loading config from: %TOOL_ROOT%\config\.env
  for /f "usebackq tokens=1,* delims==" %%a in (`powershell -NoProfile -Command "Get-Content '%TOOL_ROOT%\config\.env' -Encoding UTF8 | Where-Object { $_ -match '^[A-Za-z_][A-Za-z0-9_]*=' }"`) do (
    set "%%a=%%b"
  )
)

REM -----------------------------------------------------------------------------
REM Auto-detect project type by scanning files
REM -----------------------------------------------------------------------------
echo.
echo =============================================================================
echo Security Checker - OWASP Top 10:2025
echo =============================================================================
echo [INFO] Tool location: %TOOL_ROOT%
echo [INFO] Target project: %TARGET_ROOT%
echo.
echo [INFO] Scanning project structure...

set "HAS_MAVEN=false"
set "HAS_GRADLE=false"
set "HAS_NPM=false"
set "HAS_JAVA=false"
set "HAS_JS=false"
set "HAS_TS=false"
set "HAS_PYTHON=false"

REM Check build files
if exist "%TARGET_ROOT%\pom.xml" (
  set "HAS_MAVEN=true"
  echo [DETECT] pom.xml found - Maven project
)
if exist "%TARGET_ROOT%\build.gradle" (
  set "HAS_GRADLE=true"
  echo [DETECT] build.gradle found - Gradle project
)
if exist "%TARGET_ROOT%\package.json" (
  set "HAS_NPM=true"
  echo [DETECT] package.json found - Node.js project
)

REM Check source files by extension
cd /d "%TARGET_ROOT%"
for /f %%n in ('dir /s /b *.java 2^>nul ^| find /c /v ""') do (
  if %%n GTR 0 (
    set "HAS_JAVA=true"
    set "ENABLE_JAVA_SCAN=true"
    echo [DETECT] %%n Java files found
  )
)
for /f %%n in ('dir /s /b *.js 2^>nul ^| find /c /v ""') do (
  if %%n GTR 0 (
    set "HAS_JS=true"
    echo [DETECT] %%n JavaScript files found
  )
)
for /f %%n in ('dir /s /b *.ts 2^>nul ^| find /c /v ""') do (
  if %%n GTR 0 (
    set "HAS_TS=true"
    echo [DETECT] %%n TypeScript files found
  )
)
if "%HAS_JS%"=="true" set "ENABLE_TS_SCAN=true"
if "%HAS_TS%"=="true" set "ENABLE_TS_SCAN=true"

for /f %%n in ('dir /s /b *.py 2^>nul ^| find /c /v ""') do (
  if %%n GTR 0 (
    set "HAS_PYTHON=true"
    set "ENABLE_PYTHON_SCAN=true"
    echo [DETECT] %%n Python files found
  )
)

echo.
echo [CONFIG] Java scan: %ENABLE_JAVA_SCAN%
echo [CONFIG] JS/TS scan: %ENABLE_TS_SCAN%
echo [CONFIG] Python scan: %ENABLE_PYTHON_SCAN%
echo [CONFIG] Maven build: %HAS_MAVEN%
echo.

REM -----------------------------------------------------------------------------
REM Create report directory
REM -----------------------------------------------------------------------------
for /f "tokens=2 delims==" %%i in ('wmic os get localdatetime /value') do set datetime=%%i
set REPORT_TIMESTAMP=%datetime:~0,4%-%datetime:~4,2%-%datetime:~6,2%_%datetime:~8,2%%datetime:~10,2%
set REPORT_DIR=%TARGET_ROOT%\%REPORT_OUTPUT_DIR%\%REPORT_TIMESTAMP%
if not exist "%REPORT_DIR%" mkdir "%REPORT_DIR%"
echo [INFO] Report output: %REPORT_DIR%
echo.

set "DOCKER_MOUNT=%TARGET_ROOT%"
set "DOCKER_REPORT_PATH=%REPORT_OUTPUT_DIR%/%REPORT_TIMESTAMP%"


REM =============================================================================
REM [1/9] Build (Maven/Gradle)
REM =============================================================================
echo [1/9] Build
if "%HAS_MAVEN%"=="true" (
  if "%SKIP_TESTS%"=="true" (
    REM install コマンドを使用してマルチモジュールプロジェクトの依存関係をローカルリポジトリにインストール
    call mvn -B -ntp install -DskipTests -f "%TARGET_ROOT%\pom.xml"
  ) else (
    call mvn -B -ntp install -f "%TARGET_ROOT%\pom.xml"
  )
)

REM =============================================================================
REM [2/9] SCA - Dependency Check (Zero invasion: all config via command line)
REM =============================================================================
echo.
echo [2/9] SCA - Dependency Scanning
set DC_VERSION=12.1.0
set DC_OPTS=-Dformat=ALL -DossindexAnalyzerEnabled=false -DfailBuildOnCVSS=11 -DnvdApiDelay=3600
if defined NVD_API_KEY (
  if not "%NVD_API_KEY%"=="YOUR_API_KEY" (
    echo [INFO] Using NVD API Key
    set DC_OPTS=%DC_OPTS% -DnvdApiKey=%NVD_API_KEY%
  )
)

if "%HAS_MAVEN%"=="true" (
  call mvn -B -ntp org.owasp:dependency-check-maven:%DC_VERSION%:check %DC_OPTS% -f "%TARGET_ROOT%\pom.xml"
  for /f %%f in ('dir /s /b "%TARGET_ROOT%\target\dependency-check-report.json" 2^>nul') do (
    copy "%%f" "%REPORT_DIR%\dependency-check-report.json" >nul
    echo [OK] dependency-check-report.json
  )
)

REM =============================================================================
REM [3/9] SBOM Generation (Zero invasion: version specified via command line)
REM =============================================================================
echo.
echo [3/9] SBOM Generation
set CYCLONEDX_VERSION=2.9.1

if "%HAS_MAVEN%"=="true" (
  call mvn -B -ntp org.cyclonedx:cyclonedx-maven-plugin:%CYCLONEDX_VERSION%:makeAggregateBom -Dcyclonedx.outputFormat=json -f "%TARGET_ROOT%\pom.xml"
  for /f %%f in ('dir /s /b "%TARGET_ROOT%\target\bom.json" 2^>nul') do (
    copy "%%f" "%REPORT_DIR%\sbom.json" >nul
    echo [OK] sbom.json
  )
)

REM =============================================================================
REM [4/9] SAST - Semgrep
REM =============================================================================
echo.
echo [4/9] SAST - Semgrep

REM Semgrep exclude pattern (exclude checker directory)
set "SEMGREP_EXCLUDE=--exclude checker --exclude node_modules --exclude target --exclude dist"

if "%ENABLE_JAVA_SCAN%"=="true" (
  echo [INFO] Scanning Java files...
  call docker run --rm -v "%DOCKER_MOUNT%:/src" -w /src semgrep/semgrep semgrep --config p/java --config p/security-audit --sarif --output "/src/%DOCKER_REPORT_PATH%/semgrep-java.sarif" %SEMGREP_EXCLUDE% --jobs %SEMGREP_JOBS% --timeout 300
  if exist "%REPORT_DIR%\semgrep-java.sarif" echo [OK] semgrep-java.sarif

  REM Custom rules from checker/tools/semgrep
  if exist "%TOOL_ROOT%\tools\semgrep\.semgrep.yml" (
    echo [INFO] Running custom Java rules...
    call docker run --rm -v "%DOCKER_MOUNT%:/src" -v "%TOOL_ROOT%\tools\semgrep:/rules" -w /src semgrep/semgrep semgrep --config /rules/.semgrep.yml --sarif --output "/src/%DOCKER_REPORT_PATH%/semgrep-custom.sarif" %SEMGREP_EXCLUDE% --timeout 120
  )
)

if "%ENABLE_TS_SCAN%"=="true" (
  echo [INFO] Scanning JavaScript/TypeScript files...
  call docker run --rm -v "%DOCKER_MOUNT%:/src" -w /src semgrep/semgrep semgrep --config p/javascript --config p/typescript --sarif --output "/src/%DOCKER_REPORT_PATH%/semgrep-js.sarif" %SEMGREP_EXCLUDE% --jobs %SEMGREP_JOBS% --timeout 300
  if exist "%REPORT_DIR%\semgrep-js.sarif" echo [OK] semgrep-js.sarif
)

if "%ENABLE_PYTHON_SCAN%"=="true" (
  echo [INFO] Scanning Python files...
  call docker run --rm -v "%DOCKER_MOUNT%:/src" -w /src semgrep/semgrep semgrep --config p/python --sarif --output "/src/%DOCKER_REPORT_PATH%/semgrep-python.sarif" %SEMGREP_EXCLUDE% --jobs %SEMGREP_JOBS% --timeout 300
  if exist "%REPORT_DIR%\semgrep-python.sarif" echo [OK] semgrep-python.sarif
)

REM =============================================================================
REM [5/9] DAST - ZAP (Optional)
REM =============================================================================
echo.
echo [5/9] DAST - ZAP
if "%ENABLE_DAST%"=="true" (
  echo [INFO] DAST enabled - starting application...
  REM This requires APP_START_CMD to be set in .env
) else (
  echo [SKIP] DAST disabled (set ENABLE_DAST=true in .env to enable)
)

REM =============================================================================
REM [6/9] Container/Filesystem Scan - Trivy
REM =============================================================================
echo.
echo [6/9] Filesystem Scan - Trivy
call docker run --rm -v "%DOCKER_MOUNT%:/src" -w /src aquasec/trivy:latest fs --format sarif --output "/src/%DOCKER_REPORT_PATH%/trivy.sarif" --severity %SEVERITY_FILTER% --skip-dirs checker --skip-dirs node_modules --skip-dirs target . 2>nul
if exist "%REPORT_DIR%\trivy.sarif" echo [OK] trivy.sarif

REM =============================================================================
REM [7/9] Secret Detection - Gitleaks
REM =============================================================================
echo.
echo [7/9] Secret Detection - Gitleaks
call docker run --rm -v "%DOCKER_MOUNT%:/repo" -w /repo zricethezav/gitleaks:latest detect --redact --report-format sarif --report-path "/repo/%DOCKER_REPORT_PATH%/gitleaks.sarif" --exit-code 0 --no-git 2>nul
if exist "%REPORT_DIR%\gitleaks.sarif" echo [OK] gitleaks.sarif

REM =============================================================================
REM [8/9] Generate Remediation Plan
REM =============================================================================
echo.
echo [8/9] Generate Remediation Plan
set SEMGREP_SARIF=%REPORT_DIR%\semgrep-java.sarif
set DEPCHECK_JSON=%REPORT_DIR%\dependency-check-report.json
set GITLEAKS_SARIF=%REPORT_DIR%\gitleaks.sarif
set TRIVY_FS_JSON=%REPORT_DIR%\trivy.sarif
set REMEDIATION_MD=%REPORT_DIR%\security-remediation.md

if exist "%TOOL_ROOT%\tools\remediate\generate_remediation.py" (
  call python "%TOOL_ROOT%\tools\remediate\generate_remediation.py"
  if exist "%REMEDIATION_MD%" echo [OK] security-remediation.md
) else (
  echo [SKIP] generate_remediation.py not found
)

REM =============================================================================
REM [9/9] Generate HTML Report
REM =============================================================================
echo.
echo [9/9] Generate HTML Report
if exist "%TOOL_ROOT%\tools\remediate\generate_html_report.py" (
  call python "%TOOL_ROOT%\tools\remediate\generate_html_report.py" --input-dir "%REPORT_DIR%" --output "%REPORT_DIR%\security-report.html" --project-name "%PROJECT_NAME%"
  if exist "%REPORT_DIR%\security-report.html" echo [OK] security-report.html
) else (
  echo [SKIP] generate_html_report.py not found
)

echo.
echo =============================================================================
echo DONE: Security Check Complete
echo =============================================================================
echo Reports saved to: %REPORT_DIR%
echo.
dir /b "%REPORT_DIR%"
echo =============================================================================

start "" "%REPORT_DIR%"
endlocal
exit /b 0

