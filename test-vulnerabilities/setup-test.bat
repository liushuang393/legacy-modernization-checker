@echo off
setlocal enabledelayedexpansion

REM =============================================================================
REM Setup test vulnerability files for security check testing (Windows)
REM =============================================================================

set SCRIPT_DIR=%~dp0
set ROOT=%SCRIPT_DIR%..

echo ========================================
echo Security Test Setup
echo ========================================

set JAVA_TEST_DIR=%ROOT%\app-web\src\main\java\com\yourco\web\vulnsamples
set TS_TEST_DIR=%ROOT%\app-web\src\main\typescript\vulnsamples

if not exist "%JAVA_TEST_DIR%" mkdir "%JAVA_TEST_DIR%"
if not exist "%TS_TEST_DIR%" mkdir "%TS_TEST_DIR%"

echo [1/3] Copying Java vulnerability test files...
copy "%SCRIPT_DIR%java\*.java" "%JAVA_TEST_DIR%\" >nul
echo   Done: %JAVA_TEST_DIR%

echo [2/3] Copying TypeScript vulnerability test files...
copy "%SCRIPT_DIR%typescript\*.ts" "%TS_TEST_DIR%\" >nul
echo   Done: %TS_TEST_DIR%

echo [3/3] Verifying build (optional)...
cd /d "%ROOT%"
where mvn >nul 2>&1
if errorlevel 1 (
    echo   [SKIP] Maven not found - skipping build verification
) else (
    call mvn -B -ntp compile -DskipTests -U >nul 2>&1
    if errorlevel 1 (
        echo   [WARN] Build failed - test files copied but may have compile errors
    ) else (
        echo   [OK] Build successful
    )
)

echo.
echo ========================================
echo Setup Complete!
echo ========================================
echo.
echo Test files copied:
echo   - A01_BrokenAccessControl.java
echo   - A02_CryptographicFailures.java
echo   - A03_Injection.java
echo   - A04_InsecureDesign.java
echo   - A05_SecurityMisconfiguration.java
echo   - A06_VulnerableComponents.java
echo   - A07_AuthenticationFailures.java
echo   - A08_DataIntegrityFailures.java
echo   - A09_LoggingFailures.java
echo   - A10_SSRF.java
echo   - AutofixExamples.java
echo   - (and more...)
echo.
echo Run security check:
echo   checker\run_check.bat .
echo.
echo Cleanup after test:
echo   test-vulnerabilities\cleanup-test.bat
echo ========================================

exit /b 0
