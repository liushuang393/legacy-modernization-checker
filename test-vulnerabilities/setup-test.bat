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

echo [3/3] Verifying build...
cd /d "%ROOT%"
call mvn -B -ntp compile -DskipTests
if errorlevel 1 (
    echo   [ERROR] Build failed
    exit /b 1
) else (
    echo   [OK] Build successful
)

echo.
echo ========================================
echo Setup Complete!
echo ========================================
echo.
echo Run security check:
echo   scripts\run_checks_local.bat
echo.
echo Cleanup after test:
echo   test-vulnerabilities\cleanup-test.bat
echo ========================================

exit /b 0
