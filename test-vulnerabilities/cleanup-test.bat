@echo off
setlocal enabledelayedexpansion

REM =============================================================================
REM Cleanup test vulnerability files (Windows)
REM =============================================================================

set SCRIPT_DIR=%~dp0
set ROOT=%SCRIPT_DIR%..

echo ========================================
echo Test File Cleanup
echo ========================================

set JAVA_TEST_DIR=%ROOT%\app-web\src\main\java\com\yourco\web\vulnsamples
set TS_TEST_DIR=%ROOT%\app-web\src\main\typescript\vulnsamples

if exist "%JAVA_TEST_DIR%" (
    echo [1/2] Removing Java test files...
    rmdir /s /q "%JAVA_TEST_DIR%"
    echo   Removed: %JAVA_TEST_DIR%
) else (
    echo [1/2] Java test directory not found - skipped
)

if exist "%TS_TEST_DIR%" (
    echo [2/2] Removing TypeScript test files...
    rmdir /s /q "%TS_TEST_DIR%"
    echo   Removed: %TS_TEST_DIR%
) else (
    echo [2/2] TypeScript test directory not found - skipped
)

echo.
echo ========================================
echo Cleanup Complete!
echo ========================================

exit /b 0

