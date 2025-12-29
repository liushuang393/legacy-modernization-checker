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
echo.
echo Removed test files:
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
echo   - SqlInjectionTest.java
echo   - XssVulnTest.java
echo   - CommandInjectionTest.java
echo   - DeserializationTest.java
echo   - HardcodedSecretTest.java
echo   - PathTraversalTest.java
echo   - (TypeScript files)
echo ========================================

exit /b 0

