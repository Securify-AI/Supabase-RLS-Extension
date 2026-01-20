@echo off
REM Build script for Supabase RLS Scanner on Windows
REM This script provides similar functionality to the Makefile for Windows users

setlocal enabledelayedexpansion

set PROJECT_NAME=supabase-rls-scanner
set VERSION=1.0.0
set JAR_NAME=%PROJECT_NAME%-%VERSION%.jar
set BUILD_DIR=build\libs

REM Check if argument is provided
if "%1"=="" goto build
if "%1"=="build" goto build
if "%1"=="clean" goto clean
if "%1"=="test" goto test
if "%1"=="verify" goto verify
if "%1"=="info" goto info
if "%1"=="help" goto help
goto help

:build
echo.
echo [BUILD] Building %PROJECT_NAME%...
echo.
call gradlew.bat clean build --no-daemon
if errorlevel 1 (
    echo [ERROR] Build failed!
    exit /b 1
)
echo.
echo [SUCCESS] Build complete! JAR location: %BUILD_DIR%\%JAR_NAME%
dir %BUILD_DIR%\%JAR_NAME%
goto end

:clean
echo.
echo [CLEAN] Cleaning build artifacts...
call gradlew.bat clean
echo [SUCCESS] Clean complete!
goto end

:test
echo.
echo [TEST] Running tests...
call gradlew.bat test --no-daemon
echo [SUCCESS] Tests complete!
goto end

:verify
echo.
echo [VERIFY] Building and verifying JAR...
call gradlew.bat clean build --no-daemon
if errorlevel 1 (
    echo [ERROR] Build failed!
    exit /b 1
)
echo.
echo [VERIFY] Checking JAR contents...
jar tf %BUILD_DIR%\%JAR_NAME% | findstr /C:"PassiveScanner.class" /C:"ScannerPanel.class" /C:"SupabaseRlsScanner.class"
echo [SUCCESS] Verification complete!
goto end

:info
echo.
echo ========================================
echo Project Information
echo ========================================
echo   Name: %PROJECT_NAME%
echo   Version: %VERSION%
echo   JAR: %JAR_NAME%
echo   Build Dir: %BUILD_DIR%
echo   OS: Windows
echo.
java -version 2>&1 | findstr /C:"version"
echo.
goto end

:help
echo.
echo ========================================
echo Supabase RLS Scanner - Build Script
echo ========================================
echo.
echo Available commands:
echo   build.bat          - Build the project (default)
echo   build.bat build    - Clean and build the JAR file
echo   build.bat clean    - Remove build artifacts
echo   build.bat test     - Run tests
echo   build.bat verify   - Build and verify JAR contents
echo   build.bat info     - Show project information
echo   build.bat help     - Show this help message
echo.
echo Requirements:
echo   - Java 21 or higher
echo   - Gradle wrapper (included)
echo.
echo For Linux/macOS users, use 'make' instead:
echo   make build
echo   make help
echo.
goto end

:end
endlocal

