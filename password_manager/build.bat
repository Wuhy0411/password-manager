@echo off
echo ============================================
echo   Password Manager - Build Script
echo ============================================
echo.

REM Install dependencies
echo [1/2] Installing dependencies...
pip install -r requirements.txt
if %errorlevel% neq 0 (
    echo ERROR: Failed to install dependencies!
    pause
    exit /b 1
)

REM Build executable
echo.
echo [2/2] Building PasswordManager.exe...
pyinstaller --onefile --windowed --name PasswordManager --clean --noconfirm password_manager.py
if %errorlevel% neq 0 (
    echo ERROR: Build failed!
    pause
    exit /b 1
)

echo.
echo ============================================
echo   Build complete!
echo   Output: dist\PasswordManager.exe
echo ============================================
pause
