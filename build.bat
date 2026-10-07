@echo off
setlocal
cd /d "%~dp0"

where py >nul 2>nul
if %errorlevel%==0 (
    set PY=py
) else (
    set PY=python
)

%PY% -m pip install --upgrade pyinstaller
if errorlevel 1 goto :error

%PY% -m PyInstaller --noconfirm --clean --onefile --windowed --uac-admin --name VPNDiagnostic vpn_diagnostic.py
if errorlevel 1 goto :error

echo.
echo Build complete: dist\VPNDiagnostic.exe
pause
exit /b 0

:error
echo.
echo Build failed.
pause
exit /b 1
