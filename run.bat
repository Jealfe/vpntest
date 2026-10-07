@echo off
cd /d "%~dp0"
where py >nul 2>nul
if %errorlevel%==0 (
    py vpn_diagnostic.py
) else (
    python vpn_diagnostic.py
)
