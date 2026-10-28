@echo off
rem LAN Trap Receiver for Windows: runs this copy of the program with the Python launcher (py) or python.
rem Double-click it for the menu, or pass the same arguments as "lantrap" (for example: lantrap.bat run).
setlocal
set "PYTHONPATH=%~dp0;%PYTHONPATH%"
where py >nul 2>nul
if %errorlevel%==0 (
    py -3 -m lantrap %*
) else (
    python -m lantrap %*
)
set "code=%errorlevel%"
if "%~1"=="" pause
exit /b %code%
