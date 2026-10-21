@echo off
rem ---------------------------------------------------------------------
rem  Start the emulator and the server together, the app is set up and
rem  the tunnel is started in it.
rem  Double click it, or run it from a terminal.
rem ---------------------------------------------------------------------
setlocal
cd /d "%~dp0"

where python >nul 2>&1
if errorlevel 1 (
    echo.
    echo  Python was not found. Install it from python.org and try again.
    echo.
    pause
    exit /b 1
)

python tools\serve.py --emulator %*
set CODE=%ERRORLEVEL%
if not "%CODE%"=="0" (
    echo.
    echo  The server stopped with the error %CODE%.
    echo.
    pause
)
endlocal
