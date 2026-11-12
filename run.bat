@echo off
rem ============================================================
rem  Baoyan System launcher (keep this file ASCII-only!)
rem  cmd parses .bat with the OEM/ANSI codepage; Chinese UTF-8
rem  text in a .bat gets mis-seeked and lines are cut in half
rem  (symptoms: "'hon' is not recognized", "call :label" losing
rem  its "call :" prefix). All Chinese messages live in launcher.py.
rem ============================================================
setlocal EnableExtensions
chcp 65001 >nul
cd /d "%~dp0"
title Baoyan System Launcher

echo ============================================================
echo   Baoyan System  -  Wuhan Textile University
echo ============================================================
echo.

if not exist "launcher.py" goto :nolauncher

set "PY="
set "MODE="

rem ------------------------------------------------------------
rem  Find Python in three passes, strictest first:
rem    pass 1: an interpreter that already has Flask  (no network)
rem    pass 2: an interpreter that has pip           (can install)
rem    pass 3: any working interpreter               (launcher explains)
rem  This skips "python that runs but has no pip" setups such as
rem  MSYS2/MinGW builds, which is the usual reason app.py fails.
rem ------------------------------------------------------------
call :scan flask
if not defined PY call :scan pip
if not defined PY call :scan any

if not defined PY goto :nopython

echo   Interpreter: %PY:"=%
echo.
%PY% launcher.py
set "RC=%ERRORLEVEL%"

echo.
if "%RC%"=="0" goto :done
if "%RC%"=="2" goto :done
echo [FAILED] exit code %RC% - copy the error above and send it to the maintainer.
:done
echo.
echo [Window can be closed] Press any key to exit.
pause >nul
exit /b %RC%


rem ============================================================
rem  :scan <flask^|pip^|any>
rem ============================================================
:scan
if defined PY goto :eof
set "MODE=%~1"

rem 1) project virtualenv
if exist ".venv\Scripts\python.exe" call :probe ".venv\Scripts\python.exe"

rem 2) official py launcher
call :probe_py

rem 3) default install dirs
if not defined PY (
    for /d %%D in ("%LOCALAPPDATA%\Programs\Python\Python3*") do (
        if not defined PY if exist "%%~fD\python.exe" call :probe "%%~fD\python.exe"
    )
)
if not defined PY (
    for /d %%D in ("C:\Python3*") do (
        if not defined PY if exist "%%~fD\python.exe" call :probe "%%~fD\python.exe"
    )
)

rem 4) python on PATH (skip the Microsoft Store stub)
if not defined PY (
    for /f "delims=" %%P in ('where python 2^>nul') do (
        if not defined PY call :probe_path "%%P"
    )
)

rem 5) last resort: an existing Python runtime on this machine
if not defined PY (
    for /d %%D in ("%USERPROFILE%\.workbuddy\binaries\python\versions\3.*") do (
        if not defined PY if exist "%%~fD\python.exe" call :probe "%%~fD\python.exe"
    )
)
goto :eof


rem ---- probe a python.exe against the current MODE ----
:probe
if defined PY goto :eof
if /i "%MODE%"=="flask" goto :probe_flask
if /i "%MODE%"=="pip" goto :probe_pip
"%~1" -c "import sys" >nul 2>nul
if errorlevel 1 goto :eof
goto :probe_ok

:probe_flask
"%~1" -c "import flask" >nul 2>nul
if errorlevel 1 goto :eof
goto :probe_ok

:probe_pip
"%~1" -m pip --version >nul 2>nul
if errorlevel 1 goto :eof
goto :probe_ok

:probe_ok
set "PY="%~1""
goto :eof

rem ---- same, but skip the 0-byte Microsoft Store stub ----
:probe_path
if defined PY goto :eof
echo %~1 | findstr /i "WindowsApps" >nul
if not errorlevel 1 goto :eof
"%~1" -c "import sys" >nul 2>nul
if errorlevel 1 goto :eof
if /i "%MODE%"=="flask" goto :probe_path_flask
if /i "%MODE%"=="pip" goto :probe_path_pip
goto :probe_path_ok

:probe_path_flask
"%~1" -c "import flask" >nul 2>nul
if errorlevel 1 goto :eof
goto :probe_path_ok

:probe_path_pip
"%~1" -m pip --version >nul 2>nul
if errorlevel 1 goto :eof
goto :probe_path_ok

:probe_path_ok
set "PY="%~1""
goto :eof

rem ---- probe the py launcher ----
:probe_py
if defined PY goto :eof
py -3 -c "import sys" >nul 2>nul
if errorlevel 1 goto :eof
if /i "%MODE%"=="flask" goto :probe_py_flask
if /i "%MODE%"=="pip" goto :probe_py_pip
goto :probe_py_ok

:probe_py_flask
py -3 -c "import flask" >nul 2>nul
if errorlevel 1 goto :eof
goto :probe_py_ok

:probe_py_pip
py -3 -m pip --version >nul 2>nul
if errorlevel 1 goto :eof
goto :probe_py_ok

:probe_py_ok
set "PY=py -3"
goto :eof


:nopython
echo [ERROR] No usable Python found, so the system cannot start.
echo.
echo   Install it in three steps:
echo     1. Open  https://www.python.org/downloads/windows/
echo     2. Download "Windows installer (64-bit)" and run it
echo     3. On the first screen, tick "Add python.exe to PATH"
echo.
echo   Then close this window and double-click run.bat again.
echo.
echo   Already installed but still failing? PATH is not picked up.
echo     Reinstall with "Add to PATH" ticked, or send the maintainer
echo     the full path of your python.exe.
echo.
pause
exit /b 1

:nolauncher
echo [ERROR] launcher.py not found.
echo   run.bat and launcher.py must stay in the same folder.
pause
exit /b 1
