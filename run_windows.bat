@echo off
setlocal EnableExtensions
set "SCRIPT_DIR=%~dp0"
set "PRIMARY_VENV=%SCRIPT_DIR%.venv"
set "PRIMARY_PYTHON=%PRIMARY_VENV%\Scripts\python.exe"
set "FALLBACK_VENV=%SCRIPT_DIR%.venv-py310plus"
set "FALLBACK_PYTHON=%FALLBACK_VENV%\Scripts\python.exe"
set "STATUS="

if not exist "%PRIMARY_PYTHON%" goto try_fallback_venv
set "PYTHON_CMD=%PRIMARY_PYTHON%"
set "PYTHON_ARGS="
"%PYTHON_CMD%" %PYTHON_ARGS% -c "import sys; raise SystemExit(sys.version_info ^< (3, 10))" >nul 2>nul
if not errorlevel 1 (
    set "PYTHON_KIND=primary"
    goto python_ready
)

:try_fallback_venv
if not exist "%FALLBACK_PYTHON%" goto select_bootstrap
set "PYTHON_CMD=%FALLBACK_PYTHON%"
set "PYTHON_ARGS="
"%PYTHON_CMD%" %PYTHON_ARGS% -c "import sys; raise SystemExit(sys.version_info ^< (3, 10))" >nul 2>nul
if not errorlevel 1 (
    set "PYTHON_KIND=fallback"
    goto python_ready
)

:select_bootstrap
where py >nul 2>nul
if errorlevel 1 goto try_python
py -3.14 -c "import sys; raise SystemExit(sys.version_info ^< (3, 10))" >nul 2>nul
if not errorlevel 1 (
    set "BOOTSTRAP_CMD=py"
    set "BOOTSTRAP_ARGS=-3.14"
    goto bootstrap_ready
)
py -3.13 -c "import sys; raise SystemExit(sys.version_info ^< (3, 10))" >nul 2>nul
if not errorlevel 1 (
    set "BOOTSTRAP_CMD=py"
    set "BOOTSTRAP_ARGS=-3.13"
    goto bootstrap_ready
)
py -3.12 -c "import sys; raise SystemExit(sys.version_info ^< (3, 10))" >nul 2>nul
if not errorlevel 1 (
    set "BOOTSTRAP_CMD=py"
    set "BOOTSTRAP_ARGS=-3.12"
    goto bootstrap_ready
)
py -3.11 -c "import sys; raise SystemExit(sys.version_info ^< (3, 10))" >nul 2>nul
if not errorlevel 1 (
    set "BOOTSTRAP_CMD=py"
    set "BOOTSTRAP_ARGS=-3.11"
    goto bootstrap_ready
)
py -3.10 -c "import sys; raise SystemExit(sys.version_info ^< (3, 10))" >nul 2>nul
if not errorlevel 1 (
    set "BOOTSTRAP_CMD=py"
    set "BOOTSTRAP_ARGS=-3.10"
    goto bootstrap_ready
)
py -3 -c "import sys; raise SystemExit(sys.version_info ^< (3, 10))" >nul 2>nul
if errorlevel 1 goto try_python
set "BOOTSTRAP_CMD=py"
set "BOOTSTRAP_ARGS=-3"
goto bootstrap_ready

:try_python
where python >nul 2>nul
if errorlevel 1 goto missing_python
python -c "import sys; raise SystemExit(sys.version_info ^< (3, 10))" >nul 2>nul
if errorlevel 1 goto missing_python
set "BOOTSTRAP_CMD=python"
set "BOOTSTRAP_ARGS="

:bootstrap_ready
set "PYTHON_CMD=%BOOTSTRAP_CMD%"
set "PYTHON_ARGS=%BOOTSTRAP_ARGS%"
set "PYTHON_KIND=bootstrap"

:python_ready
"%PYTHON_CMD%" %PYTHON_ARGS% -c "import sys; raise SystemExit(sys.version_info ^< (3, 10))"
if errorlevel 1 (
    echo Python 3.10 or newer is required. Install a newer Python, then run this launcher again.
    goto failed
)

"%PYTHON_CMD%" %PYTHON_ARGS% -c "import tkinter" >nul 2>nul
if errorlevel 1 (
    echo Tk is missing. Reinstall Python with Tcl/Tk enabled, then run this launcher again.
    goto failed
)

"%PYTHON_CMD%" %PYTHON_ARGS% -c "import unicorn, PIL" >nul 2>nul
if errorlevel 1 goto dependency_setup
goto dependencies_ready

:dependency_setup
if /I "%PYTHON_KIND%"=="primary" goto install_dependencies
if /I "%PYTHON_KIND%"=="fallback" goto install_dependencies
if exist "%FALLBACK_PYTHON%" goto invalid_fallback
if exist "%FALLBACK_VENV%\" goto invalid_fallback
echo Creating local .venv-py310plus...
"%PYTHON_CMD%" %PYTHON_ARGS% -m venv "%FALLBACK_VENV%"
if errorlevel 1 goto failed
if not exist "%FALLBACK_PYTHON%" goto failed
set "PYTHON_CMD=%FALLBACK_PYTHON%"
set "PYTHON_ARGS="
set "PYTHON_KIND=fallback"

:install_dependencies
if not exist "%SCRIPT_DIR%requirements.txt" goto missing_requirements
echo Installing Python dependencies. First setup may require network access...
"%PYTHON_CMD%" %PYTHON_ARGS% -m pip install -r "%SCRIPT_DIR%requirements.txt"
if errorlevel 1 goto failed

:dependencies_ready
"%PYTHON_CMD%" %PYTHON_ARGS% -c "import unicorn, PIL" >nul 2>nul
if errorlevel 1 (
    echo Python dependencies are still unavailable after installation.
    goto failed
)

"%PYTHON_CMD%" %PYTHON_ARGS% "%SCRIPT_DIR%gui.py" %*
set "STATUS=%ERRORLEVEL%"
if not "%STATUS%"=="0" (
    echo Emulator exited with status %STATUS%.
    pause
)
exit /b %STATUS%

:missing_python
echo Python 3.10 or newer was not found by py or PATH.
echo Check: py -3.13 --version
set "STATUS=127"
goto failed

:missing_requirements
echo Missing requirements.txt beside launcher.
set "STATUS=1"
goto failed

:invalid_fallback
echo Existing .venv-py310plus is incompatible. Rename it, then run this launcher again.
set "STATUS=1"
goto failed

:failed
if not defined STATUS set "STATUS=%ERRORLEVEL%"
if "%STATUS%"=="0" set "STATUS=1"
echo Launcher failed with status %STATUS%.
pause
exit /b %STATUS%
