@echo off
setlocal
cd /d "%~dp0"
if exist "%~dp0RAT_Guard_Lite.py" (
    where py >nul 2>&1
    if "%errorlevel%"=="0" (
        py -3 "%~dp0RAT_Guard_Lite.py"
    ) else (
        where python >nul 2>&1
        if "%errorlevel%"=="0" (
            python "%~dp0RAT_Guard_Lite.py"
        ) else (
            echo Python 3 was not found. Install Python and enable Add to PATH.
            pause
        )
    )
) else (
    echo RAT_Guard_Lite.py was not found in this folder.
    pause
)
endlocal

pause