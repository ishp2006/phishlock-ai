@echo off
setlocal
echo Running JavaScript syntax verification for script.js...
set ELECTRON_RUN_AS_NODE=1
"C:\Users\Ish\AppData\Local\Programs\Microsoft VS Code\Code.exe" -c "%~dp0script.js"
if %ERRORLEVEL% equ 0 (
    echo [SUCCESS] script.js passed all syntax checks with 0 errors!
) else (
    echo [ERROR] Syntax error detected in script.js!
)
endlocal
