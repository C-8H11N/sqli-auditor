@echo off
setlocal
cd /d "%~dp0"
where go >nul 2>nul || (echo Go was not found in PATH.& pause & exit /b 1)
start "" http://127.0.0.1:8812/
go run -buildvcs=false .
endlocal
