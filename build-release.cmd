@echo off
setlocal
cd /d "%~dp0"
if not exist dist mkdir dist
go test -buildvcs=false ./... || exit /b 1
go build -buildvcs=false -trimpath -ldflags="-s -w" -o dist\sqli-auditor-windows-amd64.exe .
endlocal
