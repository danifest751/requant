@echo off
cd /d "%~dp0"
call config.bat
cppminer.exe --algo tnet --selftest --device %DEVICE%
pause
