@echo off
cd /d "%~dp0"
start "Requant node" cmd /c start-node.bat
echo Waiting 20 s for the node to start and sync...
timeout /t 20 /nobreak >nul
start "Requant miner" cmd /c start-miner.bat
