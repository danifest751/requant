@echo off
cd /d "%~dp0"
call config.bat
title Requant node (test network)
echo Requant node, test network. Keep this window open. Data: %~dp0data
echo New signed releases are installed automatically (the node restarts itself).
:loop
requantd.exe --network test --datadir data --listen 127.0.0.1:19333 --rpc %RPC% %SEEDS% --auto-update
echo Node stopped; restarting in 10 s (close this window to stop it)
timeout /t 10 /nobreak >nul
goto loop
