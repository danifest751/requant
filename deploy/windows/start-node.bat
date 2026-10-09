@echo off
cd /d "%~dp0"
call config.bat
title Requant node (test network)
echo Requant node, test network. Keep this window open. Data: %~dp0data
requantd.exe --network test --datadir data --listen 127.0.0.1:19333 --rpc %RPC% %SEEDS%
pause
