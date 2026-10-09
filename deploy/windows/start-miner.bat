@echo off
cd /d "%~dp0"
call config.bat
title Requant miner (TNet, GPU %DEVICE%)
echo Mining to %ADDRESS%
:loop
cppminer.exe --algo tnet --rpc %RPC% --payee %PAYEE% --device %DEVICE% --batch %BATCH%
echo Miner stopped; restarting in 15 s (is the node window open?)
timeout /t 15 /nobreak >nul
goto loop
