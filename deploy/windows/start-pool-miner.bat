@echo off
cd /d "%~dp0"
call config.bat
title Requant pool miner (TNet, GPU %DEVICE%)
echo Mining in the pool %POOL% for %ADDRESS% (no local node needed)
:loop
cppminer.exe --algo tnet --rpc %POOL% --payee %PAYEE% --device %DEVICE% --batch %BATCH%
echo Miner stopped; restarting in 15 s
timeout /t 15 /nobreak >nul
goto loop
