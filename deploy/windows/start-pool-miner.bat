@echo off
cd /d "%~dp0"
call config.bat
title Requant pool miner (TNet, GPU %DEVICE%)
echo Mining in the pool %POOL% for %ADDRESS% as device "%WORKER%" (no local node needed)
:loop
cppminer.exe --algo tnet --rpc %POOL% --payee %PAYEE% --worker %WORKER% --device %DEVICE% --batch %BATCH%
echo Miner stopped; restarting in 15 s
timeout /t 15 /nobreak >nul
goto loop
