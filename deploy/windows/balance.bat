@echo off
cd /d "%~dp0"
call config.bat
requant-wallet.exe balance %ADDRESS% --network test --rpc %RPC%
echo.
requant-wallet.exe history %ADDRESS% 10 --network test --rpc %RPC%
pause
