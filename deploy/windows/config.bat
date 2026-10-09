@echo off
rem Requant test network settings shared by the scripts in this folder.
rem PAYEE: key hash of the wallet that receives mining rewards (requant-wallet address KEYFILE prints it).
set PAYEE=856110f44be982c4d5c8f0c7befdece4a98393c1d71ea528ecf84915816c46d4
set ADDRESS=trq1qs4s3paztaxpvf4wg7rrmal0vuj5c8y7p6u02228vlpy3tqtvgm2qgr7fxk
set SEEDS=--connect 193.187.93.29:19333 --connect 193.32.188.248:19333 --connect 185.174.40.96:19333
set RPC=127.0.0.1:19334
rem GPU number (0 = first) and rows per GPU pass (lower it to 2048 on GPUs with 4 GB or less).
set DEVICE=0
set BATCH=8192
set POOL=193.187.93.29:19340
rem Name of this device in the pool's statistics (rewards still go to PAYEE); defaults to the computer name.
set WORKER=%COMPUTERNAME%
