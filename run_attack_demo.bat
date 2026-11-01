@echo off
title DNS Attack Simulator
echo ========================================================
echo  Injecting Simulated DNS Tunneling Attack
echo ========================================================
cd /d "%~dp0"
.\.venv\Scripts\python.exe simulate_attack.py --count 20
pause
