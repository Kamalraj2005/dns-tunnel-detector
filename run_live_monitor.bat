@echo off
title Real-Time DNS Tunneling Live Monitor
echo ========================================================
echo  Launching Real-Time Network Sniffer on UDP Port 53
echo ========================================================
cd /d "%~dp0"
.\.venv\Scripts\python.exe live_monitor.py
pause
