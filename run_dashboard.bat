@echo off
title DNS Tunneling SOC Console
echo ========================================================
echo  Starting DNS Tunneling Incident Detection Dashboard
echo ========================================================
cd /d "%~dp0"
echo Opening browser at http://localhost:8501 ...
start http://localhost:8501
.\.venv\Scripts\streamlit.exe run dashboard/app.py --server.port=8501
pause
