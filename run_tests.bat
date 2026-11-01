@echo off
title DNS Detection Unit Tests
echo ========================================================
echo  Executing Automated Unit Test Suite
echo ========================================================
cd /d "%~dp0"
.\.venv\Scripts\python.exe -m unittest tests/test_pipeline.py
pause
