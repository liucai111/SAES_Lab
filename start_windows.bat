@echo off
cd /d "%~dp0source"
python main.py
if errorlevel 1 pause
