@echo off
cd /d "%~dp0"
python -m pip install -q paramiko
python reconftw_setup.py
if errorlevel 1 pause
