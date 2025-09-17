@echo off
cd /d "%~dp0"
python -m pip install -q pyinstaller paramiko
python -m PyInstaller --noconfirm --clean --onefile --noconsole --name "RECONFTW-INSTALLER-v1.0.0" --icon icon.ico --add-data "payload;payload" --add-data "icon.png;." --add-data "icon.ico;." --hidden-import paramiko --collect-submodules paramiko reconftw_setup.py
if errorlevel 1 (
  echo BUILD FAILED
  pause
  exit /b 1
)
copy /Y "dist\RECONFTW-INSTALLER-v1.0.0.exe" "."
echo.
echo Built: %cd%\RECONFTW-INSTALLER-v1.0.0.exe
pause
