@echo off
cd /d "%~dp0"
git add -A
git commit -m "auto: update %date% %time%"
git push origin main
echo.
echo Done! Press any key to close.
pause >nul
