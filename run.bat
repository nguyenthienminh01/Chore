@echo off
cd /d "%~dp0"
echo.
echo  ╔══════════════════════════════════════════════════════════╗
echo  ║                                                          ║
echo  ║   ██╗    ██╗██╗███████╗██╗    ███████╗███████╗ ██████╗   ║
echo  ║   ██║    ██║██║██╔════╝██║    ██╔════╝██╔════╝██╔════╝   ║
echo  ║   ██║ █╗ ██║██║█████╗  ██║    ███████╗█████╗  ██║        ║
echo  ║   ██║███╗██║██║██╔══╝  ██║    ╚════██║██╔══╝  ██║        ║
echo  ║   ╚███╔███╔╝██║██║     ██║    ███████║███████╗╚██████╗   ║
echo  ║    ╚══╝╚══╝ ╚═╝╚═╝     ╚═╝    ╚══════╝╚══════╝ ╚═════╝   ║
echo  ║                                                          ║
echo  ║          WiFi Security Checker v1.0                      ║
echo  ║          Professional Security Testing Tool              ║
echo  ║                                                          ║
echo  ╚══════════════════════════════════════════════════════════╝
echo.
echo  [*] Activating virtual environment...
call venv\Scripts\activate.bat
echo  [*] Starting web server...
echo  [*] Open browser: http://127.0.0.1:5000
echo  [*] Press Ctrl+C to stop
echo.
python app.py
pause
