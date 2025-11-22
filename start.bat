@echo off
chcp 65001
title Chat Server

echo ========================================
echo     Starting Chat Server
echo ========================================

:: Try different Node.js paths
if exist "C:\Program Files\nodejs\node.exe" (
    set NODE="C:\Program Files\nodejs\node.exe"
    goto :found_node
)

if exist "C:\Program Files (x86)\nodejs\node.exe" (
    set NODE="C:\Program Files (x86)\nodejs\node.exe"
    goto :found_node
)

:: Try node from PATH
node --version >nul 2>&1
if %errorlevel% == 0 (
    set NODE=node
    goto :found_node
)

echo ERROR: Node.js not found!
echo Please install Node.js from https://nodejs.org/
pause
exit /b 1

:found_node
echo Node.js found: %NODE%
echo.

:: Install dependencies
echo Installing dependencies...
%NODE% -e "console.log('Node version:', process.version)"
call npm install

if exist "ssl-generator.js" (
    echo Generating SSL certificates...
    %NODE% ssl-generator.js
)

echo.
echo Starting server...
echo URLs:
echo - http://26.191.144.233:3000
echo - https://26.191.144.233:3000
echo.
echo For Radmin VPN: Use the IP above
echo.

%NODE% server.js

pause