@echo off
setlocal EnableDelayedExpansion

echo Starting DeadCode build...

set "PROJECT_DIR=%~dp0"
set "PROJECT_DIR=%PROJECT_DIR:~0,-1%"

echo Project directory: %PROJECT_DIR%

if not exist "%PROJECT_DIR%\ui\DeadCode.pro" (
    echo Error: DeadCode.pro not found in ui directory
    pause
    exit /b 1
) else (
    echo DeadCode.pro found in ui directory
    cd /d "%PROJECT_DIR%\ui" || (
        echo Error: Failed to change to ui directory
        pause
        exit /b 1
    )
)

echo Checking dependencies...
where sqlite3 >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo Error: SQLite3 not found. Ensure SQLite is installed and added to PATH.
    pause
    exit /b 1
)
where curl >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo Error: curl not found. Ensure curl is installed and added to PATH.
    pause
    exit /b 1
)

where qmake >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo qmake not found in PATH, trying default path...
    set "QMAKE_PATH=C:\Qt\5.15.2\mingw81_64\bin\qmake.exe"
    if not exist "!QMAKE_PATH!" (
        echo Error: qmake not found at !QMAKE_PATH!
        set /p QMAKE_PATH="Enter path to qmake.exe: "
        if not exist "!QMAKE_PATH!" (
            echo Error: Invalid qmake path: !QMAKE_PATH!
            pause
            exit /b 1
        )
    )
) else (
    for /f "delims=" %%i in ('where qmake') do set "QMAKE_PATH=%%i"
)

echo Using !QMAKE_PATH!...
"!QMAKE_PATH!" DeadCode.pro -spec win32-g++ || (
    echo Error: qmake failed
    pause
    exit /b 1
)

where mingw32-make >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo Error: mingw32-make not found in PATH
    pause
    exit /b 1
)

echo Cleaning previous build...
mingw32-make -f Makefile.Release clean || (
    echo Warning: Cleaning failed, continuing...
)

echo Building with mingw32-make...
mingw32-make -f Makefile.Release -j4 || (
    echo Error: mingw32-make failed
    pause
    exit /b 1
)

cd /d "%PROJECT_DIR%\build\release" || (
    echo Error: Failed to change to build\release directory
    pause
    exit /b 1
)

if not exist DeadCode.exe (
    echo Error: DeadCode.exe not found in build directory
    dir
    pause
    exit /b 1
)

echo Deploying Qt dependencies...
set "QT_DIR=C:\Qt\5.15.2\mingw81_64"
if not exist "!QT_DIR!\bin\windeployqt.exe" (
    echo Error: windeployqt not found at !QT_DIR!\bin
    pause
    exit /b 1
)
"!QT_DIR!\bin\windeployqt.exe" DeadCode.exe --release --no-translations --no-angle --no-opengl-sw || (
    echo Error: windeployqt failed
    pause
    exit /b 1
)

echo Copying vcpkg dependencies...
set "VCPKG_DIR=C:\vcpkg\installed\x64-mingw-dynamic\bin"
for %%d in (sqlite3.dll libcurl.dll libssl-3-x64.dll libcrypto-3-x64.dll libzip.dll) do (
    if exist "!VCPKG_DIR!\%%d" (
        copy "!VCPKG_DIR!\%%d" . || (
            echo Error: Failed to copy %%d
            pause
            exit /b 1
        )
        echo Copied %%d
    ) else (
        echo Warning: %%d not found in !VCPKG_DIR!
    )
)

echo Copying additional files...
copy "%PROJECT_DIR%\config.json" . || (
    echo Warning: config.json not found, creating stub
    echo {} > config.json
)
copy "%PROJECT_DIR%\icon.ico" . || echo Warning: icon.ico not found
mkdir data 2>nul

echo Verifying files...
for %%f in (
    DeadCode.exe
    Qt5Core.dll
    Qt5Gui.dll
    Qt5Widgets.dll
    Qt5Network.dll
    Qt5Sql.dll
    sqlite3.dll
    libcurl.dll
    libssl-3-x64.dll
    libcrypto-3-x64.dll
    libzip.dll
    platforms\qwindows.dll
    sqldrivers\qsqlite.dll
    config.json
    icon.ico
    data
) do (
    if not exist "%%f" (
        echo Error: %%f is missing
        pause
        exit /b 1
    )
)
echo All required files are present

echo Build completed successfully!
echo Executable and dependencies: %PROJECT_DIR%\build\release
pause
exit /b 0