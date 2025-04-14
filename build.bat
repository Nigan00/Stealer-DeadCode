@echo off
setlocal EnableDelayedExpansion

echo Starting DeadCode build...

set "PROJECT_DIR=%~dp0"
set "PROJECT_DIR=%PROJECT_DIR:~0,-1%"

echo Project directory: %PROJECT_DIR%

:: Проверка наличия DeadCode.pro
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

:: Проверка системных утилит
echo Checking system utilities...
for %%u in (where.exe dir.exe copy.exe mkdir.exe) do (
    where %%u >nul 2>&1 || (
        echo Error: %%u not found in PATH
        pause
        exit /b 1
    )
)

:: Проверка qmake
echo Checking qmake...
set "QMAKE_PATH=C:\Qt\6.5.3\mingw_64\bin\qmake.exe"
where qmake >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo qmake not found in PATH, checking default path...
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
echo Using qmake: !QMAKE_PATH!
"!QMAKE_PATH!" --version || (
    echo Error: qmake version check failed
    pause
    exit /b 1
)

:: Проверка mingw32-make
echo Checking mingw32-make...
set "MINGW_MAKE_PATH=C:\Qt\Tools\mingw1120_64\bin\mingw32-make.exe"
where mingw32-make >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo mingw32-make not found in PATH, checking default path...
    if not exist "!MINGW_MAKE_PATH!" (
        echo Error: mingw32-make not found at !MINGW_MAKE_PATH!
        pause
        exit /b 1
    )
) else (
    for /f "delims=" %%i in ('where mingw32-make') do set "MINGW_MAKE_PATH=%%i"
)
echo Using mingw32-make: !MINGW_MAKE_PATH!

:: Проверка vcpkg зависимостей
echo Checking vcpkg dependencies...
set "VCPKG_DIR=C:\vcpkg\installed\x64-windows-static"
if not exist "!VCPKG_DIR!\bin" (
    echo Error: vcpkg binary directory not found at !VCPKG_DIR!\bin
    pause
    exit /b 1
)
for %%d in (sqlite3.dll libcurl.dll libssl-3-x64.dll libcrypto-3-x64.dll libzip.dll) do (
    if not exist "!VCPKG_DIR!\bin\%%d" (
        echo Warning: %%d not found in !VCPKG_DIR!\bin
    ) else (
        echo Found %%d
    )
)

:: Генерация Makefile
echo Running qmake...
"!QMAKE_PATH!" DeadCode.pro -spec win32-g++ "CONFIG+=release" "QMAKE_INCDIR+=!VCPKG_DIR!\include" "QMAKE_LIBDIR+=!VCPKG_DIR!\lib" || (
    echo Error: qmake failed
    pause
    exit /b 1
)

:: Очистка предыдущей сборки
echo Cleaning previous build...
"!MINGW_MAKE_PATH!" -f Makefile.Release clean || (
    echo Warning: Cleaning failed, continuing...
)

:: Сборка проекта
echo Building with mingw32-make...
"!MINGW_MAKE_PATH!" -f Makefile.Release -j4 || (
    echo Error: mingw32-make failed
    dir /s
    pause
    exit /b 1
)

:: Переход в директорию сборки
cd /d "%PROJECT_DIR%\build\release" ||
    echo Error: Failed to change to build\release directory
    pause
    exit /b 1
)

:: Проверка наличия DeadCode.exe
if not exist DeadCode.exe (
    echo Error: DeadCode.exe not found in build directory
    dir /s
    pause
    exit /b 1
)

:: Развёртывание Qt зависимостей
echo Deploying Qt dependencies...
set "QT_DIR=C:\Qt\6.5.3\mingw_64"
if not exist "!QT_DIR!\bin\windeployqt.exe" (
    echo Error: windeployqt not found at !QT_DIR!\bin
    pause
    exit /b 1
)
"!QT_DIR!\bin\windeployqt.exe" DeadCode.exe --release --no-translations --no-opengl-sw --no-system-d3d-compiler || (
    echo Error: windeployqt failed
    pause
    exit /b 1
)

:: Копирование vcpkg зависимостей
echo Copying vcpkg dependencies...
for %%d in (sqlite3.dll libcurl.dll libssl-3-x64.dll libcrypto-3-x64.dll libzip.dll) do (
    if exist "!VCPKG_DIR!\bin\%%d" (
        copy "!VCPKG_DIR!\bin\%%d" . || (
            echo Error: Failed to copy %%d
            pause
            exit /b 1
        )
        echo Copied %%d
    ) else (
        echo Warning: %%d not found in !VCPKG_DIR!\bin
    )
)

:: Копирование дополнительных файлов
echo Copying additional files...
if exist "%PROJECT_DIR%\config.json" (
    copy "%PROJECT_DIR%\config.json" . || (
        echo Warning: Failed to copy config.json
    )
) else (
    echo Warning: config.json not found, creating stub
    echo {} > config.json
)
if exist "%PROJECT_DIR%\icon.ico" (
    copy "%PROJECT_DIR%\icon.ico" . || (
        echo Warning: Failed to copy icon.ico
    )
) else (
    echo Warning: icon.ico not found
)
mkdir data 2>nul

:: Проверка всех файлов
echo Verifying files...
for %%f in (
    DeadCode.exe
    Qt6Core.dll
    Qt6Gui.dll
    Qt6Widgets.dll
    Qt6Network.dll
    Qt6Sql.dll
    sqlite3.dll
    libcurl.dll
    libssl-3-x64.dll
    libcrypto-3-x64.dll
    libzip.dll
    plugins\platforms\qwindows.dll
    plugins\sqldrivers\qsqlite.dll
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