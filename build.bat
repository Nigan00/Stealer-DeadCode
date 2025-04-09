@echo off
setlocal EnableDelayedExpansion

echo Начало сборки DeadCode...

REM Устанавливаем корневую директорию проекта (динамически на основе расположения скрипта)
set "PROJECT_DIR=%~dp0"
set "PROJECT_DIR=%PROJECT_DIR:~0,-1%"

echo Проект находится в: %PROJECT_DIR%

REM Проверяем наличие DeadCode.pro
if not exist "%PROJECT_DIR%\ui\DeadCode.pro" (
    echo Ошибка: Файл DeadCode.pro не найден в директории ui
    pause
    exit /b 1
) else (
    echo DeadCode.pro найден в директории ui
    cd /d "%PROJECT_DIR%\ui" || (
        echo Ошибка: Не удалось перейти в директорию ui
        pause
        exit /b 1
    )
)

REM Устанавливаем пути к vcpkg
set "VCPKG_ROOT=C:\vcpkg"
set "VCPKG_LIB_DIR=%VCPKG_ROOT%\installed\x64-mingw-dynamic\lib"
set "VCPKG_BIN_DIR=%VCPKG_ROOT%\installed\x64-mingw-dynamic\bin"
set "VCPKG_INCLUDE_DIR=%VCPKG_ROOT%\installed\x64-mingw-dynamic\include"

REM Проверяем наличие vcpkg и его директорий
if not exist "%VCPKG_ROOT%" (
    echo Ошибка: vcpkg не найден в %VCPKG_ROOT%. Убедитесь, что vcpkg установлен.
    pause
    exit /b 1
)

if not exist "%VCPKG_LIB_DIR%" (
    echo Ошибка: Директория библиотек vcpkg не найдена: %VCPKG_LIB_DIR%
    pause
    exit /b 1
)

if not exist "%VCPKG_BIN_DIR%" (
    echo Ошибка: Директория бинарных файлов vcpkg не найдена: %VCPKG_BIN_DIR%
    pause
    exit /b 1
)

if not exist "%VCPKG_INCLUDE_DIR%" (
    echo Ошибка: Директория заголовочных файлов vcpkg не найдена: %VCPKG_INCLUDE_DIR%
    pause
    exit /b 1
)

REM Проверяем зависимости vcpkg
echo Проверяем зависимости vcpkg...
set "MISSING_DEPS="

REM Список библиотек для проверки
set "REQUIRED_LIBS=libsqlite3.dll.a libzip.dll.a libzlib.dll.a libbz2.dll.a libcurl.dll.a libssl.dll.a libcrypto.dll.a"
set "REQUIRED_DLLS=sqlite3.dll libzip.dll zlib1.dll bz2.dll libcurl.dll libssl.dll libcrypto.dll"
set "REQUIRED_HEADERS=sqlite3.h zip.h zlib.h bzlib.h curl\curl.h openssl\ssl.h openssl\crypto.h"

REM Проверка библиотек (.dll.a)
for %%L in (%REQUIRED_LIBS%) do (
    if not exist "%VCPKG_LIB_DIR%\%%L" (
        set "MISSING_DEPS=!MISSING_DEPS! %%L"
    )
)

REM Проверка DLL
for %%D in (%REQUIRED_DLLS%) do (
    if not exist "%VCPKG_BIN_DIR%\%%D" (
        set "MISSING_DEPS=!MISSING_DEPS! %%D"
    )
)

REM Проверка заголовочных файлов
for %%H in (%REQUIRED_HEADERS%) do (
    if not exist "%VCPKG_INCLUDE_DIR%\%%H" (
        set "MISSING_DEPS=!MISSING_DEPS! %%H"
    )
)

if not "!MISSING_DEPS!"=="" (
    echo Ошибка: Не найдены следующие зависимости: !MISSING_DEPS!
    echo Убедитесь, что зависимости установлены через vcpkg с triplet x64-mingw-dynamic.
    dir "%VCPKG_LIB_DIR%"
    dir "%VCPKG_BIN_DIR%"
    dir "%VCPKG_INCLUDE_DIR%" /s
    pause
    exit /b 1
) else (
    echo Все зависимости vcpkg найдены.
)

REM Проверяем, доступен ли qmake в PATH, если нет — пробуем стандартный путь
where qmake >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo qmake не найден в PATH, пробуем стандартный путь...
    set "QMAKE_PATH=C:\Qt\5.15.2\mingw81_64\bin\qmake.exe"
    if not exist "!QMAKE_PATH!" (
        echo Ошибка: qmake не найден по пути !QMAKE_PATH!
        set /p QMAKE_PATH="Введите путь к qmake.exe (например, C:\Qt\5.15.2\mingw81_64\bin\qmake.exe): "
        if not exist "!QMAKE_PATH!" (
            echo Ошибка: Указанный путь к qmake.exe недействителен: !QMAKE_PATH!
            pause
            exit /b 1
        )
    )
) else (
    for /f "delims=" %%i in ('where qmake') do set "QMAKE_PATH=%%i"
)

echo Используем !QMAKE_PATH! для генерации Makefile...

REM Проверяем наличие mingw32-make в PATH, если нет — пробуем стандартный путь
where mingw32-make >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo mingw32-make не найден в PATH, пробуем стандартный путь...
    set "MINGW32_MAKE_PATH=C:\Qt\Tools\mingw810_64\bin\mingw32-make.exe"
    if not exist "!MINGW32_MAKE_PATH!" (
        echo Ошибка: mingw32-make не найден по пути !MINGW32_MAKE_PATH!
        set /p MINGW32_MAKE_PATH="Введите путь к mingw32-make.exe (например, C:\Qt\Tools\mingw810_64\bin\mingw32-make.exe): "
        if not exist "!MINGW32_MAKE_PATH!" (
            echo Ошибка: Указанный путь к mingw32-make.exe недействителен: !MINGW32_MAKE_PATH!
            pause
            exit /b 1
        )
    )
) else (
    for /f "delims=" %%i in ('where mingw32-make') do set "MINGW32_MAKE_PATH=%%i"
)

echo Используем !MINGW32_MAKE_PATH! для сборки...

REM Добавляем пути к vcpkg в PATH
set "PATH=%PATH%;%VCPKG_BIN_DIR%;C:\Qt\5.15.2\mingw81_64\bin;C:\Qt\Tools\mingw810_64\bin"

REM Запускаем qmake с указанием путей к vcpkg
echo Запускаем qmake...
"!QMAKE_PATH!" DeadCode.pro -spec win32-g++ "INCLUDEPATH+=%VCPKG_INCLUDE_DIR%" "LIBS+=-L%VCPKG_LIB_DIR%" || (
    echo Ошибка: qmake не выполнен успешно
    pause
    exit /b 1
)

REM Очищаем предыдущую сборку
echo Очищаем предыдущую сборку...
"!MINGW32_MAKE_PATH!" -f Makefile.Release clean || (
    echo Предупреждение: Очистка предыдущей сборки не удалась, продолжаем...
)

REM Выполняем сборку с MinGW (с параллельными задачами для ускорения)
echo Выполняем сборку с mingw32-make...
"!MINGW32_MAKE_PATH!" -f Makefile.Release -j4 || (
    echo Ошибка: Сборка с mingw32-make не удалась
    pause
    exit /b 1
)

REM Переходим в директорию build/release (с учетом DESTDIR из DeadCode.pro)
cd /d "%PROJECT_DIR%\build\release" || (
    echo Ошибка: Не удалось перейти в директорию build\release
    pause
    exit /b 1
)

REM Проверяем наличие собранного файла
if not exist DeadCode.exe (
    echo Ошибка: DeadCode.exe не найден в директории build\release
    dir
    pause
    exit /b 1
)

REM Сжатие файла с помощью UPX, если UPX доступен
where upx >nul 2>&1
if %ERRORLEVEL% equ 0 (
    echo Сжимаем DeadCode.exe с помощью UPX...
    upx --best DeadCode.exe || (
        echo Предупреждение: Сжатие UPX не удалось. Продолжаю...
    )
    if exist DeadCode.exe (
        echo Сжатие успешно или файл сохранен
    ) else (
        echo Ошибка: Файл DeadCode.exe удален после сжатия UPX
        pause
        exit /b 1
    )
) else (
    echo UPX не найден, пропускаем сжатие...
)

echo Сборка успешно завершена!
echo Исполняемый файл находится в: %PROJECT_DIR%\build\release\DeadCode.exe
pause
exit /b 0