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

REM Проверяем зависимости: SQLite, zlib, libcurl
echo Проверяем зависимости...
where sqlite3 >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo Ошибка: SQLite3 не найден. Убедитесь, что SQLite установлен и добавлен в PATH.
    pause
    exit /b 1
)
where pkg-config >nul 2>&1
if %ERRORLEVEL% equ 0 (
    pkg-config --exists zlib
    if %ERRORLEVEL% neq 0 (
        echo Ошибка: zlib не найден. Установите zlib для поддержки ZIP архивов.
        pause
        exit /b 1
    )
    pkg-config --exists libcurl
    if %ERRORLEVEL% neq 0 (
        echo Ошибка: libcurl не найден. Установите libcurl для отправки данных через Telegram/Discord.
        pause
        exit /b 1
    )
) else (
    echo Предупреждение: pkg-config не найден, пропускаем проверку zlib и libcurl...
)

REM Проверяем, доступен ли qmake в PATH, если нет — пробуем стандартный путь или запрашиваем у пользователя
where qmake >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo qmake не найден в PATH, пробуем стандартный путь...
    set "QMAKE_PATH=C:\Qt\5.15.2\mingw81_64\bin\qmake.exe"
    if not exist "!QMAKE_PATH!" (
        echo Ошибка: qmake не найден по пути !QMAKE_PATH!
        set /p QMAKE_PATH="Введите путь к qmake.exe (например, C:\Qt\6.5.0\mingw_64\bin\qmake.exe): "
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
"!QMAKE_PATH!" DeadCode.pro -spec win32-g++ || (
    echo Ошибка: qmake не выполнен успешно
    pause
    exit /b 1
)

REM Проверяем наличие mingw32-make
where mingw32-make >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo Ошибка: mingw32-make не найден в PATH
    echo Убедитесь, что MinGW установлен и добавлен в PATH
    pause
    exit /b 1
)

REM Очищаем предыдущую сборку
echo Очищаем предыдущую сборку...
mingw32-make -f Makefile.Release clean || (
    echo Предупреждение: Очистка предыдущей сборки не удалась, продолжаем...
)

REM Выполняем сборку с MinGW (с параллельными задачами для ускорения)
echo Выполняем сборку с mingw32-make...
mingw32-make -f Makefile.Release -j4 || (
    echo Ошибка: Сборка с mingw32-make не удалась
    pause
    exit /b 1
)

REM Переходим в директорию build (с учетом DESTDIR из DeadCode.pro)
cd /d "%PROJECT_DIR%\build" || (
    echo Ошибка: Не удалось перейти в директорию build
    pause
    exit /b 1
)

REM Проверяем наличие собранного файла
if not exist DeadCode.exe (
    echo Ошибка: DeadCode.exe не найден в директории build
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
echo Исполняемый файл находится в: %PROJECT_DIR%\build\DeadCode.exe
pause
exit /b 0