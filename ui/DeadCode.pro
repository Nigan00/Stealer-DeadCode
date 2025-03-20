# Основные модули Qt, которые используются в проекте
QT       += core gui network widgets

# Имя целевого исполняемого файла
TARGET = DeadCode
# Тип проекта — приложение
TEMPLATE = app

# Исходные файлы (.cpp)
SOURCES += \
    $$PWD/../src/main.cpp \
    $$PWD/mainwindow.cpp

# Заголовочные файлы (.h)
HEADERS += \
    $$PWD/mainwindow.h \
    $$PWD/../src/build_key.h \
    $$PWD/../src/polymorphic_code.h \
    $$PWD/../src/junk_code.h

# Файлы интерфейса (.ui)
FORMS   += \
    $$PWD/mainwindow.ui

# Ресурсы (иконка)
RC_ICONS = $$PWD/../icon.ico

# Пути для поиска заголовочных файлов
INCLUDEPATH += \
    $$PWD/../src \
    $$PWD \
    $$(VCPKG_ROOT)/installed/x64-windows-static/include

# Пути для отслеживания зависимостей
DEPENDPATH += \
    $$PWD/../src \
    $$PWD

# Библиотеки (vcpkg и системные Windows-библиотеки)
LIBS += \
    -L$$(VCPKG_ROOT)/installed/x64-windows-static/lib \
    -lsqlite3 \
    -lzip \
    -lzlib \
    -lbz2 \
    -lcurl \
    -lbcrypt \
    -lws2_32 \
    -lshlwapi \
    -lpsapi

# Флаги компиляции
QMAKE_CXXFLAGS += -O2 \
                  -std=gnu++17 \
                  -Wall \
                  -Wextra \
                  -Werror=return-type \
                  -fexceptions \
                  -DUNICODE \
                  -D_UNICODE \
                  -DWIN32 \
                  -DQT_NO_DEBUG \
                  -D_CRT_SECURE_NO_WARNINGS

# Флаги линковки
QMAKE_LFLAGS += -DYNAMICBASE \
                -NXCOMPAT \
                -SUBSYSTEM:WINDOWS

# Определения для сборки (добавляем дату сборки и версию из git)
DEFINES += BUILD_DATE=\\\"$$system(date /t)\\\" \
           BUILD_VERSION=\\\"$$system(git rev-parse --short HEAD 2> nul || echo unknown)\\\"

# Директории для выходных файлов
DESTDIR = $$PWD/../build
OBJECTS_DIR = $$PWD/../release
MOC_DIR = $$PWD/../release
UI_DIR = $$PWD/../release

# Очистка (удаляем только исполняемый файл и временные файлы сборки)
QMAKE_CLEAN += \
    $$DESTDIR/DeadCode.exe \
    $$OBJECTS_DIR/*.o \
    $$MOC_DIR/*.cpp \
    $$UI_DIR/*.h

# Дополнительные проверки и зависимости для Windows
win32 {
    CONFIG(debug, debug|release) {
        # Для отладочной сборки
        QMAKE_CXXFLAGS += -g
    } else {
        # Для релизной сборки
        # Убрали -static, так как Qt динамический
    }
}

# Удаляем создание пустых заголовков, так как они генерируются динамически
# Вместо этого добавляем зависимость от генерации
PRE_TARGETDEPS += \
    $$PWD/../src/build_key.h \
    $$PWD/../src/polymorphic_code.h \
    $$PWD/../src/junk_code.h

QMAKE_EXTRA_TARGETS += gen_headers
gen_headers.commands = @echo "Headers are generated during runtime by mainwindow.cpp"