# Основные модули Qt, которые используются в проекте
QT       += core gui network widgets

# Имя целевого исполняемого файла
TARGET = DeadCode
# Тип проекта — приложение
TEMPLATE = app

# Исходные файлы (.cpp)
SOURCES += \
    $$PWD/src/main.cpp \
    $$PWD/ui/mainwindow.cpp

# Заголовочные файлы (.h)
HEADERS += \
    $$PWD/ui/mainwindow.h \
    $$PWD/src/build_key.h \
    $$PWD/src/polymorphic_code.h \
    $$PWD/src/junk_code.h

# Файлы интерфейса (.ui)
FORMS   += \
    $$PWD/ui/mainwindow.ui

# Ресурсы (иконка)
RC_ICONS = $$PWD/icon.ico

# Пути для поиска заголовочных файлов (только проектные директории)
INCLUDEPATH += \
    $$PWD/src \
    $$PWD/ui

# Настройка библиотек (используем vcpkg через переменные окружения)
# Удаляем жестко прописанные пути, полагаемся на $env:INCLUDE и $env:LIB из build.yml
LIBS += -lsqlite3 \
        -lzip \
        -lz \
        -lbz2 \
        -lcurl \
        -lws2_32

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
DESTDIR = $$PWD/build
OBJECTS_DIR = $$PWD/release
MOC_DIR = $$PWD/release
UI_DIR = $$PWD/release

# Очистка (удаляем исполняемый файл и временные заголовки при очистке проекта)
QMAKE_CLEAN += \
    $$DESTDIR/DeadCode.exe \
    $$PWD/src/build_key.h \
    $$PWD/src/polymorphic_code.h \
    $$PWD/src/junk_code.h

# Дополнительные проверки и зависимости для Windows
win32 {
    CONFIG(debug, debug|release) {
        # Для отладочной сборки
        QMAKE_CXXFLAGS += -g
    } else {
        # Для релизной сборки
        # Убрали -static, так как Qt обычно динамический
    }
}

# Пользовательские шаги сборки для генерации заголовков
PRE_TARGETDEPS += \
    $$PWD/src/build_key.h \
    $$PWD/src/polymorphic_code.h \
    $$PWD/src/junk_code.h

QMAKE_EXTRA_TARGETS += gen_headers
gen_headers.commands = @echo "Headers are generated during runtime by mainwindow.cpp"
# Создание пустых файлов, если они отсутствуют
!exists($$PWD/src/build_key.h) {
    system(echo. > $$PWD/src/build_key.h)
}
!exists($$PWD/src/polymorphic_code.h) {
    system(echo. > $$PWD/src/polymorphic_code.h)
}
!exists($$PWD/src/junk_code.h) {
    system(echo. > $$PWD/src/junk_code.h)
}