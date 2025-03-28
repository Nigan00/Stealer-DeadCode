# Основные модули Qt
QT += core gui network widgets

# Имя целевого исполняемого файла
TARGET = DeadCode
# Тип проекта — приложение
TEMPLATE = app

# Исходные файлы (.cpp)
SOURCES += \
    ../src/main.cpp \
    mainwindow.cpp \
    ../src/stealerworker.cpp

# Заголовочные файлы (.h)
HEADERS += \
    mainwindow.h \
    ../src/build_key.h \
    ../src/polymorphic_code.h \
    ../src/junk_code.h \
    ../src/stealerworker.h

# Файлы интерфейса (.ui)
FORMS += \
    mainwindow.ui

# Ресурсы (иконка)
RC_ICONS = ../icon.ico

# Пути для поиска заголовочных файлов
INCLUDEPATH += \
    ../src \
    . \
    C:/vcpkg/installed/x64-mingw-static/include \
    ../release

# Библиотеки (vcpkg и системные Windows-библиотеки)
LIBS += -LC:/vcpkg/installed/x64-mingw-static/lib \
        -lsqlite3 \
        -lzip \
        -lz \
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
        -lurlmon

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
                  -D_CRT_SECURE_NO_WARNINGS \
                  -Wno-deprecated-declarations \
                  -Wno-cast-function-type

# Флаги линковки
QMAKE_LFLAGS += -static \
                -DYNAMICBASE \
                -NXCOMPAT \
                -SUBSYSTEM:WINDOWS

# Определения для сборки (добавляем дату сборки и версию из git)
BUILD_DATE = $$system(powershell -Command "Get-Date -Format 'yyyy-MM-dd'")
isEmpty(BUILD_DATE) {
    BUILD_DATE = "unknown"
}
BUILD_VERSION = $$system(git rev-parse --short HEAD 2> nul)
isEmpty(BUILD_VERSION) {
    BUILD_VERSION = "unknown"
}
DEFINES += BUILD_DATE=\\\"$${BUILD_DATE}\\\" \
           BUILD_VERSION=\\\"$${BUILD_VERSION}\\\"

# Директории для выходных файлов
DESTDIR = ../build
OBJECTS_DIR = ../release
MOC_DIR = ../Release
UI_DIR = ../Release

# Очистка
QMAKE_CLEAN += \
    ../build/DeadCode.exe \
    ../Release/*.o \
    ../Release/*.cpp \
    ../Release/*.h

# Дополнительные проверки и зависимости для Windows
win32 {
    CONFIG(debug, debug|release) {
        QMAKE_CXXFLAGS += -g
        QMAKE_LFLAGS -= -O2
    } else {
        QMAKE_CXXFLAGS += -O2
        QMAKE_LFLAGS += -O2
    }
}

# Пользовательские шаги сборки для генерации заголовков
PRE_TARGETDEPS += \
    ../src/build_key.h \
    ../src/polymorphic_code.h \
    ../src/junk_code.h \
    ../src/stealerworker.h

# Создание пустых файлов, если они отсутствуют
!exists(../src/build_key.h) {
    system(echo. > ../src/build_key.h)
}
!exists(../src/polymorphic_code.h) {
    system(echo. > ../src/polymorphic_code.h)
}
!exists(../src/junk_code.h) {
    system(echo. > ../src/junk_code.h)
}
!exists(../src/stealerworker.h) {
    system(echo. > ../src/stealerworker.h)
}