#ifndef COMPAT_H
#define COMPAT_H

#include <cstdlib>
#include <cstring>
#include <cerrno>

// Эмуляция dupenv_s для MinGW-w64
inline errno_t dupenv_s(char** buffer, size_t* size, const char* name) {
    if (buffer == nullptr || name == nullptr) {
        return EINVAL;
    }

    *buffer = nullptr;
    if (size != nullptr) {
        *size = 0;
    }

    const char* value = std::getenv(name);
    if (value == nullptr) {
        return ENOENT; // Переменная не найдена
    }

    size_t len = std::strlen(value) + 1;
    *buffer = static_cast<char*>(std::malloc(len));
    if (*buffer == nullptr) {
        return ENOMEM; // Ошибка выделения памяти
    }

    std::strcpy(*buffer, value);
    if (size != nullptr) {
        *size = len;
    }

    return 0;
}

#endif // COMPAT_H