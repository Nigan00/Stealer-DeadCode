#ifndef COMPAT_H
#define COMPAT_H

#ifdef __MINGW32__
// MinGW-w64 не предоставляет _dupenv_s, реализуем её через getenv
#include <cstdlib>
#include <cstring>

inline errno_t _dupenv_s(char** buffer, size_t* size, const char* varname) {
    if (!buffer || !varname) {
        return EINVAL; // Ошибка: некорректные аргументы
    }

    *buffer = nullptr;
    if (size) *size = 0;

    const char* value = getenv(varname);
    if (!value) {
        return ENOENT; // Переменная окружения не найдена
    }

    size_t len = strlen(value) + 1;
    *buffer = (char*)malloc(len);
    if (!*buffer) {
        return ENOMEM; // Ошибка выделения памяти
    }

    strcpy(*buffer, value);
    if (size) *size = len;

    return 0; // Успех
}
#endif

#endif // COMPAT_H