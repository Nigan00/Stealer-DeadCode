#ifndef JUNK_CODE_H
#define JUNK_CODE_H

#include <string>
#include <vector>
#include "build_key.h" // Для использования RandomGenerator

// Генерация случайного "мусорного" кода
std::string GenerateJunkCode(size_t length) {
    if (length == 0) {
        return "";
    }

    std::string junkCode;
    RandomGenerator& generator = RandomGenerator::getGenerator();

    // Генерируем случайные байты
    for (size_t i = 0; i < length; ++i) {
        junkCode += static_cast<char>(generator.getRandomByte());
    }

    return junkCode;
}

// Вставка "мусорного" кода в исходный код
std::string InsertJunkCode(const std::string& originalCode, size_t junkSize, size_t interval) {
    if (originalCode.empty() || junkSize == 0 || interval == 0) {
        return originalCode;
    }

    std::string result;
    RandomGenerator& generator = RandomGenerator::getGenerator();
    size_t position = 0;

    // Проходим по исходному коду
    for (char c : originalCode) {
        result += c;
        ++position;

        // Каждые 'interval' символов вставляем случайный "мусорный" код
        if (position % interval == 0) {
            std::string junk = GenerateJunkCode(junkSize);
            result += junk;
        }
    }

    // Добавляем дополнительный "мусор" в конец, если осталось место
    if (position % interval != 0) {
        std::string junk = GenerateJunkCode(junkSize);
        result += junk;
    }

    return result;
}

#endif // JUNK_CODE_H