#ifndef POLYMORPHIC_CODE_H
#define POLYMORPHIC_CODE_H

#include <string>
#include <vector>
#include "build_key.h" // Включаем build_key.h для использования RandomGenerator

// Генерация полиморфного кода
std::string GeneratePolymorphicCode(const std::string& originalCode) {
    if (originalCode.empty()) {
        return "";
    }

    std::string polymorphicCode;
    RandomGenerator& generator = RandomGenerator::getGenerator();

    // Проходим по каждому символу исходного кода
    for (char c : originalCode) {
        // С вероятностью 50% добавляем случайный "мусорный" код
        if (generator.getRandomInt(0, 1) == 1) {
            // Добавляем случайное количество NOP-подобных инструкций (в виде символов)
            int nopCount = generator.getRandomInt(1, 5);
            for (int i = 0; i < nopCount; ++i) {
                polymorphicCode += static_cast<char>(generator.getRandomByte());
            }
        }
        // Добавляем исходный символ
        polymorphicCode += c;
    }

    // Дополнительно перемешиваем результат
    for (size_t i = 0; i < polymorphicCode.size(); ++i) {
        if (generator.getRandomInt(0, 1) == 1) {
            size_t j = generator.getRandomInt(0, polymorphicCode.size() - 1);
            std::swap(polymorphicCode[i], polymorphicCode[j]);
        }
    }

    return polymorphicCode;
}

// Обфускация строки
std::string ObfuscateString(const std::string& input) {
    if (input.empty()) {
        return "";
    }

    std::string obfuscated;
    RandomGenerator& generator = RandomGenerator::getGenerator();

    // Применяем XOR-обфускацию с использованием случайного ключа
    unsigned char key = generator.getRandomByte();
    for (char c : input) {
        obfuscated += static_cast<char>(c ^ key);
    }

    // Добавляем случайные байты в начало и конец строки
    int prefixLength = generator.getRandomInt(1, 5);
    int suffixLength = generator.getRandomInt(1, 5);

    std::string result;
    // Добавляем случайный префикс
    for (int i = 0; i < prefixLength; ++i) {
        result += static_cast<char>(generator.getRandomByte());
    }
    // Добавляем обфусцированную строку
    result += obfuscated;
    // Добавляем случайный суффикс
    for (int i = 0; i < suffixLength; ++i) {
        result += static_cast<char>(generator.getRandomByte());
    }

    return result;
}

#endif // POLYMORPHIC_CODE_H