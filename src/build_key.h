#ifndef BUILD_KEY_H
#define BUILD_KEY_H

#include <array>
#include <string>
#include <sstream>
#include <iomanip>
#include <random>
#include <cstring>

// Генерация уникального ключа для шифрования (16 байт для AES-128)
inline std::array<unsigned char, 16> GenerateUniqueKey() {
    std::array<unsigned char, 16> key;
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    for (size_t i = 0; i < key.size(); ++i) {
        key[i] = static_cast<unsigned char>(dis(gen));
    }
    return key;
}

// Генерация уникального ключа в виде строки (для XOR-шифрования)
inline std::string GenerateUniqueXorKey() {
    std::array<unsigned char, 16> key = GenerateUniqueKey();
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (unsigned char byte : key) {
        ss << std::setw(2) << static_cast<int>(byte);
    }
    return ss.str();
}

// Получение статического ключа из строки
inline std::array<unsigned char, 16> GetStaticEncryptionKey(const std::string& keyStr) {
    std::array<unsigned char, 16> key = {};
    if (!keyStr.empty()) {
        size_t len = std::min<size_t>(keyStr.length(), 16);
        std::memcpy(key.data(), keyStr.c_str(), len);
        // Заполняем остаток нулями, если строка короче 16 байт
        if (len < 16) {
            std::memset(key.data() + len, 0, 16 - len);
        }
    }
    return key;
}

// Получение соли шифрования
inline std::string GetEncryptionSalt(const std::string& userSalt) {
    if (!userSalt.empty()) {
        return userSalt;
    }
    // Если пользовательская соль не указана, генерируем новую
    return GenerateUniqueXorKey();
}

// Генерация случайной соли
inline std::string GenerateRandomSalt() {
    return GenerateUniqueXorKey();
}

// Генерация инициализационного вектора (IV) для AES
inline std::array<unsigned char, 16> GenerateIV() {
    std::array<unsigned char, 16> iv;
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    for (size_t i = 0; i < iv.size(); ++i) {
        iv[i] = static_cast<unsigned char>(dis(gen));
    }
    return iv;
}

#endif // BUILD_KEY_H