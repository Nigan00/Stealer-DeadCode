#ifndef BUILD_KEY_H
#define BUILD_KEY_H

#include <array>
#include <string>
#include <sstream>
#include <iomanip>
#include <random>
#include <cstring>
#include <mutex>

// Потокобезопасный генератор случайных чисел
class RandomGenerator {
public:
    static std::mt19937& getGenerator() {
        static std::mutex mtx;
        std::lock_guard<std::mutex> lock(mtx);
        static std::random_device rd;
        static std::mt19937 gen(rd());
        return gen;
    }
};

// Генерация уникального ключа для шифрования (16 байт для AES-128)
inline std::array<unsigned char, 16> GenerateUniqueKey() {
    std::array<unsigned char, 16> key;
    std::uniform_int_distribution<> dis(0, 255);
    auto& gen = RandomGenerator::getGenerator();
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
        if (len < 16) {
            std::memset(key.data() + len, 0, 16 - len);
        }
    }
    return key;
}

// Генерация инициализационного вектора (IV) для AES
inline std::array<unsigned char, 16> GenerateIV() {
    std::array<unsigned char, 16> iv;
    std::uniform_int_distribution<> dis(0, 255);
    auto& gen = RandomGenerator::getGenerator();
    for (size_t i = 0; i < iv.size(); ++i) {
        iv[i] = static_cast<unsigned char>(dis(gen));
    }
    return iv;
}

// Константы, которые будут перегенерироваться при каждой сборке
// Эти значения будут заменены методом generateBuildKeyHeader в mainwindow.cpp
#define ENCRYPTION_KEY_1 "00000000000000000000000000000000" // 32 символа (16 байт в hex)
#define ENCRYPTION_KEY_2 "00000000000000000000000000000000" // 32 символа (16 байт в hex)
#define ENCRYPTION_SALT  "00000000000000000000000000000000" // 32 символа (16 байт в hex)

#endif // BUILD_KEY_H