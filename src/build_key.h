#ifndef BUILD_KEY_H
#define BUILD_KEY_H

#include <array>
#include <random>
#include <mutex>
#include <string>
#include <sstream>
#include <iomanip>

// Класс для генерации случайных чисел (потокобезопасный)
class RandomGenerator {
public:
    static RandomGenerator& getGenerator() {
        static RandomGenerator instance;
        return instance;
    }

    int getRandomInt(int min, int max) {
        std::lock_guard<std::mutex> lock(mutex_);
        std::uniform_int_distribution<int> dist(min, max);
        return dist(gen_);
    }

    unsigned char getRandomByte() {
        return static_cast<unsigned char>(getRandomInt(0, 255));
    }

private:
    RandomGenerator() : gen_(rd_()) {}
    RandomGenerator(const RandomGenerator&) = delete;
    RandomGenerator& operator=(const RandomGenerator&) = delete;

    std::random_device rd_;
    std::mt19937 gen_;
    std::mutex mutex_;
};

// Генерация уникального ключа
inline std::array<unsigned char, 16> GenerateUniqueKey() {
    std::array<unsigned char, 16> key;
    RandomGenerator& generator = RandomGenerator::getGenerator();
    for (auto& byte : key) {
        byte = generator.getRandomByte();
    }
    return key;
}

// Генерация инициализационного вектора (IV)
inline std::array<unsigned char, 16> GenerateIV() {
    std::array<unsigned char, 16> iv;
    RandomGenerator& generator = RandomGenerator::getGenerator();
    for (auto& byte : iv) {
        byte = generator.getRandomByte();
    }
    return iv;
}

// Генерация XOR-ключа как строки
inline std::string GenerateUniqueXorKey() {
    RandomGenerator& generator = RandomGenerator::getGenerator();
    std::stringstream ss;
    for (int i = 0; i < 16; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(generator.getRandomByte());
    }
    return ss.str();
}

// Получение статического ключа шифрования на основе строки
inline std::array<unsigned char, 16> GetStaticEncryptionKey(const std::string& key) {
    std::array<unsigned char, 16> encryptionKey = {};
    if (key.empty()) {
        return encryptionKey; // Нулевой ключ при пустой строке
    }

    size_t keyLength = key.length();
    for (size_t i = 0; i < encryptionKey.size(); ++i) {
        encryptionKey[i] = static_cast<unsigned char>(key[i % keyLength]);
    }

    RandomGenerator& generator = RandomGenerator::getGenerator();
    for (size_t i = 0; i < encryptionKey.size(); ++i) {
        encryptionKey[i] ^= generator.getRandomByte();
    }
    return encryptionKey;
}

#endif // BUILD_KEY_H