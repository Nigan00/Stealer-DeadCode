#ifndef BUILD_KEY_H
#define BUILD_KEY_H

#include <array>
#include <random>
#include <mutex>

// Класс для генерации случайных чисел (потокобезопасный)
class RandomGenerator {
public:
    static RandomGenerator& getGenerator() {
        static RandomGenerator instance;
        return instance;
    }

    // Генерация случайного числа в заданном диапазоне
    int getRandomInt(int min, int max) {
        std::lock_guard<std::mutex> lock(mutex_);
        std::uniform_int_distribution<int> dist(min, max);
        return dist(gen_);
    }

    // Генерация случайного байта (0-255)
    unsigned char getRandomByte() {
        return static_cast<unsigned char>(getRandomInt(0, 255));
    }

private:
    RandomGenerator() : gen_(rd_()) {} // Инициализация генератора случайных чисел
    RandomGenerator(const RandomGenerator&) = delete;
    RandomGenerator& operator=(const RandomGenerator&) = delete;

    std::random_device rd_;
    std::mt19937 gen_;
    std::mutex mutex_;
};

// Генерация инициализационного вектора (IV) для шифрования
std::array<unsigned char, 16> GenerateIV() {
    std::array<unsigned char, 16> iv;
    RandomGenerator& generator = RandomGenerator::getGenerator();
    for (auto& byte : iv) {
        byte = generator.getRandomByte();
    }
    return iv;
}

// Получение статического ключа шифрования на основе входной строки
std::array<unsigned char, 16> GetStaticEncryptionKey(const std::string& key) {
    std::array<unsigned char, 16> encryptionKey = {};
    if (key.empty()) {
        return encryptionKey; // Возвращаем пустой ключ, если входная строка пуста
    }

    // Используем входной ключ для заполнения массива
    size_t keyLength = key.length();
    for (size_t i = 0; i < encryptionKey.size(); ++i) {
        encryptionKey[i] = static_cast<unsigned char>(key[i % keyLength]);
    }

    // Добавляем случайные данные для повышения энтропии
    RandomGenerator& generator = RandomGenerator::getGenerator();
    for (size_t i = 0; i < encryptionKey.size(); ++i) {
        encryptionKey[i] ^= generator.getRandomByte();
    }

    return encryptionKey;
}

#endif // BUILD_KEY_H