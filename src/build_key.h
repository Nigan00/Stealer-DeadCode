#ifndef BUILD_KEY_H
#define BUILD_KEY_H

#include <array>
#include <random>
#include <mutex>
#include <string> // Добавлено для использования std::string в GetStaticEncryptionKey

// Класс для генерации случайных чисел (потокобезопасный)
class RandomGenerator {
public:
    // Получение единственного экземпляра генератора (паттерн Singleton)
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
    // Приватный конструктор для реализации Singleton
    RandomGenerator() : gen_(rd_()) {} // Инициализация генератора случайных чисел
    RandomGenerator(const RandomGenerator&) = delete; // Запрет копирования
    RandomGenerator& operator=(const RandomGenerator&) = delete; // Запрет присваивания

    std::random_device rd_; // Источник энтропии
    std::mt19937 gen_;     // Генератор случайных чисел (Mersenne Twister)
    std::mutex mutex_;     // Мьютекс для потокобезопасности
};

// Генерация инициализационного вектора (IV) для шифрования
std::array<unsigned char, 16> GenerateIV() {
    std::array<unsigned char, 16> iv;
    RandomGenerator& generator = RandomGenerator::getGenerator();
    for (auto& byte : iv) {
        byte = generator.getRandomByte(); // Заполняем IV случайными байтами
    }
    return iv;
}

// Получение статического ключа шифрования на основе входной строки
std::array<unsigned char, 16> GetStaticEncryptionKey(const std::string& key) {
    std::array<unsigned char, 16> encryptionKey = {};
    if (key.empty()) {
        // Предупреждение: возвращение нулевого ключа может ослабить шифрование.
        // Рекомендуется выбросить исключение или использовать резервный ключ.
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
        encryptionKey[i] ^= generator.getRandomByte(); // Применяем XOR с случайным байтом
    }

    return encryptionKey;
}

#endif // BUILD_KEY_H