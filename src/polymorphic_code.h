#ifndef POLYMORPHIC_CODE_H
#define POLYMORPHIC_CODE_H

#include <random>
#include <string>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <thread>
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

// Функция для генерации случайного числа
inline int getRandomNumber(int min, int max) {
    std::uniform_int_distribution<> dis(min, max);
    auto& gen = RandomGenerator::getGenerator();
    return dis(gen);
}

// Генерация случайной строки
inline std::string generateRandomString(size_t length) {
    static const char alphanum[] =
        "0123456789"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz";
    std::string result;
    result.reserve(length);
    for (size_t i = 0; i < length; ++i) {
        result += alphanum[getRandomNumber(0, sizeof(alphanum) - 2)];
    }
    return result;
}

// Генерация случайного имени функции для полиморфизма
inline std::string generateRandomFuncName() {
    static const char* prefixes[] = {"polyFunc", "obfFunc", "cryptFunc", "hideFunc", "maskFunc"};
    std::stringstream ss;
    ss << prefixes[getRandomNumber(0, 4)] << "_"
       << getRandomNumber(10000, 99999) << "_"
       << getRandomNumber(10000, 99999);
    return ss.str();
}

namespace Polymorphic {
// Функции ниже будут генерироваться динамически методом generatePolymorphicCode в mainwindow.cpp
// Пример сгенерированной функции (будет заменен при сборке)
inline void polyFunc_12345_67890() {
    volatile int dummy = getRandomNumber(1000, 10000);
    std::string noise = generateRandomString(getRandomNumber(5, 15));
    dummy ^= noise.length();
    for (int i = 0; i < 12; i++) {
        if (dummy % 2 == 0) {
            dummy = (dummy << getRandomNumber(1, 3)) ^ getRandomNumber(1, 255);
        } else {
            dummy = (dummy >> getRandomNumber(1, 2)) + noise[i % noise.length()];
        }
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(getRandomNumber(1, 10)));
}

// Функция executePolymorphicCode вызывает сгенерированные функции
inline void executePolymorphicCode() {
    // Имена функций будут заменены при сборке
    polyFunc_12345_67890();
    // Другие вызовы будут добавлены при генерации
}
} // namespace Polymorphic

#endif // POLYMORPHIC_CODE_H