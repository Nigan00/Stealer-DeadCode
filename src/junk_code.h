#ifndef JUNK_CODE_H
#define JUNK_CODE_H

#include <string>
#include <vector>
#include <random>
#include <algorithm>
#include <chrono>
#include <thread>
#include "polymorphic_code.h"

namespace JunkCode {

inline void junkFunc1() {
    volatile int a = getRandomNumber(100, 2000);
    volatile int b = getRandomNumber(50, 1000);
    volatile int c = a * b;
    c ^= getRandomNumber(1, 255);
    for (int i = 0; i < getRandomNumber(5, 25); i++) {
        if (c % 2 == 0) {
            c += (i * getRandomNumber(1, 15)) ^ getRandomNumber(1, 63);
        } else {
            c -= getRandomNumber(0, 10) + (c >> getRandomNumber(1, 3));
        }
    }
    std::string dummy = generateRandomString(getRandomNumber(10, 60));
    std::vector<char> buffer(dummy.begin(), dummy.end());
    std::reverse(buffer.begin(), buffer.end());
    std::this_thread::sleep_for(std::chrono::milliseconds(getRandomNumber(1, 10)));
}

// Добавляем вариативность: генерируем разные тела функций
inline void junkFunc2() {
    std::string str1 = generateRandomString(getRandomNumber(20, 40));
    std::string str2 = generateRandomString(getRandomNumber(30, 50));
    std::string concat = str1 + str2;
    for (size_t i = 0; i < concat.size(); i++) {
        concat[i] ^= getRandomNumber(0, 127);
        if (concat[i] % 2 == 0) {
            concat[i] += getRandomNumber(1, 10);
        } else {
            concat[i] -= getRandomNumber(1, 5);
        }
    }
    std::vector<int> numbers(getRandomNumber(10, 80));
    for (auto& num : numbers) {
        num = getRandomNumber(-2000, 2000);
        num *= getRandomNumber(1, 7);
        num ^= getRandomNumber(0, 255);
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(getRandomNumber(1, 8)));
}

inline void junkFunc3() {
    std::vector<char> buffer(getRandomNumber(1024, 4096));
    for (size_t i = 0; i < buffer.size(); i++) {
        buffer[i] = static_cast<char>(getRandomNumber(0, 255));
    }
    volatile int sum = 0;
    for (size_t i = 0; i < buffer.size(); i++) {
        sum += buffer[i];
        sum ^= getRandomNumber(0, 31);
        if (sum % 3 == 0) {
            sum -= getRandomNumber(0, 5);
        } else {
            sum += getRandomNumber(1, 10);
        }
    }
    std::string dummy = generateRandomString(getRandomNumber(8, 30));
    std::vector<char> vec(dummy.begin(), dummy.end());
    if (getRandomNumber(0, 1)) {
        std::sort(vec.begin(), vec.end());
    } else {
        std::reverse(vec.begin(), vec.end());
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(getRandomNumber(1, 7)));
}

inline void junkFunc4() {
    static std::mutex mtx;
    std::lock_guard<std::mutex> lock(mtx);
    static std::random_device rd;
    static std::mt19937 gen(rd());
    volatile int counter = getRandomNumber(200, 1500);
    while (counter > 0) {
        counter -= getRandomNumber(1, 15);
        volatile int temp = counter * getRandomNumber(2, 10);
        temp ^= getRandomNumber(0, 127);
        for (int j = 0; j < getRandomNumber(1, 7); j++) {
            if (temp % 2 == 1) {
                temp += (j * getRandomNumber(1, 4)) ^ getRandomNumber(1, 31);
            } else {
                temp >>= getRandomNumber(1, 2);
            }
        }
    }
    std::string dummy = generateRandomString(getRandomNumber(12, 45));
    std::vector<char> vec(dummy.begin(), dummy.end());
    std::shuffle(vec.begin(), vec.end(), gen);
    std::this_thread::sleep_for(std::chrono::milliseconds(getRandomNumber(1, 6)));
}

inline void junkFunc5() {
    volatile double x = static_cast<double>(getRandomNumber(2000, 6000));
    volatile double y = static_cast<double>(getRandomNumber(1000, 3000));
    x *= static_cast<double>(getRandomNumber(1, 6));
    y /= static_cast<double>(getRandomNumber(1, 4));
    volatile double z = x + y;
    for (int i = 0; i < getRandomNumber(15, 40); i++) {
        z += static_cast<double>(getRandomNumber(-100, 100));
        if (static_cast<int>(z) % 5 == 0) {
            z *= static_cast<double>(getRandomNumber(1, 3));
        } else {
            z -= static_cast<double>(getRandomNumber(50, 150));
        }
    }
    std::string dummy = generateRandomString(getRandomNumber(10, 40));
    std::vector<double> dummyVec(getRandomNumber(8, 25), 0.0);
    for (auto& val : dummyVec) {
        val = static_cast<double>(getRandomNumber(-500, 500));
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(getRandomNumber(1, 5)));
}

inline void executeJunkCode() {
    // Случайный порядок вызова функций
    std::vector<void(*)()> funcs = { junkFunc1, junkFunc2, junkFunc3, junkFunc4, junkFunc5 };
    std::shuffle(funcs.begin(), funcs.end(), RandomGenerator::getGenerator());
    for (const auto& func : funcs) {
        func();
    }
}

} // namespace JunkCode

#endif // JUNK_CODE_H