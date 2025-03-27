#ifndef POLYMORPHIC_CODE_H
#define POLYMORPHIC_CODE_H

#include <string>
#include <random>
#include <chrono>
#include <thread>

namespace Polymorphic {
    inline int getRandomNumber(int min, int max) {
        static std::random_device rd;
        static std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(min, max);
        return dis(gen);
    }

    inline std::string generateRandomString(size_t length) {
        static const char alphanum[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
        std::string result;
        result.reserve(length);
        for (size_t i = 0; i < length; ++i) {
            result += alphanum[getRandomNumber(0, sizeof(alphanum) - 2)];
        }
        return result;
    }

    inline void executePolymorphicCode() {
        // Пример реализации из mainwindow.cpp
        volatile int dummy = getRandomNumber(1000, 15000);
        std::string noise = generateRandomString(getRandomNumber(5, 20));
        volatile int dummy2 = dummy ^ noise.length();
        for (int i = 0; i < getRandomNumber(3, 15); i++) {
            if (dummy2 % 2 == 0) {
                dummy2 = (dummy2 << getRandomNumber(1, 3)) ^ noise[i % noise.length()];
            } else {
                dummy2 = (dummy2 >> getRandomNumber(1, 2)) + getRandomNumber(10, 50);
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(getRandomNumber(1, 10)));
    }
}

#endif // POLYMORPHIC_CODE_H