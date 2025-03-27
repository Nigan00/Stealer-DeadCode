#ifndef JUNK_CODE_H
#define JUNK_CODE_H

#include <string>
#include <vector>
#include <random>
#include <chrono>
#include <thread>

namespace JunkCode {
    inline int getRandomNumber(int min, int max) {
        static std::random_device rd;
        static std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(min, max);
        return dis(gen);
    }

    inline void executeJunkCode() {
        // Пример реализации из mainwindow.cpp
        volatile int x = getRandomNumber(1000, 10000);
        volatile int y = getRandomNumber(500, 5000);
        std::vector<int> noise;
        for (int j = 0; j < getRandomNumber(5, 20); ++j) {
            noise.push_back(getRandomNumber(1, 100));
        }
        for (size_t k = 0; k < noise.size(); ++k) {
            if (noise[k] % 2 == 0) {
                x = (x ^ noise[k]) + y;
            } else {
                y = (y - noise[k]) ^ x;
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(getRandomNumber(1, 5)));
    }
}

#endif // JUNK_CODE_H