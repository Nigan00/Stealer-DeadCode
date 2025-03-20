#ifndef JUNK_CODE_H
#define JUNK_CODE_H

#include <string>
#include <vector>
#include <random>
#include <cstring>
#include <algorithm>
#include <chrono>
#include <thread>
#include "polymorphic_code.h" // Для использования getRandomNumber и generateRandomString

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

    inline void junkFunc2() {
        std::string str1 = generateRandomString(25);
        std::string str2 = generateRandomString(35);
        std::string concat = str1 + str2;
        for (size_t i = 0; i < concat.size(); i++) {
            concat[i] ^= getRandomNumber(0, 127);
            if (concat[i] % 2 == 0) {
                concat[i] += getRandomNumber(1, 10);
            }
        }
        std::vector<int> numbers(getRandomNumber(15, 60));
        for (auto& num : numbers) {
            num = getRandomNumber(-1500, 1500);
            num *= getRandomNumber(1, 6);
            num ^= getRandomNumber(0, 255);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(getRandomNumber(1, 8)));
    }

    inline void junkFunc3() {
        char* buffer = new char[2048];
        for (int i = 0; i < 2048; i++) {
            buffer[i] = static_cast<char>(getRandomNumber(0, 255));
        }
        volatile int sum = 0;
        for (int i = 0; i < 2048; i++) {
            sum += buffer[i];
            sum ^= getRandomNumber(0, 31);
            if (sum % 3 == 0) {
                sum -= getRandomNumber(0, 5);
            } else {
                sum += getRandomNumber(1, 10);
            }
        }
        delete[] buffer;
        std::string dummy = generateRandomString(getRandomNumber(8, 30));
        std::vector<char> vec(dummy.begin(), dummy.end());
        std::sort(vec.begin(), vec.end());
        std::this_thread::sleep_for(std::chrono::milliseconds(getRandomNumber(1, 7)));
    }

    inline void junkFunc4() {
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
        std::shuffle(vec.begin(), vec.end(), std::mt19937(std::random_device()()));
        std::this_thread::sleep_for(std::chrono::milliseconds(getRandomNumber(1, 6)));
    }

    inline void junkFunc5() {
        volatile int x = getRandomNumber(2000, 6000);
        volatile int y = getRandomNumber(1000, 3000);
        x <<= getRandomNumber(1, 6);
        y >>= getRandomNumber(1, 4);
        volatile int z = x ^ y;
        for (int i = 0; i < getRandomNumber(15, 40); i++) {
            z += getRandomNumber(-100, 100);
            if (z % 5 == 0) {
                z &= getRandomNumber(0, 511);
            } else {
                z *= getRandomNumber(1, 3);
            }
        }
        std::string dummy = generateRandomString(getRandomNumber(10, 40));
        std::vector<int> dummyVec(getRandomNumber(8, 25), 0);
        for (auto& val : dummyVec) {
            val = getRandomNumber(-500, 500);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(getRandomNumber(1, 5)));
    }

    inline void executeJunkCode() {
        junkFunc1();
        junkFunc2();
        junkFunc3();
        junkFunc4();
        junkFunc5();
    }

} // namespace JunkCode

#endif // JUNK_CODE_H