#ifndef BUILD_KEY_H
#define BUILD_KEY_H

#include <QRandomGenerator>
#include <array>
#include <ctime>
#include <string>
#include <sstream>
#include <iomanip>

// Дефолтные значения ключей шифрования, заменяемые при сборке
#ifndef TELEGRAM_BOT_TOKEN
#define TELEGRAM_BOT_TOKEN ""
#endif

#ifndef TELEGRAM_CHAT_ID
#define TELEGRAM_CHAT_ID ""
#endif

#ifndef DISCORD_WEBHOOK
#define DISCORD_WEBHOOK ""
#endif

#ifndef ENCRYPTION_KEY1
#define ENCRYPTION_KEY1 "1234567890abcdef"
#endif

#ifndef ENCRYPTION_KEY2
#define ENCRYPTION_KEY2 "abcdef1234567890"
#endif

#ifndef ENCRYPTION_SALT
#define ENCRYPTION_SALT "deadcode_salt123"
#endif

// Генерация уникального ключа для шифрования (16 байт для AES-128 с учетом времени сборки)
inline std::array<unsigned char, 16> GenerateUniqueKey() {
    std::array<unsigned char, 16> key;
    QRandomGenerator generator(static_cast<quint32>(time(nullptr)));
    for (size_t i = 0; i < key.size(); ++i) {
        key[i] = static_cast<unsigned char>(generator.bounded(256));
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
    if (keyStr.empty()) {
        // Если строка пустая, возвращаем дефолтный ключ (например, ENCRYPTION_KEY1)
        std::string defaultKey = ENCRYPTION_KEY1;
        size_t len = std::min<size_t>(defaultKey.length(), 16);
        std::memcpy(key.data(), defaultKey.c_str(), len);
    } else {
        size_t len = std::min<size_t>(keyStr.length(), 16);
        std::memcpy(key.data(), keyStr.c_str(), len);
    }
    return key;
}

// Получение соли шифрования
inline std::string GetEncryptionSalt(const std::string& userSalt) {
    if (!userSalt.empty()) {
        return userSalt;
    }
    // Если пользовательская соль не указана, используем дефолтную
    return ENCRYPTION_SALT;
}

// Генерация случайной соли
inline std::string GenerateRandomSalt() {
    std::array<unsigned char, 16> salt = GenerateUniqueKey();
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (unsigned char byte : salt) {
        ss << std::setw(2) << static_cast<int>(byte);
    }
    return ss.str();
}

// Генерация инициализационного вектора (IV) для AES
inline std::array<unsigned char, 16> GenerateIV() {
    std::array<unsigned char, 16> iv;
    QRandomGenerator generator(static_cast<quint32>(time(nullptr)));
    for (size_t i = 0; i < iv.size(); ++i) {
        iv[i] = static_cast<unsigned char>(generator.bounded(256));
    }
    return iv;
}

#endif // BUILD_KEY_H