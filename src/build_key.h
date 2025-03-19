#ifndef BUILD_KEY_H
#define BUILD_KEY_H

#include <QRandomGenerator>
#include <array>
#include <ctime>
#include <string>

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

// Получение статического ключа из строки
inline std::array<unsigned char, 16> GetStaticEncryptionKey(const std::string& keyStr) {
    std::array<unsigned char, 16> key = {};
    size_t len = std::min<size_t>(keyStr.length(), 16);
    std::memcpy(key.data(), keyStr.c_str(), len);
    return key;
}

#endif // BUILD_KEY_H