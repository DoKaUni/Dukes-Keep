#include "keystore.h"

std::vector<unsigned char> EphemeralKeyStorage::encryptedKey;
std::mutex EphemeralKeyStorage::mutex;
bool EphemeralKeyStorage::initialized = false;

void EphemeralKeyStorage::Initialize() {
    if (!initialized) {
        std::atexit(CleanupHandler);
        
        initialized = true;
    }
}

void EphemeralKeyStorage::CleanupHandler() {
    std::lock_guard<std::mutex> lock(mutex);
    SecureZeroMemory(encryptedKey.data(), encryptedKey.size());
    encryptedKey.clear();
}

void EphemeralKeyStorage::StoreKey(const std::vector<unsigned char>& key) {
    std::lock_guard<std::mutex> lock(mutex);
    Initialize();

    DATA_BLOB dataIn = { static_cast<DWORD>(key.size()), const_cast<BYTE*>(key.data()) };
    DATA_BLOB dataOut;
    
    if (!CryptProtectData(
        &dataIn,
        L"Duke's Keep AES Key",
        nullptr,
        nullptr,
        nullptr,
        CRYPTPROTECT_UI_FORBIDDEN,
        &dataOut)) {
        throw std::runtime_error("CryptProtectData failed. Error: " + std::to_string(GetLastError()));
    }

    // Store encrypted data in memory
    encryptedKey.assign(dataOut.pbData, dataOut.pbData + dataOut.cbData);
    LocalFree(dataOut.pbData);
}

void EphemeralKeyStorage::RetrieveKey(unsigned char* lockedBuffer, size_t bufferSize) {
    std::lock_guard<std::mutex> lock(mutex);
    if (encryptedKey.empty()) {
        throw std::runtime_error("No key stored");
    }

    DATA_BLOB dataIn = { static_cast<DWORD>(encryptedKey.size()), encryptedKey.data() };
    DATA_BLOB dataOut;

    if (!CryptUnprotectData(
        &dataIn,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        CRYPTPROTECT_UI_FORBIDDEN,
        &dataOut)) {
        throw std::runtime_error("CryptUnprotectData failed. Error: " + std::to_string(GetLastError()));
    }

    if (dataOut.cbData > bufferSize) {
        LocalFree(dataOut.pbData);
        
        throw std::runtime_error("Buffer too small for decrypted key");
    }

    std::copy_n(dataOut.pbData, dataOut.cbData, lockedBuffer);
    SecureZeroMemory(dataOut.pbData, dataOut.cbData);
    LocalFree(dataOut.pbData);
}

void EphemeralKeyStorage::ClearKey() {
    CleanupHandler();
}