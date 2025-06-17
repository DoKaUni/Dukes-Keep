#pragma once

#include <iostream>
#include <windows.h>
#include <dpapi.h>
#include <vector>
#include <string>
#include <stdexcept>
#include <mutex>
#include <memory>
#include <cstdio>

class EphemeralKeyStorage {
private:
    static std::vector<unsigned char> encryptedKey;
    static std::vector<unsigned char> entropy;
    static std::mutex mutex;
    static bool initialized;

    EphemeralKeyStorage() = delete;
    static void Initialize();
    static void CleanupHandler();

public:
    /**
     * Stores an encryption key securely in memory after encrypting it with Windows DPAPI.
     * 
     * @param key The key to be stored, provided as a vector of unsigned characters.
     * 
     * @throws std::runtime_error If the encryption operation fails.
     */
    static void StoreKey(const std::vector<unsigned char>& key);

    /**
     * Retrieves the stored encryption key by decrypting it using Windows DPAPI.
     * 
     * @return The decrypted key as a vector of unsigned characters.
     * 
     * @throws std::runtime_error If no key is stored or if the decryption operation fails.
     */
    static std::vector<unsigned char> RetrieveKey();

    /**
     * Securely clears the stored encryption key from memory by zeroing out the storage.
     */
    static void ClearKey();
};