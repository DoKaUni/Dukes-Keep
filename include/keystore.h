#pragma once

#include <iostream>
#include <windows.h>
#include <algorithm>
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
     * @param lockedBuffer A buffer that will store the retrieved key.
     * @param bufferSize The size of the buffer.
     * 
     * @throws std::runtime_error If no key is stored, if the decryption operation fails or the data is decrypted data is too large for the buffer.
     */
    static void RetrieveKey(unsigned char* lockedBuffer, size_t bufferSize);

    /**
     * Securely clears the stored encryption key from memory by zeroing out the storage.
     */
    static void ClearKey();
};

struct VirtualLockDeleter {
    void operator()(void* ptr) const {
        if (ptr) {
            SecureZeroMemory(ptr, size);
            VirtualUnlock(ptr, size);
            VirtualFree(ptr, 0, MEM_RELEASE);
        }
    }
    size_t size;
};

/**
 * Creates and locks a unique_ptr of the given data type and size using Windows' memory API.
 *
 * @param numElements The number of elements of type `T` to allocate memory for. The total allocated size will be `numElements * sizeof(T)`.
 *
 * @return allocated and locked unique_ptr of the given data type and size.
 *
 * @throws std::runtime_error If `VirtualAlloc` or `VirtualLock` fails.
 */
template <typename T>
std::unique_ptr<T[], VirtualLockDeleter> AllocateLockedMemory(size_t numElements) {
    const size_t bufferSize = numElements * sizeof(T);

    // Allocate memory
    void* buffer = VirtualAlloc(nullptr, bufferSize, MEM_COMMIT, PAGE_READWRITE);
    if (!buffer) {
        throw std::runtime_error("VirtualAlloc failed");
    }

    // Lock memory
    if (!VirtualLock(buffer, bufferSize)) {
        VirtualFree(buffer, 0, MEM_RELEASE);
        throw std::runtime_error("VirtualLock failed");
    }

    // Return as unique_ptr with custom deleter
    return std::unique_ptr<T[], VirtualLockDeleter>(
        static_cast<T*>(buffer),
        VirtualLockDeleter{bufferSize}
    );
}