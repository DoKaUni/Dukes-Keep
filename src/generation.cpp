#include "generation.h"

void handleErrors() {
    char errorBuffer[512];
    ERR_error_string_n(ERR_get_error(), errorBuffer, sizeof(errorBuffer));
    std::cerr << "LibreSSL error: " << errorBuffer << std::endl;
}

bool GenerateRandomBytes(unsigned char* buffer, int length) {
    if (RAND_bytes(buffer, length) != 1) {
        std::cerr << "Error generating random bytes." << std::endl;

        handleErrors();
        
        return false;
    }

    return true;
}

bool SaveSeedAndIV(const std::string& seedPath, const unsigned char* seed, int seedLength, const unsigned char* fixedIV, int ivLength) {
    std::ofstream file(seedPath, std::ios::binary);

    if (!file) {
        std::cerr << "Error opening seed file for writing: " << seedPath << std::endl;
        
        return false;
    }

    file.write(reinterpret_cast<const char*>(seed), seedLength);
    file.write(reinterpret_cast<const char*>(fixedIV), ivLength);

    return true;
}

void LoadSeedAndIV(const std::string& seedPath, unsigned char* seed, int seedLength, unsigned char* fixedIV, int ivLength) {
        std::ifstream file(seedPath, std::ios::binary);
    
    if (!file) {
        std::cerr << "Seed file not found. Generating a new seed and fixed IV." << std::endl;
        GenerateRandomBytes(seed, seedLength);
        GenerateRandomBytes(fixedIV, ivLength);
        SaveSeedAndIV(seedPath, seed, seedLength, fixedIV, ivLength);
    } else {
        file.read(reinterpret_cast<char*>(seed), seedLength);
        file.read(reinterpret_cast<char*>(fixedIV), ivLength);
    }
}

bool DeriveKey(const unsigned char* seed, int seedLength, const std::string& input, unsigned char* key) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        std::cerr << "Error creating EVP context." << std::endl;
        
        handleErrors();

        return false;
    }

    // Use SHA-256 to derive the key
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1) {
        std::cerr << "Error initializing SHA-256." << std::endl;

        handleErrors();
        EVP_MD_CTX_free(ctx);
        
        return false;
    }

    // Hash the seed and input together
    if (EVP_DigestUpdate(ctx, seed, seedLength) != 1) {
        std::cerr << "Error updating hash with seed." << std::endl;

        handleErrors();
        EVP_MD_CTX_free(ctx);

        return false;
    }

    if (EVP_DigestUpdate(ctx, input.c_str(), input.length()) != 1) {
        std::cerr << "Error updating hash with input." << std::endl;

        handleErrors();
        EVP_MD_CTX_free(ctx);

        return false;
    }

    // Finalize the hash
    unsigned int hashLength;
    if (EVP_DigestFinal_ex(ctx, key, &hashLength) != 1) {
        std::cerr << "Error finalizing hash." << std::endl;

        handleErrors();
        EVP_MD_CTX_free(ctx);

        return false;
    }

    // Clean up
    EVP_MD_CTX_free(ctx);

    return true;
}

bool GenerateRandomBytesWithIV(const unsigned char* key, const unsigned char* iv, unsigned char* output, int outputLength) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        std::cerr << "Error creating EVP context." << std::endl;
        
        handleErrors();

        return false;
    }

    // Initialize AES-CTR with the key and IV
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), nullptr, key, iv) != 1) {
        std::cerr << "Error initializing AES-CTR." << std::endl;

        handleErrors();
        EVP_CIPHER_CTX_free(ctx);
        
        return false;
    }

    // Generate random bytes
    int len;
    unsigned char* zeroInput = new unsigned char[outputLength]();
    if (EVP_EncryptUpdate(ctx, output, &len, zeroInput, outputLength) != 1) {
        std::cerr << "Error generating random bytes." << std::endl;

        handleErrors();
        delete[] zeroInput; // Clean up
        EVP_CIPHER_CTX_free(ctx);
        
        return false;
    }

    // Clean up
    delete[] zeroInput;
    EVP_CIPHER_CTX_free(ctx);

    return true;
}

std::string GenerateRandomString(int outputLength, const std::string& characterSet) {
    std::string randomString;
    for (int i = 0; i < outputLength; ++i) {
    unsigned char randomByte;
    do {
        if (RAND_bytes(&randomByte, 1) != 1) {
            std::cerr << "Error generating random bytes." << std::endl;
            
            handleErrors();

            return "";
        }
    } while (randomByte >= (256 / characterSet.length()) * characterSet.length());
    randomString += characterSet[randomByte % characterSet.length()];
    }

    return randomString;
}

bool GenerateRandomBoolean(const unsigned char* key, const unsigned char* fixedIV) {
    const int outputLength = 1;
    unsigned char randomByte;

    // Generate random bytes using AES-CTR
    GenerateRandomBytesWithIV(key, fixedIV, &randomByte, outputLength);

    // Use the least significant bit to determine the boolean value
    return (randomByte & 0x01) == 1;
}

std::vector<int> GenerateRandomIndexes(int count, int maxIndex, const unsigned char* key, const unsigned char* IV) {
    std::vector<int> indexes;
    indexes.reserve(count);

    for (int i = 0; i < count; ++i) {
        indexes.push_back(i);
    }

    for (int i = count; i < maxIndex; ++i) {
        unsigned char randomByte;
        GenerateRandomBytesWithIV(key, IV, &randomByte, 1);
        int j = randomByte % (i + 1);
        if (j < count) {
            indexes[j] = i;
        }
    }

    return indexes;
}