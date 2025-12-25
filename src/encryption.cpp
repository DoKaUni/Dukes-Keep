#include "encryption.h"
#include "generation.h"

bool ReadFile(const std::string& filename, std::vector<unsigned char>& outData) {
    std::ifstream inFile(filename, std::ios::binary);

    if (!inFile) {
        std::cerr << "Error opening file for reading: " << filename << std::endl;

        return false;
    }

    outData.assign((std::istreambuf_iterator<char>(inFile)), std::istreambuf_iterator<char>());

    return true;
}

bool WriteFile(const std::string& filename, const std::vector<unsigned char>& data) {
    std::ofstream outFile(filename, std::ios::binary);

    if (!outFile) {
        std::cerr << "Error opening file for writing: " << filename << std::endl;
        
        return false;
    }
    
    outFile.write(reinterpret_cast<const char*>(data.data()), data.size());

    return outFile.good();
}

bool DerivePasswordKey(const std::string& password, const unsigned char* salt,  unsigned char* outKey) {
    if (PKCS5_PBKDF2_HMAC(password.c_str(), password.length(), salt, SALT_SIZE, ITERATIONS, EVP_sha256(), KEY_SIZE, outKey) != 1) {
        handleErrors();

        return false;
    }

    return true;
}

bool EncryptData(const std::vector<unsigned char>& data, const unsigned char* key, const unsigned char* salt, std::vector<unsigned char>& outEncryptedData) {
    std::vector<unsigned char> iv(EVP_MAX_IV_LENGTH);
    if (RAND_bytes(iv.data(), EVP_MAX_IV_LENGTH) != 1) {
        handleErrors();
        return false;
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        handleErrors();
        return false;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv.data()) != 1) {
        handleErrors();
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    std::vector<unsigned char> ciphertext(data.size() + EVP_MAX_BLOCK_LENGTH);
    int length, ciphertextLength;

    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &length, data.data(), data.size()) != 1) {
        handleErrors();
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    ciphertextLength = length;

    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + length, &length) != 1) {
        handleErrors();
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    ciphertextLength += length;
    ciphertext.resize(ciphertextLength);
    EVP_CIPHER_CTX_free(ctx);


    // Combine header, salt (if provided), IV, and ciphertext
    outEncryptedData.clear();
    unsigned char header = salt ? 0x01 : 0x00;
    outEncryptedData.push_back(header);

    if (salt)
        outEncryptedData.insert(outEncryptedData.end(), salt, salt + SALT_SIZE);

    outEncryptedData.insert(outEncryptedData.end(), iv.begin(), iv.end());
    outEncryptedData.insert(outEncryptedData.end(), ciphertext.begin(), ciphertext.end());

    return true;
}

bool DecryptData(const std::vector<unsigned char>& encryptedData, const unsigned char* key, unsigned char* outDecryptedData, size_t& outDecryptedSize) {
    if (encryptedData.size() < 1 + EVP_MAX_IV_LENGTH) {
        std::cerr << "Invalid encrypted data format." << std::endl;

        return false;
    }

    bool hasSalt = (encryptedData[0] == 0x01);

    // Calculate offsets
    size_t saltOffset = 1;
    size_t ivOffset = saltOffset + (hasSalt ? SALT_SIZE : 0);
    size_t ciphertextOffset = ivOffset + EVP_MAX_IV_LENGTH;

    // Extract IV
    std::vector<unsigned char> iv(EVP_MAX_IV_LENGTH);
    std::copy(encryptedData.begin() + ivOffset, encryptedData.begin() + ivOffset + EVP_MAX_IV_LENGTH, iv.begin());

    // Extract ciphertext
    std::vector<unsigned char> ciphertext(encryptedData.begin() + ciphertextOffset, encryptedData.end());

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        handleErrors();
        return false;
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv.data()) != 1) {
        handleErrors();
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    int length, plaintextLength;

    if (EVP_DecryptUpdate(ctx, outDecryptedData, &length, ciphertext.data(), ciphertext.size()) != 1) {
        handleErrors();
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    plaintextLength = length;

    if (EVP_DecryptFinal_ex(ctx, outDecryptedData + length, &length) != 1) {
        handleErrors();
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    plaintextLength += length;

    outDecryptedSize = plaintextLength;
    EVP_CIPHER_CTX_free(ctx);

    return true;
}

std::vector<unsigned char> StringToVector(const std::string& str) {
    return std::vector<unsigned char>(str.begin(), str.end());
}

void VectorToBuffer(const std::vector<unsigned char>& vec, char* buffer, size_t bufferSize) {
    if (vec.size() > bufferSize - 1) {
        throw std::runtime_error("Decrypted data too large for buffer");
    }
    
    std::copy(vec.begin(), vec.end(), reinterpret_cast<unsigned char*>(buffer));
    buffer[vec.size()] = '\0';
}