#pragma once

#include <iostream>
#include <fstream>
#include <vector>
#include <cstring>
#include <filesystem>

#define KEY_SIZE 32 // 256-bit key
#define IV_SIZE 16 // 128-bit IV
#define SALT_SIZE 8
#define ITERATIONS 1000000 // Potentially change to 10 000 000

/**
 * Reads the contents of a file and stores it in a vector of unsigned chars.
 * 
 * @param filename The path to the file to read.
 * @param outData A reference to a vector that will hold the file's data.
 * @return True if the file was read successfully; False if there was an error opening the file.
 */
bool ReadFile(const std::string& filename, std::vector<unsigned char>& outData);

/**
 * Writes data from a vector of unsigned chars to a file.
 * 
 * @param filename The path to the file to write.
 * @param data A vector of unsigned chars containing the data to write to the file.
 * @return True if the data was written successfully; false if there was an error opening or writing to the file.
 */
bool WriteFile(const std::string& filename, const std::vector<unsigned char>& data);

/**
 * Derives a cryptographic key from a password and salt using PBKDF2-HMAC.
 * 
 * @param password The password to derive the key from.
 * @param salt A pointer to the salt used for the key derivation.
 * @param outKey A buffer that will store the derived key.
 * @return True if the key was successfully derived; false if an error occurred.
 */
bool DerivePasswordKey(const std::string& password, const unsigned char* salt, unsigned char* outKey);

/**
 * Encrypts data using AES-256-CBC encryption with a provided key and an optional salt.
 * 
 * @param data A vector of unsigned chars representing the data to encrypt.
 * @param key A buffer storing the encryption key.
 * @param salt A pointer to the salt to use (can be nullptr).
 * @param outEncryptedData A reference to a vector that will hold the encrypted data, including the header, salt, IV, and ciphertext.
 * @return True if the data was successfully encrypted; false if an error occurred.
 */
bool EncryptData(const std::vector<unsigned char>& data, const unsigned char* key, const unsigned char* salt, std::vector<unsigned char>& outEncryptedData);

 /**
 * Decrypts encrypted data using AES-256-CBC decryption with the provided key.
 *
 * @param encryptedData A vector of unsigned chars representing the encrypted data (including header, salt, IV, and ciphertext).
 * @param key A buffer storing the encryption key.
 * @param outDecryptedData A pointer to a locked buffer where the decrypted data will be written.
 * @param outDecryptedSize A reference to a size_t that will hold the size of the decrypted data.
 *
 * @return True if the data was successfully decrypted; false if an error occurred or the data format is invalid.
 */
bool DecryptData(const std::vector<unsigned char>& encryptedData, const unsigned char* key, unsigned char* outDecryptedData, size_t& outDecryptedSize);

/**
 * Converts a string to a vector of unsigned chars.
 * 
 * @param str The string to convert.
 * @return A vector of unsigned chars containing the bytes of the string.
 */
std::vector<unsigned char> StringToVector(const std::string& str);

/**
 * Copies and converts a vector of unsigned chars to the given char buffer.
 * 
 * @param vec The vector of unsigned chars to convert.
 * @param buffer the char buffer to copy and convert to.
 * @param bufferSize size of the buffer.
 * 
 * @throw std::runtime_error if the size of the vector is bigger than the given `bufferSize`.
 */
void VectorToBuffer(const std::vector<unsigned char>& vec, char* buffer, size_t bufferSize);