#pragma once

#include <iostream>
#include <chrono>
#include <algorithm>
#include <string>
#include <random>
#include <vector>
#include <iterator>
#include <chrono>
#include <thread>

class PasswordSection {
private:
    std::string section;
    bool isFake;
    int index;
    
public:
    PasswordSection(std::string section, int givenIndex)
        : section(section), isFake(false), index(givenIndex) {}
    
    int* GetIndex() { return &index; }
    bool* GetIsFake() { return &isFake; }
    std::string& GetStringSection() { return section; }
    void SetIsFake(bool sectionState) { isFake = sectionState; }
};
    
/**
 * Randomizes the order of password sections based on random bytes generated with AES-CTR.
 * 
 * @param sections The vector of PasswordSection objects to randomize.
 * @param key The key used to generate a secure random seed.
 * @param iv The initialization vector (IV) used in combination with the key for random generation.
 */
void RandomizeStringSections(std::vector<PasswordSection>& sections, const unsigned char* key, const unsigned char* iv);

/**
 * Splits a string into sections and assigns a state (fake or not) to each section.
 * 
 * @param str The string to split into sections.
 * @param indexes The list of indexes that should be marked, based on the section state.
 * @param sectionLength The length of each section.
 * @param sectionState Pointer to a boolean that determines if sections should be marked as fake or not.
 * @return A vector of PasswordSection objects representing the split sections of the input string.
 */
std::vector<PasswordSection> SplitString(const std::string& str, const std::vector<int>& indexes, const int sectionLength, const bool *sectionState);

