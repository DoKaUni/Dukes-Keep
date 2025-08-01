#include "sections.h"
#include "generation.h"

void RandomizeStringSections(std::vector<PasswordSection>& sections, const unsigned char* key, const unsigned char* iv) {
    // Use 4 bytes (32 bits) for each random value to shuffle
    const int outputLength = 4;  
    std::vector<unsigned char> randomBytes(outputLength);

    // Generate a random value for each section to use as the seed for shuffling
    for (size_t i = 0; i < sections.size(); ++i) {
        GenerateRandomBytesWithIV(key, iv, randomBytes.data(), outputLength);

        // Use the generated bytes as a seed for shuffling
        unsigned int randomValue = 0;
        for (int j = 0; j < outputLength; ++j) {
            randomValue = (randomValue << 8) | randomBytes[j];
        }

        std::random_device rd;
        std::seed_seq seed{randomValue, rd()};  // Combine the AES-derived value and a system RNG
        std::default_random_engine engine(seed);

        std::shuffle(sections.begin(), sections.end(), engine);
    }
}


// Function to split a string into sections
std::vector<PasswordSection> SplitString(const std::string& str, const std::vector<int>& indexes, int sectionLength, const bool *sectionState) {
    std::vector<PasswordSection> PasswordSections;
    int length = str.length();
    int sections = length / sectionLength;

    for (int i = 0; i < sections; i++) {
        PasswordSection currentSection(str.substr(i * sectionLength, sectionLength), i);
            
        if(std::find(std::begin(indexes), std::end(indexes), i) != std::end(indexes))
            currentSection.SetIsFake(*sectionState);
        else
            currentSection.SetIsFake(!*sectionState);

        PasswordSections.push_back(currentSection);
    }

    return PasswordSections;
}