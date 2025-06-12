#include "pasting.h"

bool SetClipboardText(const std::string& text) {
    if (!OpenClipboard(nullptr)) {
        return false;
    }

    EmptyClipboard();

    int textLength = static_cast<int>(text.length());
    HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, (textLength + 1) * sizeof(char));  

    if (!hMem) {
        CloseClipboard();
        return false;  
    }

    char* memPtr = static_cast<char*>(GlobalLock(hMem));
    if (!memPtr) {
        GlobalFree(hMem);
        CloseClipboard();
        return false;
    }

    strncpy_s(memPtr, textLength + 1, text.c_str(), textLength);

    // Ensure null-termination
    memPtr[textLength] = '\0'; 
    GlobalUnlock(hMem);

    if (!SetClipboardData(CF_TEXT, hMem)) {
        GlobalFree(hMem);
        CloseClipboard();
        return false;
    }

    CloseClipboard();
    return true;
}

void PasteSections(std::vector<PasswordSection>& sections, const int sectionLength, const int sleepTime){
    int sectionsAmount = sections.size();
    std::vector<int> PastedSections;
    int currentPosition = 0;
    int newPosition, distance;
    int currentSection;
    int j;

    while(sectionsAmount > 0){
        currentSection = *sections[0].GetIndex();

        if(*sections[0].GetIsFake()){
            SetClipboardText(sections[0].GetStringSection());

            if (!OpenClipboard(nullptr)) {
                EmptyClipboard();

                std::this_thread::sleep_for(std::chrono::milliseconds(sleepTime));

                ClipboardPaste(sleepTime);
            }

            sections.erase(sections.begin());
            sectionsAmount--;

            continue;
        }

        // Perform binary search to find the insertion point
        auto iterator = std::lower_bound(PastedSections.begin(), PastedSections.end(), currentSection, 
                                   [](int a, int b) { return a < b; });

        j = std::distance(PastedSections.begin(), iterator);

        newPosition = j * sectionLength;

        if(currentPosition != newPosition)
            distance = abs(currentPosition - newPosition);

        if(currentPosition > newPosition){       
            KeyPress(0x4B, true, distance);
            currentPosition -= distance;
        }
        else if(currentPosition < newPosition){
            KeyPress(0x4D, true, distance);
            currentPosition += distance;
        }

        SetClipboardText(sections[0].GetStringSection());
        std::this_thread::sleep_for(std::chrono::milliseconds(sleepTime));
        ClipboardPaste(sleepTime);

        PastedSections.insert(PastedSections.begin() + j, currentSection);

        currentPosition += sectionLength;
        
        sections.erase(sections.begin());
        sectionsAmount--;
    }
}

void KeyPress(WORD keyCode, bool isExtendedKey, int amount){
    int inputAmount = amount * 2;
    INPUT *input = new INPUT[inputAmount];

    for(int i = 0; i < inputAmount; i++){
        input[i].type = INPUT_KEYBOARD;
        input[i].ki.wScan = keyCode;
        input[i].ki.dwFlags = KEYEVENTF_SCANCODE;

        if(isExtendedKey)
            input[i].ki.dwFlags |= KEYEVENTF_EXTENDEDKEY;

        if(i % 2 != 0)
            input[i].ki.dwFlags |= KEYEVENTF_KEYUP;
    }

    SendInput(inputAmount, input, sizeof(INPUT));

    delete[] input;
}

void ClipboardPaste(const int sleepTime) {
    INPUT input[4] = {};

    input[0].type = INPUT_KEYBOARD;
    input[0].ki.wVk = VK_CONTROL;

    input[1].type = INPUT_KEYBOARD;
    input[1].ki.wVk = 'V';

    input[2].type = INPUT_KEYBOARD;
    input[2].ki.wVk = 'V';
    input[2].ki.dwFlags = KEYEVENTF_KEYUP;

    input[3].type = INPUT_KEYBOARD;
    input[3].ki.wVk = VK_CONTROL;
    input[3].ki.dwFlags = KEYEVENTF_KEYUP;

    SendInput(4, input, sizeof(INPUT));

    std::this_thread::sleep_for(std::chrono::milliseconds(sleepTime));

    EmptyClipboard();
}