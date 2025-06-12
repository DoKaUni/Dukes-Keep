#pragma once

#include "sections.h"

#include <stdio.h>
#include <windows.h>
#include <atomic>

/**
 * Sets the specified text to the Windows clipboard.
 * 
 * @param text The string to be copied to the clipboard.
 * @return True if the text was successfully set to the clipboard, False otherwise.
 */
bool SetClipboardText(const std::string& text);

/**
 * Simulates pressing and releasing a keyboard key.
 * 
 * @param keyCode The key code of the key to be pressed.
 * @param isExtendedKey Flag indicating whether the key is an extended key.
 * @param amount The number of times the key should be pressed.
 */
void KeyPress(WORD keyCode, bool isExtendedKey, int amount);

/**
 * Simulates the Ctrl + V keypress to paste the clipboard contents.
 * 
 * @param sleepTime The delay in milliseconds before clearing the clipboard.
 */
void ClipboardPaste(const int sleepTime);

/**
 * Pastes password sections in the original order, simulating key presses for navigation.
 * 
 * @param sections The vector of password sections to paste.
 * @param sectionLength The length of each password section.
 * @param sleepTime The time to wait between keypresses and clipboard operations.
 */
void PasteSections(std::vector<PasswordSection>& sections, const int sectionLength, const int sleepTime);