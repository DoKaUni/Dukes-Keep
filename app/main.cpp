// Executables must have the following defined if the library contains
// doctest definitions. For builds with this disabled, e.g. code shipped to
// users, this can be left out.
#ifdef ENABLE_DOCTEST_IN_LIBRARY
#define DOCTEST_CONFIG_IMPLEMENT
#include "doctest/doctest.h"
#endif

#include "config.h"
#include "database.h"
#include "encryption.h"
#include "fileUtils.h"
#include "generation.h"
#include "initialization.h"
#include "keystore.h"
#include "pasting.h"
#include "sections.h"

#include <iostream>
#include <stdlib.h>
#include <locale>
#include <codecvt>
#include <regex>

static bool showReplaceEntryWindow = false;
PasswordEntry* currentPassword = nullptr;

struct ManagerTab {
    std::string name;
    bool isOpen = true;
    bool canClose = true;
    bool showTagFilter = false;
    bool showDeletedOnly = false;
    std::vector<int> filterTags;
    int selectedItem = -1;
};

struct PasswordDetailWindow {
    bool isOpen = true;
    PasswordEntry* entry;
};

struct PasswordEntryWindowState {
    PasswordEntry* ReplacedEntry = nullptr;
    char nameBuffer[65] = "";
    char usernameBuffer[65] = "";
    int passwordLengthIndex = 0;
    std::vector<char> selectedTags;
    std::vector<bool> selectedCharacterSets;
    bool initializedTags = false;
    bool shouldOpen = false;
    bool result = false;

    void Reset() {
        nameBuffer[0] = '\0';
        usernameBuffer[0] = '\0';
        passwordLengthIndex = 0;
        selectedTags.clear();
        selectedCharacterSets.clear();
        initializedTags = false;
        result = false;
    }

    void Initialize(const std::vector<Tag>& allTags, const std::string* initialName = nullptr, const std::string* initialUsername = nullptr, const std::vector<std::string>* initialTags = nullptr) { 
        if (initialName) {
            strncpy(nameBuffer, initialName->c_str(), sizeof(nameBuffer) - 1);
            nameBuffer[sizeof(nameBuffer) - 1] = '\0';
        }

        if (initialUsername) {
            strncpy(usernameBuffer, initialUsername->c_str(), sizeof(usernameBuffer) - 1);
            usernameBuffer[sizeof(usernameBuffer) - 1] = '\0';
        }

        if (selectedCharacterSets.size() != std::size(characterSets))
            selectedCharacterSets.resize(std::size(characterSets), false);

        selectedTags.resize(allTags.size(), false);

        if (initialTags) {
            size_t i = 0;
            for (const auto& tag : allTags) {
                selectedTags[i] = std::find(initialTags->begin(), initialTags->end(), tag.GetName()) != initialTags->end();
                i++;
            }
        }

        if(showReplaceEntryWindow)
            ReplacedEntry = currentPassword;

        initializedTags = true;
    }
};

std::vector<PasswordDetailWindow> openPasswordWindows;
std::vector<PasswordEntry> passwords;
std::vector<ManagerTab> managerTabs;
static PasswordEntryWindowState entryWindowState;
static std::vector<Tag> allTags;
static std::vector<char> selectedTags;
static bool showEntryWindow = false;
static bool showSettingsWindow = false;
static bool showTagManagerWindow = false;
static bool showTagFilterWindow = false;
static ManagerTab* currentTabForNewEntry = nullptr;

std::atomic<bool> startPollingThread(false);
std::thread keyMonitorThread;

static int pasteTime{};
static int listenTime{};
static int showPasswordTime{};
static int shortcutKey{};
static int sectionLength{};
static std::string shortcutKeyName{};
static bool capturingKey = false;

static std::vector<unsigned char> key;
static std::string settingsFile{};
static std::string seedPath{};
static const float windowScale = 1.5f;
static bool capsLock = false;
static bool showOnScreenKeyboard = false;
static std::vector<std::vector<std::string>> keyboardLayout = {
    {"Caps", "1", "2", "3", "4", "5", "6", "7", "8", "9", "0", "-", "=", "Backspace"},
    {"q", "w", "e", "r", "t", "y", "u", "i", "o", "p", "[", "]", "\\"},
    {"a", "s", "d", "f", "g", "h", "j", "k", "l", ";", "'"},
    {"z", "x", "c", "v", "b", "n", "m", ",", ".", "/"},
};

const int defaultPasteTime = 20;
const int defaultListenTime = 5;
const int defaultShowPasswordTime = 10;
const int defaultShortcutKey = 0xDC; // '\' key
const int defaultSectionLength = 4;

// Initialization & Setup Functions
static std::string WStringToString(const std::wstring& wstr);
static void InitializeDefaultTabs();
static void LoadSettings();
static void SaveSettings(int pasteTime, int listenTime, int showPasswordTime, int shortcutKey, int sectionLength);
static void SettingsCheck(int& pasteTime, int& listenTime, int& showPasswordTime, int& shortcutKey, int& sectionLength);
static std::string GetKeyName(int vkCode);

// Authentication Functions
static bool HandleLogin(const std::string& keyFile, const std::string& dbFile, sqlite3*& db, const std::string& passwordInput, const bool firstRun, bool& wrongPassword);
static void Authentication(ImGuiIO& io, const std::string& keyFile, const std::string& dbFile, sqlite3*& db, const bool firstRun, bool& result);

// Management Functions
static void SavePassword(sqlite3* db);
static std::string DecryptPassword();
static void monitorKeyPress();
static bool CheckCharBuffer(const char buffer[], const bool canBeEmpty);
static void HandleKeyPress(char* buffer, int& cursorPos, const std::string& keyboardKey);
static bool ShowPasswordEntryWindow(const char* windowTitle, sqlite3* db, std::vector<PasswordEntry>& passwords);
static bool ShouldSkipEntry(const PasswordEntry& entry, bool showDeletedOnly);
static bool HasAllRequiredTags(const std::vector<int>& filterTags, const std::vector<Tag>& entryTags);
static void FilterPasswords(const ManagerTab& tab, sqlite3* db, std::vector<PasswordEntry>& passwords, std::vector<PasswordEntry*>& filteredPasswords);
static bool IsPasswordWindowOpen(int entryId);

// UI Rendering Functions
static void ShowConfirmationDialog(const char* title, const char* message, std::shared_ptr<bool> answer);
static void RenderManagerTab(ManagerTab& tab, sqlite3* db);
static void RenderTagManagerWindow(sqlite3* db);
static void RenderTagFilterWindow(ManagerTab& tab, sqlite3* db);
static void RenderSettingsWindow();
static void RenderOnScreenKeyboard(char* passwordInput, int& cursorPos);
static void RenderPasswordWindow(PasswordDetailWindow* window);
static void RenderMainUI(sqlite3* db, const int windowWidth, const int windowHeight);

// Utility functions
static int InputTextCallback(ImGuiInputTextCallbackData* data);
static bool CheckPositiveInt(const int integer);
static bool IsPrintableVirtualKey(UINT vkCode);

int main(int, char**) {
    sqlite3* db;

    std::cout << "Duke's Keep: "<< PROJECT_VERSION_MAJOR << "."<< PROJECT_VERSION_MINOR << "." << PROJECT_VERSION_PATCH << "." << PROJECT_VERSION_TWEAK << std::endl;

    std::wstring appDataLocalPath = GetAppDataLocalPath();
    if (appDataLocalPath.empty()) {
        std::wcerr << L"Failed to retrieve AppData Local Path." << std::endl;
        return 1;
    }

    std::wstring appPath = GetAppPath(appDataLocalPath);
    if (appPath.empty()) {
        std::wcerr << L"Failed to get or create the program's AppData Local directory." << std::endl;
        return 1;
    }

    // Convert appPath to std::string for file operations
    std::string convertedAppPath = WStringToString(appPath);

    // Construct file paths using the narrow (std::string) appPath
    std::string keyFile = convertedAppPath + "\\encryption_key.bin";
    std::string dbFile = convertedAppPath + "\\test_encrypted.db";
    settingsFile = convertedAppPath + "\\settings.ini";
    seedPath = convertedAppPath + "\\seed.bin";

    OpenSSL_add_all_algorithms(); 
    ERR_load_crypto_strings();

    bool authenticated = false;
    bool firstRun = !std::filesystem::exists(keyFile) && !std::filesystem::exists(dbFile);

    // Setup SDL
    if (SDL_Init(SDL_INIT_VIDEO | SDL_INIT_TIMER | SDL_INIT_GAMECONTROLLER) != 0)
    {
        printf("Error: %s\n", SDL_GetError());
        return -1;
    }

    // From 2.0.18: Enable native IME.
#ifdef SDL_HINT_IME_SHOW_UI
    SDL_SetHint(SDL_HINT_IME_SHOW_UI, "1");
#endif

    SDL_DisplayMode displayMode;
    if (SDL_GetCurrentDisplayMode(0, &displayMode) != 0) {
        SDL_Log("Could not get display mode: %s", SDL_GetError());
        displayMode.w = 1280;
        displayMode.h = 720;
    }

    int windowWidth = static_cast<int>(displayMode.w / windowScale);
    int windowHeight = static_cast<int>(displayMode.h / windowScale);

    // Create window with Vulkan graphics context
    SDL_WindowFlags window_flags = (SDL_WindowFlags)(SDL_WINDOW_VULKAN | SDL_WINDOW_RESIZABLE | SDL_WINDOW_ALLOW_HIGHDPI);
    SDL_Window* window = SDL_CreateWindow("Duke's Keep", SDL_WINDOWPOS_CENTERED, SDL_WINDOWPOS_CENTERED, windowWidth, windowHeight, window_flags);
    if (window == nullptr) {
        printf("Error: SDL_CreateWindow(): %s\n", SDL_GetError());
        return -1;
    }

    ImVector<const char*> extensions;
    uint32_t extensions_count = 0;
    SDL_Vulkan_GetInstanceExtensions(window, &extensions_count, nullptr);
    extensions.resize(extensions_count);
    SDL_Vulkan_GetInstanceExtensions(window, &extensions_count, extensions.Data);
    SetupVulkan(extensions);

    // Create Window Surface
    VkSurfaceKHR surface;
    VkResult err;
    if (SDL_Vulkan_CreateSurface(window, g_Instance, &surface) == 0)
    {
        printf("Failed to create Vulkan surface.\n");
        return 1;
    }

    // Create Framebuffers
    int w, h;
    SDL_GetWindowSize(window, &w, &h);
    ImGui_ImplVulkanH_Window* wd = &g_MainWindowData;
    SetupVulkanWindow(wd, surface, w, h);

    // Setup Dear ImGui context
    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO(); (void)io;
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;     // Enable Keyboard Controls
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableGamepad;      // Enable Gamepad Controls
    io.ConfigFlags |= ImGuiConfigFlags_DockingEnable;         // Enable Docking
    io.ConfigFlags |= ImGuiConfigFlags_ViewportsEnable;       // Enable Multi-Viewport / Platform Windows

    // Setup Dear ImGui style
    ImGui::StyleColorsDark();

    // When viewports are enabled we tweak WindowRounding/WindowBg so platform windows can look identical to regular ones.
    ImGuiStyle& style = ImGui::GetStyle();
    if (io.ConfigFlags & ImGuiConfigFlags_ViewportsEnable)
    {
        style.WindowRounding = 0.0f;
        style.Colors[ImGuiCol_WindowBg].w = 1.0f;
    }

    // Setup Platform/Renderer backends
    ImGui_ImplSDL2_InitForVulkan(window);
    ImGui_ImplVulkan_InitInfo init_info = {};
    init_info.Instance = g_Instance;
    init_info.PhysicalDevice = g_PhysicalDevice;
    init_info.Device = g_Device;
    init_info.QueueFamily = g_QueueFamily;
    init_info.Queue = g_Queue;
    init_info.PipelineCache = g_PipelineCache;
    init_info.DescriptorPool = g_DescriptorPool;
    init_info.RenderPass = wd->RenderPass;
    init_info.Subpass = 0;
    init_info.MinImageCount = g_MinImageCount;
    init_info.ImageCount = wd->ImageCount;
    init_info.MSAASamples = VK_SAMPLE_COUNT_1_BIT;
    init_info.Allocator = g_Allocator;
    init_info.CheckVkResultFn = check_vk_result;
    ImGui_ImplVulkan_Init(&init_info);

    // Our state
    ImVec4 clear_color = ImVec4(0.45f, 0.55f, 0.60f, 1.00f);

    // Main loop
    bool done = false;

    while (!done) {
        SDL_Event event;
        while (SDL_PollEvent(&event)) {
            ImGui_ImplSDL2_ProcessEvent(&event);
            if (event.type == SDL_QUIT) done = true;
            if (event.type == SDL_WINDOWEVENT && event.window.event == SDL_WINDOWEVENT_CLOSE && event.window.windowID == SDL_GetWindowID(window)) done = true;
        }
    
        if (g_SwapChainRebuild) {
            int width, height;
            SDL_GetWindowSize(window, &width, &height);
            if (width > 0 && height > 0) {
                ImGui_ImplVulkan_SetMinImageCount(g_MinImageCount);
                ImGui_ImplVulkanH_CreateOrResizeWindow(g_Instance, g_PhysicalDevice, g_Device, &g_MainWindowData, g_QueueFamily, g_Allocator, width, height, g_MinImageCount);
                g_MainWindowData.FrameIndex = 0;
                g_SwapChainRebuild = false;
            }
        }
    
        ImGui_ImplVulkan_NewFrame();
        ImGui_ImplSDL2_NewFrame();
        ImGui::NewFrame();
    
        if (!authenticated) {
            Authentication(io, keyFile, dbFile, db, firstRun, authenticated);
        }
        else {
            int sdlWidth, sdlHeight;
            SDL_GetWindowSize(window, &sdlWidth, &sdlHeight);

            RenderMainUI(db, sdlWidth, sdlHeight);
        }

        // Rendering
        ImGui::Render();
        ImDrawData* main_draw_data = ImGui::GetDrawData();
        const bool main_is_minimized = (main_draw_data->DisplaySize.x <= 0.0f || main_draw_data->DisplaySize.y <= 0.0f);
        wd->ClearValue.color.float32[0] = clear_color.x * clear_color.w;
        wd->ClearValue.color.float32[1] = clear_color.y * clear_color.w;
        wd->ClearValue.color.float32[2] = clear_color.z * clear_color.w;
        wd->ClearValue.color.float32[3] = clear_color.w;
        if (!main_is_minimized)
            FrameRender(wd, main_draw_data);

        // Update and Render additional Platform Windows
        if (io.ConfigFlags & ImGuiConfigFlags_ViewportsEnable) {
            ImGui::UpdatePlatformWindows();
            ImGui::RenderPlatformWindowsDefault();
        }

        // Present Main Platform Window
        if (!main_is_minimized)
            FramePresent(wd);
    }

    // If the thread was started, join it before exiting
    if (keyMonitorThread.joinable()) {
        keyMonitorThread.join();
    }

    // Cleanup
    sqlite3_close(db);
    std::cout << "Database closed successfully!" << std::endl;

    EphemeralKeyStorage::ClearKey();

    err = vkDeviceWaitIdle(g_Device);
    check_vk_result(err);
    ImGui_ImplVulkan_Shutdown();
    ImGui_ImplSDL2_Shutdown();
    ImGui::DestroyContext();

    CleanupVulkanWindow();
    CleanupVulkan();

    SDL_DestroyWindow(window);
    SDL_Quit();

    return 0;
}

/*
 * Utility
*/

static int InputTextCallback(ImGuiInputTextCallbackData* data) {
    if (data->EventChar >= 128) { // Non-ASCII character detected
        return 1;
    }
    return 0;
}

static bool CheckPositiveInt(const int integer) {
    if(integer > 0 && integer <= INT_MAX)
        return true;
    return false;
}

static bool IsPrintableVirtualKey(UINT vkCode) {
    BYTE keyboardState[256];
    GetKeyboardState(keyboardState);
    
    WORD asciiChar = 0;
    if (ToAscii(vkCode, MapVirtualKey(vkCode, MAPVK_VK_TO_VSC), keyboardState, &asciiChar, 0) == 1) {
        return isprint(asciiChar & 0xFF);
    }

    return false;
}

/*
 * Initialization & Setup Functions
*/

static std::string WStringToString(const std::wstring& wstr) {
    std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
    return converter.to_bytes(wstr);
}

static void InitializeDefaultTabs() {
    managerTabs.push_back(ManagerTab{"All Passwords", true, false, false, false, {}, -1});
    managerTabs.push_back(ManagerTab{"Deleted Passwords", true, false, false, true, {}, -1});
}

static void LoadSettings() {
    SettingsCheck(pasteTime, listenTime, showPasswordTime, shortcutKey, sectionLength);

    SaveSettings(pasteTime, listenTime, showPasswordTime, shortcutKey, sectionLength);
    
    // Update the key name display
    shortcutKeyName = GetKeyName(shortcutKey);
}

static void SaveSettings(int pasteTime, int listenTime, int showPasswordTime, int shortcutKey, int sectionLength) {
    std::filesystem::path path(settingsFile);
    if (!path.parent_path().empty()) {
        std::filesystem::create_directories(path.parent_path());
    }

    WritePrivateProfileStringA("Settings", "PasteTime", std::to_string(pasteTime).c_str(), settingsFile.c_str());
    WritePrivateProfileStringA("Settings", "ListenTime", std::to_string(listenTime).c_str(), settingsFile.c_str());
    WritePrivateProfileStringA("Settings", "ShowPasswordTime", std::to_string(showPasswordTime).c_str(), settingsFile.c_str());
    WritePrivateProfileStringA("Settings", "ShortcutKey", std::to_string(shortcutKey).c_str(), settingsFile.c_str());
    WritePrivateProfileStringA("Settings", "SectionLength", std::to_string(sectionLength).c_str(), settingsFile.c_str());
}

static void SettingsCheck(int& pasteTime, int& listenTime, int& showPasswordTime, int& shortcutKey, int& sectionLength) {
    int tempPasteTime = pasteTime;
    int tempListenTime = listenTime;
    int tempShowPasswordTime = showPasswordTime;
    int tempShortcutKey = shortcutKey;
    int tempSectionLength = sectionLength;
    
    // Read values from INI file
    tempPasteTime = GetPrivateProfileIntA("Settings", "PasteTime", tempPasteTime, settingsFile.c_str());
    tempListenTime = GetPrivateProfileIntA("Settings", "ListenTime", tempListenTime, settingsFile.c_str());
    tempShowPasswordTime = GetPrivateProfileIntA("Settings", "ShowPasswordTime", tempShowPasswordTime, settingsFile.c_str());
    tempShortcutKey = GetPrivateProfileIntA("Settings", "ShortcutKey", tempShortcutKey, settingsFile.c_str());
    tempSectionLength = GetPrivateProfileIntA("Settings", "SectionLength", tempSectionLength, settingsFile.c_str());
    
    // Validate pasteTime (must be positive integer)
    pasteTime = (tempPasteTime > 0 && tempPasteTime <= INT_MAX) ? tempPasteTime : defaultPasteTime;
    
    // Validate listenTime (must be positive integer)
    listenTime = (tempListenTime > 0 && tempListenTime <= INT_MAX) ? tempListenTime : defaultListenTime;

    // Validate listenTime (must be positive integer)
    showPasswordTime = (tempShowPasswordTime > 0 && tempShowPasswordTime <= INT_MAX) ? tempShowPasswordTime : defaultShowPasswordTime;
    
    // Validate shortcutKey (must be within valid virtual key code range)
    // Typical virtual key codes are between 0x01 and 0xFE
    shortcutKey = (tempShortcutKey >= 0x01 && tempShortcutKey <= 0xFE) ? tempShortcutKey : defaultShortcutKey;
    
    // Validate sectionLength (must be between 2 and 8)
    sectionLength = (tempSectionLength >= sectionLengths[0] && tempSectionLength <= sizeof(sectionLengths) - 1) ? tempSectionLength : defaultSectionLength;
}

static std::string GetKeyName(int vkCode) {
    if (vkCode == 0) return "None";

    // Special cases that GetKeyNameText doesn't handle well
    switch (vkCode) {
        case VK_LBUTTON: return "Left Mouse";
        case VK_RBUTTON: return "Right Mouse";
        case VK_MBUTTON: return "Middle Mouse";
        case VK_XBUTTON1: return "X1 Mouse";
        case VK_XBUTTON2: return "X2 Mouse";
        case VK_BACK: return "Backspace";
        case VK_TAB: return "Tab";
        case VK_RETURN: return "Enter";
        case VK_SHIFT: return "Shift";
        case VK_CONTROL: return "Ctrl";
        case VK_MENU: return "Alt";
        case VK_PAUSE: return "Pause";
        case VK_CAPITAL: return "Caps Lock";
        case VK_ESCAPE: return "Escape";
        case VK_SPACE: return "Space";
        case VK_PRIOR: return "Page Up";
        case VK_NEXT: return "Page Down";
        case VK_END: return "End";
        case VK_HOME: return "Home";
        case VK_LEFT: return "Left Arrow";
        case VK_UP: return "Up Arrow";
        case VK_RIGHT: return "Right Arrow";
        case VK_DOWN: return "Down Arrow";
        case VK_PRINT: return "Print Screen";
        case VK_SNAPSHOT: return "Print Screen";
        case VK_INSERT: return "Insert";
        case VK_DELETE: return "Delete";
        case VK_LWIN: return "Left Win";
        case VK_RWIN: return "Right Win";
        case VK_NUMPAD0: return "Num 0";
        case VK_NUMPAD1: return "Num 1";
        case VK_NUMPAD2: return "Num 2";
        case VK_NUMPAD3: return "Num 3";
        case VK_NUMPAD4: return "Num 4";
        case VK_NUMPAD5: return "Num 5";
        case VK_NUMPAD6: return "Num 6";
        case VK_NUMPAD7: return "Num 7";
        case VK_NUMPAD8: return "Num 8";
        case VK_NUMPAD9: return "Num 9";
        case VK_MULTIPLY: return "Num *";
        case VK_ADD: return "Num +";
        case VK_SEPARATOR: return "Num ,";
        case VK_SUBTRACT: return "Num -";
        case VK_DECIMAL: return "Num .";
        case VK_DIVIDE: return "Num /";
        case VK_F1: return "F1";
        case VK_F2: return "F2";
        case VK_F3: return "F3";
        case VK_F4: return "F4";
        case VK_F5: return "F5";
        case VK_F6: return "F6";
        case VK_F7: return "F7";
        case VK_F8: return "F8";
        case VK_F9: return "F9";
        case VK_F10: return "F10";
        case VK_F11: return "F11";
        case VK_F12: return "F12";
        case VK_NUMLOCK: return "Num Lock";
        case VK_SCROLL: return "Scroll Lock";
        case VK_OEM_1: return ";";
        case VK_OEM_PLUS: return "+";
        case VK_OEM_COMMA: return ",";
        case VK_OEM_MINUS: return "-";
        case VK_OEM_PERIOD: return ".";
        case VK_OEM_2: return "/";
        case VK_OEM_3: return "`";
        case VK_OEM_4: return "[";
        case VK_OEM_5: return "\\";
        case VK_OEM_6: return "]";
        case VK_OEM_7: return "'";
    }

    // Get the scan code
    UINT scanCode = MapVirtualKey(vkCode, MAPVK_VK_TO_VSC);

    // Handle extended keys
    switch (vkCode) {
        case VK_RCONTROL:
        case VK_RMENU:
        case VK_RSHIFT:
            scanCode |= KF_EXTENDED;
            break;
    }

    // Get the key name
    char keyName[256];
    if (GetKeyNameTextA(scanCode << 16, keyName, sizeof(keyName)) != 0) {
        // Clean up the name (remove "Left/Right" for some keys)
        std::string name(keyName);
        if (name.find("Left ") == 0 || name.find("Right ") == 0) {
            return name.substr(name.find(' ') + 1);
        }
        return name;
    }

    // Fallback for unknown keys
    return "Key " + std::to_string(vkCode);
}

/*
 * Authentication Functions
*/

static bool HandleLogin(const std::string& keyFile, const std::string& dbFile, sqlite3*& db, const std::string& passwordInput, const bool firstRun, bool& wrongPassword) {
    if (firstRun) {
        key.resize(KEY_SIZE);
        if(!GenerateRandomBytes(key.data(), KEY_SIZE)){
            return false;
        }

        try{
            EphemeralKeyStorage::StoreKey(key);
        } catch (const std::exception& e) {
            std::cerr << "Error: " << e.what() << std::endl;

            return false;
        }

        unsigned char salt[SALT_SIZE];
        if(!GenerateRandomBytes(salt, SALT_SIZE)){
            return false;
        }
        
        std::vector<unsigned char> derivedKey;
        std::vector<unsigned char> encryptedData;

        DerivePasswordKey(passwordInput, salt, derivedKey);
        EncryptData(key, derivedKey, salt, encryptedData);
        WriteFile(keyFile, encryptedData);
        
        bool db_exists = std::filesystem::exists(dbFile);
        if (!OpenDatabase(&db, dbFile.c_str(), key, db_exists))
            return false;

        if (!InitializeDatabase(db)) {
            sqlite3_close(db);

            return false;
        }

        key.clear();
        
        return true;
    } else {
        std::vector<unsigned char> encryptedData;
        ReadFile(keyFile, encryptedData);
        unsigned char header = encryptedData[0];
        bool hasSalt = (header == 0x01);

        unsigned char salt[SALT_SIZE];
        if (hasSalt) {
            std::copy(encryptedData.begin() + 1, encryptedData.begin() + 1 + SALT_SIZE, salt);
        }
        
        std::vector<unsigned char> derivedKey;
        bool decrypted;

        DerivePasswordKey(passwordInput, salt, derivedKey);
        decrypted  = DecryptData(encryptedData, derivedKey, key);

        try{
            EphemeralKeyStorage::StoreKey(key);
        } catch (const std::exception& e) {
            std::cerr << "Error: " << e.what() << std::endl;

            return false;
        }
        
        if(!decrypted){
            wrongPassword = true;
            return false;
        }
        
        bool db_exists = std::filesystem::exists(dbFile);
        if (!OpenDatabase(&db, dbFile.c_str(), key, db_exists)) {
            return false;
        }

        key.clear();

        return true;
    }
}

static void Authentication(ImGuiIO& io, const std::string& keyFile, const std::string& dbFile, sqlite3*& db, const bool firstRun, bool& result) {
    static char passwordInput[65] = "";
    static bool wrongPassword = false;
    static int cursorPos = 0;
    static int sectionLengthIndex = 0;
    bool canCheck = false;
    
    ImGui::SetNextWindowPos(ImGui::GetMainViewport()->GetCenter(), ImGuiCond_Always, ImVec2(0.5f, 0.5f));
    ImGui::SetNextWindowSize(ImVec2(400, 200), ImGuiCond_Always);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 10.0f);
    
    if (ImGui::Begin(firstRun ? "Set Up Password" : "Login", nullptr, ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoSavedSettings)) {
        ImGui::SetCursorPosX((ImGui::GetWindowSize().x - ImGui::CalcTextSize(firstRun ? "Set a master password for your password manager:" : "Enter your master password:").x) * 0.5f);
        ImGui::Text(firstRun ? "Set a master password for your password manager:" : "Enter your master password:");
        
        ImGui::Spacing();
        
        ImGui::SetCursorPosX((ImGui::GetWindowSize().x - 300) * 0.5f);
        ImGui::SetNextItemWidth(300);
        ImGui::InputText("##Password", passwordInput, sizeof(passwordInput), 
            ImGuiInputTextFlags_Password | ImGuiInputTextFlags_CallbackCharFilter, 
            InputTextCallback);

        ImGui::Spacing();

        if(firstRun){
            ImGui::SliderInt("Section Length:", &sectionLengthIndex, 0, sizeof(sectionLengths)/sizeof(sectionLengths[0]) - 1, "", ImGuiSliderFlags_NoInput);
            ImGui::SameLine();
            ImGui::Text("%d", sectionLengths[sectionLengthIndex]);
        }
        
        // Keyboard toggle
        ImGui::Spacing();
        ImGui::Checkbox("Show On-Screen Keyboard", &showOnScreenKeyboard);
        
        ImGui::Spacing();
        
        // Error message if wrong password
        if (wrongPassword) {
            ImGui::SetCursorPosX((ImGui::GetWindowSize().x - ImGui::CalcTextSize("Incorrect password. Please try again.").x) * 0.5f);
            ImGui::TextColored(ImVec4(1.0f, 0.2f, 0.2f, 1.0f), "Incorrect password. Please try again.");
            ImGui::Spacing();
        }
        
        ImGui::SetCursorPosX((ImGui::GetWindowSize().x - 200) * 0.5f);
        ImGui::SetNextItemWidth(200);
        if (ImGui::Button(firstRun ? "Set Password" : "Login", ImVec2(200, 0)) || ImGui::IsKeyPressed(ImGuiKey_Enter)) {
            canCheck = CheckCharBuffer(passwordInput, false);
        }

        if(canCheck){
            result = HandleLogin(keyFile, dbFile, db, passwordInput, firstRun, wrongPassword);
            memset(passwordInput, 0, sizeof(passwordInput));
            cursorPos = 0;
        }

        if(result){
            PurgeDeletedPasswords(db);
            passwords = GetAllPasswords(db);
            InitializeDefaultTabs();

            if(firstRun)
                SaveSettings(defaultPasteTime, defaultListenTime, defaultShowPasswordTime, defaultShortcutKey, sectionLengths[sectionLengthIndex]);

            LoadSettings();
        }
        
        ImGui::End();
    }

    ImGui::PopStyleVar();
    
    if (showOnScreenKeyboard) {
        RenderOnScreenKeyboard(passwordInput, cursorPos);
    }
}

/*
 * Management Functions
*/

static void SavePassword(sqlite3* db) {
    int userPasswordLength = passwordLengths[sectionLength - 2].at(entryWindowState.passwordLengthIndex);

    auto randomIV = std::make_unique<unsigned char[]>(IV_SIZE);
    auto genKey = std::make_unique<unsigned char[]>(KEY_SIZE);

    std::string characters = "";

    for(size_t i = 0; i < entryWindowState.selectedCharacterSets.size(); i++) {
        if (entryWindowState.selectedCharacterSets[i])
            characters += characterSets[i];
    }

    auto password = std::make_unique<std::string>();
    int fullLength = userPasswordLength*2;

    if(!GenerateRandomBytes(randomIV.get(), IV_SIZE))
        return;

    if(!GenerateRandomBytes(genKey.get(), KEY_SIZE))
        return;

    std::vector<int> indexes = GenerateRandomIndexes(userPasswordLength/sectionLength, fullLength/sectionLength, genKey.get(), randomIV.get());

    genKey.reset();
    randomIV.reset();

    *password = GenerateRandomString(fullLength, characters);
    std::vector<unsigned char> encryptedPassword;

    key = EphemeralKeyStorage::RetrieveKey();
    EncryptData(StringToVector(*password), key, nullptr, encryptedPassword);
    key.clear();
    
    password.reset();
    
    // Insert password and get ID
    InsertPassword(db, entryWindowState.nameBuffer, entryWindowState.usernameBuffer, userPasswordLength, indexes, encryptedPassword, {});
    int id = sqlite3_last_insert_rowid(db);

    // Add selected tags
    for (size_t i = 0; i < entryWindowState.selectedTags.size() && i < allTags.size(); i++) {
        if (entryWindowState.selectedTags[i]) {
            AddTagToPassword(db, id, allTags[i].GetId());
        }
    }

    // Get creation datetime
    std::string creationDateTime;
    sqlite3_stmt* stmt;
    const char* query = "SELECT creation_datetime FROM passwords WHERE id = ?";
    if (sqlite3_prepare_v2(db, query, -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_int(stmt, 1, id);
        
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            creationDateTime = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        }
        sqlite3_finalize(stmt);
    }

    PasswordEntry newEntry(
        id, entryWindowState.nameBuffer, entryWindowState.usernameBuffer, 
        creationDateTime, "",
        userPasswordLength, indexes, encryptedPassword, 
        false, false, std::vector<std::string>()
    );
    
    for (size_t i = 0; i < entryWindowState.selectedTags.size() && i < allTags.size(); i++) {
        if (entryWindowState.selectedTags[i]) {
            newEntry.AddTag(allTags[i].GetName());
        }
    }

    passwords.push_back(newEntry);

    if(showReplaceEntryWindow)
        if(SetPasswordDeletedStatus(db, entryWindowState.ReplacedEntry->GetId(), true))
            entryWindowState.ReplacedEntry->SetIsDeleted(true);
}

static std::string DecryptPassword(){
    std::regex non_digits("[^0-9]");
    
    std::string input = std::regex_replace(currentPassword->GetCreationDatetime(), non_digits, "");

    auto seed = std::make_unique<unsigned char[]>(KEY_SIZE);
    auto fixedIV = std::make_unique<unsigned char[]>(IV_SIZE);
    auto genKey = std::make_unique<unsigned char[]>(KEY_SIZE);

    key = EphemeralKeyStorage::RetrieveKey();
    LoadSeedAndIV(seedPath, seed.get(), KEY_SIZE, fixedIV.get(), IV_SIZE, key);
    key.clear();

    DeriveKey(seed.get(), KEY_SIZE, input, genKey.get());

    auto sectionState = std::make_unique<bool>(GenerateRandomBoolean(genKey.get(), fixedIV.get()));
    auto password = std::make_unique<std::string>();
    auto decryptedData = std::make_unique<std::vector<unsigned char>>();

    key = EphemeralKeyStorage::RetrieveKey();
    if(!DecryptData(currentPassword->GetPassword(), key, *decryptedData)){
        std::cerr << "Password decryption failed" << std::endl;

        return "";
    }
    key.clear();

    *password = VectorToString(*decryptedData);

    decryptedData.reset();

    std::vector<PasswordSection> sections = SplitString(*password, currentPassword->GetIndexes(), sectionLength, sectionState.get());

    password.reset();
    sectionState.reset();

    std::string result;
    result.reserve(currentPassword->GetLength());

    for (auto& section : sections) {
        if (!*(section.GetIsFake()))
            result.append(section.GetStringSection());
    }

    return result;
}

static void monitorKeyPress() {
    auto startTime = std::chrono::steady_clock::now();

    while (true) {
        auto currentTime = std::chrono::steady_clock::now();
        auto elapsedTime = std::chrono::duration_cast<std::chrono::seconds>(currentTime - startTime).count();

        if (elapsedTime >= listenTime) {
            std::cout << "ListenTime elapsed. Stopping key monitoring." << std::endl;
            break;
        }

        // If the shortcut key is pressed
        if (GetAsyncKeyState(shortcutKey) & 0x8000) { 
            if (IsPrintableVirtualKey(shortcutKey)) {
                KeyPress(0x0E, false, 1);
                std::this_thread::sleep_for(std::chrono::milliseconds(pasteTime));
            }

            std::regex non_digits("[^0-9]");
            std::string input = std::regex_replace(currentPassword->GetCreationDatetime(), non_digits, "");

            auto seed = std::make_unique<unsigned char[]>(KEY_SIZE);
            auto fixedIV = std::make_unique<unsigned char[]>(IV_SIZE);
            auto randomIV = std::make_unique<unsigned char[]>(IV_SIZE);
            auto genKey = std::make_unique<unsigned char[]>(KEY_SIZE);

            // Derive key from the seed and input
            key = EphemeralKeyStorage::RetrieveKey();
            LoadSeedAndIV(seedPath, seed.get(), KEY_SIZE, fixedIV.get(), IV_SIZE, key);
            key.clear();

            DeriveKey(seed.get(), KEY_SIZE, input, genKey.get());

            seed.reset();

            auto sectionState = std::make_unique<bool>(GenerateRandomBoolean(genKey.get(), fixedIV.get()));

            fixedIV.reset();
            
            auto password = std::make_unique<std::string>();
            auto decryptedData = std::make_unique<std::vector<unsigned char>>();

            key = EphemeralKeyStorage::RetrieveKey();
            if(!DecryptData(currentPassword->GetPassword(), key, *decryptedData)){
                std::cerr << "Password decryption failed" << std::endl;

                return;
            }
            key.clear();
            
            *password = VectorToString(*decryptedData);

            decryptedData.reset();

            std::vector<PasswordSection> sections = SplitString(*password, currentPassword->GetIndexes(), sectionLength, sectionState.get());

            password.reset();
            sectionState.reset();

            GenerateRandomBytes(randomIV.get(), IV_SIZE);
            RandomizeStringSections(sections, genKey.get(), randomIV.get());

            randomIV.reset();
            genKey.reset();

            PasteSections(sections, sectionLength, pasteTime);

            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    // Reset flag after thread execution is complete
    startPollingThread.store(false);
}

static bool CheckCharBuffer(const char buffer[], const bool canBeEmpty) {
    const size_t inputLength = strlen(buffer);

    if(inputLength <= 0){
        if(canBeEmpty)
            return true;

        std::cerr << "Empty name" << std::endl;

        return false;
    }

    if(buffer[0] == ' ') {
        std::cerr << "Leading space" << std::endl;

        return false;
    }

    if(buffer[inputLength - 1] == ' ') {
        std::cerr << "Trailing space" << std::endl;

        return false;
    }

    return true;
}

static void HandleKeyPress(char* buffer, int& cursorPos, const std::string& keyboardKey) {
    if (keyboardKey == "Backspace") {
        if (cursorPos > 0) {
            buffer[cursorPos - 1] = '\0';
            cursorPos--;
        }
    } 
    else if (keyboardKey == "Caps") {
        capsLock = !capsLock;
    }
    // 64 is buffer size - 1
    else if (keyboardKey != " " && cursorPos < 64) { 
        buffer[cursorPos] = capsLock ? toupper(keyboardKey[0]) : keyboardKey[0];
        cursorPos++;
        buffer[cursorPos] = '\0';
    }
}

static bool ShouldSkipEntry(const PasswordEntry& entry, bool showDeletedOnly) {
    return showDeletedOnly ? !entry.GetIsDeleted() : entry.GetIsDeleted();
}

static bool HasAllRequiredTags(const std::vector<int>& filterTags, const std::vector<Tag>& entryTags) {
    for (int filterTagId : filterTags) {
        auto it = std::find_if(entryTags.begin(), entryTags.end(), 
        [filterTagId](const Tag& tag) { return tag.GetId() == filterTagId; });
        
        if (it == entryTags.end())
            return false;
    }

    return true;
}

static void FilterPasswords(const ManagerTab& tab, sqlite3* db, std::vector<PasswordEntry>& passwords, std::vector<PasswordEntry*>& filteredPasswords) {
    for (auto& entry : passwords) {
        if (ShouldSkipEntry(entry, tab.showDeletedOnly)) 
            continue;
        if (!tab.filterTags.empty() && !HasAllRequiredTags(tab.filterTags, GetTagsForPassword(db, entry.GetId()))) 
            continue;
        
        filteredPasswords.push_back(&entry);
    }
}

static bool IsPasswordWindowOpen(int entryId) {
    for (const auto& window : openPasswordWindows)
        if (window.entry->GetId() == entryId && window.isOpen)
            return true;

    return false;
}

/*
 * UI Rendering
*/

static void ShowConfirmationDialog(const char* title, const char* message, std::shared_ptr<bool> answer) {
    ImGui::SetNextWindowPos(ImGui::GetMainViewport()->GetCenter(), ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));
    
    if (ImGui::BeginPopupModal(title, nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {
        ImGui::TextUnformatted(message);
        ImGui::Separator();

        if (ImGui::Button("Yes", ImVec2(120, 0)) || ImGui::IsKeyPressed(ImGuiKey_Enter)) {
            if (answer) *answer = true;
            ImGui::CloseCurrentPopup();
        }
        
        ImGui::SameLine();
        
        if (ImGui::Button("No", ImVec2(120, 0))) {
            if (answer) *answer = false;
            ImGui::CloseCurrentPopup();
        }
        
        ImGui::EndPopup();
    }
}

static bool ShowPasswordEntryWindow(const char* windowTitle, sqlite3* db, std::vector<PasswordEntry>& passwords) {
    const auto& currentLengths = passwordLengths[sectionLength - 2];
    bool windowResult = false;
    bool canSave = false;

    ImGui::SetNextWindowSize(ImVec2(300, 300), ImGuiCond_FirstUseEver);
    if (ImGui::Begin(windowTitle, &entryWindowState.shouldOpen, ImGuiWindowFlags_None)) {
        ImGui::InputText("Name", entryWindowState.nameBuffer, sizeof(entryWindowState.nameBuffer), ImGuiInputTextFlags_CallbackCharFilter, InputTextCallback);
        ImGui::InputText("Username", entryWindowState.usernameBuffer, sizeof(entryWindowState.usernameBuffer), ImGuiInputTextFlags_CallbackCharFilter, InputTextCallback);
        
        ImGui::SliderInt("Password Length:", &entryWindowState.passwordLengthIndex, 0, (int)currentLengths.size() - 1, "", ImGuiSliderFlags_NoInput);
        ImGui::SameLine();
        ImGui::Text("%d", currentLengths.at(entryWindowState.passwordLengthIndex));

        ImGui::Separator();
        ImGui::Text("Character Sets:");
        ImGui::BeginChild("CharacterSetSelections", ImVec2(0, 100), true);
        for (size_t i = 0; i < std::size(characterSets); i++) {
            bool checked = entryWindowState.selectedCharacterSets[i];

            if (ImGui::Checkbox(characterSets[i].c_str(), &checked))
                entryWindowState.selectedCharacterSets[i] = checked;
        }

        ImGui::EndChild();

        ImGui::Separator();
        ImGui::Text("Tags:");
        ImGui::BeginChild("TagSelection", ImVec2(0, 100), true);
        
        auto allTags = GetAllTags(db);
        for (size_t i = 0; i < allTags.size(); i++) {
            if (i >= entryWindowState.selectedTags.size()) {
                entryWindowState.selectedTags.push_back(false);
            }
            bool checked = entryWindowState.selectedTags[i];
            if (ImGui::Checkbox(allTags[i].GetName().c_str(), &checked)) {
                entryWindowState.selectedTags[i] = checked;
            }
        }
        
        ImGui::EndChild();

        // Action buttons
        if (ImGui::Button("Save", ImVec2(138, 20)) || ImGui::IsKeyPressed(ImGuiKey_Enter))
            canSave = (CheckCharBuffer(entryWindowState.nameBuffer, false) &&
            CheckCharBuffer(entryWindowState.usernameBuffer, true) && 
            std::any_of(entryWindowState.selectedCharacterSets.begin(), entryWindowState.selectedCharacterSets.end(), [](bool s) { return s; }));

        if(canSave){
            SavePassword(db);

            entryWindowState.result = true;
            windowResult = true;
            showEntryWindow = false;
            showReplaceEntryWindow = false;

            entryWindowState.Reset();            
        }

        ImGui::SameLine();
        if (ImGui::Button("Cancel", ImVec2(138, 20))) {
            entryWindowState.result = false;
            windowResult = false;
            showEntryWindow = false;
            showReplaceEntryWindow = false;
            entryWindowState.Reset();
        }
    }
    ImGui::End();

    return windowResult;
}

static void RenderManagerTab(ManagerTab& tab, sqlite3* db) {
    if (!tab.isOpen) return;

    enum class DialogType { None, Delete, Restore };
    static DialogType activeDialog = DialogType::None;
    static std::shared_ptr<bool> dialogAnswer;

    std::vector<PasswordEntry*> filteredPasswords;
    FilterPasswords(tab, db, passwords, filteredPasswords);
    
    // Sort alphabetically
    std::sort(filteredPasswords.begin(), filteredPasswords.end(), 
        [](const PasswordEntry* a, const PasswordEntry* b) {
            return a->GetName() < b->GetName();
        });

    // Begin tab content
    ImGui::BeginChild(tab.name.c_str(), ImVec2(0, 0), true, ImGuiWindowFlags_NoSavedSettings);

    if (!tab.showDeletedOnly) {
        if (ImGui::Button("Add new entry", ImVec2(100, 30))) {
            showEntryWindow = true;
            currentTabForNewEntry = &tab;
        }
    }

    ImGui::SameLine();
    if (ImGui::Button("Tag Manager", ImVec2(100, 30))) {
        showTagManagerWindow = true;
        allTags = GetAllTags(db);
    }
    
    ImGui::SameLine();
    if (ImGui::Button("Filter Tags", ImVec2(100, 30))) {
        tab.showTagFilter = true;
        allTags = GetAllTags(db);
    }

    ImGui::SameLine();
    if (ImGui::Button("Settings", ImVec2(100, 30))) {
        showSettingsWindow = true;
    }

    // Entry list
    ImGui::Text("Entries (%d)", filteredPasswords.size());
    const float itemHeight = ImGui::GetTextLineHeightWithSpacing();
    const float maxHeight = itemHeight * 26.0f;

    ImGui::BeginChild("Elements", ImVec2(0, maxHeight), true, ImGuiWindowFlags_HorizontalScrollbar);
    for (int i = 0; i < filteredPasswords.size(); i++) {
        ImGui::PushID(filteredPasswords[i]->GetId());
        bool isSelected = (tab.selectedItem == i);
        if (ImGui::Selectable(filteredPasswords[i]->GetName().c_str(), isSelected)) {
            tab.selectedItem = i;
        }
        ImGui::PopID();
    }
    ImGui::EndChild();

    // Entry actions
    if (tab.selectedItem != -1 && tab.selectedItem < filteredPasswords.size()) {
        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        if (ImGui::Button("Open", ImVec2(100, 30))) {
            if (!IsPasswordWindowOpen(filteredPasswords[tab.selectedItem]->GetId())) {
                PasswordDetailWindow newWindow;
                newWindow.isOpen = true;
                newWindow.entry = filteredPasswords[tab.selectedItem];
                openPasswordWindows.push_back(newWindow);
            }
        }

        ImGui::SameLine();

        if (!tab.showDeletedOnly) {
            if (ImGui::Button("Replace", ImVec2(100, 30))) {
                showEntryWindow = true;
                showReplaceEntryWindow = true;
                currentPassword = filteredPasswords[tab.selectedItem];
            }

            ImGui::SameLine();
            if (ImGui::Button("Delete", ImVec2(100, 30))) {
                dialogAnswer = std::make_shared<bool>(false);
                ImGui::OpenPopup("Password Entry Deletion");
                activeDialog = DialogType::Delete;
            }
        } else {
            if (ImGui::Button("Restore", ImVec2(100, 30))) {
                dialogAnswer = std::make_shared<bool>(false);
                ImGui::OpenPopup("Password Entry Restoration");
                activeDialog = DialogType::Restore;
            }
        }
        
        switch (activeDialog) {
        case DialogType::Delete:
            ShowConfirmationDialog("Password Entry Deletion", "Are you sure you want to delete this password entry?", dialogAnswer);
            
            if (!ImGui::IsPopupOpen("Password Entry Deletion") && dialogAnswer) {
                if (*dialogAnswer)
                    if (SetPasswordDeletedStatus(db, filteredPasswords[tab.selectedItem]->GetId(), true))
                        filteredPasswords[tab.selectedItem]->SetIsDeleted(true);

                activeDialog = DialogType::None;
                dialogAnswer.reset();
            }
            
            break;
        case DialogType::Restore:
            ShowConfirmationDialog("Password Entry Restoration", "Are you sure you want to restore this password entry", dialogAnswer);
            
            if (!ImGui::IsPopupOpen("Password Entry Restoration") && dialogAnswer) {
                if (*dialogAnswer)
                    if (SetPasswordDeletedStatus(db, filteredPasswords[tab.selectedItem]->GetId(), false))
                        filteredPasswords[tab.selectedItem]->SetIsDeleted(false);

                activeDialog = DialogType::None;
                dialogAnswer.reset();
            }

            break;       
        case DialogType::None:
            break;
        }
    }

    ImGui::EndChild();
}

static void RenderTagManagerWindow(sqlite3* db) {
    if (!showTagManagerWindow) return;

    bool canSave = false;

    ImGui::SetNextWindowSize(ImVec2(400, 300), ImGuiCond_FirstUseEver);
    if (ImGui::Begin("Tag Manager", &showTagManagerWindow)) {
        if (ImGui::Button("Refresh")) {
            allTags = GetAllTags(db);
        }

        // List all tags with delete buttons
        ImGui::BeginChild("TagList", ImVec2(0, 200), true);
        for (auto it = allTags.begin(); it != allTags.end(); ) {
            ImGui::PushID(it->GetId());
            
            ImGui::Text("%s", it->GetName().c_str());
            ImGui::SameLine(ImGui::GetWindowWidth() - 50);
            
            if (ImGui::Button("Delete")) {
                DeleteTag(db, it->GetId());
                it = allTags.erase(it);
            } else {
                ++it;
            }
            
            ImGui::PopID();
        }
        ImGui::EndChild();

        // Add new tag
        static char newTagName[17] = "";
        ImGui::InputText("New Tag", newTagName, sizeof(newTagName), ImGuiInputTextFlags_CallbackCharFilter, InputTextCallback);

        if (ImGui::Button("Add Tag") || ImGui::IsKeyPressed(ImGuiKey_Enter))
            canSave = CheckCharBuffer(newTagName, false);

        if(canSave){
            if (AddTag(db, newTagName)) {
                 // Refresh list
                allTags = GetAllTags(db);
                newTagName[0] = '\0';
            }
        }
    }
    ImGui::End();
}

static void RenderTagFilterWindow(ManagerTab& tab, sqlite3* db) {
    if (!tab.showTagFilter) return;

    ImGui::SetNextWindowSize(ImVec2(300, 200), ImGuiCond_FirstUseEver);
    if (ImGui::Begin(("Tag Filter - " + tab.name).c_str(), &tab.showTagFilter, ImGuiWindowFlags_NoSavedSettings)) {
        ImGui::Text("Select tags to filter:");
        ImGui::BeginChild("TagFilters", ImVec2(0, 0), true);
        
        for (size_t i = 0; i < allTags.size(); i++) {
            bool selected = std::find(tab.filterTags.begin(), tab.filterTags.end(), allTags[i].GetId()) != tab.filterTags.end();
            if (ImGui::Checkbox(allTags[i].GetName().c_str(), &selected)) {
                if (selected) {
                    tab.filterTags.push_back(allTags[i].GetId());
                } else {
                    tab.filterTags.erase(std::remove(tab.filterTags.begin(), tab.filterTags.end(), allTags[i].GetId()), tab.filterTags.end());
                }
            }
        }
        ImGui::EndChild();
    }

    if (ImGui::Button("Clear Filters"))
        tab.filterTags.clear();
    
    ImGui::End();
}

static void RenderSettingsWindow() {
    static bool firstOpen = true;

    static int tempPasteTime;
    static int templistenTime;
    static int tempShowPasswordTime;
    static int tempShortcutKey;
    static std::string tempShortcutKeyName;

    if (firstOpen && showSettingsWindow) {
        tempPasteTime = pasteTime;
        templistenTime = listenTime;
        tempShowPasswordTime = showPasswordTime;
        tempShortcutKey = shortcutKey;
        tempShortcutKeyName = shortcutKeyName;

        firstOpen = false;
    }

    if (!showSettingsWindow) {
        firstOpen = true;

        return;
    }

    ImGui::SetNextWindowSize(ImVec2(400, 250), ImGuiCond_FirstUseEver);
    if (ImGui::Begin("Settings", &showSettingsWindow)) {
        // Paste Time setting
        ImGui::Text("Paste Delay (Milliseconds):");
        ImGui::SameLine();
        ImGui::SetNextItemWidth(100);
        if(ImGui::InputInt("##PasteTime", &tempPasteTime, 1, 1))
            if(!CheckPositiveInt(tempPasteTime))
                tempPasteTime = 1;

        // Listen Time setting
        ImGui::Text("Pasting listening time (Seconds):");
        ImGui::SameLine();
        ImGui::SetNextItemWidth(100);
        if(ImGui::InputInt("##ListenTime", &templistenTime, 1, 1))
            if(!CheckPositiveInt(templistenTime))
                templistenTime = 1;

        // Show Password Time setting
        ImGui::Text("Password show time (Seconds):");
        ImGui::SameLine();
        ImGui::SetNextItemWidth(100);
        if(ImGui::InputInt("##ShowPasswordTime", &tempShowPasswordTime, 1, 1))
            if(!CheckPositiveInt(tempShowPasswordTime))
                tempShowPasswordTime = 1;

        // Shortcut Key setting
        ImGui::Text("Paste Shortcut Key:");
        ImGui::SameLine();

        if (capturingKey) {
            ImGui::TextColored(ImVec4(1, 1, 0, 1), "Press any key...");
            
            // Check all possible virtual keys
            for (int vk = 1; vk < 256; vk++) {
                if (GetAsyncKeyState(vk) & 0x8000) {
                    // Skip mouse buttons
                    if (vk >= VK_LBUTTON && vk <= VK_XBUTTON2) continue;
                    
                    tempShortcutKey = vk;
                    tempShortcutKeyName = GetKeyName(vk);
                    capturingKey = false;
                    break;
                }
            }

            if (ImGui::Button("Cancel", ImVec2(100, 0))) {
                capturingKey = false;
            }
        } else {
            ImGui::Text("%s", tempShortcutKeyName.c_str());
            ImGui::SameLine();
            if (ImGui::Button("Change Key", ImVec2(100, 0))) {
                capturingKey = true;
            }
        }

        if (ImGui::Button("Save", ImVec2(120, 30)) || ImGui::IsKeyPressed(ImGuiKey_Enter)) {
            pasteTime = tempPasteTime;
            listenTime = templistenTime;
            showPasswordTime = tempShowPasswordTime;
            shortcutKey = tempShortcutKey;
            shortcutKeyName = tempShortcutKeyName;

            SaveSettings(pasteTime, listenTime, showPasswordTime, shortcutKey, sectionLength);

            showSettingsWindow = false;
            firstOpen = true;
        }
        ImGui::SameLine();
        if (ImGui::Button("Cancel", ImVec2(120, 30))) {
            tempPasteTime = pasteTime;
            templistenTime = listenTime;
            tempShowPasswordTime = showPasswordTime;
            tempShortcutKey = shortcutKey;
            tempShortcutKeyName = shortcutKeyName;
            
            showSettingsWindow = false;
            firstOpen = true;
        }
    }
    ImGui::End();
}

static void RenderOnScreenKeyboard(char* passwordInput, int& cursorPos) {
    ImGui::SetNextWindowSize(ImVec2(550, 250), ImGuiCond_FirstUseEver);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 10.0f);

    if (ImGui::Begin("On-Screen Keyboard", &showOnScreenKeyboard, ImGuiWindowFlags_NoCollapse)) {
        const float keyWidth = 30.0f;
        const float keyHeight = 40.0f;
        const float spacing = 2.0f;
        
        for (const auto& row : keyboardLayout) {
            ImGui::BeginGroup();
            float rowWidth = (row.size() * (keyWidth + spacing)) - spacing;
            ImGui::SetCursorPosX((ImGui::GetWindowWidth() - rowWidth) * 0.5f);
            
            for (const auto& keyboardKey : row) {
                if (keyboardKey == "Backspace") {
                    if (ImGui::Button("<-", ImVec2(keyWidth * 1.5f, keyHeight))) {
                        HandleKeyPress(passwordInput, cursorPos, keyboardKey);
                    }
                } 
                else if (keyboardKey == "Caps") {
                    if (ImGui::Button(capsLock ? "CAPS" : "Caps", ImVec2(keyWidth * 1.5f, keyHeight))) {
                        HandleKeyPress(passwordInput, cursorPos, keyboardKey);
                    }
                }
                else {
                    std::string displayKey = capsLock ? std::string(1, toupper(keyboardKey[0])) : keyboardKey;
                    if (ImGui::Button(displayKey.c_str(), ImVec2(keyWidth, keyHeight))) {
                        HandleKeyPress(passwordInput, cursorPos, keyboardKey);
                    }
                }

                ImGui::SameLine(0, spacing);
            }

            ImGui::EndGroup();
        }
    }

    ImGui::End();
    ImGui::PopStyleVar();
}

static void RenderPasswordWindow(PasswordDetailWindow* window) {
    enum class DialogType { None, Clipboard, ShowPassword };
    static DialogType activeDialog = DialogType::None;
    static std::shared_ptr<bool> dialogAnswer;

    static std::chrono::steady_clock::time_point passwordShowStartTime;
    static bool showingPassword = false;
    static std::string displayedPassword;

    std::string windowName = "Password Details - " + std::to_string(window->entry->GetId()) + " - " + window->entry->GetName();

    if (ImGui::Begin(windowName.c_str(), &window->isOpen, ImGuiWindowFlags_NoSavedSettings)) {
        // Always visible fields
        ImGui::Text("Name: %s", window->entry->GetName().c_str());
        ImGui::Text("Username: %s", window->entry->GetUsername().c_str());
        ImGui::Text("Last Used Date: %s", window->entry->GetLastUsedDatetime().c_str());
        ImGui::Text("Replacement Notification: %s", window->entry->GetGotReplacementNotification() ? "Yes" : "No");

        ImGui::Text("Tags:");
        for (const auto& tag : window->entry->GetTags()) {
            ImGui::BulletText("%s", tag.c_str());
        }

        // Password field with show button
        ImGui::Text("Password: ");
        ImGui::SameLine();
        
        if (showingPassword) {
            auto now = std::chrono::steady_clock::now();
            if (now - passwordShowStartTime > std::chrono::seconds(showPasswordTime)) {
                showingPassword = false;
                displayedPassword.clear();
            }
            
            // Show the actual password
            ImGui::Text("%s", displayedPassword.c_str());
        } else {
            ImGui::Text("********");
            ImGui::SameLine();
            if (ImGui::Button("Show")) {
                dialogAnswer = std::make_shared<bool>(false);
                ImGui::OpenPopup("Show Password Confirmation");
                activeDialog = DialogType::ShowPassword;
            }
        }

        // Collapsible section for additional details
        if (ImGui::CollapsingHeader("Additional Details")) {
            ImGui::Text("ID: %d", window->entry->GetId());
            ImGui::Text("Creation Date: %s", window->entry->GetCreationDatetime().c_str());
            ImGui::Text("Length: %d", window->entry->GetLength());
            ImGui::Text("Deleted: %s", window->entry->GetIsDeleted() ? "Yes" : "No");
        }

        if (ImGui::Button("Clipboard Copy")) {
            dialogAnswer = std::make_shared<bool>(false);
            ImGui::OpenPopup("Clipboard Copy Confirmation");
            activeDialog = DialogType::Clipboard;
        }

        ImGui::SameLine();

        if (ImGui::Button("Automatic Pasting")) {
            if (!startPollingThread.load()) {
                startPollingThread.store(true);

                if (keyMonitorThread.joinable()) {
                    keyMonitorThread.join();
                }
                currentPassword = window->entry;

                keyMonitorThread = std::thread(monitorKeyPress);
            } else {
                std::cerr << "Thread already running!" << std::endl;
            }
        }

        switch (activeDialog) {
        case DialogType::Clipboard:
            ShowConfirmationDialog("Clipboard Copy Confirmation", "Are you sure you want to copy the password to clipboard?", dialogAnswer);
            
            if (!ImGui::IsPopupOpen("Clipboard Copy Confirmation") && dialogAnswer) {
                if (*dialogAnswer) {
                    currentPassword = window->entry;
                    SetClipboardText(DecryptPassword());
                }

                activeDialog = DialogType::None;
                dialogAnswer.reset();
            }
            break;
            
        case DialogType::ShowPassword:
            ShowConfirmationDialog("Show Password Confirmation", "Are you sure you want to show the password?", dialogAnswer);
            
            if (!ImGui::IsPopupOpen("Show Password Confirmation") && dialogAnswer) {
                if (*dialogAnswer) {
                    currentPassword = window->entry;
                    displayedPassword = DecryptPassword();

                    showingPassword = true;
                    passwordShowStartTime = std::chrono::steady_clock::now();
                }

                activeDialog = DialogType::None;
                dialogAnswer.reset();
            }
            break;
            
        case DialogType::None:
            break;
        }
    }
}

static void RenderMainUI(sqlite3* db, const int windowWidth, const int windowHeight) {
{
    ImGui::SetNextWindowPos(ImGui::GetMainViewport()->GetCenter(), ImGuiCond_Always, ImVec2(0.5f, 0.5f));
    ImGui::SetNextWindowSize(ImVec2(windowWidth, windowHeight));
    ImGui::Begin("Password Manager", nullptr, ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoBringToFrontOnFocus| ImGuiWindowFlags_NoSavedSettings);

    if (ImGui::BeginTabBar("ManagerTabs", ImGuiTabBarFlags_AutoSelectNewTabs | ImGuiTabBarFlags_Reorderable)) {
        if (ImGui::TabItemButton("+", ImGuiTabItemFlags_Trailing | ImGuiTabItemFlags_NoTooltip)) {
            managerTabs.push_back({"Tab " + std::to_string(managerTabs.size() + 1), true, true, "", false});
        }

        for (auto it = managerTabs.begin(); it != managerTabs.end(); ) {
            bool tabOpen = it->isOpen;
            ImGuiTabItemFlags flags = it->canClose ? ImGuiTabItemFlags_None : ImGuiTabItemFlags_None;
            
            if (ImGui::BeginTabItem(it->name.c_str(), &tabOpen, flags)) {
                RenderManagerTab(*it, db);
                ImGui::EndTabItem();
            }
        
            if (!tabOpen && it->canClose) {
                it = managerTabs.erase(it);
            } else {
                ++it;
            }
        }

        ImGui::EndTabBar();
    }

    ImGui::End();
}

    if(showEntryWindow) {
        if (!entryWindowState.initializedTags) {
            const std::string* initialName = 
            showReplaceEntryWindow ? &(currentPassword->GetName()) : nullptr;

            const std::string* initialUsername = 
            showReplaceEntryWindow ? &(currentPassword->GetUsername()) : nullptr;

            const std::vector<std::string>* initialTags = 
            showReplaceEntryWindow ? &(currentPassword->GetTags()) : nullptr;

            auto allTags = GetAllTags(db);
            entryWindowState.Initialize(allTags, initialName, initialUsername, initialTags);
        }
        
        ShowPasswordEntryWindow(showReplaceEntryWindow ? "Replace Entry" : "New Entry", db, passwords);
    }

    if (showTagManagerWindow || std::any_of(managerTabs.begin(), managerTabs.end(), [](const ManagerTab& t) { return t.showTagFilter; })) {
        RenderTagManagerWindow(db);
        for (auto& tab : managerTabs) {
            if (tab.showTagFilter)
                RenderTagFilterWindow(tab, db);
        }
    }

    for (auto it = openPasswordWindows.begin(); it != openPasswordWindows.end();) {
        if (it->isOpen) {
            RenderPasswordWindow(&(*it));

            ImGui::End();

            ++it;
        } else {
            it = openPasswordWindows.erase(it);
        }
    }

    if (showSettingsWindow) {
        RenderSettingsWindow();
    }
}