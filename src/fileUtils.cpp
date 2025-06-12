#include "fileUtils.h"

std::wstring GetAppDataLocalPath() {
    PWSTR path = nullptr;
    if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_LocalAppData, 0, NULL, &path))) {
        std::wstring result(path);

        // Free the memory allocated by SHGetKnownFolderPath
        CoTaskMemFree(path);  

        return result;
    }

    return L"";
}

std::wstring GetAppPath(const std::wstring& appDataLocalPath) {
    std::filesystem::path fullPath = std::filesystem::path(appDataLocalPath) / L"Duke's Keep";

    if (!std::filesystem::exists(fullPath)) {
        if (!std::filesystem::create_directory(fullPath)) {
            std::wcerr << L"Failed to create directory: " << fullPath << std::endl;
            
            return L"";
        }
        std::wcout << L"Created directory: " << fullPath << std::endl;
    } else {
        std::wcout << L"Directory already exists: " << fullPath << std::endl;
    }

    // Return the full path as a wide string
    return fullPath.wstring();
}