#pragma once

#define NTDDI_VERSION 0x06000000

#include <shlobj.h>  // For SHGetKnownFolderPath
#include <iostream>
#include <string>
#include <filesystem>  // For directory operations


/**
 * Retrieves the path to the AppData\Local directory for the current user.
 * 
 * @return A wide string containing the path to the LocalAppData directory or an empty string if the path could not be retrieved.
 */
std::wstring GetAppDataLocalPath();

/**
 * Retrieves or creates the directory for the application inside the AppData\Local folder.
 * 
 * @param appDataLocalPath The path to the AppData\Local directory. This is passed to construct the full path to the application's directory.
 * 
 * @return A wide string containing the full path to the application's directory inside AppData\Local, or an empty string if the directory could not be created or accessed.
 */
std::wstring GetAppPath(const std::wstring& appDataLocalPath);