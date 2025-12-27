#pragma once

#include <sqlite3.h>

#include <iostream>
#include <cstring>
#include <sys/stat.h>
#include <vector>
#include <filesystem>
#include <map>

class PasswordEntry {
private:
    int id;
    std::string name;
    std::string username;
    std::string creation_datetime;
    std::string last_used_datetime;
    int length;
    std::vector<int> indexes;
    std::vector<unsigned char> password;
    bool isDeleted;
    bool gotReplacementNotification;
    std::vector<std::string> tags;

public:
    PasswordEntry(int id, const std::string& name, const std::string& username, 
         const std::string& creation_datetime, const std::string& last_used_datetime,
         int length, const std::vector<int>& indexes, const std::vector<unsigned char>& password,
         bool isDeleted, bool gotReplacementNotification, 
         const std::vector<std::string>& tags)
        : id(id), name(name), username(username), 
         creation_datetime(creation_datetime), last_used_datetime(last_used_datetime),
         length(length), indexes(indexes), password(password),
         isDeleted(isDeleted), gotReplacementNotification(gotReplacementNotification),
         tags(tags) {}

    // Setters
    void SetCreationDateTime(std::string datetime) { creation_datetime = datetime; }
    void SetLastUsedDatetime(const std::string& datetime) { last_used_datetime = datetime; }
    void SetPassword(const std::vector<unsigned char>& newPassword) { password = newPassword; }
    void SetIsDeleted(bool deleted) { isDeleted = deleted; }
    void SetGotReplacementNotification(bool notified) { gotReplacementNotification = notified; }
    void AddTag(const std::string& tag) { tags.push_back(tag); }

    // Getters
    int GetId() const { return id; }
    const std::string& GetName() const { return name; }
    const std::string& GetUsername() const { return username; }
    const std::string& GetCreationDatetime() const { return creation_datetime; }
    const std::string& GetLastUsedDatetime() const { return last_used_datetime; }
    int GetLength() const { return length; }
    const std::vector<int>& GetIndexes() const { return indexes; }
    const std::vector<unsigned char>& GetPassword() const { return password; }
    bool GetIsDeleted() const { return isDeleted; }
    bool GetGotReplacementNotification() const { return gotReplacementNotification; }
    const std::vector<std::string>& GetTags() const { return tags; }
};

class Tag {
private:
    int id;
    std::string name;

public:
    Tag(int id, const std::string& name) : id(id), name(name) {}

    // Setters
    void SetName(const std::string& newName) { name = newName; }

    // Getters
    int GetId() const { return id; }
    const std::string& GetName() const { return name; }
};

// Currently unused
class PasswordTag {
private:
    int password_id;
    int tag_id;

public:
    PasswordTag(int passwordId, int tagId) : password_id(passwordId), tag_id(tagId) {}

    // Getters
    int GetPasswordId() const { return password_id; }
    int GetTagId() const { return tag_id; }
};

/**
 * Serialize a vector of indexes into a string format.
 * 
 * @param indexes Vector of integers to be serialized.
 * @return A string representing the serialized indexes.
 */
std::string SerializeIndexes(const std::vector<int>& indexes);

/**
 * Deserialize a string of serialized indexes back into a vector of integers.
 * 
 * @param indexes_str A string of serialized indexes to be deserialized.
 * @return A vector of integers representing the deserialized indexes.
 */
std::vector<int> DeserializeIndexes(const std::string& indexes_str);

/**
 * Opens a connection to an SQLite database and sets the encryption key (if needed).
 * 
 * @param db Pointer to the SQLite database connection to be opened.
 * @param db_file Path to the SQLite database file.
 * @param key A vector containing the encryption key for the database.
 * @param db_exists Flag indicating if the database already exists (true) or if it's a new database (false).
 * @return True if the database was opened successfully, false otherwise.
 */
bool OpenDatabase(sqlite3 **db, const char *db_file, const std::vector<unsigned char>& key, bool db_exists);

/**
 * Initializes the SQLite database by creating necessary tables if they don't exist.
 * 
 * @param db The SQLite database connection.
 * @return True if the tables were created successfully, false otherwise.
 */
bool InitializeDatabase(sqlite3 *db);

/**
 * Inserts a new password entry into the database, including associated tags.
 * 
 * @param db The SQLite database connection.
 * @param name The name associated with the password.
 * @param username The username associated with the password.
 * @param length The length of the password.
 * @param indexes A vector of integers representing the indexes related to the password.
 * @param password A vector of unsigned characters representing the password.
 * @param tags A vector of tag names to associate with the password.
 */
void InsertPassword(sqlite3 *db, const std::string &name, const std::string &username, const int &length, const std::vector<int> &indexes, const std::vector<unsigned char> &password, const std::vector<std::string> &tags);

/**
 * Sets the "isDeleted" status of a password entry in the database.
 * 
 * @param db The SQLite database connection.
 * @param passwordId The ID of the password entry to update.
 * @param isDeleted A flag indicating if the password should be marked as deleted (true) or not (false).
 * @param changedDateTime A buffer that will store the changed password entry's creation_datetime.
 * @return True if the status was updated successfully, false otherwise.
 */
bool SetPasswordDeletedStatus(sqlite3* db, int passwordId, bool isDeleted, const char* changedDateTime);

/**
 * Retrieves all password entries from the database.
 * 
 * @param db The SQLite database connection.
 * @return A vector of PasswordEntry objects containing all the retrieved password entries.
 */
std::vector<PasswordEntry> GetAllPasswords(sqlite3 *db);

/**
 * Checks marked password entries, based on `deletedPasswordKeepTim` (days), and deletes them from the database.
 * 
 * @param db The SQLite database connection.
 * @param deletedPasswordKeepTime The time (days) that deletion marked password entries need to be older than to be deleted.
 * @return True if the passwords were purged successfully, false otherwise.
 */
bool PurgeDeletedPasswords(sqlite3* db, int deletedPasswordKeepTime);

/**
 * Marks all the passwords that are found to be older than the `replacementInterval` (days)
 * 
 * @param db The SQLite database connection.
 * @param replacementInterval The time (days) that password entries need to be older than, to be marked. 
 * 
 * @return True if passwords were marked, false otherwise.
 */
bool MarkReplacementNotifications(sqlite3* db, int replacementInterval);

/**
 * Retrieves all tags from the database.
 * 
 * @param db The SQLite database connection.
 * @return A vector of Tag objects representing all tags in the database.
 */
std::vector<Tag> GetAllTags(sqlite3* db);

/**
 * Adds a new tag to the database.
 * 
 * @param db The SQLite database connection.
 * @param tagName The name of the tag to add.
 * @return True if the tag was added successfully, false otherwise.
 */
bool AddTag(sqlite3* db, const std::string& tagName);

/**
 * Deletes a tag from the database and removes its associations with passwords.
 * 
 * @param db The SQLite database connection.
 * @param tagId The ID of the tag to delete.
 * @return True if the tag was deleted successfully, false otherwise.
 */
bool DeleteTag(sqlite3* db, int tagId);

/**
 * Adds a tag to a password in the database by associating the password with the tag.
 * 
 * @param db The SQLite database connection.
 * @param passwordId The ID of the password to associate the tag with.
 * @param tagId The ID of the tag to add to the password.
 * @return True if the tag was successfully added to the password, false otherwise.
 */
bool AddTagToPassword(sqlite3* db, int passwordId, int tagId);

/**
 * Retrieves all tags associated with a specific password.
 * 
 * @param db The SQLite database connection.
 * @param passwordId The ID of the password whose tags are to be retrieved.
 * @return A vector of Tag objects representing the tags associated with the password.
 */
std::vector<Tag> GetTagsForPassword(sqlite3* db, int passwordId);