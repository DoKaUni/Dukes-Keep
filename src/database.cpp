#include "database.h"

std::string SerializeIndexes(const std::vector<int>& indexes) {
    std::ostringstream oss;

    for (size_t i = 0; i < indexes.size(); ++i) {
        if (i != 0) oss << ",";
        oss << indexes[i];
    }

    return oss.str();
}

std::vector<int> DeserializeIndexes(const std::string& indexes_str) {
    std::vector<int> indexes;
    std::stringstream ss(indexes_str);
    std::string item;

    while (std::getline(ss, item, ','))
        indexes.push_back(std::stoi(item));

    return indexes;
}

bool OpenDatabase(sqlite3 **db, const char *db_file, const std::vector<unsigned char>& key, bool db_exists) {
    int rc = sqlite3_open(db_file, db);
    if (rc) {
        std::cerr << "Can't open database: " << sqlite3_errmsg(*db) << std::endl;
        return false;
    }
    std::cout << "Opened database successfully!" << std::endl;

    rc = sqlite3_key(*db, key.data(), static_cast<int>(key.size()));
    if (rc != SQLITE_OK) {
        std::cerr << "Failed to set encryption key: " << sqlite3_errmsg(*db) << std::endl;
        sqlite3_close(*db);
        
        return false;
    }
    std::cout << (db_exists ? "Decrypted database with key successfully!" : "Encryption key set successfully for new database!") << std::endl;

    return true;
}

bool InitializeDatabase(sqlite3 *db) {
    const char *create_passwords_table_sql = 
        "CREATE TABLE IF NOT EXISTS passwords ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "name TEXT NOT NULL, "
        "username TEXT, "
        "creation_datetime DATETIME NOT NULL, "
        "last_used_datetime DATETIME, "
        "length INTEGER NOT NULL, "
        "indexes TEXT, "
        "password BLOB NOT NULL, "
        "isDeleted BOOLEAN DEFAULT 0, "
        "gotReplacementNotification BOOLEAN DEFAULT 0);";

    const char *create_tags_table_sql = 
        "CREATE TABLE IF NOT EXISTS tags ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "tag_name TEXT NOT NULL UNIQUE);";

    const char *create_password_tags_table_sql = 
        "CREATE TABLE IF NOT EXISTS password_tags ("
        "password_id INTEGER, "
        "tag_id INTEGER, "
        "PRIMARY KEY (password_id, tag_id), "
        "FOREIGN KEY (password_id) REFERENCES passwords(id), "
        "FOREIGN KEY (tag_id) REFERENCES tags(id));";

    char *err_msg = nullptr;
    int rc;

    rc = sqlite3_exec(db, create_passwords_table_sql, nullptr, nullptr, &err_msg);
    if (rc != SQLITE_OK) {
        std::cerr << "SQL error (creating passwords table): " << err_msg << std::endl;
        sqlite3_free(err_msg);
        return false;
    }
    std::cout << "Passwords table created successfully!" << std::endl;

    rc = sqlite3_exec(db, create_tags_table_sql, nullptr, nullptr, &err_msg);
    if (rc != SQLITE_OK) {
        std::cerr << "SQL error (creating tags table): " << err_msg << std::endl;
        sqlite3_free(err_msg);
        return false;
    }
    std::cout << "Tags table created successfully!" << std::endl;

    rc = sqlite3_exec(db, create_password_tags_table_sql, nullptr, nullptr, &err_msg);
    if (rc != SQLITE_OK) {
        std::cerr << "SQL error (creating password_tags table): " << err_msg << std::endl;
        sqlite3_free(err_msg);
        return false;
    }
    std::cout << "Password_tags table created successfully!" << std::endl;

    return true;
}

void InsertPassword(sqlite3 *db, const std::string &name, const std::string &username, const int &length, const std::vector<int> &indexes, const std::vector<unsigned char> &password,  const std::vector<std::string> &tags) {
    std::string sql = "INSERT INTO passwords (name, username, creation_datetime, length, indexes, password) VALUES (?, ?, datetime('now'), ?, ?, ?);";
    sqlite3_stmt *stmt;

    sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, 0);
    sqlite3_bind_text(stmt, 1, name.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, username.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 3, static_cast<int>(length));
    sqlite3_bind_text(stmt, 4, SerializeIndexes(indexes).c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 5, password.data(), password.size(), SQLITE_STATIC);

    sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    int password_id = sqlite3_last_insert_rowid(db);

    for (const auto &tag : tags) {
        sql = "INSERT OR IGNORE INTO tags (tag_name) VALUES (?);";
        sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, 0);
        sqlite3_bind_text(stmt, 1, tag.c_str(), -1, SQLITE_STATIC);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);

        sql = "SELECT id FROM tags WHERE tag_name = ?;";
        sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, 0);
        sqlite3_bind_text(stmt, 1, tag.c_str(), -1, SQLITE_STATIC);
        sqlite3_step(stmt);
        int tag_id = sqlite3_column_int(stmt, 0);
        sqlite3_finalize(stmt);

        sql = "INSERT INTO password_tags (password_id, tag_id) VALUES (?, ?);";
        sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, 0);
        sqlite3_bind_int(stmt, 1, password_id);
        sqlite3_bind_int(stmt, 2, tag_id);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    }
}

bool SetPasswordDeletedStatus(sqlite3* db, int passwordId, bool isDeleted, const char* changedDateTime) {
    sqlite3_stmt* stmt;
    const char* sql = "UPDATE passwords SET isDeleted = ?, creation_datetime = ? WHERE id = ?";

    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_int(stmt, 1, isDeleted ? 1 : 0);
        sqlite3_bind_text(stmt, 2, changedDateTime, -1, SQLITE_STATIC);
        sqlite3_bind_int(stmt, 3, passwordId);
        bool success = sqlite3_step(stmt) == SQLITE_DONE;
        sqlite3_finalize(stmt);

        return success;
    }

    return false;
}

std::vector<PasswordEntry> GetAllPasswords(sqlite3 *db) {
    std::vector<PasswordEntry> entries;
    const char *sql = "SELECT id, name, username, creation_datetime, last_used_datetime, length, indexes, password, isDeleted, gotReplacementNotification FROM passwords;";
    sqlite3_stmt *stmt;
    
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, 0) != SQLITE_OK)
        return entries;

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const void* blobData = sqlite3_column_blob(stmt, 7);
        int blobSize = sqlite3_column_bytes(stmt, 7);
        std::vector<unsigned char> passwordData;
        if (blobData && blobSize > 0) {
            passwordData.resize(blobSize);
            memcpy(passwordData.data(), blobData, blobSize);
        }

        PasswordEntry entry(
            sqlite3_column_int(stmt, 0),
            reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1)),
            (sqlite3_column_type(stmt, 2) == SQLITE_NULL) ? "" : reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2)),
            reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3)),
            (sqlite3_column_type(stmt, 4) == SQLITE_NULL) ? "" : reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4)),
            sqlite3_column_int(stmt, 5),
            DeserializeIndexes(reinterpret_cast<const char*>(sqlite3_column_text(stmt, 6))),
            passwordData,
            sqlite3_column_int(stmt, 8) != 0,
            sqlite3_column_int(stmt, 9) != 0,
            std::vector<std::string>()
        );

        const char *tag_sql = "SELECT tag_name FROM tags WHERE id IN (SELECT tag_id FROM password_tags WHERE password_id = ?);";
        sqlite3_stmt *tag_stmt;
        if (sqlite3_prepare_v2(db, tag_sql, -1, &tag_stmt, 0) == SQLITE_OK) {
            sqlite3_bind_int(tag_stmt, 1, entry.GetId());

            while (sqlite3_step(tag_stmt) == SQLITE_ROW)
                entry.AddTag(reinterpret_cast<const char*>(sqlite3_column_text(tag_stmt, 0)));

            sqlite3_finalize(tag_stmt);

            entries.push_back(entry);
        }
    }
    sqlite3_finalize(stmt);

    return entries;
}

bool PurgeDeletedPasswords(sqlite3* db, int deletedPasswordKeepTime) {
    sqlite3_stmt* stmt = nullptr;
    bool success = false;

    const char* deleteTagsSql =
        "DELETE FROM password_tags WHERE password_id IN "
        "(SELECT id FROM passwords WHERE isDeleted = 1"
        " AND (? = 0 OR date(creation_datetime) <= date('now', '-' || ? || ' days')))";

    if (sqlite3_prepare_v2(db, deleteTagsSql, -1, &stmt, nullptr) != SQLITE_OK)
        return false;

    sqlite3_bind_int(stmt, 1, deletedPasswordKeepTime);
    sqlite3_bind_int(stmt, 2, deletedPasswordKeepTime);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        return false;
    }
    sqlite3_finalize(stmt);

    const char* deletePasswordsSql =
        "DELETE FROM passwords WHERE isDeleted = 1"
        " AND (? = 0 OR date(creation_datetime) <= date('now', '-' || ? || ' days'))";

    if (sqlite3_prepare_v2(db, deletePasswordsSql, -1, &stmt, nullptr) != SQLITE_OK)
        return false;

    sqlite3_bind_int(stmt, 1, deletedPasswordKeepTime);
    sqlite3_bind_int(stmt, 2, deletedPasswordKeepTime);

    success = sqlite3_step(stmt) == SQLITE_DONE;
    sqlite3_finalize(stmt);

    return success;
}

bool MarkReplacementNotifications(sqlite3* db, int replacementInterval) {
    const char* markReplacementSql =
        "UPDATE passwords "
        "SET gotReplacementNotification = 1 "
        "WHERE date(creation_datetime) <= date('now', ? || ' days') "
        "AND gotReplacementNotification = 0;";

    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db, markReplacementSql, -1, &stmt, nullptr) == SQLITE_OK) {
        std::string interval = "-" + std::to_string(replacementInterval);
        sqlite3_bind_text(stmt, 1, interval.c_str(), -1, SQLITE_STATIC);
        bool success = sqlite3_step(stmt) == SQLITE_DONE;
        sqlite3_finalize(stmt);

        return success;
    }

    return false;
}

std::vector<Tag> GetAllTags(sqlite3* db) {
    std::vector<Tag> tags;
    sqlite3_stmt* stmt;
    const char* sql = "SELECT id, tag_name FROM tags";
    
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) == SQLITE_OK) {
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            int id = sqlite3_column_int(stmt, 0);
            const char* name = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
            tags.emplace_back(id, name ? name : "");
        }
        sqlite3_finalize(stmt);
    }

    return tags;
}

bool AddTag(sqlite3* db, const std::string& tagName) {
    sqlite3_stmt* stmt;
    const char* sql = "INSERT INTO tags (tag_name) VALUES (?)";
    
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, tagName.c_str(), -1, SQLITE_TRANSIENT);
        bool success = sqlite3_step(stmt) == SQLITE_DONE;
        sqlite3_finalize(stmt);

        return success;
    }

    return false;
}

bool DeleteTag(sqlite3* db, int tagId) {
    const char* deleteAssocSql = "DELETE FROM password_tags WHERE tag_id = ?";
    sqlite3_stmt* stmt;
    
    if (sqlite3_prepare_v2(db, deleteAssocSql, -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_int(stmt, 1, tagId);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    }
    
    const char* deleteTagSql = "DELETE FROM tags WHERE id = ?";
    if (sqlite3_prepare_v2(db, deleteTagSql, -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_int(stmt, 1, tagId);
        bool success = sqlite3_step(stmt) == SQLITE_DONE;
        sqlite3_finalize(stmt);

        return success;
    }

    return false;
}

bool AddTagToPassword(sqlite3* db, int passwordId, int tagId) {
    sqlite3_stmt* stmt;
    const char* sql = "INSERT INTO password_tags (password_id, tag_id) VALUES (?, ?)";
    
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_int(stmt, 1, passwordId);
        sqlite3_bind_int(stmt, 2, tagId);
        bool success = sqlite3_step(stmt) == SQLITE_DONE;
        sqlite3_finalize(stmt);

        return success;
    }

    return false;
}

std::vector<Tag> GetTagsForPassword(sqlite3* db, int passwordId) {
    std::vector<Tag> tags;
    const char* sql = "SELECT t.id, t.tag_name FROM tags t "
                     "JOIN password_tags pt ON t.id = pt.tag_id "
                     "WHERE pt.password_id = ?";
    sqlite3_stmt* stmt;
    
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_int(stmt, 1, passwordId);

        while (sqlite3_step(stmt) == SQLITE_ROW) {
            int id = sqlite3_column_int(stmt, 0);
            const char* name = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
            tags.emplace_back(id, name ? name : "");
        }
        sqlite3_finalize(stmt);
    }

    return tags;
}
