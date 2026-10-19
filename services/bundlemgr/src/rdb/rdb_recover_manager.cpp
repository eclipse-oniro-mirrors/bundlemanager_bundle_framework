/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// Snapshot salvage recovery of the bms rdb databases. The interface lives in
// rdb_recover_manager.h; RdbDataManager owns the rdb store and calls into this
// manager while opening the db.

#include <cctype>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <dirent.h>
#include <fcntl.h>
#include <fstream>
#include <memory>
#include <mutex>
#include <set>
#include <strings.h>
#include <sys/stat.h>
#include <unistd.h>
#include <unordered_map>

#include "bms_rdb_open_callback.h"
#include "bundle_service_constants.h"
#include "rdb_recover_manager.h"

#include "app_log_wrapper.h"
#include "event_report.h"
#include "hitrace_meter.h"
#include "installd_client.h"
#include "scope_guard.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr const char* SNAPSHOT_MAGIC = "BMS_SNAPSHOT_V1";
constexpr const char* SNAPSHOT_KEY_DBINFO = "DBINFO";
constexpr const char* SNAPSHOT_KEY_TABLE = "TABLE";
constexpr const char* SNAPSHOT_KEY_SCHEMA = "SCHEMA";
constexpr const char* SNAPSHOT_KEY_COLS = "COLS";
constexpr const char* SNAPSHOT_KEY_ROW = "R";
constexpr const char* SNAPSHOT_KEY_END = "END";
constexpr const char* SNAPSHOT_KEY_MISSING = "MISSING";
constexpr const char* SNAPSHOT_KEY_EOF = "EOF";
// snapshot line field indexes: every line is key 	 field1 	 ... (see the
// format comment above RestoreFromSnapshotFile for the per-key layouts)
constexpr size_t FIELD_INDEX_KEY = 0;
constexpr size_t FIELD_INDEX_FIRST = 1;
constexpr size_t FIELD_INDEX_SECOND = 2;
constexpr size_t FIELD_INDEX_THIRD = 3;
// total field count (key included) of the fixed-layout lines
constexpr size_t DBINFO_FIELD_COUNT = 3;
constexpr size_t EOF_FIELD_COUNT = 3;
constexpr size_t MISSING_FIELD_COUNT = 2;
constexpr size_t TABLE_FIELD_COUNT = 3;
constexpr size_t SCHEMA_FIELD_COUNT = 2;
constexpr size_t END_FIELD_COUNT = 4;
// INT32_MAX has 10 digits, anything longer can never be a valid count
constexpr size_t MAX_COUNT_DIGITS = 10;
// sqlite reserves the "sqlite_" prefix case-insensitively
constexpr size_t SQLITE_PREFIX_LEN = 7;
// defensive bound for the leftover directory recursion
constexpr int32_t MAX_REMOVE_DIR_DEPTH = 64;
constexpr const char* SQLITE_MASTER_TABLES_SQL =
    "SELECT name, sql FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'";
constexpr const char* TABLE_EXISTS_SQL = "SELECT COUNT(1) FROM sqlite_master WHERE type='table' AND name=?";
constexpr const char* COMPLETE_FLAG = "1";
constexpr const char* INCOMPLETE_FLAG = "0";
// tables that the boot scan can fully rebuild from install dirs; other tables
// lost from the snapshot are lost for good and must not trigger the rescan
const std::set<std::string> CORE_REBUILDABLE_TABLES = {
    ServiceConstants::INSTALLED_BUNDLE_TABLE,
    ServiceConstants::PREINSTALLED_BUNDLE_TABLE,
    ServiceConstants::APP_PROVISION_INFO_TABLE,
};
enum class SnapshotWriteResult {
    // the whole table was read and written
    COMPLETE = 0,
    // the table block was written but some rows could not be read
    PARTIAL,
    // the table exists but nothing could be read, no block was written
    UNREADABLE,
    // writing the snapshot file itself failed
    WRITE_FAILED,
};

// state shared by all recovery entry points, keyed by db name because several
// RdbDataManager instances share one db file; the db name must stay unique per
// db file in this process (every production storage manager uses its own db
// name), otherwise the coordination state would cross-wire between databases
std::mutex g_recoverStateMutex;
std::set<std::string> g_recoveringDbs;
// dbs whose salvage export failed and must not be served by any instance
std::set<std::string> g_corruptionDetectedDbs;
std::unordered_map<std::string, uint64_t> g_dbGenerations;
std::unordered_map<std::string, int32_t> g_replayFailCounts;
// registry of the per-db shared operation locks used by RdbOpGuard and the
// recovery exclusive sections
std::mutex g_dbOpMutexRegistryMutex;
std::unordered_map<std::string, std::unique_ptr<std::shared_mutex>> g_dbOpMutexes;
// after this many failed replay attempts the snapshot is treated as unsalvageable
// and the recovery downgrades to an empty db instead of retrying forever
constexpr int32_t MAX_SNAPSHOT_REPLAY_ATTEMPTS = 3;

// marks the db as under recovery for the whole scope: other instances of the same
// db stop serving their cached stores while the db is being deleted and replayed
class RecoverScope {
public:
    explicit RecoverScope(const std::string &dbName) : dbName_(dbName)
    {
        std::lock_guard<std::mutex> lock(g_recoverStateMutex);
        g_recoveringDbs.insert(dbName_);
    }

    ~RecoverScope()
    {
        std::lock_guard<std::mutex> lock(g_recoverStateMutex);
        g_recoveringDbs.erase(dbName_);
    }

    RecoverScope(const RecoverScope &) = delete;
    RecoverScope &operator=(const RecoverScope &) = delete;

private:
    std::string dbName_;
};

// remove one directory entry of an open directory fd: real directories are
// removed recursively, everything else (files, symlinks) is unlinked without
// ever being followed. All operations are relative to dirFd, so a concurrent
// rename of the entry cannot redirect the deletion.
bool RemoveDirEntrySafely(int dirFd, const std::string &name, int32_t depth)
{
    if (depth > MAX_REMOVE_DIR_DEPTH) {
        APP_LOGW("remove dir aborted, too deep: %{public}s", name.c_str());
        return false;
    }
    struct stat st = {};
    if (fstatat(dirFd, name.c_str(), &st, AT_SYMLINK_NOFOLLOW) != 0) {
        return false;
    }
    if (!S_ISDIR(st.st_mode)) {
        return unlinkat(dirFd, name.c_str(), 0) == 0;
    }
    int childFd = openat(dirFd, name.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (childFd < 0) {
        // a symlink to a directory fails O_NOFOLLOW|O_DIRECTORY and is unlinked
        return unlinkat(dirFd, name.c_str(), 0) == 0;
    }
    DIR *childPtr = fdopendir(childFd);
    if (childPtr == nullptr) {
        close(childFd);
        return false;
    }
    ScopeGuard childGuard([&] { closedir(childPtr); });
    struct dirent *entry = nullptr;
    while ((entry = readdir(childPtr)) != nullptr) {
        std::string entryName = entry->d_name;
        if (entryName == "." || entryName == "..") {
            continue;
        }
        if (!RemoveDirEntrySafely(childFd, entryName, depth + 1)) {
            return false;
        }
    }
    closedir(childPtr);
    childGuard.Dismiss();
    return unlinkat(dirFd, name.c_str(), AT_REMOVEDIR) == 0;
}

// remove a directory tree by path without ever following symlinks and without
// TOCTOU between the type check and the deletion
bool RemoveDirSafely(const std::string &path, int32_t depth)
{
    if (depth > MAX_REMOVE_DIR_DEPTH) {
        APP_LOGW("remove dir aborted, too deep: %{public}s", path.c_str());
        return false;
    }
    size_t slash = path.find_last_of('/');
    if (slash == std::string::npos || slash == 0 || slash + 1 >= path.size()) {
        return false;
    }
    std::string parent = path.substr(0, slash);
    std::string name = path.substr(slash + 1);
    int parentFd = open(parent.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (parentFd < 0) {
        return false;
    }
    bool removed = RemoveDirEntrySafely(parentFd, name, depth);
    close(parentFd);
    return removed;
}

// the snapshot schema must be a single CREATE TABLE statement: the snapshot is a
// semi-trusted file and anything else must never reach ExecuteSql
bool IsValidCreateTableSql(const std::string &createSql)
{
    static constexpr char CREATE_TABLE_PREFIX[] = "CREATE TABLE";
    size_t bodyStart = createSql.find_first_not_of(" \t\r\n");
    if (bodyStart == std::string::npos ||
        createSql.size() - bodyStart < sizeof(CREATE_TABLE_PREFIX) - 1) {
        return false;
    }
    for (size_t i = 0; i < sizeof(CREATE_TABLE_PREFIX) - 1; i++) {
        if (std::toupper(static_cast<unsigned char>(createSql[bodyStart + i])) !=
            CREATE_TABLE_PREFIX[i]) {
            return false;
        }
    }
    std::string body = createSql.substr(bodyStart);
    size_t lastChar = body.find_last_not_of(" \t\r\n");
    if (lastChar != std::string::npos && body[lastChar] == ';') {
        body = body.substr(0, lastChar);
    }
    // no additional statements may hide behind the table definition
    return body.find(';') == std::string::npos;
}

// Snapshot file format (all fields tab separated and escaped, one line per record):
//   BMS_SNAPSHOT_V1
//   DBINFO\t<dbName>\t<schemaVersion>   (db identity stamp, mismatch is rejected)
//   TABLE\t<name>\t<colCount>
//   SCHEMA\t<createSql>
//   COLS\t<col1>\t...\t<colN>
//   R\t<field1>\t...\t<fieldN>   (one line per row)
//   END\t<name>\t<rowCount>\t<completeFlag>
//   MISSING\t<name>              (table exists in db but nothing could be read)
//   EOF\t<tableCount>\t<enumeratedFlag>
// fields escape \\, \n, \r, \t and \0 with a backslash prefix so a row can never
// be truncated or split by its own content;
// completeFlag records whether the table was read fully from the corrupted db;
// enumeratedFlag records whether sqlite_master was iterated without error, when
// it is 0 the snapshot may be silently missing tables nobody knows the names of.

void AppendEscapedField(std::string &out, const std::string &field)
{
    for (char c : field) {
        switch (c) {
            case '\\':
                out += "\\\\";
                break;
            case '\n':
                out += "\\n";
                break;
            case '\r':
                out += "\\r";
                break;
            case '\t':
                out += "\\t";
                break;
            case '\0':
                out += "\\0";
                break;
            default:
                out += c;
                break;
        }
    }
}

bool UnescapeField(const std::string &line, size_t begin, size_t end, std::string &field)
{
    field.clear();
    for (size_t i = begin; i < end; i++) {
        if (line[i] != '\\') {
            field += line[i];
            continue;
        }
        i++;
        if (i >= end) {
            return false;
        }
        switch (line[i]) {
            case '\\':
                field += '\\';
                break;
            case 'n':
                field += '\n';
                break;
            case 'r':
                field += '\r';
                break;
            case 't':
                field += '\t';
                break;
            case '0':
                field += '\0';
                break;
            default:
                return false;
        }
    }
    return true;
}

bool SplitSnapshotLine(const std::string &line, std::vector<std::string> &fields)
{
    fields.clear();
    size_t begin = 0;
    for (size_t i = 0; i <= line.size(); i++) {
        if (i == line.size() || line[i] == '\t') {
            std::string field;
            if (!UnescapeField(line, begin, i, field)) {
                return false;
            }
            fields.push_back(std::move(field));
            begin = i + 1;
        }
    }
    return true;
}

bool ParseSnapshotCount(const std::string &text, int32_t &value)
{
    if (text.empty() || text.size() > MAX_COUNT_DIGITS) {
        return false;
    }
    int64_t result = 0;
    for (char c : text) {
        if (c < '0' || c > '9') {
            return false;
        }
        result = result * 10 + (c - '0');
        if (result > INT32_MAX) {
            return false;
        }
    }
    value = static_cast<int32_t>(result);
    return true;
}

std::string QuoteIdentifier(const std::string &identifier)
{
    std::string quoted = "\"";
    for (char c : identifier) {
        quoted += c;
        if (c == '"') {
            quoted += '"';
        }
    }
    quoted += '"';
    return quoted;
}

bool WriteFileLine(FILE *file, const std::string &text)
{
    return fputs(text.c_str(), file) != EOF && fputs("\n", file) != EOF;
}

void SyncParentDir(const std::string &filePath)
{
    size_t pos = filePath.find_last_of('/');
    if (pos == std::string::npos || pos == 0) {
        return;
    }
    std::string dir = filePath.substr(0, pos);
    int32_t fd = open(dir.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0) {
        return;
    }
    fsync(fd);
    close(fd);
}

bool IsTableExists(const std::shared_ptr<NativeRdb::RdbStore> &store, const std::string &tableName)
{
    if (store == nullptr) {
        return false;
    }
    NativeRdb::RdbStore::Values args;
    args.emplace_back(tableName);
    auto rs = store->QuerySql(TABLE_EXISTS_SQL, args);
    if (rs == nullptr) {
        return false;
    }
    ScopeGuard rsGuard([&] { rs->Close(); });
    if (rs->GoToFirstRow() != NativeRdb::E_OK) {
        return false;
    }
    int32_t count = 0;
    if (rs->GetInt(0, count) != NativeRdb::E_OK) {
        return false;
    }
    return count > 0;
}

bool IsCoreRebuildableTable(const std::string &tableName)
{
    return CORE_REBUILDABLE_TABLES.find(tableName) != CORE_REBUILDABLE_TABLES.end();
}

SnapshotWriteResult WriteSnapshotTable(const std::shared_ptr<NativeRdb::RdbStore> &store, FILE *file,
    const std::string &tableName, const std::string &createSql)
{
    auto rowsRs = store->QuerySql("SELECT * FROM " + QuoteIdentifier(tableName));
    if (rowsRs == nullptr) {
        APP_LOGW_NOFUNC("query table %{public}s failed, exported as unreadable", tableName.c_str());
        return SnapshotWriteResult::UNREADABLE;
    }
    ScopeGuard rsGuard([&] { rowsRs->Close(); });
    int32_t colCount = 0;
    if (rowsRs->GetColumnCount(colCount) != NativeRdb::E_OK || colCount <= 0) {
        APP_LOGW_NOFUNC("get columns of %{public}s failed, exported as unreadable", tableName.c_str());
        return SnapshotWriteResult::UNREADABLE;
    }
    std::string line = std::string(SNAPSHOT_KEY_TABLE) + "\t";
    AppendEscapedField(line, tableName);
    line += "\t" + std::to_string(colCount);
    line += std::string("\n") + SNAPSHOT_KEY_SCHEMA + "\t";
    AppendEscapedField(line, createSql);
    line += std::string("\n") + SNAPSHOT_KEY_COLS;
    for (int32_t i = 0; i < colCount; i++) {
        std::string colName;
        if (rowsRs->GetColumnName(i, colName) != NativeRdb::E_OK || colName.empty()) {
            APP_LOGW_NOFUNC("get column name of %{public}s failed, exported as unreadable", tableName.c_str());
            return SnapshotWriteResult::UNREADABLE;
        }
        line += "\t";
        AppendEscapedField(line, colName);
    }
    if (!WriteFileLine(file, line)) {
        return SnapshotWriteResult::WRITE_FAILED;
    }
    bool tableComplete = true;
    int32_t rowCount = 0;
    int32_t rr = rowsRs->GoToFirstRow();
    if (rr != NativeRdb::E_OK && rr != NativeRdb::E_NO_MORE_ROWS) {
        APP_LOGW_NOFUNC("read table %{public}s failed at first row, exported as incomplete", tableName.c_str());
        tableComplete = false;
    }
    std::string rowLine;
    while (rr == NativeRdb::E_OK) {
        rowLine.assign(SNAPSHOT_KEY_ROW);
        bool rowOk = true;
        for (int32_t i = 0; i < colCount; i++) {
            std::string value;
            if (rowsRs->GetString(i, value) != NativeRdb::E_OK) {
                rowOk = false;
                break;
            }
            rowLine += "\t";
            AppendEscapedField(rowLine, value);
        }
        if (!rowOk) {
            APP_LOGW_NOFUNC("read table %{public}s stopped at row %{public}d, exported partially",
                tableName.c_str(), rowCount);
            tableComplete = false;
            break;
        }
        if (!WriteFileLine(file, rowLine)) {
            return SnapshotWriteResult::WRITE_FAILED;
        }
        rowCount++;
        rr = rowsRs->GoToNextRow();
    }
    if (tableComplete && rr != NativeRdb::E_OK && rr != NativeRdb::E_NO_MORE_ROWS) {
        APP_LOGW_NOFUNC("iterate table %{public}s stopped by error, ret:%{public}d", tableName.c_str(), rr);
        tableComplete = false;
    }
    line.assign(SNAPSHOT_KEY_END).append("\t");
    AppendEscapedField(line, tableName);
    line += "\t" + std::to_string(rowCount) + "\t" + (tableComplete ? COMPLETE_FLAG : INCOMPLETE_FLAG);
    if (!WriteFileLine(file, line)) {
        return SnapshotWriteResult::WRITE_FAILED;
    }
    return tableComplete ? SnapshotWriteResult::COMPLETE : SnapshotWriteResult::PARTIAL;
}

// Export the whole snapshot content (magic, db info, every table from
// sqlite_master, EOF line). Returns false when writing the file failed.
bool WriteSnapshotTables(const std::string &dbName, int32_t dbVersion,
    const std::shared_ptr<NativeRdb::RdbStore> &store, FILE *file,
    int32_t &tableCount, bool &allTablesEnumerated)
{
    tableCount = 0;
    allTablesEnumerated = true;
    if (!WriteFileLine(file, SNAPSHOT_MAGIC)) {
        return false;
    }
    // stamp the snapshot with the db identity and schema version so a stale
    // snapshot of another db (or another schema era, e.g. after an OTA
    // rollback) is rejected instead of replayed over newer data
    std::string dbInfoLine = std::string(SNAPSHOT_KEY_DBINFO) + "\t";
    AppendEscapedField(dbInfoLine, dbName);
    dbInfoLine += "\t" + std::to_string(dbVersion);
    if (!WriteFileLine(file, dbInfoLine)) {
        return false;
    }
    auto tablesRs = store->QuerySql(SQLITE_MASTER_TABLES_SQL);
    if (tablesRs == nullptr) {
        APP_LOGW_NOFUNC("query sqlite_master failed, snapshot may miss tables");
        allTablesEnumerated = false;
        return true;
    }
    ScopeGuard rsGuard([&] { tablesRs->Close(); });
    int32_t tr = tablesRs->GoToFirstRow();
    while (tr == NativeRdb::E_OK) {
        std::string tableName;
        std::string createSql;
        bool tableReadable = tablesRs->GetString(0, tableName) == NativeRdb::E_OK &&
            tablesRs->GetString(1, createSql) == NativeRdb::E_OK &&
            !tableName.empty() && !createSql.empty();
        if (tableReadable) {
            SnapshotWriteResult result = WriteSnapshotTable(store, file, tableName, createSql);
            if (result == SnapshotWriteResult::WRITE_FAILED) {
                return false;
            }
            if (result == SnapshotWriteResult::UNREADABLE) {
                // record the name so the restore knows this table's data is
                // lost entirely instead of silently missing from the snapshot
                std::string missingLine = std::string(SNAPSHOT_KEY_MISSING) + "\t";
                AppendEscapedField(missingLine, tableName);
                if (!WriteFileLine(file, missingLine)) {
                    return false;
                }
            } else {
                tableCount++;
            }
        } else {
            // an sqlite_master row itself is unreadable, so the table list is
            // incomplete and the lost tables cannot be named
            allTablesEnumerated = false;
        }
        tr = tablesRs->GoToNextRow();
    }
    if (tr != NativeRdb::E_OK && tr != NativeRdb::E_NO_MORE_ROWS) {
        APP_LOGW_NOFUNC("iterate sqlite_master stopped by error, ret:%{public}d", tr);
        allTablesEnumerated = false;
    }
    std::string eofLine = std::string(SNAPSHOT_KEY_EOF) + "\t" + std::to_string(tableCount) + "\t" +
        (allTablesEnumerated ? COMPLETE_FLAG : INCOMPLETE_FLAG);
    return WriteFileLine(file, eofLine);
}
}

bool RdbRecoverManager::MarkRebuildIfDataIncomplete(const std::string &dbName,
    const std::shared_ptr<NativeRdb::RdbStore> &rdbStore)
{
    // only the main bms db keeps the rebuild mark; other dbs have no bms_param
    // and no rescan either, so there is nothing to signal for them
    if (dbName != ServiceConstants::BUNDLE_RDB_NAME) {
        return true;
    }
    if (rdbStore == nullptr) {
        return false;
    }
    int32_t ret = rdbStore->ExecuteSql(std::string("CREATE TABLE IF NOT EXISTS ") +
        ServiceConstants::BMS_PARAM_TABLE_NAME + "(" + ServiceConstants::BMS_KEY +
        " TEXT NOT NULL PRIMARY KEY, " + ServiceConstants::BMS_VALUE + " TEXT NOT NULL);");
    if (ret != NativeRdb::E_OK) {
        APP_LOGE("create %{public}s for rebuild mark failed, ret:%{public}d",
            ServiceConstants::BMS_PARAM_TABLE_NAME, ret);
        return false;
    }
    NativeRdb::RdbStore::Values args;
    args.emplace_back(std::string(ServiceConstants::DB_REBUILD_MARK));
    args.emplace_back(std::string(ServiceConstants::DB_REBUILD_MARK_DOING));
    ret = rdbStore->ExecuteSql(std::string("INSERT OR REPLACE INTO ") +
        ServiceConstants::BMS_PARAM_TABLE_NAME + "(" + ServiceConstants::BMS_KEY + ", " +
        ServiceConstants::BMS_VALUE + ") VALUES(?, ?)", args);
    if (ret != NativeRdb::E_OK) {
        APP_LOGE("save db rebuild mark failed, ret:%{public}d", ret);
        return false;
    }
    APP_LOGW("salvaged data may be incomplete, db rebuild mark set for rebuild from install dirs");
    return true;
}

bool RdbRecoverManager::RenameSnapshotToFailed(const std::string &dbName, const std::string &dbFile,
    const std::string &snapshotPath)
{
    std::string failedPath = dbFile + ServiceConstants::RDB_SNAPSHOT_FAILED_SUFFIX;
    if (rename(snapshotPath.c_str(), failedPath.c_str()) != 0) {
        APP_LOGE("rename invalid snapshot to failed failed, errno:%{public}d", errno);
        return false;
    }
    // the failed file is kept for forensics and makes BMSEventHandler distrust the db
    EventReport::SendDbErrorEvent(dbName, static_cast<int32_t>(DB_OPERATION_TYPE::REBUILD),
        NativeRdb::E_SQLITE_CORRUPT);
    return true;
}

bool RdbRecoverManager::WriteSnapshotFile(const BmsRdbConfig &bmsRdbConfig,
    const std::shared_ptr<NativeRdb::RdbStore> &rdbStore, const std::string &snapshotPath)
{
    if (rdbStore == nullptr) {
        APP_LOGE("RdbStore is null");
        return false;
    }
    std::string dbFile = bmsRdbConfig.dbPath + bmsRdbConfig.dbName;
    std::string tmpPath = dbFile + ServiceConstants::RDB_SNAPSHOT_TMP_SUFFIX;
    int32_t fd = open(tmpPath.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC,
        S_IRUSR | S_IWUSR);
    if (fd < 0) {
        APP_LOGE("open snapshot tmp file failed, path:%{public}s, errno:%{public}d",
            tmpPath.c_str(), errno);
        return false;
    }
    FILE *file = fdopen(fd, "w");
    if (file == nullptr) {
        APP_LOGE("fdopen snapshot tmp file failed, errno:%{public}d", errno);
        close(fd);
        return false;
    }
    int32_t tableCount = 0;
    bool allTablesEnumerated = true;
    bool contentOk = WriteSnapshotTables(bmsRdbConfig.dbName, bmsRdbConfig.version, rdbStore,
        file, tableCount, allTablesEnumerated);
    int32_t writeFlag = ferror(file);
    if (contentOk && writeFlag == 0) {
        contentOk = fflush(file) == 0 && fsync(fileno(file)) == 0;
    }
    int32_t writeErrno = errno;
    fclose(file);
    if (!contentOk) {
        unlink(tmpPath.c_str());
        APP_LOGE("write snapshot failed, path:%{public}s, ferror:%{public}d, errno:%{public}d",
            snapshotPath.c_str(), writeFlag, writeErrno);
        return false;
    }
    if (rename(tmpPath.c_str(), snapshotPath.c_str()) != 0) {
        unlink(tmpPath.c_str());
        APP_LOGE("rename snapshot tmp file failed, path:%{public}s, errno:%{public}d",
            snapshotPath.c_str(), errno);
        return false;
    }
    SyncParentDir(snapshotPath);
    APP_LOGI("snapshot exported, path:%{public}s, tables:%{public}d, enumerated:%{public}d",
        snapshotPath.c_str(), tableCount, allTablesEnumerated);
    return true;
}

bool RdbRecoverManager::RestoreFromSnapshotFile(const std::string &dbName, int32_t dbVersion,
    const std::shared_ptr<NativeRdb::RdbStore> &rdbStore, const std::string &snapshotPath,
    bool &snapshotInvalid, int32_t &errCode)
{
    snapshotInvalid = false;
    errCode = NativeRdb::E_OK;
    if (rdbStore == nullptr) {
        APP_LOGE("RdbStore is null");
        errCode = NativeRdb::E_SQLITE_ERROR;
        return false;
    }
    // refuse symlinks so the reader cannot be pointed somewhere else; note that
    // no size or line length limits are imposed on purpose: real app data (e.g.
    // the serialized bundle info of large apps) can be arbitrarily big and a
    // wrongly rejected snapshot means real data loss, which outweighs the
    // crafted-file memory risk inside this foundation-owned directory
    struct stat snapshotStat = {};
    if (lstat(snapshotPath.c_str(), &snapshotStat) != 0) {
        APP_LOGE("stat snapshot failed, path:%{public}s, errno:%{public}d", snapshotPath.c_str(), errno);
        snapshotInvalid = true;
        return true;
    }
    if (S_ISLNK(snapshotStat.st_mode)) {
        APP_LOGE("snapshot is a symlink, path:%{public}s", snapshotPath.c_str());
        snapshotInvalid = true;
        return true;
    }
    std::ifstream in(snapshotPath);
    if (!in.is_open()) {
        // errno is not guaranteed meaningful after an ifstream failure, the
        // preceding lstat already told whether the file is reachable
        APP_LOGE("open snapshot failed, path:%{public}s", snapshotPath.c_str());
        snapshotInvalid = true;
        return true;
    }
    std::string line;
    if (!std::getline(in, line) || line != SNAPSHOT_MAGIC) {
        APP_LOGE("snapshot magic mismatch, path:%{public}s", snapshotPath.c_str());
        snapshotInvalid = true;
        return true;
    }
    bool coreDataIncomplete = false;
    bool sawEof = false;
    bool sawDbInfo = false;
    size_t lineNo = 0;
    size_t firstInvalidLine = 0;
    // record the first invalid line so the forensics .recover.failed file can be
    // matched against the log without parsing it by hand
    auto markInvalid = [&]() {
        if (!snapshotInvalid) {
            snapshotInvalid = true;
            firstInvalidLine = lineNo;
        }
    };
    int32_t tableCount = 0;
    std::vector<std::string> fields;
    while (!sawEof && std::getline(in, line)) {
        lineNo++;
        if (!SplitSnapshotLine(line, fields) || fields.empty()) {
            markInvalid();
            break;
        }
        if (fields[FIELD_INDEX_KEY] == SNAPSHOT_KEY_DBINFO) {
            sawDbInfo = true;
            // the snapshot must belong to this db and schema era, a mismatch
            // means it is stale (e.g. left over across an OTA rollback)
            int32_t snapshotVersion = 0;
            if (fields.size() != DBINFO_FIELD_COUNT || fields[FIELD_INDEX_FIRST] != dbName ||
                !ParseSnapshotCount(fields[FIELD_INDEX_SECOND], snapshotVersion) ||
                snapshotVersion != dbVersion) {
                APP_LOGE("snapshot db info mismatch, db:%{public}s, snapshot db:%{public}s",
                    dbName.c_str(), fields.size() > FIELD_INDEX_FIRST ?
                        fields[FIELD_INDEX_FIRST].c_str() : "");
                markInvalid();
                break;
            }
            continue;
        }
        if (fields[FIELD_INDEX_KEY] == SNAPSHOT_KEY_EOF) {
            int32_t eofTableCount = 0;
            if (fields.size() != EOF_FIELD_COUNT ||
                !ParseSnapshotCount(fields[FIELD_INDEX_FIRST], eofTableCount) ||
                eofTableCount != tableCount) {
                markInvalid();
                break;
            }
            if (!sawDbInfo) {
                // every snapshot written by this code carries the db stamp; a
                // missing one means the file was crafted or truncated
                APP_LOGE("snapshot db info line missing");
                markInvalid();
                break;
            }
            if (fields[FIELD_INDEX_SECOND] != COMPLETE_FLAG) {
                // sqlite_master was not fully enumerated, tables nobody knows the
                // names of may be missing, so be conservative about the core ones
                coreDataIncomplete = true;
            }
            sawEof = true;
            break;
        }
        if (fields[FIELD_INDEX_KEY] == SNAPSHOT_KEY_MISSING) {
            if (fields.size() != MISSING_FIELD_COUNT) {
                markInvalid();
                break;
            }
            if (IsCoreRebuildableTable(fields[FIELD_INDEX_FIRST])) {
                coreDataIncomplete = true;
            } else {
                // cannot be rebuilt from install dirs, the loss is permanent
                APP_LOGW("table %{public}s was unreadable, its data is lost",
                    fields[FIELD_INDEX_FIRST].c_str());
            }
            continue;
        }
        int32_t colCount = 0;
        if (fields[FIELD_INDEX_KEY] != SNAPSHOT_KEY_TABLE ||
            fields.size() != TABLE_FIELD_COUNT ||
            !ParseSnapshotCount(fields[FIELD_INDEX_SECOND], colCount) || colCount <= 0) {
            markInvalid();
            break;
        }
        std::string tableName = fields[FIELD_INDEX_FIRST];
        if (strncasecmp(tableName.c_str(), "sqlite_", SQLITE_PREFIX_LEN) == 0) {
            // internal tables are never exported, replaying one would corrupt
            // e.g. the autoincrement sequence
            APP_LOGE("snapshot table %{public}s is a sqlite internal table", tableName.c_str());
            markInvalid();
            break;
        }
        if (!std::getline(in, line) || !SplitSnapshotLine(line, fields) ||
            fields.size() != SCHEMA_FIELD_COUNT ||
            fields[FIELD_INDEX_KEY] != SNAPSHOT_KEY_SCHEMA) {
            lineNo++;
            markInvalid();
            break;
        }
        std::string createSql = fields[FIELD_INDEX_FIRST];
        if (!std::getline(in, line) || !SplitSnapshotLine(line, fields) ||
            fields.size() != static_cast<size_t>(colCount) + 1 ||
            fields[FIELD_INDEX_KEY] != SNAPSHOT_KEY_COLS) {
            lineNo++;
            markInvalid();
            break;
        }
        std::vector<std::string> cols(fields.begin() + FIELD_INDEX_FIRST, fields.end());
        // create the table with the schema the salvaged data belongs to if it does
        // not exist yet, the owning manager's CreateTable later becomes a no-op
        if (!IsTableExists(rdbStore, tableName)) {
            if (!IsValidCreateTableSql(createSql)) {
                APP_LOGW("snapshot schema of %{public}s is not a plain CREATE TABLE, rejected",
                    tableName.c_str());
                markInvalid();
                break;
            }
            int32_t ret = rdbStore->ExecuteSql(createSql);
            if (ret != NativeRdb::E_OK) {
                APP_LOGE("create table %{public}s from snapshot failed, ret:%{public}d",
                    tableName.c_str(), ret);
                errCode = ret;
                return false;
            }
        }
        int32_t txRet = rdbStore->BeginTransaction();
        if (txRet != NativeRdb::E_OK) {
            APP_LOGE("begin transaction for %{public}s failed, ret:%{public}d",
                tableName.c_str(), txRet);
            errCode = txRet;
            return false;
        }
        // clear leftovers of an interrupted replay first, then insert with the
        // salvaged primary keys, so replaying is idempotent and never duplicates
        // autoincrement rows
        txRet = rdbStore->ExecuteSql("DELETE FROM " + QuoteIdentifier(tableName));
        bool txOk = txRet == NativeRdb::E_OK;
        if (!txOk) {
            APP_LOGE("delete table %{public}s before restore failed, ret:%{public}d",
                tableName.c_str(), txRet);
        }
        std::string insertSql;
        if (txOk) {
            insertSql = "INSERT INTO " + QuoteIdentifier(tableName) + "(";
            std::string placeholders;
            for (int32_t i = 0; i < colCount; i++) {
                insertSql += QuoteIdentifier(cols[static_cast<size_t>(i)]);
                placeholders += "?";
                if (i != colCount - 1) {
                    insertSql += ",";
                    placeholders += ",";
                }
            }
            insertSql += ") VALUES(" + placeholders + ")";
        }
        int32_t rowCount = 0;
        bool sawEnd = false;
        while (txOk && std::getline(in, line)) {
            lineNo++;
            if (!SplitSnapshotLine(line, fields) || fields.empty()) {
                markInvalid();
                txOk = false;
                break;
            }
            if (fields[FIELD_INDEX_KEY] == SNAPSHOT_KEY_END) {
                int32_t endRowCount = 0;
                if (fields.size() != END_FIELD_COUNT ||
                    fields[FIELD_INDEX_FIRST] != tableName ||
                    !ParseSnapshotCount(fields[FIELD_INDEX_SECOND], endRowCount) ||
                    endRowCount != rowCount) {
                    markInvalid();
                    txOk = false;
                    break;
                }
                sawEnd = true;
                if (fields[FIELD_INDEX_THIRD] != COMPLETE_FLAG) {
                    if (IsCoreRebuildableTable(tableName)) {
                        coreDataIncomplete = true;
                    } else {
                        // salvaged partially and cannot be rebuilt from install dirs
                        APP_LOGW("table %{public}s was salvaged partially, some rows are lost",
                            tableName.c_str());
                    }
                }
                break;
            }
            if (fields[FIELD_INDEX_KEY] != SNAPSHOT_KEY_ROW ||
                fields.size() != static_cast<size_t>(colCount) + 1) {
                markInvalid();
                txOk = false;
                break;
            }
            NativeRdb::RdbStore::Values args;
            args.reserve(colCount);
            for (size_t i = FIELD_INDEX_FIRST; i < fields.size(); i++) {
                args.emplace_back(fields[i]);
            }
            int32_t insertRet = rdbStore->ExecuteSql(insertSql, args);
            if (insertRet != NativeRdb::E_OK) {
                APP_LOGE("insert into %{public}s from snapshot failed, ret:%{public}d",
                    tableName.c_str(), insertRet);
                errCode = insertRet;
                txOk = false;
                break;
            }
            rowCount++;
        }
        if (!txOk) {
            rdbStore->RollBack();
            if (snapshotInvalid) {
                break;
            }
            if (errCode == NativeRdb::E_OK) {
                errCode = txRet;
            }
            return false;
        }
        if (!sawEnd) {
            rdbStore->RollBack();
            markInvalid();
            break;
        }
        txRet = rdbStore->Commit();
        if (txRet != NativeRdb::E_OK) {
            APP_LOGE("commit restore of %{public}s failed, ret:%{public}d",
                tableName.c_str(), txRet);
            rdbStore->RollBack();
            errCode = txRet;
            return false;
        }
        tableCount++;
    }
    if (!sawEof && !snapshotInvalid) {
        // the snapshot was truncated past the last line read: the fault sits on
        // the next line, not on the last one that parsed fine
        lineNo++;
        markInvalid();
    }
    if (!sawDbInfo && !snapshotInvalid) {
        APP_LOGE("snapshot db info line missing");
        markInvalid();
    }
    // the rebuild mark triggers a full rescan of install dirs, which only helps
    // installed_bundle and preinstalled_bundle; losing other tables must not pay
    // that cost because the rescan cannot recover them anyway
    if (coreDataIncomplete || snapshotInvalid) {
        // the mark is the only distrust signal when the snapshot itself is valid:
        // if it cannot be persisted, keep the snapshot as .recover.failed so the
        // boot path still rescans instead of trusting partially restored data
        if (!MarkRebuildIfDataIncomplete(dbName, rdbStore)) {
            snapshotInvalid = true;
        }
    }
    APP_LOGI("restore from snapshot finished, path:%{public}s, tables:%{public}d, "
        "invalid:%{public}d, coreIncomplete:%{public}d, firstInvalidLine:%{public}zu",
        snapshotPath.c_str(), tableCount, snapshotInvalid, coreDataIncomplete, firstInvalidLine);
    return true;
}

ErrCode RdbRecoverManager::RecoverFromLeftoverSnapshot(const BmsRdbConfig &bmsRdbConfig,
    const NativeRdb::RdbStoreConfig &rdbStoreConfig, std::shared_ptr<NativeRdb::RdbStore> &rdbStore)
{
    std::string dbFile = bmsRdbConfig.dbPath + bmsRdbConfig.dbName;
    std::string snapshotPath = dbFile + ServiceConstants::RDB_SNAPSHOT_SUFFIX;
    std::string tmpPath = dbFile + ServiceConstants::RDB_SNAPSHOT_TMP_SUFFIX;
    if (access(snapshotPath.c_str(), F_OK) != 0) {
        if (access(tmpPath.c_str(), F_OK) == 0) {
            // a leftover tmp means the export itself was interrupted before the
            // atomic rename; the db file was not deleted yet at that point (the
            // deletion only happens after a successful export), so the data is
            // still in the db and there is nothing to salvage from the tmp:
            // drop it, replaying it over the live db could only roll back the
            // writes made since the export started
            APP_LOGW("discard interrupted snapshot tmp file, the data is still in the db: %{public}s",
                tmpPath.c_str());
            if (unlink(tmpPath.c_str()) != 0) {
                APP_LOGW("remove interrupted snapshot tmp file failed, errno:%{public}d", errno);
            }
        }
        return ERR_OK;
    }
    HITRACE_METER_NAME_EX(HITRACE_LEVEL_INFO, HITRACE_TAG_APP, __PRETTY_FUNCTION__, nullptr);
    RecoverScope recoverScope(bmsRdbConfig.dbName);
    // exclusive section: no data operation of any instance may run while the
    // snapshot is replayed over the db, otherwise its writes would be rolled back
    std::unique_lock<std::shared_mutex> dbOpLock(GetDbOpMutex(bmsRdbConfig.dbName));
    // the leftover snapshot means the previous recovery was interrupted before its
    // commit point, so the db must not be served as-is even if it is readable
    APP_LOGI("found leftover snapshot, recovering: %{public}s", snapshotPath.c_str());
    bool snapshotInvalid = false;
    int32_t replayErrCode = NativeRdb::E_OK;
    if (!RestoreFromSnapshotFile(bmsRdbConfig.dbName, bmsRdbConfig.version, rdbStore, snapshotPath,
        snapshotInvalid, replayErrCode)) {
        // db write failure: stop serving this db, the next open retries the restore
        // unless the replay keeps failing, in which case the snapshot is unsalvageable
        rdbStore = nullptr;
        int32_t failCount = 0;
        {
            std::lock_guard<std::mutex> lock(g_recoverStateMutex);
            failCount = ++g_replayFailCounts[bmsRdbConfig.dbName];
        }
        if (failCount < MAX_SNAPSHOT_REPLAY_ATTEMPTS) {
            EventReport::SendDbErrorEvent(bmsRdbConfig.dbName,
                static_cast<int32_t>(DB_OPERATION_TYPE::REBUILD), replayErrCode);
            return replayErrCode;
        }
        APP_LOGW("snapshot replay failed %{public}d times, downgrade to an empty db: %{public}s",
            failCount, snapshotPath.c_str());
        {
            std::lock_guard<std::mutex> lock(g_recoverStateMutex);
            g_replayFailCounts[bmsRdbConfig.dbName] = 0;
        }
        // keep the snapshot as failed for forensics; when even the rename fails,
        // delete it: the data is unsalvageable anyway and a leftover .recover
        // would restart the downgrade loop on every open
        if (!RenameSnapshotToFailed(bmsRdbConfig.dbName, dbFile, snapshotPath) &&
            unlink(snapshotPath.c_str()) != 0 && errno != ENOENT) {
            APP_LOGE("remove unsalvageable snapshot failed, errno:%{public}d", errno);
        }
        int32_t reopenRet = DeleteAndReopenDb(bmsRdbConfig, rdbStoreConfig, rdbStore);
        if (reopenRet != NativeRdb::E_OK) {
            EventReport::SendDbErrorEvent(bmsRdbConfig.dbName,
                static_cast<int32_t>(DB_OPERATION_TYPE::REBUILD), reopenRet);
            return reopenRet;
        }
        if (!MarkRebuildIfDataIncomplete(bmsRdbConfig.dbName, rdbStore)) {
            // the empty db is served without any distrust signal, make the
            // triple failure at least visible in the event stream
            APP_LOGW("rebuild mark failed after downgrade, the boot scan will not run");
            EventReport::SendDbErrorEvent(bmsRdbConfig.dbName,
                static_cast<int32_t>(DB_OPERATION_TYPE::REBUILD), NativeRdb::E_SQLITE_CORRUPT);
        }
        InstalldClient::GetInstance()->ResetBmsDBSecurity();
        ClearCorruptionDetected(bmsRdbConfig.dbName);
        return ERR_OK;
    }
    {
        std::lock_guard<std::mutex> lock(g_recoverStateMutex);
        g_replayFailCounts[bmsRdbConfig.dbName] = 0;
    }
    if (snapshotInvalid) {
        // keep the snapshot as failed for forensics; when even the rename fails,
        // delete it: leaving it behind would replay it over the db on every open
        if (!RenameSnapshotToFailed(bmsRdbConfig.dbName, dbFile, snapshotPath) &&
            unlink(snapshotPath.c_str()) != 0 && errno != ENOENT) {
            APP_LOGE("remove invalid snapshot failed, errno:%{public}d", errno);
        }
        return ERR_OK;
    }
    // commit point: only remove the snapshot after every table was restored; a
    // failed removal keeps the "not committed" marker on disk, the next open
    // would replay over the writes made after this point, so stop serving the
    // db instead and let the next open retry the whole recovery
    if ((unlink(snapshotPath.c_str()) != 0 && errno != ENOENT) ||
        (unlink(tmpPath.c_str()) != 0 && errno != ENOENT)) {
        APP_LOGE("remove snapshot after recovery failed, path:%{public}s, errno:%{public}d",
            snapshotPath.c_str(), errno);
        EventReport::SendDbErrorEvent(bmsRdbConfig.dbName,
            static_cast<int32_t>(DB_OPERATION_TYPE::REBUILD), NativeRdb::E_SQLITE_IOERR);
        rdbStore = nullptr;
        return NativeRdb::E_SQLITE_IOERR;
    }
    APP_LOGI("recovered from snapshot successfully: %{public}s", snapshotPath.c_str());
    return ERR_OK;
}

void RdbRecoverManager::CleanDbLeftoverFiles(const std::string &dbFile)
{
    size_t slash = dbFile.find_last_of('/');
    if (slash == std::string::npos || slash == 0 || slash + 1 >= dbFile.size()) {
        return;
    }
    std::string dir = dbFile.substr(0, slash);
    std::string fileName = dbFile.substr(slash + 1);
    size_t dot = fileName.find('.');
    std::string stem = (dot == std::string::npos) ? fileName : fileName.substr(0, dot);
    if (stem.empty()) {
        return;
    }
    // only the exact framework artifact names are removed: a bare prefix match
    // would also delete unrelated files that merely share the db name stem
    const std::set<std::string> artifacts = {
        stem + "_master_corrupted.db",
        fileName + ".bak",
        fileName + "-slaveFailure",
        fileName + "_binlog",
        fileName + "-wal",
        fileName + "-shm",
        fileName + "-journal",
    };
    DIR *dirPtr = opendir(dir.c_str());
    if (dirPtr == nullptr) {
        APP_LOGW("opendir failed, dir:%{public}s, errno:%{public}d", dir.c_str(), errno);
        return;
    }
    ScopeGuard dirGuard([&] { closedir(dirPtr); });
    struct dirent *entry = nullptr;
    while ((entry = readdir(dirPtr)) != nullptr) {
        std::string name = entry->d_name;
        if (artifacts.find(name) == artifacts.end()) {
            continue;
        }
        std::string path = dir + "/" + name;
        struct stat st = {};
        if (lstat(path.c_str(), &st) != 0) {
            continue;
        }
        bool removed = false;
        if (S_ISLNK(st.st_mode)) {
            // never follow symlinks out of the db directory, remove the link itself
            removed = unlink(path.c_str()) == 0;
        } else {
            removed = S_ISDIR(st.st_mode) ? RemoveDirSafely(path, 0) : (unlink(path.c_str()) == 0);
        }
        if (removed) {
            APP_LOGI("removed db leftover file: %{public}s", path.c_str());
        } else {
            APP_LOGW("remove db leftover file failed: %{public}s, errno:%{public}d", path.c_str(), errno);
        }
    }
}

ErrCode RdbRecoverManager::RebuildDbWithSnapshot(const BmsRdbConfig &bmsRdbConfig,
    const NativeRdb::RdbStoreConfig &rdbStoreConfig,
    std::shared_ptr<NativeRdb::RdbStore> &rdbStore, int32_t rebuildCode)
{
    HITRACE_METER_NAME_EX(HITRACE_LEVEL_INFO, HITRACE_TAG_APP, __PRETTY_FUNCTION__, nullptr);
    RecoverScope recoverScope(bmsRdbConfig.dbName);
    // exclusive section: no data operation of any instance may run while the db
    // is exported, deleted and replayed, otherwise its writes would be lost or
    // rolled back by the replay
    std::unique_lock<std::shared_mutex> dbOpLock(GetDbOpMutex(bmsRdbConfig.dbName));
    std::string dbFile = bmsRdbConfig.dbPath + bmsRdbConfig.dbName;
    std::string snapshotPath = dbFile + ServiceConstants::RDB_SNAPSHOT_SUFFIX;
    std::string tmpPath = dbFile + ServiceConstants::RDB_SNAPSHOT_TMP_SUFFIX;
    // salvage readable data into the snapshot file first; it is the durable source
    // for both this rebuild and any retry after an interruption; when even the
    // export fails, stop serving the corrupted db instead of writing into it
    // until the process restarts. A leftover snapshot of an earlier interrupted
    // recovery may hold more data than the corrupted db can still yield, so it
    // is kept instead of being overwritten by a fresh export.
    if (access(snapshotPath.c_str(), F_OK) != 0 &&
        !WriteSnapshotFile(bmsRdbConfig, rdbStore, snapshotPath)) {
        APP_LOGE("export snapshot failed, stop serving the corrupted db: %{public}s", dbFile.c_str());
        rdbStore = nullptr;
        MarkCorruptionDetected(bmsRdbConfig.dbName);
        EventReport::SendDbErrorEvent(bmsRdbConfig.dbName,
            static_cast<int32_t>(DB_OPERATION_TYPE::REBUILD), NativeRdb::E_SQLITE_IOERR);
        return NativeRdb::E_SQLITE_IOERR;
    }
    int32_t reopenRet = DeleteAndReopenDb(bmsRdbConfig, rdbStoreConfig, rdbStore);
    if (reopenRet != NativeRdb::E_OK) {
        EventReport::SendDbErrorEvent(bmsRdbConfig.dbName,
            static_cast<int32_t>(DB_OPERATION_TYPE::REBUILD), reopenRet);
        return reopenRet;
    }
    bool snapshotInvalid = false;
    int32_t replayErrCode = NativeRdb::E_OK;
    if (!RestoreFromSnapshotFile(bmsRdbConfig.dbName, bmsRdbConfig.version, rdbStore, snapshotPath,
        snapshotInvalid, replayErrCode)) {
        // keep the snapshot and stop serving this db, the next open retries the
        // restore so no service write can interleave with the table replays
        rdbStore = nullptr;
        EventReport::SendDbErrorEvent(bmsRdbConfig.dbName,
            static_cast<int32_t>(DB_OPERATION_TYPE::REBUILD), replayErrCode);
        return replayErrCode;
    }
    if (snapshotInvalid) {
        // keep the snapshot as failed for forensics; when even the rename fails,
        // delete it: leaving it behind would replay it over the db on every open
        if (!RenameSnapshotToFailed(bmsRdbConfig.dbName, dbFile, snapshotPath) &&
            unlink(snapshotPath.c_str()) != 0 && errno != ENOENT) {
            APP_LOGE("remove invalid snapshot failed, errno:%{public}d", errno);
        }
    } else if ((unlink(snapshotPath.c_str()) != 0 && errno != ENOENT) ||
        (unlink(tmpPath.c_str()) != 0 && errno != ENOENT)) {
        // commit point: only remove the snapshot after every table was restored;
        // a failed removal keeps the "not committed" marker on disk, so stop
        // serving the db and let the next open retry the whole recovery
        APP_LOGE("remove snapshot after rebuild failed, path:%{public}s, errno:%{public}d",
            snapshotPath.c_str(), errno);
        EventReport::SendDbErrorEvent(bmsRdbConfig.dbName,
            static_cast<int32_t>(DB_OPERATION_TYPE::REBUILD), NativeRdb::E_SQLITE_IOERR);
        rdbStore = nullptr;
        return NativeRdb::E_SQLITE_IOERR;
    }
    InstalldClient::GetInstance()->ResetBmsDBSecurity();
    ClearCorruptionDetected(bmsRdbConfig.dbName);
    EventReport::SendDbErrorEvent(bmsRdbConfig.dbName,
        static_cast<int32_t>(DB_OPERATION_TYPE::REBUILD), rebuildCode);
    APP_LOGI("rdb rebuild from snapshot finished: %{public}s", bmsRdbConfig.dbName.c_str());
    return ERR_OK;
}

bool RdbRecoverManager::IsRecovering(const std::string &dbName)
{
    std::lock_guard<std::mutex> lock(g_recoverStateMutex);
    return g_recoveringDbs.find(dbName) != g_recoveringDbs.end();
}

uint64_t RdbRecoverManager::GetDbGeneration(const std::string &dbName)
{
    std::lock_guard<std::mutex> lock(g_recoverStateMutex);
    auto it = g_dbGenerations.find(dbName);
    return it == g_dbGenerations.end() ? 0 : it->second;
}

void RdbRecoverManager::BumpDbGeneration(const std::string &dbName)
{
    std::lock_guard<std::mutex> lock(g_recoverStateMutex);
    ++g_dbGenerations[dbName];
}

int32_t RdbRecoverManager::DeleteAndReopenDb(const BmsRdbConfig &bmsRdbConfig,
    const NativeRdb::RdbStoreConfig &rdbStoreConfig, std::shared_ptr<NativeRdb::RdbStore> &rdbStore)
{
    std::string dbFile = bmsRdbConfig.dbPath + bmsRdbConfig.dbName;
    rdbStore = nullptr;
    NativeRdb::RdbHelper::ClearCache();
    // DeleteRdbStore removes the full framework file set (main/wal/shm/journal,
    // slave db, binlog folder, key files), the prefix scan then removes leftovers
    // it does not know about; neither touches the snapshot files
    APP_LOGI("delete db %{public}s", dbFile.c_str());
    NativeRdb::RdbHelper::DeleteRdbStore(dbFile);
    BumpDbGeneration(bmsRdbConfig.dbName);
    CleanDbLeftoverFiles(dbFile);
    int32_t reopenErrCode = NativeRdb::E_OK;
    BmsRdbOpenCallback bmsRdbOpenCallback(bmsRdbConfig);
    rdbStore = NativeRdb::RdbHelper::GetRdbStore(
        rdbStoreConfig, bmsRdbConfig.version, bmsRdbOpenCallback, reopenErrCode);
    if (rdbStore == nullptr) {
        APP_LOGE("re-open rdb after delete failed, errCode:%{public}d", reopenErrCode);
        return reopenErrCode;
    }
    // Re-create the table directly on rdbStore instead of calling CreateTable(),
    // because the caller runs inside GetRdbStore which holds rdbMutex_; calling
    // GetRdbStore again would self-deadlock on the non-recursive mutex.
    std::string createTableSql;
    if (bmsRdbConfig.createTableSql.empty()) {
        createTableSql = std::string("CREATE TABLE IF NOT EXISTS ")
            + bmsRdbConfig.tableName
            + "(" + ServiceConstants::BMS_KEY + " TEXT NOT NULL PRIMARY KEY, "
            + ServiceConstants::BMS_VALUE + " TEXT NOT NULL);";
    } else {
        createTableSql = bmsRdbConfig.createTableSql;
    }
    int32_t createRet = rdbStore->ExecuteSql(createTableSql);
    if (createRet != NativeRdb::E_OK) {
        APP_LOGE("re-create table after manual rebuild failed, ret:%{public}d", createRet);
    }
    for (const auto &sql : bmsRdbConfig.insertColumnSql) {
        rdbStore->ExecuteSql(sql);
    }
    return NativeRdb::E_OK;
}

std::shared_mutex &RdbRecoverManager::GetDbOpMutex(const std::string &dbName)
{
    std::lock_guard<std::mutex> lock(g_dbOpMutexRegistryMutex);
    auto it = g_dbOpMutexes.find(dbName);
    if (it != g_dbOpMutexes.end()) {
        return *it->second;
    }
    return *g_dbOpMutexes.emplace(dbName, std::make_unique<std::shared_mutex>()).first->second;
}

std::string RdbRecoverManager::BuildFailedSnapshotPath(const std::string &dbPath, const std::string &dbName)
{
    return dbPath + dbName + ServiceConstants::RDB_SNAPSHOT_FAILED_SUFFIX;
}

void RdbRecoverManager::MarkCorruptionDetected(const std::string &dbName)
{
    std::lock_guard<std::mutex> lock(g_recoverStateMutex);
    g_corruptionDetectedDbs.insert(dbName);
}

void RdbRecoverManager::ClearCorruptionDetected(const std::string &dbName)
{
    std::lock_guard<std::mutex> lock(g_recoverStateMutex);
    g_corruptionDetectedDbs.erase(dbName);
}

bool RdbRecoverManager::IsCorruptionDetected(const std::string &dbName)
{
    std::lock_guard<std::mutex> lock(g_recoverStateMutex);
    return g_corruptionDetectedDbs.find(dbName) != g_corruptionDetectedDbs.end();
}
}  // namespace AppExecFwk
}  // namespace OHOS
