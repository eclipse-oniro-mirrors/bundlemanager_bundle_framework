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

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <map>
#include <memory>
#include "result_set.h"
#define private public
#include "read_only_installed_bundle_store.h"
#undef private
#ifndef ATM_RECOVERY_ROWS_ONLY
#include <fstream>
#include <iterator>
#include <sys/stat.h>
#include <unistd.h>
#include "rdb_errno.h"
#include "rdb_helper.h"
#include "rdb_open_callback.h"
#include "rdb_store.h"
#include "rdb_store_config.h"
#endif

using namespace testing::ext;

namespace OHOS::AppExecFwk::AtmRecovery {
using namespace testing;
using namespace NativeRdb;

#ifndef ATM_RECOVERY_ROWS_ONLY
namespace {
class StoreTestOpenCallback : public NativeRdb::RdbOpenCallback {
public:
    int OnCreate(NativeRdb::RdbStore &) override { return NativeRdb::E_OK; }
    int OnUpgrade(NativeRdb::RdbStore &, int, int) override { return NativeRdb::E_OK; }
};
}
#endif

class AtmRecoveryStoreTest : public testing::Test {
#ifndef ATM_RECOVERY_ROWS_ONLY
protected:
    std::string directory;
    std::string path;
    std::shared_ptr<NativeRdb::RdbStore> writer;
    void SetUp() override
    {
#ifdef __OHOS__
        char pattern[] = "/data/local/tmp/atm-recovery-XXXXXX";
#else
        char pattern[] = "/tmp/atm-recovery-XXXXXX";
#endif
        const char *dir = mkdtemp(pattern);
        ASSERT_NE(dir, nullptr);
        directory = dir;
        path = directory + "/test.db";
    }
    void TearDown() override
    {
        writer.reset();
        unlink((path + "-wal").c_str());
        unlink((path + "-shm").c_str());
        unlink((path + "-journal").c_str());
        unlink(path.c_str());
        rmdir(directory.c_str());
    }
    void OpenWriter(bool wal = false)
    {
        NativeRdb::RdbStoreConfig config(path);
        config.SetJournalMode(wal ? NativeRdb::JournalMode::MODE_WAL : NativeRdb::JournalMode::MODE_TRUNCATE);
        config.SetLocalOnly(true);
        config.SetSilentAccessible(false);
        StoreTestOpenCallback callback;
        int error = NativeRdb::E_OK;
        writer = NativeRdb::RdbHelper::GetRdbStore(config, 1, callback, error);
        ASSERT_EQ(error, NativeRdb::E_OK);
        ASSERT_NE(writer, nullptr);
        // Keep the writer alive, but prevent read-only queries from reusing its cached store.
        ASSERT_EQ(NativeRdb::RdbHelper::ClearStoreCache(config), NativeRdb::E_OK);
    }
    void Create(bool wal = false)
    {
        OpenWriter(wal);
        ASSERT_NE(writer, nullptr);
        Sql("CREATE TABLE installed_bundle(KEY TEXT NOT NULL PRIMARY KEY, VALUE TEXT NOT NULL)");
    }
    void Sql(const char *sql) { ASSERT_EQ(writer->ExecuteSql(sql), NativeRdb::E_OK); }
    std::string Bytes(const std::string &file)
    {
        std::ifstream stream(file, std::ios::binary);
        return std::string(std::istreambuf_iterator<char>(stream), {});
    }
#endif
};

namespace {
class FaultResultSet : public ResultSet {
public:
    MOCK_METHOD(int, GetAllColumnNames, (std::vector<std::string> &), (override));
    MOCK_METHOD(int, GetColumnCount, (int &), (override));
    MOCK_METHOD(int, GetColumnType, (int, ColumnType &), (override));
    MOCK_METHOD(int, GetColumnIndex, (const std::string &, int &), (override));
    MOCK_METHOD(int, GetColumnName, (int, std::string &), (override));
    MOCK_METHOD(int, GetRowCount, (int &), (override));
    MOCK_METHOD(int, GetRowIndex, (int &), (const, override));
    MOCK_METHOD(int, GoTo, (int), (override));
    MOCK_METHOD(int, GoToRow, (int), (override));
    MOCK_METHOD(int, GoToFirstRow, (), (override));
    MOCK_METHOD(int, GoToLastRow, (), (override));
    MOCK_METHOD(int, GoToNextRow, (), (override));
    MOCK_METHOD(int, GoToPreviousRow, (), (override));
    MOCK_METHOD(int, IsEnded, (bool &), (override));
    MOCK_METHOD(int, IsStarted, (bool &), (const, override));
    MOCK_METHOD(int, IsAtFirstRow, (bool &), (const, override));
    MOCK_METHOD(int, IsAtLastRow, (bool &), (override));
    MOCK_METHOD(int, GetBlob, (int, std::vector<uint8_t> &), (override));
    MOCK_METHOD(int, GetString, (int, std::string &), (override));
    MOCK_METHOD(int, GetInt, (int, int &), (override));
    MOCK_METHOD(int, GetLong, (int, int64_t &), (override));
    MOCK_METHOD(int, GetDouble, (int, double &), (override));
    MOCK_METHOD(int, IsColumnNull, (int, bool &), (override));
    MOCK_METHOD(bool, IsClosed, (), (const, override));
    MOCK_METHOD(int, Close, (), (override));
    MOCK_METHOD(int, GetAsset, (int32_t, ValueObject::Asset &), (override));
    MOCK_METHOD(int, GetAssets, (int32_t, ValueObject::Assets &), (override));
    MOCK_METHOD(int, Get, (int32_t, ValueObject &), (override));
    MOCK_METHOD(int, GetRow, (RowEntity &), (override));
    MOCK_METHOD(int, GetSize, (int, size_t &), (override));
};
}


/**
 * @tc.name: EmptyResultSucceedsAndClearsOldOutput
 * @tc.desc: Accept an empty result set and clear any previous output.
 */
HWTEST_F(AtmRecoveryStoreTest, EmptyResultSucceedsAndClearsOldOutput, Function | SmallTest | Level1)
{
    StrictMock<FaultResultSet> rows;
    EXPECT_CALL(rows, GoToFirstRow()).WillOnce(Return(E_ROW_OUT_RANGE));
    std::map<std::string, std::string> data = {{"stale", "value"}};
    EXPECT_TRUE(ReadOnlyInstalledBundleStore::ReadAllRows(rows, data));
    EXPECT_TRUE(data.empty());
}

/**
 * @tc.name: BadKeyAndValueDoNotHideLaterGoodRows
 * @tc.desc: Skip unreadable keys or values and continue collecting later valid rows.
 */
HWTEST_F(AtmRecoveryStoreTest, BadKeyAndValueDoNotHideLaterGoodRows, Function | SmallTest | Level1)
{
    StrictMock<FaultResultSet> rows;
    InSequence sequence;
    EXPECT_CALL(rows, GoToFirstRow()).WillOnce(Return(E_OK));
    EXPECT_CALL(rows, GetString(0, _)).WillOnce(DoAll(SetArgReferee<1>("first"), Return(E_OK)));
    EXPECT_CALL(rows, GetString(1, _)).WillOnce(DoAll(SetArgReferee<1>("good-1"), Return(E_OK)));
    EXPECT_CALL(rows, GoToNextRow()).WillOnce(Return(E_OK));
    EXPECT_CALL(rows, GetString(0, _)).WillOnce(Return(E_ERROR));
    EXPECT_CALL(rows, GoToNextRow()).WillOnce(Return(E_OK));
    EXPECT_CALL(rows, GetString(0, _)).WillOnce(DoAll(SetArgReferee<1>("+clone-10000+first"), Return(E_OK)));
    EXPECT_CALL(rows, GetString(1, _)).WillOnce(DoAll(SetArgReferee<1>("partial"), Return(E_ERROR)));
    EXPECT_CALL(rows, GoToNextRow()).WillOnce(Return(E_OK));
    EXPECT_CALL(rows, GetString(0, _)).WillOnce(DoAll(SetArgReferee<1>("last"), Return(E_OK)));
    EXPECT_CALL(rows, GetString(1, _)).WillOnce(DoAll(SetArgReferee<1>("good-2"), Return(E_OK)));
    EXPECT_CALL(rows, GoToNextRow()).WillOnce(Return(E_ROW_OUT_RANGE));
    std::map<std::string, std::string> data;
    EXPECT_TRUE(ReadOnlyInstalledBundleStore::ReadAllRows(rows, data));
    const std::map<std::string, std::string> expected = {
        {"first", "good-1"}, {"last", "good-2"}};
    EXPECT_EQ(data, expected);
}

/**
 * @tc.name: AllUnreadableRowsFail
 * @tc.desc: Fail when no row in a nonempty result set can be read.
 */
HWTEST_F(AtmRecoveryStoreTest, AllUnreadableRowsFail, Function | SmallTest | Level1)
{
    StrictMock<FaultResultSet> rows;
    InSequence sequence;
    EXPECT_CALL(rows, GoToFirstRow()).WillOnce(Return(E_OK));
    EXPECT_CALL(rows, GetString(0, _)).WillOnce(Return(E_ERROR));
    EXPECT_CALL(rows, GoToNextRow()).WillOnce(Return(E_OK));
    EXPECT_CALL(rows, GetString(0, _)).WillOnce(DoAll(SetArgReferee<1>("key"), Return(E_OK)));
    EXPECT_CALL(rows, GetString(1, _)).WillOnce(Return(E_ERROR));
    EXPECT_CALL(rows, GoToNextRow()).WillOnce(Return(E_ROW_OUT_RANGE));
    std::map<std::string, std::string> data;
    EXPECT_FALSE(ReadOnlyInstalledBundleStore::ReadAllRows(rows, data));
    EXPECT_TRUE(data.empty());
}

/**
 * @tc.name: CursorErrorDiscardsEarlierRows
 * @tc.desc: Discard earlier rows if advancing the cursor fails.
 */
HWTEST_F(AtmRecoveryStoreTest, CursorErrorDiscardsEarlierRows, Function | SmallTest | Level1)
{
    StrictMock<FaultResultSet> rows;
    InSequence sequence;
    EXPECT_CALL(rows, GoToFirstRow()).WillOnce(Return(E_OK));
    EXPECT_CALL(rows, GetString(0, _)).WillOnce(DoAll(SetArgReferee<1>("key"), Return(E_OK)));
    EXPECT_CALL(rows, GetString(1, _)).WillOnce(DoAll(SetArgReferee<1>("good"), Return(E_OK)));
    EXPECT_CALL(rows, GoToNextRow()).WillOnce(Return(E_ERROR));
    std::map<std::string, std::string> data;
    EXPECT_FALSE(ReadOnlyInstalledBundleStore::ReadAllRows(rows, data));
    EXPECT_TRUE(data.empty());
}

/**
 * @tc.name: FirstRowErrorIsNotEmptySuccess
 * @tc.desc: Distinguish a first-row cursor error from a valid empty result set.
 */
HWTEST_F(AtmRecoveryStoreTest, FirstRowErrorIsNotEmptySuccess, Function | SmallTest | Level1)
{
    StrictMock<FaultResultSet> rows;
    EXPECT_CALL(rows, GoToFirstRow()).WillOnce(Return(E_ERROR));
    std::map<std::string, std::string> data = {{"stale", "value"}};
    EXPECT_FALSE(ReadOnlyInstalledBundleStore::ReadAllRows(rows, data));
    EXPECT_TRUE(data.empty());
}

#ifndef ATM_RECOVERY_ROWS_ONLY
/**
 * @tc.name: MissingAndZeroByteFilesAreNotCreatedOrRepaired
 * @tc.desc: Reject missing and zero-byte database files without creating or repairing them.
 */
HWTEST_F(AtmRecoveryStoreTest, MissingAndZeroByteFilesAreNotCreatedOrRepaired, Function | SmallTest | Level1)
{
    ReadOnlyInstalledBundleStore missing(path);
    EXPECT_FALSE(missing.Open());
    EXPECT_NE(access(path.c_str(), F_OK), 0);
    std::ofstream(path).close();
    ReadOnlyInstalledBundleStore emptyFile(path);
    EXPECT_FALSE(emptyFile.Open());
    EXPECT_TRUE(Bytes(path).empty());
}

/**
 * @tc.name: ValidEmptyTableSucceeds
 * @tc.desc: Read a valid empty table successfully and clear previous output.
 */
HWTEST_F(AtmRecoveryStoreTest, ValidEmptyTableSucceeds, Function | SmallTest | Level1)
{
    Create();
    ReadOnlyInstalledBundleStore store(path);
    ASSERT_TRUE(store.Open());
    std::map<std::string, std::string> data = {{"stale", "value"}};
    EXPECT_TRUE(store.QueryAllData(data));
    EXPECT_TRUE(data.empty());
}

/**
 * @tc.name: MissingTableOrColumnAndCorruptionFail
 * @tc.desc: Fail queries with a missing table or column and leave corrupt database contents unchanged.
 */
HWTEST_F(AtmRecoveryStoreTest, MissingTableOrColumnAndCorruptionFail, Function | SmallTest | Level1)
{
    OpenWriter();
    ASSERT_NE(writer, nullptr);
    std::map<std::string, std::string> data;
    Sql("CREATE TABLE unrelated (value TEXT)");
    {
        ReadOnlyInstalledBundleStore store(path);
        ASSERT_TRUE(store.Open());
        EXPECT_FALSE(store.QueryAllData(data));
    }
    Sql("CREATE TABLE installed_bundle(KEY TEXT)");
    {
        ReadOnlyInstalledBundleStore store(path);
        ASSERT_TRUE(store.Open());
        EXPECT_FALSE(store.QueryAllData(data));
    }
    writer.reset();
    std::ofstream(path, std::ios::binary | std::ios::trunc) << std::string(4096, 'x');
    ReadOnlyInstalledBundleStore corrupt(path);
    if (corrupt.Open()) {
        EXPECT_FALSE(corrupt.QueryAllData(data));
    }
    EXPECT_EQ(Bytes(path), std::string(4096, 'x'));
}

/**
 * @tc.name: ReadableColumnsWithoutConstraintsSucceed
 * @tc.desc: Read available records without requiring primary-key or not-null constraints.
 */
HWTEST_F(AtmRecoveryStoreTest, ReadableColumnsWithoutConstraintsSucceed, Function | SmallTest | Level1)
{
    OpenWriter();
    ASSERT_NE(writer, nullptr);
    Sql("CREATE TABLE installed_bundle(KEY TEXT, VALUE TEXT)");
    Sql("INSERT INTO installed_bundle VALUES('app', 'record')");
    ReadOnlyInstalledBundleStore store(path);
    ASSERT_TRUE(store.Open());
    std::map<std::string, std::string> data;
    ASSERT_TRUE(store.QueryAllData(data));
    ASSERT_EQ(data.size(), 1U);
    EXPECT_EQ(data.at("app"), "record");
}

/**
 * @tc.name: ReadsInstalledAndUninstallTablesInSequence
 * @tc.desc: Read both recovery tables through separate read-only scans of the same database.
 */
HWTEST_F(AtmRecoveryStoreTest, ReadsInstalledAndUninstallTablesInSequence, Function | SmallTest | Level1)
{
    Create();
    Sql("INSERT INTO installed_bundle VALUES ('app', 'installed-record')");
    Sql("CREATE TABLE uninstall_bundle_info(BUNDLENAME TEXT PRIMARY KEY NOT NULL, "
        "UNINSTALL_BUNDLE_INFO TEXT NOT NULL)");
    Sql("INSERT INTO uninstall_bundle_info VALUES ('removed-app', '{\"userInfos\":{}}')");
    ReadOnlyInstalledBundleStore store(path);
    ASSERT_TRUE(store.Open());
    std::map<std::string, std::string> installed;
    ASSERT_TRUE(store.QueryAllData(installed));
    ASSERT_EQ(installed.size(), 1U);
    EXPECT_EQ(installed.at("app"), "installed-record");
    ASSERT_TRUE(store.Open());
    std::map<std::string, std::string> uninstalled;
    ASSERT_TRUE(store.QueryAllUninstallData(uninstalled));
    ASSERT_EQ(uninstalled.size(), 1U);
    EXPECT_EQ(uninstalled.at("removed-app"), "{\"userInfos\":{}}");
}

/**
 * @tc.name: QueryWithoutOpenFailsAndClearsOutput
 * @tc.desc: Fail a query before opening the store and clear previous output.
 */
HWTEST_F(AtmRecoveryStoreTest, QueryWithoutOpenFailsAndClearsOutput, Function | SmallTest | Level1)
{
    ReadOnlyInstalledBundleStore store(path);
    std::map<std::string, std::string> data = {{"stale", "value"}};
    EXPECT_FALSE(store.QueryAllData(data));
    EXPECT_TRUE(data.empty());
    EXPECT_NE(access(path.c_str(), F_OK), 0);
}

/**
 * @tc.name: ReadingDoesNotChangeDatabasePermissions
 * @tc.desc: Preserve database file permissions during a read-only query.
 */
HWTEST_F(AtmRecoveryStoreTest, ReadingDoesNotChangeDatabasePermissions, Function | SmallTest | Level1)
{
    Create();
    ASSERT_EQ(chmod(path.c_str(), 0666), 0);
    {
        ReadOnlyInstalledBundleStore store(path);
        ASSERT_TRUE(store.Open());
        std::map<std::string, std::string> data;
        EXPECT_TRUE(store.QueryAllData(data));
        EXPECT_TRUE(data.empty());
    }
    struct stat status = {};
    ASSERT_EQ(stat(path.c_str(), &status), 0);
    EXPECT_EQ(status.st_mode & 0777, 0666);
}
#endif
} // namespace OHOS::AppExecFwk::AtmRecovery
