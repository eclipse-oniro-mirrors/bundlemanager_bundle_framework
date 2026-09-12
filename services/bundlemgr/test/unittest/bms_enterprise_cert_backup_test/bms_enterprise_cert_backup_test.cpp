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

#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <fstream>
#include <map>
#include <set>
#include <string>
#include <vector>

#include "app_log_wrapper.h"
#include "bundle_constants.h"
#include "enterprise_cert_backup_helper.h"
#include "gtest/gtest.h"
#include "mock_enterprise_cert_record.h"

using namespace testing::ext;

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr int32_t TEST_USER_ID = 100;
constexpr int32_t TEST_USER_ID_SECOND = 101;
const std::string PEM_CONTENT_A =
    "-----BEGIN CERTIFICATE-----\nMIIBtestContentA==\n-----END CERTIFICATE-----\n";
const std::string PEM_CONTENT_B =
    "-----BEGIN CERTIFICATE-----\nMIIBtestContentB==\n-----END CERTIFICATE-----\n";
}  // namespace

class BmsEnterpriseCertBackupTest : public testing::Test {
protected:
    void SetUp() override
    {
        root_ = "/data/local/tmp/bms_cert_backup_test_" + std::to_string(getpid());
        (void)system(("rm -rf " + root_).c_str());
        (void)mkdir(root_.c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
    }

    void TearDown() override
    {
        (void)system(("rm -rf " + root_).c_str());
    }

    void WriteCert(int32_t userId, const std::string &alias, const std::string &content)
    {
        std::string userDir = root_ + "/" + std::to_string(userId);
        (void)mkdir(userDir.c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
        std::ofstream ofs(userDir + "/" + alias, std::ios::binary | std::ios::trunc);
        ofs << content;
        ofs.close();
    }

    std::string root_;
};

/**
 * @tc.number: BmsEnterpriseCertBackupTest_BackupToJson_0100
 * @tc.name: BackupToJson
 * @tc.desc: cert root dir not exist, returns empty array with ERR_OK
 */
HWTEST_F(BmsEnterpriseCertBackupTest, BmsEnterpriseCertBackupTest_BackupToJson_0100, TestSize.Level1)
{
    nlohmann::json certs;
    ErrCode ret = EnterpriseCertBackupHelper::BackupToJson(certs, {TEST_USER_ID}, root_ + "/not_exist");
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(certs.is_array());
    EXPECT_EQ(certs.size(), 0);
}

/**
 * @tc.number: BmsEnterpriseCertBackupTest_BackupToJson_0200
 * @tc.name: BackupToJson
 * @tc.desc: multi user multi cert; non-cer file / userId not in set filtered
 */
HWTEST_F(BmsEnterpriseCertBackupTest, BmsEnterpriseCertBackupTest_BackupToJson_0200, TestSize.Level1)
{
    WriteCert(TEST_USER_ID, "a.cer", PEM_CONTENT_A);
    WriteCert(TEST_USER_ID, "b.cer", PEM_CONTENT_B);
    WriteCert(TEST_USER_ID_SECOND, "c.cer", PEM_CONTENT_A);
    WriteCert(TEST_USER_ID, "note.txt", "not a cert");          // filtered: not .cer
    WriteCert(102, "y.cer", PEM_CONTENT_A);                     // filtered: userId not in set

    nlohmann::json certs;
    ErrCode ret = EnterpriseCertBackupHelper::BackupToJson(
        certs, {TEST_USER_ID, TEST_USER_ID_SECOND}, root_);
    EXPECT_EQ(ret, ERR_OK);
    ASSERT_EQ(certs.size(), 3);
    // readdir order is unspecified; assert (userId, alias) as sets, not as a sequence.
    std::map<int32_t, std::set<std::string>> userAliases;
    for (const auto &item : certs) {
        userAliases[item[ServiceConstants::BACKUP_CERT_USER_ID_KEY].get<int32_t>()]
            .insert(item[ServiceConstants::BACKUP_CERT_ALIAS_KEY].get<std::string>());
    }
    EXPECT_EQ(userAliases[TEST_USER_ID], (std::set<std::string> {"a.cer", "b.cer"}));
    EXPECT_EQ(userAliases[TEST_USER_ID_SECOND], (std::set<std::string> {"c.cer"}));
    EXPECT_EQ(userAliases.size(), 2);
}

/**
 * @tc.number: BmsEnterpriseCertBackupTest_BackupToJson_0300
 * @tc.name: BackupToJson
 * @tc.desc: content is standard base64 of exact file bytes
 */
HWTEST_F(BmsEnterpriseCertBackupTest, BmsEnterpriseCertBackupTest_BackupToJson_0300, TestSize.Level1)
{
    WriteCert(TEST_USER_ID, "a.cer", PEM_CONTENT_A);
    nlohmann::json certs;
    ASSERT_EQ(EnterpriseCertBackupHelper::BackupToJson(certs, {TEST_USER_ID}, root_), ERR_OK);
    ASSERT_EQ(certs.size(), 1);
    std::string encoded = certs[0][ServiceConstants::BACKUP_CERT_CONTENT_KEY].get<std::string>();
    EXPECT_EQ(encoded.size(), ((PEM_CONTENT_A.size() + 2) / 3) * 4);  // standard base64 length
    EXPECT_NE(encoded.find("LS0tLS1C"), std::string::npos);  // base64 prefix of "-----BE"
}

/**
 * @tc.number: BmsEnterpriseCertBackupTest_BackupToJson_0400
 * @tc.name: BackupToJson
 * @tc.desc: cert file larger than CAPACITY_SIZE fails backup
 */
HWTEST_F(BmsEnterpriseCertBackupTest, BmsEnterpriseCertBackupTest_BackupToJson_0400, TestSize.Level1)
{
    WriteCert(TEST_USER_ID, "big.cer", std::string(Constants::CAPACITY_SIZE + 1, 'A'));
    nlohmann::json certs;
    ErrCode ret = EnterpriseCertBackupHelper::BackupToJson(certs, {TEST_USER_ID}, root_);
    EXPECT_EQ(ret, ERR_APPEXECFWK_BACKUP_FILE_IO_ERROR);
}
/**
 * @tc.number: BmsEnterpriseCertBackupTest_RestoreCheck_0100
 * @tc.name: RestoreFromJson param check
 * @tc.desc: non-array json rejected
 */
HWTEST_F(BmsEnterpriseCertBackupTest, BmsEnterpriseCertBackupTest_RestoreCheck_0100, TestSize.Level1)
{
    nlohmann::json certs;
    certs["invalid"] = "object";
    EXPECT_EQ(EnterpriseCertBackupHelper::RestoreFromJson(certs, root_),
        ERR_APPEXECFWK_BACKUP_ENTERPRISE_CERT_PARAM_ERROR);
}

/**
 * @tc.number: BmsEnterpriseCertBackupTest_RestoreCheck_0200
 * @tc.name: RestoreFromJson param check
 * @tc.desc: alias with path separator rejected
 */
HWTEST_F(BmsEnterpriseCertBackupTest, BmsEnterpriseCertBackupTest_RestoreCheck_0200, TestSize.Level1)
{
    nlohmann::json certs = nlohmann::json::array({{
        {ServiceConstants::BACKUP_CERT_USER_ID_KEY, TEST_USER_ID},
        {ServiceConstants::BACKUP_CERT_ALIAS_KEY, "a/b.cer"},
        {ServiceConstants::BACKUP_CERT_CONTENT_KEY, "QUJD"},
    }});
    EXPECT_EQ(EnterpriseCertBackupHelper::RestoreFromJson(certs, root_),
        ERR_APPEXECFWK_BACKUP_ENTERPRISE_CERT_PARAM_ERROR);
}

/**
 * @tc.number: BmsEnterpriseCertBackupTest_RestoreCheck_0300
 * @tc.name: RestoreFromJson param check
 * @tc.desc: wrong suffix / userId too small / invalid base64 rejected
 */
HWTEST_F(BmsEnterpriseCertBackupTest, BmsEnterpriseCertBackupTest_RestoreCheck_0300, TestSize.Level1)
{
    auto makeItem = [](int32_t userId, const std::string &alias, const std::string &content) {
        return nlohmann::json({
            {ServiceConstants::BACKUP_CERT_USER_ID_KEY, userId},
            {ServiceConstants::BACKUP_CERT_ALIAS_KEY, alias},
            {ServiceConstants::BACKUP_CERT_CONTENT_KEY, content},
        });
    };
    nlohmann::json badSuffix = nlohmann::json::array({makeItem(TEST_USER_ID, "a.txt", "QUJD")});
    EXPECT_EQ(EnterpriseCertBackupHelper::RestoreFromJson(badSuffix, root_),
        ERR_APPEXECFWK_BACKUP_ENTERPRISE_CERT_PARAM_ERROR);

    nlohmann::json badUser = nlohmann::json::array({makeItem(0, "a.cer", "QUJD")});
    EXPECT_EQ(EnterpriseCertBackupHelper::RestoreFromJson(badUser, root_),
        ERR_APPEXECFWK_BACKUP_ENTERPRISE_CERT_PARAM_ERROR);

    nlohmann::json badBase64 = nlohmann::json::array({makeItem(TEST_USER_ID, "a.cer", "!!!not-base64!!!")});
    EXPECT_EQ(EnterpriseCertBackupHelper::RestoreFromJson(badBase64, root_),
        ERR_APPEXECFWK_BACKUP_ENTERPRISE_CERT_PARAM_ERROR);
}

/**
 * @tc.number: BmsEnterpriseCertBackupTest_RestoreCheck_0400
 * @tc.name: RestoreFromJson param check
 * @tc.desc: more than MAX_ENTERPRISE_RESIGN_CERT_NUM certs for one user rejected
 */
HWTEST_F(BmsEnterpriseCertBackupTest, BmsEnterpriseCertBackupTest_RestoreCheck_0400, TestSize.Level1)
{
    nlohmann::json certs = nlohmann::json::array();
    for (int32_t i = 0; i <= ServiceConstants::MAX_ENTERPRISE_RESIGN_CERT_NUM; ++i) {
        certs.push_back({
            {ServiceConstants::BACKUP_CERT_USER_ID_KEY, TEST_USER_ID},
            {ServiceConstants::BACKUP_CERT_ALIAS_KEY, "cert" + std::to_string(i) + ".cer"},
            {ServiceConstants::BACKUP_CERT_CONTENT_KEY, "QUJD"},
        });
    }
    EXPECT_EQ(EnterpriseCertBackupHelper::RestoreFromJson(certs, root_),
        ERR_APPEXECFWK_BACKUP_ENTERPRISE_CERT_PARAM_ERROR);
}

/**
 * @tc.number: BmsEnterpriseCertBackupTest_RestoreCheck_0500
 * @tc.name: RestoreFromJson param check
 * @tc.desc: empty array passes validation and no-op restore returns ERR_OK
 */
HWTEST_F(BmsEnterpriseCertBackupTest, BmsEnterpriseCertBackupTest_RestoreCheck_0500, TestSize.Level1)
{
    nlohmann::json certs = nlohmann::json::array();
    EXPECT_EQ(EnterpriseCertBackupHelper::RestoreFromJson(certs, root_), ERR_OK);
}

/**
 * @tc.number: BmsEnterpriseCertBackupTest_Restore_0100
 * @tc.name: RestoreFromJson transaction
 * @tc.desc: normal restore clears local certs and reinstalls byte-exact content
 */
HWTEST_F(BmsEnterpriseCertBackupTest, BmsEnterpriseCertBackupTest_Restore_0100, TestSize.Level1)
{
    WriteCert(TEST_USER_ID, "a.cer", PEM_CONTENT_A);
    WriteCert(TEST_USER_ID, "b.cer", PEM_CONTENT_B);
    nlohmann::json certs;
    ASSERT_EQ(EnterpriseCertBackupHelper::BackupToJson(certs, {TEST_USER_ID}, root_), ERR_OK);
    // Replace local certs with a different one (simulate EDM re-issuing before restore).
    (void)system(("rm -rf " + root_ + "/" + std::to_string(TEST_USER_ID)).c_str());
    WriteCert(TEST_USER_ID, "new.cer", PEM_CONTENT_A);

    ClearCertRecordForTest();
    ASSERT_EQ(EnterpriseCertBackupHelper::RestoreFromJson(certs, root_), ERR_OK);
    ASSERT_EQ(g_deletedCertPaths.size(), 1);                        // old new.cer cleared
    EXPECT_NE(g_deletedCertPaths[0].find("new.cer"), std::string::npos);
    // Reinstall order follows the backup array (readdir order); assert as a
    // path -> content map with byte-exact contents, not as a sequence.
    ASSERT_EQ(g_addedCertPaths.size(), 2);
    std::map<std::string, std::string> restored;
    for (size_t i = 0; i < g_addedCertPaths.size(); ++i) {
        restored[g_addedCertPaths[i]] = g_addedCertContents[i];
    }
    std::string userDir = root_ + "/" + std::to_string(TEST_USER_ID);
    EXPECT_EQ(restored[userDir + "/a.cer"], PEM_CONTENT_A);
    EXPECT_EQ(restored[userDir + "/b.cer"], PEM_CONTENT_B);
}

/**
 * @tc.number: BmsEnterpriseCertBackupTest_Restore_0200
 * @tc.name: RestoreFromJson transaction
 * @tc.desc: AddCertAndEnableKey fails on second cert, first restored cert is rolled back
 */
HWTEST_F(BmsEnterpriseCertBackupTest, BmsEnterpriseCertBackupTest_Restore_0200, TestSize.Level1)
{
    nlohmann::json certs = nlohmann::json::array({
        {
            {ServiceConstants::BACKUP_CERT_USER_ID_KEY, TEST_USER_ID},
            {ServiceConstants::BACKUP_CERT_ALIAS_KEY, "a.cer"},
            {ServiceConstants::BACKUP_CERT_CONTENT_KEY, "QUJDRA=="},
        },
        {
            {ServiceConstants::BACKUP_CERT_USER_ID_KEY, TEST_USER_ID},
            {ServiceConstants::BACKUP_CERT_ALIAS_KEY, "b.cer"},
            {ServiceConstants::BACKUP_CERT_CONTENT_KEY, "QUJDRA=="},
        },
    });
    ClearCertRecordForTest();
    SetAddCertRetListForTest({ERR_OK, ERR_APPEXECFWK_BACKUP_FILE_IO_ERROR});  // first succeeds, second fails
    EXPECT_EQ(EnterpriseCertBackupHelper::RestoreFromJson(certs, root_),
        ERR_APPEXECFWK_BACKUP_ENTERPRISE_CERT_RESTORE_FAILED);
    ASSERT_EQ(g_addedCertPaths.size(), 2);       // two attempts
    ASSERT_EQ(g_deletedCertPaths.size(), 1);     // rollback deleted the restored a.cer
    EXPECT_NE(g_deletedCertPaths[0].find("/a.cer"), std::string::npos);
    SetAddCertRetListForTest({});
}

/**
 * @tc.number: BmsEnterpriseCertBackupTest_Restore_0300
 * @tc.name: RestoreFromJson transaction
 * @tc.desc: user dir absent, Mkdir branch taken then cert restored
 */
HWTEST_F(BmsEnterpriseCertBackupTest, BmsEnterpriseCertBackupTest_Restore_0300, TestSize.Level1)
{
    // dir 100 not pre-created -> Mkdir branch (mock returns ERR_OK)
    (void)system(("rm -rf " + root_ + "/" + std::to_string(TEST_USER_ID)).c_str());
    nlohmann::json certs = nlohmann::json::array({
        {
            {ServiceConstants::BACKUP_CERT_USER_ID_KEY, TEST_USER_ID},
            {ServiceConstants::BACKUP_CERT_ALIAS_KEY, "a.cer"},
            {ServiceConstants::BACKUP_CERT_CONTENT_KEY, "QUJD"},
        },
    });
    ClearCertRecordForTest();
    EXPECT_EQ(EnterpriseCertBackupHelper::RestoreFromJson(certs, root_), ERR_OK);
    ASSERT_EQ(g_addedCertPaths.size(), 1);
    EXPECT_NE(g_addedCertPaths[0].find(std::to_string(TEST_USER_ID) + "/a.cer"), std::string::npos);
}

/**
 * @tc.number: BmsEnterpriseCertBackupTest_Restore_0400
 * @tc.name: RestoreFromJson transaction
 * @tc.desc: empty array involves no user and touches no local certs
 */
HWTEST_F(BmsEnterpriseCertBackupTest, BmsEnterpriseCertBackupTest_Restore_0400, TestSize.Level1)
{
    WriteCert(TEST_USER_ID, "a.cer", PEM_CONTENT_A);
    WriteCert(TEST_USER_ID_SECOND, "c.cer", PEM_CONTENT_B);
    nlohmann::json certs = nlohmann::json::array();
    ClearCertRecordForTest();
    EXPECT_EQ(EnterpriseCertBackupHelper::RestoreFromJson(certs, root_), ERR_OK);
    EXPECT_EQ(g_deletedCertPaths.size(), 0);
    EXPECT_EQ(g_addedCertPaths.size(), 0);
}

/**
 * @tc.number: BmsEnterpriseCertBackupTest_Restore_0600
 * @tc.name: RestoreFromJson transaction
 * @tc.desc: restoring one user's certs leaves the other user's local certs untouched
 */
HWTEST_F(BmsEnterpriseCertBackupTest, BmsEnterpriseCertBackupTest_Restore_0600, TestSize.Level1)
{
    WriteCert(TEST_USER_ID, "old.cer", PEM_CONTENT_B);
    WriteCert(TEST_USER_ID_SECOND, "keep.cer", PEM_CONTENT_A);
    nlohmann::json certs = nlohmann::json::array({
        {
            {ServiceConstants::BACKUP_CERT_USER_ID_KEY, TEST_USER_ID},
            {ServiceConstants::BACKUP_CERT_ALIAS_KEY, "a.cer"},
            {ServiceConstants::BACKUP_CERT_CONTENT_KEY, "QUJD"},
        },
    });
    ClearCertRecordForTest();
    EXPECT_EQ(EnterpriseCertBackupHelper::RestoreFromJson(certs, root_), ERR_OK);
    // only user 100's old cert is cleared and replaced; user 101 is untouched
    ASSERT_EQ(g_deletedCertPaths.size(), 1);
    EXPECT_NE(g_deletedCertPaths[0].find(std::to_string(TEST_USER_ID) + "/old.cer"), std::string::npos);
    ASSERT_EQ(g_addedCertPaths.size(), 1);
    EXPECT_NE(g_addedCertPaths[0].find(std::to_string(TEST_USER_ID) + "/a.cer"), std::string::npos);
}

/**
 * @tc.number: BmsEnterpriseCertBackupTest_Restore_0500
 * @tc.name: RestoreFromJson full rollback
 * @tc.desc: restore fails midway, cleared original local certs are re-installed from snapshot
 */
HWTEST_F(BmsEnterpriseCertBackupTest, BmsEnterpriseCertBackupTest_Restore_0500, TestSize.Level1)
{
    WriteCert(TEST_USER_ID, "orig.cer", PEM_CONTENT_B);           // pre-existing local cert (will be cleared)
    nlohmann::json certs = nlohmann::json::array({
        {
            {ServiceConstants::BACKUP_CERT_USER_ID_KEY, TEST_USER_ID},
            {ServiceConstants::BACKUP_CERT_ALIAS_KEY, "a.cer"},
            {ServiceConstants::BACKUP_CERT_CONTENT_KEY, "QUJD"},
        },
        {
            {ServiceConstants::BACKUP_CERT_USER_ID_KEY, TEST_USER_ID},
            {ServiceConstants::BACKUP_CERT_ALIAS_KEY, "b.cer"},
            {ServiceConstants::BACKUP_CERT_CONTENT_KEY, "QUJDRA=="},
        },
    });
    ClearCertRecordForTest();
    // Sequence: restore a (ok) -> restore b (fail) -> rollback reinstalls orig (ok)
    SetAddCertRetListForTest({ERR_OK, ERR_APPEXECFWK_BACKUP_FILE_IO_ERROR, ERR_OK});
    EXPECT_EQ(EnterpriseCertBackupHelper::RestoreFromJson(certs, root_),
        ERR_APPEXECFWK_BACKUP_ENTERPRISE_CERT_RESTORE_FAILED);
    // clear orig + rollback delete a
    ASSERT_EQ(g_deletedCertPaths.size(), 2);
    EXPECT_NE(g_deletedCertPaths[0].find("orig.cer"), std::string::npos);
    EXPECT_NE(g_deletedCertPaths[1].find("/a.cer"), std::string::npos);
    // all three add attempts are recorded: a (ok), b (fail), snapshot reinstall orig (ok)
    ASSERT_EQ(g_addedCertPaths.size(), 3);
    EXPECT_NE(g_addedCertPaths[0].find("/a.cer"), std::string::npos);
    EXPECT_NE(g_addedCertPaths[1].find("/b.cer"), std::string::npos);
    EXPECT_NE(g_addedCertPaths[2].find("orig.cer"), std::string::npos);
    EXPECT_EQ(g_addedCertContents[2], PEM_CONTENT_B);
    SetAddCertRetListForTest({});
}
}  // namespace AppExecFwk
}  // namespace OHOS
