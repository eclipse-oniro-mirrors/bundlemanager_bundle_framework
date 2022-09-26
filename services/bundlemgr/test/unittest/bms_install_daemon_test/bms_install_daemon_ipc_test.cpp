/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>
#include <vector>

#include "ipc/file_stat.h"
#include "parcel_macro.h"
#include "installd/installd_host_impl.h"
#include "ipc/installd_proxy.h"

using namespace testing::ext;
using namespace OHOS::AppExecFwk;
namespace OHOS {
namespace {
constexpr int32_t UID = 100;
constexpr int32_t GID = 100;
constexpr int64_t LAST_MODIFY_TIME = 8707247;
constexpr bool IS_DIR = false;
std::string TEST_STRING = "test.string";
}; // namespace
class BmsInstallDaemonIpcTest : public testing::Test {
public:
    BmsInstallDaemonIpcTest();
    ~BmsInstallDaemonIpcTest();
    static void SetUpTestCase();
    static void TearDownTestCase();
    sptr<InstalldProxy> GetInstallProxy();
    void SetUp();
    void TearDown();

private:
    sptr<InstalldHostImpl> hostImpl_ = nullptr;
    sptr<InstalldProxy> installdProxy_ = nullptr;
};

BmsInstallDaemonIpcTest::BmsInstallDaemonIpcTest()
{}

BmsInstallDaemonIpcTest::~BmsInstallDaemonIpcTest()
{}

void BmsInstallDaemonIpcTest::SetUpTestCase()
{
}

void BmsInstallDaemonIpcTest::TearDownTestCase()
{}

void BmsInstallDaemonIpcTest::SetUp()
{}

void BmsInstallDaemonIpcTest::TearDown()
{}

sptr<InstalldProxy> BmsInstallDaemonIpcTest::GetInstallProxy()
{
    if ((hostImpl_ != nullptr) && (installdProxy_ != nullptr)) {
        return installdProxy_;
    }
    hostImpl_ = new (std::nothrow) InstalldHostImpl();
    if (hostImpl_ == nullptr || hostImpl_->AsObject() == nullptr) {
        return nullptr;
    }
    installdProxy_ = new (std::nothrow) InstalldProxy(hostImpl_->AsObject());
    if (installdProxy_ == nullptr) {
        return nullptr;
    }
    return installdProxy_;
}

/**
 * @tc.number: FileStatTest_0100
 * @tc.name: test ReadFromParcel function of FileStat
 * @tc.desc: 1. create a parcel
 *           2. ReadFromParcel
 * @tc.require: issueI5T6P3
*/
HWTEST_F(BmsInstallDaemonIpcTest, FileStatTest_0100, Function | SmallTest | Level0)
{
    Parcel parcel;
    parcel.WriteInt32(UID);
    parcel.WriteInt32(GID);
    parcel.WriteInt64(LAST_MODIFY_TIME);
    parcel.WriteBool(IS_DIR);
    FileStat fileStat;
    auto ret = fileStat.ReadFromParcel(parcel);
    EXPECT_TRUE(ret);
    EXPECT_EQ(fileStat.uid, UID);
    EXPECT_EQ(fileStat.gid, GID);
    EXPECT_EQ(fileStat.lastModifyTime, LAST_MODIFY_TIME);
    EXPECT_EQ(fileStat.isDir, IS_DIR);
}

/**
 * @tc.number: FileStatTest_0200
 * @tc.name: test Marshalling function of FileStat
 * @tc.desc: 1. create a parceland a filestat
 *           2. calling Marshalling
 * @tc.require: issueI5T6P3
*/
HWTEST_F(BmsInstallDaemonIpcTest, FileStatTest_0200, Function | SmallTest | Level0)
{
    FileStat fileStat;
    fileStat.uid = UID;
    fileStat.gid = GID;
    fileStat.lastModifyTime = LAST_MODIFY_TIME;
    fileStat.isDir = IS_DIR;

    Parcel parcel;
    auto ret = fileStat.Marshalling(parcel);
    EXPECT_TRUE(ret);

    FileStat fileStatBack;
    ret = fileStatBack.ReadFromParcel(parcel);
    EXPECT_TRUE(ret);
    EXPECT_EQ(fileStatBack.uid, UID);
    EXPECT_EQ(fileStatBack.gid, GID);
    EXPECT_EQ(fileStatBack.lastModifyTime, LAST_MODIFY_TIME);
    EXPECT_EQ(fileStatBack.isDir, IS_DIR);
}

/**
 * @tc.number: FileStatTest_0300
 * @tc.name: test Marshalling function of FileStat
 * @tc.desc: 1. create a parceland a filestat
 *           2. calling Marshalling
 *           3. calling Unmarshalling
 * @tc.require: issueI5T6P3
*/
HWTEST_F(BmsInstallDaemonIpcTest, FileStatTest_0300, Function | SmallTest | Level0)
{
    FileStat fileStat;
    fileStat.uid = UID;
    fileStat.gid = GID;
    fileStat.lastModifyTime = LAST_MODIFY_TIME;
    fileStat.isDir = IS_DIR;

    Parcel parcel;
    auto ret = fileStat.Marshalling(parcel);
    EXPECT_TRUE(ret);

    FileStat fileStatBack;
    auto innerFileStat = fileStatBack.Unmarshalling(parcel);
    EXPECT_NE(innerFileStat, nullptr);
}

/**
 * @tc.number: InstalldProxyTest_0100
 * @tc.name: test Marshalling function of FileStat
 * @tc.desc: 1. calling CreateBundleDir of proxy
 * @tc.require: issueI5T6P3
*/
HWTEST_F(BmsInstallDaemonIpcTest, InstalldProxyTest_0100, Function | SmallTest | Level0)
{
    auto proxy = GetInstallProxy();
    EXPECT_NE(proxy, nullptr);

    auto ret = proxy->CreateBundleDir(TEST_STRING);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: InstalldProxyTest_0200
 * @tc.name: test Marshalling function of FileStat
 * @tc.desc: 1. calling ExtractModuleFiles of proxy
 * @tc.require: issueI5T6P3
*/
HWTEST_F(BmsInstallDaemonIpcTest, InstalldProxyTest_0200, Function | SmallTest | Level0)
{
    auto proxy = GetInstallProxy();
    EXPECT_NE(proxy, nullptr);

    auto ret = proxy->ExtractModuleFiles(TEST_STRING, TEST_STRING, TEST_STRING, TEST_STRING);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: InstalldProxyTest_0300
 * @tc.name: test Marshalling function of FileStat
 * @tc.desc: 1. calling RenameModuleDir of proxy
 * @tc.require: issueI5T6P3
*/
HWTEST_F(BmsInstallDaemonIpcTest, InstalldProxyTest_0300, Function | SmallTest | Level0)
{
    auto proxy = GetInstallProxy();
    EXPECT_NE(proxy, nullptr);

    auto ret = proxy->RenameModuleDir(TEST_STRING, TEST_STRING);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: InstalldProxyTest_0400
 * @tc.name: test Marshalling function of FileStat
 * @tc.desc: 1. calling CreateBundleDataDir of proxy
 * @tc.require: issueI5T6P3
*/
HWTEST_F(BmsInstallDaemonIpcTest, InstalldProxyTest_0400, Function | SmallTest | Level0)
{
    auto proxy = GetInstallProxy();
    EXPECT_NE(proxy, nullptr);

    auto ret = proxy->CreateBundleDataDir(TEST_STRING, 0, 0, 0, TEST_STRING);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: InstalldProxyTest_0500
 * @tc.name: test Marshalling function of FileStat
 * @tc.desc: 1. calling RemoveBundleDataDir of proxy
 * @tc.require: issueI5T6P3
*/
HWTEST_F(BmsInstallDaemonIpcTest, InstalldProxyTest_0500, Function | SmallTest | Level0)
{
    auto proxy = GetInstallProxy();
    EXPECT_NE(proxy, nullptr);

    auto ret = proxy->RemoveBundleDataDir(TEST_STRING, 0);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: InstalldProxyTest_0600
 * @tc.name: test Marshalling function of FileStat
 * @tc.desc: 1. calling RemoveModuleDataDir of proxy
 * @tc.require: issueI5T6P3
*/
HWTEST_F(BmsInstallDaemonIpcTest, InstalldProxyTest_0600, Function | SmallTest | Level0)
{
    auto proxy = GetInstallProxy();
    EXPECT_NE(proxy, nullptr);

    auto ret = proxy->RemoveModuleDataDir(TEST_STRING, 0);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: InstalldProxyTest_0700
 * @tc.name: test Marshalling function of FileStat
 * @tc.desc: 1. calling RemoveDir of proxy
 * @tc.require: issueI5T6P3
*/
HWTEST_F(BmsInstallDaemonIpcTest, InstalldProxyTest_0700, Function | SmallTest | Level0)
{
    auto proxy = GetInstallProxy();
    EXPECT_NE(proxy, nullptr);

    auto ret = proxy->RemoveDir(TEST_STRING);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: InstalldProxyTest_0800
 * @tc.name: test Marshalling function of FileStat
 * @tc.desc: 1. calling CleanBundleDataDir of proxy
 * @tc.require: issueI5T6P3
*/
HWTEST_F(BmsInstallDaemonIpcTest, InstalldProxyTest_0800, Function | SmallTest | Level0)
{
    auto proxy = GetInstallProxy();
    EXPECT_NE(proxy, nullptr);

    auto ret = proxy->CleanBundleDataDir(TEST_STRING);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: InstalldProxyTest_0900
 * @tc.name: test Marshalling function of FileStat
 * @tc.desc: 1. calling GetBundleStats of proxy
 * @tc.require: issueI5T6P3
*/
HWTEST_F(BmsInstallDaemonIpcTest, InstalldProxyTest_0900, Function | SmallTest | Level0)
{
    auto proxy = GetInstallProxy();
    EXPECT_NE(proxy, nullptr);

    std::vector<int64_t> vec;
    auto ret = proxy->GetBundleStats(TEST_STRING, 0, vec);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: InstalldProxyTest_1000
 * @tc.name: test Marshalling function of FileStat
 * @tc.desc: 1. calling SetDirApl of proxy
 * @tc.require: issueI5T6P3
*/
HWTEST_F(BmsInstallDaemonIpcTest, InstalldProxyTest_1000, Function | SmallTest | Level0)
{
    auto proxy = GetInstallProxy();
    EXPECT_NE(proxy, nullptr);

    auto ret = proxy->SetDirApl(TEST_STRING, TEST_STRING, TEST_STRING);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: InstalldProxyTest_1100
 * @tc.name: test Marshalling function of FileStat
 * @tc.desc: 1. calling GetBundleCachePath of proxy
 * @tc.require: issueI5T6P3
*/
HWTEST_F(BmsInstallDaemonIpcTest, InstalldProxyTest_1100, Function | SmallTest | Level0)
{
    auto proxy = GetInstallProxy();
    EXPECT_NE(proxy, nullptr);

    std::vector<std::string> vec;
    auto ret = proxy->GetBundleCachePath(TEST_STRING, vec);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: InstalldProxyTest_1200
 * @tc.name: test Marshalling function of FileStat
 * @tc.desc: 1. calling ScanDir of proxy
 * @tc.require: issueI5T6P3
*/
HWTEST_F(BmsInstallDaemonIpcTest, InstalldProxyTest_1200, Function | SmallTest | Level0)
{
    auto proxy = GetInstallProxy();
    EXPECT_NE(proxy, nullptr);

    std::vector<std::string> vec;
    auto ret = proxy->ScanDir(TEST_STRING, ScanMode::SUB_FILE_ALL, ResultMode::ABSOLUTE_PATH, vec);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: InstalldProxyTest_1300
 * @tc.name: test Marshalling function of FileStat
 * @tc.desc: 1. calling MoveFile of proxy
 * @tc.require: issueI5T6P3
*/
HWTEST_F(BmsInstallDaemonIpcTest, InstalldProxyTest_1300, Function | SmallTest | Level0)
{
    auto proxy = GetInstallProxy();
    EXPECT_NE(proxy, nullptr);

    auto ret = proxy->MoveFile(TEST_STRING, TEST_STRING);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: InstalldProxyTest_1400
 * @tc.name: test Marshalling function of FileStat
 * @tc.desc: 1. calling CopyFile of proxy
 * @tc.require: issueI5T6P3
*/
HWTEST_F(BmsInstallDaemonIpcTest, InstalldProxyTest_1400, Function | SmallTest | Level0)
{
    auto proxy = GetInstallProxy();
    EXPECT_NE(proxy, nullptr);

    auto ret = proxy->CopyFile(TEST_STRING, TEST_STRING);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: InstalldProxyTest_1500
 * @tc.name: test Marshalling function of FileStat
 * @tc.desc: 1. calling Mkdir of proxy
 * @tc.require: issueI5T6P3
*/
HWTEST_F(BmsInstallDaemonIpcTest, InstalldProxyTest_1500, Function | SmallTest | Level0)
{
    auto proxy = GetInstallProxy();
    EXPECT_NE(proxy, nullptr);

    auto ret = proxy->Mkdir(TEST_STRING, 0, 0, 0);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: InstalldProxyTest_1600
 * @tc.name: test Marshalling function of FileStat
 * @tc.desc: 1. calling GetFileStat of proxy
 * @tc.require: issueI5T6P3
*/
HWTEST_F(BmsInstallDaemonIpcTest, InstalldProxyTest_1600, Function | SmallTest | Level0)
{
    auto proxy = GetInstallProxy();
    EXPECT_NE(proxy, nullptr);

    FileStat fileStat;
    auto ret = proxy->GetFileStat(TEST_STRING, fileStat);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: InstalldProxyTest_1700
 * @tc.name: test Marshalling function of FileStat
 * @tc.desc: 1. calling ExtractDiffFiles of proxy
 * @tc.require: issueI5T6P3
*/
HWTEST_F(BmsInstallDaemonIpcTest, InstalldProxyTest_1700, Function | SmallTest | Level0)
{
    auto proxy = GetInstallProxy();
    EXPECT_NE(proxy, nullptr);

    auto ret = proxy->ExtractDiffFiles(TEST_STRING, TEST_STRING, TEST_STRING);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: InstalldProxyTest_1800
 * @tc.name: test Marshalling function of FileStat
 * @tc.desc: 1. calling ApplyDiffPatch of proxy
 * @tc.require: issueI5T6P3
*/
HWTEST_F(BmsInstallDaemonIpcTest, InstalldProxyTest_1800, Function | SmallTest | Level0)
{
    auto proxy = GetInstallProxy();
    EXPECT_NE(proxy, nullptr);

    auto ret = proxy->ApplyDiffPatch(TEST_STRING, TEST_STRING, TEST_STRING);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: InstalldProxyTest_1900
 * @tc.name: test Marshalling function of FileStat
 * @tc.desc: 1. calling IsExistDir of proxy
 * @tc.require: issueI5T6P3
*/
HWTEST_F(BmsInstallDaemonIpcTest, InstalldProxyTest_1900, Function | SmallTest | Level0)
{
    auto proxy = GetInstallProxy();
    EXPECT_NE(proxy, nullptr);

    bool isExist = true;
    auto ret = proxy->IsExistDir(TEST_STRING, isExist);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: InstalldProxyTest_2000
 * @tc.name: test Marshalling function of FileStat
 * @tc.desc: 1. calling IsDirEmpty of proxy
 * @tc.require: issueI5T6P3
*/
HWTEST_F(BmsInstallDaemonIpcTest, InstalldProxyTest_2000, Function | SmallTest | Level0)
{
    auto proxy = GetInstallProxy();
    EXPECT_NE(proxy, nullptr);

    bool isDirEmpty = true;
    auto ret = proxy->IsDirEmpty(TEST_STRING, isDirEmpty);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: InstalldProxyTest_2100
 * @tc.name: test Marshalling function of FileStat
 * @tc.desc: 1. calling ObtainQuickFixFileDir of proxy
 * @tc.require: issueI5T6P3
*/
HWTEST_F(BmsInstallDaemonIpcTest, InstalldProxyTest_2100, Function | SmallTest | Level0)
{
    auto proxy = GetInstallProxy();
    EXPECT_NE(proxy, nullptr);

    std::vector<std::string> vec;
    auto ret = proxy->ObtainQuickFixFileDir(TEST_STRING, vec);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: InstalldProxyTest_2200
 * @tc.name: test Marshalling function of FileStat
 * @tc.desc: 1. calling CopyFiles of proxy
 * @tc.require: issueI5T6P3
*/
HWTEST_F(BmsInstallDaemonIpcTest, InstalldProxyTest_2200, Function | SmallTest | Level0)
{
    auto proxy = GetInstallProxy();
    EXPECT_NE(proxy, nullptr);

    std::vector<std::string> vec;
    auto ret = proxy->CopyFiles(TEST_STRING, TEST_STRING);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: InstalldProxyTest_2300
 * @tc.name: test Marshalling function of FileStat
 * @tc.desc: 1. calling CopyFiles of proxy
 * @tc.require: issueI5T6P3
*/
HWTEST_F(BmsInstallDaemonIpcTest, InstalldProxyTest_2300, Function | SmallTest | Level0)
{
    sptr<InstalldProxy> installdProxy = new (std::nothrow) InstalldProxy(nullptr);
    EXPECT_NE(installdProxy, nullptr);

    auto ret = installdProxy->CopyFiles(TEST_STRING, TEST_STRING);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_INSTALLD_SERVICE_ERROR);
}

/**
 * @tc.number: InstalldProxyTest_2400
 * @tc.name: test Marshalling function of FileStat
 * @tc.desc: 1. calling CopyFiles of proxy
 * @tc.require: issueI5T6P3
*/
HWTEST_F(BmsInstallDaemonIpcTest, InstalldProxyTest_2400, Function | SmallTest | Level0)
{
    sptr<InstalldProxy> installdProxy = new (std::nothrow) InstalldProxy(nullptr);
    EXPECT_NE(installdProxy, nullptr);

    std::vector<std::string> vec;
    auto ret = installdProxy->ObtainQuickFixFileDir(TEST_STRING, vec);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_INSTALLD_SERVICE_ERROR);
}
} // OHOS