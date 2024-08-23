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
constexpr int32_t DATA_LENGTH = 100;
constexpr int32_t MAX_PARCEL_CAPACITY = 101 * 1024 * 1024;
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

    CreateDirParam createDirParam;
    createDirParam.bundleName = TEST_STRING;
    createDirParam.userId = 0;
    createDirParam.uid = 0;
    createDirParam.gid = 0;
    createDirParam.apl = TEST_STRING;
    createDirParam.isPreInstallApp = false;
    auto ret = proxy->CreateBundleDataDir(createDirParam);
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
    auto ret = proxy->GetBundleStats(TEST_STRING, 0, vec, 0);
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

    auto ret = proxy->SetDirApl(TEST_STRING, TEST_STRING, TEST_STRING, false, false);
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

    auto ret = proxy->ApplyDiffPatch(TEST_STRING, TEST_STRING, TEST_STRING, 0);
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

/**
 * @tc.number: InstalldProxyTest_2500
 * @tc.name: test Marshalling function of FileStat
 * @tc.desc: 1. calling CopyFiles of proxy
 * @tc.require: issueI5T6P3
*/
HWTEST_F(BmsInstallDaemonIpcTest, InstalldProxyTest_2500, Function | SmallTest | Level0)
{
    auto proxy = GetInstallProxy();
    EXPECT_NE(proxy, nullptr);

    CodeSignatureParam codeSignatureParam;
    codeSignatureParam.modulePath = TEST_STRING;
    codeSignatureParam.cpuAbi = TEST_STRING;
    codeSignatureParam.targetSoPath = TEST_STRING;
    codeSignatureParam.signatureFileDir = TEST_STRING;
    codeSignatureParam.isEnterpriseBundle = false;
    codeSignatureParam.appIdentifier = TEST_STRING;
    auto ret = proxy->VerifyCodeSignature(codeSignatureParam);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: InstalldProxyTest_2600
 * @tc.name: test Marshalling function of FileStat
 * @tc.desc: 1. calling VerifyCodeSignature of proxy
 * @tc.require: issueI5T6P3
*/
HWTEST_F(BmsInstallDaemonIpcTest, InstalldProxyTest_2600, Function | SmallTest | Level0)
{
    sptr<InstalldProxy> installdProxy = new (std::nothrow) InstalldProxy(nullptr);
    EXPECT_NE(installdProxy, nullptr);

    CodeSignatureParam codeSignatureParam;
    codeSignatureParam.modulePath = TEST_STRING;
    codeSignatureParam.cpuAbi = TEST_STRING;
    codeSignatureParam.targetSoPath = TEST_STRING;
    codeSignatureParam.signatureFileDir = TEST_STRING;
    codeSignatureParam.isEnterpriseBundle = false;
    codeSignatureParam.appIdentifier = TEST_STRING;
    auto ret = installdProxy->VerifyCodeSignature(codeSignatureParam);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_INSTALLD_SERVICE_ERROR);
}

/**
 * @tc.number: InstalldProxyTest_2700
 * @tc.name: test Marshalling function of FileStat
 * @tc.desc: 1. calling ExecuteAOT of proxy
*/
HWTEST_F(BmsInstallDaemonIpcTest, InstalldProxyTest_2700, Function | SmallTest | Level0)
{
    sptr<InstalldProxy> installdProxy = new (std::nothrow) InstalldProxy(nullptr);
    EXPECT_NE(installdProxy, nullptr);

    AOTArgs aotArgs;
    std::vector<uint8_t> pendSignData;
    auto ret = installdProxy->ExecuteAOT(aotArgs, pendSignData);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_INSTALLD_SERVICE_ERROR);
}

/**
 * @tc.number: InstalldProxyTest_2800
 * @tc.name: test Marshalling function of FileStat
 * @tc.desc: 1. calling IsExistFile of proxy
*/
HWTEST_F(BmsInstallDaemonIpcTest, InstalldProxyTest_2800, Function | SmallTest | Level0)
{
    sptr<InstalldProxy> installdProxy = new (std::nothrow) InstalldProxy(nullptr);
    EXPECT_NE(installdProxy, nullptr);

    bool isExist = false;
    auto ret = installdProxy->IsExistFile("data/test", isExist);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_INSTALLD_SERVICE_ERROR);
}

/**
 * @tc.number: InstalldProxyTest_2900
 * @tc.name: test Marshalling function of FileStat
 * @tc.desc: 1. calling GetNativeLibraryFileNames of proxy
*/
HWTEST_F(BmsInstallDaemonIpcTest, InstalldProxyTest_2900, Function | SmallTest | Level0)
{
    sptr<InstalldProxy> installdProxy = new (std::nothrow) InstalldProxy(nullptr);
    EXPECT_NE(installdProxy, nullptr);

    std::vector<std::string> fileNames;
    std::string apuAbi = "libs/arm";
    auto ret = installdProxy->GetNativeLibraryFileNames("data/test", apuAbi, fileNames);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_INSTALLD_SERVICE_ERROR);
}

/**
 * @tc.number: InstalldProxyTest_3000
 * @tc.name: test Marshalling function of CheckEncryptionParam
 * @tc.desc: 1. calling CheckEncryption of proxy
*/
HWTEST_F(BmsInstallDaemonIpcTest, InstalldProxyTest_3000, Function | SmallTest | Level0)
{
    auto proxy = GetInstallProxy();
    EXPECT_NE(proxy, nullptr);

    CheckEncryptionParam checkEncryptionParam;
    checkEncryptionParam.modulePath = TEST_STRING;
    checkEncryptionParam.cpuAbi = TEST_STRING;
    checkEncryptionParam.targetSoPath = TEST_STRING;
    checkEncryptionParam.bundleId = -1;
    bool isEncrypted = false;
    auto ret = proxy->CheckEncryption(checkEncryptionParam, isEncrypted);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: InstalldProxyTest_3100
 * @tc.name: test Marshalling function of CheckEncryptionParam
 * @tc.desc: 1. calling CheckEncryption of proxy
*/
HWTEST_F(BmsInstallDaemonIpcTest, InstalldProxyTest_3100, Function | SmallTest | Level0)
{
    sptr<InstalldProxy> installdProxy = new (std::nothrow) InstalldProxy(nullptr);
    EXPECT_NE(installdProxy, nullptr);

    CheckEncryptionParam checkEncryptionParam;
    checkEncryptionParam.modulePath = TEST_STRING;
    checkEncryptionParam.cpuAbi = TEST_STRING;
    checkEncryptionParam.targetSoPath = TEST_STRING;
    checkEncryptionParam.bundleId = -1;
    bool isEncrypted = false;
    auto ret = installdProxy->CheckEncryption(checkEncryptionParam, isEncrypted);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_INSTALLD_SERVICE_ERROR);
}

/**
 * @tc.number: InstalldProxyTest_3200
 * @tc.name: test Marshalling function of CreateBundleDataDirWithVector
 * @tc.desc: 1. calling CreateBundleDataDirWithVector of proxy
*/
HWTEST_F(BmsInstallDaemonIpcTest, InstalldProxyTest_3200, Function | SmallTest | Level0)
{
    sptr<InstalldProxy> installdProxy = new (std::nothrow) InstalldProxy(nullptr);
    EXPECT_NE(installdProxy, nullptr);

    std::vector<CreateDirParam> createDirParams;
    auto ret = installdProxy->CreateBundleDataDirWithVector(createDirParams);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INVALID_PARAMETER);

    CreateDirParam createDirParam;
    createDirParams.push_back(createDirParam);
    ret = installdProxy->CreateBundleDataDirWithVector(createDirParams);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_INSTALLD_SERVICE_ERROR);
}

/**
 * @tc.number: InstalldProxyTest_3300
 * @tc.name: test Marshalling function of GetAllBundleStats
 * @tc.desc: 1. calling GetAllBundleStats of proxy
*/
HWTEST_F(BmsInstallDaemonIpcTest, InstalldProxyTest_3300, Function | SmallTest | Level0)
{
    sptr<InstalldProxy> installdProxy = new (std::nothrow) InstalldProxy(nullptr);
    EXPECT_NE(installdProxy, nullptr);

    std::vector<std::string> bundleNames;
    std::vector<int64_t> bundleStats;
    std::vector<int32_t> uids;
    bundleNames.push_back(TEST_STRING);
    bundleStats.push_back(LAST_MODIFY_TIME);
    uids.push_back(UID);
    auto ret = installdProxy->GetAllBundleStats(bundleNames, UID, bundleStats, uids);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_INSTALLD_SERVICE_ERROR);
}

/**
 * @tc.number: InstalldProxyTest_3400
 * @tc.name: test Marshalling function of IsExistApFile
 * @tc.desc: 1. calling IsExistApFile of proxy
*/
HWTEST_F(BmsInstallDaemonIpcTest, InstalldProxyTest_3400, Function | SmallTest | Level0)
{
    sptr<InstalldProxy> installdProxy = new (std::nothrow) InstalldProxy(nullptr);
    EXPECT_NE(installdProxy, nullptr);

    bool isExist = true;
    auto ret = installdProxy->IsExistApFile(TEST_STRING, isExist);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_INSTALLD_SERVICE_ERROR);
}

/**
 * @tc.number: InstalldProxyTest_3500
 * @tc.name: test Marshalling function of MoveFiles
 * @tc.desc: 1. calling MoveFiles of proxy
*/
HWTEST_F(BmsInstallDaemonIpcTest, InstalldProxyTest_3500, Function | SmallTest | Level0)
{
    sptr<InstalldProxy> installdProxy = new (std::nothrow) InstalldProxy(nullptr);
    EXPECT_NE(installdProxy, nullptr);

    auto ret = installdProxy->MoveFiles(TEST_STRING, TEST_STRING);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_INSTALLD_SERVICE_ERROR);
}

/**
 * @tc.number: InstalldProxyTest_3600
 * @tc.name: test Marshalling function of ExtractDriverSoFiles
 * @tc.desc: 1. calling ExtractDriverSoFiles of proxy
*/
HWTEST_F(BmsInstallDaemonIpcTest, InstalldProxyTest_3600, Function | SmallTest | Level0)
{
    sptr<InstalldProxy> installdProxy = new (std::nothrow) InstalldProxy(nullptr);
    EXPECT_NE(installdProxy, nullptr);

    std::unordered_multimap<std::string, std::string> dirMap;
    auto ret = installdProxy->ExtractDriverSoFiles(TEST_STRING, dirMap);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_INSTALLD_SERVICE_ERROR);
}

/**
 * @tc.number: InstalldProxyTest_3600
 * @tc.name: test Marshalling function of ExtractEncryptedSoFiles
 * @tc.desc: 1. calling ExtractEncryptedSoFiles of proxy
*/
HWTEST_F(BmsInstallDaemonIpcTest, InstalldProxyTest_3700, Function | SmallTest | Level0)
{
    sptr<InstalldProxy> installdProxy = new (std::nothrow) InstalldProxy(nullptr);
    EXPECT_NE(installdProxy, nullptr);

    std::unordered_multimap<std::string, std::string> dirMap;
    auto ret = installdProxy->ExtractEncryptedSoFiles(TEST_STRING, TEST_STRING, TEST_STRING, TEST_STRING, UID);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_INSTALLD_SERVICE_ERROR);
}

/**
 * @tc.number: InstalldProxyTest_3800
 * @tc.name: test Marshalling function of VerifyCodeSignatureForHap
 * @tc.desc: 1. calling VerifyCodeSignatureForHap of proxy
*/
HWTEST_F(BmsInstallDaemonIpcTest, InstalldProxyTest_3800, Function | SmallTest | Level0)
{
    sptr<InstalldProxy> installdProxy = new (std::nothrow) InstalldProxy(nullptr);
    EXPECT_NE(installdProxy, nullptr);

    CodeSignatureParam codeSignatureParam;
    auto ret = installdProxy->VerifyCodeSignatureForHap(codeSignatureParam);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_INSTALLD_SERVICE_ERROR);
}

/**
 * @tc.number: InstalldProxyTest_3900
 * @tc.name: test Marshalling function of DeliverySignProfile
 * @tc.desc: 1. calling DeliverySignProfile of proxy
*/
HWTEST_F(BmsInstallDaemonIpcTest, InstalldProxyTest_3900, Function | SmallTest | Level0)
{
    sptr<InstalldProxy> installdProxy = new (std::nothrow) InstalldProxy(nullptr);
    EXPECT_NE(installdProxy, nullptr);

    unsigned char *profileBlock;
    auto ret = installdProxy->DeliverySignProfile(TEST_STRING, DATA_LENGTH, profileBlock);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);

    ret = installdProxy->DeliverySignProfile(TEST_STRING, MAX_PARCEL_CAPACITY, profileBlock);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
}

/**
 * @tc.number: InstalldProxyTest_4000
 * @tc.name: test Marshalling function of RemoveSignProfile
 * @tc.desc: 1. calling RemoveSignProfile of proxy
*/
HWTEST_F(BmsInstallDaemonIpcTest, InstalldProxyTest_4000, Function | SmallTest | Level0)
{
    sptr<InstalldProxy> installdProxy = new (std::nothrow) InstalldProxy(nullptr);
    EXPECT_NE(installdProxy, nullptr);

    auto ret = installdProxy->RemoveSignProfile(TEST_STRING);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_INSTALLD_SERVICE_ERROR);
}

/**
 * @tc.number: InstalldProxyTest_4100
 * @tc.name: test function SetEncryptionPolicy
 * @tc.desc: 1. calling SetEncryptionPolicy of proxy
*/
HWTEST_F(BmsInstallDaemonIpcTest, InstalldProxyTest_4100, Function | SmallTest | Level0)
{
    auto proxy = GetInstallProxy();
    EXPECT_NE(proxy, nullptr);

    int32_t uid = 0;
    std::string bundleName = TEST_STRING;
    int32_t userId = 100;
    std::string keyId = "";
    auto ret = proxy->SetEncryptionPolicy(uid, bundleName, userId, keyId);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: InstalldProxyTest_4200
 * @tc.name: test function DeleteEncryptionKeyId
 * @tc.desc: 1. calling DeleteEncryptionKeyId of proxy
*/
HWTEST_F(BmsInstallDaemonIpcTest, InstalldProxyTest_4200, Function | SmallTest | Level0)
{
    auto proxy = GetInstallProxy();
    EXPECT_NE(proxy, nullptr);

    std::string bundleName = TEST_STRING;
    int32_t userId = 100;
    auto ret = proxy->DeleteEncryptionKeyId(bundleName, userId);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: InstalldProxyTest_4300
 * @tc.name: test function CleanBundleDataDirByName
 * @tc.desc: 1. calling CleanBundleDataDirByName of proxy
 */
HWTEST_F(BmsInstallDaemonIpcTest, InstalldProxyTest_4300, Function | SmallTest | Level0)
{
    auto proxy = GetInstallProxy();
    EXPECT_NE(proxy, nullptr);

    std::string bundleName = TEST_STRING;
    int userId = 100;
    int appIndex = 1;
    auto ret = proxy->CleanBundleDataDirByName(TEST_STRING, userId, appIndex);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: InstalldProxyTest_4400
 * @tc.name: test function GetExtensionSandboxTypeList
 * @tc.desc: 1. calling GetExtensionSandboxTypeList of proxy
 */
HWTEST_F(BmsInstallDaemonIpcTest, InstalldProxyTest_4400, Function | SmallTest | Level0)
{
    auto proxy = GetInstallProxy();
    ASSERT_NE(proxy, nullptr);
    std::vector<std::string> types;
    auto ret = proxy->GetExtensionSandboxTypeList(types);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: InstalldProxyTest_4500
 * @tc.name: test function of DeliverySignProfile
 * @tc.desc: 1. calling DeliverySignProfile of proxy
 */
HWTEST_F(BmsInstallDaemonIpcTest, InstalldProxyTest_4500, Function | SmallTest | Level0)
{
    auto proxy = GetInstallProxy();
    ASSERT_NE(proxy, nullptr);

    int32_t profileBlockLength = 1;
    unsigned char *profileBlock = new unsigned char[1];
    auto ret = proxy->DeliverySignProfile(TEST_STRING, profileBlockLength, profileBlock);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: InstalldProxyTest_4600
 * @tc.name: test function of RemoveExtensionDir
 * @tc.desc: 1. calling RemoveExtensionDir of proxy
 */
HWTEST_F(BmsInstallDaemonIpcTest, InstalldProxyTest_4600, Function | SmallTest | Level0)
{
    auto proxy = GetInstallProxy();
    ASSERT_NE(proxy, nullptr);
    int32_t userid = 0;
    std::vector<std::string> extensionBundleDirs;
    extensionBundleDirs.push_back(TEST_STRING);
    extensionBundleDirs.push_back(TEST_STRING);
    auto ret = proxy->RemoveExtensionDir(userid, extensionBundleDirs);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: InstalldProxyTest_4700
 * @tc.name: test function of VerifyCodeSignatureForHap
 * @tc.desc: 1. calling VerifyCodeSignatureForHap of proxy
 */
HWTEST_F(BmsInstallDaemonIpcTest, InstalldProxyTest_4700, Function | SmallTest | Level0)
{
    auto proxy = GetInstallProxy();
    ASSERT_NE(proxy, nullptr);

    CodeSignatureParam codeSignatureParam;
    codeSignatureParam.modulePath = TEST_STRING;
    codeSignatureParam.cpuAbi = TEST_STRING;
    codeSignatureParam.targetSoPath = TEST_STRING;
    codeSignatureParam.signatureFileDir = TEST_STRING;
    codeSignatureParam.isEnterpriseBundle = false;
    codeSignatureParam.appIdentifier = TEST_STRING;
    auto ret = proxy->VerifyCodeSignatureForHap(codeSignatureParam);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: InstalldProxyTest_4800
 * @tc.name: test function of CreateExtensionDataDir
 * @tc.desc: 1. calling CreateExtensionDataDir of proxy
 */
HWTEST_F(BmsInstallDaemonIpcTest, InstalldProxyTest_4800, Function | SmallTest | Level0)
{
    auto proxy = GetInstallProxy();
    ASSERT_NE(proxy, nullptr);

    CreateDirParam createDirParam;
    createDirParam.bundleName = TEST_STRING;
    createDirParam.userId = 0;
    createDirParam.uid = 0;
    createDirParam.gid = 0;
    createDirParam.apl = TEST_STRING;
    createDirParam.isPreInstallApp = false;
    createDirParam.createDirFlag = CreateDirFlag::CREATE_DIR_UNLOCKED;
    ErrCode res = proxy->CreateExtensionDataDir(createDirParam);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: InstalldProxyTest_4900
 * @tc.name: test Marshalling function of RemoveSignProfile
 * @tc.desc: 1. calling RemoveSignProfile of proxy
 */
HWTEST_F(BmsInstallDaemonIpcTest, InstalldProxyTest_4900, Function | SmallTest | Level0)
{
    auto proxy = GetInstallProxy();
    ASSERT_NE(proxy, nullptr);

    auto ret = proxy->RemoveSignProfile(TEST_STRING);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: InstalldProxyTest_5000
 * @tc.name: test Marshalling function of CreateBundleDataDirWithVector
 * @tc.desc: 1. calling CreateBundleDataDirWithVector of proxy
 */
HWTEST_F(BmsInstallDaemonIpcTest, InstalldProxyTest_5000, Function | SmallTest | Level0)
{
    auto proxy = GetInstallProxy();
    ASSERT_NE(proxy, nullptr);

    std::vector<CreateDirParam> createDirParams;
    CreateDirParam createDirParam;
    createDirParams.push_back(createDirParam);
    auto ret = proxy->CreateBundleDataDirWithVector(createDirParams);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: InstalldProxyTest_5100
 * @tc.name: test Marshalling function of StopAOT
 * @tc.desc: 1. calling StopAOT of proxy
 */
HWTEST_F(BmsInstallDaemonIpcTest, InstalldProxyTest_5100, Function | SmallTest | Level0)
{
    auto proxy = GetInstallProxy();
    ASSERT_NE(proxy, nullptr);

    auto ret = proxy->StopAOT();
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: InstalldProxyTest_5200
 * @tc.name: test Marshalling function of ExecuteAOT
 * @tc.desc: 1. calling ExecuteAOT of proxy
 */
HWTEST_F(BmsInstallDaemonIpcTest, InstalldProxyTest_5200, Function | SmallTest | Level0)
{
    auto proxy = GetInstallProxy();
    ASSERT_NE(proxy, nullptr);

    AOTArgs aotArgs;
    std::vector<uint8_t> pendSignData;
    auto ret = proxy->ExecuteAOT(aotArgs, pendSignData);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: InstalldProxyTest_5300
 * @tc.name: test Marshalling function of PendSignAOT
 * @tc.desc: 1. calling PendSignAOT of proxy
 */
HWTEST_F(BmsInstallDaemonIpcTest, InstalldProxyTest_5300, Function | SmallTest | Level0)
{
    auto proxy = GetInstallProxy();
    ASSERT_NE(proxy, nullptr);

    std::string anFileName = TEST_STRING;
    std::vector<uint8_t> signData;
    auto ret = proxy->PendSignAOT(anFileName, signData);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: InstalldProxyTest_5400
 * @tc.name: test Marshalling function of FileStat
 * @tc.desc: 1. calling IsExistFile of proxy
 */
HWTEST_F(BmsInstallDaemonIpcTest, InstalldProxyTest_5400, Function | SmallTest | Level0)
{
    auto proxy = GetInstallProxy();
    ASSERT_NE(proxy, nullptr);

    bool isExist = false;
    auto ret = proxy->IsExistFile("data/test", isExist);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: InstalldProxyTest_5500
 * @tc.name: test Marshalling function of IsExistApFile
 * @tc.desc: 1. calling IsExistApFile of proxy
 */
HWTEST_F(BmsInstallDaemonIpcTest, InstalldProxyTest_5500, Function | SmallTest | Level0)
{
    auto proxy = GetInstallProxy();
    ASSERT_NE(proxy, nullptr);

    bool isExist = true;
    auto ret = proxy->IsExistApFile(TEST_STRING, isExist);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: InstalldProxyTest_5600
 * @tc.name: test Marshalling function of FileStat
 * @tc.desc: 1. calling IsDirEmpty of proxy
 */
HWTEST_F(BmsInstallDaemonIpcTest, InstalldProxyTest_5600, Function | SmallTest | Level0)
{
    sptr<InstalldProxy> proxy = new (std::nothrow) InstalldProxy(nullptr);
    ASSERT_NE(proxy, nullptr);

    bool isDirEmpty = true;
    auto ret = proxy->IsDirEmpty(TEST_STRING, isDirEmpty);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_INSTALLD_SERVICE_ERROR);
}

/**
 * @tc.number: InstalldProxyTest_5700
 * @tc.name: test Marshalling function of MoveFiles
 * @tc.desc: 1. calling MoveFiles of proxy
 */
HWTEST_F(BmsInstallDaemonIpcTest, InstalldProxyTest_5700, Function | SmallTest | Level0)
{
    auto proxy = GetInstallProxy();
    ASSERT_NE(proxy, nullptr);

    auto ret = proxy->MoveFiles(TEST_STRING, TEST_STRING);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: InstalldProxyTest_5800
 * @tc.name: test Marshalling function of ExtractDriverSoFiles
 * @tc.desc: 1. calling ExtractDriverSoFiles of proxy
 */
HWTEST_F(BmsInstallDaemonIpcTest, InstalldProxyTest_5800, Function | SmallTest | Level0)
{
    auto proxy = GetInstallProxy();
    ASSERT_NE(proxy, nullptr);

    std::unordered_multimap<std::string, std::string> dirMap;
    dirMap.insert(std::make_pair(TEST_STRING, TEST_STRING));
    auto ret = proxy->ExtractDriverSoFiles(TEST_STRING, dirMap);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: InstalldProxyTest_5900
 * @tc.name: test Marshalling function of ExtractEncryptedSoFiles
 * @tc.desc: 1. calling ExtractEncryptedSoFiles of proxy
 */
HWTEST_F(BmsInstallDaemonIpcTest, InstalldProxyTest_5900, Function | SmallTest | Level0)
{
    auto proxy = GetInstallProxy();
    ASSERT_NE(proxy, nullptr);

    auto ret = proxy->ExtractEncryptedSoFiles(TEST_STRING, TEST_STRING, TEST_STRING, TEST_STRING, UID);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: InstalldProxyTest_6000
 * @tc.name: test function SetEncryptionPolicy
 * @tc.desc: 1. calling SetEncryptionPolicy of proxy
 */
HWTEST_F(BmsInstallDaemonIpcTest, InstalldProxyTest_6000, Function | SmallTest | Level0)
{
    sptr<InstalldProxy> proxy = new (std::nothrow) InstalldProxy(nullptr);
    ASSERT_NE(proxy, nullptr);

    int32_t uid = 0;
    std::string bundleName = TEST_STRING;
    int32_t userId = 100;
    std::string keyId = "";
    auto ret = proxy->SetEncryptionPolicy(uid, bundleName, userId, keyId);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_INSTALLD_SERVICE_ERROR);
}

/**
 * @tc.number: InstalldProxyTest_6100
 * @tc.name: test function DeleteEncryptionKeyId
 * @tc.desc: 1. calling DeleteEncryptionKeyId of proxy
 */
HWTEST_F(BmsInstallDaemonIpcTest, InstalldProxyTest_6100, Function | SmallTest | Level0)
{
    sptr<InstalldProxy> proxy = new (std::nothrow) InstalldProxy(nullptr);
    ASSERT_NE(proxy, nullptr);

    std::string bundleName = TEST_STRING;
    int32_t userId = 100;
    auto ret = proxy->DeleteEncryptionKeyId(bundleName, userId);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_INSTALLD_SERVICE_ERROR);
}

/**
 * @tc.number: InstalldProxyTest_6200
 * @tc.name: test function of RemoveExtensionDir
 * @tc.desc: 1. calling RemoveExtensionDir of proxy
 */
HWTEST_F(BmsInstallDaemonIpcTest, InstalldProxyTest_6200, Function | SmallTest | Level0)
{
    auto proxy = GetInstallProxy();
    ASSERT_NE(proxy, nullptr);

    int32_t userid = 0;
    std::vector<std::string> extensionBundleDirs;
    for (size_t i = 0; i < 1200; i++) {
        extensionBundleDirs.push_back(TEST_STRING);
    }
    auto ret = proxy->RemoveExtensionDir(userid, extensionBundleDirs);
    EXPECT_EQ(ret, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.number: InstalldProxyTest_6300
 * @tc.name: test function of RemoveExtensionDir
 * @tc.desc: 1. calling RemoveExtensionDir of proxy
 */
HWTEST_F(BmsInstallDaemonIpcTest, InstalldProxyTest_6300, Function | SmallTest | Level0)
{
    auto proxy = GetInstallProxy();
    ASSERT_NE(proxy, nullptr);

    int32_t userid = 0;
    std::vector<std::string> extensionBundleDirs;
    std::string extensionBundleDir(2000, ' ');
    extensionBundleDirs.push_back(extensionBundleDir);
    auto ret = proxy->RemoveExtensionDir(userid, extensionBundleDirs);
    EXPECT_EQ(ret, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.number: InstalldProxyTest_6400
 * @tc.name: test function of IsExistExtensionDir
 * @tc.desc: 1. calling IsExistExtensionDir of proxy
 */
HWTEST_F(BmsInstallDaemonIpcTest, InstalldProxyTest_6400, Function | SmallTest | Level0)
{
    auto proxy = GetInstallProxy();
    ASSERT_NE(proxy, nullptr);

    int32_t userid = 0;
    std::string extensionBundleDir(2000, ' ');
    bool isExist = false;
    auto ret = proxy->IsExistExtensionDir(userid, extensionBundleDir, isExist);
    EXPECT_EQ(ret, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.number: InstalldProxyTest_6500
 * @tc.name: test function of IsExistExtensionDir
 * @tc.desc: 1. calling IsExistExtensionDir of proxy
 */
HWTEST_F(BmsInstallDaemonIpcTest, InstalldProxyTest_6500, Function | SmallTest | Level0)
{
    auto proxy = GetInstallProxy();
    ASSERT_NE(proxy, nullptr);

    int32_t userid = 0;
    bool isExist = false;
    auto ret = proxy->IsExistExtensionDir(userid, TEST_STRING, isExist);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: InstalldProxyTest_6600
 * @tc.name: test Marshalling function of FileStat
 * @tc.desc: 1. calling GetBundleStats of proxy
 */
HWTEST_F(BmsInstallDaemonIpcTest, InstalldProxyTest_6600, Function | SmallTest | Level0)
{
    sptr<InstalldProxy> proxy = new (std::nothrow) InstalldProxy(nullptr);
    ASSERT_NE(proxy, nullptr);

    std::vector<int64_t> vec;
    auto ret = proxy->GetBundleStats(TEST_STRING, 0, vec, 0);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_INSTALLD_SERVICE_ERROR);
}

/**
 * @tc.number: InstalldProxyTest_6700
 * @tc.name: test Marshalling function of GetAllBundleStats
 * @tc.desc: 1. calling GetAllBundleStats of proxy
 */
HWTEST_F(BmsInstallDaemonIpcTest, InstalldProxyTest_6700, Function | SmallTest | Level0)
{
    auto proxy = GetInstallProxy();
    ASSERT_NE(proxy, nullptr);

    std::vector<std::string> bundleNames;
    std::vector<int64_t> bundleStats;
    std::vector<int32_t> uids;
    bundleNames.push_back(TEST_STRING);
    bundleStats.push_back(LAST_MODIFY_TIME);
    uids.push_back(UID);
    auto ret = proxy->GetAllBundleStats(bundleNames, UID, bundleStats, uids);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: InstalldProxyTest_6800
 * @tc.name: test Marshalling function of FileStat
 * @tc.desc: 1. calling SetDirApl of proxy
 */
HWTEST_F(BmsInstallDaemonIpcTest, InstalldProxyTest_6800, Function | SmallTest | Level0)
{
    sptr<InstalldProxy> proxy = new (std::nothrow) InstalldProxy(nullptr);
    ASSERT_NE(proxy, nullptr);

    auto ret = proxy->SetDirApl(TEST_STRING, TEST_STRING, TEST_STRING, false, false);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_INSTALLD_SERVICE_ERROR);
}
} // OHOS