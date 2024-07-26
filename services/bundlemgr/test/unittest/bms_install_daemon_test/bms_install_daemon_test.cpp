/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include <cstdio>
#include <gtest/gtest.h>
#include <sys/stat.h>
#include <unistd.h>

#include "bundle_constants.h"
#include "directory_ex.h"
#include "installd/installd_service.h"
#include "installd_client.h"

using namespace testing::ext;
using namespace OHOS::AppExecFwk;
namespace OHOS {
namespace {
const std::string BUNDLE_NAME13 = "com.example.l3jsdemo";
const std::string BUNDLE_FILE = "/data/test/resource/bms/install_daemon/right.hap";
const std::string SYSTEM_DIR = "/sys/com.example.l3jsdemo";
const std::string TEMP_DIR = "/data/app/el1/bundle/public/com.example.l3jsdemo/temp";
const std::string MODULE_DIR = "/data/app/el1/bundle/public/com.example.l3jsdemo/com.example.l3jsdemo";
const std::string BUNDLE_DATA_DIR = "/data/app/el2/100/base/com.example.l3jsdemo";
const std::string BUNDLE_DATA_DIR_CACHE = "/data/app/el2/100/base/com.example.l3jsdemo/cache/temp";
const std::string BUNDLE_DATA_DIR_TEMP = "/data/app/el2/100/base/com.example.l3jsdemo/files/temp";
const std::string BUNDLE_DATA_DIR_DATA_BASE = "/data/app/el2/100/database/com.example.l3jsdemo";
const std::string BUNDLE_DATA_DIR_DATA_BASE_TEMP = "/data/app/el2/100/database/com.example.l3jsdemo/temp";
const std::string BUNDLE_CODE_DIR = "/data/app/el1/bundle/public/com.example.l3jsdemo";
const std::string BUNDLE_CODE_DIR_CODE = "/data/app/el1/bundle/public/com.example.l3jsdemo/code";
const std::string BUNDLE_NAME = "com.example.l4jsdemo";
const std::string TEST_CPU_ABI = "arm64";
const std::string HAP_FILE_PATH =
    "/data/app/el1/bundle/public/com.example.test/entry.hap";
const std::string TEST_PATH = "/data/app/el1/bundle/public/com.example.test/";
const int32_t USERID = 100;
const int32_t UID = 1000;
const int32_t GID = 1000;
const std::string APL = "normal";
}  // namespace

class BmsInstallDaemonTest : public testing::Test {
public:
    BmsInstallDaemonTest();
    ~BmsInstallDaemonTest();
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

    int CreateBundleDir(const std::string &bundleDir) const;
    int CreateBundleDataDir(const std::string &bundleDir, const int32_t userid, const int32_t uid, const int32_t gid,
        const std::string &apl) const;
    int RemoveBundleDir(const std::string &bundleDir) const;
    int RemoveBundleDataDir(const std::string &bundleDataDir) const;
    int CleanBundleDataDir(const std::string &bundleDataDir) const;
    int ExtractModuleFiles(const std::string &srcModulePath, const std::string &targetPath,
        const std::string &targetSoPath, const std::string &cpuAbi) const;
    int ExtractFiles(const ExtractParam &extractParam) const;
    int RenameModuleDir(const std::string &oldPath, const std::string &newPath) const;
    bool CheckBundleDirExist() const;
    bool CheckBundleDataDirExist() const;
    bool GetBundleStats(const std::string &bundleName, const int32_t userId,
        std::vector<int64_t> &bundleStats, const int32_t uid) const;
    int32_t GetNativeLibraryFileNames(const std::string &filePath, const std::string &cpuAbi,
        std::vector<std::string> &fileNames) const;
private:
    std::shared_ptr<InstalldService> service_ = std::make_shared<InstalldService>();
};

BmsInstallDaemonTest::BmsInstallDaemonTest()
{}

BmsInstallDaemonTest::~BmsInstallDaemonTest()
{}

void BmsInstallDaemonTest::SetUpTestCase()
{}

void BmsInstallDaemonTest::TearDownTestCase()
{}

void BmsInstallDaemonTest::SetUp()
{
    setuid(Constants::FOUNDATION_UID);
}

void BmsInstallDaemonTest::TearDown()
{
    // clear files.
    OHOS::ForceRemoveDirectory(BUNDLE_CODE_DIR);
    OHOS::ForceRemoveDirectory(BUNDLE_DATA_DIR);
    OHOS::ForceRemoveDirectory(BUNDLE_DATA_DIR_DATA_BASE);

    if (service_->IsServiceReady()) {
        service_->Stop();
        InstalldClient::GetInstance()->ResetInstalldProxy();
    }
}

int BmsInstallDaemonTest::CreateBundleDir(const std::string &bundleDir) const
{
    if (!service_->IsServiceReady()) {
        service_->Start();
    }
    return InstalldClient::GetInstance()->CreateBundleDir(bundleDir);
}

int BmsInstallDaemonTest::CreateBundleDataDir(const std::string &bundleDataDir,
    const int32_t userid, const int32_t uid, const int32_t gid, const std::string &apl) const
{
    if (!service_->IsServiceReady()) {
        service_->Start();
    }
    CreateDirParam createDirParam;
    createDirParam.bundleName = bundleDataDir;
    createDirParam.userId = userid;
    createDirParam.uid = uid;
    createDirParam.gid = gid;
    createDirParam.apl = apl;
    createDirParam.isPreInstallApp = false;
    return InstalldClient::GetInstance()->CreateBundleDataDir(createDirParam);
}

int BmsInstallDaemonTest::RemoveBundleDir(const std::string &bundleDir) const
{
    if (!service_->IsServiceReady()) {
        service_->Start();
    }
    return InstalldClient::GetInstance()->RemoveDir(bundleDir);
}

int BmsInstallDaemonTest::RemoveBundleDataDir(const std::string &bundleDataDir) const
{
    if (!service_->IsServiceReady()) {
        service_->Start();
    }
    return InstalldClient::GetInstance()->RemoveDir(bundleDataDir);
}

int BmsInstallDaemonTest::CleanBundleDataDir(const std::string &bundleDataDir) const
{
    if (!service_->IsServiceReady()) {
        service_->Start();
    }
    return InstalldClient::GetInstance()->CleanBundleDataDir(bundleDataDir);
}

int BmsInstallDaemonTest::ExtractModuleFiles(const std::string &srcModulePath, const std::string &targetPath,
    const std::string &targetSoPath, const std::string &cpuAbi) const
{
    if (!service_->IsServiceReady()) {
        service_->Start();
    }
    return InstalldClient::GetInstance()->ExtractModuleFiles(srcModulePath, targetPath, targetSoPath, cpuAbi);
}

int BmsInstallDaemonTest::ExtractFiles(const ExtractParam &extractParam) const
{
    if (!service_->IsServiceReady()) {
        service_->Start();
    }
    return InstalldClient::GetInstance()->ExtractFiles(extractParam);
}

int BmsInstallDaemonTest::RenameModuleDir(const std::string &oldPath, const std::string &newPath) const
{
    if (!service_->IsServiceReady()) {
        service_->Start();
    }
    return InstalldClient::GetInstance()->RenameModuleDir(oldPath, newPath);
}

bool BmsInstallDaemonTest::CheckBundleDirExist() const
{
    int bundleCodeExist = access(BUNDLE_CODE_DIR.c_str(), F_OK);
    if (bundleCodeExist == 0) {
        return true;
    }
    return false;
}

bool BmsInstallDaemonTest::CheckBundleDataDirExist() const
{
    int bundleDataExist = access(BUNDLE_DATA_DIR.c_str(), F_OK);
    if (bundleDataExist == 0) {
        return true;
    }
    return false;
}

bool BmsInstallDaemonTest::GetBundleStats(const std::string &bundleName, const int32_t userId,
    std::vector<int64_t> &bundleStats, const int32_t uid) const
{
    if (!service_->IsServiceReady()) {
        service_->Start();
    }
    if (InstalldClient::GetInstance()->GetBundleStats(bundleName, userId, bundleStats, uid) == ERR_OK) {
        return true;
    }
    return false;
}

int32_t BmsInstallDaemonTest::GetNativeLibraryFileNames(const std::string &filePath, const std::string &cpuAbi,
    std::vector<std::string> &fileNames) const
{
    if (!service_->IsServiceReady()) {
        service_->Start();
    }
    return InstalldClient::GetInstance()->GetNativeLibraryFileNames(filePath, cpuAbi, fileNames);
}

/**
 * @tc.number: Startup_0100
 * @tc.name: test the start function of the installd service when service is not ready
 * @tc.desc: 1. the service is not initialized
 *           2. the non initialized installd service can be started
*/
HWTEST_F(BmsInstallDaemonTest, Startup_0100, Function | SmallTest | Level0)
{
    std::shared_ptr<InstalldService> installdService = std::make_shared<InstalldService>();
    EXPECT_NE(installdService, nullptr);
    bool ready = installdService->IsServiceReady();
    EXPECT_EQ(false, ready);
    installdService->Start();
    ready = installdService->IsServiceReady();
    EXPECT_EQ(true, ready);
}

/**
 * @tc.number: Startup_0200
 * @tc.name: test the stop function of the installd service when service is ready
 * @tc.desc: 1. the service is already initialized
 *           2. the initialized installd service can be stopped
*/
HWTEST_F(BmsInstallDaemonTest, Startup_0200, Function | SmallTest | Level0)
{
    std::shared_ptr<InstalldService> installdService = std::make_shared<InstalldService>();
    EXPECT_NE(installdService, nullptr);
    installdService->Start();
    bool ready = installdService->IsServiceReady();
    EXPECT_EQ(true, ready);
    installdService->Stop();
    ready = installdService->IsServiceReady();
    EXPECT_EQ(false, ready);
}

/**
 * @tc.number: Startup_0300
 * @tc.name: test the restart function of the installd service
 * @tc.desc: 1. the service is already initialized
 *           2. the stopped installd service can be restarted
*/
HWTEST_F(BmsInstallDaemonTest, Startup_0300, Function | SmallTest | Level0)
{
    std::shared_ptr<InstalldService> installdService = std::make_shared<InstalldService>();
    EXPECT_NE(installdService, nullptr);
    installdService->Start();
    bool ready = installdService->IsServiceReady();
    EXPECT_EQ(true, ready);
    installdService->Stop();
    ready = installdService->IsServiceReady();
    EXPECT_EQ(false, ready);
    installdService->Start();
    ready = installdService->IsServiceReady();
    EXPECT_EQ(true, ready);
}

/**
 * @tc.number: Startup_0400
 * @tc.name: test the restart function of the installd service which is already initialized
 * @tc.desc: 1. the service is already initialized
 *           2. the recall start function will not affect the initialized installd service
*/
HWTEST_F(BmsInstallDaemonTest, Startup_0400, Function | SmallTest | Level0)
{
    std::shared_ptr<InstalldService> installdService = std::make_shared<InstalldService>();
    EXPECT_NE(installdService, nullptr);
    installdService->Start();
    bool ready = installdService->IsServiceReady();
    EXPECT_EQ(true, ready);
    installdService->Start();
    ready = installdService->IsServiceReady();
    EXPECT_EQ(true, ready);
}

/**
 * @tc.number: Communication_0100
 * @tc.name: test the communication of the installd service and installd client
 * @tc.desc: 1. the service is already initialized
 *           2. the installd client can send msg to the service and receive the right result
*/
HWTEST_F(BmsInstallDaemonTest, Communication_0100, Function | SmallTest | Level0)
{
    int result = CreateBundleDir(BUNDLE_CODE_DIR);
    EXPECT_EQ(result, 0);
}

/**
 * @tc.number: Communication_0200
 * @tc.name: test the communication of the installd service and installd client
 * @tc.desc: 1. the service is not initialized
 *           2. the installd client can't send msg to the service and receive the error result
*/
HWTEST_F(BmsInstallDaemonTest, Communication_0200, Function | SmallTest | Level0)
{
    std::shared_ptr<InstalldService> installdService = std::make_shared<InstalldService>();
    EXPECT_NE(installdService, nullptr);
    bool ready = installdService->IsServiceReady();
    EXPECT_EQ(false, ready);
    InstalldClient::GetInstance()->ResetInstalldProxy();
    int result = InstalldClient::GetInstance()->CreateBundleDir(BUNDLE_CODE_DIR);
    EXPECT_EQ(result, 0);
}

/**
 * @tc.number: Communication_0300
 * @tc.name: test the communication of the installd service and installd client
 * @tc.desc: 1. the service is already initialized
 *           2. the installd client can send msg to the service and receive the right result
*/
HWTEST_F(BmsInstallDaemonTest, Communication_0300, Function | SmallTest | Level0)
{
    int result = CreateBundleDir(BUNDLE_DATA_DIR);
    EXPECT_EQ(result, 0);
}

/**
 * @tc.number:BundleDir_0100
 * @tc.name: test the create and remove bundle dir function of installd service
 * @tc.desc: 1. the service is already initialized
 *           2. the bundle dir of the right code dir can be created and removed
*/
HWTEST_F(BmsInstallDaemonTest, BundleDir_0100, Function | SmallTest | Level0)
{
    int result = CreateBundleDir(BUNDLE_CODE_DIR);
    EXPECT_EQ(result, 0);
    bool dirExist = CheckBundleDirExist();
    EXPECT_TRUE(dirExist);
    int result1 = RemoveBundleDir(BUNDLE_CODE_DIR);
    EXPECT_EQ(result1, 0);
    dirExist = CheckBundleDirExist();
    EXPECT_FALSE(dirExist);
}

/**
 * @tc.number: BundleDir_0200
 * @tc.name: test the create and remove bundle dir function of installd service
 * @tc.desc: 1. the service is already initialized and the code dir is illegal
 *           2. the bundle dir of the illegal code dir can't be create
*/
HWTEST_F(BmsInstallDaemonTest, BundleDir_0200, Function | SmallTest | Level0)
{
    int result = CreateBundleDir("");
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
    bool dirExist = CheckBundleDirExist();
    EXPECT_FALSE(dirExist);
}

/**
 * @tc.number: BundleDir_0300
 * @tc.name: test the create and remove bundle dir function of installd service
 * @tc.desc: 1. the service is already initialized and the code dir is system dir
            2. the bundle dir of the system dir can't be created
*/
HWTEST_F(BmsInstallDaemonTest, BundleDir_0300, Function | SmallTest | Level0)
{
    int result1 = CreateBundleDir(SYSTEM_DIR);
    EXPECT_EQ(result1, ERR_APPEXECFWK_INSTALLD_CREATE_DIR_FAILED);
    bool dirExist = CheckBundleDirExist();
    EXPECT_FALSE(dirExist);
}

/**
 * @tc.number: BundleDataDir_0100
 * @tc.name: test the create and remove bundle data dir function of installd service
 * @tc.desc: 1. the service is already initialized and the code dir is system dir
 *           2. the bundle data dir of the right code dir can be created and removed
*/
HWTEST_F(BmsInstallDaemonTest, BundleDataDir_0100, Function | SmallTest | Level0)
{
    int result = CreateBundleDataDir(BUNDLE_NAME13, USERID, UID, GID, APL);
    EXPECT_EQ(result, 0);
    bool dirExist = CheckBundleDataDirExist();
    EXPECT_TRUE(dirExist);
    int result1 = RemoveBundleDataDir(BUNDLE_DATA_DIR);
    EXPECT_EQ(result1, 0);
    dirExist = CheckBundleDataDirExist();
    EXPECT_FALSE(dirExist);
}

/**
 * @tc.number: BundleDataDir_0200
 * @tc.name: test the create and clean bundle data dir function of installd service
 * @tc.desc: 1. the service is already initialized
 *           2. the bundle data dir of the right code dir can be created and clean
*/
HWTEST_F(BmsInstallDaemonTest, BundleDataDir_0200, Function | SmallTest | Level0)
{
    int result = CreateBundleDataDir(BUNDLE_NAME13, USERID, UID, GID, APL);
    EXPECT_EQ(result, 0);
    bool dirExist = CheckBundleDataDirExist();
    EXPECT_TRUE(dirExist);
    int result1 = CleanBundleDataDir(BUNDLE_DATA_DIR);
    EXPECT_EQ(result1, 0);
    dirExist = CheckBundleDataDirExist();
    EXPECT_TRUE(dirExist);
}

/**
 * @tc.number: BundleDataDir_0300
 * @tc.name: test the create and remove bundle data dir function of installd service
 * @tc.desc: 1. the service is already initialized and the code dir is illegal
 *           2. the bundle data dir of the illegal code dir can't be created
*/
HWTEST_F(BmsInstallDaemonTest, BundleDataDir_0300, Function | SmallTest | Level0)
{
    int result = CreateBundleDataDir("", USERID, UID, GID, APL);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
    bool dirExist = CheckBundleDataDirExist();
    EXPECT_FALSE(dirExist);
}

/**
 * @tc.number: BundleDataDir_0400
 * @tc.name: test the create and remove bundle data dir function of installd service
 * @tc.desc: 1. the service is already initialized and the uid is illegal
 *           2. the bundle data dir of the illegal uid can't be created
*/
HWTEST_F(BmsInstallDaemonTest, BundleDataDir_0400, Function | SmallTest | Level0)
{
    int result = CreateBundleDataDir(BUNDLE_NAME13, USERID, -1, GID, APL);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
    bool dirExist = CheckBundleDataDirExist();
    EXPECT_FALSE(dirExist);
}

/**
 * @tc.number: BundleDataDir_0500
 * @tc.name: test the create and remove bundle data dir function of installd service
 * @tc.desc: 1. the service is already initialized and the gid is illegal
 *           2. the bundle data dir of the illegal gid can't be created
*/
HWTEST_F(BmsInstallDaemonTest, BundleDataDir_0500, Function | SmallTest | Level0)
{
    int result = CreateBundleDataDir(BUNDLE_NAME13, USERID, UID, -1, APL);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
    bool dirExist = CheckBundleDataDirExist();
    EXPECT_FALSE(dirExist);
}

/**
 * @tc.number: BundleDataDir_0500
 * @tc.name: test the create and remove bundle data dir function of installd service
 * @tc.desc: 1. the service is already initialized and the code dir is system dir
 *           2. the bundle data dir of the system dir can't be created
*/
HWTEST_F(BmsInstallDaemonTest, BundleDataDir_0600, Function | SmallTest | Level0)
{
    int result = CreateBundleDataDir("", USERID, UID, GID, APL);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
    bool dirExist = CheckBundleDataDirExist();
    EXPECT_FALSE(dirExist);
}

/**
 * @tc.number: BundleDataDir_0700
 * @tc.name: test the create and remove bundle data dir function of installd service
 * @tc.desc: 1. the service is already initialized and the code dir is illegal
 *           2. the bundle data dir of the illegal code dir can't be created
*/
HWTEST_F(BmsInstallDaemonTest, BundleDataDir_0700, Function | SmallTest | Level0)
{
    int result = CreateBundleDataDir(BUNDLE_NAME13, USERID, UID, GID, APL);
    EXPECT_EQ(result, 0);
    std::shared_ptr<InstalldService> service = std::make_shared<InstalldService>();
    if (!service->IsServiceReady()) {
        service->Start();
    }
    ErrCode ret = InstalldClient::GetInstance()->RemoveBundleDataDir("", USERID);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
    ret = InstalldClient::GetInstance()->RemoveBundleDataDir(BUNDLE_NAME, -1);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
}

/**
 * @tc.number: BundleDataDir_0800
 * @tc.name: Test RemoveModuleDataDir
 * @tc.desc: 1.Test the RemoveModuleDataDir of InstalldClient
*/
HWTEST_F(BmsInstallDaemonTest, BundleDataDir_0800, Function | SmallTest | Level0)
{
    std::shared_ptr<InstalldService> service = std::make_shared<InstalldService>();
    if (!service->IsServiceReady()) {
        service->Start();
    }
    ErrCode ret = InstalldClient::GetInstance()->RemoveModuleDataDir("", USERID);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
    ret = InstalldClient::GetInstance()->RemoveModuleDataDir("entry", -1);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
}

/**
 * @tc.number: BundleDataDir_0900
 * @tc.name: Test CleanBundleDataDir, Param is empty
 * @tc.desc: 1.Test the CleanBundleDataDir of InstalldClient
*/
HWTEST_F(BmsInstallDaemonTest, BundleDataDir_0900, Function | SmallTest | Level0)
{
    std::shared_ptr<InstalldService> service = std::make_shared<InstalldService>();
    if (!service->IsServiceReady()) {
        service->Start();
    }
    ErrCode ret = InstalldClient::GetInstance()->CleanBundleDataDir("");
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
}

/**
 * @tc.number: BundleDataDir_1000
 * @tc.name: test function of InstallHostImpl
 * @tc.desc: 1. calling CreateBundleDataDir of hostImpl
*/
HWTEST_F(BmsInstallDaemonTest, BundleDataDir_1000, Function | SmallTest | Level0)
{
    InstalldHostImpl hostImpl;
    CreateDirParam createDirParam;
    createDirParam.createDirFlag = CreateDirFlag::CREATE_DIR_UNLOCKED;
    createDirParam.bundleName = BUNDLE_NAME13;
    createDirParam.userId = USERID;
    createDirParam.uid = UID;
    createDirParam.gid = GID;
    createDirParam.apl = APL;
    createDirParam.isPreInstallApp = false;
    auto ret = hostImpl.CreateBundleDataDir(createDirParam);
    EXPECT_EQ(ret, ERR_OK);
}
/**
 * @tc.number: InstalldClient_0100
 * @tc.name: Test SetDirApl, Param is empty
 * @tc.desc: 1.Test the SetDirApl of InstalldClient
*/
HWTEST_F(BmsInstallDaemonTest, InstalldClient_0100, Function | SmallTest | Level0)
{
    std::shared_ptr<InstalldService> service = std::make_shared<InstalldService>();
    if (!service->IsServiceReady()) {
        service->Start();
    }
    std::string TEST_STRING = "test.string";
    ErrCode ret = InstalldClient::GetInstance()->SetDirApl("", BUNDLE_NAME, TEST_STRING, false, false);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
    ret = InstalldClient::GetInstance()->SetDirApl(BUNDLE_DATA_DIR, "", TEST_STRING, false, false);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
    ret = InstalldClient::GetInstance()->SetDirApl(BUNDLE_DATA_DIR, BUNDLE_NAME, "", true, true);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
}

/**
 * @tc.number: InstalldClient_0200
 * @tc.name: Test GetBundleCachePath, A param is empty
 * @tc.desc: 1.Test the GetBundleCachePath of InstalldClient
*/
HWTEST_F(BmsInstallDaemonTest, InstalldClient_0200, Function | SmallTest | Level0)
{
    std::shared_ptr<InstalldService> service = std::make_shared<InstalldService>();
    if (!service->IsServiceReady()) {
        service->Start();
    }
    std::vector<std::string> cachePath;
    ErrCode ret = InstalldClient::GetInstance()->GetBundleCachePath("", cachePath);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
}

/**
 * @tc.number: InstalldClient_0300
 * @tc.name: Test ScanDir, dir param is empty
 * @tc.desc: 1.Test the ScanDir of InstalldClient
*/
HWTEST_F(BmsInstallDaemonTest, InstalldClient_0300, Function | SmallTest | Level0)
{
    std::shared_ptr<InstalldService> service = std::make_shared<InstalldService>();
    if (!service->IsServiceReady()) {
        service->Start();
    }
    std::vector<std::string> paths;
    ErrCode ret = InstalldClient::GetInstance()->ScanDir(
        "", ScanMode::SUB_FILE_ALL, ResultMode::ABSOLUTE_PATH, paths);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
}

/**
 * @tc.number: InstalldClient_0400
 * @tc.name: Test MoveFile, a param is empty
 * @tc.desc: 1.Test the MoveFile of InstalldClient
*/
HWTEST_F(BmsInstallDaemonTest, InstalldClient_0400, Function | SmallTest | Level0)
{
    std::shared_ptr<InstalldService> service = std::make_shared<InstalldService>();
    if (!service->IsServiceReady()) {
        service->Start();
    }
    ErrCode ret = InstalldClient::GetInstance()->MoveFile("", BUNDLE_DATA_DIR);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
    ret = InstalldClient::GetInstance()->MoveFile(BUNDLE_DATA_DIR, "");
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
    ret = InstalldClient::GetInstance()->MoveFile(
        BUNDLE_DATA_DIR, BUNDLE_DATA_DIR);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_MOVE_FILE_FAILED);
}

/**
 * @tc.number: InstalldClient_0500
 * @tc.name: Test MoveFile, a param is empty
 * @tc.desc: 1.Test the MoveFile of InstalldClient
*/
HWTEST_F(BmsInstallDaemonTest, InstalldClient_0500, Function | SmallTest | Level0)
{
    std::shared_ptr<InstalldService> service = std::make_shared<InstalldService>();
    if (!service->IsServiceReady()) {
        service->Start();
    }
    ErrCode ret = InstalldClient::GetInstance()->CopyFile("", BUNDLE_DATA_DIR);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
    ret = InstalldClient::GetInstance()->CopyFile(BUNDLE_DATA_DIR, "");
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
}

/**
 * @tc.number: InstalldClient_0600
 * @tc.name: Test Mkdir, a param is empty
 * @tc.desc: 1.Test the Mkdir of InstalldClient
*/
HWTEST_F(BmsInstallDaemonTest, InstalldClient_0600, Function | SmallTest | Level0)
{
    std::shared_ptr<InstalldService> service = std::make_shared<InstalldService>();
    if (!service->IsServiceReady()) {
        service->Start();
    }
    ErrCode ret = InstalldClient::GetInstance()->Mkdir("", 0, 0, 0);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
    ret = InstalldClient::GetInstance()->Mkdir(BUNDLE_DATA_DIR, 0, 0, 0);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: InstalldClient_0700
 * @tc.name: Test GetFileStat, a param is empty
 * @tc.desc: 1.Test the GetFileStat of InstalldClient
*/
HWTEST_F(BmsInstallDaemonTest, InstalldClient_0700, Function | SmallTest | Level0)
{
    std::shared_ptr<InstalldService> service = std::make_shared<InstalldService>();
    if (!service->IsServiceReady()) {
        service->Start();
    }
    FileStat fileStat;
    ErrCode ret = InstalldClient::GetInstance()->GetFileStat("", fileStat);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
    ret = InstalldClient::GetInstance()->GetFileStat("data/test/wrongpath", fileStat);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
}

/**
 * @tc.number: InstalldClient_0800
 * @tc.name: Test ExtractDiffFiles, a param is empty
 * @tc.desc: 1.Test the ExtractDiffFiles of InstalldClient
*/
HWTEST_F(BmsInstallDaemonTest, InstalldClient_0800, Function | SmallTest | Level0)
{
    std::shared_ptr<InstalldService> service = std::make_shared<InstalldService>();
    if (!service->IsServiceReady()) {
        service->Start();
    }
    std::string TEST_STRING = "test.string";
    ErrCode ret = InstalldClient::GetInstance()->ExtractDiffFiles("", TEST_STRING, TEST_STRING);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
    ret = InstalldClient::GetInstance()->ExtractDiffFiles(TEST_STRING, "", TEST_STRING);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
    ret = InstalldClient::GetInstance()->ExtractDiffFiles(TEST_STRING, TEST_STRING, "");
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
    ret = InstalldClient::GetInstance()->ExtractDiffFiles(
        BUNDLE_DATA_DIR, TEST_STRING, TEST_STRING);
    EXPECT_EQ(ret, ERR_BUNDLEMANAGER_QUICK_FIX_EXTRACT_DIFF_FILES_FAILED);
}

/**
 * @tc.number: InstalldClient_0900
 * @tc.name: Test ApplyDiffPatch, a param is empty
 * @tc.desc: 1.Test the ApplyDiffPatch of InstalldClient
*/
HWTEST_F(BmsInstallDaemonTest, InstalldClient_0900, Function | SmallTest | Level0)
{
    std::shared_ptr<InstalldService> service = std::make_shared<InstalldService>();
    if (!service->IsServiceReady()) {
        service->Start();
    }
    std::string TEST_STRING = "test.string";
    ErrCode ret = InstalldClient::GetInstance()->ApplyDiffPatch("", TEST_STRING, TEST_STRING, 0);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
    ret = InstalldClient::GetInstance()->ApplyDiffPatch(TEST_STRING, "", TEST_STRING, 0);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
    ret = InstalldClient::GetInstance()->ApplyDiffPatch(TEST_STRING, TEST_STRING, "", 0);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
    ret = InstalldClient::GetInstance()->ApplyDiffPatch(
        TEST_STRING, TEST_STRING, TEST_STRING, 0);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: ExtractBundleFile_0100
 * @tc.name: test the ExtractBundleFile function of installd service with flag system bundle
 * @tc.desc: 1. the bundle file is available and the target dir exists
 *           2. the origin file exists and the extracted file exists
*/
HWTEST_F(BmsInstallDaemonTest, ExtractBundleFile_0100, Function | SmallTest | Level0)
{
    CreateBundleDir(BUNDLE_CODE_DIR);
    bool dirExist = CheckBundleDirExist();
    EXPECT_TRUE(dirExist);
    auto bundleFile = BUNDLE_FILE;
    int result = ExtractModuleFiles(bundleFile, TEMP_DIR, "", "");
    EXPECT_EQ(result, 0);
    int result1 = RenameModuleDir(TEMP_DIR, MODULE_DIR);
    EXPECT_EQ(result1, 0);
}

/**
 * @tc.number: ExtractBundleFile_0200
 * @tc.name: test the ExtractBundleFile function of installd service
 * @tc.desc: 1. the bundle file is illegal
 *           2. the bundle file can't be extracted and the extracted file does not exists
*/
HWTEST_F(BmsInstallDaemonTest, ExtractBundleFile_0200, Function | SmallTest | Level0)
{
    CreateBundleDir(BUNDLE_CODE_DIR);
    bool dirExist = CheckBundleDirExist();
    EXPECT_TRUE(dirExist);
    int result = ExtractModuleFiles("", TEMP_DIR, "", "");
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
}

/**
 * @tc.number: ExtractBundleFile_0300
 * @tc.name: test the ExtractBundleFile function of installd service
 * @tc.desc: 1. the temp dir does not exist
 *           2. the bundle file can't be extracted and the extracted file does not exists
*/
HWTEST_F(BmsInstallDaemonTest, ExtractBundleFile_0300, Function | SmallTest | Level0)
{
    CreateBundleDir(BUNDLE_CODE_DIR);
    bool dirExist = CheckBundleDirExist();
    EXPECT_TRUE(dirExist);
    auto bundleFile = BUNDLE_FILE;
    int result = ExtractModuleFiles(bundleFile, "", "", "");
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
}

/**
 * @tc.number: ExtractBundleFile_0400
 * @tc.name: test the ExtractBundleFile function of installd service
 * @tc.desc: 1. the old path does not exist
 *           2. the bundle file can't be extracted and the extracted file does not exists
*/
HWTEST_F(BmsInstallDaemonTest, ExtractBundleFile_0400, Function | SmallTest | Level0)
{
    CreateBundleDir(BUNDLE_CODE_DIR);
    bool dirExist = CheckBundleDirExist();
    EXPECT_TRUE(dirExist);
    auto bundleFile = BUNDLE_FILE;
    int result = ExtractModuleFiles(bundleFile, TEMP_DIR, "", "");
    EXPECT_EQ(result, 0);
    int result1 = RenameModuleDir("", MODULE_DIR);
    EXPECT_EQ(result1, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
}

/**
 * @tc.number: ExtractBundleFile_0500
 * @tc.name: test the ExtractBundleFile function of installd service
 * @tc.desc: 1. the new path does not exist
 *           2. the bundle file can't be extracted and the extracted file does not exists
*/
HWTEST_F(BmsInstallDaemonTest, ExtractBundleFile_0500, Function | SmallTest | Level0)
{
    CreateBundleDir(BUNDLE_CODE_DIR);
    bool dirExist = CheckBundleDirExist();
    EXPECT_TRUE(dirExist);
    auto bundleFile = BUNDLE_FILE;
    int result = ExtractModuleFiles(bundleFile, TEMP_DIR, "", "");
    EXPECT_EQ(result, 0);
    int result1 = RenameModuleDir(TEMP_DIR, "");
    EXPECT_EQ(result1, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
}

/**
 * @tc.number: GetBundleStats_0100
 * @tc.name: test the GetBundleStats function of installd service
 * @tc.desc: 1. the bundle does not exist
*/
HWTEST_F(BmsInstallDaemonTest, GetBundleStats_0100, Function | SmallTest | Level0)
{
    std::vector<int64_t> stats;
    bool result = GetBundleStats("", 0, stats, 0);
    EXPECT_EQ(result, false);
}

/**
 * @tc.number: GetBundleStats_0200
 * @tc.name: test the GetBundleStats function of installd service
 * @tc.desc: 1. the bundle exists
*/
HWTEST_F(BmsInstallDaemonTest, GetBundleStats_0200, Function | SmallTest | Level0)
{
    std::vector<int64_t> stats;
    bool result = GetBundleStats(BUNDLE_NAME13, 0, stats, 0);
    EXPECT_EQ(result, true);
    EXPECT_EQ(stats[0], 0);
    EXPECT_NE(stats[1], 0);
    EXPECT_EQ(stats[2], 0);
    EXPECT_EQ(stats[3], 0);
    EXPECT_EQ(stats[4], 0);
}

/**
 * @tc.number: GetBundleStats_0300
 * @tc.name: test the GetBundleStats function of installd service
 * @tc.desc: 1. the bundle exists, wrong userName
*/
HWTEST_F(BmsInstallDaemonTest, GetBundleStats_0300, Function | SmallTest | Level0)
{
    OHOS::ForceCreateDirectory(BUNDLE_CODE_DIR_CODE);
    std::vector<int64_t> stats;
    bool result = GetBundleStats(BUNDLE_NAME13, 0, stats, 0);
    EXPECT_EQ(result, true);
    EXPECT_NE(stats[1], 0);
    OHOS::ForceRemoveDirectory(BUNDLE_CODE_DIR_CODE);
}

/**
 * @tc.number: GetBundleStats_0400
 * @tc.name: test the GetBundleStats function of installd service
 * @tc.desc: 1. the bundle exists,
*/
HWTEST_F(BmsInstallDaemonTest, GetBundleStats_0400, Function | SmallTest | Level0)
{
    OHOS::ForceCreateDirectory(BUNDLE_DATA_DIR_CACHE);
    OHOS::ForceCreateDirectory(BUNDLE_DATA_DIR_TEMP);
    OHOS::ForceCreateDirectory(BUNDLE_CODE_DIR_CODE);
    OHOS::ForceCreateDirectory(BUNDLE_DATA_DIR_DATA_BASE);
    OHOS::ForceCreateDirectory(BUNDLE_DATA_DIR_DATA_BASE_TEMP);
    std::vector<int64_t> stats;
    bool result = GetBundleStats(BUNDLE_NAME13, USERID, stats, 0);
    EXPECT_EQ(result, true);
    EXPECT_EQ(stats[0], 0);
    EXPECT_NE(stats[1], 0);
    EXPECT_EQ(stats[2], 0); // distributed file does not exist
    EXPECT_EQ(stats[3], 0);
    EXPECT_EQ(stats[4], 0);
    OHOS::ForceRemoveDirectory(BUNDLE_DATA_DIR_CACHE);
    OHOS::ForceRemoveDirectory(BUNDLE_DATA_DIR_TEMP);
    OHOS::ForceRemoveDirectory(BUNDLE_CODE_DIR_CODE);
    OHOS::ForceRemoveDirectory(BUNDLE_DATA_DIR_DATA_BASE);
    OHOS::ForceRemoveDirectory(BUNDLE_DATA_DIR_DATA_BASE_TEMP);
}

/**
 * @tc.number: ExtractFiles_0100
 * @tc.name: test the ExtractFiles
 * @tc.desc: 1. extract files success
*/
HWTEST_F(BmsInstallDaemonTest, ExtractFiles_0100, Function | SmallTest | Level0)
{
    ExtractParam extractParam;
    ErrCode ret = ExtractFiles(extractParam);
    EXPECT_NE(ret, ERR_OK);

    extractParam.srcPath = HAP_FILE_PATH;
    ret = ExtractFiles(extractParam);
    EXPECT_NE(ret, ERR_OK);

    extractParam.targetPath = TEST_PATH;
    extractParam.cpuAbi = TEST_CPU_ABI;
    extractParam.extractFileType = ExtractFileType::AN;
    ret = ExtractFiles(extractParam);
    EXPECT_NE(ret, ERR_OK);
}


/**
 * @tc.number: Marshalling_0100
 * @tc.name: test Marshalling
 * @tc.desc: 1.read from parcel success
 */
HWTEST_F(BmsInstallDaemonTest, Marshalling_0100, Function | SmallTest | Level0)
{
    ExtractParam extractParam;
    Parcel parcel;
    extractParam.srcPath = HAP_FILE_PATH;
    extractParam.targetPath = TEST_PATH;
    extractParam.cpuAbi = TEST_CPU_ABI;
    extractParam.extractFileType = ExtractFileType::AN;
    bool res = extractParam.Marshalling(parcel);
    EXPECT_TRUE(res);
    std::string value = extractParam.ToString();
    EXPECT_EQ("[ srcPath :" +  HAP_FILE_PATH
            + ", targetPath = " + TEST_PATH
            + ", cpuAbi = " + TEST_CPU_ABI
            + ", extractFileType = An]", value);
    extractParam.Unmarshalling(parcel);
}

/**
 * @tc.number: ExtractFiles_0200
 * @tc.name: test the ExtractFiles
 * @tc.desc: 1. extract files success
*/
HWTEST_F(BmsInstallDaemonTest, ExtractFiles_0200, Function | SmallTest | Level0)
{
    ExtractParam extractParam;
    extractParam.srcPath = BUNDLE_FILE;
    extractParam.targetPath = TEST_PATH;
    extractParam.cpuAbi = "";
    extractParam.extractFileType = ExtractFileType::AP;
    auto ret = ExtractFiles(extractParam);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: GetNativeLibraryFileNames_0001
 * @tc.name: test the GetNativeLibraryFileNames
 * @tc.desc: 1. GetNativeLibraryFileNames success
*/
HWTEST_F(BmsInstallDaemonTest, GetNativeLibraryFileNames_0001, Function | SmallTest | Level0)
{
    std::string apuAbi = "libs/arm";
    std::vector<std::string> fileNames;
    auto ret = GetNativeLibraryFileNames(BUNDLE_FILE, apuAbi, fileNames);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(fileNames.empty());
}

/**
 * @tc.number: OnStart_0001
 * @tc.name: test the OnStart
 * @tc.desc: 1. OnStart success
*/
HWTEST_F(BmsInstallDaemonTest, OnStart_0001, Function | SmallTest | Level0)
{
    std::shared_ptr<InstalldService> service = std::make_shared<InstalldService>();
    service->OnStart();
    bool isRead = service->IsServiceReady();
    EXPECT_TRUE(isRead);
}

/**
 * @tc.number: OnStop_0001
 * @tc.name: test the OnStop
 * @tc.desc: 1. OnStop success
*/
HWTEST_F(BmsInstallDaemonTest, OnStop_0001, Function | SmallTest | Level0)
{
    std::shared_ptr<InstalldService> service = std::make_shared<InstalldService>();
    service->OnStop();
    bool isRead = service->IsServiceReady();
    EXPECT_FALSE(isRead);
}

/**
 * @tc.number: ProcessBundleInstallNative_0100
 * @tc.name: test function of InstallHostImpl
 * @tc.desc: 1. test ProcessBundleInstallNative
*/
HWTEST_F(BmsInstallDaemonTest, ProcessBundleInstallNative_0100, Function | SmallTest | Level0)
{
    InstalldHostImpl hostImpl;
    std::string userId = "100";
    std::string hnpRootPath = "/hnp/root";
    std::string hapPath = "/hnp/root/path";
    std::string cpuAbi = "cpuAbi";
    std::string packageName = "com.acts.example";
    ErrCode ret = hostImpl.ProcessBundleInstallNative(userId, hnpRootPath, hapPath, cpuAbi, packageName);
    EXPECT_EQ(ret, ERR_APPEXECFWK_NATIVE_INSTALL_FAILED);
}

/**
 * @tc.number: ProcessBundleUnInstallNative_0100
 * @tc.name: test function of InstallHostImpl
 * @tc.desc: 1. test ProcessBundleUnInstallNative
*/
HWTEST_F(BmsInstallDaemonTest, ProcessBundleUnInstallNative_0100, Function | SmallTest | Level0)
{
    InstalldHostImpl hostImpl;
    std::string userId = "100";
    std::string packageName = "com.acts.example";
    ErrCode ret = hostImpl.ProcessBundleUnInstallNative(userId, packageName);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: PendSignAOT_0100
 * @tc.name: test function of InstallHostImpl
 * @tc.desc: 1. test PendSignAOT
*/
HWTEST_F(BmsInstallDaemonTest, PendSignAOT_0100, Function | SmallTest | Level0)
{
    InstalldHostImpl hostImpl;
    std::string anFileName = "fileName";
    std::vector<uint8_t> signData;
    ErrCode ret = hostImpl.PendSignAOT(anFileName, signData);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: CreateBundleDataDirWithVector__0100
 * @tc.name: test function of InstallHostImpl
 * @tc.desc: 1. test CreateBundleDataDirWithVector
*/
HWTEST_F(BmsInstallDaemonTest, CreateBundleDataDirWithVector__0100, Function | SmallTest | Level0)
{
    InstalldHostImpl hostImpl;
    std::vector<CreateDirParam> createDirParams;
    ErrCode ret = hostImpl.CreateBundleDataDirWithVector(createDirParams);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: GetDiskUsage_0100
 * @tc.name: test function of InstallHostImpl
 * @tc.desc: 1. test GetDiskUsage
*/
HWTEST_F(BmsInstallDaemonTest, GetDiskUsage_0100, Function | SmallTest | Level0)
{
    InstalldHostImpl hostImpl;
    std::string dir = "dir/path/";
    bool isRealPath = true;
    int64_t ret = hostImpl.GetDiskUsage(dir, isRealPath);
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.number: GetAllBundleStats_0100
 * @tc.name: test function of InstallHostImpl
 * @tc.desc: 1. test GetAllBundleStats
*/
HWTEST_F(BmsInstallDaemonTest, GetAllBundleStats_0100, Function | SmallTest | Level0)
{
    InstalldHostImpl hostImpl;
    std::vector<std::string> bundleNames;
    int32_t userId = 100;
    std::vector<int64_t> bundleStats;
    std::vector<int32_t> uids;
    ErrCode ret = hostImpl.GetAllBundleStats(bundleNames, userId, bundleStats, uids);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
}

/**
 * @tc.number: GetAllBundleStats_0200
 * @tc.name: test function of InstallHostImpl
 * @tc.desc: 1. test GetAllBundleStats
*/
HWTEST_F(BmsInstallDaemonTest, GetAllBundleStats_0200, Function | SmallTest | Level0)
{
    InstalldHostImpl hostImpl;
    std::vector<std::string> bundleNames;
    bundleNames.push_back("com.acts.example1");
    bundleNames.push_back("com.acts.example2");
    int32_t userId = 100;
    std::vector<int64_t> bundleStats;
    std::vector<int32_t> uids;
    uids.push_back(101);
    uids.push_back(102);
    ErrCode ret = hostImpl.GetAllBundleStats(bundleNames, userId, bundleStats, uids);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: ExtractEncryptedSoFiles_0100
 * @tc.name: test function of InstallHostImpl
 * @tc.desc: 1. test ExtractEncryptedSoFiles
*/
HWTEST_F(BmsInstallDaemonTest, ExtractEncryptedSoFiles_0100, Function | SmallTest | Level0)
{
    InstalldHostImpl hostImpl;
    std::string hapPath;
    std::string realSoFilesPath;
    std::string cpuAbi;
    std::string tmpSoPath;
    int32_t uid = 100;
    ErrCode ret = hostImpl.ExtractEncryptedSoFiles(hapPath, realSoFilesPath, cpuAbi, tmpSoPath, uid);
    EXPECT_EQ(ret, ERR_BUNDLEMANAGER_QUICK_FIX_NOT_SUPPORT_CODE_ENCRYPTION);
}

/**
 * @tc.number: DeliverySignProfile_0100
 * @tc.name: test function of InstallHostImpl
 * @tc.desc: 1. test DeliverySignProfile
*/
HWTEST_F(BmsInstallDaemonTest, DeliverySignProfile_0100, Function | SmallTest | Level0)
{
    InstalldHostImpl hostImpl;
    std::string bundleName;
    int32_t profileBlockLength = 0;
    unsigned char *profileBlock = new unsigned char[0];
    ErrCode ret = hostImpl.DeliverySignProfile(bundleName, profileBlockLength, profileBlock);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
}

/**
 * @tc.number: RemoveExtensionDir_0100
 * @tc.name: test function of InstallHostImpl
 * @tc.desc: 1. test RemoveExtensionDir
*/
HWTEST_F(BmsInstallDaemonTest, RemoveExtensionDir_0100, Function | SmallTest | Level0)
{
    InstalldHostImpl hostImpl;
    int32_t userId = -1;
    std::vector<std::string> extensionBundleDirs;
    ErrCode ret = hostImpl.RemoveExtensionDir(userId, extensionBundleDirs);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
}

/**
 * @tc.number: RemoveExtensionDir_0200
 * @tc.name: test function of InstallHostImpl
 * @tc.desc: 1. test RemoveExtensionDir
*/
HWTEST_F(BmsInstallDaemonTest, RemoveExtensionDir_0200, Function | SmallTest | Level0)
{
    InstalldHostImpl hostImpl;
    int32_t userId = 100;
    std::vector<std::string> extensionBundleDirs;
    extensionBundleDirs.push_back("");
    ErrCode ret = hostImpl.RemoveExtensionDir(userId, extensionBundleDirs);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
}

/**
 * @tc.number: RemoveExtensionDir_0300
 * @tc.name: test function of InstallHostImpl
 * @tc.desc: 1. test RemoveExtensionDir
*/
HWTEST_F(BmsInstallDaemonTest, RemoveExtensionDir_0300, Function | SmallTest | Level0)
{
    InstalldHostImpl hostImpl;
    int32_t userId = 100;
    std::vector<std::string> extensionBundleDirs;
    extensionBundleDirs.push_back("com.ohos.settings");
    ErrCode ret = hostImpl.RemoveExtensionDir(userId, extensionBundleDirs);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: IsExistExtensionDir_0100
 * @tc.name: test function of InstallHostImpl
 * @tc.desc: 1. test IsExistExtensionDir
*/
HWTEST_F(BmsInstallDaemonTest, IsExistExtensionDir_0100, Function | SmallTest | Level0)
{
    InstalldHostImpl hostImpl;
    int32_t userId = -1;
    std::string extensionBundleDir = "";
    bool isExist = false;
    ErrCode ret = hostImpl.IsExistExtensionDir(userId, extensionBundleDir, isExist);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_FALSE(isExist);
}

/**
 * @tc.number: IsExistExtensionDir_0200
 * @tc.name: test function of InstallHostImpl
 * @tc.desc: 1. test IsExistExtensionDir
*/
HWTEST_F(BmsInstallDaemonTest, IsExistExtensionDir_0200, Function | SmallTest | Level0)
{
    InstalldHostImpl hostImpl;
    int32_t userId = 100;
    std::string extensionBundleDir = "com.ohos.settings";
    bool isExist = false;
    ErrCode ret = hostImpl.IsExistExtensionDir(userId, extensionBundleDir, isExist);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_FALSE(isExist);
}

/**
 * @tc.number: CreateExtensionDataDir_0100
 * @tc.name: test function of InstallHostImpl
 * @tc.desc: 1. test CreateExtensionDataDir
*/
HWTEST_F(BmsInstallDaemonTest, CreateExtensionDataDir_0100, Function | SmallTest | Level0)
{
    InstalldHostImpl hostImpl;
    CreateDirParam createDirParam;
    createDirParam.bundleName = "com.acts.example";
    createDirParam.userId = 100;
    createDirParam.uid = 100;
    createDirParam.gid = 100;
    createDirParam.apl = "apl";
    createDirParam.extensionDirs.push_back("com.acts.example");
    ErrCode ret = hostImpl.CreateExtensionDataDir(createDirParam);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_CREATE_DIR_FAILED);
}
} // OHOS
