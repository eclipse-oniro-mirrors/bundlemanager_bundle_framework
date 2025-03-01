/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#define private public
#define protected public

#include <gtest/gtest.h>

#include <chrono>
#include <sys/stat.h>
#include <thread>
#include <unistd.h>

#include "appexecfwk_errors.h"
#include "bundle_info.h"
#include "bundle_installer_host.h"
#include "bundle_mgr_service.h"
#include "directory_ex.h"
#include "installd/installd_service.h"
#include "installd_client.h"
#include "mock_status_receiver.h"

using namespace testing::ext;
using namespace std::chrono_literals;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace {
const std::string PACKAGE_NAME = "com.test.debug.update";
const std::string BUNDLE_NAME = "com.test.debug.update";
const std::string BUNDLE_FILE_DIR = "/data/test/resource/bms/install_bundle/";
const std::string ENTRY_V1_DEBUG_BUNDLE = "entry_v1debug.hap";
const std::string ENTRY_V1_RELEASE_BUNDLE = "entry_v1release.hap";
const std::string ENTRY_V2_DEBUG_BUNDLE = "entry_v2debug.hap";
const std::string ENTRY_V2_RELEASE_BUNDLE = "entry_v2release.hap";
const std::string FEATURE_V1_DEBUG_BUNDLE = "feature_v1debug.hap";
const std::string FEATURE_V1_RELEASE_BUNDLE = "feature_v1release.hap";
const std::string FEATURE_V2_DEBUG_BUNDLE = "feature_v2debug.hap";
const std::string FEATURE_V2_RELEASE_BUNDLE = "feature_v2release.hap";
const std::string LIBRARY_V1_DEBUG_BUNDLE = "library_v1debug.hap";
const std::string LIBRARY_V1_RELEASE_BUNDLE = "library_v1release.hap";
const std::string LIBRARY_V2_DEBUG_BUNDLE = "library_v2debug.hap";
const std::string LIBRARY_V2_RELEASE_BUNDLE = "library_v2release.hap";
const std::string BUNDLE_DATA_DIR = "/data/app/el2/100/base/com.test.debug.update";
const std::string BUNDLE_CODE_DIR = "/data/app/el1/bundle/public/com.test.debug.update";
const std::string SEPARATOR = "/";
const std::chrono::seconds SLEEP_TIME {2};
const int32_t USERID = 100;
const uint32_t VERSION_1 = 1000001;
const uint32_t VERSION_2 = 1000002;
const int32_t MAX_TRY_TIMES = 1000;
const int32_t WAIT_TIME = 5; // init mocked bms
}  // namespace

class BmsBundleUpdateDebugTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

    const std::shared_ptr<BundleDataMgr> GetBundleDataMgr() const;
    ErrCode InstallBundle(const std::string &bundlePath) const;
    ErrCode UninstallBundle(const std::string &bundleName) const;
    ErrCode UpdateBundle(const std::string &bundlePath) const;
    ErrCode UpdateBundle(const std::string &bundlePath, const bool needCheckInfo) const;

    void StopInstalldService() const;
    void StartInstalldService() const;
    void StopBundleService() const;

    bool CheckApplicationInfo() const;
    bool CheckApplicationDebugValue(bool value) const;

private:
    static std::shared_ptr<InstalldService> installdService_;
    static std::shared_ptr<BundleMgrService> bundleMgrService_;
};

std::shared_ptr<BundleMgrService> BmsBundleUpdateDebugTest::bundleMgrService_ =
    DelayedSingleton<BundleMgrService>::GetInstance();

std::shared_ptr<InstalldService> BmsBundleUpdateDebugTest::installdService_ =
    std::make_shared<InstalldService>();

void BmsBundleUpdateDebugTest::SetUpTestCase()
{
}

void BmsBundleUpdateDebugTest::TearDownTestCase()
{
    bundleMgrService_->OnStop();
    bundleMgrService_->GetDataMgr()->AddUserId(USERID);
}

void BmsBundleUpdateDebugTest::SetUp()
{
    installdService_->Start();
    if (!DelayedSingleton<BundleMgrService>::GetInstance()->IsServiceReady()) {
        DelayedSingleton<BundleMgrService>::GetInstance()->OnStart();
        std::this_thread::sleep_for(std::chrono::seconds(WAIT_TIME));
    }
}

void BmsBundleUpdateDebugTest::TearDown()
{
    // clear files.
    OHOS::ForceRemoveDirectory(BUNDLE_DATA_DIR);
    OHOS::ForceRemoveDirectory(BUNDLE_CODE_DIR);
}

const std::shared_ptr<BundleDataMgr> BmsBundleUpdateDebugTest::GetBundleDataMgr() const
{
    return bundleMgrService_->GetDataMgr();
}

ErrCode BmsBundleUpdateDebugTest::InstallBundle(const std::string &bundlePath) const
{
    auto installer = DelayedSingleton<BundleMgrService>::GetInstance()->GetBundleInstaller();
    if (!installer) {
        EXPECT_FALSE(true) << "the installer is nullptr";
        return ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR;
    }

    sptr<MockStatusReceiver> receiver = new (std::nothrow) MockStatusReceiver();
    if (!receiver) {
        EXPECT_FALSE(true) << "the receiver is nullptr";
        return ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR;
    }
    InstallParam installParam;
    installParam.userId = USERID;
    installParam.installFlag = InstallFlag::NORMAL;
    installParam.withCopyHaps = true;
    bool result = installer->Install(bundlePath, installParam, receiver);
    EXPECT_TRUE(result);
    return receiver->GetResultCode();
}

ErrCode BmsBundleUpdateDebugTest::UninstallBundle(const std::string &bundleName) const
{
    auto installer = DelayedSingleton<BundleMgrService>::GetInstance()->GetBundleInstaller();
    if (!installer) {
        EXPECT_FALSE(true) << "the installer is nullptr";
        return ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR;
    }

    sptr<MockStatusReceiver> receiver = new (std::nothrow) MockStatusReceiver();
    if (!receiver) {
        EXPECT_FALSE(true) << "the receiver is nullptr";
        return ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR;
    }
    InstallParam installParam;
    installParam.userId = USERID;
    installParam.installFlag = InstallFlag::NORMAL;
    bool result = installer->Uninstall(bundleName, installParam, receiver);
    EXPECT_TRUE(result);
    return receiver->GetResultCode();
}

ErrCode BmsBundleUpdateDebugTest::UpdateBundle(const std::string &bundlePath) const
{
    auto installer = DelayedSingleton<BundleMgrService>::GetInstance()->GetBundleInstaller();
    if (!installer) {
        EXPECT_FALSE(true) << "the installer is nullptr";
        return ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR;
    }

    sptr<MockStatusReceiver> receiver = new (std::nothrow) MockStatusReceiver();
    if (!receiver) {
        EXPECT_FALSE(true) << "the receiver is nullptr";
        return ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR;
    }
    InstallParam installParam;
    installParam.userId = USERID;
    installParam.installFlag = InstallFlag::REPLACE_EXISTING;
    installParam.withCopyHaps = true;
    bool result = installer->Install(bundlePath, installParam, receiver);
    EXPECT_TRUE(result);
    return receiver->GetResultCode();
}

ErrCode BmsBundleUpdateDebugTest::UpdateBundle(const std::string &bundlePath, const bool needCheckInfo) const
{
    auto installer = DelayedSingleton<BundleMgrService>::GetInstance()->GetBundleInstaller();
    if (!installer) {
        EXPECT_FALSE(true) << "the installer is nullptr";
        return ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR;
    }
    sptr<MockStatusReceiver> receiver = new (std::nothrow) MockStatusReceiver();
    if (!receiver) {
        EXPECT_FALSE(true) << "the receiver is nullptr";
        return ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR;
    }
    InstallParam installParam;
    installParam.userId = USERID;
    installParam.installFlag = InstallFlag::REPLACE_EXISTING;
    installParam.withCopyHaps = true;
    bool result = installer->Install(bundlePath, installParam, receiver);
    EXPECT_TRUE(result);

    // check can not access the application info between updating.
    if (needCheckInfo) {
        bool isBlock = false;
        for (int32_t i = 0; i < MAX_TRY_TIMES; i++) {
            std::this_thread::sleep_for(10ms);
            bool isExist = CheckApplicationInfo();
            if (isExist) {
                isBlock = true;
                break;
            }
        }
        if (!isBlock) {
            EXPECT_FALSE(true) << "the bundle info is not disable during updating";
            return ERR_APPEXECFWK_INSTALL_BUNDLE_MGR_SERVICE_ERROR;
        }
    }

    return receiver->GetResultCode();
}

void BmsBundleUpdateDebugTest::StopInstalldService() const
{
    installdService_->Stop();
    InstalldClient::GetInstance()->ResetInstalldProxy();
}

void BmsBundleUpdateDebugTest::StartInstalldService() const
{
    installdService_->Start();
}

void BmsBundleUpdateDebugTest::StopBundleService() const
{
    DelayedSingleton<BundleMgrService>::GetInstance()->OnStop();
}

bool BmsBundleUpdateDebugTest::CheckApplicationInfo() const
{
    ApplicationInfo info;
    auto dataMgr = GetBundleDataMgr();
    if (dataMgr == nullptr) {
        return false;
    }
    bool result = dataMgr->GetApplicationInfo(PACKAGE_NAME, ApplicationFlag::GET_BASIC_APPLICATION_INFO, USERID, info);
    return result;
}

bool BmsBundleUpdateDebugTest::CheckApplicationDebugValue(bool value) const
{
    ApplicationInfo info;
    auto dataMgr = GetBundleDataMgr();
    if (dataMgr == nullptr) {
        return false;
    }
    bool result = dataMgr->GetApplicationInfo(PACKAGE_NAME, ApplicationFlag::GET_BASIC_APPLICATION_INFO, USERID, info);
    if (result) {
        return info.debug == value;
    }
    return false;
}

/**
* @tc.number: UpdateDebug_0100
* @tc.name: test UpdateDebug
* @tc.desc: test oldInfo has entry
*/
HWTEST_F(BmsBundleUpdateDebugTest, UpdateDebug_0100, Function | SmallTest | Level1)
{
    InnerBundleInfo oldInfo;
    oldInfo.baseApplicationInfo_->debug = true;

    InnerModuleInfo entryModule;
    entryModule.name = "entry";
    entryModule.moduleName = "entry";
    entryModule.isEntry = true;
    entryModule.debug = true;
    oldInfo.InsertInnerModuleInfo(entryModule.name, entryModule);
    InnerModuleInfo hspModule;
    hspModule.name = "hsp";
    hspModule.moduleName = "hsp";
    hspModule.isEntry = false;
    hspModule.debug = true;
    oldInfo.InsertInnerModuleInfo(hspModule.name, hspModule);

    InnerBundleInfo newInfo;
    InnerModuleInfo tmpModule;
    tmpModule.name = "entry";
    tmpModule.isEntry = true;
    tmpModule.debug = true;
    newInfo.baseApplicationInfo_->debug = true;
    newInfo.innerModuleInfos_.clear();
    newInfo.InsertInnerModuleInfo(tmpModule.name, tmpModule);
    newInfo.SetCurrentModulePackage(tmpModule.name);
    oldInfo.UpdateDebug(newInfo);
    EXPECT_TRUE(oldInfo.baseApplicationInfo_->debug);
    auto module = oldInfo.GetInnerModuleInfoByModuleName("entry");
    EXPECT_TRUE(module->debug);
    module = oldInfo.GetInnerModuleInfoByModuleName("hsp");
    EXPECT_TRUE(module->debug);

    tmpModule.name = "entry";
    tmpModule.isEntry = true;
    tmpModule.debug = false;
    newInfo.baseApplicationInfo_->debug = false;
    newInfo.innerModuleInfos_.clear();
    newInfo.InsertInnerModuleInfo(tmpModule.name, tmpModule);
    newInfo.SetCurrentModulePackage(tmpModule.name);
    oldInfo.UpdateDebug(newInfo);
    EXPECT_FALSE(oldInfo.baseApplicationInfo_->debug);
    module = oldInfo.GetInnerModuleInfoByModuleName("entry");
    EXPECT_FALSE(module->debug);
    module = oldInfo.GetInnerModuleInfoByModuleName("hsp");
    EXPECT_TRUE(module->debug);

    tmpModule.name = "hsp";
    tmpModule.isEntry = false;
    tmpModule.debug = false;
    newInfo.baseApplicationInfo_->debug = false;
    newInfo.innerModuleInfos_.clear();
    newInfo.InsertInnerModuleInfo(tmpModule.name, tmpModule);
    newInfo.SetCurrentModulePackage(tmpModule.name);
    oldInfo.UpdateDebug(newInfo);
    EXPECT_FALSE(oldInfo.baseApplicationInfo_->debug);
    module = oldInfo.GetInnerModuleInfoByModuleName("entry");
    EXPECT_FALSE(module->debug);
    module = oldInfo.GetInnerModuleInfoByModuleName("hsp");
    EXPECT_FALSE(module->debug);

    tmpModule.name = "hsp";
    tmpModule.isEntry = false;
    tmpModule.debug = true;
    newInfo.baseApplicationInfo_->debug = true;
    newInfo.innerModuleInfos_.clear();
    newInfo.InsertInnerModuleInfo(tmpModule.name, tmpModule);
    newInfo.SetCurrentModulePackage(tmpModule.name);
    oldInfo.UpdateDebug(newInfo);
    EXPECT_FALSE(oldInfo.baseApplicationInfo_->debug);
    module = oldInfo.GetInnerModuleInfoByModuleName("entry");
    EXPECT_FALSE(module->debug);
    module = oldInfo.GetInnerModuleInfoByModuleName("hsp");
    EXPECT_TRUE(module->debug);

    tmpModule.name = "feature";
    tmpModule.isEntry = false;
    tmpModule.debug = true;
    newInfo.baseApplicationInfo_->debug = true;
    newInfo.innerModuleInfos_.clear();
    newInfo.InsertInnerModuleInfo(tmpModule.name, tmpModule);
    newInfo.SetCurrentModulePackage(tmpModule.name);
    oldInfo.UpdateDebug(newInfo);
    EXPECT_FALSE(oldInfo.baseApplicationInfo_->debug);
    module = oldInfo.GetInnerModuleInfoByModuleName("entry");
    EXPECT_FALSE(module->debug);
    module = oldInfo.GetInnerModuleInfoByModuleName("hsp");
    EXPECT_TRUE(module->debug);

    tmpModule.name = "feature";
    tmpModule.isEntry = false;
    tmpModule.debug = false;
    newInfo.baseApplicationInfo_->debug = false;
    newInfo.innerModuleInfos_.clear();
    newInfo.InsertInnerModuleInfo(tmpModule.name, tmpModule);
    newInfo.SetCurrentModulePackage(tmpModule.name);
    oldInfo.UpdateDebug(newInfo);
    EXPECT_FALSE(oldInfo.baseApplicationInfo_->debug);
    module = oldInfo.GetInnerModuleInfoByModuleName("entry");
    EXPECT_FALSE(module->debug);
    module = oldInfo.GetInnerModuleInfoByModuleName("hsp");
    EXPECT_TRUE(module->debug);
}

/**
* @tc.number: UpdateDebug_0200
* @tc.name: test UpdateDebug
* @tc.desc: test oldInfo has no entry
*/
HWTEST_F(BmsBundleUpdateDebugTest, UpdateDebug_0200, Function | SmallTest | Level2)
{
    InnerBundleInfo oldInfo;
    oldInfo.baseApplicationInfo_->debug = true;
    InnerModuleInfo feature;
    feature.name = "feature";
    feature.moduleName = "feature";
    feature.isEntry = false;
    feature.debug = true;
    oldInfo.InsertInnerModuleInfo(feature.name, feature);
    InnerModuleInfo hsp;
    hsp.name = "hsp";
    hsp.moduleName = "hsp";
    hsp.isEntry = false;
    hsp.debug = true;
    oldInfo.InsertInnerModuleInfo(hsp.name, hsp);

    InnerBundleInfo newInfo;
    InnerModuleInfo tmpModule;
    tmpModule.name = "entry";
    tmpModule.isEntry = true;
    tmpModule.debug = false;
    newInfo.baseApplicationInfo_->debug = false;
    newInfo.innerModuleInfos_.clear();
    newInfo.InsertInnerModuleInfo(tmpModule.name, tmpModule);
    newInfo.SetCurrentModulePackage(tmpModule.name);
    oldInfo.UpdateDebug(newInfo);
    EXPECT_FALSE(oldInfo.baseApplicationInfo_->debug);
    auto module = oldInfo.GetInnerModuleInfoByModuleName("feature");
    EXPECT_TRUE(module->debug);
    module = oldInfo.GetInnerModuleInfoByModuleName("hsp");
    EXPECT_TRUE(module->debug);

    newInfo.innerModuleInfos_.clear();
    newInfo.baseApplicationInfo_->debug = true;
    tmpModule.name = "entry";
    tmpModule.isEntry = true;
    tmpModule.debug = true;
    newInfo.InsertInnerModuleInfo(tmpModule.name, tmpModule);
    newInfo.SetCurrentModulePackage(tmpModule.name);
    oldInfo.UpdateDebug(newInfo);
    EXPECT_TRUE(oldInfo.baseApplicationInfo_->debug);
    module = oldInfo.GetInnerModuleInfoByModuleName("feature");
    EXPECT_TRUE(module->debug);
    module = oldInfo.GetInnerModuleInfoByModuleName("hsp");
    EXPECT_TRUE(module->debug);

    newInfo.innerModuleInfos_.clear();
    newInfo.baseApplicationInfo_->debug = false;
    tmpModule.name = "feature";
    tmpModule.isEntry = false;
    tmpModule.debug = false;
    newInfo.InsertInnerModuleInfo(tmpModule.name, tmpModule);
    newInfo.SetCurrentModulePackage(tmpModule.name);
    oldInfo.UpdateDebug(newInfo);
    EXPECT_TRUE(oldInfo.baseApplicationInfo_->debug);
    module = oldInfo.GetInnerModuleInfoByModuleName("feature");
    EXPECT_FALSE(module->debug);
    module = oldInfo.GetInnerModuleInfoByModuleName("hsp");
    EXPECT_TRUE(module->debug);

    newInfo.innerModuleInfos_.clear();
    newInfo.baseApplicationInfo_->debug = false;
    tmpModule.name = "hsp";
    tmpModule.isEntry = false;
    tmpModule.debug = false;
    newInfo.InsertInnerModuleInfo(tmpModule.name, tmpModule);
    newInfo.SetCurrentModulePackage(tmpModule.name);
    oldInfo.UpdateDebug(newInfo);
    EXPECT_FALSE(oldInfo.baseApplicationInfo_->debug);
    module = oldInfo.GetInnerModuleInfoByModuleName("feature");
    EXPECT_FALSE(module->debug);
    module = oldInfo.GetInnerModuleInfoByModuleName("hsp");
    EXPECT_FALSE(module->debug);

    newInfo.innerModuleInfos_.clear();
    newInfo.baseApplicationInfo_->debug = true;
    tmpModule.name = "hsp";
    tmpModule.isEntry = false;
    tmpModule.debug = true;
    newInfo.InsertInnerModuleInfo(tmpModule.name, tmpModule);
    newInfo.SetCurrentModulePackage(tmpModule.name);
    oldInfo.UpdateDebug(newInfo);
    EXPECT_TRUE(oldInfo.baseApplicationInfo_->debug);
    module = oldInfo.GetInnerModuleInfoByModuleName("feature");
    EXPECT_FALSE(module->debug);
    module = oldInfo.GetInnerModuleInfoByModuleName("hsp");
    EXPECT_TRUE(module->debug);

    newInfo.innerModuleInfos_.clear();
    newInfo.baseApplicationInfo_->debug = true;
    tmpModule.name = "feature";
    tmpModule.isEntry = false;
    tmpModule.debug = true;
    newInfo.InsertInnerModuleInfo(tmpModule.name, tmpModule);
    newInfo.SetCurrentModulePackage(tmpModule.name);
    oldInfo.UpdateDebug(newInfo);
    EXPECT_TRUE(oldInfo.baseApplicationInfo_->debug);
    module = oldInfo.GetInnerModuleInfoByModuleName("feature");
    EXPECT_TRUE(module->debug);
    module = oldInfo.GetInnerModuleInfoByModuleName("entry");
    EXPECT_TRUE(module->debug);
}

/**
 * @tc.number: UpdateDebug_0300
 * @tc.name: test entry update
 * @tc.desc: 1. install entry
 *           2. install the same version entry, check debug value
 */
HWTEST_F(BmsBundleUpdateDebugTest, UpdateDebug_0300, Function | SmallTest | Level2)
{
    ErrCode installResult = InstallBundle(BUNDLE_FILE_DIR + ENTRY_V1_RELEASE_BUNDLE);
    EXPECT_EQ(installResult, ERR_OK);
    EXPECT_TRUE(CheckApplicationDebugValue(false));

    installResult = UpdateBundle(BUNDLE_FILE_DIR + ENTRY_V1_DEBUG_BUNDLE, true);
    EXPECT_EQ(installResult, ERR_OK);
    EXPECT_TRUE(CheckApplicationDebugValue(true));

    installResult = InstallBundle(BUNDLE_FILE_DIR + FEATURE_V1_RELEASE_BUNDLE);
    EXPECT_EQ(installResult, ERR_OK);
    EXPECT_TRUE(CheckApplicationDebugValue(true));

    installResult = InstallBundle(BUNDLE_FILE_DIR + LIBRARY_V1_RELEASE_BUNDLE);
    EXPECT_EQ(installResult, ERR_OK);
    EXPECT_TRUE(CheckApplicationDebugValue(true));

    installResult = UpdateBundle(BUNDLE_FILE_DIR + ENTRY_V1_RELEASE_BUNDLE, true);
    EXPECT_EQ(installResult, ERR_OK);
    EXPECT_TRUE(CheckApplicationDebugValue(false));

    installResult = UninstallBundle(BUNDLE_NAME);
    EXPECT_EQ(installResult, ERR_OK);
}

/**
 * @tc.number: UpdateDebug_0400
 * @tc.name: test entry update
 * @tc.desc: 1. install entry
 *           2. install the upgrade version entry, check debug value
 */
HWTEST_F(BmsBundleUpdateDebugTest, UpdateDebug_0400, Function | SmallTest | Level2)
{
    ErrCode installResult = InstallBundle(BUNDLE_FILE_DIR + ENTRY_V1_DEBUG_BUNDLE);
    EXPECT_EQ(installResult, ERR_OK);
    EXPECT_TRUE(CheckApplicationDebugValue(true));

    installResult = InstallBundle(BUNDLE_FILE_DIR + FEATURE_V1_RELEASE_BUNDLE);
    EXPECT_EQ(installResult, ERR_OK);
    EXPECT_TRUE(CheckApplicationDebugValue(true));

    installResult = InstallBundle(BUNDLE_FILE_DIR + LIBRARY_V1_RELEASE_BUNDLE);
    EXPECT_EQ(installResult, ERR_OK);
    EXPECT_TRUE(CheckApplicationDebugValue(true));

    installResult = UpdateBundle(BUNDLE_FILE_DIR + ENTRY_V2_RELEASE_BUNDLE, true);
    EXPECT_EQ(installResult, ERR_OK);
    EXPECT_TRUE(CheckApplicationDebugValue(false));

    installResult = UninstallBundle(BUNDLE_NAME);
    EXPECT_EQ(installResult, ERR_OK);
}

/**
 * @tc.number: UpdateDebug_0500
 * @tc.name: test feature update
 * @tc.desc: 1. install feature
 *           2. install the same version feature, check debug value
 */
HWTEST_F(BmsBundleUpdateDebugTest, UpdateDebug_0500, Function | SmallTest | Level2)
{
    ErrCode installResult = InstallBundle(BUNDLE_FILE_DIR + FEATURE_V1_RELEASE_BUNDLE);
    EXPECT_EQ(installResult, ERR_OK);
    EXPECT_TRUE(CheckApplicationDebugValue(false));

    installResult = InstallBundle(BUNDLE_FILE_DIR + LIBRARY_V1_DEBUG_BUNDLE);
    EXPECT_EQ(installResult, ERR_OK);
    EXPECT_TRUE(CheckApplicationDebugValue(true));

    installResult = UpdateBundle(BUNDLE_FILE_DIR + LIBRARY_V1_RELEASE_BUNDLE);
    EXPECT_EQ(installResult, ERR_OK);
    EXPECT_TRUE(CheckApplicationDebugValue(false));

    installResult = UpdateBundle(BUNDLE_FILE_DIR + FEATURE_V1_DEBUG_BUNDLE);
    EXPECT_EQ(installResult, ERR_OK);
    EXPECT_TRUE(CheckApplicationDebugValue(true));

    installResult = UpdateBundle(BUNDLE_FILE_DIR + LIBRARY_V1_RELEASE_BUNDLE);
    EXPECT_EQ(installResult, ERR_OK);
    EXPECT_TRUE(CheckApplicationDebugValue(true));

    installResult = UninstallBundle(BUNDLE_NAME);
    EXPECT_EQ(installResult, ERR_OK);
}

/**
 * @tc.number: UpdateDebug_0600
 * @tc.name: test feature update
 * @tc.desc: 1. install feature
 *           2. install the upgrade version feature, check debug value
 */
HWTEST_F(BmsBundleUpdateDebugTest, UpdateDebug_0600, Function | SmallTest | Level2)
{
    ErrCode installResult = InstallBundle(BUNDLE_FILE_DIR + FEATURE_V1_DEBUG_BUNDLE);
    EXPECT_EQ(installResult, ERR_OK);
    EXPECT_TRUE(CheckApplicationDebugValue(true));

    installResult = InstallBundle(BUNDLE_FILE_DIR + LIBRARY_V1_RELEASE_BUNDLE);
    EXPECT_EQ(installResult, ERR_OK);
    EXPECT_TRUE(CheckApplicationDebugValue(true));

    installResult = UpdateBundle(BUNDLE_FILE_DIR + FEATURE_V1_RELEASE_BUNDLE);
    EXPECT_EQ(installResult, ERR_OK);
    EXPECT_TRUE(CheckApplicationDebugValue(false));

    installResult = UpdateBundle(BUNDLE_FILE_DIR + LIBRARY_V1_DEBUG_BUNDLE);
    EXPECT_EQ(installResult, ERR_OK);
    EXPECT_TRUE(CheckApplicationDebugValue(true));

    installResult = UpdateBundle(BUNDLE_FILE_DIR + FEATURE_V2_RELEASE_BUNDLE);
    EXPECT_EQ(installResult, ERR_OK);
    EXPECT_TRUE(CheckApplicationDebugValue(false));

    installResult = UninstallBundle(BUNDLE_NAME);
    EXPECT_EQ(installResult, ERR_OK);
}
} // OHOS
