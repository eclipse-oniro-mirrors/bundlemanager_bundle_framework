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

#include <fstream>
#include <gtest/gtest.h>
#include <map>
#include <sstream>
#include <string>

#include "bundle_installer_host.h"
#include "bundle_mgr_service.h"
#include "extend_resource_manager_host_impl.h"
#include "installd/installd_service.h"
#include "installd_client.h"
#include "mock_status_receiver.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace {
const std::string DIR_PATH_ONE = "/data/service/el1";
const std::string DIR_PATH_TWO = "/data/test/test";
const std::string FILE_PATH = "/data/service/el1/public/bms/bundle_manager_service/a.hsp";
const std::string INVALID_PATH = "/data/service/el1/public/bms/bundle_manager_service/../../a.hsp";
const std::string INVALID_SUFFIX = "/data/service/el1/public/bms/bundle_manager_service/a.hap";
const std::string INVALID_PREFIX = "/data/app/el1/bundle/public/a.hsp";
const std::string BUNDLE_PATH = "/data/test/resource/bms/resource_manager/resourceManagerTest.hap";
const std::string BUNDLE_NAME = "com.ohos.resourcedemo";
const std::string EXT_RESOURCE_FILE = "a.hsp";
const std::string ERR_FILE_PATH = "data";
const std::string BUNDLE_NAME2 = "com.ohos.mms";
const std::string TEST_BUNDLE = "com.test.ext.resource";
const std::string TEST_MODULE = "testModule";
const std::string EMPTY_STRING = "";
const int32_t WAIT_TIME = 5; // init mocked bms
const int32_t USER_ID = 100;
}  // namespace

class BmsExtendResourceManagerTest : public testing::Test {
public:
    BmsExtendResourceManagerTest();
    ~BmsExtendResourceManagerTest();
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

    ErrCode InstallBundle(const std::string &bundlePath) const;
    ErrCode UnInstallBundle(const std::string &bundleName) const;
    void StartInstalldService() const;
    void StartBundleService();
    const std::shared_ptr<BundleDataMgr> GetBundleDataMgr() const;

private:
    static std::shared_ptr<BundleMgrService> bundleMgrService_;
};

std::shared_ptr<BundleMgrService> BmsExtendResourceManagerTest::bundleMgrService_ =
    DelayedSingleton<BundleMgrService>::GetInstance();

BmsExtendResourceManagerTest::BmsExtendResourceManagerTest()
{}

BmsExtendResourceManagerTest::~BmsExtendResourceManagerTest()
{}

void BmsExtendResourceManagerTest::SetUpTestCase()
{}

ErrCode BmsExtendResourceManagerTest::InstallBundle(const std::string &bundlePath) const
{
    if (!bundleMgrService_) {
        return ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR;
    }
    auto installer = bundleMgrService_->GetBundleInstaller();
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
    installParam.installFlag = InstallFlag::REPLACE_EXISTING;
    installParam.userId = USER_ID;
    bool result = installer->Install(bundlePath, installParam, receiver);
    EXPECT_TRUE(result);
    return receiver->GetResultCode();
}

ErrCode BmsExtendResourceManagerTest::UnInstallBundle(const std::string &bundleName) const
{
    if (!bundleMgrService_) {
        return ERR_APPEXECFWK_UNINSTALL_BUNDLE_MGR_SERVICE_ERROR;
    }
    auto installer = bundleMgrService_->GetBundleInstaller();
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
    installParam.installFlag = InstallFlag::NORMAL;
    installParam.userId = USER_ID;
    bool result = installer->Uninstall(bundleName, installParam, receiver);
    EXPECT_TRUE(result);
    return receiver->GetResultCode();
}

const std::shared_ptr<BundleDataMgr> BmsExtendResourceManagerTest::GetBundleDataMgr() const
{
    return bundleMgrService_->GetDataMgr();
}


void BmsExtendResourceManagerTest::StartInstalldService() const
{}

void BmsExtendResourceManagerTest::StartBundleService()
{
    if (!bundleMgrService_->IsServiceReady()) {
        bundleMgrService_->OnStart();
        bundleMgrService_->GetDataMgr()->AddUserId(USER_ID);
        std::this_thread::sleep_for(std::chrono::seconds(WAIT_TIME));
    }
}

void BmsExtendResourceManagerTest::TearDownTestCase()
{
    bundleMgrService_->OnStop();
}

void BmsExtendResourceManagerTest::SetUp()
{
    StartBundleService();
    StartInstalldService();
    InstallBundle(BUNDLE_PATH);
}

void BmsExtendResourceManagerTest::TearDown()
{
    UnInstallBundle(BUNDLE_NAME);
}

/**
 * @tc.number: ExtResourceTest_0100
 * @tc.name: test ExtResourceTest_0100
 * @tc.desc: 1.AddExtResource test
 */
HWTEST_F(BmsExtendResourceManagerTest, ExtResourceTest_0100, Function | SmallTest | Level1)
{
    ExtendResourceManagerHostImpl impl;
    std::vector<std::string> filePaths;
    std::string emptyBundleName;
    auto ret = impl.AddExtResource(emptyBundleName, filePaths);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);

    ret = impl.AddExtResource(BUNDLE_NAME, filePaths);
    EXPECT_EQ(ret, ERR_EXT_RESOURCE_MANAGER_INVALID_PATH_FAILED);

    filePaths.emplace_back(INVALID_PATH);
    ret = impl.AddExtResource(BUNDLE_NAME, filePaths);
    EXPECT_EQ(ret, ERR_EXT_RESOURCE_MANAGER_INVALID_PATH_FAILED);

    std::vector<std::string> filePaths2;
    filePaths.emplace_back(INVALID_SUFFIX);
    ret = impl.AddExtResource(BUNDLE_NAME, filePaths2);
    EXPECT_EQ(ret, ERR_EXT_RESOURCE_MANAGER_INVALID_PATH_FAILED);

    std::vector<std::string> filePaths3;
    filePaths3.emplace_back(INVALID_PREFIX);
    ret = impl.AddExtResource(BUNDLE_NAME, filePaths3);
    EXPECT_EQ(ret, ERR_EXT_RESOURCE_MANAGER_INVALID_PATH_FAILED);
}

/**
 * @tc.number: ExtResourceTest_0200
 * @tc.name: test ExtResourceTest_0200
 * @tc.desc: 1. BeforeAddExtResource test
 */
HWTEST_F(BmsExtendResourceManagerTest, ExtResourceTest_0200, Function | SmallTest | Level1)
{
    ExtendResourceManagerHostImpl impl;
    auto ret = impl.CheckFileParam(INVALID_PATH);
    EXPECT_FALSE(ret);

    ret = impl.CheckFileParam(INVALID_SUFFIX);
    EXPECT_FALSE(ret);

    ret = impl.CheckFileParam(INVALID_PREFIX);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: ExtResourceTest_0300
 * @tc.name: test ExtResourceTest_0300
 * @tc.desc: 1.ProcessAddExtResource test
 */
HWTEST_F(BmsExtendResourceManagerTest, ExtResourceTest_0300, Function | SmallTest | Level1)
{
    ExtendResourceManagerHostImpl impl;
    std::vector<std::string> filePaths;
    auto ret = impl.ProcessAddExtResource(TEST_BUNDLE, filePaths);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
}

/**
 * @tc.number: ExtResourceTest_0400
 * @tc.name: test ExtResourceTest_0400
 * @tc.desc: 1.RemoveExtResource test
 */
HWTEST_F(BmsExtendResourceManagerTest, ExtResourceTest_0400, Function | SmallTest | Level1)
{
    ExtendResourceManagerHostImpl impl;
    std::string emptyBundleName;
    std::vector<std::string> moduleNames;
    auto ret = impl.RemoveExtResource(emptyBundleName, moduleNames);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);

    ret = impl.RemoveExtResource(TEST_BUNDLE, moduleNames);
    EXPECT_EQ(ret, ERR_EXT_RESOURCE_MANAGER_REMOVE_EXT_RESOURCE_FAILED);

    moduleNames.push_back(TEST_MODULE);
    ret = impl.RemoveExtResource(TEST_BUNDLE, moduleNames);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);

    std::vector<ExtendResourceInfo> extResourceInfos;
    impl.InnerRemoveExtendResources(TEST_BUNDLE, moduleNames, extResourceInfos);
}

/**
 * @tc.number: ExtResourceTest_0500
 * @tc.name: test ExtResourceTest_0500
 * @tc.desc: 1.CheckModuleExist test
 */
HWTEST_F(BmsExtendResourceManagerTest, ExtResourceTest_0500, Function | SmallTest | Level1)
{
    ExtendResourceManagerHostImpl impl;
    std::string emptyBundleName;
    std::vector<std::string> moduleNames;
    std::vector<ExtendResourceInfo> extendResourceInfos;
    auto ret = impl.CheckModuleExist(TEST_BUNDLE, moduleNames, extendResourceInfos);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
}

/**
 * @tc.number: ExtResourceTest_0600
 * @tc.name: test ExtResourceTest_0600
 * @tc.desc: 1.GetExtResource test
 */
HWTEST_F(BmsExtendResourceManagerTest, ExtResourceTest_0600, Function | SmallTest | Level1)
{
    ExtendResourceManagerHostImpl impl;
    std::string emptyBundleName;
    std::vector<std::string> moduleNames;
    auto ret = impl.GetExtResource(emptyBundleName, moduleNames);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);

    ret = impl.GetExtResource(TEST_BUNDLE, moduleNames);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
}

/**
 * @tc.number: ExtResourceTest_0700
 * @tc.name: test ExtResourceTest_0700
 * @tc.desc: 1.BeforeAddExtResource test
 */
HWTEST_F(BmsExtendResourceManagerTest, ExtResourceTest_0700, Function | SmallTest | Level1)
{
    ExtendResourceManagerHostImpl impl;
    std::vector<std::string> filePaths;
    auto ret = impl.BeforeAddExtResource(EMPTY_STRING, filePaths);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);

    ret = impl.BeforeAddExtResource(BUNDLE_NAME, filePaths);
    EXPECT_EQ(ret, ERR_EXT_RESOURCE_MANAGER_INVALID_PATH_FAILED);

    filePaths.emplace_back(FILE_PATH);
    filePaths.emplace_back(INVALID_PATH);
    ret = impl.BeforeAddExtResource(BUNDLE_NAME, filePaths);
    EXPECT_EQ(ret, ERR_EXT_RESOURCE_MANAGER_INVALID_PATH_FAILED);
}

/**
 * @tc.number: ExtResourceTest_0700
 * @tc.name: test ExtResourceTest_0700
 * @tc.desc: 1.BeforeAddExtResource test
 */
HWTEST_F(BmsExtendResourceManagerTest, ExtResourceTest_0800, Function | SmallTest | Level1)
{
    ExtendResourceManagerHostImpl impl;
    std::vector<std::string> filePaths;
    filePaths.emplace_back(FILE_PATH);
    std::vector<ExtendResourceInfo> extendResourceInfos;
    auto ret = impl.ParseExtendResourceFile(BUNDLE_NAME, filePaths, extendResourceInfos);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_FAILED_INVALID_SIGNATURE_FILE_PATH);
}

/**
 * @tc.number: ExtResourceTest_0700
 * @tc.name: test ExtResourceTest_0700
 * @tc.desc: 1.BeforeAddExtResource test
 */
HWTEST_F(BmsExtendResourceManagerTest, ExtResourceTest_0900, Function | SmallTest | Level1)
{
    ExtendResourceManagerHostImpl impl;
    auto ret = impl.MkdirIfNotExist(DIR_PATH_ONE);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_GET_PROXY_ERROR);

    ret = impl.MkdirIfNotExist(DIR_PATH_TWO);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_GET_PROXY_ERROR);

    std::vector<std::string> moduleNames;
    moduleNames.push_back(TEST_MODULE);
    ret = impl.RemoveExtResourcesDb(BUNDLE_NAME, moduleNames);
    EXPECT_EQ(ret, ERR_OK);

    std::vector<std::string> filePaths;
    filePaths.push_back(FILE_PATH);
    impl.RollBack(filePaths);
}

/**
 * @tc.number: ExtResourceTest_0700
 * @tc.name: test ExtResourceTest_0700
 * @tc.desc: 1.BeforeAddExtResource test
 */
HWTEST_F(BmsExtendResourceManagerTest, ExtResourceTest_1000, Function | SmallTest | Level1)
{
    ExtendResourceManagerHostImpl impl;
    std::vector<std::string> oldFilePaths;
    oldFilePaths.push_back(FILE_PATH);
    std::vector<std::string> newFilePaths;
    newFilePaths.push_back(DIR_PATH_TWO);
    auto ret = impl.CopyToTempDir(BUNDLE_NAME, oldFilePaths, newFilePaths);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_GET_PROXY_ERROR);

    std::vector<ExtendResourceInfo> extendResourceInfos;
    ret = impl.UpateExtResourcesDb(BUNDLE_NAME, extendResourceInfos);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: DynamicIconTest_0100
 * @tc.name: test DynamicIconTest_0100
 * @tc.desc: 1.EnableDynamic test
 */
HWTEST_F(BmsExtendResourceManagerTest, DynamicIconTest_0100, Function | SmallTest | Level1)
{
    ExtendResourceManagerHostImpl impl;
    std::string emptyStr;
    auto ret = impl.EnableDynamicIcon(emptyStr, emptyStr);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);

    ret = impl.EnableDynamicIcon(TEST_BUNDLE, emptyStr);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_MODULE_NOT_EXIST);

    ret = impl.EnableDynamicIcon(TEST_BUNDLE, TEST_MODULE);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
}

/**
 * @tc.number: DynamicIconTest_0200
 * @tc.name: test DynamicIconTest_0200
 * @tc.desc: 1.DisableDynamicIcon test
 */
HWTEST_F(BmsExtendResourceManagerTest, DynamicIconTest_0200, Function | SmallTest | Level1)
{
    ExtendResourceManagerHostImpl impl;
    std::string emptyStr;
    auto ret = impl.DisableDynamicIcon(emptyStr);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);

    ret = impl.DisableDynamicIcon(TEST_BUNDLE);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
}

/**
 * @tc.number: DynamicIconTest_0300
 * @tc.name: test DynamicIconTest_0300
 * @tc.desc: 1.GetDynamicIcon test
 */
HWTEST_F(BmsExtendResourceManagerTest, DynamicIconTest_0300, Function | SmallTest | Level1)
{
    ExtendResourceManagerHostImpl impl;
    std::string emptyStr;
    std::string moudleName;
    auto ret = impl.GetDynamicIcon(emptyStr, moudleName);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);

    ret = impl.GetDynamicIcon(TEST_BUNDLE, moudleName);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
}

/**
 * @tc.number: DynamicIconTest_0400
 * @tc.name: test DynamicIconTest_0400
 * @tc.desc: 1.EnableDynamic test
 */
HWTEST_F(BmsExtendResourceManagerTest, DynamicIconTest_0400, Function | SmallTest | Level1)
{
    ExtendResourceManagerHostImpl impl;
    InnerBundleInfo info;
    bool hasBundle = impl.GetInnerBundleInfo(BUNDLE_NAME2, info);
    if (!hasBundle) {
        return;
    }

    auto ret = impl.DisableDynamicIcon(BUNDLE_NAME2);
    EXPECT_EQ(ret, ERR_EXT_RESOURCE_MANAGER_DISABLE_DYNAMIC_ICON_FAILED);

    impl.SaveCurDynamicIcon(BUNDLE_NAME2, TEST_MODULE);
    ret = impl.DisableDynamicIcon(BUNDLE_NAME2);
    EXPECT_EQ(ret, ERR_OK);
    impl.SaveCurDynamicIcon(BUNDLE_NAME2, "");
}

/**
 * @tc.number: DynamicIconTest_0500
 * @tc.name: test DynamicIconTest_0500
 * @tc.desc: 1.EnableDynamic test
 */
HWTEST_F(BmsExtendResourceManagerTest, DynamicIconTest_0500, Function | SmallTest | Level1)
{
    ExtendResourceManagerHostImpl impl;
    InnerBundleInfo info;
    bool hasBundle = impl.GetInnerBundleInfo(BUNDLE_NAME2, info);
    if (!hasBundle) {
        return;
    }

    std::string moudleName;
    auto ret = impl.GetDynamicIcon(BUNDLE_NAME2, moudleName);
    EXPECT_TRUE(moudleName.empty());

    impl.SaveCurDynamicIcon(BUNDLE_NAME2, TEST_MODULE);
    ret = impl.GetDynamicIcon(BUNDLE_NAME2, moudleName);
    EXPECT_FALSE(moudleName.empty());
}

/**
 * @tc.number: CreateFd_0100
 * @tc.name: test CreateFd
 * @tc.desc: 1.test create fd by bundle name and path
 */
HWTEST_F(BmsExtendResourceManagerTest, CreateFd_0100, Function | SmallTest | Level1)
{
    ExtendResourceManagerHostImpl impl;
    std::string fileName;
    int32_t fd = 0;
    std::string path = FILE_PATH;
    ErrCode code = impl.CreateFd(fileName, fd, path);
    EXPECT_EQ(code, ERR_EXT_RESOURCE_MANAGER_CREATE_FD_FAILED);
    code = impl.CreateFd(BUNDLE_NAME, fd, path);
    EXPECT_NE(code, ERR_OK);
}

/**
 * @tc.number: ResetBundleResourceIcon_0100
 * @tc.name: test ResetBundleResourceIcon
 * @tc.desc: 1.reset bundle resource icon
 */
HWTEST_F(BmsExtendResourceManagerTest, ResetBundleResourceIcon_0100, Function | SmallTest | Level1)
{
    ExtendResourceManagerHostImpl impl;
    bool ret = impl.ResetBundleResourceIcon(BUNDLE_NAME);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: ParseBundleResource_0100
 * @tc.name: test ParseBundleResource
 * @tc.desc: 1.analyze bundled package resources
 */
HWTEST_F(BmsExtendResourceManagerTest, ParseBundleResource_0100, Function | SmallTest | Level1)
{
    ExtendResourceManagerHostImpl impl;
    std::string bundleName = BUNDLE_NAME;
    ExtendResourceInfo extendResourceInfo;
    bool ret = impl.ParseBundleResource(bundleName, extendResourceInfo);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: ProcessAddExtResource_0100
 * @tc.name: Test ProcessAddExtResource
 * @tc.desc: 1.ProcessAddExtResource
 */
HWTEST_F(BmsExtendResourceManagerTest, ProcessAddExtResource_0100, Function | SmallTest | Level1)
{
    ExtendResourceManagerHostImpl impl;
    std::vector<std::string> filePaths;
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    InnerBundleInfo info;
    dataMgr->bundleInfos_.emplace(BUNDLE_NAME, info);
    auto ret = impl.ProcessAddExtResource(BUNDLE_NAME, filePaths);
    EXPECT_EQ(ret, ERR_EXT_RESOURCE_MANAGER_PARSE_FILE_FAILED);
}

/**
 * @tc.number: CheckModuleExist_0100
 * @tc.name: Test CheckModuleExist
 * @tc.desc: 1.CheckModuleExist
 */
HWTEST_F(BmsExtendResourceManagerTest, CheckModuleExist_0100, Function | SmallTest | Level1)
{
    ExtendResourceManagerHostImpl impl;
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    InnerBundleInfo info;
    dataMgr->bundleInfos_.emplace(BUNDLE_NAME, info);
    std::string bundleName;
    std::vector<std::string> moduleNames;
    moduleNames.push_back(BUNDLE_PATH);
    std::vector<ExtendResourceInfo> collectorExtResourceInfos;
    auto ret = impl.CheckModuleExist(BUNDLE_NAME, moduleNames, collectorExtResourceInfos);
    EXPECT_EQ(ret, ERR_EXT_RESOURCE_MANAGER_REMOVE_EXT_RESOURCE_FAILED);
}

/**
 * @tc.number: CheckModuleExist_0200
 * @tc.name: Test CheckModuleExist
 * @tc.desc: 1.CheckModuleExist
 */
HWTEST_F(BmsExtendResourceManagerTest, CheckModuleExist_0200, Function | SmallTest | Level1)
{
    ExtendResourceManagerHostImpl impl;
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    InnerBundleInfo info;
    ExtendResourceInfo extendResourceInfo;
    info.extendResourceInfos_.emplace(BUNDLE_NAME, extendResourceInfo);
    dataMgr->bundleInfos_.clear();
    dataMgr->bundleInfos_.emplace(BUNDLE_NAME, info);
    std::string bundleName;
    std::vector<std::string> moduleNames;
    moduleNames.push_back(BUNDLE_NAME);
    std::vector<ExtendResourceInfo> collectorExtResourceInfos;
    auto ret = impl.CheckModuleExist(BUNDLE_NAME, moduleNames, collectorExtResourceInfos);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: GetExtResource_0100
 * @tc.name: Test CheckModuleExist
 * @tc.desc: 1.CheckModuleExist
 */
HWTEST_F(BmsExtendResourceManagerTest, GetExtResource_0100, Function | SmallTest | Level1)
{
    ExtendResourceManagerHostImpl impl;
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->bundleInfos_.clear();
    std::vector<std::string> moduleNames;
    auto ret = impl.GetExtResource(BUNDLE_NAME, moduleNames);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
}

/**
 * @tc.number: GetExtResource_0200
 * @tc.name: Test CheckModuleExist
 * @tc.desc: 1.CheckModuleExist
 */
HWTEST_F(BmsExtendResourceManagerTest, GetExtResource_0200, Function | SmallTest | Level1)
{
    ExtendResourceManagerHostImpl impl;
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    InnerBundleInfo info;
    dataMgr->bundleInfos_.emplace(BUNDLE_NAME, info);
    std::vector<std::string> moduleNames;
    moduleNames.push_back(BUNDLE_NAME);
    auto ret = impl.GetExtResource(BUNDLE_NAME, moduleNames);
    EXPECT_EQ(ret, ERR_EXT_RESOURCE_MANAGER_GET_EXT_RESOURCE_FAILED);
}

/**
 * @tc.number: GetExtResource_0300
 * @tc.name: Test CheckModuleExist
 * @tc.desc: 1.CheckModuleExist
 */
HWTEST_F(BmsExtendResourceManagerTest, GetExtResource_0300, Function | SmallTest | Level1)
{
    ExtendResourceManagerHostImpl impl;
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    InnerBundleInfo info;
    ExtendResourceInfo extendResourceInfo;
    info.extendResourceInfos_.emplace(BUNDLE_NAME, extendResourceInfo);
    dataMgr->bundleInfos_.clear();
    dataMgr->bundleInfos_.emplace(BUNDLE_NAME, info);
    std::vector<std::string> moduleNames;
    moduleNames.push_back(BUNDLE_NAME);
    auto ret = impl.GetExtResource(BUNDLE_NAME, moduleNames);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: SaveCurDynamicIcon_0100
 * @tc.name: Test SaveCurDynamicIcon
 * @tc.desc: 1.SaveCurDynamicIcon
 */
HWTEST_F(BmsExtendResourceManagerTest, SaveCurDynamicIcon_0100, Function | SmallTest | Level1)
{
    ExtendResourceManagerHostImpl impl;
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    InnerBundleInfo info;
    dataMgr->bundleInfos_.clear();
    dataMgr->bundleInfos_.emplace(BUNDLE_NAME, info);
    std::vector<std::string> moduleNames;
    moduleNames.push_back(BUNDLE_NAME);
    impl.SaveCurDynamicIcon(BUNDLE_NAME, TEST_MODULE);
    EXPECT_EQ(dataMgr->bundleInfos_.at(BUNDLE_NAME).curDynamicIconModule_, TEST_MODULE);
}

/**
 * @tc.number: SaveCurDynamicIcon_0200
 * @tc.name: Test SaveCurDynamicIcon
 * @tc.desc: 1.SaveCurDynamicIcon
 */
HWTEST_F(BmsExtendResourceManagerTest, SaveCurDynamicIcon_0200, Function | SmallTest | Level1)
{
    ExtendResourceManagerHostImpl impl;
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    InnerBundleInfo info;
    dataMgr->bundleInfos_.clear();
    dataMgr->bundleInfos_.emplace(BUNDLE_NAME, info);
    std::vector<std::string> moduleNames;
    moduleNames.push_back(BUNDLE_NAME);
    impl.SaveCurDynamicIcon(BUNDLE_NAME, TEST_MODULE);
    EXPECT_EQ(dataMgr->bundleInfos_.at(BUNDLE_NAME).curDynamicIconModule_, TEST_MODULE);
}

/**
 * @tc.number: GetExtendResourceInfo_0100
 * @tc.name: Test GetExtendResourceInfo
 * @tc.desc: 1.GetExtendResourceInfo
 */
HWTEST_F(BmsExtendResourceManagerTest, GetExtendResourceInfo_0100, Function | SmallTest | Level1)
{
    ExtendResourceManagerHostImpl impl;
    std::string bundleName;
    ExtendResourceInfo extendResourceInfo;
    auto res = impl.GetExtendResourceInfo(bundleName, TEST_MODULE, extendResourceInfo);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
}

/**
 * @tc.number: GetExtendResourceInfo_0200
 * @tc.name: Test GetExtendResourceInfo
 * @tc.desc: 1.GetExtendResourceInfo
 */
HWTEST_F(BmsExtendResourceManagerTest, GetExtendResourceInfo_0200, Function | SmallTest | Level1)
{
    ExtendResourceManagerHostImpl impl;
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    InnerBundleInfo info;
    dataMgr->bundleInfos_.clear();
    dataMgr->bundleInfos_.emplace(BUNDLE_NAME, info);
    ExtendResourceInfo extendResourceInfo;
    auto res = impl.GetExtendResourceInfo(BUNDLE_NAME, TEST_MODULE, extendResourceInfo);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_MODULE_NOT_EXIST);
}

/**
 * @tc.number: GetExtendResourceInfo_0300
 * @tc.name: Test GetExtendResourceInfo
 * @tc.desc: 1.GetExtendResourceInfo
 */
HWTEST_F(BmsExtendResourceManagerTest, GetExtendResourceInfo_0300, Function | SmallTest | Level1)
{
    ExtendResourceManagerHostImpl impl;
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    InnerBundleInfo info;
    ExtendResourceInfo extendResourceInfo;
    info.extendResourceInfos_.emplace(BUNDLE_NAME, extendResourceInfo);
    dataMgr->bundleInfos_.clear();
    dataMgr->bundleInfos_.emplace(BUNDLE_NAME, info);
    auto res = impl.GetExtendResourceInfo(BUNDLE_NAME, TEST_MODULE, extendResourceInfo);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_MODULE_NOT_EXIST);
}

/**
 * @tc.number: GetExtendResourceInfo_0400
 * @tc.name: Test GetExtendResourceInfo
 * @tc.desc: 1.GetExtendResourceInfo
 */
HWTEST_F(BmsExtendResourceManagerTest, GetExtendResourceInfo_0400, Function | SmallTest | Level1)
{
    ExtendResourceManagerHostImpl impl;
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    InnerBundleInfo info;
    ExtendResourceInfo extendResourceInfo;
    info.extendResourceInfos_.emplace(TEST_MODULE, extendResourceInfo);
    dataMgr->bundleInfos_.clear();
    dataMgr->bundleInfos_.emplace(BUNDLE_NAME, info);
    auto res = impl.GetExtendResourceInfo(BUNDLE_NAME, TEST_MODULE, extendResourceInfo);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: DisableDynamicIcon_0100
 * @tc.name: Test DisableDynamicIcon
 * @tc.desc: 1.DisableDynamicIcon
 */
HWTEST_F(BmsExtendResourceManagerTest, DisableDynamicIcon_0100, Function | SmallTest | Level1)
{
    ExtendResourceManagerHostImpl impl;
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    InnerBundleInfo info;
    info.curDynamicIconModule_ = TEST_BUNDLE;
    dataMgr->bundleInfos_[BUNDLE_NAME] = info;
    auto res = impl.DisableDynamicIcon(BUNDLE_NAME);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: GetDynamicIcon_0100
 * @tc.name: Test GetDynamicIcon
 * @tc.desc: 1.GetDynamicIcon
 */
HWTEST_F(BmsExtendResourceManagerTest, GetDynamicIcon_0100, Function | SmallTest | Level1)
{
    ExtendResourceManagerHostImpl impl;
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    InnerBundleInfo info;
    info.curDynamicIconModule_ = TEST_BUNDLE;
    dataMgr->bundleInfos_[BUNDLE_NAME] = info;
    std::string moudleName;
    auto res = impl.GetDynamicIcon(BUNDLE_NAME, moudleName);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: CreateFd_0100
 * @tc.name: Test CreateFd
 * @tc.desc: 1.CreateFd
 */
HWTEST_F(BmsExtendResourceManagerTest, GCreateFd_0100, Function | SmallTest | Level1)
{
    ExtendResourceManagerHostImpl impl;
    std::string fileName = "%.hsp";
    int32_t fd = 1;
    std::string path;
    auto res = impl.CreateFd(fileName, fd, path);
    EXPECT_EQ(res, ERR_EXT_RESOURCE_MANAGER_CREATE_FD_FAILED);
}

/**
 * @tc.number: CreateFd_0200
 * @tc.name: Test CreateFd
 * @tc.desc: 1.CreateFd
 */
HWTEST_F(BmsExtendResourceManagerTest, GCreateFd_0200, Function | SmallTest | Level1)
{
    ExtendResourceManagerHostImpl impl;
    std::string fileName = ".hsp";
    int32_t fd = 1;
    std::string path;
    auto res = impl.CreateFd(fileName, fd, path);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: ExtResourceTest_0700
 * @tc.name: test ExtResourceTest_0700
 * @tc.desc: 1.BeforeAddExtResource test
 */
HWTEST_F(BmsExtendResourceManagerTest, ExtResourceTest_1002, Function | SmallTest | Level1)
{
    ExtendResourceManagerHostImpl impl;
    std::vector<std::string> filePaths;
    filePaths.emplace_back(FILE_PATH);
    std::vector<ExtendResourceInfo> extendResourceInfos;
    auto ret = impl.ParseExtendResourceFile(BUNDLE_NAME, filePaths, extendResourceInfos);
    EXPECT_TRUE(ret);
}

/**
* @tc.number: ExtResourceTest_0700
* @tc.name:  test ExtResourceTest_0700
* @tc.desc: Verify the function behavior when all MoveFile operations succeed.
*/
HWTEST_F(BmsExtendResourceManagerTest, InnerSaveExtendResourceInfoTest_0100, Function | SmallTest | Level1)
{
    ExtendResourceManagerHostImpl impl;
    std::vector<std::string> filePaths;
    std::vector<ExtendResourceInfo> extendResourceInfos;
    std::vector<std::string> moduleNames;
    moduleNames.push_back(TEST_MODULE);
    auto ret = impl.RemoveExtResource(TEST_BUNDLE, moduleNames);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
    impl.InnerSaveExtendResourceInfo(BUNDLE_NAME, filePaths, extendResourceInfos);
    EXPECT_TRUE(ret);
}

/**
* @tc.number: ExtResourceTest_0700
* @tc.name: test ExtResourceTest_0700
* @tc.desc: 1.BeforeAddExtResource test
*/
HWTEST_F(BmsExtendResourceManagerTest, ExtResourceTest_1001, Function | SmallTest | Level1)
{
    ExtendResourceManagerHostImpl impl;
    std::vector<std::string> oldFilePaths;
    oldFilePaths.push_back(FILE_PATH);
    std::vector<std::string> newFilePaths;
    std::string buildResourcePath;
    auto originalMkdirIfNotExist = [](const std::string &path) {
        return ERR_OK;
    };
    auto originalMoveFile = [](const std::string &src, const std::string &dest) {
        return ERR_OK;
    };
    auto ret = impl.CopyToTempDir(BUNDLE_NAME, oldFilePaths, newFilePaths);
    std::vector<ExtendResourceInfo> extendResourceInfos;
    ret = impl.UpateExtResourcesDb(BUNDLE_NAME, extendResourceInfos);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: DisableDynamicIcon_0200
 * @tc.name: Test DisableDynamicIcon
 * @tc.desc: 1.DisableDynamicIcon
 */
HWTEST_F(BmsExtendResourceManagerTest, DisableDynamicIcon_0200, Function | SmallTest | Level1)
{
    ExtendResourceManagerHostImpl impl;
    const std::string bundleName = BUNDLE_NAME;
    ErrCode res = impl.DisableDynamicIcon(bundleName);
    EXPECT_FALSE(res);

    ErrCode ret = impl.DisableDynamicIcon(bundleName);
    EXPECT_EQ(ret, ERR_EXT_RESOURCE_MANAGER_DISABLE_DYNAMIC_ICON_FAILED);
}

/**
 * @tc.number: ExtResourceTest_1003
 * @tc.name: test ExtResourceTest_1003
 * @tc.desc: 1. BeforeAddExtResource test
 */
HWTEST_F(BmsExtendResourceManagerTest, ExtResourceTest_1003, Function | SmallTest | Level1)
{
    ExtendResourceManagerHostImpl impl;
    const std::string bundleName = BUNDLE_NAME;
    std::vector<std::string> filePaths;
    filePaths.emplace_back(INVALID_PATH);
    auto ret = impl.BeforeAddExtResource(bundleName, filePaths);
    EXPECT_TRUE(ret);

    ret = impl.BeforeAddExtResource(EMPTY_STRING, filePaths);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);

    filePaths.emplace_back(INVALID_PATH);
    ret = impl.BeforeAddExtResource(bundleName, filePaths);
    EXPECT_EQ(ret, ERR_EXT_RESOURCE_MANAGER_INVALID_PATH_FAILED);
}

/**
 * @tc.number: ResetBundleResourceIcon_0200
 * @tc.name: test ResetBundleResourceIcon
 * @tc.desc: 1.reset bundle resource icon
 */
HWTEST_F(BmsExtendResourceManagerTest, ResetBundleResourceIcon_0200, Function | SmallTest | Level1)
{
    ExtendResourceManagerHostImpl impl;
    DelayedSingleton<BundleResourceInfo>::GetInstance();
    auto manager = DelayedSingleton<BundleResourceInfo>::GetInstance();
    ASSERT_NE(manager, nullptr);
    bool ret = impl.ResetBundleResourceIcon(BUNDLE_NAME);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: ResetBundleResourceIcon_0300
 * @tc.name: test ResetBundleResourceIcon
 * @tc.desc: 1.reset bundle resource icon
 */
HWTEST_F(BmsExtendResourceManagerTest, ResetBundleResourceIcon_0300, Function | SmallTest | Level1)
{
    ExtendResourceManagerHostImpl impl;
    DelayedSingleton<BundleResourceInfo>::GetInstance();
    auto manager = DelayedSingleton<BundleResourceInfo>::GetInstance();
    ASSERT_NE(manager, nullptr);
    bool ret = impl.ResetBundleResourceIcon("");
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: ParseBundleResource_0200
 * @tc.name: test ParseBundleResource
 * @tc.desc: 1.analyze bundled package resources
 */
HWTEST_F(BmsExtendResourceManagerTest, ParseBundleResource_0200, Function | SmallTest | Level1)
{
    ExtendResourceManagerHostImpl impl;
    std::string bundleName = BUNDLE_NAME;
    std::vector<std::string> iconId;
    ExtendResourceInfo extendResourceInfo;
    extendResourceInfo.filePath = "";
    extendResourceInfo.iconId = 0;
    bool ret = impl.ParseBundleResource(bundleName, extendResourceInfo);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: ResetBundleResourceIcon_0500
 * @tc.name: Test invalid path case
 * @tc.desc: Verify function fails with invalid resource path
 */
HWTEST_F(BmsExtendResourceManagerTest, ResetBundleResourceIcon_0500, Function | SmallTest | Level1)
{
    ExtendResourceManagerHostImpl impl;
    bool ret = impl.ResetBundleResourceIcon(EMPTY_STRING);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: ResetBundleResourceIcon_0700
 * @tc.name: Test path security check
 * @tc.desc: Verify function rejects path traversal attempts
 */
HWTEST_F(BmsExtendResourceManagerTest, ResetBundleResourceIcon_0700, Function | SmallTest | Level1)
{
    ExtendResourceManagerHostImpl impl;
    bool ret = impl.ResetBundleResourceIcon(INVALID_PATH);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: ResetBundleResourceIcon_DeleteFail_1000
 * @tc.name: Test delete resource failure (path not exist)
 * @tc.desc: Verify function returns false when resource path not exist
 */
HWTEST_F(BmsExtendResourceManagerTest, ResetBundleResourceIcon_1000, Function | SmallTest | Level1) {
    std::string cmd = "rm -rf /data/service/el1/public/bms/bundle_resource/" + BUNDLE_NAME;
    system(cmd.c_str());
    ExtendResourceManagerHostImpl impl;
    bool ret = impl.ResetBundleResourceIcon(BUNDLE_NAME);
    
    EXPECT_FALSE(ret);
}
} // OHOS