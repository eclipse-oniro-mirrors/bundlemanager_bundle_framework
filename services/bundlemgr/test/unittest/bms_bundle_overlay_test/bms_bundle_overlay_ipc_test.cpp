/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include "appexecfwk_errors.h"
#define private public
#include "bundle_framework_core_ipc_interface_code.h"
#include "overlay_manager_proxy.h"
#include "overlay_manager_host.h"
#undef private
#include "bundle_overlay_manager_host_impl.h"
#include "bundle_mgr_service.h"

using namespace testing::ext;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace {
const std::string TEST_BUNDLE_NAME = "testBundleName";
const std::string TEST_MODULE_NAME = "testModuleName";
const std::string TEST_TARGET_BUNDLE_NAME = "testTargetBundleName";
const std::string TEST_TARGET_MODULE_NAME = "testTargetModuleName";
const std::string TEST_HAP_PATH = "testHapPath";
const std::string TEST_BUNDLE_DIR = "testBundleDir";
const std::u16string TEST_HOST_DESCRIPTOR = u"ohos.bundleManager.OverlayManager.test";
const int32_t TEST_PRIORITY = 50;
const int32_t TEST_STATE = 0;
const int32_t TEST_USER_ID = 100;
const int32_t TEST_CODE = 100;
const int32_t OVERLAY_INFO_SIZE = 1;
} // namespace

class OverlayManagerHostMock : public OverlayManagerHost {
public:
    OverlayManagerHostMock() = default;
    virtual ~OverlayManagerHostMock() = default;

    virtual ErrCode GetAllOverlayModuleInfo(const std::string &bundleName,
        std::vector<OverlayModuleInfo> &overlayModuleInfo, int32_t userId = Constants::UNSPECIFIED_USERID) override;
    virtual ErrCode GetOverlayModuleInfo(const std::string &bundleName, const std::string &moduleName,
        OverlayModuleInfo &overlayModuleInfo, int32_t userId = Constants::UNSPECIFIED_USERID) override;
    virtual ErrCode GetOverlayModuleInfo(const std::string &moduleName, OverlayModuleInfo &overlayModuleInfo,
        int32_t userId = Constants::UNSPECIFIED_USERID) override;
    virtual ErrCode GetTargetOverlayModuleInfo(const std::string &targetModuleName,
        std::vector<OverlayModuleInfo> &overlayModuleInfos, int32_t userId = Constants::UNSPECIFIED_USERID) override;
    virtual ErrCode GetOverlayModuleInfoByBundleName(const std::string &bundleName, const std::string &moduleName,
        std::vector<OverlayModuleInfo> &overlayModuleInfos, int32_t userId = Constants::UNSPECIFIED_USERID) override;
    virtual ErrCode GetOverlayBundleInfoForTarget(const std::string &targetBundleName,
        std::vector<OverlayBundleInfo> &overlayBundleInfo, int32_t userId = Constants::UNSPECIFIED_USERID) override;
    virtual ErrCode GetOverlayModuleInfoForTarget(const std::string &targetBundleName,
        const std::string &targetModuleName, std::vector<OverlayModuleInfo> &overlayModuleInfo,
        int32_t userId = Constants::UNSPECIFIED_USERID) override;
    virtual ErrCode SetOverlayEnabled(const std::string &bundleName, const std::string &moduleName, bool isEnabled,
        int32_t userId = Constants::UNSPECIFIED_USERID) override;
    virtual ErrCode SetOverlayEnabledForSelf(const std::string &moduleName, bool isEnabled,
        int32_t userId = Constants::UNSPECIFIED_USERID) override;

private:
    OverlayModuleInfo CreateOverlayModuleInfo();
    OverlayBundleInfo CreateOverlayBundleInfo();
};

ErrCode OverlayManagerHostMock::GetAllOverlayModuleInfo(const std::string &bundleName,
    std::vector<OverlayModuleInfo> &overlayModuleInfo, int32_t userId)
{
    OverlayModuleInfo moduleInfo = CreateOverlayModuleInfo();
    overlayModuleInfo.emplace_back(moduleInfo);
    return ERR_OK;
}

ErrCode OverlayManagerHostMock::GetOverlayModuleInfo(const std::string &bundleName, const std::string &moduleName,
    OverlayModuleInfo &overlayModuleInfo, int32_t userId)
{
    overlayModuleInfo = CreateOverlayModuleInfo();
    return ERR_OK;
}

ErrCode OverlayManagerHostMock::GetOverlayModuleInfo(const std::string &moduleName,
    OverlayModuleInfo &overlayModuleInfo, int32_t userId)
{
    overlayModuleInfo = CreateOverlayModuleInfo();
    return ERR_OK;
}

ErrCode OverlayManagerHostMock::GetTargetOverlayModuleInfo(const std::string &targetModuleName,
    std::vector<OverlayModuleInfo> &overlayModuleInfos, int32_t userId)
{
    OverlayModuleInfo moduleInfo = CreateOverlayModuleInfo();
    overlayModuleInfos.emplace_back(moduleInfo);
    return ERR_OK;
}

ErrCode OverlayManagerHostMock::GetOverlayModuleInfoByBundleName(const std::string &bundleName,
    const std::string &moduleName, std::vector<OverlayModuleInfo> &overlayModuleInfos, int32_t userId)
{
    OverlayModuleInfo moduleInfo = CreateOverlayModuleInfo();
    overlayModuleInfos.emplace_back(moduleInfo);
    return ERR_OK;
}

ErrCode OverlayManagerHostMock::GetOverlayBundleInfoForTarget(const std::string &targetBundleName,
    std::vector<OverlayBundleInfo> &overlayBundleInfo, int32_t userId)
{
    OverlayBundleInfo bundleInfo = CreateOverlayBundleInfo();
    overlayBundleInfo.emplace_back(bundleInfo);
    return ERR_OK;
}

ErrCode OverlayManagerHostMock::GetOverlayModuleInfoForTarget(const std::string &targetBundleName,
    const std::string &targetModuleName, std::vector<OverlayModuleInfo> &overlayModuleInfo, int32_t userId)
{
    OverlayModuleInfo moduleInfo = CreateOverlayModuleInfo();
    overlayModuleInfo.emplace_back(moduleInfo);
    return ERR_OK;
}

ErrCode OverlayManagerHostMock::SetOverlayEnabled(const std::string &bundleName, const std::string &moduleName,
    bool isEnabled, int32_t userId)
{
    return ERR_OK;
}

ErrCode OverlayManagerHostMock::SetOverlayEnabledForSelf(const std::string &moduleName, bool isEnabled,
    int32_t userId)
{
    return ERR_OK;
}

OverlayModuleInfo OverlayManagerHostMock::CreateOverlayModuleInfo()
{
    OverlayModuleInfo moduleInfo;
    moduleInfo.bundleName = TEST_BUNDLE_NAME;
    moduleInfo.moduleName = TEST_MODULE_NAME;
    moduleInfo.targetModuleName = TEST_TARGET_MODULE_NAME;
    moduleInfo.hapPath = TEST_HAP_PATH;
    moduleInfo.priority = TEST_PRIORITY;
    moduleInfo.state = TEST_STATE;
    return moduleInfo;
}

OverlayBundleInfo OverlayManagerHostMock::CreateOverlayBundleInfo()
{
    OverlayBundleInfo overlayBundleInfo;
    overlayBundleInfo.bundleName = TEST_BUNDLE_NAME;
    overlayBundleInfo.bundleDir = TEST_BUNDLE_DIR;
    overlayBundleInfo.state = TEST_STATE;
    overlayBundleInfo.priority = TEST_PRIORITY;
    return overlayBundleInfo;
}

class BmsBundleOverlayIpcTest : public testing::Test {
public:
    BmsBundleOverlayIpcTest();
    ~BmsBundleOverlayIpcTest();
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

    template<typename T>
    T ReadOverlayInfo(MessageParcel &reply);

    void CheckOverlayModuleInfo(const OverlayModuleInfo &overlayModuleInfo);
    void CheckOverlayBundleInfo(const OverlayBundleInfo &overlayBundleInfo);
    sptr<IOverlayManager> GetOverlayProxy() const;
    sptr<OverlayManagerHostMock> GetOverlayHost() const;

private:
    sptr<IOverlayManager> overlayProxy_ = nullptr;
    sptr<OverlayManagerHostMock> overlayHost_ = nullptr;
    static std::shared_ptr<BundleMgrService> bundleMgrService_;
};

std::shared_ptr<BundleMgrService> BmsBundleOverlayIpcTest::bundleMgrService_ =
    DelayedSingleton<BundleMgrService>::GetInstance();

BmsBundleOverlayIpcTest::BmsBundleOverlayIpcTest()
{}

BmsBundleOverlayIpcTest::~BmsBundleOverlayIpcTest()
{}

void BmsBundleOverlayIpcTest::SetUpTestCase()
{}

void BmsBundleOverlayIpcTest::TearDownTestCase()
{
    bundleMgrService_->OnStop();
}

void BmsBundleOverlayIpcTest::SetUp()
{
    overlayProxy_ = new (std::nothrow) OverlayManagerProxy(nullptr);
    overlayHost_ = new (std::nothrow) OverlayManagerHostMock();
}

void BmsBundleOverlayIpcTest::TearDown()
{}

template<typename T>
T BmsBundleOverlayIpcTest::ReadOverlayInfo(MessageParcel &reply)
{
    std::unique_ptr<T> info(reply.ReadParcelable<T>());
    EXPECT_NE(info, nullptr);
    return *info;
}

void BmsBundleOverlayIpcTest::CheckOverlayModuleInfo(const OverlayModuleInfo &overlayModuleInfo)
{
    EXPECT_EQ(overlayModuleInfo.bundleName, TEST_BUNDLE_NAME);
    EXPECT_EQ(overlayModuleInfo.moduleName, TEST_MODULE_NAME);
    EXPECT_EQ(overlayModuleInfo.hapPath, TEST_HAP_PATH);
    EXPECT_EQ(overlayModuleInfo.targetModuleName, TEST_TARGET_MODULE_NAME);
    EXPECT_EQ(overlayModuleInfo.state, TEST_STATE);
    EXPECT_EQ(overlayModuleInfo.priority, TEST_PRIORITY);
}

void BmsBundleOverlayIpcTest::CheckOverlayBundleInfo(const OverlayBundleInfo &overlayBundleInfo)
{
    EXPECT_EQ(overlayBundleInfo.bundleName, TEST_BUNDLE_NAME);
    EXPECT_EQ(overlayBundleInfo.bundleDir, TEST_BUNDLE_DIR);
    EXPECT_EQ(overlayBundleInfo.state, TEST_STATE);
    EXPECT_EQ(overlayBundleInfo.priority, TEST_PRIORITY);
}

sptr<IOverlayManager> BmsBundleOverlayIpcTest::GetOverlayProxy() const
{
    return overlayProxy_;
}

sptr<OverlayManagerHostMock> BmsBundleOverlayIpcTest::GetOverlayHost() const
{
    return overlayHost_;
}

/**
 * @tc.number: OverlayIpcTest_0100
 * @tc.name: test GetAllOverlayModuleInfo interface in OverlayManagerProxy.
 * @tc.desc: 1.construct OverlayManagerProxy instance.
 *           2.calling GetAllOverlayModuleInfo interface by using OverlayManagerProxy instance.
 * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayIpcTest, OverlayIpcTest_0100, Function | SmallTest | Level0)
{
    auto overlayProxy = GetOverlayProxy();
    EXPECT_NE(overlayProxy, nullptr);

    std::vector<OverlayModuleInfo> overlayModuleInfos;
    auto errCode = overlayProxy->GetAllOverlayModuleInfo(TEST_BUNDLE_NAME, overlayModuleInfos, TEST_USER_ID);
    EXPECT_EQ(errCode, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.number: OverlayIpcTest_0200
 * @tc.name: test GetOverlayModuleInfo interface in OverlayManagerProxy.
 * @tc.desc: 1.construct OverlayManagerProxy instance.
 *           2.calling GetOverlayModuleInfo interface by using OverlayManagerProxy instance.
 * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayIpcTest, OverlayIpcTest_0200, Function | SmallTest | Level0)
{
    auto overlayProxy = GetOverlayProxy();
    EXPECT_NE(overlayProxy, nullptr);

    OverlayModuleInfo overlayModuleInfo;
    auto errCode = overlayProxy->GetOverlayModuleInfo(TEST_BUNDLE_NAME, TEST_MODULE_NAME, overlayModuleInfo,
        TEST_USER_ID);
    EXPECT_EQ(errCode, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.number: OverlayIpcTest_0300
 * @tc.name: test GetOverlayBundleInfoForTarget interface in OverlayManagerProxy.
 * @tc.desc: 1.construct OverlayManagerProxy instance.
 *           2.calling GetOverlayBundleInfoForTarget interface by using OverlayManagerProxy instance.
 * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayIpcTest, OverlayIpcTest_0300, Function | SmallTest | Level0)
{
    auto overlayProxy = GetOverlayProxy();
    EXPECT_NE(overlayProxy, nullptr);

    std::vector<OverlayBundleInfo> overlayBundleInfos;
    auto errCode = overlayProxy->GetOverlayBundleInfoForTarget(TEST_TARGET_BUNDLE_NAME, overlayBundleInfos,
        TEST_USER_ID);
    EXPECT_EQ(errCode, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.number: OverlayIpcTest_0400
 * @tc.name: test GetOverlayModuleInfoForTarget interface in OverlayManagerProxy.
 * @tc.desc: 1.construct OverlayManagerProxy instance.
 *           2.calling GetOverlayModuleInfoForTarget interface by using OverlayManagerProxy instance.
 * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayIpcTest, OverlayIpcTest_0400, Function | SmallTest | Level0)
{
    auto overlayProxy = GetOverlayProxy();
    EXPECT_NE(overlayProxy, nullptr);

    std::vector<OverlayModuleInfo> overlayModuleInfos;
    auto errCode = overlayProxy->GetOverlayModuleInfoForTarget(TEST_TARGET_BUNDLE_NAME, TEST_TARGET_MODULE_NAME,
        overlayModuleInfos, TEST_USER_ID);
    EXPECT_EQ(errCode, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.number: OverlayIpcTest_0500
 * @tc.name: test GetAllOverlayModuleInfo interface in OverlayManagerProxy.
 * @tc.desc: 1.construct OverlayManagerProxy instance.
 *           2.calling GetAllOverlayModuleInfo interface by using OverlayManagerProxy instance.
 *           3.bundleName is empty.
 *           4.return failed.
 * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayIpcTest, OverlayIpcTest_0500, Function | SmallTest | Level0)
{
    auto overlayProxy = GetOverlayProxy();
    EXPECT_NE(overlayProxy, nullptr);

    std::vector<OverlayModuleInfo> overlayModuleInfos;
    auto errCode = overlayProxy->GetAllOverlayModuleInfo("", overlayModuleInfos, TEST_USER_ID);
    EXPECT_EQ(errCode, ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_PARAM_ERROR);
}

/**
 * @tc.number: OverlayIpcTest_0600
 * @tc.name: test GetOverlayModuleInfo interface in OverlayManagerProxy.
 * @tc.desc: 1.construct OverlayManagerProxy instance.
 *           2.calling GetOverlayModuleInfo interface by using OverlayManagerProxy instance.
 *           3.bundleName is empty.
 *           4.return failed.
 * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayIpcTest, OverlayIpcTest_0600, Function | SmallTest | Level0)
{
    auto overlayProxy = GetOverlayProxy();
    EXPECT_NE(overlayProxy, nullptr);

    OverlayModuleInfo overlayModuleInfo;
    auto errCode = overlayProxy->GetOverlayModuleInfo("", TEST_MODULE_NAME, overlayModuleInfo, TEST_USER_ID);
    EXPECT_EQ(errCode, ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_PARAM_ERROR);
}

/**
 * @tc.number: OverlayIpcTest_0700
 * @tc.name: test GetOverlayModuleInfo interface in OverlayManagerProxy.
 * @tc.desc: 1.construct OverlayManagerProxy instance.
 *           2.calling GetOverlayModuleInfo interface by using OverlayManagerProxy instance.
 *           3.moduleName is empty.
 *           4.return failed.
 * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayIpcTest, OverlayIpcTest_0700, Function | SmallTest | Level0)
{
    auto overlayProxy = GetOverlayProxy();
    EXPECT_NE(overlayProxy, nullptr);

    OverlayModuleInfo overlayModuleInfo;
    auto errCode = overlayProxy->GetOverlayModuleInfo(TEST_BUNDLE_NAME, "", overlayModuleInfo, TEST_USER_ID);
    EXPECT_EQ(errCode, ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_PARAM_ERROR);
}

/**
 * @tc.number: OverlayIpcTest_0800
 * @tc.name: test GetOverlayBundleInfoForTarget interface in OverlayManagerProxy.
 * @tc.desc: 1.construct OverlayManagerProxy instance.
 *           2.calling GetOverlayBundleInfoForTarget interface by using OverlayManagerProxy instance.
 *           3.moduleName is empty.
 *           4.return failed.
 * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayIpcTest, OverlayIpcTest_0800, Function | SmallTest | Level0)
{
    auto overlayProxy = GetOverlayProxy();
    EXPECT_NE(overlayProxy, nullptr);

    std::vector<OverlayBundleInfo> overlayBundleInfos;
    auto errCode = overlayProxy->GetOverlayBundleInfoForTarget("", overlayBundleInfos, TEST_USER_ID);
    EXPECT_EQ(errCode, ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_PARAM_ERROR);
}

/**
 * @tc.number: OverlayIpcTest_0900
 * @tc.name: test GetOverlayModuleInfoForTarget interface in OverlayManagerProxy.
 * @tc.desc: 1.construct OverlayManagerProxy instance.
 *           2.calling GetOverlayModuleInfoForTarget interface by using OverlayManagerProxy instance.
 *           3.target bundleName is empty.
 *           4.return failed.
 * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayIpcTest, OverlayIpcTest_0900, Function | SmallTest | Level0)
{
    auto overlayProxy = GetOverlayProxy();
    EXPECT_NE(overlayProxy, nullptr);

    std::vector<OverlayModuleInfo> overlayModuleInfos;
    auto errCode = overlayProxy->GetOverlayModuleInfoForTarget("", TEST_TARGET_MODULE_NAME, overlayModuleInfos,
        TEST_USER_ID);
    EXPECT_EQ(errCode, ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_PARAM_ERROR);
}

/**
 * @tc.number: OverlayIpcTest_1000
 * @tc.name: test GetOverlayModuleInfoForTarget interface in OverlayManagerProxy.
 * @tc.desc: 1.construct OverlayManagerProxy instance.
 *           2.calling GetOverlayModuleInfoForTarget interface by using OverlayManagerProxy instance.
 *           3.target moduleName is empty.
 *           4.return failed.
 * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayIpcTest, OverlayIpcTest_1000, Function | SmallTest | Level0)
{
    auto overlayProxy = GetOverlayProxy();
    EXPECT_NE(overlayProxy, nullptr);

    std::vector<OverlayModuleInfo> overlayModuleInfos;
    auto errCode = overlayProxy->GetOverlayModuleInfoForTarget(TEST_TARGET_BUNDLE_NAME, "", overlayModuleInfos,
        TEST_USER_ID);
    EXPECT_EQ(errCode, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.number: OverlayIpcTest_1100
 * @tc.name: test HandleGetAllOverlayModuleInfo interface in OverlayManagerHost.
 * @tc.desc: 1.construct OverlayManagerHost instance.
 *           2.calling HandleGetAllOverlayModuleInfo interface by using OverlayManagerHost instance.
 *           4.return ERR_OK.
 * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayIpcTest, OverlayIpcTest_1100, Function | SmallTest | Level0)
{
    auto overlayHost = GetOverlayHost();
    EXPECT_NE(overlayHost, nullptr);

    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(OverlayManagerHost::GetDescriptor());
    auto ret = overlayHost->OnRemoteRequest(
        static_cast<uint32_t>(OverlayManagerInterfaceCode::GET_ALL_OVERLAY_MODULE_INFO), data, reply, option);
    EXPECT_EQ(ret, ERR_OK);

    ret = reply.ReadInt32();
    EXPECT_EQ(ret, ERR_OK);
    auto size = reply.ReadInt32();
    EXPECT_EQ(size, OVERLAY_INFO_SIZE);
    OverlayModuleInfo overlayModuleInfo = ReadOverlayInfo<OverlayModuleInfo>(reply);
    CheckOverlayModuleInfo(overlayModuleInfo);
}

/**
 * @tc.number: OverlayIpcTest_1200
 * @tc.name: test HandleGetOverlayModuleInfo interface in OverlayManagerHost.
 * @tc.desc: 1.construct OverlayManagerHost instance.
 *           2.calling HandleGetOverlayModuleInfo interface by using OverlayManagerHost instance.
 *           4.return ERR_OK.
 * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayIpcTest, OverlayIpcTest_1200, Function | SmallTest | Level0)
{
    auto overlayHost = GetOverlayHost();
    EXPECT_NE(overlayHost, nullptr);

    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(OverlayManagerHost::GetDescriptor());
    auto ret = overlayHost->OnRemoteRequest(
        static_cast<uint32_t>(OverlayManagerInterfaceCode::GET_OVERLAY_MODULE_INFO), data, reply, option);
    EXPECT_EQ(ret, ERR_OK);

    ret = reply.ReadInt32();
    EXPECT_EQ(ret, ERR_OK);
    OverlayModuleInfo overlayModuleInfo = ReadOverlayInfo<OverlayModuleInfo>(reply);
    CheckOverlayModuleInfo(overlayModuleInfo);
}

/**
 * @tc.number: OverlayIpcTest_1300
 * @tc.name: test HandleGetOverlayBundleInfoForTarget interface in OverlayManagerHost.
 * @tc.desc: 1.construct OverlayManagerHost instance.
 *           2.calling HandleGetOverlayBundleInfoForTarget interface by using OverlayManagerHost instance.
 *           4.return ERR_OK.
 * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayIpcTest, OverlayIpcTest_1300, Function | SmallTest | Level0)
{
    auto overlayHost = GetOverlayHost();
    EXPECT_NE(overlayHost, nullptr);

    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(OverlayManagerHost::GetDescriptor());
    auto ret = overlayHost->OnRemoteRequest(
        static_cast<uint32_t>(OverlayManagerInterfaceCode::GET_OVERLAY_BUNDLE_INFO_FOR_TARGET), data, reply, option);
    EXPECT_EQ(ret, ERR_OK);

    ret = reply.ReadInt32();
    EXPECT_EQ(ret, ERR_OK);
    auto size = reply.ReadInt32();
    EXPECT_EQ(size, OVERLAY_INFO_SIZE);
    OverlayBundleInfo overlayBundleInfo = ReadOverlayInfo<OverlayBundleInfo>(reply);
    CheckOverlayBundleInfo(overlayBundleInfo);
}

/**
 * @tc.number: OverlayIpcTest_1400
 * @tc.name: test HandleGetOverlayModuleInfoForTarget interface in OverlayManagerHost.
 * @tc.desc: 1.construct OverlayManagerHost instance.
 *           2.calling HandleGetOverlayModuleInfoForTarget interface by using OverlayManagerHost instance.
 *           4.return ERR_OK.
 * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayIpcTest, OverlayIpcTest_1400, Function | SmallTest | Level0)
{
    auto overlayHost = GetOverlayHost();
    EXPECT_NE(overlayHost, nullptr);

    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(OverlayManagerHost::GetDescriptor());
    auto ret = overlayHost->OnRemoteRequest(
        static_cast<uint32_t>(OverlayManagerInterfaceCode::GET_OVERLAY_MODULE_INFO_FOR_TARGET), data, reply, option);
    EXPECT_EQ(ret, ERR_OK);

    ret = reply.ReadInt32();
    EXPECT_EQ(ret, ERR_OK);
    auto size = reply.ReadInt32();
    EXPECT_EQ(size, OVERLAY_INFO_SIZE);
    OverlayModuleInfo overlayModuleInfo = ReadOverlayInfo<OverlayModuleInfo>(reply);
    CheckOverlayModuleInfo(overlayModuleInfo);
}

/**
 * @tc.number: OverlayIpcTest_1500
 * @tc.name: test OnRemoteRequest interface in OverlayManagerHost.
 * @tc.desc: 1.construct OverlayManagerHost instance.
 *           2.calling OnRemoteRequest interface by using OverlayManagerHost instance.
 *           3.error descriptor.
 *           4.return failed.
 * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayIpcTest, OverlayIpcTest_1500, Function | SmallTest | Level0)
{
    auto overlayHost = GetOverlayHost();
    EXPECT_NE(overlayHost, nullptr);

    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(TEST_HOST_DESCRIPTOR);
    auto ret = overlayHost->OnRemoteRequest(
        static_cast<uint32_t>(OverlayManagerInterfaceCode::GET_OVERLAY_MODULE_INFO_FOR_TARGET), data, reply, option);
    EXPECT_EQ(ret, OBJECT_NULL);
}

/**
 * @tc.number: OverlayIpcTest_1600
 * @tc.name: test OnRemoteRequest interface in OverlayManagerHost.
 * @tc.desc: 1.construct OverlayManagerHost instance.
 *           2.calling OnRemoteRequest interface by using OverlayManagerHost instance.
 *           3.error code.
 *           4.return failed.
 * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayIpcTest, OverlayIpcTest_1600, Function | SmallTest | Level0)
{
    auto overlayHost = GetOverlayHost();
    EXPECT_NE(overlayHost, nullptr);

    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(OverlayManagerHost::GetDescriptor());
    auto ret = overlayHost->OnRemoteRequest(TEST_CODE, data, reply, option);
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.number: OverlayIpcTest_1700
 * @tc.name: test SetOverlayEnabled interface in OverlayManagerProxy.
 * @tc.desc: 1.construct OverlayManagerProxy instance.
 *           2.calling SetOverlayEnabled interface by using OverlayManagerProxy instance.
 * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayIpcTest, OverlayIpcTest_1700, Function | SmallTest | Level0)
{
    auto overlayProxy = GetOverlayProxy();
    EXPECT_NE(overlayProxy, nullptr);

    auto errCode = overlayProxy->SetOverlayEnabled(TEST_TARGET_BUNDLE_NAME, TEST_TARGET_MODULE_NAME,
        true, TEST_USER_ID);
    EXPECT_EQ(errCode, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.number: OverlayIpcTest_1800
 * @tc.name: test SetOverlayEnabled interface in OverlayManagerProxy.
 * @tc.desc: 1.construct OverlayManagerProxy instance.
 *           2.calling SetOverlayEnabled interface by using OverlayManagerProxy instance.
 * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayIpcTest, OverlayIpcTest_1800, Function | SmallTest | Level0)
{
    auto overlayProxy = GetOverlayProxy();
    EXPECT_NE(overlayProxy, nullptr);

    auto errCode = overlayProxy->SetOverlayEnabled(TEST_TARGET_BUNDLE_NAME, TEST_TARGET_MODULE_NAME,
        false, TEST_USER_ID);
    EXPECT_EQ(errCode, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.number: OverlayIpcTest_1900
 * @tc.name: test SetOverlayEnabled interface in OverlayManagerProxy.
 * @tc.desc: 1.construct OverlayManagerProxy instance.
 *           2.calling SetOverlayEnabled interface by using OverlayManagerProxy instance.
 *           3.bundleName is empty and set failed
 * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayIpcTest, OverlayIpcTest_1900, Function | SmallTest | Level0)
{
    auto overlayProxy = GetOverlayProxy();
    EXPECT_NE(overlayProxy, nullptr);

    auto errCode = overlayProxy->SetOverlayEnabled("", TEST_TARGET_MODULE_NAME,
        true, TEST_USER_ID);
    EXPECT_EQ(errCode, ERR_BUNDLEMANAGER_OVERLAY_SET_OVERLAY_PARAM_ERROR);
}

/**
 * @tc.number: OverlayIpcTest_2000
 * @tc.name: test SetOverlayEnabled interface in OverlayManagerProxy.
 * @tc.desc: 1.construct OverlayManagerProxy instance.
 *           2.calling SetOverlayEnabled interface by using OverlayManagerProxy instance.
 *           3.bundleName is empty and set failed
 * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayIpcTest, OverlayIpcTest_2000, Function | SmallTest | Level0)
{
    auto overlayProxy = GetOverlayProxy();
    EXPECT_NE(overlayProxy, nullptr);

    auto errCode = overlayProxy->SetOverlayEnabled(TEST_TARGET_BUNDLE_NAME, "",
        true, TEST_USER_ID);
    EXPECT_EQ(errCode, ERR_BUNDLEMANAGER_OVERLAY_SET_OVERLAY_PARAM_ERROR);
}

/**
 * @tc.number: OverlayIpcTest_2200
 * @tc.name: test HandleSetOverlayEnabled interface in OverlayManagerHost.
 * @tc.desc: 1.construct OverlayManagerHost instance.
 *           2.calling HandleSetOverlayEnabled interface by using OverlayManagerHost instance.
 *           4.return ERR_OK.
 * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayIpcTest, OverlayIpcTest_2200, Function | SmallTest | Level0)
{
    auto overlayHost = GetOverlayHost();
    EXPECT_NE(overlayHost, nullptr);

    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(OverlayManagerHost::GetDescriptor());
    auto ret = overlayHost->OnRemoteRequest(
        static_cast<uint32_t>(OverlayManagerInterfaceCode::SET_OVERLAY_ENABLED), data, reply, option);
    EXPECT_EQ(ret, ERR_OK);
    ret = reply.ReadInt32();
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: OverlayIpcTest_2400
 * @tc.name: test GetAllOverlayModuleInfo interface in OverlayManagerHostImpl.
 * @tc.desc: 1.construct OverlayManagerHostImpl instance.
 *           2.calling GetAllOverlayModuleInfo interface by using OverlayManagerHostImpl instance.
 *           4.get failed.
 * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayIpcTest, OverlayIpcTest_2400, Function | SmallTest | Level0)
{
    auto hostImpl = std::make_shared<OverlayManagerHostImpl>();
    EXPECT_NE(hostImpl, nullptr);

    std::vector<OverlayModuleInfo> vec;
    auto res = hostImpl->GetAllOverlayModuleInfo(TEST_BUNDLE_NAME, vec);
    EXPECT_EQ(res, ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_PERMISSION_DENIED);
}

/**
 * @tc.number: OverlayIpcTest_2500
 * @tc.name: test GetOverlayModuleInfo interface in OverlayManagerHostImpl.
 * @tc.desc: 1.construct OverlayManagerHostImpl instance.
 *           2.calling GetOverlayModuleInfo interface by using OverlayManagerHostImpl instance.
 *           4.get failed.
 * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayIpcTest, OverlayIpcTest_2500, Function | SmallTest | Level0)
{
    auto hostImpl = std::make_shared<OverlayManagerHostImpl>();
    EXPECT_NE(hostImpl, nullptr);

    OverlayModuleInfo info;
    auto res = hostImpl->GetOverlayModuleInfo(TEST_BUNDLE_NAME, TEST_MODULE_NAME, info);
    EXPECT_EQ(res, ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_PERMISSION_DENIED);
}

/**
 * @tc.number: OverlayIpcTest_2600
 * @tc.name: test GetOverlayBundleInfoForTarget interface in OverlayManagerHostImpl.
 * @tc.desc: 1.construct OverlayManagerHostImpl instance.
 *           2.calling GetOverlayBundleInfoForTarget interface by using OverlayManagerHostImpl instance.
 *           4.get failed.
 * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayIpcTest, OverlayIpcTest_2600, Function | SmallTest | Level0)
{
    auto hostImpl = std::make_shared<OverlayManagerHostImpl>();
    EXPECT_NE(hostImpl, nullptr);

    std::vector<OverlayBundleInfo> vec;
    auto res = hostImpl->GetOverlayBundleInfoForTarget(TEST_TARGET_BUNDLE_NAME, vec);
    EXPECT_EQ(res, ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_PERMISSION_DENIED);
}

/**
 * @tc.number: OverlayIpcTest_2700
 * @tc.name: test GetOverlayModuleInfoForTarget interface in OverlayManagerHostImpl.
 * @tc.desc: 1.construct OverlayManagerHostImpl instance.
 *           2.calling GetOverlayModuleInfoForTarget interface by using OverlayManagerHostImpl instance.
 *           4.get failed.
 * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayIpcTest, OverlayIpcTest_2700, Function | SmallTest | Level0)
{
    auto hostImpl = std::make_shared<OverlayManagerHostImpl>();
    EXPECT_NE(hostImpl, nullptr);

    std::vector<OverlayModuleInfo> vec;
    auto res = hostImpl->GetOverlayModuleInfoForTarget(TEST_TARGET_BUNDLE_NAME, TEST_TARGET_MODULE_NAME, vec);
    EXPECT_EQ(res, ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_PERMISSION_DENIED);
}

/**
 * @tc.number: OverlayIpcTest_2800
 * @tc.name: test SetOverlayEnabled interface in OverlayManagerHostImpl.
 * @tc.desc: 1.construct OverlayManagerHostImpl instance.
 *           2.calling SetOverlayEnabled interface by using OverlayManagerHostImpl instance.
 *           4.set failed.
 * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayIpcTest, OverlayIpcTest_2800, Function | SmallTest | Level0)
{
    auto hostImpl = std::make_shared<OverlayManagerHostImpl>();
    EXPECT_NE(hostImpl, nullptr);

    auto res = hostImpl->SetOverlayEnabled(TEST_BUNDLE_NAME, TEST_MODULE_NAME, true);
    EXPECT_EQ(res, ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_PERMISSION_DENIED);
}

/**
 * @tc.number: OverlayIpcTest_2900
 * @tc.name: test SetOverlayEnabled interface in OverlayManagerHostImpl.
 * @tc.desc: 1.construct OverlayManagerHostImpl instance.
 *           2.calling SetOverlayEnabled interface by using OverlayManagerHostImpl instance.
 *           4.set failed.
 * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayIpcTest, OverlayIpcTest_2900, Function | SmallTest | Level0)
{
    auto hostImpl = std::make_shared<OverlayManagerHostImpl>();
    EXPECT_NE(hostImpl, nullptr);

    auto res = hostImpl->SetOverlayEnabled(TEST_BUNDLE_NAME, TEST_MODULE_NAME, false);
    EXPECT_EQ(res, ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_PERMISSION_DENIED);
}

/**
 * @tc.number: OverlayIpcTest_3000
 * @tc.name: test HandleGetOverlayModuleInfoByName interface in OverlayManagerHost.
 * @tc.desc: 1.construct OverlayManagerHost instance.
 *           2.calling HandleGetOverlayModuleInfoByName interface by using OverlayManagerHost instance.
 *           4.return ERR_OK.
 * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayIpcTest, OverlayIpcTest_3000, Function | SmallTest | Level0)
{
    auto overlayHost = GetOverlayHost();
    EXPECT_NE(overlayHost, nullptr);

    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(OverlayManagerHost::GetDescriptor());
    auto ret = overlayHost->OnRemoteRequest(
        static_cast<uint32_t>(OverlayManagerInterfaceCode::GET_OVERLAY_MODULE_INFO_BY_NAME), data, reply, option);
    EXPECT_EQ(ret, ERR_OK);

    ret = reply.ReadInt32();
    EXPECT_EQ(ret, ERR_OK);
    OverlayModuleInfo overlayModuleInfo = ReadOverlayInfo<OverlayModuleInfo>(reply);
    CheckOverlayModuleInfo(overlayModuleInfo);
}

/**
 * @tc.number: OverlayIpcTest_3100
 * @tc.name: test HandleGetOverlayModuleInfoByName interface in OverlayManagerHost.
 * @tc.desc: 1.construct OverlayManagerHost instance.
 *           2.calling HandleGetOverlayModuleInfoByName interface by using OverlayManagerHost instance.
 *           4.return ERR_OK.
 * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayIpcTest, OverlayIpcTest_3100, Function | SmallTest | Level0)
{
    auto overlayHost = GetOverlayHost();
    EXPECT_NE(overlayHost, nullptr);

    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(OverlayManagerHost::GetDescriptor());
    auto ret = overlayHost->OnRemoteRequest(
        static_cast<uint32_t>(OverlayManagerInterfaceCode::GET_TARGET_OVERLAY_MODULE_INFOS), data, reply, option);
    EXPECT_EQ(ret, ERR_OK);

    ret = reply.ReadInt32();
    EXPECT_EQ(ret, ERR_OK);
    auto size = reply.ReadInt32();
    EXPECT_EQ(size, OVERLAY_INFO_SIZE);
    OverlayModuleInfo overlayModuleInfo = ReadOverlayInfo<OverlayModuleInfo>(reply);
    CheckOverlayModuleInfo(overlayModuleInfo);
}

/**
 * @tc.number: OverlayIpcTest_3200
 * @tc.name: test HandleGetOverlayModuleInfoByBundleName interface in OverlayManagerHost.
 * @tc.desc: 1.construct OverlayManagerHost instance.
 *           2.calling HandleGetOverlayModuleInfoByBundleName interface by using OverlayManagerHost instance.
 *           4.return ERR_OK.
 * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayIpcTest, OverlayIpcTest_3200, Function | SmallTest | Level0)
{
    auto overlayHost = GetOverlayHost();
    EXPECT_NE(overlayHost, nullptr);

    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(OverlayManagerHost::GetDescriptor());
    auto ret = overlayHost->OnRemoteRequest(
        static_cast<uint32_t>(OverlayManagerInterfaceCode::GET_OVERLAY_MODULE_INFO_BY_BUNDLE_NAME),
        data, reply, option);
    EXPECT_EQ(ret, ERR_OK);

    ret = reply.ReadInt32();
    EXPECT_EQ(ret, ERR_OK);
    auto size = reply.ReadInt32();
    EXPECT_EQ(size, OVERLAY_INFO_SIZE);
    OverlayModuleInfo overlayModuleInfo = ReadOverlayInfo<OverlayModuleInfo>(reply);
    CheckOverlayModuleInfo(overlayModuleInfo);
}

/**
 * @tc.number: OverlayIpcTest_3300
 * @tc.name: test HandleSetOverlayEnabled interface in OverlayManagerHost.
 * @tc.desc: 1.construct OverlayManagerHost instance.
 *           2.calling HandleSetOverlayEnabled interface by using OverlayManagerHost instance.
 *           4.return ERR_OK.
 * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayIpcTest, OverlayIpcTest_3300, Function | SmallTest | Level0)
{
    auto overlayHost = GetOverlayHost();
    EXPECT_NE(overlayHost, nullptr);

    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(OverlayManagerHost::GetDescriptor());
    auto ret = overlayHost->OnRemoteRequest(
        static_cast<uint32_t>(OverlayManagerInterfaceCode::SET_OVERLAY_ENABLED_FOR_SELF), data, reply, option);
    EXPECT_EQ(ret, ERR_OK);
    ret = reply.ReadInt32();
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: OverlayIpcTest_2000
 * @tc.name: test SetOverlayEnabled interface in OverlayManagerProxy.
 * @tc.desc: 1.construct OverlayManagerProxy instance.
 *           2.calling SetOverlayEnabled interface by using OverlayManagerProxy instance.
 *           3.bundleName is empty and set failed
 * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayIpcTest, OverlayIpcTest_3400, Function | SmallTest | Level0)
{
    auto overlayProxy = GetOverlayProxy();
    EXPECT_NE(overlayProxy, nullptr);

    std::vector<OverlayModuleInfo> overlayModuleInfos;
    auto errCode = overlayProxy->GetTargetOverlayModuleInfo("", overlayModuleInfos,
        TEST_USER_ID);
    EXPECT_EQ(errCode, ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_PARAM_ERROR);

    errCode = overlayProxy->GetTargetOverlayModuleInfo(TEST_TARGET_BUNDLE_NAME, overlayModuleInfos,
        TEST_USER_ID);
    EXPECT_EQ(errCode, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.number: OverlayIpcTest_2000
 * @tc.name: test SetOverlayEnabled interface in OverlayManagerProxy.
 * @tc.desc: 1.construct GetOverlayModuleInfoByBundleName instance.
 *           2.calling SetOverlayEnabled interface by using GetOverlayModuleInfoByBundleName instance.
 *           3.bundleName is empty and set failed
 * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayIpcTest, OverlayIpcTest_3500, Function | SmallTest | Level0)
{
    auto overlayProxy = GetOverlayProxy();
    EXPECT_NE(overlayProxy, nullptr);

    std::vector<OverlayModuleInfo> overlayModuleInfos;
    auto errCode = overlayProxy->GetOverlayModuleInfoByBundleName("", TEST_MODULE_NAME,
        overlayModuleInfos, TEST_USER_ID);
    EXPECT_EQ(errCode, ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_PARAM_ERROR);

    errCode = overlayProxy->GetOverlayModuleInfoByBundleName(TEST_BUNDLE_NAME, TEST_MODULE_NAME,
        overlayModuleInfos, TEST_USER_ID);
    EXPECT_EQ(errCode, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.number: OverlayIpcTest_2000
 * @tc.name: test SetOverlayEnabledForSelf interface in OverlayManagerProxy.
 * @tc.desc: 1.construct SetOverlayEnabledForSelf instance.
 *           2.calling SetOverlayEnabled interface by using SetOverlayEnabledForSelf instance.
 *           3.bundleName is empty and set failed
 * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayIpcTest, OverlayIpcTest_3600, Function | SmallTest | Level0)
{
    auto overlayProxy = GetOverlayProxy();
    EXPECT_NE(overlayProxy, nullptr);

    bool isEnabled = false;
    auto errCode = overlayProxy->SetOverlayEnabledForSelf("",
        isEnabled, TEST_USER_ID);
    EXPECT_EQ(errCode, ERR_BUNDLEMANAGER_OVERLAY_SET_OVERLAY_PARAM_ERROR);

    errCode = overlayProxy->SetOverlayEnabledForSelf(TEST_MODULE_NAME,
        isEnabled, TEST_USER_ID);
    EXPECT_EQ(errCode, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.number: OverlayIpcTest_3700
 * @tc.name: GetOverlayModuleInfo by OverlayManagerProxy
 * @tc.desc: test GetOverlayModuleInfo
 */
HWTEST_F(BmsBundleOverlayIpcTest, OverlayIpcTest_3700, Function | SmallTest | Level0)
{
    auto overlayProxy = GetOverlayProxy();
    ASSERT_NE(overlayProxy, nullptr);
    OverlayModuleInfo info;
    auto errCode = overlayProxy->GetOverlayModuleInfo(TEST_BUNDLE_NAME, TEST_MODULE_NAME, info, TEST_USER_ID);
    EXPECT_EQ(errCode, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.number: OverlayIpcTest_3800
 * @tc.name: test GetOverlayModuleInfo interface in OverlayManagerProxy.
 * @tc.desc: 1.construct OverlayManagerProxy instance.
 *           2.calling GetOverlayModuleInfo interface by using OverlayManagerProxy instance.
 *           3.moduleName is empty.
 *           4.return failed.
 * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayIpcTest, OverlayIpcTest_3800, Function | SmallTest | Level0)
{
    auto overlayProxy = GetOverlayProxy();
    ASSERT_NE(overlayProxy, nullptr);

    OverlayModuleInfo overlayModuleInfo;
    auto errCode = overlayProxy->GetOverlayModuleInfo("", overlayModuleInfo, TEST_USER_ID);
    EXPECT_EQ(errCode, ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_PARAM_ERROR);
}

/**
 * @tc.number: OverlayIpcTest_0390
 * @tc.name: test GetOverlayModuleInfo interface in OverlayManagerProxy.
 * @tc.desc: 1.construct OverlayManagerProxy instance.
 *           2.calling GetOverlayModuleInfo interface by using OverlayManagerProxy instance.
 * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayIpcTest, OverlayIpcTest_0390, Function | SmallTest | Level0)
{
    auto overlayProxy = GetOverlayProxy();
    ASSERT_NE(overlayProxy, nullptr);

    OverlayModuleInfo overlayModuleInfo;
    auto errCode = overlayProxy->GetOverlayModuleInfo(TEST_MODULE_NAME, overlayModuleInfo, TEST_USER_ID);
    EXPECT_EQ(errCode, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.number: OverlayIpcTest_4000
 * @tc.name: test GetOverlayModuleInfo interface in OverlayManagerProxy.
 * @tc.desc: 1.construct OverlayManagerProxy instance.
 *           2.calling GetOverlayModuleInfo interface by using OverlayManagerProxy instance.
 * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayIpcTest, OverlayIpcTest_4000, Function | SmallTest | Level0)
{
    auto overlayProxy = GetOverlayProxy();
    ASSERT_NE(overlayProxy, nullptr);
    MessageParcel reply;
    bool isEnabled = false;
    auto errCode = overlayProxy->SetOverlayEnabledForSelf("", isEnabled, TEST_USER_ID);
    EXPECT_EQ(errCode, ERR_BUNDLEMANAGER_OVERLAY_SET_OVERLAY_PARAM_ERROR);

    std::string moduleName = TEST_MODULE_NAME;
    errCode = overlayProxy->SetOverlayEnabledForSelf(moduleName, isEnabled, TEST_USER_ID);
    EXPECT_EQ(errCode, ERR_APPEXECFWK_PARCEL_ERROR);
    auto res = reply.ReadInt32();
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: OverlayIpcTest_4010
 * @tc.name: test GetOverlayModuleInfo interface in OverlayManagerProxy.
 * @tc.desc: 1.construct OverlayManagerProxy instance.
 *           2.calling GetOverlayModuleInfo interface by using OverlayManagerProxy instance.
 * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayIpcTest, OverlayIpcTest_4010, Function | SmallTest | Level0)
{
    auto overlayProxy = GetOverlayProxy();
    ASSERT_NE(overlayProxy, nullptr);
    bool isEnabled = false;
    MessageParcel reply;
    auto errCode = overlayProxy->SetOverlayEnabled("", TEST_TARGET_BUNDLE_NAME, isEnabled, TEST_USER_ID);
    EXPECT_EQ(errCode, ERR_BUNDLEMANAGER_OVERLAY_SET_OVERLAY_PARAM_ERROR);

    std::string moduleName = TEST_TARGET_MODULE_NAME;
    std::string bundleName = TEST_TARGET_BUNDLE_NAME;
    errCode = overlayProxy->SetOverlayEnabled(bundleName, moduleName, isEnabled, TEST_USER_ID);
    EXPECT_EQ(errCode, ERR_APPEXECFWK_PARCEL_ERROR);
    auto res = reply.ReadInt32();
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: OverlayIpcTest_4020
 * @tc.name: test GetOverlayModuleInfo interface in OverlayManagerProxy.
 * @tc.desc: 1.construct OverlayManagerProxy instance.
 *           2.calling GetOverlayModuleInfo interface by using OverlayManagerProxy instance.
 * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleOverlayIpcTest, OverlayIpcTest_4020, Function | SmallTest | Level0)
{
    auto overlayProxy = GetOverlayProxy();
    ASSERT_NE(overlayProxy, nullptr);
    bool isEnabled = false;
    MessageParcel reply;
    auto errCode = overlayProxy->SetOverlayEnabled("", TEST_TARGET_BUNDLE_NAME, isEnabled, TEST_USER_ID);
    EXPECT_EQ(errCode, ERR_BUNDLEMANAGER_OVERLAY_SET_OVERLAY_PARAM_ERROR);

    std::string bundleName = TEST_TARGET_BUNDLE_NAME;
    std::string moduleName = TEST_TARGET_MODULE_NAME;
    errCode = overlayProxy->SetOverlayEnabled(bundleName, moduleName, isEnabled, TEST_USER_ID);
    EXPECT_EQ(errCode, ERR_APPEXECFWK_PARCEL_ERROR);
    auto res = reply.ReadInt32();
    EXPECT_EQ(res, ERR_OK);
}
} // OHOS
