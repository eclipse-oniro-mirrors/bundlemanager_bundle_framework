/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include "bundle_framework_core_ipc_interface_code.h"
#include "bundle_mgr_host_impl.h"
#include "bundle_mgr_proxy.h"
#include "bundle_mgr_service.h"

using namespace testing::ext;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace {
const std::u16string TEST_HOST_DESCRIPTOR = u"ohos.bundleManager.test";
const int32_t WAIT_TIME = 5; // init mocked bms
} // namespace
class BundleMgrHostImplMock : public BundleMgrHostImpl {
public:
    BundleMgrHostImplMock() = default;
    virtual ~BundleMgrHostImplMock() = default;

    virtual sptr<IOverlayManager> GetOverlayManagerProxy() override;
};

sptr<IOverlayManager> BundleMgrHostImplMock::GetOverlayManagerProxy()
{
    return nullptr;
}

class BmsBundleManagerIpcTest : public testing::Test {
public:
    BmsBundleManagerIpcTest();
    ~BmsBundleManagerIpcTest();
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
private:
    static std::shared_ptr<BundleMgrService> bundleMgrService_;
};

std::shared_ptr<BundleMgrService> BmsBundleManagerIpcTest::bundleMgrService_ =
    DelayedSingleton<BundleMgrService>::GetInstance();

BmsBundleManagerIpcTest::BmsBundleManagerIpcTest()
{}

BmsBundleManagerIpcTest::~BmsBundleManagerIpcTest()
{}

void BmsBundleManagerIpcTest::SetUpTestCase()
{}

void BmsBundleManagerIpcTest::TearDownTestCase()
{
    bundleMgrService_->OnStop();
}

void BmsBundleManagerIpcTest::SetUp()
{
    if (!bundleMgrService_->IsServiceReady()) {
        bundleMgrService_->OnStart();
        std::this_thread::sleep_for(std::chrono::seconds(WAIT_TIME));
    }
}

void BmsBundleManagerIpcTest::TearDown()
{}

/**
 * @tc.number: BundleManagerOverlayIpcTest_0100
 * @tc.name: test GetOverlayManagerProxy interface in BundleMgrProxy.
 * @tc.desc: 1.construct BundleMgrProxy instance.
 *           2.calling GetOverlayManagerProxy interface by using BundleMgrProxy instance.
 *           3.remote object is nullptr.
 *           4.return nullptr.
 * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleManagerIpcTest, BundleManagerIpcTest_0100, Function | SmallTest | Level0)
{
    sptr<IBundleMgr> bundleManagerProxy = new (std::nothrow) BundleMgrProxy(nullptr);
    EXPECT_NE(bundleManagerProxy, nullptr);

    auto overlayProxy = bundleManagerProxy->GetOverlayManagerProxy();
    EXPECT_EQ(overlayProxy, nullptr);
}

/**
 * @tc.number: BundleManagerOverlayIpcTest_0200
 * @tc.name: test GetOverlayManagerProxy interface in BundleMgrProxy.
 * @tc.desc: 1.construct BundleMgrProxy instance.
 *           2.calling GetOverlayManagerProxy interface by using BundleMgrProxy instance.
 *           3.return overlay proxy.
 * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleManagerIpcTest, BundleManagerOverlayIpcTest_0200, Function | SmallTest | Level0)
{
    sptr<BundleMgrHostImpl> bundleManagerHostImpl = new (std::nothrow) BundleMgrHostImpl();
    EXPECT_NE(bundleManagerHostImpl, nullptr);
    sptr<IBundleMgr> bundleManagerProxy = new (std::nothrow) BundleMgrProxy(bundleManagerHostImpl->AsObject());
    EXPECT_NE(bundleManagerProxy, nullptr);

    auto overlayProxy = bundleManagerProxy->GetOverlayManagerProxy();
    EXPECT_NE(overlayProxy, nullptr);
}

/**
 * @tc.number: BundleManagerOverlayIpcTest_0300
 * @tc.name: test GetOverlayManagerProxy interface in BundleMgrProxy.
 * @tc.desc: 1.construct BundleMgrProxy instance.
 *           2.calling GetOverlayManagerProxy interface by using BundleMgrProxy instance.
 *           3.return overlay proxy.
 * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleManagerIpcTest, BundleManagerOverlayIpcTest_0300, Function | SmallTest | Level0)
{
    sptr<BundleMgrHostImpl> bundleManagerHostImpl = new (std::nothrow) BundleMgrHostImpl();
    EXPECT_NE(bundleManagerHostImpl, nullptr);
    sptr<IBundleMgr> bundleManagerProxy = new (std::nothrow) BundleMgrProxy(bundleManagerHostImpl->AsObject());
    EXPECT_NE(bundleManagerProxy, nullptr);

    auto overlayProxy = bundleManagerProxy->GetOverlayManagerProxy();
    EXPECT_NE(overlayProxy, nullptr);
}

/**
 * @tc.number: BundleManagerOverlayIpcTest_0400
 * @tc.name: test HandleGetOverlayManagerProxy interface in BundleMgrHost.
 * @tc.desc: 1.construct BundleMgrHost instance.
 *           2.calling HandleGetOverlayManagerProxy interface by using BundleMgrHost instance.
 *           3.return failed.
 * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleManagerIpcTest, BundleManagerOverlayIpcTest_0400, Function | SmallTest | Level0)
{
    sptr<BundleMgrHostImplMock> bundleManagerHostImplMock = new (std::nothrow) BundleMgrHostImplMock();
    EXPECT_NE(bundleManagerHostImplMock, nullptr);

    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(BundleMgrHost::GetDescriptor());
    auto errCode = bundleManagerHostImplMock->OnRemoteRequest(
        static_cast<uint32_t>(BundleMgrInterfaceCode::GET_OVERLAY_MANAGER_PROXY), data, reply, option);
    EXPECT_EQ(errCode, UNKNOWN_ERROR);
}

/**
 * @tc.number: BundleManagerOverlayIpcTest_0500
 * @tc.name: test HandleGetOverlayManagerProxy interface in BundleMgrHost.
 * @tc.desc: 1.construct BundleMgrHost instance.
 *           2.calling HandleGetOverlayManagerProxy interface by using BundleMgrHost instance.
 *           3.error interface descriptor
 *           3.return failed.
 * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleManagerIpcTest, BundleManagerOverlayIpcTest_0500, Function | SmallTest | Level0)
{
    sptr<BundleMgrHostImplMock> bundleManagerHostImplMock = new (std::nothrow) BundleMgrHostImplMock();
    EXPECT_NE(bundleManagerHostImplMock, nullptr);

    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(TEST_HOST_DESCRIPTOR);
    auto errCode = bundleManagerHostImplMock->OnRemoteRequest(
        static_cast<uint32_t>(BundleMgrInterfaceCode::GET_OVERLAY_MANAGER_PROXY), data, reply, option);
    EXPECT_EQ(errCode, OBJECT_NULL);
}

/**
 * @tc.number: BundleManagerOverlayIpcTest_0600
 * @tc.name: test HandleGetOverlayManagerProxy interface in BundleMgrHost.
 * @tc.desc: 1.construct BundleMgrHost instance.
 *           2.calling HandleGetOverlayManagerProxy interface by using BundleMgrHost instance.
 *           3.return ERR_OK.
 * @tc.require: issueI6F3H9
 */
HWTEST_F(BmsBundleManagerIpcTest, BundleManagerOverlayIpcTest_0600, Function | SmallTest | Level0)
{
    sptr<BundleMgrHostImpl> bundleManagerHostImpl = new (std::nothrow) BundleMgrHostImpl();
    EXPECT_NE(bundleManagerHostImpl, nullptr);

    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(BundleMgrHost::GetDescriptor());
    auto errCode = bundleManagerHostImpl->OnRemoteRequest(
        static_cast<uint32_t>(BundleMgrInterfaceCode::GET_OVERLAY_MANAGER_PROXY), data, reply, option);
    EXPECT_EQ(errCode, ERR_OK);
}
} // OHOS