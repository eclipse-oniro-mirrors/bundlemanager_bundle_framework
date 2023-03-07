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

#define private public

#include <gtest/gtest.h>

#include <string>
#include <vector>

#include "appexecfwk_errors.h"
#include "service_info.h"
#include "service_router_mgr_helper.h"
#include "want.h"

using namespace testing::ext;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace {
const std::string WRONG_BUNDLE_NAME = "wrong";
const std::string PURPOSE_NAME = "pay";
}  // namespace

class ServiceRouterMgrInterfaceTest : public testing::Test {
public:
    ServiceRouterMgrInterfaceTest();
    ~ServiceRouterMgrInterfaceTest();
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

ServiceRouterMgrInterfaceTest::ServiceRouterMgrInterfaceTest()
{}

ServiceRouterMgrInterfaceTest::~ServiceRouterMgrInterfaceTest()
{}

void ServiceRouterMgrInterfaceTest::SetUpTestCase()
{}

void ServiceRouterMgrInterfaceTest::TearDownTestCase()
{}

void ServiceRouterMgrInterfaceTest::SetUp()
{}

void ServiceRouterMgrInterfaceTest::TearDown()
{}

/**
 * @tc.number: ServiceRouterMgrInterfaceTest
 * @tc.name: test QueryServiceInfos
 * @tc.require: issueI6HQLK
 * @tc.desc: 1. system running normally
 *           2. test serviceType is invalid
 */
HWTEST_F(ServiceRouterMgrInterfaceTest, ServiceRouterMgrInterfaceTest_0001, Function | SmallTest | Level0)
{
    auto serviceRouterMgr = ServiceRouterMgrHelper::GetInstance().GetServiceRouterMgr();
    EXPECT_NE(serviceRouterMgr, nullptr);
    if (serviceRouterMgr != nullptr) {
        Want want;
        std::vector<ServiceInfo> serviceInfos;
        auto ret = serviceRouterMgr->QueryServiceInfos(want, ExtensionServiceType::UNSPECIFIED, serviceInfos);
        EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PARAM_ERROR);
    }
}

/**
 * @tc.number: ServiceRouterMgrInterfaceTest
 * @tc.name: test QueryServiceInfos
 * @tc.require: issueI6HQLK
 * @tc.desc: 1. system running normally
 *           2. test serviceType is valid
 */
HWTEST_F(ServiceRouterMgrInterfaceTest, ServiceRouterMgrInterfaceTest_0002, Function | SmallTest | Level0)
{
    auto serviceRouterMgr = ServiceRouterMgrHelper::GetInstance().GetServiceRouterMgr();
    EXPECT_NE(serviceRouterMgr, nullptr);
    if (serviceRouterMgr != nullptr) {
        Want want;
        std::vector<ServiceInfo> serviceInfos;
        auto ret = serviceRouterMgr->QueryServiceInfos(want, ExtensionServiceType::SHARE, serviceInfos);
        EXPECT_EQ(ret, ERR_OK);
    }
}

/**
 * @tc.number: ServiceRouterMgrInterfaceTest
 * @tc.name: test QueryServiceInfos
 * @tc.require: issueI6HQLK
 * @tc.desc: 1. system running normally
 *           2. test bundleName not found
 */
HWTEST_F(ServiceRouterMgrInterfaceTest, ServiceRouterMgrInterfaceTest_0003, Function | SmallTest | Level0)
{
    auto serviceRouterMgr = ServiceRouterMgrHelper::GetInstance().GetServiceRouterMgr();
    EXPECT_NE(serviceRouterMgr, nullptr);
    if (serviceRouterMgr != nullptr) {
        Want want;
        want.SetElementName(WRONG_BUNDLE_NAME, "");
        std::vector<ServiceInfo> serviceInfos;
        auto ret = serviceRouterMgr->QueryServiceInfos(want, ExtensionServiceType::SHARE, serviceInfos);
        EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
    }
}

/**
 * @tc.number: ServiceRouterMgrInterfaceTest
 * @tc.name: test QueryPurposeInfos
 * @tc.require: issueI6HQLK
 * @tc.desc: 1. system running normally
 *           2. test purposeName empty
 */
HWTEST_F(ServiceRouterMgrInterfaceTest, ServiceRouterMgrInterfaceTest_0004, Function | SmallTest | Level0)
{
    auto serviceRouterMgr = ServiceRouterMgrHelper::GetInstance().GetServiceRouterMgr();
    EXPECT_NE(serviceRouterMgr, nullptr);
    if (serviceRouterMgr != nullptr) {
        Want want;
        std::vector<PurposeInfo> purposeInfos;
        auto ret = serviceRouterMgr->QueryPurposeInfos(want, "", purposeInfos);
        EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PARAM_ERROR);
    }
}

/**
 * @tc.number: ServiceRouterMgrInterfaceTest
 * @tc.name: test QueryPurposeInfos
 * @tc.require: issueI6HQLK
 * @tc.desc: 1. system running normally
 *           2. test purposeName is valid
 */
HWTEST_F(ServiceRouterMgrInterfaceTest, ServiceRouterMgrInterfaceTest_0005, Function | SmallTest | Level0)
{
    auto serviceRouterMgr = ServiceRouterMgrHelper::GetInstance().GetServiceRouterMgr();
    EXPECT_NE(serviceRouterMgr, nullptr);
    if (serviceRouterMgr != nullptr) {
        Want want;
        std::vector<PurposeInfo> purposeInfos;
        auto ret = serviceRouterMgr->QueryPurposeInfos(want, PURPOSE_NAME, purposeInfos);
        EXPECT_EQ(ret, ERR_OK);
    }
}

/**
 * @tc.number: ServiceRouterMgrInterfaceTest
 * @tc.name: test QueryPurposeInfos
 * @tc.require: issueI6HQLK
 * @tc.desc: 1. system running normally
 *           2. test bundleName not found
 */
HWTEST_F(ServiceRouterMgrInterfaceTest, ServiceRouterMgrInterfaceTest_0006, Function | SmallTest | Level0)
{
    auto serviceRouterMgr = ServiceRouterMgrHelper::GetInstance().GetServiceRouterMgr();
    EXPECT_NE(serviceRouterMgr, nullptr);
    if (serviceRouterMgr != nullptr) {
        Want want;
        want.SetElementName(WRONG_BUNDLE_NAME, "");
        std::vector<PurposeInfo> purposeInfos;
        auto ret = serviceRouterMgr->QueryPurposeInfos(want, PURPOSE_NAME, purposeInfos);
        EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
    }
}
} // OHOS