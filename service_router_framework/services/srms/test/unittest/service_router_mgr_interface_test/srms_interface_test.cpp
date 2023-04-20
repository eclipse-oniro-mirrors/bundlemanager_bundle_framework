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

using namespace testing::ext;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace {
const std::string WRONG_BUNDLE_NAME = "wrong";
const std::string MIME_TYPE = "html";
const std::string BUNDLE_NAME = "bundleName";
const std::string PURPOSE_NAME = "pay";
const int32_t USERID = 100;
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
 * @tc.name: test QueryBusinessAbilityInfos
 * @tc.require: issueI6HQLK
 * @tc.desc: 1. system running normally
 *           2. test serviceType is invalid
 */
HWTEST_F(ServiceRouterMgrInterfaceTest, ServiceRouterMgrInterfaceTest_0001, Function | SmallTest | Level0)
{
    auto serviceRouterMgr = ServiceRouterMgrHelper::GetInstance().GetServiceRouterMgr();
    EXPECT_NE(serviceRouterMgr, nullptr);
    if (serviceRouterMgr != nullptr) {
        BusinessAbilityFilter filter;
        filter.businessType = BusinessType::UNSPECIFIED;
        std::vector<BusinessAbilityInfo> abilityInfos;
        auto ret = serviceRouterMgr->QueryBusinessAbilityInfos(filter, abilityInfos);
        EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PARAM_ERROR);
    }
}

/**
 * @tc.number: ServiceRouterMgrInterfaceTest
 * @tc.name: test QueryBusinessAbilityInfos
 * @tc.require: issueI6HQLK
 * @tc.desc: 1. system running normally
 *           2. test serviceType is valid
 */
HWTEST_F(ServiceRouterMgrInterfaceTest, ServiceRouterMgrInterfaceTest_0002, Function | SmallTest | Level0)
{
    auto serviceRouterMgr = ServiceRouterMgrHelper::GetInstance().GetServiceRouterMgr();
    EXPECT_NE(serviceRouterMgr, nullptr);
    if (serviceRouterMgr != nullptr) {
        BusinessAbilityFilter filter;
        filter.businessType = BusinessType::SHARE;
        std::vector<BusinessAbilityInfo> abilityInfos;
        auto ret = serviceRouterMgr->QueryBusinessAbilityInfos(filter, abilityInfos);
        EXPECT_EQ(ret, ERR_OK);
    }
}

/**
 * @tc.number: ServiceRouterMgrInterfaceTest_0003
 * Function: BusinessAbilityFilter
 * @tc.name: test BusinessAbilityFilter
 * @tc.desc: BusinessAbilityFilter
 */
HWTEST_F(ServiceRouterMgrInterfaceTest, ServiceRouterMgrInterfaceTest_0003, Function | SmallTest | Level0)
{
    BusinessAbilityFilter filter;
    filter.mimeType = MIME_TYPE;
    Parcel parcel;
    auto result = BusinessAbilityFilter::Unmarshalling(parcel);
    EXPECT_NE(result->mimeType, MIME_TYPE);
    auto ret = filter.Marshalling(parcel);
    EXPECT_TRUE(ret);
    result = BusinessAbilityFilter::Unmarshalling(parcel);
    EXPECT_EQ(result->mimeType, MIME_TYPE);
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

/**
 * @tc.number: ServiceRouterMgrInterfaceTest_0007
 * Function: AppInfo
 * @tc.name: test AppInfo
 * @tc.desc: AppInfo
 */
HWTEST_F(ServiceRouterMgrInterfaceTest, ServiceRouterMgrInterfaceTest_0007, Function | SmallTest | Level0)
{
    AppInfo info;
    info.bundleName = BUNDLE_NAME;
    Parcel parcel;
    auto result = AppInfo::Unmarshalling(parcel);
    EXPECT_NE(result->bundleName, BUNDLE_NAME);
    auto ret = info.Marshalling(parcel);
    EXPECT_TRUE(ret);
    result = AppInfo::Unmarshalling(parcel);
    EXPECT_EQ(result->bundleName, BUNDLE_NAME);
}

/**
 * @tc.number: ServiceRouterMgrInterfaceTest_0008
 * Function: BusinessAbilityInfo
 * @tc.name: test BusinessAbilityInfo
 * @tc.desc: BusinessAbilityInfo
 */
HWTEST_F(ServiceRouterMgrInterfaceTest, ServiceRouterMgrInterfaceTest_0008, Function | SmallTest | Level0)
{
    BusinessAbilityInfo info;
    info.bundleName = BUNDLE_NAME;
    Parcel parcel;
    auto ret = info.Marshalling(parcel);
    EXPECT_TRUE(ret);
    auto result = BusinessAbilityInfo::Unmarshalling(parcel);
    EXPECT_EQ(result->bundleName, BUNDLE_NAME);
}

/**
 * @tc.number: ServiceRouterMgrInterfaceTest_0009
 * Function: PurposeInfo
 * @tc.name: test PurposeInfo
 * @tc.desc: PurposeInfo
 */
HWTEST_F(ServiceRouterMgrInterfaceTest, ServiceRouterMgrInterfaceTest_0009, Function | SmallTest | Level0)
{
    PurposeInfo info;
    info.bundleName = BUNDLE_NAME;
    Parcel parcel;
    auto ret = info.Marshalling(parcel);
    EXPECT_TRUE(ret);
    auto result = PurposeInfo::Unmarshalling(parcel);
    EXPECT_EQ(result->bundleName, BUNDLE_NAME);
}

/**
 * @tc.number: ServiceRouterMgrInterfaceTest_0010
 * @tc.name: test StartUIExtensionAbility
 * @tc.require: issueI6HQLK
 * @tc.desc: 1. system running normally
 *           2. test StartUIExtensionAbility
 */
HWTEST_F(ServiceRouterMgrInterfaceTest, ServiceRouterMgrInterfaceTest_0010, Function | SmallTest | Level0)
{
    auto serviceRouterMgr = ServiceRouterMgrHelper::GetInstance().GetServiceRouterMgr();
    EXPECT_NE(serviceRouterMgr, nullptr);
    if (serviceRouterMgr != nullptr) {
        Want want;
        sptr<SessionInfo> sessionInfo;
        auto ret = serviceRouterMgr->StartUIExtensionAbility(
            want, sessionInfo, USERID, ExtensionAbilityType::UNSPECIFIED);
        EXPECT_NE(ret, ERR_OK);
    }
}

/**
 * @tc.number: ServiceRouterMgrInterfaceTest_0011
 * @tc.name: test ConnectUIExtensionAbility
 * @tc.require: issueI6HQLK
 * @tc.desc: 1. system running normally
 *           2. test ConnectUIExtensionAbility
 */
HWTEST_F(ServiceRouterMgrInterfaceTest, ServiceRouterMgrInterfaceTest_0011, Function | SmallTest | Level0)
{
    auto serviceRouterMgr = ServiceRouterMgrHelper::GetInstance().GetServiceRouterMgr();
    EXPECT_NE(serviceRouterMgr, nullptr);
    if (serviceRouterMgr != nullptr) {
        Want want;
        sptr<IAbilityConnection> connect;
        sptr<SessionInfo> sessionInfo;
        auto ret = serviceRouterMgr->ConnectUIExtensionAbility(
            want, connect, sessionInfo, USERID);
        EXPECT_NE(ret, ERR_OK);
    }
}
} // OHOS