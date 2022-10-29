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

#include <fstream>
#include <gtest/gtest.h>
#include <sstream>
#include <string>

#include "appexecfwk_errors.h"
#include "distributed_bms.h"
#include "distributed_bms_interface.h"
#include "distributed_bms_proxy.h"
#include "element_name.h"

using namespace testing::ext;
using namespace std::chrono_literals;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace {
const std::string WRONG_BUNDLE_NAME = "wrong";
const std::string WRONG_ABILITY_NAME = "wrong";
const std::string BUNDLE_NAME = "com.ohos.launcher";
const std::string MODULE_NAME = "launcher_settings";
const std::string ABILITY_NAME = "com.ohos.launcher.settings.MainAbility";
const std::string DEVICE_ID = "1111";
}  // namespace

class DbmsServicesKitTest : public testing::Test {
public:
    DbmsServicesKitTest();
    ~DbmsServicesKitTest();
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    std::shared_ptr<DistributedBms> GetDistributedBms();
    std::shared_ptr<DistributedBmsProxy> GetDistributedBmsProxy();
    void StartInstalldService() const;
    void StartBundleService();
private:
    std::shared_ptr<DistributedBms> distributedBms_ = nullptr;
    std::shared_ptr<DistributedBmsProxy> distributedBmsProxy_ = nullptr;
};

DbmsServicesKitTest::DbmsServicesKitTest()
{}

DbmsServicesKitTest::~DbmsServicesKitTest()
{}

void DbmsServicesKitTest::SetUpTestCase()
{}

void DbmsServicesKitTest::TearDownTestCase()
{}

void DbmsServicesKitTest::SetUp()
{}

void DbmsServicesKitTest::TearDown()
{}

std::shared_ptr<DistributedBms> DbmsServicesKitTest::GetDistributedBms()
{
    if (distributedBms_ == nullptr) {
        distributedBms_ = DelayedSingleton<DistributedBms>::GetInstance();
    }
    return distributedBms_;
}

std::shared_ptr<DistributedBmsProxy> DbmsServicesKitTest::GetDistributedBmsProxy()
{
    if (distributedBmsProxy_ == nullptr) {
        distributedBmsProxy_ = std::make_shared<DistributedBmsProxy>(nullptr);
    }
    return distributedBmsProxy_;
}
/**
 * @tc.number: DbmsServicesKitTest
 * @tc.name: test GetRemoteAbilityInfo
 * @tc.require: issueI5MZ8V
 * @tc.desc: 1. system running normally
 *           2. test ElementName empty
 */
HWTEST_F(DbmsServicesKitTest, DbmsServicesKitTest_0001, Function | SmallTest | Level0)
{
    auto distributedBms = GetDistributedBms();
    EXPECT_NE(distributedBms, nullptr);
    if (distributedBms != nullptr) {
        ElementName name;
        RemoteAbilityInfo info;
        auto ret = distributedBms->GetRemoteAbilityInfo(name, info);
        EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_DEVICE_ID_NOT_EXIST);
    }
}

/**
 * @tc.number: DbmsServicesKitTest
 * @tc.name: test GetRemoteAbilityInfo
 * @tc.require: issueI5MZ8V
 * @tc.desc: 1. system running normally
 *           2. test ElementName empty
 */
HWTEST_F(DbmsServicesKitTest, DbmsServicesKitTest_0002, Function | SmallTest | Level0)
{
    auto distributedBms = GetDistributedBms();
    EXPECT_NE(distributedBms, nullptr);
    if (distributedBms != nullptr) {
        ElementName name;
        RemoteAbilityInfo info;
        auto ret = distributedBms->GetRemoteAbilityInfo(name, "", info);
        EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_DEVICE_ID_NOT_EXIST);
    }
}

/**
 * @tc.number: DbmsServicesKitTest
 * @tc.name: test GetRemoteAbilityInfo
 * @tc.require: issueI5MZ8V
 * @tc.desc: 1. system running normally
 *           2. test ElementName empty
 */
HWTEST_F(DbmsServicesKitTest, DbmsServicesKitTest_0003, Function | SmallTest | Level0)
{
    auto distributedBms = GetDistributedBms();
    EXPECT_NE(distributedBms, nullptr);
    if (distributedBms != nullptr) {
        ElementName name;
        RemoteAbilityInfo info;
        auto ret = distributedBms->GetRemoteAbilityInfo(name, "", info);
        EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_DEVICE_ID_NOT_EXIST);
    }
}

/**
 * @tc.number: DbmsServicesKitTest
 * @tc.name: test GetRemoteAbilityInfos
 * @tc.require: issueI5MZ8V
 * @tc.desc: 1. system running normally
 *           2. test ElementName empty
 */
HWTEST_F(DbmsServicesKitTest, DbmsServicesKitTest_0004, Function | SmallTest | Level0)
{
    auto distributedBms = GetDistributedBms();
    EXPECT_NE(distributedBms, nullptr);
    if (distributedBms != nullptr) {
        std::vector<ElementName> name;
        std::vector<RemoteAbilityInfo> info;
        auto ret = distributedBms->GetRemoteAbilityInfos(name, info);
        EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PARAM_ERROR);
    }
}

/**
 * @tc.number: DbmsServicesKitTest
 * @tc.name: test GetRemoteAbilityInfos
 * @tc.require: issueI5MZ8V
 * @tc.desc: 1. system running normally
 *           2. test ElementName empty
 */
HWTEST_F(DbmsServicesKitTest, DbmsServicesKitTest_0005, Function | SmallTest | Level0)
{
    auto distributedBms = GetDistributedBms();
    EXPECT_NE(distributedBms, nullptr);
    if (distributedBms != nullptr) {
        std::vector<ElementName> name;
        std::vector<RemoteAbilityInfo> info;
        auto ret = distributedBms->GetRemoteAbilityInfos(name, "", info);
        EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PARAM_ERROR);
    }
}

/**
 * @tc.number: DbmsServicesKitTest
 * @tc.name: test GetAbilityInfo
 * @tc.require: issueI5MZ8V
 * @tc.desc: 1. system running normally
 *           2. test bundleName empty
 */
HWTEST_F(DbmsServicesKitTest, DbmsServicesKitTest_0006, Function | SmallTest | Level0)
{
    auto distributedBms = GetDistributedBms();
    EXPECT_NE(distributedBms, nullptr);
    if (distributedBms != nullptr) {
        ElementName name;
        name.SetBundleName(WRONG_BUNDLE_NAME);
        name.SetAbilityName(ABILITY_NAME);
        RemoteAbilityInfo info;
        auto ret = distributedBms->GetAbilityInfo(name, info);
        EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
    }
}

/**
 * @tc.number: DbmsServicesKitTest
 * @tc.name: test GetAbilityInfo
 * @tc.require: issueI5MZ8V
 * @tc.desc: 1. system running normally
 *           2. test abilityName empty
 */
HWTEST_F(DbmsServicesKitTest, DbmsServicesKitTest_0007, Function | SmallTest | Level0)
{
    auto distributedBms = GetDistributedBms();
    EXPECT_NE(distributedBms, nullptr);
    if (distributedBms != nullptr) {
        ElementName name;
        name.SetBundleName(BUNDLE_NAME);
        name.SetAbilityName(WRONG_ABILITY_NAME);
        RemoteAbilityInfo info;
        auto ret = distributedBms->GetAbilityInfo(name, info);
        EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_ABILITY_NOT_EXIST);
    }
}

/**
 * @tc.number: DbmsServicesKitTest
 * @tc.name: test GetAbilityInfo
 * @tc.require: issueI5MZ8V
 * @tc.desc: 1. system running normally
 *           2. test bundleName and abilityName both exist
 */
HWTEST_F(DbmsServicesKitTest, DbmsServicesKitTest_0008, Function | SmallTest | Level0)
{
    auto distributedBms = GetDistributedBms();
    EXPECT_NE(distributedBms, nullptr);
    if (distributedBms != nullptr) {
        ElementName name;
        name.SetBundleName(BUNDLE_NAME);
        name.SetAbilityName(ABILITY_NAME);
        RemoteAbilityInfo info;
        auto ret = distributedBms->GetAbilityInfo(name, info);
        EXPECT_EQ(ret, ERR_OK);
    }
}

/**
 * @tc.number: DbmsServicesKitTest
 * @tc.name: test GetAbilityInfo
 * @tc.require: issueI5MZ8V
 * @tc.desc: 1. system running normally
 *           2. test wrong abilityName
 */
HWTEST_F(DbmsServicesKitTest, DbmsServicesKitTest_0009, Function | SmallTest | Level0)
{
    auto distributedBms = GetDistributedBms();
    EXPECT_NE(distributedBms, nullptr);
    if (distributedBms != nullptr) {
        ElementName name;
        name.SetBundleName(BUNDLE_NAME);
        name.SetModuleName(MODULE_NAME);
        name.SetAbilityName(WRONG_ABILITY_NAME);
        RemoteAbilityInfo info;
        auto ret = distributedBms->GetAbilityInfo(name, info);
        EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_ABILITY_NOT_EXIST);
    }
}

/**
 * @tc.number: DbmsServicesKitTest
 * @tc.name: test GetAbilityInfo
 * @tc.require: issueI5MZ8V
 * @tc.desc: 1. system running normally
 *           2. test ElementName empty
 */
HWTEST_F(DbmsServicesKitTest, DbmsServicesKitTest_0010, Function | SmallTest | Level0)
{
    auto distributedBms = GetDistributedBms();
    EXPECT_NE(distributedBms, nullptr);
    if (distributedBms != nullptr) {
        std::vector<ElementName> name;
        std::vector<RemoteAbilityInfo> info;
        auto ret = distributedBms->GetAbilityInfos(name, info);
        EXPECT_EQ(ret, ERR_OK);
    }
}

/**
 * @tc.number: DbmsServicesKitTest
 * @tc.name: test GetAbilityInfo
 * @tc.require: issueI5MZ8V
 * @tc.desc: 1. system running normally
 *           2. test abilityName empty
 */
HWTEST_F(DbmsServicesKitTest, DbmsServicesKitTest_0011, Function | SmallTest | Level0)
{
    auto distributedBms = GetDistributedBms();
    EXPECT_NE(distributedBms, nullptr);
    if (distributedBms != nullptr) {
        std::vector<ElementName> names;
        ElementName name;
        name.SetBundleName(BUNDLE_NAME);
        name.SetModuleName(MODULE_NAME);
        name.SetAbilityName(WRONG_ABILITY_NAME);
        names.push_back(name);
        std::vector<RemoteAbilityInfo> infos;
        auto ret = distributedBms->GetAbilityInfos(names, infos);
        EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_ABILITY_NOT_EXIST);
    }
}

/**
 * @tc.number: DbmsServicesKitTest
 * @tc.name: test GetAbilityInfo
 * @tc.require: issueI5MZ8V
 * @tc.desc: 1. system running normally
 *           2. test abilityName empty
 */
HWTEST_F(DbmsServicesKitTest, DbmsServicesKitTest_0012, Function | SmallTest | Level0)
{
    auto distributedBms = GetDistributedBms();
    EXPECT_NE(distributedBms, nullptr);
    if (distributedBms != nullptr) {
        std::vector<ElementName> names;
        ElementName name;
        name.SetBundleName(BUNDLE_NAME);
        name.SetAbilityName(ABILITY_NAME);
        names.push_back(name);
        std::vector<RemoteAbilityInfo> infos;
        auto ret = distributedBms->GetAbilityInfos(names, infos);
        EXPECT_EQ(ret, ERR_OK);
    }
}

/**
 * @tc.number: DbmsServicesKitTest
 * @tc.name: test GetAbilityInfo
 * @tc.require: issueI5MZ8V
 * @tc.desc: 1. system running normally
 *           2. test bundleName empty
 */
HWTEST_F(DbmsServicesKitTest, DbmsServicesKitTest_0013, Function | SmallTest | Level0)
{
    auto distributedBmsProxy = GetDistributedBmsProxy();
    EXPECT_NE(distributedBmsProxy, nullptr);
    if (distributedBmsProxy != nullptr) {
        ElementName name;
        RemoteAbilityInfo info;
        auto ret = distributedBmsProxy->GetRemoteAbilityInfo(name, "", info);
        EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
    }
}

/**
 * @tc.number: DbmsServicesKitTest
 * @tc.name: test GetAbilityInfo
 * @tc.require: issueI5MZ8V
 * @tc.desc: 1. system running normally
 *           2. test abilityName empty
 */
HWTEST_F(DbmsServicesKitTest, DbmsServicesKitTest_0014, Function | SmallTest | Level0)
{
    auto distributedBmsProxy = GetDistributedBmsProxy();
    EXPECT_NE(distributedBmsProxy, nullptr);
    if (distributedBmsProxy != nullptr) {
        ElementName name;
        name.SetBundleName(BUNDLE_NAME);
        RemoteAbilityInfo info;
        auto ret = distributedBmsProxy->GetRemoteAbilityInfo(name, "", info);
        EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_ABILITY_NOT_EXIST);
    }
}

/**
 * @tc.number: DbmsServicesKitTest
 * @tc.name: test GetAbilityInfo
 * @tc.require: issueI5MZ8V
 * @tc.desc: 1. system running normally
 *           2. test deviceID empty
 */
HWTEST_F(DbmsServicesKitTest, DbmsServicesKitTest_0015, Function | SmallTest | Level0)
{
    auto distributedBmsProxy = GetDistributedBmsProxy();
    EXPECT_NE(distributedBmsProxy, nullptr);
    if (distributedBmsProxy != nullptr) {
        ElementName name;
        name.SetBundleName(BUNDLE_NAME);
        name.SetAbilityName(ABILITY_NAME);
        RemoteAbilityInfo info;
        auto ret = distributedBmsProxy->GetRemoteAbilityInfo(name, "", info);
        EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_DEVICE_ID_NOT_EXIST);
    }
}

/**
 * @tc.number: DbmsServicesKitTest
 * @tc.name: test GetAbilityInfo
 * @tc.require: issueI5MZ8V
 * @tc.desc: 1. system running normally
 *           2. test ElementName not empty
 */
HWTEST_F(DbmsServicesKitTest, DbmsServicesKitTest_0016, Function | SmallTest | Level0)
{
    auto distributedBmsProxy = GetDistributedBmsProxy();
    EXPECT_NE(distributedBmsProxy, nullptr);
    if (distributedBmsProxy != nullptr) {
        ElementName name;
        name.SetBundleName(BUNDLE_NAME);
        name.SetAbilityName(ABILITY_NAME);
        name.SetDeviceID(DEVICE_ID);
        RemoteAbilityInfo info;
        auto ret = distributedBmsProxy->GetRemoteAbilityInfo(name, "", info);
        EXPECT_EQ(ret, ERR_APPEXECFWK_FAILED_GET_REMOTE_PROXY);
    }
}

/**
 * @tc.number: DbmsServicesKitTest
 * @tc.name: test GetAbilityInfo
 * @tc.require: issueI5MZ8V
 * @tc.desc: 1. system running normally
 *           2. test ElementNames empty
 */
HWTEST_F(DbmsServicesKitTest, DbmsServicesKitTest_0017, Function | SmallTest | Level0)
{
    auto distributedBmsProxy = GetDistributedBmsProxy();
    EXPECT_NE(distributedBmsProxy, nullptr);
    if (distributedBmsProxy != nullptr) {
        std::vector<ElementName> names;
        std::vector<RemoteAbilityInfo> infos;
        auto ret = distributedBmsProxy->GetRemoteAbilityInfos(names, infos);
        EXPECT_EQ(ret, ERR_APPEXECFWK_FAILED_GET_REMOTE_PROXY);
    }
}

/**
 * @tc.number: DbmsServicesKitTest
 * @tc.name: test GetAbilityInfo
 * @tc.require: issueI5MZ8V
 * @tc.desc: 1. system running normally
 *           2. test ElementNames not empty
 */
HWTEST_F(DbmsServicesKitTest, DbmsServicesKitTest_0018, Function | SmallTest | Level0)
{
    auto distributedBmsProxy = GetDistributedBmsProxy();
    EXPECT_NE(distributedBmsProxy, nullptr);
    if (distributedBmsProxy != nullptr) {
        std::vector<ElementName> names;
        ElementName name_1;
        name_1.SetBundleName(BUNDLE_NAME);
        name_1.SetAbilityName(ABILITY_NAME);
        name_1.SetDeviceID(DEVICE_ID);
        names.push_back(name_1);

        ElementName name_2;
        name_2.SetBundleName(BUNDLE_NAME);
        name_2.SetAbilityName(ABILITY_NAME);
        names.push_back(name_2);

        std::vector<RemoteAbilityInfo> infos;
        auto ret = distributedBmsProxy->GetRemoteAbilityInfos(names, infos);
        EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_DEVICE_ID_NOT_EXIST);
    }
}
} // OHOS