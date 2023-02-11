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
#define private public
#define protected public
#include "bms_device_manager.h"
#undef private
#undef protected
#include "system_ability_definition.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace AppExecFwk {
namespace {
    const std::string DEVICEID = "100";
    const int32_t DEVICEMANAGER_SA_ID = 4802;
    const int32_t SYSTEM_ABILITY_ID = 4801;
    const int32_t SYS_ABILITY_ID = 402;
    const std::string EMPTY_STRING = "";
}
class BmsDeviceManagerTest : public testing::Test {
public:
    BmsDeviceManagerTest();
    ~BmsDeviceManagerTest();
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

BmsDeviceManagerTest::BmsDeviceManagerTest()
{}

BmsDeviceManagerTest::~BmsDeviceManagerTest()
{}

void BmsDeviceManagerTest::SetUpTestCase()
{}

void BmsDeviceManagerTest::TearDownTestCase()
{}

void BmsDeviceManagerTest::SetUp()
{}

void BmsDeviceManagerTest::TearDown()
{}

/**
 * @tc.number: InitDeviceManager_0100
 * @tc.name: test InitDeviceManager
 * @tc.desc: isInit_ is true, return true.
 */
HWTEST_F(BmsDeviceManagerTest, InitDeviceManager_0100, Function | SmallTest | Level0)
{
    BmsDeviceManager deviceManager;
    deviceManager.isInit_ = true;
    bool res = deviceManager.InitDeviceManager();
    EXPECT_TRUE(res);
}

/**
 * @tc.number: InitDeviceManager_0200
 * @tc.name: test InitDeviceManager
 * @tc.desc: isInit_ is false, return true.
 */
HWTEST_F(BmsDeviceManagerTest, InitDeviceManager_0200, Function | SmallTest | Level0)
{
    BmsDeviceManager deviceManager;
    deviceManager.isInit_ = false;
    bool res = deviceManager.InitDeviceManager();
    EXPECT_TRUE(res);
}

/**
 * @tc.number: OnAddSystemAbility_0100
 * @tc.name: test OnAddSystemAbility
 * @tc.desc: 1.systemAbilityId = DISTRIBUTED_HARDWARE_DEVICEMANAGER_SA_ID.
 *           2.deviceId = "100"
 */
HWTEST_F(BmsDeviceManagerTest, OnAddSystemAbility_0100, Function | SmallTest | Level0)
{
    BmsDeviceManager deviceManager;
    int32_t systemAbilityId = SYSTEM_ABILITY_ID;
    std::string deviceId = DEVICEID;
    deviceManager.OnAddSystemAbility(systemAbilityId, deviceId);
    EXPECT_NE(systemAbilityId, DISTRIBUTED_HARDWARE_DEVICEMANAGER_SA_ID);
}

/**
 * @tc.number: OnAddSystemAbility_0200
 * @tc.name: test OnAddSystemAbility
 * @tc.desc: 1.systemAbilityId = DISTRIBUTED_HARDWARE_DEVICEMANAGER_SA_ID.
 *           2.deviceId = EMPTY_STRING
 */
HWTEST_F(BmsDeviceManagerTest, OnAddSystemAbility_0200, Function | SmallTest | Level0)
{
    BmsDeviceManager deviceManager;
    int32_t systemAbilityId = DEVICEMANAGER_SA_ID;
    std::string deviceId = EMPTY_STRING;
    deviceManager.OnAddSystemAbility(systemAbilityId, deviceId);
    EXPECT_EQ(systemAbilityId, DISTRIBUTED_HARDWARE_DEVICEMANAGER_SA_ID);
}

/**
 * @tc.number: OnAddSystemAbility_0300
 * @tc.name: test OnAddSystemAbility
 * @tc.desc: systemAbilityId != DISTRIBUTED_HARDWARE_DEVICEMANAGER_SA_ID.
 */
HWTEST_F(BmsDeviceManagerTest, OnAddSystemAbility_0300, Function | SmallTest | Level0)
{
    BmsDeviceManager deviceManager;
    int32_t systemAbilityId = SYSTEM_ABILITY_ID;
    std::string deviceId = EMPTY_STRING;
    deviceManager.OnAddSystemAbility(systemAbilityId, deviceId);
    EXPECT_NE(systemAbilityId, DISTRIBUTED_HARDWARE_DEVICEMANAGER_SA_ID);
}

/**
 * @tc.number: OnRemoveSystemAbility_0100
 * @tc.name: test OnRemoveSystemAbility
 * @tc.desc: systemAbilityId = DISTRIBUTED_BUNDLE_MGR_SERVICE_SYS_ABILITY_ID.
 */
HWTEST_F(BmsDeviceManagerTest, OnRemoveSystemAbility_0100, Function | SmallTest | Level0)
{
    BmsDeviceManager deviceManager;
    int32_t systemAbilityId = SYS_ABILITY_ID;
    std::string deviceId = EMPTY_STRING;
    deviceManager.OnRemoveSystemAbility(systemAbilityId, deviceId);
    EXPECT_EQ(systemAbilityId, DISTRIBUTED_BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
}

/**
 * @tc.number: OnRemoveSystemAbility_0200
 * @tc.name: test OnRemoveSystemAbility
 * @tc.desc: systemAbilityId != DISTRIBUTED_BUNDLE_MGR_SERVICE_SYS_ABILITY_ID.
 */
HWTEST_F(BmsDeviceManagerTest, OnRemoveSystemAbility_0200, Function | SmallTest | Level0)
{
    BmsDeviceManager deviceManager;
    int32_t systemAbilityId = SYSTEM_ABILITY_ID;
    std::string deviceId = EMPTY_STRING;
    deviceManager.OnRemoveSystemAbility(systemAbilityId, deviceId);
    EXPECT_NE(systemAbilityId, DISTRIBUTED_BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
}

/**
 * @tc.number: GetAllDeviceList_0100
 * @tc.name: test GetAllDeviceList
 * @tc.desc: GetAllDeviceList is success
 */
HWTEST_F(BmsDeviceManagerTest, GetAllDeviceList_0100, Function | SmallTest | Level0)
{
    BmsDeviceManager deviceManager;
    std::string deviceId = DEVICEID;
    std::vector<std::string> deviceIds;
    deviceIds.push_back(deviceId);
    bool res = deviceManager.GetAllDeviceList(deviceIds);
    EXPECT_TRUE(res);
}

/**
 * @tc.number: GetTrustedDeviceList_0100
 * @tc.name: test GetTrustedDeviceList
 * @tc.desc: GetTrustedDeviceList return true
 */
HWTEST_F(BmsDeviceManagerTest, GetTrustedDeviceList_0100, Function | SmallTest | Level0)
{
    BmsDeviceManager deviceManager;
    std::vector<DistributedHardware::DmDeviceInfo> deviceList;
    bool res = deviceManager.GetTrustedDeviceList(deviceList);
    EXPECT_TRUE(res);
}

/**
 * @tc.number: GetTrustedDeviceList_0200
 * @tc.name: test GetTrustedDeviceList
 * @tc.desc: GetTrustedDeviceList return true
 */
HWTEST_F(BmsDeviceManagerTest, GetTrustedDeviceList_0200, Function | SmallTest | Level0)
{
    BmsDeviceManager deviceManager;
    std::vector<DistributedHardware::DmDeviceInfo> deviceList;
    deviceManager.isInit_ = true;
    bool res = deviceManager.GetTrustedDeviceList(deviceList);
    EXPECT_TRUE(res);
}

/**
 * @tc.number: StartDynamicSystemProcess_0100
 * @tc.name: test StartDynamicSystemProcess
 * @tc.desc: systemAbilityId != DISTRIBUTED_BUNDLE_MGR_SERVICE_SYS_ABILITY_ID.
 */
HWTEST_F(BmsDeviceManagerTest, StartDynamicSystemProcess_0100, Function | SmallTest | Level0)
{
    BmsDeviceManager deviceManager;
    int32_t systemAbilityId = 0;
    deviceManager.StartDynamicSystemProcess(systemAbilityId);
}

/**
 * @tc.number: GetUdidByNetworkId_0100
 * @tc.name: test GetUdidByNetworkId
 * @tc.desc: GetUdidByNetworkId is false
 */
HWTEST_F(BmsDeviceManagerTest, GetUdidByNetworkId_0100, Function | SmallTest | Level0)
{
    BmsDeviceManager deviceManager;
    std::string netWorkId = EMPTY_STRING;
    std::string uid = EMPTY_STRING;
    auto ret = deviceManager.GetUdidByNetworkId(netWorkId, uid);
    EXPECT_FALSE(ret == -1);
}
}
}