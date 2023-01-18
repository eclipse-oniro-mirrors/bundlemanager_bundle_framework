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
}

/**
 * @tc.number: OnAddSystemAbility_0200
 * @tc.name: test OnAddSystemAbility
 * @tc.desc: 1.systemAbilityId = DISTRIBUTED_HARDWARE_DEVICEMANAGER_SA_ID.
 *           2.deviceId = ""
 */
HWTEST_F(BmsDeviceManagerTest, OnAddSystemAbility_0200, Function | SmallTest | Level0)
{
    BmsDeviceManager deviceManager;
    int32_t systemAbilityId = DEVICEMANAGER_SA_ID;
    std::string deviceId = "";
    deviceManager.OnAddSystemAbility(systemAbilityId, deviceId);
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
    std::string deviceId = "";
    deviceManager.OnAddSystemAbility(systemAbilityId, deviceId);
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
    std::string deviceId = "";
    deviceManager.OnRemoveSystemAbility(systemAbilityId, deviceId);
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
    std::string deviceId = "";
    deviceManager.OnRemoveSystemAbility(systemAbilityId, deviceId);
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
 * @tc.number: StopDynamicSystemProcess_0100
 * @tc.name: test StopDynamicSystemProcess
 * @tc.desc: StopDynamicSystemProcess is success
 */
HWTEST_F(BmsDeviceManagerTest, StopDynamicSystemProcess_0100, Function | SmallTest | Level0)
{
    BmsDeviceManager deviceManager;
    int32_t systemAbilityId = 0;
    deviceManager.StopDynamicSystemProcess(systemAbilityId);
}

/**
 * @tc.number: GetUdidByNetworkId_0100
 * @tc.name: test GetUdidByNetworkId
 * @tc.desc: GetUdidByNetworkId is false
 */
HWTEST_F(BmsDeviceManagerTest, GetUdidByNetworkId_0100, Function | SmallTest | Level0)
{
    BmsDeviceManager deviceManager;
    std::string netWorkId = "";
    std::string uid = "";
    deviceManager.isInit_ = true;
    int32_t res = deviceManager.GetUdidByNetworkId(netWorkId, uid);
    EXPECT_FALSE(res);
}

/**
 * @tc.number: OnRemoteDied_0100
 * @tc.name: test OnRemoteDied
 * @tc.desc: Test whether OnRemoteDied is called normally.
 */
HWTEST_F(BmsDeviceManagerTest, OnRemoteDied_0100, Function | SmallTest | Level0)
{
    BmsDeviceManager deviceManager;
    deviceManager.initCallback_ = std::make_shared<AppExecFwk::BmsDeviceManager::DeviceInitCallBack>();
    deviceManager.initCallback_->OnRemoteDied();
}

/**
 * @tc.number: OnDeviceOnline_0100
 * @tc.name: test OnDeviceOnline
 * @tc.desc: Test whether OnDeviceOnline is called normally.
 */
HWTEST_F(BmsDeviceManagerTest, OnDeviceOnline_0100, Function | SmallTest | Level0)
{
    BmsDeviceManager deviceManager;
    DistributedHardware::DmDeviceInfo deviceInfo;
    deviceManager.stateCallback_ = std::make_shared<BmsDeviceManager::BmsDeviceStateCallback>();
    deviceManager.stateCallback_->OnDeviceOnline(deviceInfo);
}

/**
 * @tc.number: OnDeviceOffline_0100
 * @tc.name: test OnDeviceOffline
 * @tc.desc: Test whether OnDeviceOffline is called normally.
 */
HWTEST_F(BmsDeviceManagerTest, OnDeviceOffline_0100, Function | SmallTest | Level0)
{
    BmsDeviceManager deviceManager;
    DistributedHardware::DmDeviceInfo deviceInfo;
    deviceManager.stateCallback_ = std::make_shared<BmsDeviceManager::BmsDeviceStateCallback>();
    deviceManager.stateCallback_->OnDeviceOffline(deviceInfo);
}

/**
 * @tc.number: OnDeviceChanged_0100
 * @tc.name: test OnDeviceChanged
 * @tc.desc: Test whether OnDeviceChanged is called normally.
 */
HWTEST_F(BmsDeviceManagerTest, OnDeviceChanged_0100, Function | SmallTest | Level0)
{
    BmsDeviceManager deviceManager;
    DistributedHardware::DmDeviceInfo deviceInfo;
    deviceManager.stateCallback_ = std::make_shared<BmsDeviceManager::BmsDeviceStateCallback>();
    deviceManager.stateCallback_->OnDeviceChanged(deviceInfo);
}

/**
 * @tc.number: OnDeviceReady_0100
 * @tc.name: test OnDeviceReady
 * @tc.desc: Test whether OnDeviceReady is called normally.
 */
HWTEST_F(BmsDeviceManagerTest, OnDeviceReady_0100, Function | SmallTest | Level0)
{
    BmsDeviceManager deviceManager;
    DistributedHardware::DmDeviceInfo deviceInfo;
    deviceManager.stateCallback_ = std::make_shared<BmsDeviceManager::BmsDeviceStateCallback>();
    deviceManager.stateCallback_->OnDeviceReady(deviceInfo);
}
}
}