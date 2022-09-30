/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "bms_device_manager.h"

#include "app_log_wrapper.h"
#include "bundle_mgr_service.h"
#include "device_manager.h"
#include "service_control.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
    const std::string BUNDLE_NAME = "ohos.appexefwk.appexefwk_standard";
    const std::string SERVICES_NAME = "d-bms";
}

BmsDeviceManager::BmsDeviceManager()
{
    APP_LOGD("BmsDeviceManager instance is created");
}

bool BmsDeviceManager::InitDeviceManager()
{
    std::lock_guard<std::mutex> lock(isInitMutex_);
    if (isInit_) {
        APP_LOGI("device manager already init");
        return true;
    }

    initCallback_ = std::make_shared<DeviceInitCallBack>();
    int32_t ret =
        DistributedHardware::DeviceManager::GetInstance().InitDeviceManager(BUNDLE_NAME, initCallback_);
    if (ret != 0) {
        APP_LOGE("init device manager failed, ret:%{public}d", ret);
        return false;
    }
    stateCallback_ = std::make_shared<BmsDeviceStateCallback>();
    ret =
        DistributedHardware::DeviceManager::GetInstance().RegisterDevStateCallback(BUNDLE_NAME, "", stateCallback_);
    if (ret != 0) {
        APP_LOGE("register devStateCallback failed, ret:%{public}d", ret);
        return false;
    }
    isInit_ = true;
    APP_LOGI("register device manager success");
    return true;
}

void BmsDeviceManager::OnAddSystemAbility(int32_t systemAbilityId, const std::string& deviceId)
{
    APP_LOGI("OnAddSystemAbility systemAbilityId:%{public}d add!", systemAbilityId);
    if (DISTRIBUTED_HARDWARE_DEVICEMANAGER_SA_ID == systemAbilityId) {
        InitDeviceManager();
        std::vector<DistributedHardware::DmDeviceInfo> deviceList;
        if (!GetTrustedDeviceList(deviceList)) {
            APP_LOGW("deviceManager GetTrustedDeviceList failed");
            return;
        }
        if (deviceList.size() > 0) {
            StartDynamicSystemProcess(DISTRIBUTED_BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
        }
    }
}

void BmsDeviceManager::OnRemoveSystemAbility(int32_t systemAbilityId, const std::string& deviceId)
{
    APP_LOGI("OnRemoveSystemAbility systemAbilityId:%{public}d removed!", systemAbilityId);
    if (DISTRIBUTED_BUNDLE_MGR_SERVICE_SYS_ABILITY_ID == systemAbilityId) {
        std::vector<DistributedHardware::DmDeviceInfo> deviceList;
        if (!GetTrustedDeviceList(deviceList)) {
            APP_LOGW("deviceManager GetTrustedDeviceList failed");
            return;
        }
        if (deviceList.size() > 0) {
            StartDynamicSystemProcess(DISTRIBUTED_BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
        }
    }
}

bool BmsDeviceManager::GetAllDeviceList(std::vector<std::string> &deviceIds)
{
    std::vector<DistributedHardware::DmDeviceInfo> deviceList;
    if (!GetTrustedDeviceList(deviceList)) {
        APP_LOGE("GetTrustedDeviceList failed");
        return false;
    }
    std::transform(deviceList.begin(),
        deviceList.end(),
        std::back_inserter(deviceIds),
        [](const auto &device) { return device.deviceId; });

    DistributedHardware::DmDeviceInfo dmDeviceInfo;
    int32_t ret =
        DistributedHardware::DeviceManager::GetInstance().GetLocalDeviceInfo(BUNDLE_NAME, dmDeviceInfo);
    if (ret != 0) {
        APP_LOGE("GetLocalDeviceInfo failed");
        return false;
    }
    deviceIds.emplace_back(dmDeviceInfo.deviceId);
    return true;
}

bool BmsDeviceManager::GetTrustedDeviceList(std::vector<DistributedHardware::DmDeviceInfo> &deviceList)
{
    if (!InitDeviceManager()) {
        return false;
    }
    int32_t ret =
        DistributedHardware::DeviceManager::GetInstance().GetTrustedDeviceList(BUNDLE_NAME, "", deviceList);
    if (ret != 0) {
        APP_LOGW("GetTrustedDeviceList failed, ret:%{public}d", ret);
        return false;
    }
    APP_LOGD("GetTrustedDeviceList size :%{public}ud", static_cast<uint32_t>(deviceList.size()));
    return true;
}

void BmsDeviceManager::StartDynamicSystemProcess(int32_t systemAbilityId)
{
    APP_LOGD("StartDynamicSystemProcess systemAbilityId:%{public}d !", systemAbilityId);
    std::string strExtra = std::to_string(systemAbilityId);
    auto extraArgv = strExtra.c_str();
    int ret = ServiceControlWithExtra(SERVICES_NAME.c_str(), START, &extraArgv, 1);
    APP_LOGI("StartDynamicSystemProcess, ret:%{public}d", ret);
}

void BmsDeviceManager::StopDynamicSystemProcess(int32_t systemAbilityId)
{
    APP_LOGD("StopDynamicSystemProcess systemAbilityId:%{public}d !", systemAbilityId);
    std::string strExtra = std::to_string(systemAbilityId);
    auto extraArgv = strExtra.c_str();
    int ret = ServiceControlWithExtra(SERVICES_NAME.c_str(), STOP, &extraArgv, 1);
    APP_LOGI("StopDynamicSystemProcess, ret:%{public}d", ret);
}

int32_t BmsDeviceManager::GetUdidByNetworkId(const std::string &netWorkId, std::string &udid)
{
    APP_LOGI("GetUdidByNetworkId");
    if (!InitDeviceManager()) {
        return -1;
    }
    return DistributedHardware::DeviceManager::GetInstance().GetUdidByNetworkId(BUNDLE_NAME, netWorkId, udid);
}

void BmsDeviceManager::DeviceInitCallBack::OnRemoteDied()
{
    APP_LOGD("DeviceInitCallBack OnRemoteDied");
}

void BmsDeviceManager::BmsDeviceStateCallback::OnDeviceOnline(const DistributedHardware::DmDeviceInfo &deviceInfo)
{
    APP_LOGI("DeviceInitCallBack OnDeviceOnline");
}

void BmsDeviceManager::BmsDeviceStateCallback::OnDeviceOffline(const DistributedHardware::DmDeviceInfo &deviceInfo)
{
    APP_LOGI("DeviceInitCallBack OnDeviceOffline");
    auto deviceManager = DelayedSingleton<BundleMgrService>::GetInstance()->GetDeviceManager();
    if (deviceManager == nullptr) {
        APP_LOGW("deviceManager is nullptr");
        return;
    }
    std::vector<DistributedHardware::DmDeviceInfo> deviceList;
    if (!deviceManager->GetTrustedDeviceList(deviceList)) {
        APP_LOGW("deviceManager GetTrustedDeviceList failed");
        return;
    }
    if (deviceList.size() == 0) {
        BmsDeviceManager::StopDynamicSystemProcess(DISTRIBUTED_BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    }
}

void BmsDeviceManager::BmsDeviceStateCallback::OnDeviceChanged(const DistributedHardware::DmDeviceInfo &deviceInfo)
{
    APP_LOGD("DeviceInitCallBack OnDeviceChanged");
}

void BmsDeviceManager::BmsDeviceStateCallback::OnDeviceReady(const DistributedHardware::DmDeviceInfo &deviceInfo)
{
    APP_LOGI("DeviceInitCallBack OnDeviceReady");
    BmsDeviceManager::StartDynamicSystemProcess(DISTRIBUTED_BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
}
}
}