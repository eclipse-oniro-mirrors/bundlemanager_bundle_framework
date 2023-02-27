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

    isInit_ = true;
    APP_LOGI("register device manager success");
    return true;
}

void BmsDeviceManager::DeviceInitCallBack::OnRemoteDied()
{
    APP_LOGD("DeviceInitCallBack OnRemoteDied");
}

bool BmsDeviceManager::GetAllDeviceList(std::vector<std::string> &deviceIds)
{
    std::vector<DistributedHardware::DmDeviceInfo> deviceList;
    if (!GetTrustedDeviceList(deviceList)) {
        APP_LOGE("GetTrustedDeviceList failed");
        return false;
    }
    for (const auto &item : deviceList) {
        deviceIds.push_back(item.deviceId);
    }

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

int32_t BmsDeviceManager::GetUdidByNetworkId(const std::string &netWorkId, std::string &udid)
{
    APP_LOGI("GetUdidByNetworkId");
    if (!InitDeviceManager()) {
        return -1;
    }
    return DistributedHardware::DeviceManager::GetInstance().GetUdidByNetworkId(BUNDLE_NAME, netWorkId, udid);
}
}
}