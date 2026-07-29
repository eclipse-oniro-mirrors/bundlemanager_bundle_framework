/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include <chrono>
#include <sstream>
#include <sys/statfs.h>
#include <thread>

#include "account_helper.h"
#include "app_log_wrapper.h"
#include "battery_srv_client.h"
#include "bms_update_selinux_mgr.h"
#include "bundle_mgr_service.h"
#include "bundle_service_constants.h"
#include "ffrt.h"
#include "file_ex.h"
#include "idle_condition_mgr/idle_condition_mgr.h"
#include "idle_condition_mgr/idle_param_util.h"
#include "mem_mgr_client.h"
#include "parameter.h"
#include "parameters.h"
#include "scope_guard.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr const char* BMS_PARAM_RELABEL_BATTERY_CAPACITY = "ohos.bms.param.relabelBatteryCapacity";
constexpr const char* BMS_PARAM_RELABEL_WAIT_TIME = "ohos.bms.param.relabelWaitTimeMinutes";
constexpr const char* MEMORY_INFO_PATH = "/dev/memcg/memory.zswapd_presure_show";
constexpr const char* MEMORY_BUFFER_KEY = "buffer_size";
constexpr const char* COMMERCIAL_MODE = "commercial";
constexpr const char* COMMERCIAL_MODE_PARAM = "const.logsystem.versiontype";
constexpr const char* USER_DATA_DIR = "/data";
constexpr double MIN_FREE_INODE_PERCENT = 0.2;
constexpr int32_t RELABEL_WAIT_TIME_SECONDS = 5 * 60; // 5 minutes
constexpr int32_t RELABEL_MIN_BATTERY_CAPACITY = 20;
constexpr int32_t RELABEL_MIN_BUFFER_SIZE = 700;
}


IdleConditionMgr::IdleConditionMgr()
{
    idleConditionListener_ = std::make_shared<IdleConditionListener>();
    Memory::MemMgrClient::GetInstance().SubscribeAppState(*idleConditionListener_);
    ReloadParam();
    APP_LOGI("IdleConditionMgr created");
}

IdleConditionMgr::~IdleConditionMgr()
{
    Memory::MemMgrClient::GetInstance().UnsubscribeAppState(*idleConditionListener_);
    APP_LOGI("IdleConditionMgr destroyed");
}

void IdleConditionMgr::OnScreenLocked()
{
    APP_LOGI_NOFUNC("OnScreenLocked");
    {
        std::lock_guard<std::mutex> lock(mutex_);
        screenLocked_ = true;
    }
    TryStartRelabel();
    TryStartScanAppData();
}

void IdleConditionMgr::OnScreenUnlocked()
{
    APP_LOGI_NOFUNC("OnScreenUnlocked");
    {
        std::lock_guard<std::mutex> lock(mutex_);
        screenLocked_ = false;
    }
    InterruptRelabel("OnScreenUnlocked called");
    InterruptScanAppData("ScanSystemAppSize OnScreenUnlocked called");
}

void IdleConditionMgr::OnUserUnlocked(const int32_t userId)
{
    APP_LOGI_NOFUNC("OnUserUnlocked");
    {
        std::lock_guard<std::mutex> lock(mutex_);
        userUnlockedMap_[userId] = true;
    }
    TryStartRelabel();
    TryStartScanAppData();
}

void IdleConditionMgr::OnUserStopping(const int32_t userId)
{
    APP_LOGI_NOFUNC("OnUserStopping");
    {
        std::lock_guard<std::mutex> lock(mutex_);
        userUnlockedMap_[userId] = false;
    }
    InterruptRelabel("OnUserStopping called");
    InterruptScanAppData("ScanSystemAppSize OnUserStopping called");
}

void IdleConditionMgr::OnPowerConnected()
{
    APP_LOGI_NOFUNC("OnPowerConnected");
    if (powerConnectedThreadActive_) {
        return;
    }
    powerConnectedThreadActive_ = true;
    std::weak_ptr<IdleConditionMgr> weakPtr = shared_from_this();
    auto task = [weakPtr]() {
        auto startTime = std::chrono::steady_clock::now();
        int32_t delayTime = OHOS::system::GetIntParameter<int32_t>(
            BMS_PARAM_RELABEL_WAIT_TIME, RELABEL_WAIT_TIME_SECONDS);
        auto endTime = startTime + std::chrono::seconds(delayTime);
        auto sharedPtr = weakPtr.lock();
        if (sharedPtr == nullptr) {
            APP_LOGE("stop power connect task");
            return;
        }
        while (std::chrono::steady_clock::now() < endTime) {
            if (!sharedPtr->powerConnectedThreadActive_) {
                APP_LOGI("power connected thread is not active");
                return;
            }
            ffrt::this_task::sleep_for(std::chrono::seconds(1));
        }
        {
            std::lock_guard<std::mutex> lock(sharedPtr->mutex_);
            sharedPtr->powerConnected_ = true;
        }
        sharedPtr->TryStartRelabel();
        sharedPtr->TryStartScanAppData();
        sharedPtr->powerConnectedThreadActive_ = false;
        APP_LOGI("power connected task done");
    };
    ffrt::submit(task);
}

void IdleConditionMgr::OnPowerDisconnected()
{
    APP_LOGI_NOFUNC("OnPowerDisconnected");
    {
        std::lock_guard<std::mutex> lock(mutex_);
        powerConnected_ = false;
    }
    powerConnectedThreadActive_ = false;
    InterruptRelabel("OnPowerDisconnected called");
    InterruptScanAppData("ScanSystemAppSize OnPowerDisconnected called");
}

void IdleConditionMgr::HandleOnTrim(Memory::SystemMemoryLevel level)
{
    APP_LOGI_NOFUNC("HandleOnTrim called, level=%{public}d", level);
    switch (level) {
        case Memory::SystemMemoryLevel::UNKNOWN:
            [[fallthrough]];
        case Memory::SystemMemoryLevel::MEMORY_LEVEL_PURGEABLE:
            [[fallthrough]];
        case Memory::SystemMemoryLevel::MEMORY_LEVEL_MODERATE:
            TryStartRelabel();
            TryStartScanAppData();
            break;
        case Memory::SystemMemoryLevel::MEMORY_LEVEL_LOW:
            [[fallthrough]];
        case Memory::SystemMemoryLevel::MEMORY_LEVEL_CRITICAL:
            InterruptRelabel("memory level critical");
            InterruptScanAppData("ScanSystemAppSize memory level critical");
            break;
        default:
            break;
    }
}

bool IdleConditionMgr::IsBufferSufficient()
{
    std::string content;
    if (!LoadStringFromFile(MEMORY_INFO_PATH, content)) {
        APP_LOGE("Failed to read memory info");
        return false;
    }
    size_t pos = content.find(MEMORY_BUFFER_KEY);
    if (pos == std::string::npos) {
        APP_LOGE("Failed to find memory buffer info");
        return false;
    }
    std::string bufferMb = content.substr(pos);
    std::istringstream bufferStream(bufferMb);
    std::string statTag;
    std::string bufferSize;
    bufferStream >> statTag >> bufferSize;
    
    int32_t currentBufferSizeMb = -1;
    if (!OHOS::StrToInt(bufferSize, currentBufferSizeMb)) {
        APP_LOGE("Failed to convert buffer size to int: %s", bufferSize.c_str());
        return false;
    }
    return currentBufferSizeMb > RELABEL_MIN_BUFFER_SIZE;
}

bool IdleConditionMgr::IsThermalSatisfied()
{
    return PowerMgr::ThermalMgrClient::GetInstance().GetThermalLevel() < PowerMgr::ThermalLevel::WARM;
}

bool IdleConditionMgr::CheckInodeForCommericalDevice()
{
    std::string versionType = OHOS::system::GetParameter(COMMERCIAL_MODE_PARAM, "");
    if (versionType != COMMERCIAL_MODE) {
        APP_LOGD("non commercial device");
        return true;
    }
    struct statfs stat;
    if (statfs(USER_DATA_DIR, &stat) != 0) {
        APP_LOGE("statfs failed for %{public}s, error %{public}d",
            USER_DATA_DIR, errno);
        return false;
    }
    uint32_t minFreeInodeNum = static_cast<uint32_t>(stat.f_files * MIN_FREE_INODE_PERCENT);
    if (stat.f_ffree > minFreeInodeNum) {
        APP_LOGI("free inodes over threshold");
        return false;
    }
    APP_LOGD("total inodes: %{public}" PRIu64 ", free inodes: %{public}" PRIu64,
        stat.f_files, stat.f_ffree);
    return true;
}

void IdleConditionMgr::OnBatteryChanged()
{
    APP_LOGI_NOFUNC("OnBatteryChanged");
    int32_t currentBatteryCap = OHOS::PowerMgr::BatterySrvClient::GetInstance().GetCapacity();
    int32_t relabelBatteryCapacity = OHOS::system::GetIntParameter<int32_t>(
        BMS_PARAM_RELABEL_BATTERY_CAPACITY, RELABEL_MIN_BATTERY_CAPACITY);
    if (currentBatteryCap < relabelBatteryCapacity) {
        APP_LOGD("battery capacity %{public}d less than %{public}d interrupt relabel",
            currentBatteryCap, relabelBatteryCapacity);
        {
            std::lock_guard<std::mutex> lock(mutex_);
            batterySatisfied_ = false;
        }
        InterruptRelabel("battery capacity low");
        InterruptScanAppData("ScanSystemAppSize battery capacity low");
    } else {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            batterySatisfied_ = true;
        }
        TryStartRelabel();
        TryStartScanAppData();
    }
}

void IdleConditionMgr::OnThermalLevelChanged(PowerMgr::ThermalLevel level)
{
    APP_LOGI_NOFUNC("OnThermalLevelChanged called, level=%{public}d", level);
    if (level < PowerMgr::ThermalLevel::WARM) {
        TryStartRelabel();
        TryStartScanAppData();
    } else {
        APP_LOGD("thermal level %{public}d greater than %{public}d interrupt relabel",
            level, PowerMgr::ThermalLevel::WARM);
        InterruptRelabel("OnThermalLevelChanged called");
        InterruptScanAppData("ScanSystemAppSize OnThermalLevelChanged called");
    }
}

bool IdleConditionMgr::CheckRelabelConditions(const int32_t userId)
{
    auto installer = DelayedSingleton<BundleMgrService>::GetInstance()->GetBundleInstaller();
    if (installer == nullptr) {
        APP_LOGE("installer is null");
        return false;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    bool userUnlocked = false;
    auto iter = userUnlockedMap_.find(userId);
    if (iter != userUnlockedMap_.end() && iter->second) {
        userUnlocked = true;
    }
    if (userUnlocked && screenLocked_ && powerConnected_ && batterySatisfied_
        && g_taskCounter.load() == 0 && !isScanActive_) {
        return true;
    }
    APP_LOGI_NOFUNC("relabel state: -u %{public}d, %{public}d, %{public}d, %{public}d, %{public}d, %{public}d, "
        "isScanActive=%{public}d",
        userId, userUnlocked, screenLocked_.load(),
        powerConnected_.load(), batterySatisfied_.load(), g_taskCounter.load(), isScanActive_.load());
    return false;
}

bool IdleConditionMgr::SetIsRelabeling()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (isRelabeling_) {
        APP_LOGI_NOFUNC("Already relabeling");
        return false;
    }
    isRelabeling_ = true;
    return true;
}

bool IdleConditionMgr::SetIsScanActive()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (isScanActive_) {
        APP_LOGI_NOFUNC("ScanSystemAppSize Scan already active");
        return false;
    }
    isScanActive_ = true;
    return true;
}

void IdleConditionMgr::TryStartRelabel()
{
    if (!OHOS::system::GetBoolParameter(ServiceConstants::BMS_RELABEL_PARAM, false)) {
        return;
    }
    int32_t currentUserId = AccountHelper::GetCurrentActiveUserId();
    if (!CheckRelabelConditions(currentUserId)) {
        APP_LOGI_NOFUNC("Refresh conditions not met");
        return;
    }
    if (!featureEnabled_) {
        APP_LOGI("Feature not enabled, no need to process");
        return;
    }
    if (!CheckInodeForCommericalDevice()) {
        APP_LOGI_NOFUNC("inode sufficient");
        return;
    }
    if (!IsBufferSufficient()) {
        APP_LOGI_NOFUNC("Buffer not sufficient");
        return;
    }
    if (!IsThermalSatisfied()) {
        APP_LOGI_NOFUNC("Thermal not satisfied");
        return;
    }
    auto selinuxMgr = DelayedSingleton<BmsUpdateSelinuxMgr>::GetInstance();
    if (selinuxMgr == nullptr || !selinuxMgr->HasPendingBundles(currentUserId)) {
        APP_LOGI_NOFUNC("for ScanSystemAppSize no relabel work pending, skip arming relabel");
        return;
    }
    if (!SetIsRelabeling()) {
        APP_LOGD("Set isRelabeling failed");
        return;
    }
    std::weak_ptr<IdleConditionMgr> weakPtr = shared_from_this();
    auto task = [weakPtr] {
        APP_LOGI_NOFUNC("Relabel task started");
        auto sharedPtr = weakPtr.lock();
        if (sharedPtr == nullptr) {
            APP_LOGD("stop relabel task");
            return;
        }
        ScopeGuard relabelGuard([sharedPtr] {
            std::lock_guard<std::mutex> lock(sharedPtr->mutex_);
            sharedPtr->isRelabeling_ = false;
        });
        int32_t userId = AccountHelper::GetCurrentActiveUserId();
        if (!sharedPtr->CheckRelabelConditions(userId)) {
            APP_LOGI("Refresh conditions not met, no need to process");
            return;
        }
        if (!sharedPtr->IsBufferSufficient()) {
            APP_LOGI("Buffer not sufficient, no need to process");
            return;
        }
        if (!sharedPtr->IsThermalSatisfied()) {
            APP_LOGI("Thermal not satisfied, no need to process");
            return;
        }
        auto bmsUpdateSelinuxMgr = DelayedSingleton<BmsUpdateSelinuxMgr>::GetInstance();
        if (bmsUpdateSelinuxMgr == nullptr) {
            APP_LOGE("bms update selinux mgr is null");
            return;
        }
        bmsUpdateSelinuxMgr->StartUpdateSelinuxLabel(userId);
        APP_LOGI_NOFUNC("Relabel task finished");
    };
    std::thread(task).detach();
}

void IdleConditionMgr::InterruptRelabel(const std::string stopReason)
{
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!isRelabeling_) {
            APP_LOGI_NOFUNC("No relabeling in progress");
            return;
        }
    }
    // Interrupt logic here
    auto bmsUpdateSelinuxMgr = DelayedSingleton<BmsUpdateSelinuxMgr>::GetInstance();
    if (bmsUpdateSelinuxMgr == nullptr) {
        APP_LOGE("bms update selinux mgr is null");
        return;
    }
    bmsUpdateSelinuxMgr->StopUpdateSelinuxLabel(ServiceConstants::StopReason::BUSY, stopReason);
    APP_LOGI_NOFUNC("Relabeling interrupted");
}

bool IdleConditionMgr::CheckScanConditions(const int32_t userId)
{
    auto monitor = DelayedSingleton<AppDataMonitor>::GetInstance();
    if (monitor == nullptr) {
        APP_LOGE("ScanSystemAppSize AppDataMonitor is null");
        return false;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    bool userUnlocked = false;
    auto iter = userUnlockedMap_.find(userId);
    if (iter != userUnlockedMap_.end() && iter->second) {
        userUnlocked = true;
    }
    if (userUnlocked && screenLocked_ && powerConnected_ && batterySatisfied_
        && !monitor->IsScanning() && g_taskCounter.load() == 0 && !isRelabeling_) {
        return true;
    }
    APP_LOGI("ScanSystemAppSize scan conditions not met: userId=%{public}d, userUnlocked=%{public}d, "
        "screenLocked=%{public}d, powerConnected=%{public}d, battery=%{public}d, taskCounter=%{public}d, "
        "isRelabeling=%{public}d",
        userId, userUnlocked, screenLocked_.load(), powerConnected_.load(), batterySatisfied_.load(),
        g_taskCounter.load(), isRelabeling_.load());
    return false;
}

void IdleConditionMgr::TryStartScanAppData()
{
    if (!OHOS::system::GetBoolParameter(ServiceConstants::BMS_SCAN_APP_DATA_PARAM, false)) {
        return;
    }
    if (!scanFeatureEnabled_.load()) {
        return;
    }
    int32_t currentUserId = AccountHelper::GetCurrentActiveUserId();
    if (!CheckScanConditions(currentUserId)) {
        return;
    }
    if (!IsBufferSufficient()) {
        APP_LOGI("ScanSystemAppSize Buffer not sufficient for scan");
        return;
    }
    if (!IsThermalSatisfied()) {
        APP_LOGI("ScanSystemAppSize Thermal not satisfied for scan");
        return;
    }
    if (!SetIsScanActive()) {
        APP_LOGI("ScanSystemAppSize Scan already active");
        return;
    }
    std::weak_ptr<IdleConditionMgr> weakPtr = shared_from_this();
    auto task = [weakPtr] {
        APP_LOGI("ScanSystemAppSize App data scan task started");
        auto sharedPtr = weakPtr.lock();
        if (sharedPtr == nullptr) {
            APP_LOGD("ScanSystemAppSize stop scan task, mgr destroyed");
            return;
        }
        ScopeGuard scanActiveGuard([sharedPtr] {
            std::lock_guard<std::mutex> lock(sharedPtr->mutex_);
            sharedPtr->isScanActive_ = false;
        });
        int32_t currentUserId = AccountHelper::GetCurrentActiveUserId();
        if (!sharedPtr->CheckScanConditions(currentUserId)) {
            APP_LOGI("ScanSystemAppSize scan conditions not met in task, skip");
            return;
        }
        if (!sharedPtr->IsBufferSufficient()) {
            APP_LOGI("ScanSystemAppSize Buffer not sufficient in task, skip");
            return;
        }
        if (!sharedPtr->IsThermalSatisfied()) {
            APP_LOGI("ScanSystemAppSize Thermal not satisfied in task, skip");
            return;
        }
        auto mon = DelayedSingleton<AppDataMonitor>::GetInstance();
        if (mon == nullptr) {
            APP_LOGE("ScanSystemAppSize AppDataMonitor is null in task");
            return;
        }
        mon->StartScan(currentUserId);
        APP_LOGI("ScanSystemAppSize App data scan task finished");
    };
    std::thread(task).detach();
}

void IdleConditionMgr::InterruptScanAppData(const std::string &stopReason)
{
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!isScanActive_) {
            APP_LOGI_NOFUNC("ScanSystemAppSize No scan in progress");
            return;
        }
    }
    auto monitor = DelayedSingleton<AppDataMonitor>::GetInstance();
    if (monitor == nullptr) {
        APP_LOGE("ScanSystemAppSize AppDataMonitor is null");
        return;
    }
    monitor->StopScan(stopReason);
    APP_LOGI_NOFUNC("ScanSystemAppSize Scan interrupted");
}

void IdleConditionMgr::OnConfigChanged()
{
    APP_LOGI("OnConfigChanged called");
    ReloadParam();
}

void IdleConditionMgr::ReloadParam()
{
    if (IdleParamUtil::IsRelabelFeatureDisabled()) {
        featureEnabled_ = false;
        APP_LOGI("Relabel feature disabled");
    } else {
        featureEnabled_ = true;
        APP_LOGI("Relabel feature enabled");
    }
    if (IdleParamUtil::IsAppDataScanDisabled()) {
        scanFeatureEnabled_ = false;
        APP_LOGI("ScanSystemAppSize Scan app data feature disabled");
    } else {
        scanFeatureEnabled_ = true;
        APP_LOGI("ScanSystemAppSize Scan app data feature enabled");
    }
}
} // namespace AppExecFwk
} // namespace OHOS
