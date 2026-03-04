/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#include "aot/aot_sign_data_cache_mgr.h"

#include <thread>
#include <chrono>

#include "aot/aot_handler.h"
#include "application_info.h"
#include "installd_client.h"

namespace OHOS {
namespace AppExecFwk {
AOTSignDataCacheMgr& AOTSignDataCacheMgr::GetInstance()
{
    static AOTSignDataCacheMgr signDataCacheMgr;
    return signDataCacheMgr;
}

void AOTSignDataCacheMgr::RegisterScreenUnlockListener()
{
    EventFwk::MatchingSkills matchingSkill;
    // use COMMON_EVENT_USER_UNLOCKED if only for device with PIN
    matchingSkill.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_UNLOCKED);
    EventFwk::CommonEventSubscribeInfo eventInfo(matchingSkill);
    unlockEventSubscriber_ = std::make_shared<UnlockEventSubscriber>(eventInfo);
    const bool result = EventFwk::CommonEventManager::SubscribeCommonEvent(unlockEventSubscriber_);
    if (!result) {
        APP_LOGE_NOFUNC("register screen unlock event for pending sign AOT error");
        return;
    }
    APP_LOGI_NOFUNC("AOT register screen unlock event success");
}

void AOTSignDataCacheMgr::AddSignDataForSysComp(const std::string &anFileName, const std::vector<uint8_t> &signData,
    const ErrCode ret)
{
    if (anFileName.empty() || signData.empty()) {
        APP_LOGE_NOFUNC("empty anFileName or signData");
        return;
    }
    if (!isLocked_ || ret != ERR_APPEXECFWK_INSTALLD_SIGN_AOT_DISABLE) {
        return;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    sysCompSignDataMap_[anFileName] = signData;
}

void AOTSignDataCacheMgr::AddSignDataForModule(const AOTArgs &aotArgs, const uint32_t versionCode,
    const std::vector<uint8_t> &signData, const ErrCode ret)
{
    if (aotArgs.bundleName.empty() || aotArgs.moduleName.empty() || signData.empty()) {
        APP_LOGD("empty bundleName or moduleName or signData");
        return;
    }
    if (!isLocked_ || ret != ERR_APPEXECFWK_INSTALLD_SIGN_AOT_DISABLE) {
        return;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    moduleSignDataVector_.emplace_back(ModuleSignData{aotArgs.bundleType, aotArgs.triggerType, versionCode,
        aotArgs.bundleName, aotArgs.moduleName, signData});
}

void AOTSignDataCacheMgr::UnregisterScreenUnlockEvent()
{
    const bool result = EventFwk::CommonEventManager::UnSubscribeCommonEvent(unlockEventSubscriber_);
    if (!result) {
        APP_LOGE_NOFUNC("unregister screen unlock event error");
        return;
    }
    APP_LOGI_NOFUNC("unregister screen unlock event success");
}

void AOTSignDataCacheMgr::UnlockEventSubscriber::OnReceiveEvent(const EventFwk::CommonEventData &event)
{
    const auto want = event.GetWant();
    const auto action = want.GetAction();
    if (action == EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_UNLOCKED) {
        APP_LOGI("receive screen unlock event");
        auto task = []() {
            AOTSignDataCacheMgr::GetInstance().HandleUnlockEvent();
        };
        std::thread(task).detach();
    }
}

void AOTSignDataCacheMgr::HandleUnlockEvent()
{
    APP_LOGI_NOFUNC("begin to sign data");
    isLocked_ = false;
    UnregisterScreenUnlockEvent();

    uint8_t maxRetry = 5;
    for (uint8_t i = 1; i <= maxRetry; ++i) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        if (EnforceCodeSign()) {
            APP_LOGI_NOFUNC("sign data success");
            return;
        }
    }
    std::lock_guard<std::mutex> lock(mutex_);
    std::unordered_map<std::string, std::vector<uint8_t>>().swap(sysCompSignDataMap_);
    moduleSignDataVector_.clear();
    APP_LOGE_NOFUNC("sign data failed");
}

bool AOTSignDataCacheMgr::EnforceCodeSign()
{
    return EnforceCodeSignForSysComp() && EnforceCodeSignForModule();
}

bool AOTSignDataCacheMgr::EnforceCodeSignForSysComp()
{
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto &[anFileName, signData] : sysCompSignDataMap_) {
        ErrCode signRet = InstalldClient::GetInstance()->PendSignAOT(anFileName, signData);
        if (signRet == ERR_APPEXECFWK_INSTALLD_SIGN_AOT_DISABLE) {
            APP_LOGE_NOFUNC("sign service disabled");
            return false;
        }
    }
    std::unordered_map<std::string, std::vector<uint8_t>>().swap(sysCompSignDataMap_);
    return true;
}

bool AOTSignDataCacheMgr::EnforceCodeSignForModule()
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        APP_LOGE_NOFUNC("dataMgr is null");
        return false;
    }
    for (const ModuleSignData &signData : moduleSignDataVector_) {
        std::filesystem::path anFileName;
        if (signData.bundleType == static_cast<uint8_t>(BundleType::SHARED)) {
            anFileName = AOTHandler::BuildSharedArkCachePath(signData.bundleName, signData.versionCode);
            anFileName /= signData.moduleName + ServiceConstants::AN_SUFFIX;
        } else {
            anFileName = ServiceConstants::HAP_ARK_CACHE_PATH;
            anFileName /= signData.bundleName;
            anFileName /= ServiceConstants::ARM64;
            anFileName /= signData.moduleName + ServiceConstants::AN_SUFFIX;
        }
        ErrCode signRet = InstalldClient::GetInstance()->PendSignAOT(anFileName.string(), signData.signData);
        if (signRet == ERR_APPEXECFWK_INSTALLD_SIGN_AOT_DISABLE) {
            APP_LOGE_NOFUNC("sign service disabled");
            return false;
        }
        if (signRet == ERR_OK) {
            AOTCompileStatus status = AOTHandler::ConvertToAOTCompileStatus(signRet, signData.triggerType);
            dataMgr->SetAOTCompileStatus(signData.bundleName, signData.moduleName, status, signData.versionCode);
        }
    }
    moduleSignDataVector_.clear();
    return true;
}
}  // namespace AppExecFwk
}  // namespace OHOS
