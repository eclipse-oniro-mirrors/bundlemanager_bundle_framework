/*
 * Copyright (c) 2024-2024 Huawei Device Co., Ltd.
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

#include "installd_client.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr int8_t SLEEP_TIME_FOR_WAIT_SIGN_ENABLE = 1; // 1 s
constexpr int8_t LOOP_TIMES_FOR_WAIT_SIGN_ENABLE = 5;
}

AOTSignDataCacheMgr& AOTSignDataCacheMgr::GetInstance()
{
    static AOTSignDataCacheMgr signDataCacheMgr;
    return signDataCacheMgr;
}

void AOTSignDataCacheMgr::AddPendSignData(const AOTArgs &aotArgs, const uint32_t versionCode,
    const std::vector<uint8_t> &pendSignData, const ErrCode ret)
{
    if (isLocked_ && (ret == ERR_APPEXECFWK_INSTALLD_SIGN_AOT_DISABLE) && !pendSignData.empty()) {
        if (aotArgs.bundleName.empty() || aotArgs.moduleName.empty()) {
            APP_LOGE("empty bundle or/and module name error");
            return;
        }
        PendingData pendingData = {versionCode, pendSignData};
        {
            std::lock_guard<std::mutex> lock(mutex_);
            pendingSignData_[aotArgs.bundleName][aotArgs.moduleName] = pendingData;
        }
    }
}

void AOTSignDataCacheMgr::RegisterScreenUnlockListener()
{
    APP_LOGI("register screen unlock event start");
    EventFwk::MatchingSkills matchingSkill;
    // use COMMON_EVENT_USER_UNLOCKED if only for device with PIN
    matchingSkill.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_UNLOCKED);
    EventFwk::CommonEventSubscribeInfo eventInfo(matchingSkill);
    unlockEventSubscriber_ = std::make_shared<UnlockEventSubscriber>(eventInfo);
    const bool result = EventFwk::CommonEventManager::SubscribeCommonEvent(unlockEventSubscriber_);
    if (!result) {
        APP_LOGE("register screen unlock event for pending sign AOT error");
        return;
    }
    APP_LOGI("register screen unlock event for pending sign AOT success");
}

void AOTSignDataCacheMgr::UnregisterScreenUnlockEvent()
{
    APP_LOGI("unregister screen unlock event start");
    const bool result = EventFwk::CommonEventManager::UnSubscribeCommonEvent(unlockEventSubscriber_);
    if (!result) {
        APP_LOGE("unregister screen unlock event error");
        return;
    }
    APP_LOGI("unregister screen unlock event success");
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
    APP_LOGI("pending sign thread is wake up");
    UnregisterScreenUnlockEvent();

    sleep(SLEEP_TIME_FOR_WAIT_SIGN_ENABLE);
    isLocked_ = false;
    int32_t loopTimes = 0;
    while (ExecutePendSign() != ERR_OK) {
        if (++loopTimes > LOOP_TIMES_FOR_WAIT_SIGN_ENABLE) {
            APP_LOGE("wait for enforce sign enable time out");
            return;
        }
        sleep(SLEEP_TIME_FOR_WAIT_SIGN_ENABLE);
    }
    {
        std::lock_guard<std::mutex> lock(mutex_);
        std::unordered_map<std::string, std::unordered_map<std::string, PendingData>>().swap(pendingSignData_);
    }
    APP_LOGI("pending enforce sign success");
}

ErrCode AOTSignDataCacheMgr::ExecutePendSign()
{
    std::lock_guard<std::mutex> lock(mutex_);
    ErrCode ret = ERR_OK;
    for (auto itBundle = pendingSignData_.begin(); itBundle != pendingSignData_.end(); ++itBundle) {
        auto &bundleName = itBundle->first;
        auto &moduleSignData = itBundle->second;
        for (auto itModule = moduleSignData.begin(); itModule != moduleSignData.end();) {
            auto &moduleName = itModule->first;
            auto &signData = itModule->second.signData;
            std::string anFileName = ServiceConstants::ARK_CACHE_PATH + bundleName + ServiceConstants::PATH_SEPARATOR
                + ServiceConstants::ARM64 + ServiceConstants::PATH_SEPARATOR + moduleName + ServiceConstants::AN_SUFFIX;

            ErrCode retCS = InstalldClient::GetInstance()->PendSignAOT(anFileName, signData);
            if (retCS == ERR_APPEXECFWK_INSTALLD_SIGN_AOT_DISABLE) {
                APP_LOGE("enforce sign service is disable");
                ret = ERR_APPEXECFWK_INSTALLD_SIGN_AOT_FAILED;
                ++itModule;
                continue;
            } else if (retCS != ERR_OK) {
                itModule = moduleSignData.erase(itModule);
                continue;
            }
            auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
            if (!dataMgr) {
                APP_LOGE("dataMgr is null");
                ret = ERR_APPEXECFWK_INSTALLD_SIGN_AOT_FAILED;
                ++itModule;
                continue;
            }
            auto versionCode = itModule->second.versionCode;
            dataMgr->SetAOTCompileStatus(bundleName, moduleName, AOTCompileStatus::COMPILE_SUCCESS, versionCode);
            itModule = moduleSignData.erase(itModule);
        }
    }
    return ret;
}
}  // namespace AppExecFwk
}  // namespace OHOS
