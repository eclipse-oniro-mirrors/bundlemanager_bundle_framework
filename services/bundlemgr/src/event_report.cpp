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

#include "event_report.h"

#include <unordered_map>

#include "app_log_wrapper.h"
#include "bundle_util.h"
#ifdef HISYSEVENT_ENABLE
#include "inner_event_report.h"
#endif

namespace OHOS {
namespace AppExecFwk {
namespace {
const std::unordered_map<BundleEventType, BMSEventType> BUNDLE_EXCEPTION_SYS_EVENT_MAP = {
    { BundleEventType::INSTALL, BMSEventType::BUNDLE_INSTALL_EXCEPTION },
    { BundleEventType::UNINSTALL, BMSEventType::BUNDLE_UNINSTALL_EXCEPTION },
    { BundleEventType::UPDATE, BMSEventType::BUNDLE_UPDATE_EXCEPTION },
    { BundleEventType::RECOVER, BMSEventType::PRE_BUNDLE_RECOVER_EXCEPTION },
};

const std::unordered_map<BundleEventType, BMSEventType> BUNDLE_SYS_EVENT_MAP = {
    { BundleEventType::INSTALL, BMSEventType::BUNDLE_INSTALL },
    { BundleEventType::UNINSTALL, BMSEventType::BUNDLE_UNINSTALL },
    { BundleEventType::UPDATE, BMSEventType::BUNDLE_UPDATE },
    { BundleEventType::RECOVER, BMSEventType::PRE_BUNDLE_RECOVER },
    { BundleEventType::QUICK_FIX, BMSEventType::APPLY_QUICK_FIX }
};
}

void EventReport::SendBundleSystemEvent(BundleEventType bundleEventType, const EventInfo& eventInfo)
{
    BMSEventType bmsEventType = BMSEventType::UNKNOW;
    std::unordered_map<BundleEventType, BMSEventType>::const_iterator iter;
    if (eventInfo.errCode != ERR_OK) {
        iter = BUNDLE_EXCEPTION_SYS_EVENT_MAP.find(bundleEventType);
        if (iter != BUNDLE_EXCEPTION_SYS_EVENT_MAP.end()) {
            bmsEventType = iter->second;
        }

        SendSystemEvent(bmsEventType, eventInfo);
        return;
    }

    iter = BUNDLE_SYS_EVENT_MAP.find(bundleEventType);
    if (iter != BUNDLE_SYS_EVENT_MAP.end()) {
        bmsEventType = iter->second;
    }

    SendSystemEvent(bmsEventType, eventInfo);
}

void EventReport::SendScanSysEvent(BMSEventType bMSEventType)
{
    EventInfo eventInfo;
    eventInfo.timeStamp = BundleUtil::GetCurrentTimeMs();
    EventReport::SendSystemEvent(bMSEventType, eventInfo);
}

void EventReport::SendUserSysEvent(UserEventType userEventType, int32_t userId)
{
    EventInfo eventInfo;
    eventInfo.timeStamp = BundleUtil::GetCurrentTimeMs();
    eventInfo.userId = userId;
    eventInfo.userEventType = userEventType;
    EventReport::SendSystemEvent(BMSEventType::BMS_USER_EVENT, eventInfo);
}

void EventReport::SendComponentStateSysEventForException(const std::string &bundleName,
    const std::string &abilityName, int32_t userId, bool isEnable, int32_t appIndex)
{
    EventInfo eventInfo;
    eventInfo.bundleName = bundleName;
    eventInfo.abilityName = abilityName;
    eventInfo.userId = userId;
    eventInfo.isEnable = isEnable;
    eventInfo.appIndex = appIndex;
    BMSEventType bmsEventType = BMSEventType::BUNDLE_STATE_CHANGE_EXCEPTION;

    EventReport::SendSystemEvent(bmsEventType, eventInfo);
}

void EventReport::SendComponentStateSysEvent(const std::string &bundleName,
    const std::string &abilityName, int32_t userId, bool isEnable, int32_t appIndex)
{
    EventInfo eventInfo;
    eventInfo.bundleName = bundleName;
    eventInfo.abilityName = abilityName;
    eventInfo.userId = userId;
    eventInfo.isEnable = isEnable;
    eventInfo.appIndex = appIndex;
    BMSEventType bmsEventType = BMSEventType::BUNDLE_STATE_CHANGE;

    EventReport::SendSystemEvent(bmsEventType, eventInfo);
}

void EventReport::SendCleanCacheSysEvent(
    const std::string &bundleName, int32_t userId, bool isCleanCache, bool exception)
{
    EventInfo eventInfo;
    eventInfo.bundleName = bundleName;
    eventInfo.userId = userId;
    eventInfo.isCleanCache = isCleanCache;
    BMSEventType bmsEventType;
    if (exception) {
        bmsEventType = BMSEventType::BUNDLE_CLEAN_CACHE_EXCEPTION;
    } else {
        bmsEventType = BMSEventType::BUNDLE_CLEAN_CACHE;
    }

    EventReport::SendSystemEvent(bmsEventType, eventInfo);
}

void EventReport::SendQueryAbilityInfoByContinueTypeSysEvent(const std::string &bundleName,
    const std::string &abilityName, ErrCode errCode, int32_t userId, const std::string &continueType)
{
    EventInfo eventInfo;
    eventInfo.bundleName = bundleName;
    eventInfo.abilityName = abilityName;
    eventInfo.errCode = errCode;
    eventInfo.continueType = continueType;
    eventInfo.userId = userId,
    EventReport::SendSystemEvent(BMSEventType::QUERY_OF_CONTINUE_TYPE, eventInfo);
}

void EventReport::SendCpuSceneEvent(const std::string &processName, const int32_t sceneId)
{
    EventInfo eventInfo;
    eventInfo.sceneId = sceneId;
    eventInfo.processName = processName;
    eventInfo.timeStamp = BundleUtil::GetCurrentTimeMs();
    EventReport::SendSystemEvent(BMSEventType::CPU_SCENE_ENTRY, eventInfo);
}

void EventReport::SendFreeInstallEvent(const std::string &bundleName, const std::string &abilityName,
    const std::string &moduleName, bool isFreeInstall, int64_t timeStamp)
{
    EventInfo eventInfo;
    eventInfo.bundleName = bundleName;
    eventInfo.abilityName = abilityName;
    eventInfo.moduleName = moduleName;
    eventInfo.isFreeInstall = isFreeInstall;
    eventInfo.timeStamp = timeStamp;
    EventReport::SendSystemEvent(BMSEventType::FREE_INSTALL_EVENT, eventInfo);
}

void EventReport::SendDiskSpaceEvent(const std::string &fileName,
    int64_t freeSize, int32_t operationType)
{
    EventInfo eventInfo;
    eventInfo.fileName = fileName;
    eventInfo.freeSize = freeSize;
    eventInfo.operationType = operationType;
    EventReport::SendSystemEvent(BMSEventType::BMS_DISK_SPACE, eventInfo);
}

void EventReport::SendSystemEvent(BMSEventType bmsEventType, const EventInfo& eventInfo)
{
#ifdef HISYSEVENT_ENABLE
    InnerEventReport::SendSystemEvent(bmsEventType, eventInfo);
#else
    APP_LOGD("Hisysevent is disabled");
#endif
}
}  // namespace AppExecFwk
}  // namespace OHOS