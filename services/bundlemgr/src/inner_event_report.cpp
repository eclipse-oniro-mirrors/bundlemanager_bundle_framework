/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include "inner_event_report.h"

#include "app_log_wrapper.h"
#include "hisysevent.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
// event type
const std::string BUNDLE_INSTALL_EXCEPTION = "BUNDLE_INSTALL_EXCEPTION";
const std::string BUNDLE_UNINSTALL_EXCEPTION = "BUNDLE_UNINSTALL_EXCEPTION";
const std::string BUNDLE_UPDATE_EXCEPTION = "BUNDLE_UPDATE_EXCEPTION";
const std::string PRE_BUNDLE_RECOVER_EXCEPTION = "PRE_BUNDLE_RECOVER_EXCEPTION";
const std::string BUNDLE_STATE_CHANGE_EXCEPTION = "BUNDLE_STATE_CHANGE_EXCEPTION";
const std::string BUNDLE_CLEAN_CACHE_EXCEPTION = "BUNDLE_CLEAN_CACHE_EXCEPTION";

const std::string BOOT_SCAN_START = "BOOT_SCAN_START";
const std::string BOOT_SCAN_END = "BOOT_SCAN_END";
const std::string BUNDLE_INSTALL = "BUNDLE_INSTALL";
const std::string BUNDLE_UNINSTALL = "BUNDLE_UNINSTALL";
const std::string BUNDLE_UPDATE = "BUNDLE_UPDATE";
const std::string PRE_BUNDLE_RECOVER = "PRE_BUNDLE_RECOVER";
const std::string BUNDLE_STATE_CHANGE = "BUNDLE_STATE_CHANGE";
const std::string BUNDLE_CLEAN_CACHE = "BUNDLE_CLEAN_CACHE";
const std::string BMS_USER_EVENT = "BMS_USER_EVENT";
const std::string BUNDLE_QUICK_FIX = "BUNDLE_QUICK_FIX";
const std::string QUERY_OF_CONTINUE_TYPE = "QUERY_OF_CONTINUE_TYPE";
const std::string CPU_SCENE_ENTRY = "CPU_SCENE_ENTRY";
const std::string ACCESSTOKEN_PROCESS_NAME = "accesstoken_service";
static constexpr char PERFORMANCE_DOMAIN[] = "PERFORMANCE";

// event params
const std::string EVENT_PARAM_USERID = "USERID";
const std::string EVENT_PARAM_UID = "UID";
const std::string EVENT_PARAM_BUNDLE_NAME = "BUNDLE_NAME";
const std::string EVENT_PARAM_ERROR_CODE = "ERROR_CODE";
const std::string EVENT_PARAM_ABILITY_NAME = "ABILITY_NAME";
const std::string EVENT_PARAM_TIME = "TIME";
const std::string EVENT_PARAM_VERSION = "VERSION";
const std::string EVENT_PARAM_SCENE = "SCENE";
const std::string EVENT_PARAM_CLEAN_TYPE = "CLEAN_TYPE";
const std::string EVENT_PARAM_INSTALL_TYPE = "INSTALL_TYPE";
const std::string EVENT_PARAM_STATE = "STATE";
const std::string EVENT_PARAM_CALLING_BUNDLE_NAME = "CALLING_BUNDLE_NAME";
const std::string EVENT_PARAM_CALLING_UID = "CALLING_UID";
const std::string EVENT_PARAM_CALLING_APPID = "CALLING_APPID";
const std::string EVENT_PARAM_FINGERPRINT = "FINGERPRINT";
const std::string EVENT_PARAM_HIDE_DESKTOP_ICON = "HIDE_DESKTOP_ICON";
const std::string EVENT_PARAM_APP_DISTRIBUTION_TYPE = "APP_DISTRIBUTION_TYPE";
const std::string EVENT_PARAM_FILE_PATH = "FILE_PATH";
const std::string EVENT_PARAM_HASH_VALUE = "HASH_VALUE";
const std::string EVENT_PARAM_INSTALL_TIME = "INSTALL_TIME";
const std::string EVENT_PARAM_APPLY_QUICK_FIX_FREQUENCY = "APPLY_QUICK_FIX_FREQUENCY";
const std::string EVENT_PARAM_CONTINUE_TYPE = "CONTINUE_TYPE";
const std::string AOT_COMPILE_SUMMARY = "AOT_COMPILE_SUMMARY";
const std::string AOT_COMPILE_RECORD = "AOT_COMPILE_RECORD";
const std::string EVENT_PARAM_PACKAGE_NAME = "PACKAGE_NAME";
const std::string EVENT_PARAM_SCENE_ID = "SCENE_ID";
const std::string EVENT_PARAM_HAPPEN_TIME = "HAPPEN_TIME";

const std::string FREE_INSTALL_TYPE = "FreeInstall";
const std::string PRE_BUNDLE_INSTALL_TYPE = "PreBundleInstall";
const std::string NORMAL_INSTALL_TYPE = "normalInstall";
const std::string NORMAL_SCENE = "Normal";
const std::string BOOT_SCENE = "Boot";
const std::string REBOOT_SCENE = "Reboot";
const std::string CREATE_USER_SCENE = "CreateUser";
const std::string REMOVE_USER_SCENE = "RemoveUser";
const std::string CLEAN_CACHE = "cleanCache";
const std::string CLEAN_DATA = "cleanData";
const std::string ENABLE = "enable";
const std::string DISABLE = "disable";
const std::string APPLICATION = "application";
const std::string ABILITY = "ability";
const std::string TYPE = "TYPE";
const std::string UNKNOW = "Unknow";
const std::string CREATE_START = "CreateUserStart";
const std::string CREATE_END = "CreateUserEnd";
const std::string REMOVE_START = "RemoveUserStart";
const std::string REMOVE_END = "RemoveUserEnd";
// AOT
const std::string TOTAL_BUNDLE_NAMES = "totalBundleNames";
const std::string TOTAL_SIZE = "totalSize";
const std::string SUCCESS_SIZE = "successSize";
const std::string COST_TIME_SECONDS = "costTimeSeconds";
const std::string COMPILE_MODE = "compileMode";
const std::string COMPILE_RESULT = "compileResult";
const std::string FAILURE_REASON = "failureReason";

const std::unordered_map<InstallScene, std::string> INSTALL_SCENE_STR_MAP = {
    { InstallScene::NORMAL, NORMAL_SCENE },
    { InstallScene::BOOT, BOOT_SCENE },
    { InstallScene::REBOOT, REBOOT_SCENE },
    { InstallScene::CREATE_USER, CREATE_USER_SCENE },
    { InstallScene::REMOVE_USER, REMOVE_USER_SCENE },
};

const std::unordered_map<UserEventType, std::string> USER_TYPE_STR_MAP = {
    { UserEventType::CREATE_START, CREATE_START },
    { UserEventType::CREATE_END, CREATE_END },
    { UserEventType::REMOVE_START, REMOVE_START },
    { UserEventType::REMOVE_END, REMOVE_END },
};

std::string GetInstallType(const EventInfo& eventInfo)
{
    std::string installType = NORMAL_INSTALL_TYPE;
    if (eventInfo.isFreeInstallMode) {
        installType = FREE_INSTALL_TYPE;
    } else if (eventInfo.isPreInstallApp) {
        installType = PRE_BUNDLE_INSTALL_TYPE;
    }

    return installType;
}

std::string GetInstallScene(const EventInfo& eventInfo)
{
    std::string installScene = NORMAL_SCENE;
    auto iter = INSTALL_SCENE_STR_MAP.find(eventInfo.preBundleScene);
    if (iter != INSTALL_SCENE_STR_MAP.end()) {
        installScene = iter->second;
    }

    return installScene;
}

std::string GetUserEventType(const EventInfo& eventInfo)
{
    std::string type = UNKNOW;
    auto iter = USER_TYPE_STR_MAP.find(eventInfo.userEventType);
    if (iter != USER_TYPE_STR_MAP.end()) {
        type = iter->second;
    }

    return type;
}
}

std::unordered_map<BMSEventType, void (*)(const EventInfo& eventInfo)>
    InnerEventReport::bmsSysEventMap_ = {
        { BMSEventType::BUNDLE_INSTALL_EXCEPTION,
            [](const EventInfo& eventInfo) {
                InnerSendBundleInstallExceptionEvent(eventInfo);
            } },
        { BMSEventType::BUNDLE_UNINSTALL_EXCEPTION,
            [](const EventInfo& eventInfo) {
                InnerSendBundleUninstallExceptionEvent(eventInfo);
            } },
        { BMSEventType::BUNDLE_UPDATE_EXCEPTION,
            [](const EventInfo& eventInfo) {
                InnerSendBundleUpdateExceptionEvent(eventInfo);
            } },
        { BMSEventType::PRE_BUNDLE_RECOVER_EXCEPTION,
            [](const EventInfo& eventInfo) {
                InnerSendPreBundleRecoverExceptionEvent(eventInfo);
            } },
        { BMSEventType::BUNDLE_STATE_CHANGE_EXCEPTION,
            [](const EventInfo& eventInfo) {
                InnerSendBundleStateChangeExceptionEvent(eventInfo);
            } },
        { BMSEventType::BUNDLE_CLEAN_CACHE_EXCEPTION,
            [](const EventInfo& eventInfo) {
                InnerSendBundleCleanCacheExceptionEvent(eventInfo);
            } },
        { BMSEventType::BOOT_SCAN_START,
            [](const EventInfo& eventInfo) {
                InnerSendBootScanStartEvent(eventInfo);
            } },
        { BMSEventType::BOOT_SCAN_END,
            [](const EventInfo& eventInfo) {
                InnerSendBootScanEndEvent(eventInfo);
            } },
        { BMSEventType::BUNDLE_INSTALL,
            [](const EventInfo& eventInfo) {
                InnerSendBundleInstallEvent(eventInfo);
            } },
        { BMSEventType::BUNDLE_UNINSTALL,
            [](const EventInfo& eventInfo) {
                InnerSendBundleUninstallEvent(eventInfo);
            } },
        { BMSEventType::BUNDLE_UPDATE,
            [](const EventInfo& eventInfo) {
                InnerSendBundleUpdateEvent(eventInfo);
            } },
        { BMSEventType::PRE_BUNDLE_RECOVER,
            [](const EventInfo& eventInfo) {
                InnerSendPreBundleRecoverEvent(eventInfo);
            } },
        { BMSEventType::BUNDLE_STATE_CHANGE,
            [](const EventInfo& eventInfo) {
                InnerSendBundleStateChangeEvent(eventInfo);
            } },
        { BMSEventType::BUNDLE_CLEAN_CACHE,
            [](const EventInfo& eventInfo) {
                InnerSendBundleCleanCacheEvent(eventInfo);
            } },
        { BMSEventType::BMS_USER_EVENT,
            [](const EventInfo& eventInfo) {
                InnerSendUserEvent(eventInfo);
            } },
        { BMSEventType::APPLY_QUICK_FIX,
            [](const EventInfo& eventInfo) {
                InnerSendQuickFixEvent(eventInfo);
            } },
        { BMSEventType::QUERY_OF_CONTINUE_TYPE,
            [](const EventInfo& eventInfo) {
                InnerSendQueryOfContinueTypeEvent(eventInfo);
            } },
        { BMSEventType::AOT_COMPILE_SUMMARY,
            [](const EventInfo& eventInfo) {
                InnerSendAOTSummaryEvent(eventInfo);
            } },
        { BMSEventType::AOT_COMPILE_RECORD,
            [](const EventInfo& eventInfo) {
                InnerSendAOTRecordEvent(eventInfo);
            } },
        { BMSEventType::CPU_SCENE_ENTRY,
            [](const EventInfo& eventInfo) {
                InnerSendCpuSceneEvent(eventInfo);
            } }
    };

void InnerEventReport::SendSystemEvent(BMSEventType bmsEventType, const EventInfo& eventInfo)
{
    auto iter = bmsSysEventMap_.find(bmsEventType);
    if (iter == bmsSysEventMap_.end()) {
        return;
    }

    iter->second(eventInfo);
}

void InnerEventReport::InnerSendBundleInstallExceptionEvent(const EventInfo& eventInfo)
{
    InnerEventWrite(
        BUNDLE_INSTALL_EXCEPTION,
        HiSysEventType::FAULT,
        EVENT_PARAM_USERID, eventInfo.userId,
        EVENT_PARAM_BUNDLE_NAME, eventInfo.bundleName,
        EVENT_PARAM_VERSION, eventInfo.versionCode,
        EVENT_PARAM_INSTALL_TYPE, GetInstallType(eventInfo),
        EVENT_PARAM_SCENE, GetInstallScene(eventInfo),
        EVENT_PARAM_ERROR_CODE, eventInfo.errCode);
}

void InnerEventReport::InnerSendBundleUninstallExceptionEvent(const EventInfo& eventInfo)
{
    InnerEventWrite(
        BUNDLE_UNINSTALL_EXCEPTION,
        HiSysEventType::FAULT,
        EVENT_PARAM_USERID, eventInfo.userId,
        EVENT_PARAM_BUNDLE_NAME, eventInfo.bundleName,
        EVENT_PARAM_VERSION, eventInfo.versionCode,
        EVENT_PARAM_INSTALL_TYPE, GetInstallType(eventInfo),
        EVENT_PARAM_ERROR_CODE, eventInfo.errCode);
}

void InnerEventReport::InnerSendBundleUpdateExceptionEvent(const EventInfo& eventInfo)
{
    InnerEventWrite(
        BUNDLE_UPDATE_EXCEPTION,
        HiSysEventType::FAULT,
        EVENT_PARAM_USERID, eventInfo.userId,
        EVENT_PARAM_BUNDLE_NAME, eventInfo.bundleName,
        EVENT_PARAM_VERSION, eventInfo.versionCode,
        EVENT_PARAM_INSTALL_TYPE, GetInstallType(eventInfo),
        EVENT_PARAM_ERROR_CODE, eventInfo.errCode);
}

void InnerEventReport::InnerSendPreBundleRecoverExceptionEvent(const EventInfo& eventInfo)
{
    InnerEventWrite(
        PRE_BUNDLE_RECOVER_EXCEPTION,
        HiSysEventType::FAULT,
        EVENT_PARAM_USERID, eventInfo.userId,
        EVENT_PARAM_BUNDLE_NAME, eventInfo.bundleName,
        EVENT_PARAM_VERSION, eventInfo.versionCode,
        EVENT_PARAM_INSTALL_TYPE, PRE_BUNDLE_INSTALL_TYPE,
        EVENT_PARAM_ERROR_CODE, eventInfo.errCode);
}

void InnerEventReport::InnerSendBundleStateChangeExceptionEvent(const EventInfo& eventInfo)
{
    std::string type = eventInfo.abilityName.empty() ? APPLICATION : ABILITY;
    InnerEventWrite(
        BUNDLE_STATE_CHANGE_EXCEPTION,
        HiSysEventType::FAULT,
        EVENT_PARAM_USERID, eventInfo.userId,
        EVENT_PARAM_BUNDLE_NAME, eventInfo.bundleName,
        EVENT_PARAM_ABILITY_NAME, eventInfo.abilityName,
        TYPE, type);
}

void InnerEventReport::InnerSendBundleCleanCacheExceptionEvent(const EventInfo& eventInfo)
{
    std::string cleanType = eventInfo.isCleanCache ? CLEAN_CACHE : CLEAN_DATA;
    InnerEventWrite(
        BUNDLE_CLEAN_CACHE_EXCEPTION,
        HiSysEventType::FAULT,
        EVENT_PARAM_USERID, eventInfo.userId,
        EVENT_PARAM_BUNDLE_NAME, eventInfo.bundleName,
        EVENT_PARAM_CLEAN_TYPE, cleanType);
}

void InnerEventReport::InnerSendBootScanStartEvent(const EventInfo& eventInfo)
{
    InnerEventWrite(
        BOOT_SCAN_START,
        HiSysEventType::BEHAVIOR,
        EVENT_PARAM_TIME, eventInfo.timeStamp);
}

void InnerEventReport::InnerSendBootScanEndEvent(const EventInfo& eventInfo)
{
    InnerEventWrite(
        BOOT_SCAN_END,
        HiSysEventType::BEHAVIOR,
        EVENT_PARAM_TIME, eventInfo.timeStamp);
}

void InnerEventReport::InnerSendBundleInstallEvent(const EventInfo& eventInfo)
{
    InnerEventWrite(
        BUNDLE_INSTALL,
        HiSysEventType::BEHAVIOR,
        EVENT_PARAM_USERID, eventInfo.userId,
        EVENT_PARAM_BUNDLE_NAME, eventInfo.bundleName,
        EVENT_PARAM_VERSION, eventInfo.versionCode,
        EVENT_PARAM_APP_DISTRIBUTION_TYPE, eventInfo.appDistributionType,
        EVENT_PARAM_INSTALL_TIME, eventInfo.timeStamp,
        EVENT_PARAM_CALLING_UID, eventInfo.callingUid,
        EVENT_PARAM_CALLING_APPID, eventInfo.callingAppId,
        EVENT_PARAM_CALLING_BUNDLE_NAME, eventInfo.callingBundleName,
        EVENT_PARAM_FILE_PATH, eventInfo.filePath,
        EVENT_PARAM_HASH_VALUE, eventInfo.hashValue,
        EVENT_PARAM_FINGERPRINT, eventInfo.fingerprint,
        EVENT_PARAM_HIDE_DESKTOP_ICON, eventInfo.hideDesktopIcon,
        EVENT_PARAM_INSTALL_TYPE, GetInstallType(eventInfo),
        EVENT_PARAM_SCENE, GetInstallScene(eventInfo));
}

void InnerEventReport::InnerSendBundleUninstallEvent(const EventInfo& eventInfo)
{
    InnerEventWrite(
        BUNDLE_UNINSTALL,
        HiSysEventType::BEHAVIOR,
        EVENT_PARAM_USERID, eventInfo.userId,
        EVENT_PARAM_BUNDLE_NAME, eventInfo.bundleName,
        EVENT_PARAM_VERSION, eventInfo.versionCode,
        EVENT_PARAM_CALLING_UID, eventInfo.callingUid,
        EVENT_PARAM_CALLING_APPID, eventInfo.callingAppId,
        EVENT_PARAM_CALLING_BUNDLE_NAME, eventInfo.callingBundleName,
        EVENT_PARAM_INSTALL_TYPE, GetInstallType(eventInfo));
}

void InnerEventReport::InnerSendBundleUpdateEvent(const EventInfo& eventInfo)
{
    InnerEventWrite(
        BUNDLE_UPDATE,
        HiSysEventType::BEHAVIOR,
        EVENT_PARAM_USERID, eventInfo.userId,
        EVENT_PARAM_BUNDLE_NAME, eventInfo.bundleName,
        EVENT_PARAM_VERSION, eventInfo.versionCode,
        EVENT_PARAM_APP_DISTRIBUTION_TYPE, eventInfo.appDistributionType,
        EVENT_PARAM_INSTALL_TIME, eventInfo.timeStamp,
        EVENT_PARAM_CALLING_UID, eventInfo.callingUid,
        EVENT_PARAM_CALLING_APPID, eventInfo.callingAppId,
        EVENT_PARAM_CALLING_BUNDLE_NAME, eventInfo.callingBundleName,
        EVENT_PARAM_FILE_PATH, eventInfo.filePath,
        EVENT_PARAM_HASH_VALUE, eventInfo.hashValue,
        EVENT_PARAM_FINGERPRINT, eventInfo.fingerprint,
        EVENT_PARAM_HIDE_DESKTOP_ICON, eventInfo.hideDesktopIcon,
        EVENT_PARAM_INSTALL_TYPE, GetInstallType(eventInfo));
}

void InnerEventReport::InnerSendPreBundleRecoverEvent(const EventInfo& eventInfo)
{
    InnerEventWrite(
        PRE_BUNDLE_RECOVER,
        HiSysEventType::BEHAVIOR,
        EVENT_PARAM_USERID, eventInfo.userId,
        EVENT_PARAM_BUNDLE_NAME, eventInfo.bundleName,
        EVENT_PARAM_VERSION, eventInfo.versionCode,
        EVENT_PARAM_APP_DISTRIBUTION_TYPE, eventInfo.appDistributionType,
        EVENT_PARAM_INSTALL_TIME, eventInfo.timeStamp,
        EVENT_PARAM_CALLING_UID, eventInfo.callingUid,
        EVENT_PARAM_CALLING_APPID, eventInfo.callingAppId,
        EVENT_PARAM_CALLING_BUNDLE_NAME, eventInfo.callingBundleName,
        EVENT_PARAM_FINGERPRINT, eventInfo.fingerprint,
        EVENT_PARAM_HIDE_DESKTOP_ICON, eventInfo.hideDesktopIcon,
        EVENT_PARAM_INSTALL_TYPE, PRE_BUNDLE_INSTALL_TYPE);
}

void InnerEventReport::InnerSendBundleStateChangeEvent(const EventInfo& eventInfo)
{
    std::string type = eventInfo.abilityName.empty() ? APPLICATION : ABILITY;
    std::string state = eventInfo.isEnable ? ENABLE : DISABLE;
    InnerEventWrite(
        BUNDLE_STATE_CHANGE,
        HiSysEventType::BEHAVIOR,
        EVENT_PARAM_USERID, eventInfo.userId,
        EVENT_PARAM_BUNDLE_NAME, eventInfo.bundleName,
        EVENT_PARAM_ABILITY_NAME, eventInfo.abilityName,
        TYPE, type,
        EVENT_PARAM_STATE, state);
}

void InnerEventReport::InnerSendBundleCleanCacheEvent(const EventInfo& eventInfo)
{
    std::string cleanType = eventInfo.isCleanCache ? CLEAN_CACHE : CLEAN_DATA;
    InnerEventWrite(
        BUNDLE_CLEAN_CACHE,
        HiSysEventType::BEHAVIOR,
        EVENT_PARAM_USERID, eventInfo.userId,
        EVENT_PARAM_BUNDLE_NAME, eventInfo.bundleName,
        EVENT_PARAM_CLEAN_TYPE, cleanType);
}

void InnerEventReport::InnerSendUserEvent(const EventInfo& eventInfo)
{
    InnerEventWrite(
        BMS_USER_EVENT,
        HiSysEventType::BEHAVIOR,
        TYPE, GetUserEventType(eventInfo),
        EVENT_PARAM_USERID, eventInfo.userId,
        EVENT_PARAM_TIME, eventInfo.timeStamp);
}

void InnerEventReport::InnerSendQuickFixEvent(const EventInfo& eventInfo)
{
    InnerEventWrite(
        BUNDLE_QUICK_FIX,
        HiSysEventType::BEHAVIOR,
        EVENT_PARAM_BUNDLE_NAME, eventInfo.bundleName,
        EVENT_PARAM_APP_DISTRIBUTION_TYPE, eventInfo.appDistributionType,
        EVENT_PARAM_APPLY_QUICK_FIX_FREQUENCY, eventInfo.applyQuickFixFrequency,
        EVENT_PARAM_FILE_PATH, eventInfo.filePath,
        EVENT_PARAM_HASH_VALUE, eventInfo.hashValue);
}

void InnerEventReport::InnerSendQueryOfContinueTypeEvent(const EventInfo& eventInfo)
{
    InnerEventWrite(
        QUERY_OF_CONTINUE_TYPE,
        HiSysEventType::BEHAVIOR,
        EVENT_PARAM_BUNDLE_NAME, eventInfo.bundleName,
        EVENT_PARAM_ABILITY_NAME, eventInfo.abilityName,
        EVENT_PARAM_ERROR_CODE, eventInfo.errCode,
        EVENT_PARAM_USERID, eventInfo.userId,
        EVENT_PARAM_CONTINUE_TYPE, eventInfo.continueType);
}

void InnerEventReport::InnerSendAOTSummaryEvent(const EventInfo& eventInfo)
{
    InnerEventWrite(
        AOT_COMPILE_SUMMARY,
        HiSysEventType::BEHAVIOR,
        TOTAL_BUNDLE_NAMES, eventInfo.totalBundleNames,
        TOTAL_SIZE, eventInfo.totalBundleNames.size(),
        SUCCESS_SIZE, eventInfo.successCnt,
        COST_TIME_SECONDS, eventInfo.costTimeSeconds,
        EVENT_PARAM_TIME, eventInfo.timeStamp);
}

void InnerEventReport::InnerSendAOTRecordEvent(const EventInfo& eventInfo)
{
    InnerEventWrite(
        AOT_COMPILE_RECORD,
        HiSysEventType::BEHAVIOR,
        EVENT_PARAM_BUNDLE_NAME, eventInfo.bundleName,
        COMPILE_RESULT, eventInfo.compileResult,
        FAILURE_REASON, eventInfo.failureReason,
        COST_TIME_SECONDS, eventInfo.costTimeSeconds,
        COMPILE_MODE, eventInfo.compileMode,
        EVENT_PARAM_TIME, eventInfo.timeStamp);
}

void InnerEventReport::InnerSendCpuSceneEvent(const EventInfo& eventInfo)
{
    int32_t id = 1 << 1; // second scene
    HiSysEventWrite(
        PERFORMANCE_DOMAIN,
        CPU_SCENE_ENTRY,
        HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
        EVENT_PARAM_PACKAGE_NAME, ACCESSTOKEN_PROCESS_NAME,
        EVENT_PARAM_SCENE_ID, std::to_string(id).c_str(),
        EVENT_PARAM_HAPPEN_TIME, eventInfo.timeStamp);
}

template<typename... Types>
void InnerEventReport::InnerEventWrite(
    const std::string &eventName,
    HiSysEventType type,
    Types... keyValues)
{
    HiSysEventWrite(
        OHOS::HiviewDFX::HiSysEvent::Domain::BUNDLE_MANAGER,
        eventName,
        static_cast<OHOS::HiviewDFX::HiSysEvent::EventType>(type),
        keyValues...);
}
}  // namespace AppExecFwk
}  // namespace OHOS