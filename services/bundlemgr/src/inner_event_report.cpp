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

#include "hisysevent.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
// event type
constexpr const char* BUNDLE_INSTALL_EXCEPTION = "BUNDLE_INSTALL_EXCEPTION";
constexpr const char* BUNDLE_UNINSTALL_EXCEPTION = "BUNDLE_UNINSTALL_EXCEPTION";
constexpr const char* BUNDLE_UPDATE_EXCEPTION = "BUNDLE_UPDATE_EXCEPTION";
constexpr const char* PRE_BUNDLE_RECOVER_EXCEPTION = "PRE_BUNDLE_RECOVER_EXCEPTION";
constexpr const char* BUNDLE_STATE_CHANGE_EXCEPTION = "BUNDLE_STATE_CHANGE_EXCEPTION";
constexpr const char* BUNDLE_CLEAN_CACHE_EXCEPTION = "BUNDLE_CLEAN_CACHE_EXCEPTION";

constexpr const char* BOOT_SCAN_START = "BOOT_SCAN_START";
constexpr const char* BOOT_SCAN_END = "BOOT_SCAN_END";
constexpr const char* BUNDLE_INSTALL = "BUNDLE_INSTALL";
constexpr const char* BUNDLE_UNINSTALL = "BUNDLE_UNINSTALL";
constexpr const char* BUNDLE_UPDATE = "BUNDLE_UPDATE";
constexpr const char* PRE_BUNDLE_RECOVER = "PRE_BUNDLE_RECOVER";
constexpr const char* BUNDLE_STATE_CHANGE = "BUNDLE_STATE_CHANGE";
constexpr const char* BUNDLE_CLEAN_CACHE = "BUNDLE_CLEAN_CACHE";
constexpr const char* BMS_USER_EVENT = "BMS_USER_EVENT";
constexpr const char* BUNDLE_QUICK_FIX = "BUNDLE_QUICK_FIX";
constexpr const char* CPU_SCENE_ENTRY = "CPU_SCENE_ENTRY";
constexpr const char* FREE_INSTALL_EVENT = "FREE_INSTALL_EVENT";
static constexpr char PERFORMANCE_DOMAIN[] = "PERFORMANCE";
static constexpr char BUNDLE_MANAGER[] = "BUNDLE_MANAGER";
constexpr const char* AOT_COMPILE_SUMMARY = "AOT_COMPILE_SUMMARY";
constexpr const char* AOT_COMPILE_RECORD = "AOT_COMPILE_RECORD";
constexpr const char* QUERY_OF_CONTINUE_TYPE = "QUERY_OF_CONTINUE_TYPE";
constexpr const char* BMS_DISK_SPACE = "BMS_DISK_SPACE";
constexpr const char* APP_CONTROL_RULE = "APP_CONTROL_RULE";

// event params
const char* EVENT_PARAM_PNAMEID = "PNAMEID";
const char* EVENT_PARAM_PVERSIONID = "PVERSIONID";
const char* EVENT_PARAM_USERID = "USERID";
const char* EVENT_PARAM_UID = "UID";
const char* EVENT_PARAM_BUNDLE_NAME = "BUNDLE_NAME";
const char* EVENT_PARAM_ERROR_CODE = "ERROR_CODE";
const char* EVENT_PARAM_ABILITY_NAME = "ABILITY_NAME";
const char* EVENT_PARAM_TIME = "TIME";
const char* EVENT_PARAM_VERSION = "VERSION";
const char* EVENT_PARAM_SCENE = "SCENE";
const char* EVENT_PARAM_CLEAN_TYPE = "CLEAN_TYPE";
const char* EVENT_PARAM_INSTALL_TYPE = "INSTALL_TYPE";
const char* EVENT_PARAM_STATE = "STATE";
const char* EVENT_PARAM_CALLING_BUNDLE_NAME = "CALLING_BUNDLE_NAME";
const char* EVENT_PARAM_CALLING_UID = "CALLING_UID";
const char* EVENT_PARAM_CALLING_APPID = "CALLING_APPID";
const char* EVENT_PARAM_FINGERPRINT = "FINGERPRINT";
const char* EVENT_PARAM_HIDE_DESKTOP_ICON = "HIDE_DESKTOP_ICON";
const char* EVENT_PARAM_APP_DISTRIBUTION_TYPE = "APP_DISTRIBUTION_TYPE";
const char* EVENT_PARAM_FILE_PATH = "FILE_PATH";
const char* EVENT_PARAM_HASH_VALUE = "HASH_VALUE";
const char* EVENT_PARAM_INSTALL_TIME = "INSTALL_TIME";
const char* EVENT_PARAM_APPLY_QUICK_FIX_FREQUENCY = "APPLY_QUICK_FIX_FREQUENCY";
const char* EVENT_PARAM_CONTINUE_TYPE = "CONTINUE_TYPE";
const char* EVENT_PARAM_PACKAGE_NAME = "PACKAGE_NAME";
const char* EVENT_PARAM_SCENE_ID = "SCENE_ID";
const char* EVENT_PARAM_HAPPEN_TIME = "HAPPEN_TIME";
const char* EVENT_PARAM_MODULE_NAME = "MODULE_NAME";
const char* EVENT_PARAM_IS_FREE_INSTALL = "IS_FREE_INSTALL";
const char* EVENT_PARAM_APP_IDS = "APP_IDS";
const char* EVENT_PARAM_CALLING_NAME = "CALLING_NAME";
const char* EVENT_PARAM_OPERATION_TYPE = "OPERATION_TYPE";
const char* EVENT_PARAM_ACTION_TYPE = "ACTION_TYPE";
const char* EVENT_PARAM_RULE = "ACTION_RULE";
const char* EVENT_PARAM_APP_INDEX = "APP_INDEX";

const char* FREE_INSTALL_TYPE = "FreeInstall";
const char* PRE_BUNDLE_INSTALL_TYPE = "PreBundleInstall";
const char* NORMAL_INSTALL_TYPE = "normalInstall";
const char* NORMAL_SCENE = "Normal";
const char* BOOT_SCENE = "Boot";
const char* REBOOT_SCENE = "Reboot";
const char* CREATE_USER_SCENE = "CreateUser";
const char* REMOVE_USER_SCENE = "RemoveUser";
const char* CLEAN_CACHE = "cleanCache";
const char* CLEAN_DATA = "cleanData";
const char* ENABLE = "enable";
const char* DISABLE = "disable";
const char* APPLICATION = "application";
const char* ABILITY = "ability";
const char* TYPE = "TYPE";
const char* UNKNOW = "Unknow";
const char* CREATE_START = "CreateUserStart";
const char* CREATE_END = "CreateUserEnd";
const char* REMOVE_START = "RemoveUserStart";
const char* REMOVE_END = "RemoveUserEnd";
// AOT
const char* TOTAL_BUNDLE_NAMES = "totalBundleNames";
const char* TOTAL_SIZE = "totalSize";
const char* SUCCESS_SIZE = "successSize";
const char* COST_TIME_SECONDS = "costTimeSeconds";
const char* COMPILE_MODE = "compileMode";
const char* COMPILE_RESULT = "compileResult";
const char* FAILURE_REASON = "failureReason";
const char* FILE_NAME = "fileName";
const char* FREE_SIZE = "freeSize";
const char* OPERATION_TYPE = "operationType";

const InstallScene INSTALL_SCENE_STR_MAP_KEY[] = {
    InstallScene::NORMAL,
    InstallScene::BOOT,
    InstallScene::REBOOT,
    InstallScene::CREATE_USER,
    InstallScene::REMOVE_USER,
};
const char* g_installSceneStrMapValue[] = {
    NORMAL_SCENE,
    BOOT_SCENE,
    REBOOT_SCENE,
    CREATE_USER_SCENE,
    REMOVE_USER_SCENE,
};

const UserEventType USER_TYPE_STR_MAP_KEY[] = {
    UserEventType::CREATE_START,
    UserEventType::CREATE_END,
    UserEventType::REMOVE_START,
    UserEventType::REMOVE_END,
};
const char* g_userTypeStrMapValue[] = {
    CREATE_START,
    CREATE_END,
    REMOVE_START,
    REMOVE_END,
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
    size_t len = sizeof(INSTALL_SCENE_STR_MAP_KEY) / sizeof(INSTALL_SCENE_STR_MAP_KEY[0]);
    for (size_t i = 0; i < len; i++) {
        if (eventInfo.preBundleScene == INSTALL_SCENE_STR_MAP_KEY[i]) {
            installScene = g_installSceneStrMapValue[i];
            break;
        }
    }

    return installScene;
}

std::string GetUserEventType(const EventInfo& eventInfo)
{
    std::string type = UNKNOW;
    size_t len = sizeof(USER_TYPE_STR_MAP_KEY) / sizeof(USER_TYPE_STR_MAP_KEY[0]);
    for (size_t i = 0; i < len; i++) {
        if (eventInfo.userEventType == USER_TYPE_STR_MAP_KEY[i]) {
            type = g_userTypeStrMapValue[i];
            break;
        }
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
        { BMSEventType::CPU_SCENE_ENTRY,
            [](const EventInfo& eventInfo) {
                InnerSendCpuSceneEvent(eventInfo);
            } },
        { BMSEventType::AOT_COMPILE_SUMMARY,
            [](const EventInfo& eventInfo) {
                InnerSendAOTSummaryEvent(eventInfo);
            } },
        { BMSEventType::AOT_COMPILE_RECORD,
            [](const EventInfo& eventInfo) {
                InnerSendAOTRecordEvent(eventInfo);
            } },
        { BMSEventType::QUERY_OF_CONTINUE_TYPE,
            [](const EventInfo& eventInfo) {
                InnerSendQueryOfContinueTypeEvent(eventInfo);
            } },
        { BMSEventType::FREE_INSTALL_EVENT,
            [](const EventInfo& eventInfo) {
                InnerSendFreeInstallEvent(eventInfo);
            } },
        { BMSEventType::BMS_DISK_SPACE,
            [](const EventInfo& eventInfo) {
                InnerSendBmsDiskSpaceEvent(eventInfo);
            } },
        { BMSEventType::APP_CONTROL_RULE,
            [](const EventInfo& eventInfo) {
                InnerSendAppConitolRule(eventInfo);
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
    if (eventInfo.errCode == ERR_APPEXECFWK_INSTALL_ZERO_USER_WITH_NO_SINGLETON) {
        return;
    }
    InnerEventWrite(
        BUNDLE_INSTALL_EXCEPTION,
        HiSysEventType::FAULT,
        EVENT_PARAM_PNAMEID, eventInfo.packageName,
        EVENT_PARAM_PVERSIONID, eventInfo.applicationVersion,
        EVENT_PARAM_USERID, eventInfo.userId,
        EVENT_PARAM_BUNDLE_NAME, eventInfo.bundleName,
        EVENT_PARAM_VERSION, eventInfo.versionCode,
        EVENT_PARAM_INSTALL_TYPE, GetInstallType(eventInfo),
        EVENT_PARAM_SCENE, GetInstallScene(eventInfo),
        EVENT_PARAM_ERROR_CODE, eventInfo.errCode);
}

void InnerEventReport::InnerSendBundleUninstallExceptionEvent(const EventInfo& eventInfo)
{
    if (eventInfo.errCode == ERR_APPEXECFWK_UNINSTALL_MISSING_INSTALLED_BUNDLE ||
        eventInfo.errCode == ERR_APPEXECFWK_UNINSTALL_MISSING_INSTALLED_MODULE ||
        eventInfo.errCode == ERR_APPEXECFWK_UNINSTALL_SYSTEM_APP_ERROR) {
        return;
    }
    InnerEventWrite(
        BUNDLE_UNINSTALL_EXCEPTION,
        HiSysEventType::FAULT,
        EVENT_PARAM_PNAMEID, eventInfo.packageName,
        EVENT_PARAM_PVERSIONID, eventInfo.applicationVersion,
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
        EVENT_PARAM_PNAMEID, eventInfo.packageName,
        EVENT_PARAM_PVERSIONID, eventInfo.applicationVersion,
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
        EVENT_PARAM_PNAMEID, eventInfo.packageName,
        EVENT_PARAM_PVERSIONID, eventInfo.applicationVersion,
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
        EVENT_PARAM_PNAMEID, eventInfo.packageName,
        EVENT_PARAM_PVERSIONID, eventInfo.applicationVersion,
        EVENT_PARAM_USERID, eventInfo.userId,
        EVENT_PARAM_BUNDLE_NAME, eventInfo.bundleName,
        EVENT_PARAM_ABILITY_NAME, eventInfo.abilityName,
        TYPE, type,
        EVENT_PARAM_CALLING_BUNDLE_NAME, eventInfo.callingBundleName,
        EVENT_PARAM_APP_INDEX, eventInfo.appIndex);
}

void InnerEventReport::InnerSendBundleCleanCacheExceptionEvent(const EventInfo& eventInfo)
{
    std::string cleanType = eventInfo.isCleanCache ? CLEAN_CACHE : CLEAN_DATA;
    InnerEventWrite(
        BUNDLE_CLEAN_CACHE_EXCEPTION,
        HiSysEventType::FAULT,
        EVENT_PARAM_PNAMEID, eventInfo.packageName,
        EVENT_PARAM_PVERSIONID, eventInfo.applicationVersion,
        EVENT_PARAM_USERID, eventInfo.userId,
        EVENT_PARAM_BUNDLE_NAME, eventInfo.bundleName,
        EVENT_PARAM_CLEAN_TYPE, cleanType);
}

void InnerEventReport::InnerSendBootScanStartEvent(const EventInfo& eventInfo)
{
    InnerEventWrite(
        BOOT_SCAN_START,
        HiSysEventType::BEHAVIOR,
        EVENT_PARAM_PNAMEID, eventInfo.packageName,
        EVENT_PARAM_PVERSIONID, eventInfo.applicationVersion,
        EVENT_PARAM_TIME, eventInfo.timeStamp);
}

void InnerEventReport::InnerSendBootScanEndEvent(const EventInfo& eventInfo)
{
    InnerEventWrite(
        BOOT_SCAN_END,
        HiSysEventType::BEHAVIOR,
        EVENT_PARAM_PNAMEID, eventInfo.packageName,
        EVENT_PARAM_PVERSIONID, eventInfo.applicationVersion,
        EVENT_PARAM_TIME, eventInfo.timeStamp);
}

void InnerEventReport::InnerSendBundleInstallEvent(const EventInfo& eventInfo)
{
    InnerEventWrite(
        BUNDLE_INSTALL,
        HiSysEventType::BEHAVIOR,
        EVENT_PARAM_PNAMEID, eventInfo.packageName,
        EVENT_PARAM_PVERSIONID, eventInfo.applicationVersion,
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
        EVENT_PARAM_PNAMEID, eventInfo.packageName,
        EVENT_PARAM_PVERSIONID, eventInfo.applicationVersion,
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
        EVENT_PARAM_PNAMEID, eventInfo.packageName,
        EVENT_PARAM_PVERSIONID, eventInfo.applicationVersion,
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
        EVENT_PARAM_PNAMEID, eventInfo.packageName,
        EVENT_PARAM_PVERSIONID, eventInfo.applicationVersion,
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
        EVENT_PARAM_PNAMEID, eventInfo.packageName,
        EVENT_PARAM_PVERSIONID, eventInfo.applicationVersion,
        EVENT_PARAM_USERID, eventInfo.userId,
        EVENT_PARAM_BUNDLE_NAME, eventInfo.bundleName,
        EVENT_PARAM_ABILITY_NAME, eventInfo.abilityName,
        TYPE, type,
        EVENT_PARAM_STATE, state,
        EVENT_PARAM_CALLING_BUNDLE_NAME, eventInfo.callingBundleName,
        EVENT_PARAM_APP_INDEX, eventInfo.appIndex);
}

void InnerEventReport::InnerSendBundleCleanCacheEvent(const EventInfo& eventInfo)
{
    std::string cleanType = eventInfo.isCleanCache ? CLEAN_CACHE : CLEAN_DATA;
    InnerEventWrite(
        BUNDLE_CLEAN_CACHE,
        HiSysEventType::BEHAVIOR,
        EVENT_PARAM_PNAMEID, eventInfo.packageName,
        EVENT_PARAM_PVERSIONID, eventInfo.applicationVersion,
        EVENT_PARAM_USERID, eventInfo.userId,
        EVENT_PARAM_BUNDLE_NAME, eventInfo.bundleName,
        EVENT_PARAM_CLEAN_TYPE, cleanType);
}

void InnerEventReport::InnerSendUserEvent(const EventInfo& eventInfo)
{
    InnerEventWrite(
        BMS_USER_EVENT,
        HiSysEventType::BEHAVIOR,
        EVENT_PARAM_PNAMEID, eventInfo.packageName,
        EVENT_PARAM_PVERSIONID, eventInfo.applicationVersion,
        TYPE, GetUserEventType(eventInfo),
        EVENT_PARAM_USERID, eventInfo.userId,
        EVENT_PARAM_TIME, eventInfo.timeStamp);
}

void InnerEventReport::InnerSendQuickFixEvent(const EventInfo& eventInfo)
{
    InnerEventWrite(
        BUNDLE_QUICK_FIX,
        HiSysEventType::BEHAVIOR,
        EVENT_PARAM_PNAMEID, eventInfo.packageName,
        EVENT_PARAM_PVERSIONID, eventInfo.applicationVersion,
        EVENT_PARAM_BUNDLE_NAME, eventInfo.bundleName,
        EVENT_PARAM_APP_DISTRIBUTION_TYPE, eventInfo.appDistributionType,
        EVENT_PARAM_APPLY_QUICK_FIX_FREQUENCY, eventInfo.applyQuickFixFrequency,
        EVENT_PARAM_FILE_PATH, eventInfo.filePath,
        EVENT_PARAM_HASH_VALUE, eventInfo.hashValue);
}

void InnerEventReport::InnerSendCpuSceneEvent(const EventInfo& eventInfo)
{
    HiSysEventWrite(
        PERFORMANCE_DOMAIN,
        CPU_SCENE_ENTRY,
        HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
        EVENT_PARAM_PACKAGE_NAME, eventInfo.processName,
        EVENT_PARAM_SCENE_ID, std::to_string(eventInfo.sceneId).c_str(),
        EVENT_PARAM_HAPPEN_TIME, eventInfo.timeStamp);
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

void InnerEventReport::InnerSendFreeInstallEvent(const EventInfo& eventInfo)
{
    InnerEventWrite(
        FREE_INSTALL_EVENT,
        HiSysEventType::BEHAVIOR,
        EVENT_PARAM_BUNDLE_NAME, eventInfo.bundleName,
        EVENT_PARAM_ABILITY_NAME, eventInfo.abilityName,
        EVENT_PARAM_MODULE_NAME, eventInfo.moduleName,
        EVENT_PARAM_IS_FREE_INSTALL, eventInfo.isFreeInstall,
        EVENT_PARAM_TIME, eventInfo.timeStamp);
}

void InnerEventReport::InnerSendBmsDiskSpaceEvent(const EventInfo& eventInfo)
{
    InnerEventWrite(
        BMS_DISK_SPACE,
        HiSysEventType::BEHAVIOR,
        FILE_NAME, eventInfo.fileName,
        FREE_SIZE, eventInfo.freeSize,
        OPERATION_TYPE, eventInfo.operationType);
}

void InnerEventReport::InnerSendAppConitolRule(const EventInfo& eventInfo)
{
    InnerEventWrite(
        APP_CONTROL_RULE,
        HiSysEventType::BEHAVIOR,
        EVENT_PARAM_PNAMEID, eventInfo.packageName,
        EVENT_PARAM_PVERSIONID, eventInfo.applicationVersion,
        EVENT_PARAM_APP_IDS, eventInfo.appIds,
        EVENT_PARAM_USERID, eventInfo.userId,
        EVENT_PARAM_CALLING_NAME, eventInfo.callingName,
        EVENT_PARAM_OPERATION_TYPE, eventInfo.operationType,
        EVENT_PARAM_ACTION_TYPE, eventInfo.actionType,
        EVENT_PARAM_RULE, eventInfo.rule,
        EVENT_PARAM_APP_INDEX, eventInfo.appIndex);
}

template<typename... Types>
void InnerEventReport::InnerEventWrite(
    const std::string &eventName,
    HiSysEventType type,
    Types... keyValues)
{
    HiSysEventWrite(
        OHOS::HiviewDFX::HiSysEvent::Domain::BUNDLEMANAGER_UE,
        eventName,
        static_cast<OHOS::HiviewDFX::HiSysEvent::EventType>(type),
        keyValues...);
}
}  // namespace AppExecFwk
}  // namespace OHOS