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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_EVENT_REPORT_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_EVENT_REPORT_H

#include <string>
#include <vector>

#include "appexecfwk_errors.h"
#include "bundle_constants.h"

namespace OHOS {
namespace AppExecFwk {
enum class BMSEventType : uint8_t {
    UNKNOW = 0,
    /***********FAULT EVENT**************/
    BUNDLE_INSTALL_EXCEPTION,
    BUNDLE_UNINSTALL_EXCEPTION,
    BUNDLE_UPDATE_EXCEPTION,
    PRE_BUNDLE_RECOVER_EXCEPTION,
    BUNDLE_STATE_CHANGE_EXCEPTION,
    BUNDLE_CLEAN_CACHE_EXCEPTION,
    /***********BEHAVIOR EVENT***********/
    BOOT_SCAN_START,
    BOOT_SCAN_END,
    BUNDLE_INSTALL,
    BUNDLE_UNINSTALL,
    BUNDLE_UPDATE,
    PRE_BUNDLE_RECOVER,
    BUNDLE_STATE_CHANGE,
    BUNDLE_CLEAN_CACHE,
    BMS_USER_EVENT,
    APPLY_QUICK_FIX,
    CPU_SCENE_ENTRY,
    AOT_COMPILE_SUMMARY,
    AOT_COMPILE_RECORD,
    QUERY_OF_CONTINUE_TYPE,
    FREE_INSTALL_EVENT,
    BMS_DISK_SPACE,
    APP_CONTROL_RULE
};

enum class BundleEventType : uint8_t {
    UNKNOW = 0,
    INSTALL,
    UNINSTALL,
    UPDATE,
    RECOVER,
    QUICK_FIX
};

enum class InstallScene : uint8_t {
    NORMAL = 0,
    BOOT,
    REBOOT,
    CREATE_USER,
    REMOVE_USER,
};

enum HiSysEventType : uint8_t {
    FAULT     = 1,    // system fault event
    STATISTIC = 2,    // system statistic event
    SECURITY  = 3,    // system security event
    BEHAVIOR  = 4     // system behavior event
};

enum class UserEventType : uint8_t {
    UNKNOW = 0,
    CREATE_START,
    CREATE_END,
    REMOVE_START,
    REMOVE_END,
};

enum class ACTION_TYPE_ENUM : uint8_t {
    ACTION_TYPE_OF_INSTALL = 1,
    ACTION_TYPE_OF_RUNUING = 2,
    ACTION_TYPE_DISPOSE_STATUS = 3,
    ACTION_TYPE_DISPOSE_RULE = 4,
    ACTION_TYPE_UNINSTALL_DISPOSE_RULE = 5,
};

enum class OPERATION_TYPE_ENUM : uint8_t {
    OPERATION_TYPE_ADD_RULE = 1,
    OPERATION_TYPE_REMOVE_RULE = 2,
};

struct EventInfo {
    bool hideDesktopIcon = false;

    // only used for clean cache
    bool isCleanCache = true;

    // only used for component disable or enable
    bool isEnable = false;

    // only used for free install
    bool isFreeInstallMode = false;

    //for free install event
    bool isFreeInstall = false;

    // only used for preBundle
    bool isPreInstallApp = false;

    // AOT
    bool compileResult = false;
    InstallScene preBundleScene = InstallScene::NORMAL;

    // only used in user event
    UserEventType userEventType = UserEventType::UNKNOW;
    int32_t userId = Constants::INVALID_USERID;

    // for quick fix
    int32_t applyQuickFixFrequency = 0;

    // for install and uninstall
    int32_t callingUid = 0;
    int32_t appIndex = 0;
    int32_t sceneId = 0;
    int32_t operationType = 0;
    int32_t actionType = 0;
    uint32_t versionCode = 0;
    uint32_t successCnt = 0;

    // only used in fault event
    ErrCode errCode = ERR_OK;
    int64_t costTimeSeconds = 0;
    int64_t timeStamp = 0;
    int64_t freeSize = 0;
    std::string bundleName;
    std::string moduleName;
    std::string abilityName;
    std::string packageName;
    std::string applicationVersion;
    std::string callingAppId;
    std::string callingBundleName;
    // only for install
    std::string fingerprint;
    std::string appDistributionType;
    std::string compileMode;
    std::string failureReason;
    std::string processName;

    //for query of continue type
    std::string continueType;
    std::string fileName;
    std::string callingName;
    std::string rule;
    std::vector<std::string> filePath;
    std::vector<std::string> hashValue;
    std::vector<std::string> totalBundleNames;
    std::vector<std::string> appIds;

    void Reset()
    {
        userId = Constants::INVALID_USERID;
        bundleName.clear();
        moduleName.clear();
        abilityName.clear();
        packageName.clear();
        applicationVersion.clear();
        versionCode = 0;
        timeStamp = 0;
        preBundleScene = InstallScene::NORMAL;
        isCleanCache = false;
        isPreInstallApp = false;
        isFreeInstallMode = false;
        isEnable = false;
        errCode = ERR_OK;
        userEventType = UserEventType::UNKNOW;
        callingUid = 0;
        callingAppId.clear();
        callingBundleName.clear();
        filePath.clear();
        hashValue.clear();
        fingerprint.clear();
        hideDesktopIcon = false;
        appDistributionType.clear();
        applyQuickFixFrequency = 0;
        totalBundleNames.clear();
        successCnt = 0;
        compileMode.clear();
        compileResult = false;
        failureReason.clear();
        costTimeSeconds = 0;
        continueType.clear();
        sceneId = 0;
        processName.clear();
        appIndex = 0;
        isFreeInstall = false;
        fileName.clear();
        freeSize = 0;
        operationType = 0;
        appIds.clear();
        callingName.clear();
        actionType = 0;
        rule.clear();
    }
};

class EventReport {
public:
    /**
     * @brief Send bundle system events.
     * @param bundleEventType Indicates the bundle eventType.
     * @param eventInfo Indicates the eventInfo.
     */
    static void SendBundleSystemEvent(BundleEventType bundleEventType, const EventInfo& eventInfo);
    /**
     * @brief Send scan system events.
     * @param bMSEventType Indicates the bMSEventType.
     */
    static void SendScanSysEvent(BMSEventType bMSEventType);
    /**
     * @brief Send component diable or enable system events.
     * @param bundleName Indicates the bundleName.
     * @param abilityName Indicates the abilityName.
     * @param userId Indicates the userId.
     * @param isEnable Indicates the isEnable.
     * @param appIndex Indicates the app index for clone app.
     */
    static void SendComponentStateSysEventForException(const std::string &bundleName, const std::string &abilityName,
        int32_t userId, bool isEnable, int32_t appIndex, const std::string &callingName);
    /**
     * @brief Send component diable or enable system events.
     * @param bundleName Indicates the bundleName.
     * @param abilityName Indicates the abilityName.
     * @param userId Indicates the userId.
     * @param isEnable Indicates the isEnable.
     * @param appIndex Indicates the app index for clone app.
     */
    static void SendComponentStateSysEvent(const std::string &bundleName, const std::string &abilityName,
        int32_t userId, bool isEnable, int32_t appIndex, const std::string &callingName);
    /**
     * @brief Send clean cache system events.
     * @param bundleName Indicates the bundleName.
     * @param userId Indicates the userId.
     * @param isCleanCache Indicates the isCleanCache.
     * @param exception Indicates the exception.
     */
    static void SendCleanCacheSysEvent(
        const std::string &bundleName, int32_t userId, bool isCleanCache, bool exception);
    /**
     * @brief Send clean cache system events.
     * @param bundleName Indicates the bundleName.
     * @param userId Indicates the userId.
     * @param appIndex Indicates the appIndex.
     * @param isCleanCache Indicates the isCleanCache.
     * @param exception Indicates the exception.
     */
    static void SendCleanCacheSysEventWithIndex(
        const std::string &bundleName, int32_t userId, int32_t appIndex, bool isCleanCache, bool exception);
    /**
     * @brief Send system events.
     * @param eventType Indicates the bms eventInfo.
     * @param eventInfo Indicates the eventInfo.
     */
    static void SendSystemEvent(BMSEventType eventType, const EventInfo& eventInfo);
    /**
     * @brief Send user system events.
     * @param userEventType Indicates the userEventType.
     * @param userId Indicates the userId.
     */
    static void SendUserSysEvent(UserEventType userEventType, int32_t userId);

    /**
     * @brief Send query abilityInfos by continueType system events.
     * @param bundleName Indicates the bundleName.
     * @param abilityName Indicates the abilityName.
     * @param errCode code of result.
     * @param continueType Indicates the continueType.
     */
    static void SendQueryAbilityInfoByContinueTypeSysEvent(const std::string &bundleName,
        const std::string &abilityName, ErrCode errCode, int32_t userId, const std::string &continueType);

    static void SendCpuSceneEvent(const std::string &processName, const int32_t sceneId);
    /**
     *@brief send free install event
     *@param bundleName Indicates the bundleName.
     *@param abilityName Indicates the abilityName.
     *@param moduleName Indicates the moduleName.
     *@param isFreeInstall Indicates the isFreeInstall.
     *@param timeStamp Indicates the timeStamp.
     */
    static void SendFreeInstallEvent(const std::string &bundleName, const std::string &abilityName,
        const std::string &moduleName, bool isFreeInstall, int64_t timeStamp);

    /**
     * @brief Send system events the disk space in insufficient when an applicaiton is begin installed ir uninstall .
     * @param fileName file name.
     * @param freeSize free size.
     * @param operationType operation type.
     */
    static void SendDiskSpaceEvent(const std::string &fileName,
        int64_t freeSize, int32_t operationType);

    /**
     * @brief Send info when add or remove app contitol rule.
     * @param eventInfo report info.
     */
    static void SendAppControlRuleEvent(const EventInfo& eventInfo);
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_EVENT_REPORT_H
