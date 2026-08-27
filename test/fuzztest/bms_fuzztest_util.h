/*
* Copyright (c) 2025-2026 Huawei Device Co., Ltd.
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

#ifndef BMS_FUZZTEST_UTIL_H
#define BMS_FUZZTEST_UTIL_H

#include <fuzzer/FuzzedDataProvider.h>
#include <map>
#include <string>
#include <vector>

#include "ability_info.h"
#include "application_info.h"
#include "bundle_info.h"
#include "bundle_option.h"
#include "bundle_user_info.h"
#include "clean_cache_info.h"
#include "clone/clone_param.h"
#include "common_event_info.h"
#include "disposed_rule.h"
#include "extension_ability_info.h"
#include "form_info.h"
#include "hap_module_info.h"
#include "install_param.h"
#include "install_plugin_param.h"
#include "ipc_object_stub.h"
#include "message_parcel.h"
#include "shortcut_info.h"
#include "want.h"

namespace OHOS {
namespace AppExecFwk {
namespace BMSFuzzTestUtil {
// attack vectortype
enum AttackVector {
    ATTACK_PATH_TRAVERSAL = 0,   // pathtraversal
    ATTACK_SELINUX,              // SELinux privilege escalation
    ATTACK_CERT_BYPASS,          // signature bypass
    ATTACK_MEMCPY_OVERFLOW,      // memcpy_soverflow
    ATTACK_ARCHIVE,              // attack
};

// Forward declarations (defined later)
inline std::string GenAttackAwareString(FuzzedDataProvider& fdp, AttackVector type);
inline void WriteParcelString16(MessageParcel& parcel, const std::string& str);

constexpr size_t STRING_MAX_LENGTH = 128;
constexpr size_t ARRAY_MAX_LENGTH = 128;
constexpr int32_t MINUS_ONE = -1;
constexpr uint32_t CODE_MIN_ONE = 1;
constexpr uint32_t CODE_MAX_ONE = 1;
constexpr uint32_t CODE_MAX_TWO = 2;
constexpr uint32_t CODE_MAX_THREE = 3;
constexpr uint32_t CODE_MAX_FOUR = 4;
constexpr uint32_t CODE_MAX_FIVE = 5;
constexpr uint32_t ORIENTATION_MAX = 14;
constexpr uint32_t EXTENSION_ABILITY_MAX = 25;
const std::vector<int32_t> USERS {
    Constants::ANY_USERID,
    Constants::ALL_USERID,
    Constants::UNSPECIFIED_USERID,
    Constants::INVALID_USERID,
    Constants::U1,
    Constants::DEFAULT_USERID,
    Constants::START_USERID
};

std::vector<std::string> GenerateStringArray(FuzzedDataProvider& fdp, size_t arraySizeMax = ARRAY_MAX_LENGTH,
    size_t stringSize = STRING_MAX_LENGTH)
{
    std::vector<std::string> result;
    size_t arraySize = fdp.ConsumeIntegralInRange<size_t>(0, arraySizeMax);
    result.reserve(arraySize);

    for (size_t i = 0; i < arraySize; ++i) {
        std::string str = fdp.ConsumeRandomLengthString(stringSize);
        result.emplace_back(str);
    }

    return result;
}

void GenerateDynamicShortcutInfo(FuzzedDataProvider& fdp, const std::string& shortcutId, const std::string& bundleName,
    const int32_t appIndex, ShortcutInfo &shortcutInfo)
{
    shortcutInfo.isStatic = fdp.ConsumeBool();
    shortcutInfo.isHomeShortcut = fdp.ConsumeBool();
    shortcutInfo.isEnables = fdp.ConsumeBool();
    shortcutInfo.visible = fdp.ConsumeBool();
    shortcutInfo.iconId = fdp.ConsumeIntegral<uint32_t>();
    shortcutInfo.labelId = fdp.ConsumeIntegral<uint32_t>();
    shortcutInfo.appIndex = appIndex;
    shortcutInfo.sourceType = fdp.ConsumeIntegral<int32_t>();
    shortcutInfo.id = shortcutId;
    shortcutInfo.bundleName = bundleName;
    shortcutInfo.moduleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    shortcutInfo.hostAbility = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    shortcutInfo.icon = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    shortcutInfo.label = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    shortcutInfo.disableMessage = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
}

Resource GenerateResource(FuzzedDataProvider& fdp)
{
    Resource info;
    info.id = fdp.ConsumeIntegral<uint32_t>();
    info.bundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.moduleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    return info;
}

void GenerateApplicationInfo(FuzzedDataProvider& fdp, ApplicationInfo &applicationInfo)
{
    applicationInfo.keepAlive = fdp.ConsumeBool();
    applicationInfo.removable = fdp.ConsumeBool();
    applicationInfo.singleton = fdp.ConsumeBool();
    applicationInfo.userDataClearable = fdp.ConsumeBool();
    applicationInfo.allowAppRunWhenDeviceFirstLocked = fdp.ConsumeBool();
    applicationInfo.accessible = fdp.ConsumeBool();
    applicationInfo.runningResourcesApply = fdp.ConsumeBool();
    applicationInfo.associatedWakeUp = fdp.ConsumeBool();
    applicationInfo.hideDesktopIcon = fdp.ConsumeBool();
    applicationInfo.formVisibleNotify = fdp.ConsumeBool();
    applicationInfo.isSystemApp = fdp.ConsumeBool();
    applicationInfo.isLauncherApp = fdp.ConsumeBool();
    applicationInfo.isFreeInstallApp = fdp.ConsumeBool();
    applicationInfo.asanEnabled = fdp.ConsumeBool();
    applicationInfo.debug = fdp.ConsumeBool();
    applicationInfo.distributedNotificationEnabled = fdp.ConsumeBool();
    applicationInfo.installedForAllUser = fdp.ConsumeBool();
    applicationInfo.allowEnableNotification = fdp.ConsumeBool();
    applicationInfo.allowMultiProcess = fdp.ConsumeBool();
    applicationInfo.gwpAsanEnabled = fdp.ConsumeBool();
    applicationInfo.enabled = fdp.ConsumeBool();
    applicationInfo.hasPlugin = fdp.ConsumeBool();
    applicationInfo.multiProjects = fdp.ConsumeBool();
    applicationInfo.isCompressNativeLibs = fdp.ConsumeBool();
    applicationInfo.tsanEnabled = fdp.ConsumeBool();
    applicationInfo.hwasanEnabled = fdp.ConsumeBool();
    applicationInfo.ubsanEnabled = fdp.ConsumeBool();
    applicationInfo.cloudFileSyncEnabled = fdp.ConsumeBool();
    applicationInfo.cloudStructuredDataSyncEnabled = fdp.ConsumeBool();
    applicationInfo.needAppDetail = fdp.ConsumeBool();
    applicationInfo.versionCode = fdp.ConsumeIntegral<uint32_t>();
    applicationInfo.apiCompatibleVersion = fdp.ConsumeIntegral<uint32_t>();
    applicationInfo.iconId = fdp.ConsumeIntegral<uint32_t>();
    applicationInfo.labelId = fdp.ConsumeIntegral<uint32_t>();
    applicationInfo.descriptionId = fdp.ConsumeIntegral<uint32_t>();
    applicationInfo.accessTokenId = fdp.ConsumeIntegral<uint32_t>();
    applicationInfo.applicationReservedFlag = fdp.ConsumeIntegral<uint32_t>();
    applicationInfo.apiTargetVersion = fdp.ConsumeIntegral<int32_t>();
    applicationInfo.minCompatibleVersionCode = fdp.ConsumeIntegral<int32_t>();
    applicationInfo.supportedModes = fdp.ConsumeIntegral<int32_t>();
    applicationInfo.appIndex = fdp.ConsumeIntegral<int32_t>();
    applicationInfo.uid = fdp.ConsumeIntegral<int32_t>();
    applicationInfo.flags = fdp.ConsumeIntegral<int32_t>();
    applicationInfo.targetPriority = fdp.ConsumeIntegral<int32_t>();
    applicationInfo.overlayState = fdp.ConsumeIntegral<int32_t>();
    applicationInfo.maxChildProcess = fdp.ConsumeIntegral<int32_t>();
    applicationInfo.applicationFlags = fdp.ConsumeIntegral<int32_t>();
    applicationInfo.bundleType = static_cast<BundleType>(fdp.ConsumeIntegralInRange<int32_t>(0, CODE_MAX_FOUR));
    applicationInfo.crowdtestDeadline = fdp.ConsumeIntegral<int64_t>();
    applicationInfo.accessTokenIdEx = fdp.ConsumeIntegral<uint64_t>();
    applicationInfo.name = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    applicationInfo.bundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    applicationInfo.versionName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    applicationInfo.iconPath = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    applicationInfo.label = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    applicationInfo.description = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    applicationInfo.asanLogPath = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    applicationInfo.codePath = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    applicationInfo.dataDir = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    applicationInfo.dataBaseDir = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    applicationInfo.cacheDir = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    applicationInfo.entryDir = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    applicationInfo.apiReleaseType = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    applicationInfo.deviceId = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    applicationInfo.entityType = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    applicationInfo.process = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    applicationInfo.vendor = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    applicationInfo.appPrivilegeLevel = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    applicationInfo.appDistributionType = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    applicationInfo.appProvisionType = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    applicationInfo.nativeLibraryPath = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    applicationInfo.cpuAbi = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    applicationInfo.arkNativeFilePath = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    applicationInfo.arkNativeFileAbi = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    applicationInfo.fingerprint = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    applicationInfo.icon = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    applicationInfo.entryModuleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    applicationInfo.signatureKey = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    applicationInfo.targetBundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    applicationInfo.compileSdkVersion = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    applicationInfo.compileSdkType = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    applicationInfo.organization = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    applicationInfo.appDetailAbilityLibraryPath = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    applicationInfo.installSource = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    applicationInfo.configuration = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    applicationInfo.iconResource = GenerateResource(fdp);
    applicationInfo.labelResource = GenerateResource(fdp);
    applicationInfo.descriptionResource = GenerateResource(fdp);

    applicationInfo.allowCommonEvent = GenerateStringArray(fdp);
    applicationInfo.assetAccessGroups = GenerateStringArray(fdp);

    // assign when calling the get interface
    applicationInfo.permissions = GenerateStringArray(fdp);
    applicationInfo.moduleSourceDirs = GenerateStringArray(fdp);
    // Installation-free
    applicationInfo.targetBundleList = GenerateStringArray(fdp);
}

void GenerateSignatureInfo(FuzzedDataProvider& fdp, SignatureInfo &signatureInfo)
{
    signatureInfo.appId = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    signatureInfo.fingerprint = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    signatureInfo.appIdentifier = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    signatureInfo.certificate = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
}

template<typename T>
void GenerateAbilityInfo(FuzzedDataProvider& fdp, T &abilityInfo)
{
    abilityInfo.visible = fdp.ConsumeBool();
    abilityInfo.isLauncherAbility = fdp.ConsumeBool();
    abilityInfo.isNativeAbility = fdp.ConsumeBool();
    abilityInfo.enabled = fdp.ConsumeBool();
    abilityInfo.supportPipMode = fdp.ConsumeBool();
    abilityInfo.formEnabled = fdp.ConsumeBool();
    abilityInfo.removeMissionAfterTerminate = fdp.ConsumeBool();
    abilityInfo.allowSelfRedirect  = fdp.ConsumeBool();
    abilityInfo.isModuleJson = fdp.ConsumeBool();
    abilityInfo.isStageBasedModel = fdp.ConsumeBool();
    abilityInfo.continuable = fdp.ConsumeBool();
    // whether to display in the missions list
    abilityInfo.excludeFromMissions = fdp.ConsumeBool();
    abilityInfo.unclearableMission = fdp.ConsumeBool();
    abilityInfo.excludeFromDock = fdp.ConsumeBool();
    // whether to support recover UI interface
    abilityInfo.recoverable = fdp.ConsumeBool();
    abilityInfo.isolationProcess = fdp.ConsumeBool();
    abilityInfo.multiUserShared = fdp.ConsumeBool();
    abilityInfo.grantPermission = fdp.ConsumeBool();
    abilityInfo.directLaunch = fdp.ConsumeBool();

    abilityInfo.linkType = static_cast<LinkType>(fdp.ConsumeIntegralInRange<uint8_t>(0, CODE_MAX_TWO));
    abilityInfo.labelId = fdp.ConsumeIntegral<uint32_t>();
    abilityInfo.descriptionId = fdp.ConsumeIntegral<uint32_t>();
    abilityInfo.iconId = fdp.ConsumeIntegral<uint32_t>();
    abilityInfo.orientationId = fdp.ConsumeIntegral<uint32_t>();
    abilityInfo.formEntity = fdp.ConsumeIntegral<uint32_t>();
    abilityInfo.backgroundModes = fdp.ConsumeIntegral<uint32_t>();
    abilityInfo.startWindowId = fdp.ConsumeIntegral<uint32_t>();
    abilityInfo.startWindowIconId = fdp.ConsumeIntegral<uint32_t>();
    abilityInfo.startWindowBackgroundId = fdp.ConsumeIntegral<uint32_t>();
    abilityInfo.maxWindowWidth = fdp.ConsumeIntegral<uint32_t>();
    abilityInfo.minWindowWidth = fdp.ConsumeIntegral<uint32_t>();
    abilityInfo.maxWindowHeight = fdp.ConsumeIntegral<uint32_t>();
    abilityInfo.minWindowHeight = fdp.ConsumeIntegral<uint32_t>();
    abilityInfo.packageSize = fdp.ConsumeIntegral<uint32_t>();
    abilityInfo.minFormHeight = fdp.ConsumeIntegral<int32_t>();
    abilityInfo.defaultFormHeight = fdp.ConsumeIntegral<int32_t>();
    abilityInfo.minFormWidth = fdp.ConsumeIntegral<int32_t>();
    abilityInfo.defaultFormWidth = fdp.ConsumeIntegral<int32_t>();
    abilityInfo.priority = fdp.ConsumeIntegral<int32_t>();
    abilityInfo.appIndex = fdp.ConsumeIntegral<int32_t>();
    abilityInfo.uid = fdp.ConsumeIntegral<int32_t>();
    abilityInfo.type = static_cast<AbilityType>(fdp.ConsumeIntegralInRange<uint8_t>(0, CODE_MAX_FIVE));
    abilityInfo.extensionAbilityType =
        static_cast<ExtensionAbilityType>(fdp.ConsumeIntegralInRange<uint16_t>(0, EXTENSION_ABILITY_MAX));
    abilityInfo.orientation = static_cast<DisplayOrientation>(fdp.ConsumeIntegralInRange<uint8_t>(0, ORIENTATION_MAX));
    abilityInfo.launchMode = static_cast<LaunchMode>(fdp.ConsumeIntegralInRange<uint8_t>(0, CODE_MAX_TWO));
    abilityInfo.compileMode = static_cast<CompileMode>(fdp.ConsumeIntegralInRange<uint8_t>(0, CODE_MAX_ONE));
    abilityInfo.subType = static_cast<AbilitySubType>(fdp.ConsumeIntegralInRange<uint8_t>(0, CODE_MAX_ONE));

    abilityInfo.name = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);  // ability name, only the main class name
    abilityInfo.label = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    abilityInfo.description = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    abilityInfo.iconPath = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    abilityInfo.theme = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    abilityInfo.kind = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);  // ability category
    abilityInfo.extensionTypeName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    abilityInfo.srcPath = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    abilityInfo.srcLanguage = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);

    abilityInfo.process = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    abilityInfo.uri = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    abilityInfo.targetAbility = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    abilityInfo.readPermission = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    abilityInfo.writePermission = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);

    // set when install
    abilityInfo.package = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);  // the "module.package" in config.json
    abilityInfo.bundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    abilityInfo.moduleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);       // the "module.name" in config.json
    abilityInfo.applicationName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);  // the "bundlename" in config.json

    abilityInfo.codePath = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);         // ability main code path with name
    abilityInfo.resourcePath = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);     // resource path for resource init
    abilityInfo.hapPath = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);

    abilityInfo.srcEntrance = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);

    // configuration fields on startup page
    abilityInfo.startWindow = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    abilityInfo.startWindowIcon = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    abilityInfo.startWindowBackground = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    abilityInfo.preferMultiWindowOrientation = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);

    abilityInfo.originalBundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    abilityInfo.appName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    abilityInfo.privacyUrl = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    abilityInfo.privacyName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    abilityInfo.downloadUrl = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    abilityInfo.versionName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    abilityInfo.className = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    abilityInfo.originalClassName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    abilityInfo.uriPermissionMode = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    abilityInfo.uriPermissionPath = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    abilityInfo.libPath = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    abilityInfo.deviceId = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
}

void GenerateBundleInfo(FuzzedDataProvider& fdp, BundleInfo &bundleInfo)
{
    bundleInfo.isNewVersion = fdp.ConsumeBool();
    bundleInfo.isKeepAlive = fdp.ConsumeBool();
    bundleInfo.singleton = fdp.ConsumeBool();
    bundleInfo.isPreInstallApp = fdp.ConsumeBool();
    bundleInfo.isNativeApp = fdp.ConsumeBool();
    bundleInfo.entryInstallationFree = fdp.ConsumeBool();
    bundleInfo.isDifferentName = fdp.ConsumeBool();
    bundleInfo.versionCode = fdp.ConsumeIntegral<uint32_t>();
    bundleInfo.minCompatibleVersionCode = fdp.ConsumeIntegral<uint32_t>();
    bundleInfo.compatibleVersion = fdp.ConsumeIntegral<uint32_t>();
    bundleInfo.targetVersion = fdp.ConsumeIntegral<uint32_t>();
    bundleInfo.appIndex = fdp.ConsumeIntegral<int32_t>();
    bundleInfo.minSdkVersion = fdp.ConsumeIntegral<int32_t>();
    bundleInfo.maxSdkVersion = fdp.ConsumeIntegral<int32_t>();
    bundleInfo.overlayType = fdp.ConsumeIntegralInRange<int32_t>(CODE_MIN_ONE, CODE_MAX_THREE);
    bundleInfo.uid = fdp.ConsumeIntegral<int>();
    bundleInfo.gid = fdp.ConsumeIntegral<int>();
    bundleInfo.installTime = fdp.ConsumeIntegral<int64_t>();
    bundleInfo.updateTime = fdp.ConsumeIntegral<int64_t>();
    bundleInfo.firstInstallTime = fdp.ConsumeIntegral<int64_t>();
    bundleInfo.name = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    bundleInfo.versionName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    bundleInfo.vendor = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    bundleInfo.releaseType = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    bundleInfo.mainEntry = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    bundleInfo.entryModuleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    bundleInfo.appId = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    bundleInfo.cpuAbi = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    bundleInfo.seInfo = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    bundleInfo.label = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    bundleInfo.description = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    bundleInfo.jointUserId = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);

    GenerateSignatureInfo(fdp, bundleInfo.signatureInfo);

    bundleInfo.oldAppIds = GenerateStringArray(fdp);
    bundleInfo.hapModuleNames = GenerateStringArray(fdp);    // the "module.package" in each config.json
    bundleInfo.moduleNames = GenerateStringArray(fdp);       // the "module.name" in each config.json
    bundleInfo.modulePublicDirs = GenerateStringArray(fdp);  // the public paths of all modules of the application.
    bundleInfo.moduleDirs = GenerateStringArray(fdp);        // the paths of all modules of the application.
    bundleInfo.moduleResPaths = GenerateStringArray(fdp);    // the paths of all resources paths.

    bundleInfo.reqPermissions = GenerateStringArray(fdp);
    bundleInfo.defPermissions = GenerateStringArray(fdp);
}

void GenerateMap(FuzzedDataProvider& fdp, std::map<std::string, std::string> &data)
{
    // Generate number of key-value pairs (0 to 128)
    const size_t numPairs = fdp.ConsumeIntegralInRange<size_t>(0, ARRAY_MAX_LENGTH);

    for (size_t i = 0; i < numPairs; ++i) {
        // Generate key with maximum length 128
        const std::string key = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);

        // Generate value with maximum length 128
        const std::string value = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);

        // Insert into map (allow overwriting existing keys)
        data[key] = value;
    }
}

void GenerateDeviceFeatureMap(FuzzedDataProvider& fdp, std::map<std::string, std::vector<std::string>> &data)
{
    // Generate number of key-value pairs (0 to 128)
    const size_t numPairs = fdp.ConsumeIntegralInRange<size_t>(0, ARRAY_MAX_LENGTH);

    for (size_t i = 0; i < numPairs; ++i) {
        // Generate key with maximum length 128
        const std::string key = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);

        // Generate vector value
        const std::vector<std::string> value = GenerateStringArray(fdp);

        // Insert into map (allow overwriting existing keys)
        data[key] = value;
    }
}

void GenerateInstallParam(FuzzedDataProvider& fdp, InstallParam &installParam)
{
    installParam.isKeepData = fdp.ConsumeBool();
    installParam.needSavePreInstallInfo = fdp.ConsumeBool();
    installParam.isPreInstallApp = fdp.ConsumeBool();
    installParam.removable = fdp.ConsumeBool();
    // whether need copy hap to install path
    installParam.copyHapToInstallPath = fdp.ConsumeBool();
    // is aging Cause uninstall.
    installParam.isAgingUninstall = fdp.ConsumeBool();
    installParam.needSendEvent = fdp.ConsumeBool();
    installParam.withCopyHaps = fdp.ConsumeBool();
    // for MDM self update
    installParam.isSelfUpdate = fdp.ConsumeBool();
    // is shell token
    installParam.isCallByShell = fdp.ConsumeBool();
    // for AOT
    installParam.isOTA = fdp.ConsumeBool();
    installParam.concentrateSendEvent = fdp.ConsumeBool();
    installParam.isRemoveUser = fdp.ConsumeBool();
    installParam.isFirstBootInstall = fdp.ConsumeBool();
    installParam.isCreateUser = fdp.ConsumeBool();
    installParam.allUser = fdp.ConsumeBool();
    installParam.isPatch = fdp.ConsumeBool();
    installParam.isDataPreloadHap = fdp.ConsumeBool();
    installParam.userId = fdp.ConsumeIntegral<int32_t>();
    installParam.installFlag =
        static_cast<InstallFlag>(fdp.ConsumeIntegralInRange<int8_t>(0, CODE_MAX_ONE));
    installParam.installLocation =
        static_cast<InstallLocation>(fdp.ConsumeIntegralInRange<int8_t>(CODE_MIN_ONE, CODE_MAX_TWO));
    installParam.installBundlePermissionStatus =
        static_cast<PermissionStatus>(fdp.ConsumeIntegralInRange<int8_t>(0, CODE_MAX_TWO));
    installParam.installEnterpriseBundlePermissionStatus =
        static_cast<PermissionStatus>(fdp.ConsumeIntegralInRange<int8_t>(0, CODE_MAX_TWO));
    installParam.installEtpNormalBundlePermissionStatus =
        static_cast<PermissionStatus>(fdp.ConsumeIntegralInRange<int8_t>(0, CODE_MAX_TWO));
    installParam.installEtpMdmBundlePermissionStatus =
        static_cast<PermissionStatus>(fdp.ConsumeIntegralInRange<int8_t>(0, CODE_MAX_TWO));
    installParam.installInternaltestingBundlePermissionStatus =
        static_cast<PermissionStatus>(fdp.ConsumeIntegralInRange<int8_t>(0, CODE_MAX_TWO));
    installParam.installUpdateSelfBundlePermissionStatus =
        static_cast<PermissionStatus>(fdp.ConsumeIntegralInRange<int8_t>(0, CODE_MAX_TWO));
    installParam.preinstallSourceFlag = static_cast<ApplicationInfoFlag>(fdp.ConsumeIntegral<int32_t>());
    installParam.crowdtestDeadline = fdp.ConsumeIntegral<int64_t>(); // for crowdtesting type hap
    // Indicates the distribution type
    installParam.specifiedDistributionType = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    // Indicates the additional Info
    installParam.additionalInfo = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    installParam.appIdentifier = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    // shared bundle directory paths
    installParam.sharedBundleDirPaths = GenerateStringArray(fdp);
    GenerateMap(fdp, installParam.parameters);
    GenerateMap(fdp, installParam.pgoParams);
    GenerateMap(fdp, installParam.hashParams);
    GenerateMap(fdp, installParam.verifyCodeParams);
}

// InstallPluginParam: checkactualfieldsandconstruct
void GenerateInstallPluginParam(FuzzedDataProvider& fdp, InstallPluginParam &installPluginParam)
{
    installPluginParam.userId = fdp.ConsumeIntegral<int32_t>();
    GenerateMap(fdp, installPluginParam.parameters);
}

void GenerateBundleUserInfo(FuzzedDataProvider& fdp, BundleUserInfo &bundleUserInfo)
{
    bundleUserInfo.enabled = fdp.ConsumeBool();
    bundleUserInfo.userId = fdp.ConsumeIntegral<int32_t>();
    bundleUserInfo.setEnabledCaller = GenAttackAwareString(fdp, ATTACK_PATH_TRAVERSAL);
    bundleUserInfo.disabledAbilities = GenerateStringArray(fdp);
    bundleUserInfo.overlayModulesState = GenerateStringArray(fdp);
}

void GenerateCompatibleApplicationInfo(FuzzedDataProvider& fdp, CompatibleApplicationInfo &compatibleApplicationInfo)
{
    compatibleApplicationInfo.isCompressNativeLibs = fdp.ConsumeBool();
    compatibleApplicationInfo.systemApp = fdp.ConsumeBool();
    compatibleApplicationInfo.enabled = fdp.ConsumeBool();
    compatibleApplicationInfo.debug = fdp.ConsumeBool();
    compatibleApplicationInfo.iconId = fdp.ConsumeIntegral<uint32_t>();
    compatibleApplicationInfo.labelId = fdp.ConsumeIntegral<uint32_t>();
    compatibleApplicationInfo.descriptionId = fdp.ConsumeIntegral<uint32_t>();
    compatibleApplicationInfo.supportedModes = fdp.ConsumeIntegral<int32_t>(); // supported modes.
    // items set when installing.
    compatibleApplicationInfo.name = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    compatibleApplicationInfo.icon = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    compatibleApplicationInfo.label = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    compatibleApplicationInfo.description = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    compatibleApplicationInfo.cpuAbi = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    compatibleApplicationInfo.process = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    compatibleApplicationInfo.permissions = GenerateStringArray(fdp);
}

void GenerateCompatibleAbilityInfo(FuzzedDataProvider& fdp, CompatibleAbilityInfo &compatibleAbilityInfo)
{
    compatibleAbilityInfo.visible = fdp.ConsumeBool();
    compatibleAbilityInfo.formEnabled = fdp.ConsumeBool();
    compatibleAbilityInfo.multiUserShared = fdp.ConsumeBool();
    compatibleAbilityInfo.supportPipMode = fdp.ConsumeBool();
    compatibleAbilityInfo.grantPermission = fdp.ConsumeBool();
    compatibleAbilityInfo.directLaunch = fdp.ConsumeBool();
    compatibleAbilityInfo.enabled = fdp.ConsumeBool();
    compatibleAbilityInfo.backgroundModes = fdp.ConsumeIntegral<uint32_t>();
    compatibleAbilityInfo.packageSize = fdp.ConsumeIntegral<uint32_t>();

    // form widget info
    compatibleAbilityInfo.formEntity = 1; // where form can be displayed

    compatibleAbilityInfo.iconId = fdp.ConsumeIntegral<uint32_t>();
    compatibleAbilityInfo.labelId = fdp.ConsumeIntegral<uint32_t>();
    compatibleAbilityInfo.descriptionId = fdp.ConsumeIntegral<uint32_t>();
    compatibleAbilityInfo.minFormHeight = fdp.ConsumeIntegral<int32_t>(); // minimum height of ability.
    compatibleAbilityInfo.defaultFormHeight = fdp.ConsumeIntegral<int32_t>(); // default height of ability.
    compatibleAbilityInfo.minFormWidth = fdp.ConsumeIntegral<int32_t>(); // minimum width of ability.
    compatibleAbilityInfo.defaultFormWidth = fdp.ConsumeIntegral<int32_t>(); // default width of ability.
    // deprecated: remove this field in new package format.
    compatibleAbilityInfo.type = static_cast<AbilityType>(fdp.ConsumeIntegralInRange<uint8_t>(0, CODE_MAX_FIVE));
    compatibleAbilityInfo.subType = static_cast<AbilitySubType>(fdp.ConsumeIntegralInRange<uint8_t>(0, CODE_MAX_ONE));
    compatibleAbilityInfo.orientation =
        static_cast<DisplayOrientation>(fdp.ConsumeIntegralInRange<uint8_t>(0, ORIENTATION_MAX));
    compatibleAbilityInfo.launchMode = static_cast<LaunchMode>(fdp.ConsumeIntegralInRange<uint8_t>(0, CODE_MAX_TWO));
    // deprecated: ability code class simple name, use 'className' instead.
    compatibleAbilityInfo.package = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    compatibleAbilityInfo.name = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    compatibleAbilityInfo.label = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH); // display name on screen.
    compatibleAbilityInfo.description = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    compatibleAbilityInfo.iconPath = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    // used as icon data (base64) for WEB Ability.
    compatibleAbilityInfo.uri = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH); // uri of ability.
    compatibleAbilityInfo.moduleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    // indicates the name of the .hap package to which the capability belongs.
    compatibleAbilityInfo.process = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    compatibleAbilityInfo.targetAbility = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    compatibleAbilityInfo.appName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    compatibleAbilityInfo.privacyUrl = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    compatibleAbilityInfo.privacyName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    compatibleAbilityInfo.downloadUrl = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    compatibleAbilityInfo.versionName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    compatibleAbilityInfo.readPermission = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    compatibleAbilityInfo.writePermission = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    compatibleAbilityInfo.uriPermissionMode = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    compatibleAbilityInfo.uriPermissionPath = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);

    // set when install
    compatibleAbilityInfo.bundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    compatibleAbilityInfo.className = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    compatibleAbilityInfo.originalClassName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    compatibleAbilityInfo.deviceId = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    compatibleAbilityInfo.permissions = GenerateStringArray(fdp);
    compatibleAbilityInfo.deviceTypes = GenerateStringArray(fdp);
    compatibleAbilityInfo.deviceCapabilities = GenerateStringArray(fdp);
    GenerateCompatibleApplicationInfo(fdp, compatibleAbilityInfo.applicationInfo);
}

void GenerateExtensionAbilityInfo(FuzzedDataProvider& fdp, ExtensionAbilityInfo &extensionAbilityInfo)
{
    extensionAbilityInfo.visible = fdp.ConsumeBool();

    // set when install
    extensionAbilityInfo.enabled = fdp.ConsumeBool();

    extensionAbilityInfo.needCreateSandbox = fdp.ConsumeBool();
    extensionAbilityInfo.iconId = fdp.ConsumeIntegral<uint32_t>();
    extensionAbilityInfo.labelId = fdp.ConsumeIntegral<uint32_t>();
    extensionAbilityInfo.descriptionId = fdp.ConsumeIntegral<uint32_t>();
    extensionAbilityInfo.priority = fdp.ConsumeIntegral<int32_t>();
    // for NAPI, save self query cache
    extensionAbilityInfo.uid = fdp.ConsumeIntegral<int32_t>();
    extensionAbilityInfo.appIndex = fdp.ConsumeIntegral<int32_t>();
    extensionAbilityInfo.type =
        static_cast<ExtensionAbilityType>(fdp.ConsumeIntegralInRange<uint16_t>(0, ARRAY_MAX_LENGTH));
    extensionAbilityInfo.compileMode = static_cast<CompileMode>(fdp.ConsumeIntegralInRange<uint8_t>(0, CODE_MIN_ONE));
    extensionAbilityInfo.extensionProcessMode =
        static_cast<ExtensionProcessMode>(fdp.ConsumeIntegralInRange<int8_t>(-1, CODE_MAX_THREE));
    extensionAbilityInfo.bundleName = GenAttackAwareString(fdp, ATTACK_PATH_TRAVERSAL);
    extensionAbilityInfo.moduleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    extensionAbilityInfo.name = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    extensionAbilityInfo.srcEntrance = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    extensionAbilityInfo.icon = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    extensionAbilityInfo.label = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    extensionAbilityInfo.description = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    extensionAbilityInfo.readPermission = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    extensionAbilityInfo.writePermission = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    extensionAbilityInfo.uri = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    extensionAbilityInfo.extensionTypeName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    extensionAbilityInfo.resourcePath = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    extensionAbilityInfo.hapPath = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    extensionAbilityInfo.process = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    extensionAbilityInfo.customProcess = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    std::vector<std::string> permissions = GenerateStringArray(fdp);
    std::vector<std::string> appIdentifierAllowList = GenerateStringArray(fdp);
    std::vector<std::string> dataGroupIds = GenerateStringArray(fdp);
    std::vector<std::string> validDataGroupIds = GenerateStringArray(fdp);
    GenerateApplicationInfo(fdp, extensionAbilityInfo.applicationInfo);
}

void GenerateFormInfo(FuzzedDataProvider& fdp, FormInfo &formInfo)
{
    formInfo.defaultFlag = fdp.ConsumeBool();
    formInfo.formVisibleNotify = fdp.ConsumeBool();
    formInfo.updateEnabled = fdp.ConsumeBool();
    formInfo.isStatic = fdp.ConsumeBool();
    formInfo.dataProxyEnabled = fdp.ConsumeBool();
    formInfo.isDynamic = fdp.ConsumeBool();
    formInfo.transparencyEnabled = fdp.ConsumeBool();
    formInfo.fontScaleFollowSystem = fdp.ConsumeBool();
    formInfo.enableBlurBackground = fdp.ConsumeBool();
    formInfo.colorMode = static_cast<FormsColorMode>(fdp.ConsumeIntegralInRange<uint8_t>(0, CODE_MIN_ONE));
    formInfo.renderingMode = static_cast<FormsRenderingMode>(fdp.ConsumeIntegralInRange<uint8_t>(0, CODE_MAX_TWO));
    formInfo.displayNameId = fdp.ConsumeIntegral<uint32_t>();
    formInfo.descriptionId = fdp.ConsumeIntegral<uint32_t>();
    formInfo.versionCode = fdp.ConsumeIntegral<uint32_t>();
    formInfo.updateDuration = fdp.ConsumeIntegral<int32_t>();
    formInfo.defaultDimension = fdp.ConsumeIntegral<int32_t>();
    formInfo.privacyLevel = fdp.ConsumeIntegral<int32_t>();
    formInfo.type = static_cast<FormType>(fdp.ConsumeIntegralInRange<uint8_t>(0, CODE_MAX_TWO));
    formInfo.uiSyntax = static_cast<FormType>(fdp.ConsumeIntegralInRange<uint8_t>(0, CODE_MAX_TWO));
    formInfo.bundleType = static_cast<BundleType>(fdp.ConsumeIntegralInRange<uint8_t>(0, CODE_MAX_FOUR));
    formInfo.package = GenAttackAwareString(fdp, ATTACK_PATH_TRAVERSAL);
    formInfo.bundleName = GenAttackAwareString(fdp, ATTACK_PATH_TRAVERSAL);
    formInfo.originalBundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    formInfo.relatedBundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    formInfo.moduleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    // the "module.distro.moduleName" in config.json
    formInfo.abilityName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    formInfo.name = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    formInfo.displayName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    formInfo.description = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    formInfo.jsComponentName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    formInfo.deepLink = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    formInfo.formConfigAbility = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    formInfo.scheduledUpdateTime = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    formInfo.multiScheduledUpdateTime = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    formInfo.src = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
}

void GenerateShortcutInfo(FuzzedDataProvider& fdp, ShortcutInfo &shortcutInfo)
{
    shortcutInfo.isStatic = fdp.ConsumeBool();
    shortcutInfo.isHomeShortcut = fdp.ConsumeBool();
    shortcutInfo.isEnables = fdp.ConsumeBool();
    shortcutInfo.visible = fdp.ConsumeBool();
    shortcutInfo.iconId = fdp.ConsumeIntegral<uint32_t>();
    shortcutInfo.labelId = fdp.ConsumeIntegral<uint32_t>();
    shortcutInfo.appIndex = fdp.ConsumeIntegral<int32_t>();
    shortcutInfo.sourceType = fdp.ConsumeIntegral<int32_t>();
    shortcutInfo.id = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    shortcutInfo.bundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    shortcutInfo.moduleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    shortcutInfo.hostAbility = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    shortcutInfo.icon = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    shortcutInfo.label = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    shortcutInfo.disableMessage = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
}

int32_t GenerateRandomUser(FuzzedDataProvider& fdp)
{
    uint8_t usersSize = USERS.size();
    if (usersSize == 0) {
        return Constants::START_USERID; // No users available, return 100
    }
    uint8_t index = fdp.ConsumeIntegralInRange<uint8_t>(0, usersSize) % usersSize; // 0 to size-1
    return USERS[index];
}

void GenerateHapModuleInfo(FuzzedDataProvider& fdp, HapModuleInfo &hapModuleInfo)
{
    hapModuleInfo.compressNativeLibs = fdp.ConsumeBool();
    hapModuleInfo.isLibIsolated = fdp.ConsumeBool();
    hapModuleInfo.deliveryWithInstall = fdp.ConsumeBool();
    hapModuleInfo.installationFree = fdp.ConsumeBool();
    hapModuleInfo.isModuleJson = fdp.ConsumeBool();
    hapModuleInfo.isStageBasedModel = fdp.ConsumeBool();
    hapModuleInfo.hasIntent = fdp.ConsumeBool();
    hapModuleInfo.resizeable = fdp.ConsumeBool();
    hapModuleInfo.descriptionId = fdp.ConsumeIntegral<uint32_t>();
    hapModuleInfo.iconId = fdp.ConsumeIntegral<uint32_t>();
    hapModuleInfo.labelId = fdp.ConsumeIntegral<uint32_t>();
    hapModuleInfo.upgradeFlag = fdp.ConsumeIntegral<int32_t>();
    hapModuleInfo.supportedModes = fdp.ConsumeIntegral<int>();
    hapModuleInfo.colorMode =
        static_cast<ModuleColorMode>(fdp.ConsumeIntegralInRange<int8_t>(MINUS_ONE, CODE_MAX_ONE));
    hapModuleInfo.moduleType = static_cast<ModuleType>(fdp.ConsumeIntegralInRange<uint8_t>(0, CODE_MAX_THREE));
    hapModuleInfo.compileMode = fdp.ConsumeBool() ? CompileMode::ES_MODULE : CompileMode::JS_BUNDLE;
    hapModuleInfo.aotCompileStatus =
        static_cast<AOTCompileStatus>(fdp.ConsumeIntegralInRange<uint8_t>(0, CODE_MAX_FIVE));
    hapModuleInfo.isolationMode = static_cast<IsolationMode>(fdp.ConsumeIntegralInRange<uint8_t>(0, CODE_MAX_THREE));
    hapModuleInfo.name = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);        // module.name in config.json
    hapModuleInfo.package = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    hapModuleInfo.moduleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    hapModuleInfo.description = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    hapModuleInfo.iconPath = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    hapModuleInfo.label = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    hapModuleInfo.backgroundImg = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    hapModuleInfo.mainAbility = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    hapModuleInfo.srcPath = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    hapModuleInfo.hashValue = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    hapModuleInfo.hapPath = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    hapModuleInfo.nativeLibraryPath = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    hapModuleInfo.cpuAbi = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    // new version fields
    hapModuleInfo.bundleName = GenAttackAwareString(fdp, ATTACK_PATH_TRAVERSAL);
    hapModuleInfo.mainElementName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    hapModuleInfo.pages = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    hapModuleInfo.systemTheme = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    hapModuleInfo.process = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    hapModuleInfo.resourcePath = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    hapModuleInfo.srcEntrance = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    hapModuleInfo.uiSyntax = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    hapModuleInfo.virtualMachine = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    hapModuleInfo.moduleSourceDir = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    hapModuleInfo.buildHash = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    hapModuleInfo.fileContextMenu = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    hapModuleInfo.routerMap = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    hapModuleInfo.packageName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    hapModuleInfo.abilitySrcEntryDelegator = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    hapModuleInfo.abilityStageSrcEntryDelegator = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    hapModuleInfo.appStartup = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    hapModuleInfo.nativeLibraryFileNames = GenerateStringArray(fdp);
    hapModuleInfo.reqCapabilities = GenerateStringArray(fdp);
    hapModuleInfo.deviceTypes = GenerateStringArray(fdp);
    GenerateDeviceFeatureMap(fdp, hapModuleInfo.requiredDeviceFeatures);
}

void GenerateBundleOptionInfo(FuzzedDataProvider& fdp, BundleOptionInfo &bundleOptionInfo)
{
    bundleOptionInfo.bundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    bundleOptionInfo.moduleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    bundleOptionInfo.abilityName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    bundleOptionInfo.userId = fdp.ConsumeIntegral<int32_t>();
    bundleOptionInfo.appIndex = fdp.ConsumeIntegral<int32_t>();
}

// ============ Named constants for fuzz data generation ============
// Buffer sizes for overflow testing
constexpr size_t SMALL_BUFFER_SIZE = 64;     // small buffer for overflow
constexpr size_t TINY_BUFFER_SIZE = 16;      // tiny buffer for overflow
constexpr size_t MEDIUM_BUFFER_SIZE = 32;    // medium buffer for overflow

// Target buffer sizes for strcpy_s overflow
constexpr size_t BUNDLE_NAME_MAX_SIZE = 128;         // MAX_BUNDLE_NAME
constexpr size_t PATH_MAX_SIZE = 4096;                // BMS_MAX_PATH_LENGTH
constexpr size_t CPU_ABI_MAX_SIZE = 256;             // cpuAbi buffer size
constexpr size_t APP_IDENTIFIER_MAX_SIZE = 256;      // appIdentifier buffer size

// Filler chars for string construction
constexpr char FILLER_CHAR_A = 'A';          // filler char for overflow strings
constexpr char FILLER_CHAR_X = 'X';          // filler char for memcpy overflow
constexpr char FILLER_CHAR_NULL = '\0';      // NULL filler char

// Filler bytes for buffer padding
constexpr uint8_t FILLER_BYTE_A = 0xAA;
constexpr uint8_t FILLER_BYTE_B = 0xBB;
constexpr uint8_t FILLER_BYTE_C = 0xCC;
constexpr uint8_t FILLER_BYTE_D = 0xDD;
constexpr uint8_t FILLER_BYTE_FF = 0xFF;
constexpr uint8_t FILLER_NULL = 0x00;
constexpr uint8_t ASN1_SEQUENCE_TAG = 0x30;   // ASN.1 DER SEQUENCE tag
constexpr uint8_t ASN1_LONG_FORM_LENGTH = 0x82;
constexpr uint8_t BOMB_FILLER_CHAR = 0x5A;  // Z char for decompression bomb

// Max counts for batch/collection operations
constexpr uint8_t MAX_DIR_COUNT = 32;        // max dirs in batch clean/scan
constexpr uint8_t MAX_UID_COUNT = 8;         // max uids in batch stats
constexpr uint8_t MAX_GROUP_COUNT = 8;       // max data groups/uuids/map entries
constexpr uint8_t MAX_PATH_COUNT = 16;       // max paths in batch operations
constexpr uint16_t MAX_SIGN_DATA_SIZE = 256;  // max sign data size
constexpr uint8_t MAX_WANT_COUNT = 4;        // max wants in batch query
constexpr uint8_t MAX_TYPE_COUNT = 8;        // max types in batch operations
constexpr uint16_t PROFILE_DATA_MAX_SIZE = 1024;  // max profile block data size
constexpr uint16_t CERT_DATA_MAX_SIZE = 512;      // max cert data size

// Security-relevant max values
constexpr uint32_t UINT32_MAX_VAL = 0xFFFFFFFF;
constexpr uint32_t PROFILE_BLOCK_MAX_SIZE = 1048576;      // 1M
constexpr uint32_t PARCEL_CAPACITY_MAX_SIZE = 134217728;  // 128M
constexpr uint32_t CERT_CAPACITY_MAX_SIZE = 1024000;      // ~1M

// Enum sizes for safe casting
constexpr uint8_t DATA_DIR_EL_COUNT = 4;     // DataDirEl enum has 4 values
constexpr uint8_t CREATE_DIR_FLAG_COUNT = 2; // CreateDirFlag enum has 2 values
constexpr uint8_t MODULE_TYPE_COUNT = 5;     // ModuleType enum has 5 values
constexpr uint8_t OVERFLOW_TYPE_COUNT = 4;   // profileBlock overflow modes
constexpr uint8_t STRCPY_OVERFLOW_TYPE_COUNT = 6;  // strcpy overflow modes
constexpr uint8_t ATTACK_VECTOR_COUNT = 8;  // path traversal vectors

// Overflow mode enums for switch cases
enum StrcpyOverflowMode {
    STRCPY_JUST_FITS = 0,
    STRCPY_OFF_BY_ONE,
    STRCPY_TWO_BYTE_OVERFLOW,
    STRCPY_LARGE_OVERFLOW,
    STRCPY_NULL_FILL,
    STRCPY_NULL_TRUNCATION,
};
enum ProfileBlockOverflowMode {
    PROFILE_BOUNDARY_MINUS_ONE = 0,
    PROFILE_EXACT_MAX,
    PROFILE_INTEGER_OVERFLOW,
    PROFILE_PARCEL_CAPACITY,
    PROFILE_EXCEEDS_CAPACITY,
    PROFILE_LENGTH_ONE_EMPTY,
    PROFILE_MALICIOUS_ASN1,
    PROFILE_NULL_TRUNCATION,
};
enum MemcpyOverflowMode {
    MEMCPY_JUST_FITS = 0,
    MEMCPY_OFF_BY_ONE,
    MEMCPY_TWO_BYTE_OVERFLOW,
    MEMCPY_LARGE_OVERFLOW,
};
enum DataSizeOverflowMode {
    DATASIZE_BOUNDARY = 0,
    DATASIZE_EXCEEDS_CAPACITY,
    DATASIZE_INTEGER_OVERFLOW,
    DATASIZE_LENGTH_ONE_EMPTY,
    DATASIZE_MALICIOUS_PEM,
    DATASIZE_NULL_TRUNCATION,
};

// ============ Parcel helper functions for reuse ============
// Reduce code duplication across Host fuzzers: 660+ repeated patterns consolidated

// Prepare a MessageParcel with interface token pre-written
template<typename HostType>
inline void PrepareParcel(MessageParcel& data)
{
    data.WriteInterfaceToken(HostType::GetDescriptor());
}

// Write bundleName/path string field with attack vector (139+ usages)
inline void WriteStringField(MessageParcel& data, FuzzedDataProvider& fdp,
    AttackVector type = ATTACK_PATH_TRAVERSAL)
{
    data.WriteString(GenAttackAwareString(fdp, type));
}

// Write String16 field with attack vector (72+ usages, for Installd Host)
inline void WriteString16Field(MessageParcel& data, FuzzedDataProvider& fdp,
    AttackVector type = ATTACK_PATH_TRAVERSAL)
{
    WriteParcelString16(data, GenAttackAwareString(fdp, type));
}

// Write plain string field (no attack vector)
inline void WritePlainString(MessageParcel& data, FuzzedDataProvider& fdp)
{
    data.WriteString(fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH));
}

// Write userId field with special values (65+ usages)
inline void WriteUserId(MessageParcel& data, FuzzedDataProvider& fdp)
{
    data.WriteInt32(GenerateRandomUser(fdp));
}

// Write bool field (30+ usages)
inline void WriteBoolField(MessageParcel& data, FuzzedDataProvider& fdp)
{
    data.WriteBool(fdp.ConsumeBool());
}

// Write int32 field
inline void WriteInt32Field(MessageParcel& data, FuzzedDataProvider& fdp)
{
    data.WriteInt32(fdp.ConsumeIntegral<int32_t>());
}

// Write uint32 field
inline void WriteUint32Field(MessageParcel& data, FuzzedDataProvider& fdp)
{
    data.WriteUint32(fdp.ConsumeIntegral<uint32_t>());
}

// Write uint64 field
inline void WriteUint64Field(MessageParcel& data, FuzzedDataProvider& fdp)
{
    data.WriteUint64(fdp.ConsumeIntegral<uint64_t>());
}

// Write uint8 field (for enum types)
inline void WriteUint8Field(MessageParcel& data, FuzzedDataProvider& fdp)
{
    data.WriteUint8(fdp.ConsumeIntegral<uint8_t>());
}

// Write Want Parcelable with attack vector (8+ usages)
inline void WriteWant(MessageParcel& data, FuzzedDataProvider& fdp,
    AttackVector type = ATTACK_PATH_TRAVERSAL)
{
    AAFwk::Want want;
    want.SetBundle(GenAttackAwareString(fdp, type));
    want.SetAction(GenAttackAwareString(fdp, type));
    want.Marshalling(data);
}

// Write remote object (non-null IPCObjectStub)
inline void WriteRemoteObject(MessageParcel& data)
{
    sptr<IRemoteObject> object = new (std::nothrow) IPCObjectStub(u"");
    data.WriteRemoteObject(object);
}

// Write string vector field
inline void WriteStringVectorField(MessageParcel& data, FuzzedDataProvider& fdp)
{
    auto vec = GenerateStringArray(fdp);
    data.WriteStringVector(vec);
}

// Finalize parcel for Handle method call (178+ usages)
inline void FinishParcel(MessageParcel& data)
{
    data.RewindRead(0);
}

// ============ attack vector library ============
// real attack vectors for high-risk vulnerability paths, improving fuzz attack surface reachability

// ---- supplement Parcelable Generate functions, expand input space ----
// DisposedRule: 6+fields, includingpriority/elementList/callerName/appId/appIndex
inline void GenerateDisposedRule(FuzzedDataProvider& fdp, DisposedRule& rule)
{
    rule.isEdm = fdp.ConsumeBool();
    rule.priority = fdp.ConsumeIntegral<int32_t>();
    rule.callerName = GenAttackAwareString(fdp, ATTACK_PATH_TRAVERSAL);
    uint8_t elemCount = fdp.ConsumeIntegral<uint8_t>() % MAX_GROUP_COUNT;
    for (uint8_t i = 0; i < elemCount; i++) {
        ElementName elem;
        elem.SetBundleName(GenAttackAwareString(fdp, ATTACK_PATH_TRAVERSAL));
        elem.SetModuleName(fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH));
        elem.SetAbilityName(fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH));
        rule.elementList.push_back(elem);
    }
}

// DestroyAppCloneParam: userId + parameters map
inline void GenerateDestroyAppCloneParam(FuzzedDataProvider& fdp, DestroyAppCloneParam& param)
{
    param.userId = GenerateRandomUser(fdp);
    GenerateMap(fdp, param.parameters);
}

// CommonEventInfo: 7fields, includinguid/name/bundleName/permission/data/type/events
inline void GenerateCommonEventInfo(FuzzedDataProvider& fdp, CommonEventInfo& info)
{
    info.uid = fdp.ConsumeIntegral<int32_t>();
    info.name = GenAttackAwareString(fdp, ATTACK_PATH_TRAVERSAL);
    info.bundleName = GenAttackAwareString(fdp, ATTACK_PATH_TRAVERSAL);
    info.permission = GenAttackAwareString(fdp, ATTACK_SELINUX);
    info.data = GenerateStringArray(fdp);
    info.type = GenerateStringArray(fdp);
    info.events = GenerateStringArray(fdp);
}

// path traversal attack vector: directory traversal/symlink/overlong path overflow
inline std::string GenPathTraversalString(FuzzedDataProvider& fdp)
{
    static const std::vector<std::string> pathVectors = {
        "../../etc/passwd",           // classic path traversal
        "..%2F..%2Fetc%2Fpasswd",     // URL-encoded traversal
        "/data/app/../../../root",    // absolute path traversal
        "/proc/self/cwd/../../../",   // symlink traversal
        "....//....//....//etc/shadow", // dot bypass
        "/dev/..tmp/../../",          // device file traversal
        std::string(PATH_MAX_SIZE, FILLER_CHAR_A),  // overlong path
        std::string(CPU_ABI_MAX_SIZE, '/'),   // overlong nested path
        "/data/app/",                 // normal path as control
        "./current/../../../backup",  // relative path traversal
        "/sys/class/../../../etc",    // sysfs traversal
        "\x00",                       // NULL byte truncation
        "$(cat /etc/passwd)",         // command injection
        "/data/app/el1/bundle/../..\x00malicious", // NULL bypass
        "/data/app/el2/../el1/../../", // EL cross-level traversal
        "/data/app/el1/bundle/" + std::string(128, '.') + "/", // deep nesting
        "/data/service/el1/" + std::string(256, 'X'), // service dir overflow
        "/mnt/extract/../../tmp/",    // mount point escape
        "/data/app/../data/bundle/", // app-to-bundle traversal
    };
    uint8_t idx = fdp.ConsumeIntegral<uint8_t>() % pathVectors.size();
    std::string base = pathVectors[idx];
    // append fuzz data to enhance mutation
    if (fdp.remaining_bytes() > 0) {
        base += fdp.ConsumeRandomLengthString(SMALL_BUFFER_SIZE);
    }
    return base;
}

// SELinux privilege escalation: label tampering/restorecon bypass
inline std::string GenSelinuxLabelString(FuzzedDataProvider& fdp)
{
    static const std::vector<std::string> selinuxVectors = {
        "u:r:su:s0",                  // root SELinux domain
        "u:r:shell:s0",               // shell domain escalation
        "u:r:platform_app:s0",       // platform app domain
        "u:r:system:s0:s0",           // system domain
        "u:object_r:unlabeled:s0",   // unlabeled bypass
        "u:r:installd:s0",           // installd domain
        "u:r:foundation:s0",          // foundation domain
        "",                           // empty label
        std::string(256, 'u'),        // overlong label
        "u:r:test\x00:s0",           // NULL truncation
        "u:r:hal_default:s0",       // HAL default domain
        "u:r:hal_bluetooth:s0",      // bluetooth HAL escalation
        "u:r:untrusted_app:s0",      // untrusted app to bypass
        "u:r:system_app:s0",         // system app domain
        "u:r:reserved_disk:s0",     // reserved disk domain
    };
    uint8_t idx = fdp.ConsumeIntegral<uint8_t>() % selinuxVectors.size();
    return selinuxVectors[idx];
}

// signature bypass: provision/cert parsing overflow
inline std::string GenCertBypassString(FuzzedDataProvider& fdp)
{
    static const std::vector<std::string> certVectors = {
        "-----BEGIN CERTIFICATE-----\nMIIB\x00\n-----END CERTIFICATE-----",
        std::string(PROFILE_DATA_MAX_SIZE * 8, 'M'),  // overlong cert
        "invalid_cert_data",
        "\x30\x82\x01\x00",            // ASN.1 DER SEQUENCE
        "",                             // empty certificate
        "cert_alias\x00malicious",      // NULL truncation
        std::string(PROFILE_DATA_MAX_SIZE, FILLER_BYTE_FF),  // 0xFF padding
        "../../../data/app/cert.pem",  // path traversal cert
        "\x30\x82\x0c\x00" + std::string(PROFILE_DATA_MAX_SIZE, '\x00'), // ASN.1 oversized
        "-----BEGIN CERTIFICATE-----\n\n-----END CERTIFICATE-----", // empty body
        "\x30\x06\x03\x02\x01\x00",   // malformed ASN.1 (bad length)
        "provision\x00bypass",        // provision NULL truncation
        std::string(2, '\xff') + "EXTRA", // short overflow prefix
        "keyAlias\x00inject",          // keyAlias injection
    };
    uint8_t idx = fdp.ConsumeIntegral<uint8_t>() % certVectors.size();
    return certVectors[idx];
}

// memcpy_s overflow: buffer operation overflow
inline std::string GenOverflowString(FuzzedDataProvider& fdp, size_t targetSize = 0)
{
    // constructprecisesizestringtriggermemcpy_sboundarycondition
    if (targetSize > 0) {
        // precise matchtargetbuffersize，triggeroff-by-one
        uint8_t overflowType = fdp.ConsumeIntegral<uint8_t>() % OVERFLOW_TYPE_COUNT;
        switch (overflowType) {
            case MEMCPY_JUST_FITS: return std::string(targetSize - 1, FILLER_CHAR_X);   // just fits, no overflow
            case MEMCPY_OFF_BY_ONE: return std::string(targetSize, FILLER_CHAR_X);        // exact 1-byte overflow
            case MEMCPY_TWO_BYTE_OVERFLOW: return std::string(targetSize + 1, FILLER_CHAR_X);   // 2-byte overflow
            default: return std::string(targetSize * 2, FILLER_CHAR_X);   // large overflow
        }
    }
    // default constructionstring
    static const std::vector<size_t> sizes = {
        CPU_ABI_MAX_SIZE, CERT_DATA_MAX_SIZE, PROFILE_DATA_MAX_SIZE,
        PATH_MAX_SIZE, CERT_CAPACITY_MAX_SIZE / MAX_SIGN_DATA_SIZE,
        MAX_SIGN_DATA_SIZE * MAX_SIGN_DATA_SIZE};
    uint8_t idx = fdp.ConsumeIntegral<uint8_t>() % sizes.size();
    return std::string(sizes[idx], fdp.ConsumeIntegral<uint8_t>());
}

// strcpy_s overflow verification: precisely trigger HapInfo fixed buffer overflow
// HapInfo.packageName(MAX_BUNDLE_NAME=128) / hapPath(BMS_MAX_PATH_LENGTH=4096) / abi / appIdentifier
inline std::string GenStrcpyOverflowString(FuzzedDataProvider& fdp, size_t targetBufSize)
{
    if (targetBufSize == 0) {
        return fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    }
    uint8_t overflowType = fdp.ConsumeIntegral<uint8_t>() % STRCPY_OVERFLOW_TYPE_COUNT;
    switch (overflowType) {
        case STRCPY_JUST_FITS: return std::string(targetBufSize - 1, FILLER_CHAR_A);     // just fits, no overflow
        case STRCPY_OFF_BY_ONE: return std::string(targetBufSize, FILLER_CHAR_A);          // exact off-by-one
        case STRCPY_TWO_BYTE_OVERFLOW: return std::string(targetBufSize + 1, FILLER_CHAR_A);      // 2-byte overflow
        case STRCPY_LARGE_OVERFLOW: return std::string(targetBufSize * 2, FILLER_CHAR_A);      // large overflow
        case STRCPY_NULL_FILL: return std::string(targetBufSize, FILLER_CHAR_NULL);  // NULL fill
        default: return std::string(targetBufSize, FILLER_CHAR_A) + "\x00malicious"; // NULL truncation bypass
    }
}

// malicious HapInfo payload: trigger 4 strcpy_s overflow paths in installd_operator.cpp
// path1: hapInfo.packageName (MAX_BUNDLE_NAME=128)
// path2: hapInfo.hapPath (BMS_MAX_PATH_LENGTH=4096)
// path3: hapInfo.abi
// path4: hapInfo.appIdentifier
inline void GenMaliciousHapInfoPayload(FuzzedDataProvider& fdp,
    std::string& packageName, std::string& hapPath,
    std::string& cpuAbi, std::string& appIdentifier)
{
    // MAX_BUNDLE_NAME=128, construct129-256triggerpackageNameoverflow
    packageName = GenStrcpyOverflowString(fdp, BUNDLE_NAME_MAX_SIZE);
    // BMS_MAX_PATH_LENGTH=4096, construct4097-8192triggerhapPathoverflow
    hapPath = GenStrcpyOverflowString(fdp, PATH_MAX_SIZE);
    // cpuAbiconstructstring
    cpuAbi = GenStrcpyOverflowString(fdp, CPU_ABI_MAX_SIZE);
    // appIdentifierconstructstring+char
    appIdentifier = GenStrcpyOverflowString(fdp, APP_IDENTIFIER_MAX_SIZE);
}

// ====== length field overflow: targeting declared length > actual data overflow read paths ======
// target constants:
//   MAX_PROFILE_BLOCK_LENGTH = 1*1024*1024 = PROFILE_BLOCK_MAX_SIZE (1M)
//   MAX_PARCEL_CAPACITY = 128*1024*1024 = PARCEL_CAPACITY_MAX_SIZE (128M)
// CAPACITY_SIZE = 1*1024*1000 = CERT_CAPACITY_MAX_SIZE (1M)

// malicious profileBlockLength: trigger length overflow in CodeSignatureParam/HandDeliverySignProfile
// return (profileBlockLength, actual data) pair，length mismatchtrigger overflow read
struct MaliciousLengthPayload {
    uint32_t declaredLength;     // declarelength（writeParcel）
    std::vector<uint8_t> actualData;  // actual data（maydeclare，trigger overflow）
};

inline MaliciousLengthPayload GenMaliciousProfileBlockLength(FuzzedDataProvider& fdp)
{
    MaliciousLengthPayload payload;
    uint8_t attackType = fdp.ConsumeIntegral<uint8_t>() % ATTACK_VECTOR_COUNT;
    constexpr uint32_t MAX_PROFILE_BLOCK_LENGTH = PROFILE_BLOCK_MAX_SIZE;      // 1M
    constexpr uint32_t MAX_PARCEL_CAPACITY = PARCEL_CAPACITY_MAX_SIZE;        // 128M
    switch (attackType) {
        case PROFILE_BOUNDARY_MINUS_ONE: // boundary: MAX-1, passes check
            payload.declaredLength = MAX_PROFILE_BLOCK_LENGTH - 1;
            payload.actualData.resize(SMALL_BUFFER_SIZE, FILLER_BYTE_A);  // overflow
            break;
        case PROFILE_EXACT_MAX: // exactly equalsMAX_PROFILE_BLOCK_LENGTH，skips validation, profileBlock is empty
            payload.declaredLength = MAX_PROFILE_BLOCK_LENGTH;
            payload.actualData.resize(0);  // empty data
            break;
        case PROFILE_INTEGER_OVERFLOW: // integer overflow: UINT32_MAX，passes >0 check but may truncate
            payload.declaredLength = UINT32_MAX_VAL;
            payload.actualData.resize(SMALL_BUFFER_SIZE, FILLER_BYTE_B);
            break;
        case PROFILE_PARCEL_CAPACITY: // triggers 128M allocation
            payload.declaredLength = MAX_PARCEL_CAPACITY;
            payload.actualData.resize(SMALL_BUFFER_SIZE, FILLER_BYTE_C);  // declares 128M actual 64 bytes -> overflow
            break;
        case PROFILE_EXCEEDS_CAPACITY: // MAX_PARCEL_CAPACITY + 1：exceeds validation, should be blocked
            payload.declaredLength = MAX_PARCEL_CAPACITY + 1;
            payload.actualData.resize(TINY_BUFFER_SIZE, FILLER_BYTE_D);
            break;
        case PROFILE_LENGTH_ONE_EMPTY: // length=1：boundarymin value，actual dataas0 -> 1-byte overflow
            payload.declaredLength = 1;
            payload.actualData.resize(0);
            break;
        case PROFILE_MALICIOUS_ASN1: {  // ASN.1 DER
            payload.declaredLength = fdp.ConsumeIntegral<uint32_t>() % PROFILE_DATA_MAX_SIZE + 1;
            payload.actualData.resize(payload.declaredLength);
            payload.actualData[0] = ASN1_SEQUENCE_TAG;  // ASN.1 SEQUENCE tag
            payload.actualData[1] = ASN1_LONG_FORM_LENGTH;  // long form length
            for (size_t i = 2; i < payload.actualData.size(); i++) {
                payload.actualData[i] = fdp.ConsumeIntegral<uint8_t>();
            }
            break;
        }
        default: // lengthwithdata matchesbutincludingNULL byte truncation
            payload.declaredLength = fdp.ConsumeIntegral<uint32_t>() % MAX_SIGN_DATA_SIZE + 1;
            payload.actualData.resize(payload.declaredLength, FILLER_NULL);  // all NULL
            break;
    }
    return payload;
}

// malicious dataSize: trigger std::string(content, dataSize) overflow in HandleAddCertAndEnableKey
inline MaliciousLengthPayload GenMaliciousDataSize(FuzzedDataProvider& fdp)
{
    MaliciousLengthPayload payload;
    uint8_t attackType = fdp.ConsumeIntegral<uint8_t>() % STRCPY_OVERFLOW_TYPE_COUNT;
    constexpr uint32_t CAPACITY_SIZE = CERT_CAPACITY_MAX_SIZE;  // 1*1024*1000
    switch (attackType) {
        case DATASIZE_BOUNDARY: // boundary: CAPACITY_SIZE, passes check
            payload.declaredLength = CAPACITY_SIZE;
            payload.actualData.resize(SMALL_BUFFER_SIZE, FILLER_BYTE_A);  // declares 1M actual 64 bytes -> overflow
            break;
        case DATASIZE_EXCEEDS_CAPACITY: // CAPACITY_SIZE + 1：exceeds validation, should be blocked
            payload.declaredLength = CAPACITY_SIZE + 1;
            payload.actualData.resize(TINY_BUFFER_SIZE, FILLER_BYTE_B);
            break;
        case PROFILE_INTEGER_OVERFLOW: // integer overflow: UINT32_MAX
            payload.declaredLength = UINT32_MAX_VAL;
            payload.actualData.resize(MEDIUM_BUFFER_SIZE, FILLER_BYTE_C);
            break;
        case DATASIZE_LENGTH_ONE_EMPTY: // length=1 but data empty -> 1-byte overflow
            payload.declaredLength = 1;
            payload.actualData.resize(0);
            break;
        case DATASIZE_MALICIOUS_PEM: {  // PEM format
            payload.declaredLength = fdp.ConsumeIntegral<uint32_t>() % CERT_DATA_MAX_SIZE + 1;
            payload.actualData.resize(payload.declaredLength);
            const std::string pemHeader = "-----BEGIN CERTIFICATE-----\n";
            const std::string pemFooter = "\n-----END CERTIFICATE-----";
            size_t copyLen = std::min(pemHeader.size(), payload.actualData.size());
            memcpy(payload.actualData.data(), pemHeader.c_str(), copyLen);
            break;
        }
        default: // all NULLdata
            payload.declaredLength = fdp.ConsumeIntegral<uint32_t>() % MAX_SIGN_DATA_SIZE + 1;
            payload.actualData.resize(payload.declaredLength, FILLER_NULL);
            break;
    }
    return payload;
}

// archive attack: ZipSlip/decompression bomb/nested compression
inline std::string GenArchiveAttackString(FuzzedDataProvider& fdp)
{
    static const std::vector<std::string> archiveVectors = {
        "../../../etc/cron.daily/evil",    // ZipSlip directory traversal
        "../../root/.ssh/authorized_keys", // SSH key injection
        std::string(PROFILE_DATA_MAX_SIZE, BOMB_FILLER_CHAR),            // decompression bomb filename
        "/",                               // root directory
        "\x00",                            // NULL truncationfile
        "....//....//....//etc/shadow",   // dot bypass
        "/dev/null",                       // device file
        std::string(512, '.'),            // overlong dot path
    };
    uint8_t idx = fdp.ConsumeIntegral<uint8_t>() % archiveVectors.size();
    return archiveVectors[idx];
}

// probabilistic selection of attack vector or random fuzz data
inline std::string GenAttackAwareString(FuzzedDataProvider& fdp, AttackVector type = ATTACK_PATH_TRAVERSAL)
{
    // 30%makeuseattack vector，70%makeusefuzzdata
    bool useAttackVector = fdp.ConsumeBool();
    if (useAttackVector) {
        switch (type) {
            case ATTACK_PATH_TRAVERSAL: return GenPathTraversalString(fdp);
            case ATTACK_SELINUX:        return GenSelinuxLabelString(fdp);
            case ATTACK_CERT_BYPASS:    return GenCertBypassString(fdp);
            case ATTACK_MEMCPY_OVERFLOW:return GenOverflowString(fdp);
            case ATTACK_ARCHIVE:        return GenArchiveAttackString(fdp);
            default:                    return GenPathTraversalString(fdp);
        }
    }
    return fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
}

// precise MessageParcel construction: write in Handle method real read order
inline void WriteParcelString16(MessageParcel& parcel, const std::string& str)
{
    parcel.WriteString16(Str8ToStr16(str));
}
inline void WriteParcelString(MessageParcel& parcel, const std::string& str)
{
    parcel.WriteString(str);
}

// CleanCacheInfo: 4 fields, used by HandleCleanBundlePartialCacheAutomatic
inline void GenerateCleanCacheInfo(FuzzedDataProvider& fdp, CleanCacheInfo& info)
{
    info.bundleName = GenAttackAwareString(fdp, ATTACK_PATH_TRAVERSAL);
    info.userId = GenerateRandomUser(fdp);
    info.appIndex = fdp.ConsumeIntegral<int32_t>();
    info.cacheThreshold = fdp.ConsumeIntegral<uint64_t>();
}

// IPC Stub loop common template: avoid repetition across fuzzers
template<typename HostType>
inline void FuzzIpcStubLoop(HostType& host, const uint8_t* data, size_t size, uint32_t codeMax)
{
    for (uint32_t code = 0; code <= codeMax; code++) {
        MessageParcel datas;
        MessageParcel reply;
        MessageOption option;
        datas.WriteInterfaceToken(HostType::GetDescriptor());
        datas.WriteBuffer(data, size);
        datas.RewindRead(0);
        host.OnRemoteRequest(code, datas, reply, option);
    }
}

// Single IPC request with RewindRead (eliminates RewindRead+OnRemoteRequest duplication in callback fuzzers)
template<typename HostType>
inline void FuzzIpcRequest(HostType& host, uint32_t code, MessageParcel& datas, MessageParcel& reply,
    MessageOption& option)
{
    datas.RewindRead(0);
    host.OnRemoteRequest(code, datas, reply, option);
}

}  // namespace BMSFuzzTestUtil
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // BMS_FUZZTEST_UTIL_H

// Parcelable unmarshalling fuzz macro (eliminates ~1140 lines of boilerplate across 57 fuzzers)
#define BMS_PARCELABLE_UNMARSHAL_FUZZ(className, funcName) \
bool funcName(const uint8_t* data, size_t size) { \
    Parcel dataParcel; \
    FuzzedDataProvider fdp(data, size); \
    className obj; \
    (void)fdp; \
    if (!obj.Marshalling(dataParcel)) { return false; } \
    dataParcel.RewindRead(0); \
    className *result = new (std::nothrow) className(); \
    if (result == nullptr) { return false; } \
    bool ret = result->ReadFromParcel(dataParcel); \
    delete result; \
    result = nullptr; \
    return ret; \
}