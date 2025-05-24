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

#ifndef BMS_FUZZTEST_UTIL_H
#define BMS_FUZZTEST_UTIL_H

#include <fuzzer/FuzzedDataProvider.h>
#include <map>
#include <string>
#include <vector>

#include "bundle_info.h"
#include "bundle_user_info.h"
#include "install_param.h"

namespace OHOS {
namespace AppExecFwk {
namespace BMSFuzzTestUtil {
constexpr size_t STRING_MAX_LENGTH = 128;
constexpr size_t ARRAY_MAX_LENGTH = 128;
constexpr uint32_t CODE_MIN_ONE = 1;
constexpr uint32_t CODE_MAX_ONE = 1;
constexpr uint32_t CODE_MAX_TWO = 2;
constexpr uint32_t CODE_MAX_THREE = 3;
constexpr uint32_t CODE_MAX_FOUR = 4;
constexpr uint32_t CODE_MAX_FIVE = 5;
constexpr uint32_t ORIENTATION_MAX = 14;
constexpr uint32_t EXTENSION_ABILITY_MAX = 25;


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

void GenerateAbilityInfo(FuzzedDataProvider& fdp, AbilityInfo &abilityInfo)
{
    abilityInfo.visible = fdp.ConsumeBool();
    abilityInfo.isLauncherAbility = fdp.ConsumeBool();
    abilityInfo.isNativeAbility = fdp.ConsumeBool();
    abilityInfo.enabled = fdp.ConsumeBool();
    abilityInfo.supportPipMode = fdp.ConsumeBool();
    abilityInfo.formEnabled = fdp.ConsumeBool();
    abilityInfo.removeMissionAfterTerminate = fdp.ConsumeBool();
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

void GenerateBundleUserInfo(FuzzedDataProvider& fdp, BundleUserInfo &bundleUserInfo)
{
    bundleUserInfo.enabled = fdp.ConsumeBool();
    bundleUserInfo.userId = fdp.ConsumeIntegral<int32_t>();
    bundleUserInfo.setEnabledCaller = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    bundleUserInfo.disabledAbilities = GenerateStringArray(fdp);
    bundleUserInfo.overlayModulesState = GenerateStringArray(fdp);
}
}  // namespace BMSFuzzTestUtil
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // BMS_FUZZTEST_UTIL_H