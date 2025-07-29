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

#include "data/inner_ability_info.h"

namespace OHOS {
namespace AppExecFwk {
AbilityInfo InnerAbilityInfo::ConvertToAbilityInfo(const InnerAbilityInfo &innerAbilityInfo)
{
    AbilityInfo abilityInfo;
    abilityInfo.visible = innerAbilityInfo.visible;
    abilityInfo.isLauncherAbility = innerAbilityInfo.isLauncherAbility;
    abilityInfo.isNativeAbility = innerAbilityInfo.isNativeAbility;
    abilityInfo.enabled = innerAbilityInfo.enabled;
    abilityInfo.supportPipMode = innerAbilityInfo.supportPipMode;
    abilityInfo.formEnabled = innerAbilityInfo.formEnabled;
    abilityInfo.removeMissionAfterTerminate = innerAbilityInfo.removeMissionAfterTerminate;
    abilityInfo.isModuleJson = innerAbilityInfo.isModuleJson;
    abilityInfo.isStageBasedModel = innerAbilityInfo.isStageBasedModel;
    abilityInfo.continuable = innerAbilityInfo.continuable;
    abilityInfo.excludeFromMissions = innerAbilityInfo.excludeFromMissions;
    abilityInfo.unclearableMission = innerAbilityInfo.unclearableMission;
    abilityInfo.excludeFromDock = innerAbilityInfo.excludeFromDock;
    abilityInfo.recoverable = innerAbilityInfo.recoverable;
    abilityInfo.isolationProcess = innerAbilityInfo.isolationProcess;
    abilityInfo.multiUserShared = innerAbilityInfo.multiUserShared;
    abilityInfo.grantPermission = innerAbilityInfo.grantPermission;
    abilityInfo.directLaunch = innerAbilityInfo.directLaunch;
    abilityInfo.linkType = innerAbilityInfo.linkType;
    abilityInfo.labelId = innerAbilityInfo.labelId;
    abilityInfo.descriptionId = innerAbilityInfo.descriptionId;
    abilityInfo.iconId = innerAbilityInfo.iconId;
    abilityInfo.orientationId = innerAbilityInfo.orientationId;
    abilityInfo.formEntity = innerAbilityInfo.formEntity;
    abilityInfo.backgroundModes = innerAbilityInfo.backgroundModes;
    abilityInfo.startWindowId = innerAbilityInfo.startWindowId;
    abilityInfo.startWindowIconId = innerAbilityInfo.startWindowIconId;
    abilityInfo.startWindowBackgroundId = innerAbilityInfo.startWindowBackgroundId;
    abilityInfo.maxWindowWidth = innerAbilityInfo.maxWindowWidth;
    abilityInfo.minWindowWidth = innerAbilityInfo.minWindowWidth;
    abilityInfo.maxWindowHeight = innerAbilityInfo.maxWindowHeight;
    abilityInfo.minWindowHeight = innerAbilityInfo.minWindowHeight;
    abilityInfo.packageSize = innerAbilityInfo.packageSize;
    abilityInfo.minFormHeight = innerAbilityInfo.minFormHeight;
    abilityInfo.defaultFormHeight = innerAbilityInfo.defaultFormHeight;
    abilityInfo.minFormWidth = innerAbilityInfo.minFormWidth;
    abilityInfo.defaultFormWidth = innerAbilityInfo.defaultFormWidth;
    abilityInfo.priority = innerAbilityInfo.priority;
    abilityInfo.appIndex = innerAbilityInfo.appIndex;
    abilityInfo.uid = innerAbilityInfo.uid;
    abilityInfo.type = innerAbilityInfo.type;
    abilityInfo.extensionAbilityType = innerAbilityInfo.extensionAbilityType;
    abilityInfo.orientation = innerAbilityInfo.orientation;
    abilityInfo.launchMode = innerAbilityInfo.launchMode;
    abilityInfo.compileMode = innerAbilityInfo.compileMode;
    abilityInfo.subType = innerAbilityInfo.subType;
    abilityInfo.installTime = innerAbilityInfo.installTime;
    abilityInfo.maxWindowRatio = innerAbilityInfo.maxWindowRatio;
    abilityInfo.minWindowRatio = innerAbilityInfo.minWindowRatio;
    abilityInfo.name = innerAbilityInfo.name;
    abilityInfo.label = innerAbilityInfo.label;
    abilityInfo.description = innerAbilityInfo.description;
    abilityInfo.iconPath = innerAbilityInfo.iconPath;
    abilityInfo.theme = innerAbilityInfo.theme;
    abilityInfo.kind = innerAbilityInfo.kind;
    abilityInfo.extensionTypeName = innerAbilityInfo.extensionTypeName;
    abilityInfo.srcPath = innerAbilityInfo.srcPath;
    abilityInfo.srcLanguage = innerAbilityInfo.srcLanguage;
    abilityInfo.arkTSMode = innerAbilityInfo.arkTSMode;
    abilityInfo.process = innerAbilityInfo.process;
    abilityInfo.uri = innerAbilityInfo.uri;
    abilityInfo.targetAbility = innerAbilityInfo.targetAbility;
    abilityInfo.readPermission = innerAbilityInfo.readPermission;
    abilityInfo.writePermission = innerAbilityInfo.writePermission;
    abilityInfo.package = innerAbilityInfo.package;
    abilityInfo.bundleName = innerAbilityInfo.bundleName;
    abilityInfo.moduleName = innerAbilityInfo.moduleName;
    abilityInfo.applicationName = innerAbilityInfo.applicationName;
    abilityInfo.codePath = innerAbilityInfo.codePath;
    abilityInfo.resourcePath = innerAbilityInfo.resourcePath;
    abilityInfo.hapPath = innerAbilityInfo.hapPath;
    abilityInfo.srcEntrance = innerAbilityInfo.srcEntrance;
    abilityInfo.startWindow = innerAbilityInfo.startWindow;
    abilityInfo.startWindowIcon = innerAbilityInfo.startWindowIcon;
    abilityInfo.startWindowBackground = innerAbilityInfo.startWindowBackground;
    abilityInfo.preferMultiWindowOrientation = innerAbilityInfo.preferMultiWindowOrientation;
    abilityInfo.originalBundleName = innerAbilityInfo.originalBundleName;
    abilityInfo.appName = innerAbilityInfo.appName;
    abilityInfo.privacyUrl = innerAbilityInfo.privacyUrl;
    abilityInfo.privacyName = innerAbilityInfo.privacyName;
    abilityInfo.downloadUrl = innerAbilityInfo.downloadUrl;
    abilityInfo.versionName = innerAbilityInfo.versionName;
    abilityInfo.className = innerAbilityInfo.className;
    abilityInfo.originalClassName = innerAbilityInfo.originalClassName;
    abilityInfo.uriPermissionMode = innerAbilityInfo.uriPermissionMode;
    abilityInfo.uriPermissionPath = innerAbilityInfo.uriPermissionPath;
    abilityInfo.libPath = innerAbilityInfo.libPath;
    abilityInfo.deviceId = innerAbilityInfo.deviceId;
    abilityInfo.permissions = innerAbilityInfo.permissions;
    abilityInfo.deviceTypes = innerAbilityInfo.deviceTypes;
    abilityInfo.deviceCapabilities = innerAbilityInfo.deviceCapabilities;
    abilityInfo.configChanges = innerAbilityInfo.configChanges;
    abilityInfo.skillUri = innerAbilityInfo.skillUri;
    abilityInfo.skills = innerAbilityInfo.skills;
    abilityInfo.metadata = innerAbilityInfo.metadata;
    abilityInfo.windowModes = innerAbilityInfo.windowModes;
    abilityInfo.supportExtNames = innerAbilityInfo.supportExtNames;
    abilityInfo.supportMimeTypes = innerAbilityInfo.supportMimeTypes;
    abilityInfo.continueType = innerAbilityInfo.continueType;
    abilityInfo.metaData = innerAbilityInfo.metaData;
    abilityInfo.continueBundleNames = innerAbilityInfo.continueBundleNames;
    abilityInfo.startWindowResource = innerAbilityInfo.startWindowResource;
    return abilityInfo;
}
}  // namespace AppExecFwk
}  // namespace OHOS
