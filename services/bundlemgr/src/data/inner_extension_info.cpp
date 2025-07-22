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

#include "data/inner_extension_info.h"

namespace OHOS {
namespace AppExecFwk {
ExtensionAbilityInfo InnerExtensionInfo::ConvertToExtensionInfo(const InnerExtensionInfo &innerExtensionInfo)
{
    ExtensionAbilityInfo extensionAbilityInfo;
    extensionAbilityInfo.visible = innerExtensionInfo.visible;
    extensionAbilityInfo.enabled = innerExtensionInfo.enabled;
    extensionAbilityInfo.needCreateSandbox = innerExtensionInfo.needCreateSandbox;
    extensionAbilityInfo.isolationProcess = innerExtensionInfo.isolationProcess;
    extensionAbilityInfo.iconId = innerExtensionInfo.iconId;
    extensionAbilityInfo.labelId = innerExtensionInfo.labelId;
    extensionAbilityInfo.descriptionId = innerExtensionInfo.descriptionId;
    extensionAbilityInfo.priority = innerExtensionInfo.priority;
    extensionAbilityInfo.uid = innerExtensionInfo.uid;
    extensionAbilityInfo.appIndex = innerExtensionInfo.appIndex;
    extensionAbilityInfo.type = innerExtensionInfo.type;
    extensionAbilityInfo.compileMode = innerExtensionInfo.compileMode;
    extensionAbilityInfo.extensionProcessMode = innerExtensionInfo.extensionProcessMode;
    extensionAbilityInfo.bundleName = innerExtensionInfo.bundleName;
    extensionAbilityInfo.moduleName = innerExtensionInfo.moduleName;
    extensionAbilityInfo.name = innerExtensionInfo.name;
    extensionAbilityInfo.srcEntrance = innerExtensionInfo.srcEntrance;
    extensionAbilityInfo.icon = innerExtensionInfo.icon;
    extensionAbilityInfo.label = innerExtensionInfo.label;
    extensionAbilityInfo.description = innerExtensionInfo.description;
    extensionAbilityInfo.readPermission = innerExtensionInfo.readPermission;
    extensionAbilityInfo.writePermission = innerExtensionInfo.writePermission;
    extensionAbilityInfo.uri = innerExtensionInfo.uri;
    extensionAbilityInfo.extensionTypeName = innerExtensionInfo.extensionTypeName;
    extensionAbilityInfo.resourcePath = innerExtensionInfo.resourcePath;
    extensionAbilityInfo.hapPath = innerExtensionInfo.hapPath;
    extensionAbilityInfo.process = innerExtensionInfo.process;
    extensionAbilityInfo.customProcess = innerExtensionInfo.customProcess;
    extensionAbilityInfo.arkTSMode = innerExtensionInfo.arkTSMode;
    extensionAbilityInfo.permissions = innerExtensionInfo.permissions;
    extensionAbilityInfo.appIdentifierAllowList = innerExtensionInfo.appIdentifierAllowList;
    extensionAbilityInfo.metadata = innerExtensionInfo.metadata;
    extensionAbilityInfo.skillUri = innerExtensionInfo.skillUri;
    extensionAbilityInfo.skills = innerExtensionInfo.skills;
    extensionAbilityInfo.dataGroupIds = innerExtensionInfo.dataGroupIds;
    extensionAbilityInfo.validDataGroupIds = innerExtensionInfo.validDataGroupIds;
    return extensionAbilityInfo;
}
}  // namespace AppExecFwk
}  // namespace OHOS
