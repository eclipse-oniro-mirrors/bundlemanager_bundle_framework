/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <cstdint>
#include <string>

#include "bundle_manager_utils.h"
#include "ipc_skeleton.h"
#include "bundle_info.h"
#include "bundle_mgr_proxy.h"
#include "common_func.h"
#include "bundle_manager_convert.h"
#include "app_log_wrapper.h"

namespace OHOS {
namespace CJSystemapi {
namespace BundleManager {
namespace Convert {

const std::string PATH_PREFIX = "/data/app/el1/bundle/public";
const std::string CODE_PATH_PREFIX = "/data/storage/el1/bundle/";
const std::string CONTEXT_DATA_STORAGE_BUNDLE("/data/storage/el1/bundle/");

char *MallocCString(const std::string &origin)
{
    if (origin.empty()) {
        return nullptr;
    }
    auto len = origin.length() + 1;
    char* res = static_cast<char *>(malloc(sizeof(char) * len));
    if (res == nullptr) {
        APP_LOGE("MallocCString malloc failed");
        return nullptr;
    }
    return std::char_traits<char>::copy(res, origin.c_str(), len);
}

void ClearCharPointer(char** ptr, int count)
{
    for (int i = 0; i < count; i++) {
        free(ptr[i]);
        ptr[i] = nullptr;
    }
}

CArrString ConvertArrString(const std::vector<std::string>& vecStr)
{
    if (vecStr.size() == 0) {
        return {nullptr, 0};
    }
    char **retValue = static_cast<char **>(malloc(sizeof(char *) * vecStr.size()));
    if (retValue == nullptr) {
        return {nullptr, 0};
    }

    for (size_t i = 0; i < vecStr.size(); i++) {
        retValue[i] = MallocCString(vecStr[i]);
        if (retValue[i] == nullptr) {
            ClearCharPointer(retValue, i);
            free(retValue);
            return {nullptr, 0};
        }
    }

    return {retValue, vecStr.size()};
}

void FreeCArrString(CArrString& cArrString)
{
    if (cArrString.head == nullptr) {
        return;
    }
    for (int64_t i = 0; i < cArrString.size; i++) {
        free(cArrString.head[i]);
        cArrString.head[i] = nullptr;
    }
    free(cArrString.head);
    cArrString.head = nullptr;
    cArrString.size = 0;
}

RetUsedScene ConvertUsedScene(const AppExecFwk::RequestPermissionUsedScene& usedScence)
{
    RetUsedScene uScene;
    uScene.abilities = ConvertArrString(usedScence.abilities);
    uScene.when = MallocCString(usedScence.when);
    return uScene;
}

void FreeRetUsedScene(RetUsedScene& uScene)
{
    FreeCArrString(uScene.abilities);
    free(uScene.when);
    uScene.when = nullptr;
}

RetMetadata ConvertMetadata(const AppExecFwk::Metadata& cData)
{
    RetMetadata data;
    data.name = MallocCString(cData.name);
    data.value = MallocCString(cData.value);
    data.resource = MallocCString(cData.resource);
    return data;
}

void FreeRetMetadata(RetMetadata& data)
{
    free(data.name);
    data.name = nullptr;
    free(data.value);
    data.value = nullptr;
    free(data.resource);
    data.resource = nullptr;
}

CResource ConvertResource(const AppExecFwk::Resource& cRes)
{
    CResource res;
    res.bundleName = MallocCString(cRes.bundleName);
    res.moduleName = MallocCString(cRes.moduleName);
    res.id = cRes.id;
    return res;
}

void FreeCResource(CResource& res)
{
    free(res.bundleName);
    res.bundleName = nullptr;
    free(res.moduleName);
    res.moduleName = nullptr;
}

CArrMetadata ConvertArrMetadata(const std::vector<AppExecFwk::Metadata>& cData)
{
    CArrMetadata data;
    data.size = static_cast<int64_t>(cData.size());
    data.head = nullptr;
    if (data.size > 0) {
        RetMetadata *retValue = reinterpret_cast<RetMetadata *>(malloc(sizeof(RetMetadata) * data.size));
        if (retValue != nullptr) {
            for (int32_t i = 0; i < data.size; i++) {
                retValue[i] = ConvertMetadata(cData[i]);
            }
            data.head = retValue;
        } else {
            APP_LOGE("ConvertArrMetadata malloc failed");
            return data;
        }
    }
    return data;
}

void FreeCArrMetadata(CArrMetadata& data)
{
    if (data.head == nullptr) {
        return;
    }
    for (int64_t i = 0; i < data.size; i++) {
        FreeRetMetadata(data.head[i]);
    }
    free(data.head);
    data.head = nullptr;
    data.size = 0;
}

CArrMoMeta ConvertArrMoMeta(const std::map<std::string, std::vector<AppExecFwk::Metadata>>& metadata)
{
    CArrMoMeta arrMdata;
    arrMdata.size = static_cast<int64_t>(metadata.size());
    arrMdata.head = nullptr;
    if (arrMdata.size > 0) {
        ModuleMetadata* retValue = reinterpret_cast<ModuleMetadata *>(malloc(sizeof(ModuleMetadata) * arrMdata.size));
        if (retValue != nullptr) {
            int32_t i = 0;
            for (const auto &item : metadata) {
                retValue[i].moduleName = MallocCString(item.first);
                retValue[i++].metadata = ConvertArrMetadata(item.second);
            }
        } else {
            APP_LOGE("ConvertArrMoMeta malloc failed");
            return arrMdata;
        }
        arrMdata.head = retValue;
    }
    return arrMdata;
}

void FreeModuleMetadata(ModuleMetadata& metadata)
{
    free(metadata.moduleName);
    metadata.moduleName = nullptr;
    FreeCArrMetadata(metadata.metadata);
}

void FreeCArrMoMeta(CArrMoMeta& arrMdata)
{
    if (arrMdata.head == nullptr) {
        return;
    }
    for (int64_t i = 0; i < arrMdata.size; i++) {
        FreeModuleMetadata(arrMdata.head[i]);
    }
    free(arrMdata.head);
    arrMdata.head = nullptr;
    arrMdata.size = 0;
}

RetSkillUri ConvertSkillUri(const AppExecFwk::SkillUri& cUri)
{
    RetSkillUri skillUri;
    skillUri.scheme = MallocCString(cUri.scheme);
    skillUri.host = MallocCString(cUri.host);
    skillUri.port = MallocCString(cUri.port);
    skillUri.path = MallocCString(cUri.path);
    skillUri.pathStartWith = MallocCString(cUri.pathStartWith);
    skillUri.pathRegex = MallocCString(cUri.pathRegex);
    skillUri.type = MallocCString(cUri.type);
    skillUri.utd = MallocCString(cUri.utd);
    skillUri.maxFileSupported = cUri.maxFileSupported;
    skillUri.linkFeature = MallocCString(cUri.linkFeature);
    return skillUri;
}

void FreeRetSkillUri(RetSkillUri& skillUri)
{
    free(skillUri.scheme);
    skillUri.scheme = nullptr;
    free(skillUri.host);
    skillUri.host = nullptr;
    free(skillUri.port);
    skillUri.port = nullptr;
    free(skillUri.path);
    skillUri.path = nullptr;
    free(skillUri.pathStartWith);
    skillUri.pathStartWith = nullptr;
    free(skillUri.pathRegex);
    skillUri.pathRegex = nullptr;
    free(skillUri.type);
    skillUri.type = nullptr;
    free(skillUri.utd);
    skillUri.utd = nullptr;
    free(skillUri.linkFeature);
    skillUri.linkFeature = nullptr;
}

RetCArrSkillUri ConvertArrSkillUris(const std::vector<AppExecFwk::SkillUri>& cUris)
{
    RetCArrSkillUri skillUris;
    skillUris.size = static_cast<int64_t>(cUris.size());
    skillUris.head = nullptr;

    if (skillUris.size == 0) {
        return skillUris;
    }
    RetSkillUri *retValue = reinterpret_cast<RetSkillUri *>(malloc(sizeof(RetSkillUri) * skillUris.size));
    if (retValue != nullptr) {
        for (int32_t i = 0; i < skillUris.size; i++) {
            retValue[i] = ConvertSkillUri(cUris[i]);
        }
        skillUris.head = retValue;
    } else {
        APP_LOGE("ConvertArrSkillUris malloc failed");
        return skillUris;
    }
    return skillUris;
}

void FreeRetCArrSkillUri(RetCArrSkillUri& skillUris)
{
    if (skillUris.head == nullptr) {
        return;
    }
    for (int64_t i = 0; i < skillUris.size; i++) {
        FreeRetSkillUri(skillUris.head[i]);
    }
    free(skillUris.head);
    skillUris.head = nullptr;
    skillUris.size = 0;
}

RetSkill ConvertSkill(const AppExecFwk::Skill& cSkill)
{
    RetSkill skill;
    skill.actions = ConvertArrString(cSkill.actions);
    skill.entities = ConvertArrString(cSkill.entities);
    skill.uris = ConvertArrSkillUris(cSkill.uris);
    skill.domainVerify = cSkill.domainVerify;
    return skill;
}

void FreeRetSkill(RetSkill& skill)
{
    FreeCArrString(skill.actions);
    FreeCArrString(skill.entities);
    FreeRetCArrSkillUri(skill.uris);
}

RetCArrSkill ConvertSkills(const std::vector<AppExecFwk::Skill>& cSkills)
{
    RetCArrSkill skills;
    skills.size = static_cast<int64_t>(cSkills.size());
    skills.head = nullptr;
    if (skills.size == 0) {
        return skills;
    }
    RetSkill *retValue = reinterpret_cast<RetSkill *>(malloc(sizeof(RetSkill) * skills.size));
    if (retValue != nullptr) {
        for (int32_t i = 0; i < skills.size; i++) {
            retValue[i] = ConvertSkill(cSkills[i]);
        }
        skills.head = retValue;
    } else {
        APP_LOGE("ConvertSkills malloc failed");
        return skills;
    }
    return skills;
}

void FreeRetCArrSkill(RetCArrSkill& skills)
{
    if (skills.head == nullptr) {
        return;
    }
    for (int64_t i = 0; i < skills.size; i++) {
        FreeRetSkill(skills.head[i]);
    }
    free(skills.head);
    skills.head = nullptr;
    skills.size = 0;
}

RetReqPermissionDetail ConvertRequestPermission(const AppExecFwk::RequestPermission& requestPermission)
{
    RetReqPermissionDetail reqPer;
    reqPer.name = MallocCString(requestPermission.name);
    reqPer.moduleName = MallocCString(requestPermission.moduleName);
    reqPer.reason = MallocCString(requestPermission.reason);
    reqPer.reasonId = requestPermission.reasonId;
    reqPer.usedScence = ConvertUsedScene(requestPermission.usedScene);
    return reqPer;
}

void FreeRetReqPermissionDetail(RetReqPermissionDetail& reqPer)
{
    free(reqPer.name);
    reqPer.name = nullptr;
    free(reqPer.moduleName);
    reqPer.moduleName = nullptr;
    free(reqPer.reason);
    reqPer.reason = nullptr;
    FreeRetUsedScene(reqPer.usedScence);
}

RetApplicationInfo ConvertApplicationInfo(const AppExecFwk::ApplicationInfo& cAppInfo)
{
    RetApplicationInfo appInfo;
    appInfo.name = MallocCString(cAppInfo.name);
    appInfo.description = MallocCString(cAppInfo.description);
    appInfo.descriptionId = cAppInfo.descriptionId;
    appInfo.enabled = cAppInfo.enabled;
    appInfo.label = MallocCString(cAppInfo.label);
    appInfo.labelId = cAppInfo.labelId;
    appInfo.icon = MallocCString(cAppInfo.iconPath);
    appInfo.iconId = cAppInfo.iconId;
    appInfo.process = MallocCString(cAppInfo.process);

    appInfo.permissions = ConvertArrString(cAppInfo.permissions);

    appInfo.codePath = MallocCString(cAppInfo.codePath);

    appInfo.metadataArray = ConvertArrMoMeta(cAppInfo.metadata);

    appInfo.removable = cAppInfo.removable;
    appInfo.accessTokenId = cAppInfo.accessTokenId;
    appInfo.uid = cAppInfo.uid;

    appInfo.iconResource = ConvertResource(cAppInfo.iconResource);
    appInfo.labelResource = ConvertResource(cAppInfo.labelResource);
    appInfo.descriptionResource = ConvertResource(cAppInfo.descriptionResource);

    appInfo.appDistributionType = MallocCString(cAppInfo.appDistributionType);
    appInfo.appProvisionType = MallocCString(cAppInfo.appProvisionType);
    appInfo.systemApp = cAppInfo.isSystemApp;
    appInfo.bundleType = static_cast<int32_t>(cAppInfo.bundleType);
    appInfo.debug = cAppInfo.debug;
    appInfo.dataUnclearable = !cAppInfo.userDataClearable;
    appInfo.cloudFileSyncEnabled = cAppInfo.cloudFileSyncEnabled;
    return appInfo;
}

RetApplicationInfoV2 ConvertApplicationInfoV2(const AppExecFwk::ApplicationInfo& cAppInfo)
{
    RetApplicationInfoV2 appInfo;
    appInfo.name = MallocCString(cAppInfo.name);
    appInfo.description = MallocCString(cAppInfo.description);
    appInfo.descriptionId = cAppInfo.descriptionId;
    appInfo.enabled = cAppInfo.enabled;
    appInfo.label = MallocCString(cAppInfo.label);
    appInfo.labelId = cAppInfo.labelId;
    appInfo.icon = MallocCString(cAppInfo.iconPath);
    appInfo.iconId = cAppInfo.iconId;
    appInfo.process = MallocCString(cAppInfo.process);

    appInfo.permissions = ConvertArrString(cAppInfo.permissions);

    appInfo.codePath = MallocCString(cAppInfo.codePath);

    appInfo.metadataArray = ConvertArrMoMeta(cAppInfo.metadata);

    appInfo.removable = cAppInfo.removable;
    appInfo.accessTokenId = cAppInfo.accessTokenId;
    appInfo.uid = cAppInfo.uid;

    appInfo.iconResource = ConvertResource(cAppInfo.iconResource);
    appInfo.labelResource = ConvertResource(cAppInfo.labelResource);
    appInfo.descriptionResource = ConvertResource(cAppInfo.descriptionResource);

    appInfo.appDistributionType = MallocCString(cAppInfo.appDistributionType);
    appInfo.appProvisionType = MallocCString(cAppInfo.appProvisionType);
    appInfo.systemApp = cAppInfo.isSystemApp;
    appInfo.bundleType = static_cast<int32_t>(cAppInfo.bundleType);
    appInfo.debug = cAppInfo.debug;
    appInfo.dataUnclearable = !cAppInfo.userDataClearable;
    appInfo.cloudFileSyncEnabled = cAppInfo.cloudFileSyncEnabled;
    std::string externalNativeLibraryPath = "";
    if (!cAppInfo.nativeLibraryPath.empty()) {
        externalNativeLibraryPath = CONTEXT_DATA_STORAGE_BUNDLE + cAppInfo.nativeLibraryPath;
    }
    appInfo.nativeLibraryPath = MallocCString(externalNativeLibraryPath);
    appInfo.multiAppMode.multiAppModeType = static_cast<int32_t>(cAppInfo.multiAppMode.multiAppModeType);
    appInfo.multiAppMode.count = cAppInfo.multiAppMode.maxCount;
    appInfo.appIndex = cAppInfo.appIndex;
    appInfo.installSource =  MallocCString(cAppInfo.installSource);
    appInfo.releaseType = MallocCString(cAppInfo.apiReleaseType);
    return appInfo;
}

void FreeRetApplicationInfoV2(RetApplicationInfoV2& appInfo)
{
    free(appInfo.name);
    appInfo.name = nullptr;
    free(appInfo.description);
    appInfo.description = nullptr;
    free(appInfo.label);
    appInfo.label = nullptr;
    free(appInfo.icon);
    appInfo.icon = nullptr;
    free(appInfo.process);
    appInfo.process = nullptr;
    FreeCArrString(appInfo.permissions);
    free(appInfo.codePath);
    appInfo.codePath = nullptr;
    FreeCArrMoMeta(appInfo.metadataArray);
    FreeCResource(appInfo.iconResource);
    FreeCResource(appInfo.labelResource);
    FreeCResource(appInfo.descriptionResource);
    free(appInfo.appDistributionType);
    appInfo.appDistributionType = nullptr;
    free(appInfo.appProvisionType);
    appInfo.appProvisionType = nullptr;
    free(appInfo.nativeLibraryPath);
    appInfo.nativeLibraryPath = nullptr;
    free(appInfo.installSource);
    appInfo.installSource = nullptr;
    free(appInfo.releaseType);
    appInfo.releaseType = nullptr;
}

RetExtensionAbilityInfo ConvertExtensionAbilityInfo(const AppExecFwk::ExtensionAbilityInfo& extensionInfos)
{
    RetExtensionAbilityInfo exInfo;
    exInfo.bundleName = MallocCString(extensionInfos.bundleName);
    exInfo.moduleName = MallocCString(extensionInfos.moduleName);
    exInfo.name = MallocCString(extensionInfos.name);
    exInfo.labelId = extensionInfos.labelId;
    exInfo.descriptionId = extensionInfos.descriptionId;
    exInfo.iconId = extensionInfos.iconId;
    exInfo.exported = extensionInfos.visible;
    exInfo.extensionAbilityType = static_cast<int32_t>(extensionInfos.type);
    exInfo.permissions = ConvertArrString(extensionInfos.permissions);
    exInfo.applicationInfo = ConvertApplicationInfo(extensionInfos.applicationInfo);
    exInfo.metadata = ConvertArrMetadata(extensionInfos.metadata);
    exInfo.enabled = extensionInfos.enabled;
    exInfo.readPermission = MallocCString(extensionInfos.readPermission);
    exInfo.writePermission = MallocCString(extensionInfos.writePermission);
    exInfo.extensionAbilityTypeName = MallocCString(extensionInfos.extensionTypeName);
    return exInfo;
}

RetExtensionAbilityInfoV2 ConvertExtensionAbilityInfoV2(const AppExecFwk::ExtensionAbilityInfo& extensionInfos)
{
    RetExtensionAbilityInfoV2 exInfo;
    exInfo.bundleName = MallocCString(extensionInfos.bundleName);
    exInfo.moduleName = MallocCString(extensionInfos.moduleName);
    exInfo.name = MallocCString(extensionInfos.name);
    exInfo.labelId = extensionInfos.labelId;
    exInfo.descriptionId = extensionInfos.descriptionId;
    exInfo.iconId = extensionInfos.iconId;
    exInfo.exported = extensionInfos.visible;
    exInfo.extensionAbilityType = static_cast<int32_t>(extensionInfos.type);
    exInfo.permissions = ConvertArrString(extensionInfos.permissions);
    exInfo.applicationInfo = ConvertApplicationInfoV2(extensionInfos.applicationInfo);
    exInfo.metadata = ConvertArrMetadata(extensionInfos.metadata);
    exInfo.enabled = extensionInfos.enabled;
    exInfo.readPermission = MallocCString(extensionInfos.readPermission);
    exInfo.writePermission = MallocCString(extensionInfos.writePermission);
    exInfo.extensionAbilityTypeName = MallocCString(extensionInfos.extensionTypeName);
    exInfo.skills = ConvertSkills(extensionInfos.skills);
    exInfo.appIndex = extensionInfos.appIndex;
    return exInfo;
}

void FreeRetExtensionAbilityInfoV2(RetExtensionAbilityInfoV2& exInfo)
{
    free(exInfo.bundleName);
    exInfo.bundleName = nullptr;
    free(exInfo.moduleName);
    exInfo.moduleName = nullptr;
    free(exInfo.name);
    exInfo.name = nullptr;
    FreeCArrString(exInfo.permissions);
    FreeRetApplicationInfoV2(exInfo.applicationInfo);
    FreeCArrMetadata(exInfo.metadata);
    free(exInfo.readPermission);
    exInfo.readPermission = nullptr;
    free(exInfo.writePermission);
    exInfo.writePermission = nullptr;
    free(exInfo.extensionAbilityTypeName);
    exInfo.extensionAbilityTypeName = nullptr;
    FreeRetCArrSkill(exInfo.skills);
}

CArrRetExtensionAbilityInfo ConvertArrExtensionAbilityInfo(
    const std::vector<AppExecFwk::ExtensionAbilityInfo>& extensionInfos)
{
    CArrRetExtensionAbilityInfo exAbInfo;
    exAbInfo.size = static_cast<int64_t>(extensionInfos.size());
    exAbInfo.head = nullptr;
    if (exAbInfo.size > 0) {
        RetExtensionAbilityInfo *retValue = reinterpret_cast<RetExtensionAbilityInfo *>
        (malloc(sizeof(RetExtensionAbilityInfo) * exAbInfo.size));
        if (retValue != nullptr) {
            for (int32_t i = 0; i < exAbInfo.size; i++) {
                retValue[i] = ConvertExtensionAbilityInfo(extensionInfos[i]);
            }
            exAbInfo.head = retValue;
        } else {
            APP_LOGE("ConvertArrExtensionAbilityInfo malloc failed");
            return exAbInfo;
        }
    }
    return exAbInfo;
}

CArrRetExtensionAbilityInfoV2 ConvertArrExtensionAbilityInfoV2(
    const std::vector<AppExecFwk::ExtensionAbilityInfo>& extensionInfos)
{
    CArrRetExtensionAbilityInfoV2 exAbInfo;
    exAbInfo.size = static_cast<int64_t>(extensionInfos.size());
    exAbInfo.head = nullptr;
    if (exAbInfo.size > 0) {
        RetExtensionAbilityInfoV2 *retValue = reinterpret_cast<RetExtensionAbilityInfoV2 *>
        (malloc(sizeof(RetExtensionAbilityInfoV2) * exAbInfo.size));
        if (retValue != nullptr) {
            for (int32_t i = 0; i < exAbInfo.size; i++) {
                retValue[i] = ConvertExtensionAbilityInfoV2(extensionInfos[i]);
            }
            exAbInfo.head = retValue;
        } else {
            APP_LOGE("ConvertArrExtensionAbilityInfo malloc failed");
            return exAbInfo;
        }
    }
    return exAbInfo;
}

void FreeCArrRetExtensionAbilityInfoV2(CArrRetExtensionAbilityInfoV2 exAbInfo)
{
    if (exAbInfo.head == nullptr) {
        return;
    }
    for (int64_t i = 0; i < exAbInfo.size; i++) {
        FreeRetExtensionAbilityInfoV2(exAbInfo.head[i]);
    }
    free(exAbInfo.head);
    exAbInfo.head = nullptr;
    exAbInfo.size = 0;
}

RetSignatureInfo ConvertSignatureInfo(const AppExecFwk::SignatureInfo& cSignatureInfo)
{
    RetSignatureInfo signatureInfo;
    signatureInfo.appId = MallocCString(cSignatureInfo.appId);
    signatureInfo.fingerprint = MallocCString(cSignatureInfo.fingerprint);
    signatureInfo.appIdentifier = MallocCString(cSignatureInfo.appIdentifier);
    return signatureInfo;
}

void FreeRetSignatureInfo(RetSignatureInfo& signatureInfo)
{
    free(signatureInfo.appId);
    signatureInfo.appId = nullptr;
    free(signatureInfo.fingerprint);
    signatureInfo.fingerprint = nullptr;
    free(signatureInfo.appIdentifier);
    signatureInfo.appIdentifier = nullptr;
}

RetAbilityInfo ConvertAbilityInfo(const AppExecFwk::AbilityInfo& cAbilityInfos)
{
    RetAbilityInfo abInfo;
    abInfo.bundleName = MallocCString(cAbilityInfos.bundleName);
    abInfo.moduleName = MallocCString(cAbilityInfos.moduleName);
    abInfo.name = MallocCString(cAbilityInfos.name);
    abInfo.label = MallocCString(cAbilityInfos.label);
    abInfo.labelId = cAbilityInfos.labelId;
    abInfo.description = MallocCString(cAbilityInfos.description);
    abInfo.descriptionId = cAbilityInfos.descriptionId;
    abInfo.icon = MallocCString(cAbilityInfos.iconPath);
    abInfo.iconId = cAbilityInfos.iconId;
    abInfo.process = MallocCString(cAbilityInfos.process);
    abInfo.exported = cAbilityInfos.visible;
    abInfo.orientation = static_cast<int32_t>(cAbilityInfos.orientation);
    abInfo.launchType = static_cast<int32_t>(cAbilityInfos.launchMode);
    abInfo.permissions = ConvertArrString(cAbilityInfos.permissions);
    abInfo.deviceTypes = ConvertArrString(cAbilityInfos.deviceTypes);
    abInfo.applicationInfo = ConvertApplicationInfo(cAbilityInfos.applicationInfo);
    abInfo.metadata = ConvertArrMetadata(cAbilityInfos.metadata);
    abInfo.enabled = cAbilityInfos.enabled;

    abInfo.supportWindowModes.size = static_cast<int64_t>(cAbilityInfos.windowModes.size());
    abInfo.supportWindowModes.head = nullptr;
    if (abInfo.supportWindowModes.size > 0) {
        int32_t *retValue = static_cast<int32_t *>(malloc(sizeof(int32_t) * abInfo.supportWindowModes.size));
        if (retValue != nullptr) {
            for (int32_t i = 0; i < abInfo.supportWindowModes.size; i++) {
                retValue[i] = static_cast<int32_t>(cAbilityInfos.windowModes[i]);
            }
            abInfo.supportWindowModes.head = retValue;
        } else {
            APP_LOGE("ConvertAbilityInfo malloc failed");
            return abInfo;
        }
    }

    abInfo.windowSize.maxWindowRatio = cAbilityInfos.maxWindowRatio;
    abInfo.windowSize.minWindowRatio = cAbilityInfos.minWindowRatio;
    abInfo.windowSize.maxWindowWidth = cAbilityInfos.maxWindowWidth;
    abInfo.windowSize.minWindowWidth = cAbilityInfos.minWindowWidth;
    abInfo.windowSize.maxWindowHeight = cAbilityInfos.maxWindowHeight;
    abInfo.windowSize.minWindowHeight = cAbilityInfos.minWindowHeight;
    return abInfo;
}

RetAbilityInfoV2 ConvertAbilityInfoV2(const AppExecFwk::AbilityInfo& cAbilityInfos)
{
    RetAbilityInfoV2 abInfo;
    abInfo.bundleName = MallocCString(cAbilityInfos.bundleName);
    abInfo.moduleName = MallocCString(cAbilityInfos.moduleName);
    abInfo.name = MallocCString(cAbilityInfos.name);
    abInfo.label = MallocCString(cAbilityInfos.label);
    abInfo.labelId = cAbilityInfos.labelId;
    abInfo.description = MallocCString(cAbilityInfos.description);
    abInfo.descriptionId = cAbilityInfos.descriptionId;
    abInfo.icon = MallocCString(cAbilityInfos.iconPath);
    abInfo.iconId = cAbilityInfos.iconId;
    abInfo.process = MallocCString(cAbilityInfos.process);
    abInfo.exported = cAbilityInfos.visible;
    abInfo.orientation = static_cast<int32_t>(cAbilityInfos.orientation);
    abInfo.launchType = static_cast<int32_t>(cAbilityInfos.launchMode);
    abInfo.permissions = ConvertArrString(cAbilityInfos.permissions);
    abInfo.deviceTypes = ConvertArrString(cAbilityInfos.deviceTypes);
    abInfo.applicationInfo = ConvertApplicationInfoV2(cAbilityInfos.applicationInfo);
    abInfo.metadata = ConvertArrMetadata(cAbilityInfos.metadata);
    abInfo.enabled = cAbilityInfos.enabled;

    abInfo.supportWindowModes.size = static_cast<int64_t>(cAbilityInfos.windowModes.size());
    abInfo.supportWindowModes.head = nullptr;
    if (abInfo.supportWindowModes.size > 0) {
        int32_t *retValue = static_cast<int32_t *>(malloc(sizeof(int32_t) * abInfo.supportWindowModes.size));
        if (retValue != nullptr) {
            for (int32_t i = 0; i < abInfo.supportWindowModes.size; i++) {
                retValue[i] = static_cast<int32_t>(cAbilityInfos.windowModes[i]);
            }
            abInfo.supportWindowModes.head = retValue;
        } else {
            APP_LOGE("ConvertAbilityInfo malloc failed");
            return abInfo;
        }
    }

    abInfo.windowSize.maxWindowRatio = cAbilityInfos.maxWindowRatio;
    abInfo.windowSize.minWindowRatio = cAbilityInfos.minWindowRatio;
    abInfo.windowSize.maxWindowWidth = cAbilityInfos.maxWindowWidth;
    abInfo.windowSize.minWindowWidth = cAbilityInfos.minWindowWidth;
    abInfo.windowSize.maxWindowHeight = cAbilityInfos.maxWindowHeight;
    abInfo.windowSize.minWindowHeight = cAbilityInfos.minWindowHeight;

    abInfo.excludeFromDock = cAbilityInfos.excludeFromDock;
    abInfo.skills = ConvertSkills(cAbilityInfos.skills);
    return abInfo;
}

void FreeRetAbilityInfoV2(RetAbilityInfoV2& abInfo)
{
    free(abInfo.bundleName);
    abInfo.bundleName = nullptr;
    free(abInfo.moduleName);
    abInfo.moduleName = nullptr;
    free(abInfo.name);
    abInfo.name = nullptr;
    free(abInfo.label);
    abInfo.label = nullptr;
    free(abInfo.description);
    abInfo.description = nullptr;
    free(abInfo.icon);
    abInfo.icon = nullptr;
    free(abInfo.process);
    abInfo.process = nullptr;
    FreeCArrString(abInfo.permissions);
    FreeCArrString(abInfo.deviceTypes);
    FreeRetApplicationInfoV2(abInfo.applicationInfo);
    FreeCArrMetadata(abInfo.metadata);
    free(abInfo.supportWindowModes.head);
    abInfo.supportWindowModes.head = nullptr;
    FreeRetCArrSkill(abInfo.skills);
}

CArrRetAbilityInfo ConvertArrAbilityInfo(const std::vector<AppExecFwk::AbilityInfo>& abilityInfos)
{
    CArrRetAbilityInfo abInfo;
    abInfo.size = static_cast<int64_t>(abilityInfos.size());
    abInfo.head = nullptr;
    if (abInfo.size > 0) {
        RetAbilityInfo *retValue = reinterpret_cast<RetAbilityInfo *>(malloc(sizeof(RetAbilityInfo) * abInfo.size));
        if (retValue != nullptr) {
            for (int32_t i = 0; i < abInfo.size; i++) {
                retValue[i] = ConvertAbilityInfo(abilityInfos[i]);
            }
            abInfo.head = retValue;
        } else {
            APP_LOGE("ConvertArrAbilityInfo malloc failed");
            return abInfo;
        }
    }
    return abInfo;
}

CArrRetAbilityInfoV2 ConvertArrAbilityInfoV2(const std::vector<AppExecFwk::AbilityInfo>& abilityInfos)
{
    CArrRetAbilityInfoV2 abInfo;
    abInfo.size = static_cast<int64_t>(abilityInfos.size());
    abInfo.head = nullptr;
    if (abInfo.size > 0) {
        RetAbilityInfoV2 *retValue =
            reinterpret_cast<RetAbilityInfoV2 *>(malloc(sizeof(RetAbilityInfoV2) * abInfo.size));
        if (retValue != nullptr) {
            for (int32_t i = 0; i < abInfo.size; i++) {
                retValue[i] = ConvertAbilityInfoV2(abilityInfos[i]);
            }
            abInfo.head = retValue;
        } else {
            APP_LOGE("ConvertArrAbilityInfo malloc failed");
            return abInfo;
        }
    }
    return abInfo;
}

void FreeCArrRetAbilityInfoV2(CArrRetAbilityInfoV2& abInfo)
{
    if (abInfo.head == nullptr) {
        return;
    }
    for (int64_t i = 0; i < abInfo.size; i++) {
        FreeRetAbilityInfoV2(abInfo.head[i]);
    }
    free(abInfo.head);
    abInfo.head = nullptr;
    abInfo.size = 0;
}

CArrRetPreloadItem ConvertPreloadItem(const std::vector<AppExecFwk::PreloadItem>& preloads)
{
    CArrRetPreloadItem pLoad;
    pLoad.size = static_cast<int64_t>(preloads.size());
    pLoad.head = nullptr;
    if (pLoad.size > 0) {
        RetPreloadItem *retValue = reinterpret_cast<RetPreloadItem *>(malloc(sizeof(RetPreloadItem) * pLoad.size));
        if (retValue != nullptr) {
            for (int32_t i = 0; i < pLoad.size; i++) {
                retValue[i].moduleName = MallocCString(preloads[i].moduleName);
            }
            pLoad.head = retValue;
        } else {
            APP_LOGE("ConvertPreloadItem malloc failed");
            return pLoad;
        }
    }
    return pLoad;
}

void FreeCArrRetPreloadItem(CArrRetPreloadItem pLoad)
{
    if (pLoad.head == nullptr) {
        return;
    }
    for (int64_t i = 0; i < pLoad.size; i++) {
        free(pLoad.head[i].moduleName);
        pLoad.head[i].moduleName = nullptr;
    }
    free(pLoad.head);
    pLoad.head = nullptr;
    pLoad.size = 0;
}

CArrRetDependency ConvertDependency(const std::vector<AppExecFwk::Dependency>& dependencies)
{
    CArrRetDependency dep;
    dep.size = static_cast<int64_t>(dependencies.size());
    dep.head = nullptr;
    if (dep.size > 0) {
        RetDependency *retValue = reinterpret_cast<RetDependency *>(malloc(sizeof(RetDependency) * dep.size));
        if (retValue != nullptr) {
            for (int32_t i = 0; i < dep.size; i++) {
                retValue[i].bundleName = MallocCString(dependencies[i].bundleName);
                retValue[i].moduleName = MallocCString(dependencies[i].moduleName);
                retValue[i].versionCode = dependencies[i].versionCode;
            }
            dep.head = retValue;
        } else {
            APP_LOGE("ConvertDependency malloc failed");
            return dep;
        }
    }
    return dep;
}

void FreeCArrRetDependency(CArrRetDependency& dep)
{
    if (dep.head == nullptr) {
        return;
    }
    for (int64_t i = 0; i < dep.size; i++) {
        free(dep.head[i].bundleName);
        dep.head[i].bundleName = nullptr;
        free(dep.head[i].moduleName);
        dep.head[i].moduleName = nullptr;
    }
    free(dep.head);
    dep.head = nullptr;
    dep.size = 0;
}

CArrDataItem ConvertArrDataItem(const std::map<std::string, std::string>& data)
{
    CArrDataItem dataItems;
    dataItems.size = static_cast<int64_t>(data.size());
    dataItems.head = nullptr;

    if (dataItems.size == 0) {
        return dataItems;
    }
    CDataItem *retValue = reinterpret_cast<CDataItem *>
                                        (malloc(sizeof(CDataItem) * dataItems.size));
    if (retValue != nullptr) {
        int i = 0;
        for (auto it = data.begin(); it != data.end(); ++it) {
            retValue[i].key = MallocCString(it->first);
            retValue[i].value = MallocCString(it->second);
            i = i + 1;
        }
        dataItems.head = retValue;
    } else {
        APP_LOGE("ConvertArrDataItem malloc failed");
        return dataItems;
    }
    return dataItems;
}

void FreeCArrDataItem(CArrDataItem& dataItems)
{
    if (dataItems.head == nullptr) {
        return;
    }
    for (int64_t i = 0; i < dataItems.size; i++) {
        free(dataItems.head[i].key);
        dataItems.head[i].key = nullptr;
        free(dataItems.head[i].value);
        dataItems.head[i].value = nullptr;
    }
    free(dataItems.head);
    dataItems.head = nullptr;
    dataItems.size = 0;
}

CRouterItem ConvertRouterItem(const AppExecFwk::RouterItem& router)
{
    CRouterItem routerItem;
    routerItem.name = MallocCString(router.name);
    routerItem.pageSourceFile = MallocCString(router.pageSourceFile);
    routerItem.buildFunction = MallocCString(router.buildFunction);
    routerItem.data = ConvertArrDataItem(router.data);
    routerItem.customData = MallocCString(router.customData);
    return routerItem;
}

void FreeCRouterItem(CRouterItem& routerItem)
{
    free(routerItem.name);
    routerItem.name = nullptr;
    free(routerItem.pageSourceFile);
    routerItem.pageSourceFile = nullptr;
    free(routerItem.buildFunction);
    routerItem.buildFunction = nullptr;
    FreeCArrDataItem(routerItem.data);
    free(routerItem.customData);
    routerItem.customData = nullptr;
}

CArrRouterItem ConvertRouterMap(const std::vector<AppExecFwk::RouterItem>& routerArray)
{
    CArrRouterItem routerMap;
    routerMap.size = static_cast<int64_t>(routerArray.size());
    routerMap.head = nullptr;

    if (routerMap.size == 0) {
        return routerMap;
    }

    CRouterItem *retValue = reinterpret_cast<CRouterItem *>
                                        (malloc(sizeof(CRouterItem) * routerMap.size));
    if (retValue != nullptr) {
        for (int32_t i = 0; i < routerMap.size; i++) {
            retValue[i] = ConvertRouterItem(routerArray[i]);
        }
        routerMap.head = retValue;
    } else {
        APP_LOGE("ConvertRouterMap malloc failed");
        return routerMap;
    }
    return routerMap;
}

void FreeCArrRouterItem(CArrRouterItem& routerMap)
{
    if (routerMap.head == nullptr) {
        return;
    }
    for (int64_t i = 0; i < routerMap.size; i++) {
        FreeCRouterItem(routerMap.head[i]);
    }
    free(routerMap.head);
    routerMap.head = nullptr;
    routerMap.size = 0;
}

RetHapModuleInfo ConvertHapModuleInfo(const AppExecFwk::HapModuleInfo& hapModuleInfo)
{
    RetHapModuleInfo hapInfo;
    hapInfo.name = MallocCString(hapModuleInfo.name);
    hapInfo.icon = MallocCString(hapModuleInfo.iconPath);
    hapInfo.iconId = hapModuleInfo.iconId;
    hapInfo.label = MallocCString(hapModuleInfo.label);
    hapInfo.labelId = hapModuleInfo.labelId;
    hapInfo.description = MallocCString(hapModuleInfo.description);
    hapInfo.descriptionId = hapModuleInfo.descriptionId;
    hapInfo.mainElementName = MallocCString(hapModuleInfo.mainElementName);

    hapInfo.abilitiesInfo = ConvertArrAbilityInfo(hapModuleInfo.abilityInfos);

    hapInfo.extensionAbilitiesInfo = ConvertArrExtensionAbilityInfo(hapModuleInfo.extensionInfos);

    hapInfo.metadata = ConvertArrMetadata(hapModuleInfo.metadata);

    hapInfo.deviceTypes = ConvertArrString(hapModuleInfo.deviceTypes);

    hapInfo.installationFree = hapModuleInfo.installationFree;
    hapInfo.hashValue = MallocCString(hapModuleInfo.hashValue);
    hapInfo.moduleType = static_cast<int32_t>(hapModuleInfo.moduleType);

    hapInfo.preloads = ConvertPreloadItem(hapModuleInfo.preloads);

    hapInfo.dependencies = ConvertDependency(hapModuleInfo.dependencies);

    if (!hapModuleInfo.fileContextMenu.empty()) {
        hapInfo.fileContextMenuConfig = MallocCString(hapModuleInfo.fileContextMenu);
    } else {
        hapInfo.fileContextMenuConfig = MallocCString("");
    }
    return hapInfo;
}

RetHapModuleInfoV2 ConvertHapModuleInfoV2(const AppExecFwk::HapModuleInfo& hapModuleInfo)
{
    RetHapModuleInfoV2 hapInfo;
    hapInfo.name = MallocCString(hapModuleInfo.name);
    hapInfo.icon = MallocCString(hapModuleInfo.iconPath);
    hapInfo.iconId = hapModuleInfo.iconId;
    hapInfo.label = MallocCString(hapModuleInfo.label);
    hapInfo.labelId = hapModuleInfo.labelId;
    hapInfo.description = MallocCString(hapModuleInfo.description);
    hapInfo.descriptionId = hapModuleInfo.descriptionId;
    hapInfo.mainElementName = MallocCString(hapModuleInfo.mainElementName);

    hapInfo.abilitiesInfo = ConvertArrAbilityInfoV2(hapModuleInfo.abilityInfos);

    hapInfo.extensionAbilitiesInfo = ConvertArrExtensionAbilityInfoV2(hapModuleInfo.extensionInfos);

    hapInfo.metadata = ConvertArrMetadata(hapModuleInfo.metadata);

    hapInfo.deviceTypes = ConvertArrString(hapModuleInfo.deviceTypes);

    hapInfo.installationFree = hapModuleInfo.installationFree;
    hapInfo.hashValue = MallocCString(hapModuleInfo.hashValue);
    hapInfo.moduleType = static_cast<int32_t>(hapModuleInfo.moduleType);

    hapInfo.preloads = ConvertPreloadItem(hapModuleInfo.preloads);

    hapInfo.dependencies = ConvertDependency(hapModuleInfo.dependencies);

    if (!hapModuleInfo.fileContextMenu.empty()) {
        hapInfo.fileContextMenuConfig = MallocCString(hapModuleInfo.fileContextMenu);
    } else {
        hapInfo.fileContextMenuConfig = MallocCString("");
    }
    hapInfo.routerMap = ConvertRouterMap(hapModuleInfo.routerArray);

    size_t result = hapModuleInfo.hapPath.find(PATH_PREFIX);
    if (result != std::string::npos) {
        size_t pos = hapModuleInfo.hapPath.find_last_of('/');
        std::string codePath = CODE_PATH_PREFIX;
        if (pos != std::string::npos && pos != hapModuleInfo.hapPath.size() - 1) {
            codePath += hapModuleInfo.hapPath.substr(pos + 1);
        }
        hapInfo.codePath = MallocCString(codePath);
    } else {
        hapInfo.codePath = MallocCString(hapModuleInfo.hapPath);
    }

    std::string externalNativeLibraryPath = "";
    if (!hapModuleInfo.nativeLibraryPath.empty() && !hapModuleInfo.moduleName.empty()) {
        externalNativeLibraryPath = CONTEXT_DATA_STORAGE_BUNDLE + hapModuleInfo.nativeLibraryPath;
    }
    hapInfo.nativeLibraryPath = MallocCString(externalNativeLibraryPath);
    return hapInfo;
}

void FreeRetHapModuleInfoV2(RetHapModuleInfoV2& hapInfo)
{
    free(hapInfo.name);
    hapInfo.name = nullptr;
    free(hapInfo.icon);
    hapInfo.icon = nullptr;
    free(hapInfo.label);
    hapInfo.label = nullptr;
    free(hapInfo.description);
    hapInfo.description = nullptr;
    free(hapInfo.mainElementName);
    hapInfo.mainElementName = nullptr;
    FreeCArrRetAbilityInfoV2(hapInfo.abilitiesInfo);
    FreeCArrRetExtensionAbilityInfoV2(hapInfo.extensionAbilitiesInfo);
    FreeCArrMetadata(hapInfo.metadata);
    FreeCArrString(hapInfo.deviceTypes);
    free(hapInfo.hashValue);
    hapInfo.hashValue = nullptr;
    FreeCArrRetPreloadItem(hapInfo.preloads);
    FreeCArrRetDependency(hapInfo.dependencies);
    free(hapInfo.fileContextMenuConfig);
    hapInfo.fileContextMenuConfig = nullptr;
    FreeCArrRouterItem(hapInfo.routerMap);
    free(hapInfo.codePath);
    hapInfo.codePath = nullptr;
    free(hapInfo.nativeLibraryPath);
    hapInfo.nativeLibraryPath = nullptr;
}

extern "C" {
#define EXPORT __attribute__((visibility("default")))
EXPORT RetAbilityInfoV2 OHOS_ConvertAbilityInfoV2(void* param)
{
    RetAbilityInfoV2 retInfo = {};
    auto abilityInfo = reinterpret_cast<AppExecFwk::AbilityInfo*>(param);
    if (abilityInfo == nullptr) {
        return retInfo;
    }
    return ConvertAbilityInfoV2(*abilityInfo);
}

EXPORT RetHapModuleInfoV2 OHOS_ConvertHapInfoV2(void* param)
{
    RetHapModuleInfoV2 retInfo = {};
    auto hapModuleInfo = reinterpret_cast<AppExecFwk::HapModuleInfo*>(param);
    if (hapModuleInfo == nullptr) {
        return retInfo;
    }
    return ConvertHapModuleInfoV2(*hapModuleInfo);
}
}

CArrHapInfo ConvertArrHapInfo(const std::vector<AppExecFwk::HapModuleInfo>& hapModuleInfos)
{
    CArrHapInfo hapInfos;
    hapInfos.size = static_cast<int64_t>(hapModuleInfos.size());
    hapInfos.head = nullptr;
    if (hapInfos.size == 0) {
        return hapInfos;
    }
    RetHapModuleInfo *retValue = reinterpret_cast<RetHapModuleInfo *>(malloc(sizeof(RetHapModuleInfo) * hapInfos.size));
    if (retValue == nullptr) {
        APP_LOGE("ConvertArrHapInfo malloc failed");
        return hapInfos;
    }
    for (int32_t i = 0; i < hapInfos.size; i++) {
        retValue[i] = ConvertHapModuleInfo(hapModuleInfos[i]);
    }
    hapInfos.head = retValue;
    return hapInfos;
}

CArrHapInfoV2 ConvertArrHapInfoV2(const std::vector<AppExecFwk::HapModuleInfo>& hapModuleInfos)
{
    CArrHapInfoV2 hapInfos;
    hapInfos.size = static_cast<int64_t>(hapModuleInfos.size());
    hapInfos.head = nullptr;
    if (hapInfos.size == 0) {
        return hapInfos;
    }
    RetHapModuleInfoV2 *retValue =
        reinterpret_cast<RetHapModuleInfoV2 *>(malloc(sizeof(RetHapModuleInfoV2) * hapInfos.size));
    if (retValue == nullptr) {
        APP_LOGE("ConvertArrHapInfo malloc failed");
        return hapInfos;
    }
    for (int32_t i = 0; i < hapInfos.size; i++) {
        retValue[i] = ConvertHapModuleInfoV2(hapModuleInfos[i]);
    }
    hapInfos.head = retValue;
    return hapInfos;
}

void FreeCArrHapInfoV2(CArrHapInfoV2 hapInfos)
{
    if (hapInfos.head == nullptr) {
        return;
    }
    for (int64_t i = 0; i < hapInfos.size; i++) {
        FreeRetHapModuleInfoV2(hapInfos.head[i]);
    }
    free(hapInfos.head);
    hapInfos.head = nullptr;
    hapInfos.size = 0;
}

CArrReqPerDetail ConvertArrReqPerDetail(const std::vector<AppExecFwk::RequestPermission>& reqPermissionDetails)
{
    CArrReqPerDetail perDetail;
    perDetail.size = static_cast<int64_t>(reqPermissionDetails.size());
    perDetail.head = nullptr;
    if (perDetail.size > 0) {
        RetReqPermissionDetail *retValue = reinterpret_cast<RetReqPermissionDetail *>
                                            (malloc(sizeof(RetReqPermissionDetail) * perDetail.size));
        if (retValue != nullptr) {
            for (int32_t i = 0; i < perDetail.size; i++) {
                retValue[i] = ConvertRequestPermission(reqPermissionDetails[i]);
            }
            perDetail.head = retValue;
        } else {
            APP_LOGE("ConvertArrReqPerDetail malloc failed");
            return perDetail;
        }
    }
    return perDetail;
}

void FreeCArrReqPerDetail(CArrReqPerDetail& perDetail)
{
    if (perDetail.head == nullptr) {
        return;
    }
    for (int64_t i = 0; i < perDetail.size; i++) {
        FreeRetReqPermissionDetail(perDetail.head[i]);
    }
    free(perDetail.head);
    perDetail.head = nullptr;
    perDetail.size = 0;
}

RetSignatureInfo InitSignInfo()
{
    RetSignatureInfo signatureInfo = {nullptr, nullptr, nullptr};
    return signatureInfo;
}

RetApplicationInfo InitApplicationInfo()
{
    RetApplicationInfo appInfo;
    appInfo.name = nullptr;
    appInfo.description = nullptr;
    appInfo.descriptionId = 0;
    appInfo.enabled = true;
    appInfo.label = nullptr;
    appInfo.labelId = 0;
    appInfo.icon = nullptr;
    appInfo.iconId = 0;
    appInfo.process = nullptr;
    appInfo.permissions = {nullptr, 0};
    appInfo.codePath = nullptr;
    appInfo.metadataArray = {nullptr, 0};
    appInfo.removable = true;
    appInfo.accessTokenId = 0;
    appInfo.uid = -1;
    appInfo.iconResource = {nullptr, nullptr, 0};
    appInfo.labelResource = {nullptr, nullptr, 0};
    appInfo.descriptionResource = {nullptr, nullptr, 0};
    appInfo.appDistributionType = MallocCString("none");
    appInfo.appProvisionType = MallocCString("release");
    appInfo.systemApp = false;
    appInfo.bundleType = 0;
    appInfo.debug = false;
    appInfo.dataUnclearable = false;
    appInfo.cloudFileSyncEnabled = false;
    return appInfo;
}

RetApplicationInfoV2 InitApplicationInfoV2()
{
    RetApplicationInfoV2 appInfo;
    appInfo.name = nullptr;
    appInfo.description = nullptr;
    appInfo.descriptionId = 0;
    appInfo.enabled = true;
    appInfo.label = nullptr;
    appInfo.labelId = 0;
    appInfo.icon = nullptr;
    appInfo.iconId = 0;
    appInfo.process = nullptr;
    appInfo.permissions = {nullptr, 0};
    appInfo.codePath = nullptr;
    appInfo.metadataArray = {nullptr, 0};
    appInfo.removable = true;
    appInfo.accessTokenId = 0;
    appInfo.uid = -1;
    appInfo.iconResource = {nullptr, nullptr, 0};
    appInfo.labelResource = {nullptr, nullptr, 0};
    appInfo.descriptionResource = {nullptr, nullptr, 0};
    appInfo.appDistributionType = MallocCString("none");
    appInfo.appProvisionType = MallocCString("release");
    appInfo.systemApp = false;
    appInfo.bundleType = 0;
    appInfo.debug = false;
    appInfo.dataUnclearable = false;
    appInfo.cloudFileSyncEnabled = false;
    appInfo.nativeLibraryPath = MallocCString("");
    appInfo.multiAppMode.multiAppModeType = static_cast<uint8_t>(0);
    appInfo.multiAppMode.count = 0;
    appInfo.appIndex = 0;
    appInfo.installSource = MallocCString("");
    appInfo.releaseType = MallocCString("");
    return appInfo;
}

RetBundleInfo ConvertBundleInfo(const AppExecFwk::BundleInfo& cBundleInfo, int32_t flags)
{
    RetBundleInfo bundleInfo;
    bundleInfo.name = MallocCString(cBundleInfo.name);
    bundleInfo.vendor = MallocCString(cBundleInfo.vendor);
    bundleInfo.versionCode = cBundleInfo.versionCode;
    bundleInfo.versionName = MallocCString(cBundleInfo.versionName);
    bundleInfo.minCompatibleVersionCode = cBundleInfo.minCompatibleVersionCode;
    bundleInfo.targetVersion = cBundleInfo.targetVersion;
    if ((static_cast<uint32_t>(flags) &
        static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_APPLICATION)) ==
        static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_APPLICATION)
    ) {
        bundleInfo.appInfo = ConvertApplicationInfo(cBundleInfo.applicationInfo);
    } else {
        bundleInfo.appInfo = InitApplicationInfo();
    }

    bundleInfo.hapInfo = ConvertArrHapInfo(cBundleInfo.hapModuleInfos);
    bundleInfo.perDetail = ConvertArrReqPerDetail(cBundleInfo.reqPermissionDetails);

    bundleInfo.state.size = static_cast<int64_t>(cBundleInfo.reqPermissionStates.size());
    bundleInfo.state.head = nullptr;
    if (bundleInfo.state.size > 0) {
        int32_t *retValue = static_cast<int32_t *>(malloc(sizeof(int32_t) * bundleInfo.state.size));
        if (retValue != nullptr) {
            for (int32_t i = 0; i < bundleInfo.state.size; i++) {
                retValue[i] = static_cast<int32_t>(cBundleInfo.reqPermissionStates[i]);
            }
            bundleInfo.state.head = retValue;
        } else {
            APP_LOGE("ConvertBundleInfo malloc failed");
            return bundleInfo;
        }
    }

    if ((static_cast<uint32_t>(flags) &
        static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_SIGNATURE_INFO)) ==
        static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_SIGNATURE_INFO)
    ) {
        bundleInfo.signInfo = ConvertSignatureInfo(cBundleInfo.signatureInfo);
    } else {
        bundleInfo.signInfo = InitSignInfo();
    }
    bundleInfo.installTime = cBundleInfo.installTime;
    bundleInfo.updateTime = cBundleInfo.updateTime;
    bundleInfo.uid = cBundleInfo.uid;
    return bundleInfo;
}

RetBundleInfoV2 ConvertBundleInfoV2(const AppExecFwk::BundleInfo& cBundleInfo, int32_t flags)
{
    RetBundleInfoV2 bundleInfo;
    bundleInfo.name = MallocCString(cBundleInfo.name);
    bundleInfo.vendor = MallocCString(cBundleInfo.vendor);
    bundleInfo.versionCode = cBundleInfo.versionCode;
    bundleInfo.versionName = MallocCString(cBundleInfo.versionName);
    bundleInfo.minCompatibleVersionCode = cBundleInfo.minCompatibleVersionCode;
    bundleInfo.targetVersion = cBundleInfo.targetVersion;
    if ((static_cast<uint32_t>(flags) &
        static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_APPLICATION)) ==
        static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_APPLICATION)
    ) {
        bundleInfo.appInfo = ConvertApplicationInfoV2(cBundleInfo.applicationInfo);
    } else {
        bundleInfo.appInfo = InitApplicationInfoV2();
    }

    bundleInfo.hapInfo = ConvertArrHapInfoV2(cBundleInfo.hapModuleInfos);
    bundleInfo.perDetail = ConvertArrReqPerDetail(cBundleInfo.reqPermissionDetails);

    bundleInfo.state.size = static_cast<int64_t>(cBundleInfo.reqPermissionStates.size());
    bundleInfo.state.head = nullptr;
    if (bundleInfo.state.size > 0) {
        int32_t *retValue = static_cast<int32_t *>(malloc(sizeof(int32_t) * bundleInfo.state.size));
        if (retValue != nullptr) {
            for (int32_t i = 0; i < bundleInfo.state.size; i++) {
                retValue[i] = static_cast<int32_t>(cBundleInfo.reqPermissionStates[i]);
            }
            bundleInfo.state.head = retValue;
        } else {
            APP_LOGE("ConvertBundleInfo malloc failed");
            return bundleInfo;
        }
    }

    if ((static_cast<uint32_t>(flags) &
        static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_SIGNATURE_INFO)) ==
        static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_SIGNATURE_INFO)
    ) {
        bundleInfo.signInfo = ConvertSignatureInfo(cBundleInfo.signatureInfo);
    } else {
        bundleInfo.signInfo = InitSignInfo();
    }
    bundleInfo.installTime = cBundleInfo.installTime;
    bundleInfo.updateTime = cBundleInfo.updateTime;
    bundleInfo.uid = cBundleInfo.uid;
    bundleInfo.routerMap = ConvertRouterMap(cBundleInfo.routerArray);
    bundleInfo.appIndex = cBundleInfo.appIndex;
    return bundleInfo;
}

void FreeRetBundleInfoV2(RetBundleInfoV2& bundleInfo)
{
    free(bundleInfo.name);
    bundleInfo.name = nullptr;
    free(bundleInfo.vendor);
    bundleInfo.vendor = nullptr;
    free(bundleInfo.versionName);
    bundleInfo.versionName = nullptr;
    FreeRetApplicationInfoV2(bundleInfo.appInfo);
    FreeCArrHapInfoV2(bundleInfo.hapInfo);
    FreeCArrReqPerDetail(bundleInfo.perDetail);
    free(bundleInfo.state.head);
    bundleInfo.state.head = nullptr;
    FreeRetSignatureInfo(bundleInfo.signInfo);
    FreeCArrRouterItem(bundleInfo.routerMap);
}

} // Convert
} // BundleManager
} // CJSystemapi
} // OHOS