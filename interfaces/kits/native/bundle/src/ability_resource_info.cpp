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

#include <cstddef>
#include <cstring>
#include <memory>
#include <string>

#include "ability_resource_info.h"
#include "app_log_wrapper.h"
#include "securec.h"

struct OH_NativeBundle_AbilityResourceInfo {
    int appIndex;
    bool isDefaultApp;
    char *bundleName;
    char *moduleName;
    char *abilityName;
    char *label;
    char *icon;
};

// Helper function to release char* memory
static void ReleaseChar(char* &str)
{
    if (str != nullptr) {
        free(str);
        str = nullptr;
    }
}

bool CopyChar(char* &name, char* value)
{
    if (value == nullptr) {
        APP_LOGE("value is null");
    }
    size_t length = strlen(value);
    if (length == 0) {
        APP_LOGE("failed due to the length of value is empty or too long");
        return false;
    }
    name = static_cast<char*>(malloc(length + 1));
    if (name == nullptr) {
        APP_LOGE("failed due to malloc error");
        return false;
    }
    if (strcpy_s(name, length + 1, value) != EOK) {
        APP_LOGE("failed due to strcpy_s error");
        ReleaseChar(name);
        return false;
    }
    return true;
}

bool CopyConstChar(char* &name, const char* value)
{
    if (value == nullptr) {
        APP_LOGE("value is null");
    }
    size_t length = strlen(value);
    if (length == 0) {
        APP_LOGE("failed due to the length of value is empty or too long");
        return false;
    }
    name = static_cast<char*>(malloc(length + 1));
    if (name == nullptr) {
        APP_LOGE("failed due to malloc error");
        return false;
    }
    if (strcpy_s(name, length + 1, value) != EOK) {
        APP_LOGE("failed due to strcpy_s error");
        ReleaseChar(name);
        return false;
    }
    return true;
}

void ResetResourceInfo(OH_NativeBundle_AbilityResourceInfo* resourceInfo, size_t count)
{
    if (resourceInfo == nullptr || count == 0) {
        return;
    }
    for (size_t i = 0; i < count; ++i) {
        resourceInfo[i].appIndex = 0;
        resourceInfo[i].isDefaultApp = false;
        resourceInfo[i].bundleName = nullptr;
        resourceInfo[i].moduleName = nullptr;
        resourceInfo[i].abilityName = nullptr;
        resourceInfo[i].label = nullptr;
        resourceInfo[i].icon = nullptr;
    }
}

void ReleaseResourceInfo(OH_NativeBundle_AbilityResourceInfo* resourceInfo, size_t count)
{
    if (resourceInfo == nullptr) {
        return;
    }
    for (size_t i = 0; i < count; ++i) {
        ReleaseChar(resourceInfo[i].bundleName);
        ReleaseChar(resourceInfo[i].moduleName);
        ReleaseChar(resourceInfo[i].abilityName);
        ReleaseChar(resourceInfo[i].label);
        ReleaseChar(resourceInfo[i].icon);
    }
    free(resourceInfo);
}

OH_NativeBundle_AbilityResourceInfo* OH_AbilityResourceInfo_Create(size_t elementSize)
{
    if (elementSize == 0) {
        APP_LOGE("failed due to the length of value is 0");
        return nullptr;
    }

    OH_NativeBundle_AbilityResourceInfo* abilityResourceInfo = static_cast<OH_NativeBundle_AbilityResourceInfo *>(
        malloc(elementSize * sizeof(OH_NativeBundle_AbilityResourceInfo)));
    if (abilityResourceInfo == nullptr) {
        APP_LOGE("failed to allocate memory for OH_AbilityResourceInfo_Create");
        return nullptr;
    }
    ResetResourceInfo(abilityResourceInfo, elementSize);

    return abilityResourceInfo;
}

BundleManager_ErrorCode OH_AbilityResourceInfo_Destroy(OH_NativeBundle_AbilityResourceInfo* resourceInfo, size_t count)
{
    ReleaseResourceInfo(resourceInfo, count);
    return BUNDLE_MANAGER_ERROR_CODE_NO_ERROR;
}

BundleManager_ErrorCode OH_NativeBundle_SetAbilityResourceInfo_AppIndex(
    OH_NativeBundle_AbilityResourceInfo* abilityResourceInfo, int appIndex)
{
    if (abilityResourceInfo == nullptr) {
        APP_LOGE("null abilityResourceInfo");
        return BUNDLE_MANAGER_ERROR_CODE_PARAM_INVALID;
    }
    abilityResourceInfo->appIndex = appIndex;
    return BUNDLE_MANAGER_ERROR_CODE_NO_ERROR;
}

BundleManager_ErrorCode OH_NativeBundle_GetAppIndex(
    OH_NativeBundle_AbilityResourceInfo* abilityResourceInfo, int* appIndex)
{
    if (abilityResourceInfo == nullptr || appIndex == nullptr) {
        APP_LOGE("abilityResourceInfo or appIndex is nullptr");
        return BUNDLE_MANAGER_ERROR_CODE_PARAM_INVALID;
    }
    *appIndex = abilityResourceInfo->appIndex;
    return BUNDLE_MANAGER_ERROR_CODE_NO_ERROR;
}

BundleManager_ErrorCode OH_NativeBundle_SetAbilityResourceInfo_IsDefaultApp(
    OH_NativeBundle_AbilityResourceInfo* abilityResourceInfo, bool isDefaultApp)
{
    if (abilityResourceInfo == nullptr) {
        APP_LOGE("abilityResourceInfo  is nullptr");
        return BUNDLE_MANAGER_ERROR_CODE_PARAM_INVALID;
    }
    abilityResourceInfo->isDefaultApp = isDefaultApp;
    return BUNDLE_MANAGER_ERROR_CODE_NO_ERROR;
}

BundleManager_ErrorCode OH_NativeBundle_CheckDefaultApp(
    OH_NativeBundle_AbilityResourceInfo* abilityResourceInfo, bool* isDefault)
{
    if (abilityResourceInfo == nullptr || isDefault == nullptr) {
        APP_LOGE("abilityResourceInfo or appIndex is nullptr");
        return BUNDLE_MANAGER_ERROR_CODE_PARAM_INVALID;
    }
    *isDefault = abilityResourceInfo->isDefaultApp;
    return BUNDLE_MANAGER_ERROR_CODE_NO_ERROR;
}

int OH_NativeBundle_GetSize()
{
    return sizeof(OH_NativeBundle_AbilityResourceInfo);
}

BundleManager_ErrorCode OH_NativeBundle_SetAbilityResourceInfo_BundleName(
    OH_NativeBundle_AbilityResourceInfo* abilityResourceInfo, const char* bundleName)
{
    if (abilityResourceInfo == nullptr || bundleName == nullptr) {
        APP_LOGE("abilityResourceInfo or bundleName is nullptr");
        return BUNDLE_MANAGER_ERROR_CODE_PARAM_INVALID;
    }
    if (!CopyConstChar(abilityResourceInfo->bundleName, bundleName)) {
        APP_LOGE("copy bundleName failed");
        return BUNDLE_MANAGER_ERROR_CODE_PARAM_INVALID;
    }
    return BUNDLE_MANAGER_ERROR_CODE_NO_ERROR;
}

BundleManager_ErrorCode OH_NativeBundle_GetBundleName(
    OH_NativeBundle_AbilityResourceInfo* abilityResourceInfo, char** bundleName)
{
    if (abilityResourceInfo == nullptr || bundleName == nullptr) {
        APP_LOGE("abilityResourceInfo or bundleName is nullptr");
        return BUNDLE_MANAGER_ERROR_CODE_PARAM_INVALID;
    }
    if (!CopyChar(*bundleName, abilityResourceInfo->bundleName)) {
        APP_LOGE("copy bundleName failed");
        return BUNDLE_MANAGER_ERROR_CODE_PARAM_INVALID;
    }
    return BUNDLE_MANAGER_ERROR_CODE_NO_ERROR;
}

BundleManager_ErrorCode OH_NativeBundle_SetAbilityResourceInfo_ModuleName(
    OH_NativeBundle_AbilityResourceInfo* abilityResourceInfo, const char* moduleName)
{
    if (abilityResourceInfo == nullptr || moduleName == nullptr) {
        APP_LOGE("abilityResourceInfo or moduleName is nullptr");
        return BUNDLE_MANAGER_ERROR_CODE_PARAM_INVALID;
    }
    if (!CopyConstChar(abilityResourceInfo->moduleName, moduleName)) {
        APP_LOGE("copy moduleName failed");
        return BUNDLE_MANAGER_ERROR_CODE_PARAM_INVALID;
    }
    return BUNDLE_MANAGER_ERROR_CODE_NO_ERROR;
}

BundleManager_ErrorCode OH_NativeBundle_GetModuleName(
    OH_NativeBundle_AbilityResourceInfo* abilityResourceInfo, char** moduleName)
{
    if (abilityResourceInfo == nullptr || moduleName == nullptr) {
        APP_LOGE("abilityResourceInfo or moduleName is nullptr");
        return BUNDLE_MANAGER_ERROR_CODE_PARAM_INVALID;
    }
    if (!CopyChar(*moduleName, abilityResourceInfo->moduleName)) {
        APP_LOGE("copy moduleName failed");
        return BUNDLE_MANAGER_ERROR_CODE_PARAM_INVALID;
    }
    return BUNDLE_MANAGER_ERROR_CODE_NO_ERROR;
}

BundleManager_ErrorCode OH_NativeBundle_SetAbilityResourceInfo_AbilityName(
    OH_NativeBundle_AbilityResourceInfo* abilityResourceInfo, const char* abilityName)
{
    if (abilityResourceInfo == nullptr || abilityName == nullptr) {
        APP_LOGE("abilityResourceInfo or abilityName is nullptr");
        return BUNDLE_MANAGER_ERROR_CODE_PARAM_INVALID;
    }
    if (!CopyConstChar(abilityResourceInfo->abilityName, abilityName)) {
        APP_LOGE("copy abilityName failed");
        return BUNDLE_MANAGER_ERROR_CODE_PARAM_INVALID;
    }
    return BUNDLE_MANAGER_ERROR_CODE_NO_ERROR;
}

BundleManager_ErrorCode OH_NativeBundle_GetAbilityName(
    OH_NativeBundle_AbilityResourceInfo* abilityResourceInfo, char** abilityName)
{
    if (abilityResourceInfo == nullptr || abilityName == nullptr) {
        APP_LOGE("abilityResourceInfo or abilityName is nullptr");
        return BUNDLE_MANAGER_ERROR_CODE_PARAM_INVALID;
    }
    if (!CopyChar(*abilityName, abilityResourceInfo->abilityName)) {
        APP_LOGE("copy abilityName failed");
        return BUNDLE_MANAGER_ERROR_CODE_PARAM_INVALID;
    }
    return BUNDLE_MANAGER_ERROR_CODE_NO_ERROR;
}

BundleManager_ErrorCode OH_NativeBundle_SetAbilityResourceInfo_Label(
    OH_NativeBundle_AbilityResourceInfo* abilityResourceInfo, const char* label)
{
    if (abilityResourceInfo == nullptr || label == nullptr) {
        APP_LOGE("abilityResourceInfo or label is nullptr");
        return BUNDLE_MANAGER_ERROR_CODE_PARAM_INVALID;
    }
    if (!CopyConstChar(abilityResourceInfo->label, label)) {
        APP_LOGE("copy label failed");
        return BUNDLE_MANAGER_ERROR_CODE_PARAM_INVALID;
    }
    return BUNDLE_MANAGER_ERROR_CODE_NO_ERROR;
}

BundleManager_ErrorCode OH_NativeBundle_GetLabel(OH_NativeBundle_AbilityResourceInfo* abilityResourceInfo, char** label)
{
    if (abilityResourceInfo == nullptr || label == nullptr) {
        APP_LOGE("abilityResourceInfo or label is nullptr");
        return BUNDLE_MANAGER_ERROR_CODE_PARAM_INVALID;
    }
    if (!CopyChar(*label, abilityResourceInfo->label)) {
        APP_LOGE("copy label failed");
        return BUNDLE_MANAGER_ERROR_CODE_PARAM_INVALID;
    }
    return BUNDLE_MANAGER_ERROR_CODE_NO_ERROR;
}

BundleManager_ErrorCode OH_NativeBundle_SetAbilityResourceInfo_Icon(
    OH_NativeBundle_AbilityResourceInfo* abilityResourceInfo, const char* icon)
{
    if (abilityResourceInfo == nullptr || icon == nullptr) {
        APP_LOGE("abilityResourceInfo or icon is nullptr");
        return BUNDLE_MANAGER_ERROR_CODE_PARAM_INVALID;
    }
    if (!CopyConstChar(abilityResourceInfo->icon, icon)) {
        APP_LOGE("copy icon failed");
        return BUNDLE_MANAGER_ERROR_CODE_PARAM_INVALID;
    }
    return BUNDLE_MANAGER_ERROR_CODE_NO_ERROR;
}

BundleManager_ErrorCode OH_NativeBundle_GetIcon(OH_NativeBundle_AbilityResourceInfo* abilityResourceInfo, char** icon)
{
    if (abilityResourceInfo == nullptr || icon == nullptr) {
        APP_LOGE("abilityResourceInfo or icon is nullptr");
        return BUNDLE_MANAGER_ERROR_CODE_PARAM_INVALID;
    }
    if (!CopyChar(*icon, abilityResourceInfo->icon)) {
        APP_LOGE("copy icon failed");
        return BUNDLE_MANAGER_ERROR_CODE_PARAM_INVALID;
    }
    return BUNDLE_MANAGER_ERROR_CODE_NO_ERROR;
}