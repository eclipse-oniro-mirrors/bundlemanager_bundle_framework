/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#include "form_info.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include "app_log_wrapper.h"
#include "bundle_constants.h"
#include "json_serializer.h"
#include "json_util.h"
#include "nlohmann/json.hpp"
#include "parcel_macro.h"
#include "string_ex.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const char* JSON_KEY_COLOR_MODE = "colorMode";
const char* JSON_KEY_RENDERING_MODE = "renderingMode";
const char* JSON_KEY_PACKAGE = "package";
const char* JSON_KEY_SUPPORT_DIMENSIONS = "supportDimensions";
const char* JSON_KEY_DEFAULT_DIMENSION = "defaultDimension";
const char* JSON_KEY_UPDATE_ENABLED = "updateEnabled";
const char* JSON_KEY_SCHEDULED_UPDATE_TIME = "scheduledUpdateTime";
const char* JSON_KEY_MULTI_SCHEDULED_UPDATE_TIME = "multiScheduledUpdateTime";
const char* JSON_KEY_CONDITION_UPDATE = "conditionUpdate";
const char* JSON_KEY_UPDATE_DURATION = "updateDuration";
const char* JSON_KEY_DEEP_LINK = "deepLink";
const char* JSON_KEY_JS_COMPONENT_NAME = "jsComponentName";
const char* JSON_KEY_VALUE = "value";
const char* JSON_KEY_NAME = "name";
const char* JSON_KEY_ORIGINAL_BUNDLE_NAME = "originalBundleName";
const char* JSON_KEY_CUSTOMIZE_DATA = "customizeData";
const char* JSON_KEY_DISPLAY_NAME = "displayName";
const char* JSON_KEY_DISPLAY_NAME_ID = "displayNameId";
const char* JSON_KEY_DESCRIPTION = "description";
const char* JSON_KEY_DESCRIPTION_ID = "descriptionId";
const char* JSON_KEY_TYPE = "type";
const char* JSON_KEY_UI_SYNTAX = "uiSyntax";
const char* JSON_KEY_LANDSCAPE_LAYOUTS = "landscapeLayouts";
const char* JSON_KEY_FORMCONFIG_ABILITY = "formConfigAbility";
const char* JSON_KEY_FORM_VISIBLE_NOTIFY = "formVisibleNotify";
const char* JSON_KEY_RELATED_BUNDLE_NAME = "relatedBundleName";
const char* JSON_KEY_DEFAULT_FLAG = "defaultFlag";
const char* JSON_KEY_PORTRAIT_LAYOUTS = "portraitLayouts";
const char* JSON_KEY_SRC = "src";
const char* JSON_KEY_WINDOW = "window";
const char* JSON_KEY_DESIGN_WIDTH = "designWidth";
const char* JSON_KEY_AUTO_DESIGN_WIDTH = "autoDesignWidth";
const char* JSON_KEY_IS_STATIC = "isStatic";
const char* JSON_KEY_DATA_PROXY_ENABLED = "dataProxyEnabled";
const char* JSON_KEY_IS_DYNAMIC = "isDynamic";
const char* JSON_KEY_TRANSPARENCY_ENABLED = "transparencyEnabled";
const char* JSON_KEY_PRIVACY_LEVEL = "privacyLevel";
const char* JSON_KEY_FONT_SCALE_FOLLOW_SYSTEM = "fontScaleFollowSystem";
const char* JSON_KEY_SUPPORT_SHAPES = "supportShapes";
const char* JSON_KEY_VERSION_CODE = "versionCode";
const char* JSON_KEY_BUNDLE_TYPE = "bundleType";
const char* JSON_KEY_PREVIEW_IMAGES = "previewImages";
const char* JSON_KEY_ENABLE_BLUR_BACKGROUND = "enableBlurBackground";
const char* JSON_KEY_APP_FORM_VISIBLE_NOTIFY = "appFormVisibleNotify";
const char* JSON_KEY_FUN_INTERACTION_PARAMS = "funInteractionParams";
const char* JSON_KEY_SCENE_ANIMATION_PARAMS = "sceneAnimationParams";
const char* JSON_KEY_ABILITY_NAME = "abilityName";
const char* JSON_KEY_DISABLED_DESKTOP_BEHAVIORS = "disabledDesktopBehaviors";
const char* JSON_KEY_TARGET_BUNDLE_NAME = "targetBundleName";
const char* JSON_KEY_SUB_BUNDLE_NAME = "subBundleName";
const char* JSON_KEY_KEEP_STATE_DURATION = "keepStateDuration";
const char* JSON_KEY_RESIZABLE = "resizable";
const char* JSON_KEY_GROUP_ID = "groupId";
const char* JSON_KEY_SUPPORT_DEVICE_TYPE = "supportDeviceTypes";
const char* JSON_KEY_SUPPORT_DEVICE_PERFORMANCE_CLASSES = "supportDevicePerformanceClasses";
const char* JSON_KEY_IS_TEMPLATE_FORM = "isTemplateForm";
const char* JSON_KEY_STANDBY = "standby";
const char* JSON_KEY_STANDBY_IS_SUPPORTED = "isSupported";
const char* JSON_KEY_STANDBY_IS_ADAPTED = "isAdapted";
const char* JSON_KEY_STANDBY_IS_PRIVACY_SENSITIVE = "isPrivacySensitive";
}  // namespace

FormInfo::FormInfo(const ExtensionAbilityInfo &abilityInfo, const ExtensionFormInfo &formInfo)
{
    SetInfoByAbility(abilityInfo);
    name = formInfo.name;
    displayName = formInfo.displayName;
    description = formInfo.description;
    jsComponentName = "";
    deepLink = "";
    formConfigAbility = formInfo.formConfigAbility;
    scheduledUpdateTime = formInfo.scheduledUpdateTime;
    multiScheduledUpdateTime = formInfo.multiScheduledUpdateTime;
    src = formInfo.src;
    window.designWidth = formInfo.window.designWidth;
    window.autoDesignWidth = formInfo.window.autoDesignWidth;
    std::size_t pos = formInfo.displayName.find(':');
    if (pos != std::string::npos) {
        displayNameId = static_cast<uint32_t>(
            atoi(formInfo.displayName.substr(pos + 1, formInfo.displayName.length() - pos - 1).c_str()));
    }
    pos = formInfo.description.find(':');
    if (pos != std::string::npos) {
        descriptionId = static_cast<uint32_t>(
            atoi(formInfo.description.substr(pos + 1, formInfo.description.length() - pos - 1).c_str()));
    }
    updateDuration = formInfo.updateDuration;
    defaultDimension = formInfo.defaultDimension;
    defaultFlag = formInfo.isDefault;
    formVisibleNotify = formInfo.formVisibleNotify;
    updateEnabled = formInfo.updateEnabled;
    type = formInfo.type;
    uiSyntax = formInfo.uiSyntax;
    colorMode = formInfo.colorMode;
    renderingMode = formInfo.renderingMode;
    for (const auto &dimension : formInfo.supportDimensions) {
        supportDimensions.push_back(dimension);
    }
    for (const auto &metadata : formInfo.metadata) {
        customizeDatas.push_back(metadata);
    }
    funInteractionParams.abilityName = formInfo.funInteractionParams.abilityName;
    funInteractionParams.targetBundleName = formInfo.funInteractionParams.targetBundleName;
    funInteractionParams.subBundleName = formInfo.funInteractionParams.subBundleName;
    funInteractionParams.keepStateDuration = formInfo.funInteractionParams.keepStateDuration;
    sceneAnimationParams.abilityName = formInfo.sceneAnimationParams.abilityName;
    sceneAnimationParams.disabledDesktopBehaviors = formInfo.sceneAnimationParams.disabledDesktopBehaviors;
    SetInfoByFormExt(formInfo);
}

void FormInfo::SetInfoByAbility(const ExtensionAbilityInfo &abilityInfo)
{
    package = abilityInfo.bundleName + abilityInfo.moduleName;
    bundleName = abilityInfo.bundleName;
    originalBundleName = abilityInfo.bundleName;
    relatedBundleName = abilityInfo.bundleName;
    moduleName = abilityInfo.moduleName;
    abilityName = abilityInfo.name;
}

void FormInfo::SetInfoByFormExt(const ExtensionFormInfo &formInfo)
{
    for (const auto &previewImage : formInfo.previewImages) {
        formPreviewImages.push_back(previewImage);
    }
    for (const auto &conditionUpdateType : formInfo.conditionUpdate) {
        conditionUpdate.push_back(conditionUpdateType);
    }
    for (const auto &deviceTypes : formInfo.supportDeviceTypes) {
        supportDeviceTypes.push_back(deviceTypes);
    }
    for (const auto &devicePerformanceClasses : formInfo.supportDevicePerformanceClasses) {
        supportDevicePerformanceClasses.push_back(devicePerformanceClasses);
    }
    dataProxyEnabled = formInfo.dataProxyEnabled;
    isDynamic = formInfo.isDynamic;
    transparencyEnabled = formInfo.transparencyEnabled;
    fontScaleFollowSystem = formInfo.fontScaleFollowSystem;
    for (const auto &shape : formInfo.supportShapes) {
        supportShapes.push_back(shape);
    }
    enableBlurBackground = formInfo.enableBlurBackground;
    appFormVisibleNotify = formInfo.appFormVisibleNotify;
    resizable = formInfo.resizable;
    groupId = formInfo.groupId;
    standby.isSupported = formInfo.standby.isSupported;
    standby.isAdapted = formInfo.standby.isAdapted;
    standby.isPrivacySensitive = formInfo.standby.isPrivacySensitive;
}

bool FormInfo::ReadCustomizeData(Parcel &parcel)
{
    int32_t customizeDataSize = 0;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, customizeDataSize);
    CONTAINER_SECURITY_VERIFY(parcel, customizeDataSize, &customizeDatas);
    for (auto i = 0; i < customizeDataSize; ++i) {
        FormCustomizeData customizeData;
        std::string customizeName = Str16ToStr8(parcel.ReadString16());
        std::string customizeValue = Str16ToStr8(parcel.ReadString16());
        customizeData.name = customizeName;
        customizeData.value = customizeValue;
        customizeDatas.emplace_back(customizeData);
    }
    return true;
}

bool FormInfo::ReadFromParcel(Parcel &parcel)
{
    name = Str16ToStr8(parcel.ReadString16());
    package = Str16ToStr8(parcel.ReadString16());
    bundleName = Str16ToStr8(parcel.ReadString16());
    moduleName = Str16ToStr8(parcel.ReadString16());
    abilityName = Str16ToStr8(parcel.ReadString16());
    displayName = Str16ToStr8(parcel.ReadString16());
    description = Str16ToStr8(parcel.ReadString16());
    formConfigAbility = Str16ToStr8(parcel.ReadString16());
    scheduledUpdateTime = Str16ToStr8(parcel.ReadString16());
    multiScheduledUpdateTime = Str16ToStr8(parcel.ReadString16());
    jsComponentName = Str16ToStr8(parcel.ReadString16());
    relatedBundleName = Str16ToStr8(parcel.ReadString16());
    originalBundleName = Str16ToStr8(parcel.ReadString16());
    deepLink = Str16ToStr8(parcel.ReadString16());
    src = Str16ToStr8(parcel.ReadString16());
    updateEnabled = parcel.ReadBool();
    defaultFlag = parcel.ReadBool();
    formVisibleNotify = parcel.ReadBool();
    isStatic = parcel.ReadBool();
    defaultDimension = parcel.ReadInt32();
    displayNameId = parcel.ReadUint32();
    descriptionId = parcel.ReadUint32();
    updateDuration = parcel.ReadInt32();

    int32_t typeData;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, typeData);
    type = static_cast<FormType>(typeData);

    int32_t uiSyntaxData;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, uiSyntaxData);
    uiSyntax = static_cast<FormType>(uiSyntaxData);

    int32_t colorModeData;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, colorModeData);
    colorMode = static_cast<FormsColorMode>(colorModeData);

    int32_t renderingModeData;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, renderingModeData);
    renderingMode = static_cast<FormsRenderingMode>(renderingModeData);

    int32_t supportDimensionSize;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, supportDimensionSize);
    CONTAINER_SECURITY_VERIFY(parcel, supportDimensionSize, &supportDimensions);
    for (int32_t i = 0; i < supportDimensionSize; i++) {
        supportDimensions.emplace_back(parcel.ReadInt32());
    }

    int32_t landscapeLayoutsSize;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, landscapeLayoutsSize);
    CONTAINER_SECURITY_VERIFY(parcel, landscapeLayoutsSize, &landscapeLayouts);
    for (auto i = 0; i < landscapeLayoutsSize; i++) {
        landscapeLayouts.emplace_back(Str16ToStr8(parcel.ReadString16()));
    }

    int32_t portraitLayoutsSize;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, portraitLayoutsSize);
    CONTAINER_SECURITY_VERIFY(parcel, portraitLayoutsSize, &portraitLayouts);
    for (auto i = 0; i < portraitLayoutsSize; i++) {
        portraitLayouts.emplace_back(Str16ToStr8(parcel.ReadString16()));
    }

    if (!ReadCustomizeData(parcel)) {
        return false;
    }

    window.designWidth = parcel.ReadInt32();
    window.autoDesignWidth = parcel.ReadBool();
    dataProxyEnabled = parcel.ReadBool();
    isDynamic = parcel.ReadBool();
    transparencyEnabled = parcel.ReadBool();
    privacyLevel = parcel.ReadInt32();
    fontScaleFollowSystem = parcel.ReadBool();

    int32_t supportShapeSize;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, supportShapeSize);
    CONTAINER_SECURITY_VERIFY(parcel, supportShapeSize, &supportShapes);
    for (int32_t i = 0; i < supportShapeSize; i++) {
        supportShapes.emplace_back(parcel.ReadInt32());
    }
    int32_t conditionUpdateSize;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, conditionUpdateSize);
    CONTAINER_SECURITY_VERIFY(parcel, conditionUpdateSize, &conditionUpdate);
    for (int32_t i = 0; i < conditionUpdateSize; i++) {
        conditionUpdate.emplace_back(parcel.ReadInt32());
    }
    versionCode = parcel.ReadUint32();
    int32_t bundleTypeData;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, bundleTypeData);
    bundleType = static_cast<BundleType>(bundleTypeData);

    int32_t formPreviewImagesSize;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, formPreviewImagesSize);
    CONTAINER_SECURITY_VERIFY(parcel, formPreviewImagesSize, &formPreviewImages);
    for (int32_t i = 0; i < formPreviewImagesSize; i++) {
        formPreviewImages.emplace_back(parcel.ReadUint32());
    }

    int32_t supportDeviceTypeSize;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, supportDeviceTypeSize);
    CONTAINER_SECURITY_VERIFY(parcel, supportDeviceTypeSize, &supportDeviceTypes);
    for (int32_t i = 0; i < supportDeviceTypeSize; i++) {
        supportDeviceTypes.emplace_back(Str16ToStr8(parcel.ReadString16()));
    }
 
    int32_t supportDevicePerformanceClassesSize;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, supportDevicePerformanceClassesSize);
    CONTAINER_SECURITY_VERIFY(parcel, supportDevicePerformanceClassesSize, &supportDevicePerformanceClasses);
    for (int32_t i = 0; i < supportDevicePerformanceClassesSize; i++) {
        supportDevicePerformanceClasses.emplace_back(parcel.ReadInt32());
    }
    enableBlurBackground = parcel.ReadBool();
    appFormVisibleNotify = parcel.ReadBool();
    funInteractionParams.abilityName = Str16ToStr8(parcel.ReadString16());
    funInteractionParams.targetBundleName = Str16ToStr8(parcel.ReadString16());
    funInteractionParams.subBundleName = Str16ToStr8(parcel.ReadString16());
    funInteractionParams.keepStateDuration = parcel.ReadInt32();
    sceneAnimationParams.abilityName = Str16ToStr8(parcel.ReadString16());
    sceneAnimationParams.disabledDesktopBehaviors = Str16ToStr8(parcel.ReadString16());
    resizable = parcel.ReadBool();
    isTemplateForm = parcel.ReadBool();
    groupId = Str16ToStr8(parcel.ReadString16());
    standby.isSupported = parcel.ReadBool();
    standby.isAdapted = parcel.ReadBool();
    standby.isPrivacySensitive = parcel.ReadBool();
    return true;
}

FormInfo *FormInfo::Unmarshalling(Parcel &parcel)
{
    std::unique_ptr<FormInfo> info = std::make_unique<FormInfo>();
    if (!info->ReadFromParcel(parcel)) {
        APP_LOGW("read from parcel failed");
        info = nullptr;
    }
    return info.release();
}

bool FormInfo::Marshalling(Parcel &parcel) const
{
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(name));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(package));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(bundleName));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(moduleName));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(abilityName));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(displayName));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(description));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(formConfigAbility));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(scheduledUpdateTime));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(multiScheduledUpdateTime));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(jsComponentName));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(relatedBundleName));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(originalBundleName));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(deepLink));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(src));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Bool, parcel, updateEnabled);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Bool, parcel, defaultFlag);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Bool, parcel, formVisibleNotify);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Bool, parcel, isStatic);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, defaultDimension);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint32, parcel, displayNameId);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint32, parcel, descriptionId);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, updateDuration);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, static_cast<int32_t>(type));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, static_cast<int32_t>(uiSyntax));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, static_cast<int32_t>(colorMode));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, static_cast<int32_t>(renderingMode));

    const auto supportDimensionSize = static_cast<int32_t>(supportDimensions.size());
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, supportDimensionSize);
    for (auto i = 0; i < supportDimensionSize; i++) {
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, supportDimensions[i]);
    }

    const auto landscapeLayoutsSize = static_cast<int32_t>(landscapeLayouts.size());
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, landscapeLayoutsSize);
    for (auto i = 0; i < landscapeLayoutsSize; i++) {
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(landscapeLayouts[i]));
    }

    const auto portraitLayoutsSize = static_cast<int32_t>(portraitLayouts.size());
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, portraitLayoutsSize);
    for (auto i = 0; i < portraitLayoutsSize; i++) {
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(portraitLayouts[i]));
    }

    const auto customizeDataSize = static_cast<int32_t>(customizeDatas.size());
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, customizeDataSize);
    for (auto i = 0; i < customizeDataSize; i++) {
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(customizeDatas[i].name));
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(customizeDatas[i].value));
    }

    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, window.designWidth);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Bool, parcel, window.autoDesignWidth);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Bool, parcel, dataProxyEnabled);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Bool, parcel, isDynamic);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Bool, parcel, transparencyEnabled);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, privacyLevel);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Bool, parcel, fontScaleFollowSystem);

    const auto supportShapeSize = static_cast<int32_t>(supportShapes.size());
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, supportShapeSize);
    for (auto i = 0; i < supportShapeSize; i++) {
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, supportShapes[i]);
    }
    const auto conditionUpdateSize = static_cast<int32_t>(conditionUpdate.size());
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, conditionUpdateSize);
    for (auto i = 0; i < conditionUpdateSize; i++) {
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, conditionUpdate[i]);
    }
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint32, parcel, versionCode);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, static_cast<int32_t>(bundleType));
    const auto formPreviewImagesSize = static_cast<int32_t>(formPreviewImages.size());
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, formPreviewImagesSize);
    for (auto i = 0; i < formPreviewImagesSize; i++) {
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint32, parcel, formPreviewImages[i]);
    }

    const auto supportDeviceTypeSize = static_cast<int32_t>(supportDeviceTypes.size());
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, supportDeviceTypeSize);
    for (auto i = 0; i < supportDeviceTypeSize; i++) {
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(supportDeviceTypes[i]));
    }

    const auto supportDevicePerformanceClassesSize = static_cast<int32_t>(supportDevicePerformanceClasses.size());
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, supportDevicePerformanceClassesSize);
    for (auto i = 0; i < supportDevicePerformanceClassesSize; i++) {
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, supportDevicePerformanceClasses[i]);
    }

    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Bool, parcel, enableBlurBackground);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Bool, parcel, appFormVisibleNotify);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(funInteractionParams.abilityName));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(funInteractionParams.targetBundleName));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(funInteractionParams.subBundleName));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, funInteractionParams.keepStateDuration);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(sceneAnimationParams.abilityName));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(sceneAnimationParams.disabledDesktopBehaviors));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Bool, parcel, resizable);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Bool, parcel, isTemplateForm);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(groupId));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Bool, parcel, standby.isSupported);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Bool, parcel, standby.isAdapted);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Bool, parcel, standby.isPrivacySensitive);
    return true;
}

bool FormInfo::IsValid() const
{
    if (!window.autoDesignWidth && window.designWidth <= 0) {
        APP_LOGW("Invalid FormInfo, window.designWidth <= 0");
        return false;
    }
    return true;
}

void to_json(nlohmann::json &jsonObject, const FormCustomizeData &customizeDatas)
{
    jsonObject = nlohmann::json{
        {JSON_KEY_NAME, customizeDatas.name},
        {JSON_KEY_VALUE, customizeDatas.value}
    };
}

void to_json(nlohmann::json &jsonObject, const FormWindow &formWindow)
{
    jsonObject[JSON_KEY_DESIGN_WIDTH] = formWindow.designWidth;
    jsonObject[JSON_KEY_AUTO_DESIGN_WIDTH] = formWindow.autoDesignWidth;
}

void to_json(nlohmann::json &jsonObject, const FormStandby &formStandby)
{
    jsonObject[JSON_KEY_STANDBY_IS_SUPPORTED] = formStandby.isSupported;
    jsonObject[JSON_KEY_STANDBY_IS_ADAPTED] = formStandby.isAdapted;
    jsonObject[JSON_KEY_STANDBY_IS_PRIVACY_SENSITIVE] = formStandby.isPrivacySensitive;
}

void to_json(nlohmann::json &jsonObject, const FormFunInteractionParams &funInteractionParams)
{
    jsonObject[JSON_KEY_ABILITY_NAME] = funInteractionParams.abilityName;
    jsonObject[JSON_KEY_TARGET_BUNDLE_NAME] = funInteractionParams.targetBundleName;
    jsonObject[JSON_KEY_SUB_BUNDLE_NAME] = funInteractionParams.subBundleName;
    jsonObject[JSON_KEY_KEEP_STATE_DURATION] = funInteractionParams.keepStateDuration;
}

void to_json(nlohmann::json &jsonObject, const FormSceneAnimationParams &sceneAnimationParams)
{
    jsonObject[JSON_KEY_ABILITY_NAME] = sceneAnimationParams.abilityName;
    jsonObject[JSON_KEY_DISABLED_DESKTOP_BEHAVIORS] = sceneAnimationParams.disabledDesktopBehaviors;
}

void to_json(nlohmann::json &jsonObject, const FormInfo &formInfo)
{
    jsonObject = nlohmann::json{
        {JSON_KEY_NAME, formInfo.name},
        {JSON_KEY_PACKAGE, formInfo.package},
        {Constants::BUNDLE_NAME, formInfo.bundleName},
        {Constants::MODULE_NAME, formInfo.moduleName},
        {Constants::ABILITY_NAME, formInfo.abilityName},
        {JSON_KEY_DISPLAY_NAME, formInfo.displayName},
        {JSON_KEY_DESCRIPTION, formInfo.description},
        {JSON_KEY_RELATED_BUNDLE_NAME, formInfo.relatedBundleName},
        {JSON_KEY_JS_COMPONENT_NAME, formInfo.jsComponentName},
        {JSON_KEY_DEEP_LINK, formInfo.deepLink},
        {JSON_KEY_SRC, formInfo.src},
        {JSON_KEY_FORMCONFIG_ABILITY, formInfo.formConfigAbility},
        {JSON_KEY_SCHEDULED_UPDATE_TIME, formInfo.scheduledUpdateTime},
        {JSON_KEY_MULTI_SCHEDULED_UPDATE_TIME, formInfo.multiScheduledUpdateTime},
        {JSON_KEY_CONDITION_UPDATE, formInfo.conditionUpdate},
        {JSON_KEY_ORIGINAL_BUNDLE_NAME, formInfo.originalBundleName},
        {JSON_KEY_DISPLAY_NAME_ID, formInfo.displayNameId},
        {JSON_KEY_DESCRIPTION_ID, formInfo.descriptionId},
        {JSON_KEY_UPDATE_DURATION, formInfo.updateDuration},
        {JSON_KEY_DEFAULT_DIMENSION, formInfo.defaultDimension},
        {JSON_KEY_DEFAULT_FLAG, formInfo.defaultFlag},
        {JSON_KEY_FORM_VISIBLE_NOTIFY, formInfo.formVisibleNotify},
        {JSON_KEY_UPDATE_ENABLED, formInfo.updateEnabled},
        {JSON_KEY_IS_STATIC, formInfo.isStatic},
        {JSON_KEY_TYPE, formInfo.type},
        {JSON_KEY_UI_SYNTAX, formInfo.uiSyntax},
        {JSON_KEY_COLOR_MODE, formInfo.colorMode},
        {JSON_KEY_RENDERING_MODE, formInfo.renderingMode},
        {JSON_KEY_SUPPORT_DIMENSIONS, formInfo.supportDimensions},
        {JSON_KEY_CUSTOMIZE_DATA, formInfo.customizeDatas},
        {JSON_KEY_LANDSCAPE_LAYOUTS, formInfo.landscapeLayouts},
        {JSON_KEY_PORTRAIT_LAYOUTS, formInfo.portraitLayouts},
        {JSON_KEY_WINDOW, formInfo.window},
        {JSON_KEY_DATA_PROXY_ENABLED, formInfo.dataProxyEnabled},
        {JSON_KEY_IS_DYNAMIC, formInfo.isDynamic},
        {JSON_KEY_TRANSPARENCY_ENABLED, formInfo.transparencyEnabled},
        {JSON_KEY_PRIVACY_LEVEL, formInfo.privacyLevel},
        {JSON_KEY_FONT_SCALE_FOLLOW_SYSTEM, formInfo.fontScaleFollowSystem},
        {JSON_KEY_SUPPORT_SHAPES, formInfo.supportShapes},
        {JSON_KEY_VERSION_CODE, formInfo.versionCode},
        {JSON_KEY_BUNDLE_TYPE, formInfo.bundleType},
        {JSON_KEY_PREVIEW_IMAGES, formInfo.formPreviewImages},
        {JSON_KEY_ENABLE_BLUR_BACKGROUND, formInfo.enableBlurBackground},
        {JSON_KEY_APP_FORM_VISIBLE_NOTIFY, formInfo.appFormVisibleNotify},
        {JSON_KEY_FUN_INTERACTION_PARAMS, formInfo.funInteractionParams},
        {JSON_KEY_SCENE_ANIMATION_PARAMS, formInfo.sceneAnimationParams},
        {JSON_KEY_RESIZABLE, formInfo.resizable},
        {JSON_KEY_IS_TEMPLATE_FORM, formInfo.isTemplateForm},
        {JSON_KEY_GROUP_ID, formInfo.groupId},
        {JSON_KEY_SUPPORT_DEVICE_TYPE, formInfo.supportDeviceTypes},
        {JSON_KEY_SUPPORT_DEVICE_PERFORMANCE_CLASSES, formInfo.supportDevicePerformanceClasses},
        {JSON_KEY_STANDBY, formInfo.standby}
    };
}

void from_json(const nlohmann::json &jsonObject, FormCustomizeData &customizeDatas)
{
    const auto &jsonObjectEnd = jsonObject.end();
    int32_t parseResult = ERR_OK;
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        JSON_KEY_NAME,
        customizeDatas.name,
        false,
        parseResult);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        JSON_KEY_VALUE,
        customizeDatas.value,
        false,
        parseResult);
    if (parseResult != ERR_OK) {
        APP_LOGE("read customizeDatas jsonObject error : %{public}d", parseResult);
    }
}

void from_json(const nlohmann::json &jsonObject, FormWindow &formWindow)
{
    const auto &jsonObjectEnd = jsonObject.end();
    int32_t parseResult = ERR_OK;
    GetValueIfFindKey<int32_t>(jsonObject,
        jsonObjectEnd,
        JSON_KEY_DESIGN_WIDTH,
        formWindow.designWidth,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    BMSJsonUtil::GetBoolValueIfFindKey(jsonObject,
        jsonObjectEnd,
        JSON_KEY_AUTO_DESIGN_WIDTH,
        formWindow.autoDesignWidth,
        false,
        parseResult);
    if (parseResult != ERR_OK) {
        APP_LOGE("read formWindow jsonObject error : %{public}d", parseResult);
    }
}

void from_json(const nlohmann::json &jsonObject, FormStandby &formStandby)
{
    const auto &jsonObjectEnd = jsonObject.end();
    int32_t parseResult = ERR_OK;
    BMSJsonUtil::GetBoolValueIfFindKey(jsonObject,
        jsonObjectEnd,
        JSON_KEY_STANDBY_IS_SUPPORTED,
        formStandby.isSupported,
        false,
        parseResult);
    BMSJsonUtil::GetBoolValueIfFindKey(jsonObject,
        jsonObjectEnd,
        JSON_KEY_STANDBY_IS_ADAPTED,
        formStandby.isAdapted,
        false,
        parseResult);
    BMSJsonUtil::GetBoolValueIfFindKey(jsonObject,
        jsonObjectEnd,
        JSON_KEY_STANDBY_IS_PRIVACY_SENSITIVE,
        formStandby.isPrivacySensitive,
        false,
        parseResult);
    if (parseResult != ERR_OK) {
        APP_LOGE("read formStandby jsonObject error : %{public}d", parseResult);
    }
}

void from_json(const nlohmann::json &jsonObject, FormFunInteractionParams &funInteractionParams)
{
    const auto &jsonObjectEnd = jsonObject.end();
    int32_t parseResult = ERR_OK;
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        JSON_KEY_ABILITY_NAME,
        funInteractionParams.abilityName,
        false,
        parseResult);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        JSON_KEY_TARGET_BUNDLE_NAME,
        funInteractionParams.targetBundleName,
        false,
        parseResult);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        JSON_KEY_SUB_BUNDLE_NAME,
        funInteractionParams.subBundleName,
        false,
        parseResult);
    GetValueIfFindKey<int32_t>(jsonObject,
        jsonObjectEnd,
        JSON_KEY_KEEP_STATE_DURATION,
        funInteractionParams.keepStateDuration,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    if (parseResult != ERR_OK) {
        APP_LOGE("read funInteractionParams jsonObject error: %{public}d", parseResult);
    }
}

void from_json(const nlohmann::json &jsonObject, FormSceneAnimationParams &sceneAnimationParams)
{
    const auto &jsonObjectEnd = jsonObject.end();
    int32_t parseResult = ERR_OK;
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        JSON_KEY_ABILITY_NAME,
        sceneAnimationParams.abilityName,
        false,
        parseResult);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        JSON_KEY_DISABLED_DESKTOP_BEHAVIORS,
        sceneAnimationParams.disabledDesktopBehaviors,
        false,
        parseResult);
    if (parseResult != ERR_OK) {
        APP_LOGE("read sceneAnimationParams jsonObject error: %{public}d", parseResult);
    }
}

void from_json(const nlohmann::json &jsonObject, FormInfo &formInfo)
{
    int32_t parseResult = ERR_OK;
    const auto &jsonObjectEnd = jsonObject.end();
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        Constants::BUNDLE_NAME,
        formInfo.bundleName,
        false,
        parseResult);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        JSON_KEY_PACKAGE,
        formInfo.package,
        false,
        parseResult);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        Constants::MODULE_NAME,
        formInfo.moduleName,
        false,
        parseResult);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        Constants::ABILITY_NAME,
        formInfo.abilityName,
        false,
        parseResult);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        JSON_KEY_NAME,
        formInfo.name,
        false,
        parseResult);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        JSON_KEY_DISPLAY_NAME,
        formInfo.displayName,
        false,
        parseResult);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        JSON_KEY_DESCRIPTION,
        formInfo.description,
        false,
        parseResult);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        JSON_KEY_RELATED_BUNDLE_NAME,
        formInfo.relatedBundleName,
        false,
        parseResult);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        JSON_KEY_JS_COMPONENT_NAME,
        formInfo.jsComponentName,
        false,
        parseResult);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        JSON_KEY_DEEP_LINK,
        formInfo.deepLink,
        false,
        parseResult);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        JSON_KEY_FORMCONFIG_ABILITY,
        formInfo.formConfigAbility,
        false,
        parseResult);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        JSON_KEY_SCHEDULED_UPDATE_TIME,
        formInfo.scheduledUpdateTime,
        false,
        parseResult);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        JSON_KEY_MULTI_SCHEDULED_UPDATE_TIME,
        formInfo.multiScheduledUpdateTime,
        false,
        parseResult);
    GetValueIfFindKey<std::vector<int32_t>>(jsonObject,
        jsonObjectEnd,
        JSON_KEY_CONDITION_UPDATE,
        formInfo.conditionUpdate,
        JsonType::ARRAY,
        false,
        parseResult,
        ArrayType::NUMBER);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        JSON_KEY_SRC,
        formInfo.src,
        false,
        parseResult);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        JSON_KEY_ORIGINAL_BUNDLE_NAME,
        formInfo.originalBundleName,
        false,
        parseResult);
    GetValueIfFindKey<uint32_t>(jsonObject,
        jsonObjectEnd,
        JSON_KEY_DISPLAY_NAME_ID,
        formInfo.displayNameId,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<uint32_t>(jsonObject,
        jsonObjectEnd,
        JSON_KEY_DESCRIPTION_ID,
        formInfo.descriptionId,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<int32_t>(jsonObject,
        jsonObjectEnd,
        JSON_KEY_UPDATE_DURATION,
        formInfo.updateDuration,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<int32_t>(jsonObject,
        jsonObjectEnd,
        JSON_KEY_DEFAULT_DIMENSION,
        formInfo.defaultDimension,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    BMSJsonUtil::GetBoolValueIfFindKey(jsonObject,
        jsonObjectEnd,
        JSON_KEY_DEFAULT_FLAG,
        formInfo.defaultFlag,
        false,
        parseResult);
    BMSJsonUtil::GetBoolValueIfFindKey(jsonObject,
        jsonObjectEnd,
        JSON_KEY_FORM_VISIBLE_NOTIFY,
        formInfo.formVisibleNotify,
        false,
        parseResult);
    BMSJsonUtil::GetBoolValueIfFindKey(jsonObject,
        jsonObjectEnd,
        JSON_KEY_UPDATE_ENABLED,
        formInfo.updateEnabled,
        false,
        parseResult);
    BMSJsonUtil::GetBoolValueIfFindKey(jsonObject,
        jsonObjectEnd,
        JSON_KEY_IS_STATIC,
        formInfo.isStatic,
        false,
        parseResult);
    GetValueIfFindKey<FormType>(jsonObject,
        jsonObjectEnd,
        JSON_KEY_TYPE,
        formInfo.type,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<FormsColorMode>(jsonObject,
        jsonObjectEnd,
        JSON_KEY_COLOR_MODE,
        formInfo.colorMode,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<FormsRenderingMode>(jsonObject,
        jsonObjectEnd,
        JSON_KEY_RENDERING_MODE,
        formInfo.renderingMode,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::vector<int32_t>>(jsonObject,
        jsonObjectEnd,
        JSON_KEY_SUPPORT_DIMENSIONS,
        formInfo.supportDimensions,
        JsonType::ARRAY,
        false,
        parseResult,
        ArrayType::NUMBER);
    GetValueIfFindKey<std::vector<FormCustomizeData>>(jsonObject,
        jsonObjectEnd,
        JSON_KEY_CUSTOMIZE_DATA,
        formInfo.customizeDatas,
        JsonType::ARRAY,
        false,
        parseResult,
        ArrayType::OBJECT);
    GetValueIfFindKey<std::vector<std::string>>(jsonObject,
        jsonObjectEnd,
        JSON_KEY_LANDSCAPE_LAYOUTS,
        formInfo.landscapeLayouts,
        JsonType::ARRAY,
        false,
        parseResult,
        ArrayType::STRING);
    GetValueIfFindKey<std::vector<std::string>>(jsonObject,
        jsonObjectEnd,
        JSON_KEY_PORTRAIT_LAYOUTS,
        formInfo.portraitLayouts,
        JsonType::ARRAY,
        false,
        parseResult,
        ArrayType::STRING);
    GetValueIfFindKey<FormWindow>(jsonObject,
        jsonObjectEnd,
        JSON_KEY_WINDOW,
        formInfo.window,
        JsonType::OBJECT,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<FormType>(jsonObject,
        jsonObjectEnd,
        JSON_KEY_UI_SYNTAX,
        formInfo.uiSyntax,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    BMSJsonUtil::GetBoolValueIfFindKey(jsonObject,
        jsonObjectEnd,
        JSON_KEY_DATA_PROXY_ENABLED,
        formInfo.dataProxyEnabled,
        false,
        parseResult);
    BMSJsonUtil::GetBoolValueIfFindKey(jsonObject,
        jsonObjectEnd,
        JSON_KEY_IS_DYNAMIC,
        formInfo.isDynamic,
        false,
        parseResult);
    BMSJsonUtil::GetBoolValueIfFindKey(jsonObject,
        jsonObjectEnd,
        JSON_KEY_TRANSPARENCY_ENABLED,
        formInfo.transparencyEnabled,
        false,
        parseResult);
    GetValueIfFindKey<int32_t>(jsonObject,
        jsonObjectEnd,
        JSON_KEY_PRIVACY_LEVEL,
        formInfo.privacyLevel,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    BMSJsonUtil::GetBoolValueIfFindKey(jsonObject,
        jsonObjectEnd,
        JSON_KEY_FONT_SCALE_FOLLOW_SYSTEM,
        formInfo.fontScaleFollowSystem,
        false,
        parseResult);
    GetValueIfFindKey<std::vector<int32_t>>(jsonObject,
        jsonObjectEnd,
        JSON_KEY_SUPPORT_SHAPES,
        formInfo.supportShapes,
        JsonType::ARRAY,
        false,
        parseResult,
        ArrayType::NUMBER);
    GetValueIfFindKey<uint32_t>(jsonObject,
        jsonObjectEnd,
        JSON_KEY_VERSION_CODE,
        formInfo.versionCode,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<BundleType>(jsonObject,
        jsonObjectEnd,
        JSON_KEY_BUNDLE_TYPE,
        formInfo.bundleType,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::vector<uint32_t>>(jsonObject,
        jsonObjectEnd,
        JSON_KEY_PREVIEW_IMAGES,
        formInfo.formPreviewImages,
        JsonType::ARRAY,
        false,
        parseResult,
        ArrayType::NUMBER);
    BMSJsonUtil::GetBoolValueIfFindKey(jsonObject,
        jsonObjectEnd,
        JSON_KEY_ENABLE_BLUR_BACKGROUND,
        formInfo.enableBlurBackground,
        false,
        parseResult);
    BMSJsonUtil::GetBoolValueIfFindKey(jsonObject,
        jsonObjectEnd,
        JSON_KEY_APP_FORM_VISIBLE_NOTIFY,
        formInfo.appFormVisibleNotify,
        false,
        parseResult);
    GetValueIfFindKey<FormFunInteractionParams>(jsonObject,
        jsonObjectEnd,
        JSON_KEY_FUN_INTERACTION_PARAMS,
        formInfo.funInteractionParams,
        JsonType::OBJECT,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<FormSceneAnimationParams>(jsonObject,
        jsonObjectEnd,
        JSON_KEY_SCENE_ANIMATION_PARAMS,
        formInfo.sceneAnimationParams,
        JsonType::OBJECT,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    BMSJsonUtil::GetBoolValueIfFindKey(jsonObject,
        jsonObjectEnd,
        JSON_KEY_RESIZABLE,
        formInfo.resizable,
        false,
        parseResult);
    BMSJsonUtil::GetBoolValueIfFindKey(jsonObject,
        jsonObjectEnd,
        JSON_KEY_IS_TEMPLATE_FORM,
        formInfo.isTemplateForm,
        false,
        parseResult);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        JSON_KEY_GROUP_ID,
        formInfo.groupId,
        false,
        parseResult);
    GetValueIfFindKey<std::vector<std::string>>(jsonObject,
        jsonObjectEnd,
        JSON_KEY_SUPPORT_DEVICE_TYPE,
        formInfo.supportDeviceTypes,
        JsonType::ARRAY,
        false,
        parseResult,
        ArrayType::STRING);
    GetValueIfFindKey<std::vector<int32_t>>(jsonObject,
        jsonObjectEnd,
        JSON_KEY_SUPPORT_DEVICE_PERFORMANCE_CLASSES,
        formInfo.supportDevicePerformanceClasses,
        JsonType::ARRAY,
        false,
        parseResult,
        ArrayType::NUMBER);
    GetValueIfFindKey<FormStandby>(jsonObject,
        jsonObjectEnd,
        JSON_KEY_STANDBY,
        formInfo.standby,
        JsonType::OBJECT,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    if (parseResult != ERR_OK) {
        APP_LOGE("read formInfo jsonObject error : %{public}d", parseResult);
    }
}
}  // namespace AppExecFwk
}  // namespace OHOS
