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
const std::string JSON_KEY_COLOR_MODE = "colorMode";
const std::string JSON_KEY_PACKAGE = "package";
const std::string JSON_KEY_SUPPORT_DIMENSIONS = "supportDimensions";
const std::string JSON_KEY_DEFAULT_DIMENSION = "defaultDimension";
const std::string JSON_KEY_UPDATE_ENABLED = "updateEnabled";
const std::string JSON_KEY_SCHEDULED_UPDATE_TIME = "scheduledUpdateTime";
const std::string JSON_KEY_UPDATE_DURATION = "updateDuration";
const std::string JSON_KEY_DEEP_LINK = "deepLink";
const std::string JSON_KEY_JS_COMPONENT_NAME = "jsComponentName";
const std::string JSON_KEY_VALUE = "value";
const std::string JSON_KEY_NAME = "name";
const std::string JSON_KEY_ORIGINAL_BUNDLE_NAME = "originalBundleName";
const std::string JSON_KEY_CUSTOMIZE_DATA = "customizeData";
const std::string JSON_KEY_DISPLAY_NAME = "displayName";
const std::string JSON_KEY_DISPLAY_NAME_ID = "displayNameId";
const std::string JSON_KEY_DESCRIPTION = "description";
const std::string JSON_KEY_DESCRIPTION_ID = "descriptionId";
const std::string JSON_KEY_TYPE = "type";
const std::string JSON_KEY_UI_SYNTAX = "uiSyntax";
const std::string JSON_KEY_LANDSCAPE_LAYOUTS = "landscapeLayouts";
const std::string JSON_KEY_FORMCONFIG_ABILITY = "formConfigAbility";
const std::string JSON_KEY_FORM_VISIBLE_NOTIFY = "formVisibleNotify";
const std::string JSON_KEY_RELATED_BUNDLE_NAME = "relatedBundleName";
const std::string JSON_KEY_DEFAULT_FLAG = "defaultFlag";
const std::string JSON_KEY_PORTRAIT_LAYOUTS = "portraitLayouts";
const std::string JSON_KEY_SRC = "src";
const std::string JSON_KEY_WINDOW = "window";
const std::string JSON_KEY_DESIGN_WIDTH = "designWidth";
const std::string JSON_KEY_AUTO_DESIGN_WIDTH = "autoDesignWidth";
const std::string JSON_KEY_IS_STATIC = "isStatic";
const std::string JSON_KEY_DATA_PROXY_ENABLED = "dataProxyEnabled";
const std::string JSON_KEY_IS_DYNAMIC = "isDynamic";
const std::string JSON_KEY_TRANSPARENCY_ENABLED = "transparencyEnabled";
const std::string JSON_KEY_PRIVACY_LEVEL = "privacyLevel";
const std::string JSON_KEY_FONT_SCALE_FOLLOW_SYSTEM = "fontScaleFollowSystem";
const std::string JSON_KEY_SUPPORT_SHAPES = "supportShapes";
const std::string JSON_KEY_VERSION_CODE = "versionCode";
const std::string JSON_KEY_BUNDLE_TYPE = "bundleType";
}  // namespace

FormInfo::FormInfo(const ExtensionAbilityInfo &abilityInfo, const ExtensionFormInfo &formInfo)
{
    package = abilityInfo.bundleName + abilityInfo.moduleName;
    bundleName = abilityInfo.bundleName;
    originalBundleName = abilityInfo.bundleName;
    relatedBundleName = abilityInfo.bundleName;
    moduleName = abilityInfo.moduleName;
    abilityName = abilityInfo.name;
    name = formInfo.name;
    displayName = formInfo.displayName;
    description = formInfo.description;
    jsComponentName = "";
    deepLink = "";
    formConfigAbility = formInfo.formConfigAbility;
    scheduledUpdateTime = formInfo.scheduledUpdateTime;
    src = formInfo.src;
    window.designWidth = formInfo.window.designWidth;
    window.autoDesignWidth = formInfo.window.autoDesignWidth;
    std::size_t pos = formInfo.displayName.find(":");
    if (pos != std::string::npos) {
        displayNameId = atoi(formInfo.displayName.substr(pos + 1, formInfo.displayName.length() - pos - 1).c_str());
    }
    pos = formInfo.description.find(":");
    if (pos != std::string::npos) {
        descriptionId = atoi(formInfo.description.substr(pos + 1, formInfo.description.length() - pos - 1).c_str());
    }
    updateDuration = formInfo.updateDuration;
    defaultDimension = formInfo.defaultDimension;
    defaultFlag = formInfo.isDefault;
    formVisibleNotify = formInfo.formVisibleNotify;
    updateEnabled = formInfo.updateEnabled;
    type = formInfo.type;
    uiSyntax = formInfo.uiSyntax;
    colorMode = formInfo.colorMode;
    for (const auto &dimension : formInfo.supportDimensions) {
        supportDimensions.push_back(dimension);
    }
    for (const auto &metadata : formInfo.metadata) {
        customizeDatas.push_back(metadata);
    }
    dataProxyEnabled = formInfo.dataProxyEnabled;
    isDynamic = formInfo.isDynamic;
    transparencyEnabled = formInfo.transparencyEnabled;
    fontScaleFollowSystem = formInfo.fontScaleFollowSystem;
    for (const auto &shape : formInfo.supportShapes) {
        supportShapes.push_back(shape);
    }
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
    displayNameId = parcel.ReadInt32();
    descriptionId = parcel.ReadInt32();
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

    versionCode = parcel.ReadUint32();
    int32_t bundleTypeData;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, bundleTypeData);
    bundleType = static_cast<BundleType>(bundleTypeData);
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
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, displayNameId);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, descriptionId);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, updateDuration);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, static_cast<int32_t>(type));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, static_cast<int32_t>(uiSyntax));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, static_cast<int32_t>(colorMode));

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

    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint32, parcel, versionCode);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, static_cast<int32_t>(bundleType));
    return true;
}

bool FormInfo::IsValid() const
{
    if (!window.autoDesignWidth && window.designWidth <= 0) {
        APP_LOGW("Invalid FormInfo, window.designWidth <= 0.");
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
        {JSON_KEY_BUNDLE_TYPE, formInfo.bundleType}
    };
}

void from_json(const nlohmann::json &jsonObject, FormCustomizeData &customizeDatas)
{
    const auto &jsonObjectEnd = jsonObject.end();
    int32_t parseResult = ERR_OK;
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        JSON_KEY_NAME,
        customizeDatas.name,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        JSON_KEY_VALUE,
        customizeDatas.value,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    if (parseResult != ERR_OK) {
        APP_LOGE("read module customizeDatas from jsonObject error, error code : %{public}d", parseResult);
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
    GetValueIfFindKey<bool>(jsonObject,
        jsonObjectEnd,
        JSON_KEY_AUTO_DESIGN_WIDTH,
        formWindow.autoDesignWidth,
        JsonType::BOOLEAN,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    if (parseResult != ERR_OK) {
        APP_LOGE("read module formWindow from jsonObject error, error code : %{public}d", parseResult);
    }
}

void from_json(const nlohmann::json &jsonObject, FormInfo &formInfo)
{
    int32_t parseResult = ERR_OK;
    const auto &jsonObjectEnd = jsonObject.end();
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        Constants::BUNDLE_NAME,
        formInfo.bundleName,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        JSON_KEY_PACKAGE,
        formInfo.package,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        Constants::MODULE_NAME,
        formInfo.moduleName,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        Constants::ABILITY_NAME,
        formInfo.abilityName,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        JSON_KEY_NAME,
        formInfo.name,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        JSON_KEY_DISPLAY_NAME,
        formInfo.displayName,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        JSON_KEY_DESCRIPTION,
        formInfo.description,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        JSON_KEY_RELATED_BUNDLE_NAME,
        formInfo.relatedBundleName,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        JSON_KEY_JS_COMPONENT_NAME,
        formInfo.jsComponentName,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        JSON_KEY_DEEP_LINK,
        formInfo.deepLink,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        JSON_KEY_FORMCONFIG_ABILITY,
        formInfo.formConfigAbility,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        JSON_KEY_SCHEDULED_UPDATE_TIME,
        formInfo.scheduledUpdateTime,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        JSON_KEY_SRC,
        formInfo.src,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        JSON_KEY_ORIGINAL_BUNDLE_NAME,
        formInfo.originalBundleName,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<int32_t>(jsonObject,
        jsonObjectEnd,
        JSON_KEY_DISPLAY_NAME_ID,
        formInfo.displayNameId,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<int32_t>(jsonObject,
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
    GetValueIfFindKey<bool>(jsonObject,
        jsonObjectEnd,
        JSON_KEY_DEFAULT_FLAG,
        formInfo.defaultFlag,
        JsonType::BOOLEAN,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<bool>(jsonObject,
        jsonObjectEnd,
        JSON_KEY_FORM_VISIBLE_NOTIFY,
        formInfo.formVisibleNotify,
        JsonType::BOOLEAN,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<bool>(jsonObject,
        jsonObjectEnd,
        JSON_KEY_UPDATE_ENABLED,
        formInfo.updateEnabled,
        JsonType::BOOLEAN,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<bool>(jsonObject,
        jsonObjectEnd,
        JSON_KEY_IS_STATIC,
        formInfo.isStatic,
        JsonType::BOOLEAN,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
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
    GetValueIfFindKey<bool>(jsonObject,
        jsonObjectEnd,
        JSON_KEY_DATA_PROXY_ENABLED,
        formInfo.dataProxyEnabled,
        JsonType::BOOLEAN,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<bool>(jsonObject,
        jsonObjectEnd,
        JSON_KEY_IS_DYNAMIC,
        formInfo.isDynamic,
        JsonType::BOOLEAN,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<bool>(jsonObject,
        jsonObjectEnd,
        JSON_KEY_TRANSPARENCY_ENABLED,
        formInfo.transparencyEnabled,
        JsonType::BOOLEAN,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<int32_t>(jsonObject,
        jsonObjectEnd,
        JSON_KEY_PRIVACY_LEVEL,
        formInfo.privacyLevel,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<bool>(jsonObject,
        jsonObjectEnd,
        JSON_KEY_FONT_SCALE_FOLLOW_SYSTEM,
        formInfo.fontScaleFollowSystem,
        JsonType::BOOLEAN,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
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
    if (parseResult != ERR_OK) {
        APP_LOGE("read module formInfo from jsonObject error, error code : %{public}d", parseResult);
    }
}
}  // namespace AppExecFwk
}  // namespace OHOS
