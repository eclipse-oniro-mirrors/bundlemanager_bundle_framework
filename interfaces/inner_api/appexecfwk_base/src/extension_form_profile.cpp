/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include <map>
#include <mutex>
#include <set>

#include"extension_form_profile.h"
#include "json_util.h"
#include "nlohmann/json.hpp"

namespace OHOS {
namespace AppExecFwk {
namespace {
int32_t g_parseResult = ERR_OK;
std::mutex g_mutex;

const int8_t MAX_FORM_NAME = 127;
const int8_t DEFAULT_RECT_SHAPE = 1;
const char* formColorModeMapKey[] = {
    "auto",
    "dark",
    "light"
};
const FormsColorMode formColorModeMapValue[] = {
    FormsColorMode::AUTO_MODE,
    FormsColorMode::DARK_MODE,
    FormsColorMode::LIGHT_MODE
};
const char* dimensionMapKey[] = {
    "1*2",
    "2*2",
    "2*4",
    "4*4",
    "2*1",
    "1*1",
    "6*4"
};
const int32_t dimensionMapValue[] = {
    1,
    2,
    3,
    4,
    5,
    6,
    7
};
const char* shapeMapKey[] = {
    "rect", 
    "circle"
};
const int32_t shapeMapValue[] = {
    1,
    2
};
const char* formTypeMapKey[] = {
    "JS", 
    "eTS"
};
const FormType formTypeMapValue[] = {
    FormType::JS,
    FormType::ETS
};

const char* uiSyntaxMapKey[] = {
    "hml", 
    "arkts"
};
const FormType uiSyntaxMapValue[] = {
    FormType::JS,
    FormType::ETS
};

struct Window {
    int32_t designWidth = 720;
    bool autoDesignWidth = false;
};

struct Metadata {
    std::string name;
    std::string value;
};

struct ExtensionFormProfileInfo {
    std::string name;
    std::string displayName;
    std::string description;
    std::string src;
    Window window;
    std::string colorMode = "auto";
    std::string formConfigAbility;
    std::string type = "JS";
    std::string uiSyntax = "hml";
    std::string scheduledUpdateTime = "";
    int32_t updateDuration = 0;
    std::string defaultDimension;
    bool formVisibleNotify = false;
    bool isDefault = false;
    bool updateEnabled = false;
    bool dataProxyEnabled = false;
    bool isDynamic = true;
    bool transparencyEnabled = false;
    bool fontScaleFollowSystem = true;
    std::vector<std::string> supportShapes {};
    std::vector<std::string> supportDimensions {};
    std::vector<Metadata> metadata {};
};

struct ExtensionFormProfileInfoStruct {
    int32_t privacyLevel = 0;
    std::vector<ExtensionFormProfileInfo> forms {};
};

void from_json(const nlohmann::json &jsonObject, Metadata &metadata)
{
    const auto &jsonObjectEnd = jsonObject.end();
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        ExtensionFormProfileReader::METADATA_NAME,
        metadata.name,
        JsonType::STRING,
        false,
        g_parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        ExtensionFormProfileReader::METADATA_VALUE,
        metadata.value,
        JsonType::STRING,
        false,
        g_parseResult,
        ArrayType::NOT_ARRAY);
}

void from_json(const nlohmann::json &jsonObject, Window &window)
{
    const auto &jsonObjectEnd = jsonObject.end();
    GetValueIfFindKey<int32_t>(jsonObject,
        jsonObjectEnd,
        ExtensionFormProfileReader::WINDOW_DESIGN_WIDTH,
        window.designWidth,
        JsonType::NUMBER,
        false,
        g_parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<bool>(jsonObject,
        jsonObjectEnd,
        ExtensionFormProfileReader::WINDOW_AUTO_DESIGN_WIDTH,
        window.autoDesignWidth,
        JsonType::BOOLEAN,
        false,
        g_parseResult,
        ArrayType::NOT_ARRAY);
}

void from_json(const nlohmann::json &jsonObject, ExtensionFormProfileInfo &extensionFormProfileInfo)
{
    const auto &jsonObjectEnd = jsonObject.end();
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        ExtensionFormProfileReader::NAME,
        extensionFormProfileInfo.name,
        JsonType::STRING,
        true,
        g_parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        ExtensionFormProfileReader::DISPLAY_NAME,
        extensionFormProfileInfo.displayName,
        JsonType::STRING,
        false,
        g_parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        ExtensionFormProfileReader::DESCRIPTION,
        extensionFormProfileInfo.description,
        JsonType::STRING,
        false,
        g_parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        ExtensionFormProfileReader::SRC,
        extensionFormProfileInfo.src,
        JsonType::STRING,
        false,
        g_parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<Window>(jsonObject,
        jsonObjectEnd,
        ExtensionFormProfileReader::WINDOW,
        extensionFormProfileInfo.window,
        JsonType::OBJECT,
        false,
        g_parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        ExtensionFormProfileReader::COLOR_MODE,
        extensionFormProfileInfo.colorMode,
        JsonType::STRING,
        false,
        g_parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        ExtensionFormProfileReader::FORM_CONFIG_ABILITY,
        extensionFormProfileInfo.formConfigAbility,
        JsonType::STRING,
        false,
        g_parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        ExtensionFormProfileReader::TYPE,
        extensionFormProfileInfo.type,
        JsonType::STRING,
        false,
        g_parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        ExtensionFormProfileReader::UI_SYNTAX,
        extensionFormProfileInfo.uiSyntax,
        JsonType::STRING,
        false,
        g_parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<bool>(jsonObject,
        jsonObjectEnd,
        ExtensionFormProfileReader::FORM_VISIBLE_NOTIFY,
        extensionFormProfileInfo.formVisibleNotify,
        JsonType::BOOLEAN,
        false,
        g_parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<bool>(jsonObject,
        jsonObjectEnd,
        ExtensionFormProfileReader::IS_DEFAULT,
        extensionFormProfileInfo.isDefault,
        JsonType::BOOLEAN,
        true,
        g_parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<bool>(jsonObject,
        jsonObjectEnd,
        ExtensionFormProfileReader::UPDATE_ENABLED,
        extensionFormProfileInfo.updateEnabled,
        JsonType::BOOLEAN,
        true,
        g_parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        ExtensionFormProfileReader::SCHEDULED_UPDATE_TIME,
        extensionFormProfileInfo.scheduledUpdateTime,
        JsonType::STRING,
        false,
        g_parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<int32_t>(jsonObject,
        jsonObjectEnd,
        ExtensionFormProfileReader::UPDATE_DURATION,
        extensionFormProfileInfo.updateDuration,
        JsonType::NUMBER,
        false,
        g_parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        ExtensionFormProfileReader::DEFAULT_DIMENSION,
        extensionFormProfileInfo.defaultDimension,
        JsonType::STRING,
        true,
        g_parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::vector<std::string>>(jsonObject,
        jsonObjectEnd,
        ExtensionFormProfileReader::SUPPORT_DIMENSIONS,
        extensionFormProfileInfo.supportDimensions,
        JsonType::ARRAY,
        true,
        g_parseResult,
        ArrayType::STRING);
    GetValueIfFindKey<std::vector<Metadata>>(jsonObject,
        jsonObjectEnd,
        ExtensionFormProfileReader::METADATA,
        extensionFormProfileInfo.metadata,
        JsonType::ARRAY,
        false,
        g_parseResult,
        ArrayType::OBJECT);
    GetValueIfFindKey<bool>(jsonObject,
        jsonObjectEnd,
        ExtensionFormProfileReader::DATA_PROXY_ENABLED,
        extensionFormProfileInfo.dataProxyEnabled,
        JsonType::BOOLEAN,
        false,
        g_parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<bool>(jsonObject,
        jsonObjectEnd,
        ExtensionFormProfileReader::IS_DYNAMIC,
        extensionFormProfileInfo.isDynamic,
        JsonType::BOOLEAN,
        false,
        g_parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<bool>(jsonObject,
        jsonObjectEnd,
        ExtensionFormProfileReader::TRANSPARENCY_ENABLED,
        extensionFormProfileInfo.transparencyEnabled,
        JsonType::BOOLEAN,
        false,
        g_parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<bool>(jsonObject,
        jsonObjectEnd,
        ExtensionFormProfileReader::FONT_SCALE_FOLLOW_SYSTEM,
        extensionFormProfileInfo.fontScaleFollowSystem,
        JsonType::BOOLEAN,
        false,
        g_parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::vector<std::string>>(jsonObject,
        jsonObjectEnd,
        ExtensionFormProfileReader::SUPPORT_SHAPES,
        extensionFormProfileInfo.supportShapes,
        JsonType::ARRAY,
        false,
        g_parseResult,
        ArrayType::STRING);
}

void from_json(const nlohmann::json &jsonObject, ExtensionFormProfileInfoStruct &profileInfo)
{
    const auto &jsonObjectEnd = jsonObject.end();
    GetValueIfFindKey<int32_t>(jsonObject,
        jsonObjectEnd,
        ExtensionFormProfileReader::PRIVACY_LEVEL,
        profileInfo.privacyLevel,
        JsonType::NUMBER,
        false,
        g_parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::vector<ExtensionFormProfileInfo>>(jsonObject,
        jsonObjectEnd,
        ExtensionFormProfileReader::FORMS,
        profileInfo.forms,
        JsonType::ARRAY,
        false,
        g_parseResult,
        ArrayType::OBJECT);
}

bool CheckFormNameIsValid(const std::string &name)
{
    if (name.empty()) {
        APP_LOGE("name is empty");
        return false;
    }
    if (name.size() > MAX_FORM_NAME) {
        APP_LOGE("name size is too long");
        return false;
    }
    return true;
}

bool GetMetadata(const ExtensionFormProfileInfo &form, ExtensionFormInfo &info)
{
    std::set<int32_t> supportDimensionSet {};
    for (const auto &dimension: form.supportDimensions) {
        size_t i = 0;
        for (i = 0; i < sizeof(dimensionMapKey) / sizeof(dimensionMapKey[0]); i++) {
            if (dimensionMapKey[i] == dimension) break;
        }
        if (i == sizeof(dimensionMapKey) / sizeof(dimensionMapKey[0])) {
            APP_LOGW("dimension invalid form %{public}s", form.name.c_str());
            continue;
        }
        supportDimensionSet.emplace(dimensionMapValue[i]);
    }

    size_t i = 0;
    for (i = 0; i < sizeof(dimensionMapKey) / sizeof(dimensionMapKey[0]); i++) {
        if (dimensionMapKey[i] == form.defaultDimension) break;
    }
    if (i == sizeof(dimensionMapKey) / sizeof(dimensionMapKey[0])) {
        APP_LOGW("defaultDimension invalid form %{public}s", form.name.c_str());
        return false;
    }
    if (supportDimensionSet.find(dimensionMapValue[i]) == supportDimensionSet.end()) {
        APP_LOGW("defaultDimension not in supportDimensions form %{public}s", form.name.c_str());
        return false;
    }

    info.defaultDimension = dimensionMapValue[i];
    for (const auto &dimension: supportDimensionSet) {
        info.supportDimensions.emplace_back(dimension);
    }
    return true;
}

bool GetSupportShapes(const ExtensionFormProfileInfo &form, ExtensionFormInfo &info)
{
    std::set<int32_t> supportShapeSet {};
    for (const auto &shape: form.supportShapes) {
        size_t i = 0;
        for (i = 0; i < sizeof(shapeMapKey) / sizeof(shapeMapKey[0]); i++) {
            if (shapeMapKey[i] == shape) break;
        }
        if (i == sizeof(shapeMapKey) / sizeof(shapeMapKey[0])) {
            APP_LOGW("dimension invalid form %{public}s", form.name.c_str());
            continue;
        }
        supportShapeSet.emplace(shapeMapValue[i]);
    }

    if (supportShapeSet.empty()) {
        supportShapeSet.emplace(DEFAULT_RECT_SHAPE);
    }

    for (const auto &shape: supportShapeSet) {
        info.supportShapes.emplace_back(shape);
    }
    return true;
}

bool TransformToExtensionFormInfo(const ExtensionFormProfileInfo &form, ExtensionFormInfo &info)
{
    if (!CheckFormNameIsValid(form.name)) {
        APP_LOGE("form name is invalid");
        return false;
    }
    info.name = form.name;
    info.description = form.description;
    info.displayName = form.displayName;
    info.src = form.src;
    info.window.autoDesignWidth = form.window.autoDesignWidth;
    info.window.designWidth = form.window.designWidth;

    for (size_t i = 0; i < sizeof(formColorModeMapKey) / sizeof(formColorModeMapKey[0]); i++) {
        if (formColorModeMapKey[i] == form.colorMode) {
            info.colorMode = formColorModeMapValue[i];
        }
    }

    for (size_t i = 0; i < sizeof(formTypeMapKey) / sizeof(formTypeMapKey[0]); i++) {
        if (formTypeMapKey[i] == form.type) {
            info.type = formTypeMapValue[i];
        }
    }

    for (size_t i = 0; i < sizeof(uiSyntaxMapKey) / sizeof(uiSyntaxMapKey[0]); i++) {
        if (uiSyntaxMapKey[i] == form.uiSyntax) {
            info.uiSyntax = uiSyntaxMapValue[i];
        }
    }

    info.formConfigAbility = form.formConfigAbility;
    info.formVisibleNotify = form.formVisibleNotify;
    info.isDefault = form.isDefault;
    info.updateEnabled = form.updateEnabled;
    info.scheduledUpdateTime = form.scheduledUpdateTime;
    info.updateDuration = form.updateDuration;

    if (!GetMetadata(form, info)) {
        return false;
    }
    for (const auto &data: form.metadata) {
        FormCustomizeData customizeData;
        customizeData.name = data.name;
        customizeData.value = data.value;
        info.metadata.emplace_back(customizeData);
    }

    info.dataProxyEnabled = form.dataProxyEnabled;
    info.isDynamic = form.isDynamic;
    info.transparencyEnabled = form.transparencyEnabled;
    info.fontScaleFollowSystem = form.fontScaleFollowSystem;

    if (!GetSupportShapes(form, info)) {
        return false;
    }
    return true;
}

bool TransformToInfos(const ExtensionFormProfileInfoStruct &profileInfo, std::vector<ExtensionFormInfo> &infos)
{
    APP_LOGD("transform ExtensionFormProfileInfo to ExtensionFormInfo");
    for (const auto &form: profileInfo.forms) {
        ExtensionFormInfo info;
        if (!TransformToExtensionFormInfo(form, info)) {
            return false;
        }
        infos.push_back(info);
    }
    return true;
}
} // namespace

ErrCode ExtensionFormProfile::TransformTo(
    const std::string &formProfile, std::vector<ExtensionFormInfo> &infos, int32_t &privacyLevel)
{
    APP_LOGD("transform profile to extension form infos");
    nlohmann::json jsonObject = nlohmann::json::parse(formProfile, nullptr, false);
    if (jsonObject.is_discarded()) {
        APP_LOGE("bad profile");
        return ERR_APPEXECFWK_PARSE_BAD_PROFILE;
    }

    ExtensionFormProfileInfoStruct profileInfo;
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_parseResult = ERR_OK;
        profileInfo = jsonObject.get<ExtensionFormProfileInfoStruct>();
        privacyLevel = profileInfo.privacyLevel;
        if (g_parseResult != ERR_OK) {
            APP_LOGE("g_parseResult %{public}d", g_parseResult);
            int32_t ret = g_parseResult;
            // need recover parse result to ERR_OK
            g_parseResult = ERR_OK;
            return ret;
        }
    }

    if (!TransformToInfos(profileInfo, infos)) {
        return ERR_APPEXECFWK_PARSE_PROFILE_PROP_CHECK_ERROR;
    }
    return ERR_OK;
}
}  // namespace AppExecFwk
}  // namespace OHOS
