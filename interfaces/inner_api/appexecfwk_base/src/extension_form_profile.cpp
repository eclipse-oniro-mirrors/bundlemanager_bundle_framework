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

#include "extension_form_profile.h"
#include "json_util.h"
#include "nlohmann/json.hpp"

namespace OHOS {
namespace AppExecFwk {
namespace {
int32_t g_parseResult = ERR_OK;
std::mutex g_mutex;

const int8_t MAX_FORM_NAME = 127;
const int8_t DEFAULT_RECT_SHAPE = 1;
const int8_t DEFAULT_CONDITION_TYPE = 0;
#ifndef FORM_DIMENSION_2_3
const int8_t DIMENSION_2_3 = 8;
#endif
#ifndef FORM_DIMENSION_3_3
const int8_t DIMENSION_3_3 = 9;
#endif
constexpr const char* FORM_COLOR_MODE_MAP_KEY[] = {
    "auto",
    "dark",
    "light"
};
const FormsColorMode FORM_COLOR_MODE_MAP_VALUE[] = {
    FormsColorMode::AUTO_MODE,
    FormsColorMode::DARK_MODE,
    FormsColorMode::LIGHT_MODE
};
constexpr const char* DIMENSION_MAP_KEY[] = {
    "1*2",
    "2*2",
    "2*4",
    "4*4",
    "2*1",
    "1*1",
    "6*4",
    "2*3",
    "3*3"
};
const int32_t DIMENSION_MAP_VALUE[] = {
    1,
    2,
    3,
    4,
    5,
    6,
    7,
    8,
    9
};
constexpr const char* SHAPE_MAP_KEY[] = {
    "rect",
    "circle"
};
const int32_t SHAPE_MAP_VALUE[] = {
    1,
    2
};
constexpr const char* CONDITION_MAP_KEY[] = {
    "network",
};
const int32_t CONDITION_MAP_VALUE[] = {
    1,
};
constexpr const char* FORM_TYPE_MAP_KEY[] = {
    "JS",
    "eTS"
};
const FormType FORM_TYPE_MAP_VALUE[] = {
    FormType::JS,
    FormType::ETS
};

constexpr const char* UI_SYNTAX_MAP_KEY[] = {
    "hml",
    "arkts"
};
const FormType UI_SYNTAX_MAP_VALUE[] = {
    FormType::JS,
    FormType::ETS
};

struct Window {
    int32_t designWidth = 720;
    bool autoDesignWidth = false;
};

constexpr char CHAR_COLON = ':';

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
    std::vector<std::string> conditionUpdate {};
    std::vector<Metadata> metadata {};
    std::vector<std::string> previewImages {};
};

struct ExtensionFormProfileInfoStruct {
    int32_t privacyLevel = 0;
    std::vector<ExtensionFormProfileInfo> forms {};
};

void from_json(const nlohmann::json &jsonObject, Metadata &metadata)
{
    const auto &jsonObjectEnd = jsonObject.end();
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        ExtensionFormProfileReader::METADATA_NAME,
        metadata.name,
        false,
        g_parseResult);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        ExtensionFormProfileReader::METADATA_VALUE,
        metadata.value,
        false,
        g_parseResult);
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
    BMSJsonUtil::GetBoolValueIfFindKey(jsonObject,
        jsonObjectEnd,
        ExtensionFormProfileReader::WINDOW_AUTO_DESIGN_WIDTH,
        window.autoDesignWidth,
        false,
        g_parseResult);
}

void from_json(const nlohmann::json &jsonObject, ExtensionFormProfileInfo &extensionFormProfileInfo)
{
    const auto &jsonObjectEnd = jsonObject.end();
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        ExtensionFormProfileReader::NAME,
        extensionFormProfileInfo.name,
        true,
        g_parseResult);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        ExtensionFormProfileReader::DISPLAY_NAME,
        extensionFormProfileInfo.displayName,
        false,
        g_parseResult);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        ExtensionFormProfileReader::DESCRIPTION,
        extensionFormProfileInfo.description,
        false,
        g_parseResult);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        ExtensionFormProfileReader::SRC,
        extensionFormProfileInfo.src,
        false,
        g_parseResult);
    GetValueIfFindKey<Window>(jsonObject,
        jsonObjectEnd,
        ExtensionFormProfileReader::WINDOW,
        extensionFormProfileInfo.window,
        JsonType::OBJECT,
        false,
        g_parseResult,
        ArrayType::NOT_ARRAY);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        ExtensionFormProfileReader::COLOR_MODE,
        extensionFormProfileInfo.colorMode,
        false,
        g_parseResult);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        ExtensionFormProfileReader::FORM_CONFIG_ABILITY,
        extensionFormProfileInfo.formConfigAbility,
        false,
        g_parseResult);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        ExtensionFormProfileReader::TYPE,
        extensionFormProfileInfo.type,
        false,
        g_parseResult);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        ExtensionFormProfileReader::UI_SYNTAX,
        extensionFormProfileInfo.uiSyntax,
        false,
        g_parseResult);
    BMSJsonUtil::GetBoolValueIfFindKey(jsonObject,
        jsonObjectEnd,
        ExtensionFormProfileReader::FORM_VISIBLE_NOTIFY,
        extensionFormProfileInfo.formVisibleNotify,
        false,
        g_parseResult);
    BMSJsonUtil::GetBoolValueIfFindKey(jsonObject,
        jsonObjectEnd,
        ExtensionFormProfileReader::IS_DEFAULT,
        extensionFormProfileInfo.isDefault,
        true,
        g_parseResult);
    BMSJsonUtil::GetBoolValueIfFindKey(jsonObject,
        jsonObjectEnd,
        ExtensionFormProfileReader::UPDATE_ENABLED,
        extensionFormProfileInfo.updateEnabled,
        true,
        g_parseResult);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        ExtensionFormProfileReader::SCHEDULED_UPDATE_TIME,
        extensionFormProfileInfo.scheduledUpdateTime,
        false,
        g_parseResult);
    GetValueIfFindKey<int32_t>(jsonObject,
        jsonObjectEnd,
        ExtensionFormProfileReader::UPDATE_DURATION,
        extensionFormProfileInfo.updateDuration,
        JsonType::NUMBER,
        false,
        g_parseResult,
        ArrayType::NOT_ARRAY);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        ExtensionFormProfileReader::DEFAULT_DIMENSION,
        extensionFormProfileInfo.defaultDimension,
        true,
        g_parseResult);
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
    BMSJsonUtil::GetBoolValueIfFindKey(jsonObject,
        jsonObjectEnd,
        ExtensionFormProfileReader::DATA_PROXY_ENABLED,
        extensionFormProfileInfo.dataProxyEnabled,
        false,
        g_parseResult);
    BMSJsonUtil::GetBoolValueIfFindKey(jsonObject,
        jsonObjectEnd,
        ExtensionFormProfileReader::IS_DYNAMIC,
        extensionFormProfileInfo.isDynamic,
        false,
        g_parseResult);
    BMSJsonUtil::GetBoolValueIfFindKey(jsonObject,
        jsonObjectEnd,
        ExtensionFormProfileReader::TRANSPARENCY_ENABLED,
        extensionFormProfileInfo.transparencyEnabled,
        false,
        g_parseResult);
    BMSJsonUtil::GetBoolValueIfFindKey(jsonObject,
        jsonObjectEnd,
        ExtensionFormProfileReader::FONT_SCALE_FOLLOW_SYSTEM,
        extensionFormProfileInfo.fontScaleFollowSystem,
        false,
        g_parseResult);
    GetValueIfFindKey<std::vector<std::string>>(jsonObject,
        jsonObjectEnd,
        ExtensionFormProfileReader::SUPPORT_SHAPES,
        extensionFormProfileInfo.supportShapes,
        JsonType::ARRAY,
        false,
        g_parseResult,
        ArrayType::STRING);
    GetValueIfFindKey<std::vector<std::string>>(jsonObject,
        jsonObjectEnd,
        ExtensionFormProfileReader::CONDITION_UPDATE,
        extensionFormProfileInfo.conditionUpdate,
        JsonType::ARRAY,
        false,
        g_parseResult,
        ArrayType::STRING);
    GetValueIfFindKey<std::vector<std::string>>(jsonObject,
        jsonObjectEnd,
        ExtensionFormProfileReader::PREVIEW_IMAGES,
        extensionFormProfileInfo.previewImages,
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
    size_t len = sizeof(DIMENSION_MAP_KEY) / sizeof(DIMENSION_MAP_KEY[0]);
    size_t i = 0;
    for (const auto &dimension: form.supportDimensions) {
        for (i = 0; i < len; i++) {
            if (DIMENSION_MAP_KEY[i] == dimension) break;
        }
        if (i == len) {
            APP_LOGW("dimension invalid form %{public}s", form.name.c_str());
            continue;
        }
                
        int32_t dimensionItem = DIMENSION_MAP_VALUE[i];
        #ifndef FORM_DIMENSION_2_3
            if (dimensionItem == DIMENSION_2_3) {
                APP_LOGW("dimension invalid in wearable Device form %{public}d", dimensionItem);
                continue;
            }
        #endif

        #ifndef FORM_DIMENSION_3_3
            if (dimensionItem == DIMENSION_3_3) {
                APP_LOGW("dimension invalid in wearable Device form %{public}d", dimensionItem);
                continue;
            }
        #endif

        supportDimensionSet.emplace(dimensionItem);
    }
    for (i = 0; i < len; i++) {
        if (DIMENSION_MAP_KEY[i] == form.defaultDimension) break;
    }
    if (i == len) {
        APP_LOGW("defaultDimension invalid form %{public}s", form.name.c_str());
        return false;
    }
    if (supportDimensionSet.find(DIMENSION_MAP_VALUE[i]) == supportDimensionSet.end()) {
        APP_LOGW("defaultDimension not in supportDimensions form %{public}s", form.name.c_str());
        return false;
    }

    info.defaultDimension = DIMENSION_MAP_VALUE[i];
    for (const auto &dimension: supportDimensionSet) {
        info.supportDimensions.emplace_back(dimension);
    }
    return true;
}

bool GetSupportShapes(const ExtensionFormProfileInfo &form, ExtensionFormInfo &info)
{
    std::set<int32_t> supportShapeSet {};
    size_t len = sizeof(SHAPE_MAP_KEY) / sizeof(SHAPE_MAP_KEY[0]);
    for (const auto &shape: form.supportShapes) {
        size_t i = 0;
        for (i = 0; i < len; i++) {
            if (SHAPE_MAP_KEY[i] == shape) break;
        }
        if (i == len) {
            APP_LOGW("dimension invalid form %{public}s", form.name.c_str());
            continue;
        }
        supportShapeSet.emplace(SHAPE_MAP_VALUE[i]);
    }

    if (supportShapeSet.empty()) {
        supportShapeSet.emplace(DEFAULT_RECT_SHAPE);
    }

    for (const auto &shape: supportShapeSet) {
        info.supportShapes.emplace_back(shape);
    }
    return true;
}

bool GetPreviewImages(const ExtensionFormProfileInfo &form, ExtensionFormInfo &info)
{
    for (const auto &previewImage: form.previewImages) {
        auto pos = previewImage.find(CHAR_COLON);
        if (pos != std::string::npos) {
            int32_t previewImageLength = static_cast<int32_t>(previewImage.length());
            auto previewImageId = static_cast<uint32_t>(
                    atoi(previewImage.substr(pos + 1, previewImageLength - pos - 1).c_str()));
            info.previewImages.emplace_back(previewImageId);
        }
    }
    return true;
}

bool GetConditionUpdate(const ExtensionFormProfileInfo &form, ExtensionFormInfo &info)
{
    std::set<int32_t> conditionUpdateSet {};
    size_t len = sizeof(CONDITION_MAP_KEY) / sizeof(CONDITION_MAP_KEY[0]);
    size_t i = 0;
    for (const auto &conditionUpdate: form.conditionUpdate) {
        for (i = 0; i < len; i++) {
            if (CONDITION_MAP_KEY[i] == conditionUpdate) {
                break;
            }
        }
        if (i == len) {
            APP_LOGW("conditionUpdate invalid form %{public}s", form.name.c_str());
            continue;
        }
        conditionUpdateSet.emplace(CONDITION_MAP_VALUE[i]);
    }
    if (conditionUpdateSet.empty()) {
        conditionUpdateSet.emplace(DEFAULT_CONDITION_TYPE);
    }
    for (const auto &conditionUpdate: conditionUpdateSet) {
        info.conditionUpdate.emplace_back(conditionUpdate);
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

    size_t len = sizeof(FORM_COLOR_MODE_MAP_KEY) / sizeof(FORM_COLOR_MODE_MAP_KEY[0]);
    for (size_t i = 0; i < len; i++) {
        if (FORM_COLOR_MODE_MAP_KEY[i] == form.colorMode)
            info.colorMode = FORM_COLOR_MODE_MAP_VALUE[i];
    }

    len = sizeof(FORM_TYPE_MAP_KEY) / sizeof(FORM_TYPE_MAP_KEY[0]);
    for (size_t i = 0; i < len; i++) {
        if (FORM_TYPE_MAP_KEY[i] == form.type)
            info.type = FORM_TYPE_MAP_VALUE[i];
        if (UI_SYNTAX_MAP_KEY[i] == form.uiSyntax)
            info.uiSyntax = UI_SYNTAX_MAP_VALUE[i];
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
    if (!GetConditionUpdate(form, info)) {
        return false;
    }
    if (!GetPreviewImages(form, info)) {
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
