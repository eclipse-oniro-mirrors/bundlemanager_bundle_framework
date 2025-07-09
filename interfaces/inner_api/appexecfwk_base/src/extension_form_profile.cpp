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

#include <sstream>
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
constexpr const char* FORM_RENDERING_MODE_MAP_KEY[] = {
    "autoColor",
    "fullColor",
    "singleColor"
};
const FormsRenderingMode FORM_RENDERING_MODE_MAP_VALUE[] = {
    FormsRenderingMode::AUTO_COLOR,
    FormsRenderingMode::FULL_COLOR,
    FormsRenderingMode::SINGLE_COLOR
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
    "3*3",
    "3*4"
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

struct FormFunInteractionParams {
    std::string abilityName;
    std::string targetBundleName;
    std::string subBundleName;
    int32_t keepStateDuration = 10000;
};

struct FormSceneAnimationParams {
    std::string abilityName;
    bool isAlwaysActive = false;
};

struct ExtensionFormProfileInfo {
    std::string name;
    std::string displayName;
    std::string description;
    std::string src;
    Window window;
    std::string colorMode = "auto";
    std::string renderingMode = "fullColor";
    std::string formConfigAbility;
    std::string type = "JS";
    std::string uiSyntax = "hml";
    std::string scheduledUpdateTime = "";
    std::string multiScheduledUpdateTime = "";
    int32_t updateDuration = 0;
    std::string defaultDimension;
    bool formVisibleNotify = false;
    bool isDefault = false;
    bool updateEnabled = false;
    bool dataProxyEnabled = false;
    bool isDynamic = true;
    bool transparencyEnabled = false;
    bool fontScaleFollowSystem = true;
    bool enableBlurBackground = false;
    std::vector<std::string> supportShapes {};
    std::vector<std::string> supportDimensions {};
    std::vector<std::string> conditionUpdate {};
    std::vector<Metadata> metadata {};
    std::vector<std::string> previewImages {};
    FormFunInteractionParams funInteractionParams;
    FormSceneAnimationParams sceneAnimationParams;
    bool resizable = false;
    std::string groupId;
};

struct ExtensionFormProfileInfoStruct {
    int32_t privacyLevel = 0;
    std::vector<ExtensionFormProfileInfo> forms {};
};

void from_json(const nlohmann::json &jsonObject, FormFunInteractionParams &funInteractionParams)
{
    const auto &jsonObjectEnd = jsonObject.end();
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        ExtensionFormProfileReader::ABILITY_NAME,
        funInteractionParams.abilityName,
        false,
        g_parseResult);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        ExtensionFormProfileReader::TARGET_BUNDLE_NAME,
        funInteractionParams.targetBundleName,
        false,
        g_parseResult);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        ExtensionFormProfileReader::SUB_BUNDLE_NAME,
        funInteractionParams.subBundleName,
        false,
        g_parseResult);
    GetValueIfFindKey<int32_t>(jsonObject,
        jsonObjectEnd,
        ExtensionFormProfileReader::KEEP_STATE_DURATION,
        funInteractionParams.keepStateDuration,
        JsonType::NUMBER,
        false,
        g_parseResult,
        ArrayType::NOT_ARRAY);
}

void from_json(const nlohmann::json &jsonObject, FormSceneAnimationParams &sceneAnimationParams)
{
    const auto &jsonObjectEnd = jsonObject.end();
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        ExtensionFormProfileReader::ABILITY_NAME,
        sceneAnimationParams.abilityName,
        false,
        g_parseResult);
    BMSJsonUtil::GetBoolValueIfFindKey(jsonObject,
        jsonObjectEnd,
        ExtensionFormProfileReader::IS_ALWAYS_ACTIVE,
        sceneAnimationParams.isAlwaysActive,
        false,
        g_parseResult);
    GetValueIfFindKey<std::vector<std::string>>(jsonObject,
        jsonObjectEnd,
        ExtensionFormProfileReader::DISABLED_DESKTOP_BEHAVIORS,
        sceneAnimationParams.disabledDesktopBehaviors,
        JsonType::ARRAY,
        false,
        g_parseResult,
        ArrayType::STRING);
}

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
        ExtensionFormProfileReader::RENDERING_MODE,
        extensionFormProfileInfo.renderingMode,
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
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        ExtensionFormProfileReader::MULTI_SCHEDULED_UPDATE_TIME,
        extensionFormProfileInfo.multiScheduledUpdateTime,
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
    BMSJsonUtil::GetBoolValueIfFindKey(jsonObject,
        jsonObjectEnd,
        ExtensionFormProfileReader::ENABLE_BLUR_BACKGROUND,
        extensionFormProfileInfo.enableBlurBackground,
        false,
        g_parseResult);
    GetValueIfFindKey<FormFunInteractionParams>(jsonObject,
        jsonObjectEnd,
        ExtensionFormProfileReader::FUN_INTERACTION_PARAMS,
        extensionFormProfileInfo.funInteractionParams,
        JsonType::OBJECT,
        false,
        g_parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<FormSceneAnimationParams>(jsonObject,
        jsonObjectEnd,
        ExtensionFormProfileReader::SCENE_ANIMATION_PARAMS,
        extensionFormProfileInfo.sceneAnimationParams,
        JsonType::OBJECT,
        false,
        g_parseResult,
        ArrayType::NOT_ARRAY);
    BMSJsonUtil::GetBoolValueIfFindKey(jsonObject,
        jsonObjectEnd,
        ExtensionFormProfileReader::RESIZABLE,
        extensionFormProfileInfo.resizable,
        false,
        g_parseResult);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        ExtensionFormProfileReader::GROUP_ID,
        extensionFormProfileInfo.groupId,
        false,
        g_parseResult);
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

void supportFormDimension(std::set<int32_t> &supportDimensionSet, const ExtensionFormProfileInfo &form)
{
    size_t i = 0;
    size_t len = sizeof(DIMENSION_MAP_KEY) / sizeof(DIMENSION_MAP_KEY[0]);
    for (const auto &dimension: form.supportDimensions) {
        for (i = 0; i < len; i++) {
            if (DIMENSION_MAP_KEY[i] == dimension) {
                break;
            }
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
}

bool GetMetadata(const ExtensionFormProfileInfo &form, ExtensionFormInfo &info)
{
    std::set<int32_t> supportDimensionSet {};
    size_t len = sizeof(DIMENSION_MAP_KEY) / sizeof(DIMENSION_MAP_KEY[0]);
    size_t i = 0;
    supportFormDimension(supportDimensionSet, form);
    for (i = 0; i < len; i++) {
        if (DIMENSION_MAP_KEY[i] == form.defaultDimension) {
            break;
        }
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

void TransformToFormInfoExt(const ExtensionFormProfileInfo &form, ExtensionFormInfo &info)
{
    info.name = form.name;
    info.description = form.description;
    info.displayName = form.displayName;
    info.src = form.src;
    info.window.autoDesignWidth = form.window.autoDesignWidth;
    info.window.designWidth = form.window.designWidth;
    info.formConfigAbility = form.formConfigAbility;
    info.formVisibleNotify = form.formVisibleNotify;
    info.isDefault = form.isDefault;
    info.updateEnabled = form.updateEnabled;
    info.scheduledUpdateTime = form.scheduledUpdateTime;
    info.multiScheduledUpdateTime = form.multiScheduledUpdateTime;
    info.updateDuration = form.updateDuration;
    info.funInteractionParams.abilityName = form.funInteractionParams.abilityName;
    info.funInteractionParams.targetBundleName = form.funInteractionParams.targetBundleName;
    info.funInteractionParams.subBundleName = form.funInteractionParams.subBundleName;
    info.funInteractionParams.keepStateDuration = form.funInteractionParams.keepStateDuration;
    info.sceneAnimationParams.abilityName = form.sceneAnimationParams.abilityName;
    info.sceneAnimationParams.isAlwaysActive = form.sceneAnimationParams.isAlwaysActive;
    info.resizable = form.resizable;
    info.groupId = form.groupId;
}

bool TransformToExtensionFormInfo(const ExtensionFormProfileInfo &form, ExtensionFormInfo &info)
{
    if (!CheckFormNameIsValid(form.name)) {
        APP_LOGE("form name is invalid");
        return false;
    }
    TransformToFormInfoExt(form, info);

    auto& disabledDesktopBehaviors = form.sceneAnimationParams.disabledDesktopBehaviors;
    std::ostringstream oss;
    for (size_t i = 0; i < disabledDesktopBehaviors.size(); i++) {
        oss << disabledDesktopBehaviors[i];
        if (i < disabledDesktopBehaviors.size() - 1) {
            oss << "|";
        }
    }
    info.sceneAnimationParams.disabledDesktopBehaviors = oss.str();

    size_t len = sizeof(FORM_COLOR_MODE_MAP_KEY) / sizeof(FORM_COLOR_MODE_MAP_KEY[0]);
    for (size_t i = 0; i < len; i++) {
        if (FORM_COLOR_MODE_MAP_KEY[i] == form.colorMode)
            info.colorMode = FORM_COLOR_MODE_MAP_VALUE[i];
    }

    len = sizeof(FORM_RENDERING_MODE_MAP_KEY) / sizeof(FORM_RENDERING_MODE_MAP_KEY[0]);
    for (size_t i = 0; i < len; i++) {
        if (FORM_RENDERING_MODE_MAP_KEY[i] == form.renderingMode) {
            info.renderingMode = FORM_RENDERING_MODE_MAP_VALUE[i];
        }
    }

    len = sizeof(FORM_TYPE_MAP_KEY) / sizeof(FORM_TYPE_MAP_KEY[0]);
    for (size_t i = 0; i < len; i++) {
        if (FORM_TYPE_MAP_KEY[i] == form.type)
            info.type = FORM_TYPE_MAP_VALUE[i];
        if (UI_SYNTAX_MAP_KEY[i] == form.uiSyntax)
            info.uiSyntax = UI_SYNTAX_MAP_VALUE[i];
    }

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
    info.enableBlurBackground = form.enableBlurBackground;
    APP_LOGI("form name: %{public}s enableBlurBackground: %{public}d", info.name.c_str(), info.enableBlurBackground);
    if (info.enableBlurBackground) {
        info.transparencyEnabled = true;
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
