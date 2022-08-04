/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "quick_fix/patch_profile.h"

#include <sstream>

#include "app_log_wrapper.h"
#include "bundle_util.h"
#include "json_util.h"
#include "parameter.h"
#include "string_ex.h"

namespace OHOS {
namespace AppExecFwk {
namespace PatchProfileReader {
constexpr const char* BUNDLE_PATCH_PROFILE_APP_KEY_BUNDLE_NAME = "bundleName";
constexpr const char* BUNDLE_PATCH_PROFILE_APP_KEY_VERSION_CODE = "versionCode";
constexpr const char* BUNDLE_PATCH_PROFILE_APP_KEY_VERSION_NAME = "versionName";
constexpr const char* BUNDLE_PATCH_PROFILE_APP_KEY_PATCH_VERSION_CODE = "patchVersionCode";
constexpr const char* BUNDLE_PATCH_PROFILE_APP_KEY_PATCH_VERSION_NAME = "patchVersionName";
constexpr const char* BUNDLE_PATCH_PROFILE_MODULE_KEY_NAME = "name";
constexpr const char* BUNDLE_PATCH_PROFILE_MODULE_KEY_TYPE = "type";
constexpr const char* BUNDLE_PATCH_PROFILE_MODULE_KEY_DEVICE_TYPES = "deviceTypes";
constexpr const char* BUNDLE_PATCH_PROFILE_MODULE_KEY_ORIGINAL_MODULE_HASH = "originalModuleHash";
constexpr const char* BUNDLE_PATCH_PROFILE_KEY_APP = "app";
constexpr const char* BUNDLE_PATCH_PROFILE_KEY_MODULE = "module";

thread_local int32_t parseResult = 0;
struct App {
    std::string bundleName;
    int32_t versionCode = 0;
    std::string versionName;
    int32_t patchVersionCode = 0;
    std::string patchVersionName;
};

struct Module {
    std::string name;
    std::string type;
    std::vector<std::string> deviceTypes;
    std::string originalModuleHash;
};

struct PatchJson {
    App app;
    Module module;
};

void from_json(const nlohmann::json &jsonObject, App &app)
{
    const auto &jsonObjectEnd = jsonObject.end();
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        BUNDLE_PATCH_PROFILE_APP_KEY_BUNDLE_NAME,
        app.bundleName,
        JsonType::STRING,
        true,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<int32_t>(jsonObject,
        jsonObjectEnd,
        BUNDLE_PATCH_PROFILE_APP_KEY_VERSION_CODE,
        app.versionCode,
        JsonType::NUMBER,
        true,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        BUNDLE_PATCH_PROFILE_APP_KEY_VERSION_NAME,
        app.versionName,
        JsonType::STRING,
        true,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<int32_t>(jsonObject,
        jsonObjectEnd,
        BUNDLE_PATCH_PROFILE_APP_KEY_PATCH_VERSION_CODE,
        app.patchVersionCode,
        JsonType::NUMBER,
        true,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        BUNDLE_PATCH_PROFILE_APP_KEY_PATCH_VERSION_NAME,
        app.patchVersionName,
        JsonType::STRING,
        true,
        parseResult,
        ArrayType::NOT_ARRAY);
}

void from_json(const nlohmann::json &jsonObject, Module &module)
{
    const auto &jsonObjectEnd = jsonObject.end();
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        BUNDLE_PATCH_PROFILE_MODULE_KEY_NAME,
        module.name,
        JsonType::STRING,
        true,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        BUNDLE_PATCH_PROFILE_MODULE_KEY_TYPE,
        module.type,
        JsonType::STRING,
        true,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::vector<std::string>>(jsonObject,
        jsonObjectEnd,
        BUNDLE_PATCH_PROFILE_MODULE_KEY_DEVICE_TYPES,
        module.deviceTypes,
        JsonType::ARRAY,
        true,
        parseResult,
        ArrayType::STRING);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        BUNDLE_PATCH_PROFILE_MODULE_KEY_ORIGINAL_MODULE_HASH,
        module.originalModuleHash,
        JsonType::STRING,
        true,
        parseResult,
        ArrayType::NOT_ARRAY);
}

void from_json(const nlohmann::json &jsonObject, PatchJson &patchJson)
{
    const auto &jsonObjectEnd = jsonObject.end();
    GetValueIfFindKey<App>(jsonObject,
        jsonObjectEnd,
        BUNDLE_PATCH_PROFILE_KEY_APP,
        patchJson.app,
        JsonType::OBJECT,
        true,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<Module>(jsonObject,
        jsonObjectEnd,
        BUNDLE_PATCH_PROFILE_KEY_MODULE,
        patchJson.module,
        JsonType::OBJECT,
        true,
        parseResult,
        ArrayType::NOT_ARRAY);
}
}

void ToPatchInfo(PatchProfileReader::PatchJson &patchJson, AppQuickFix &appQuickFix)
{
    appQuickFix.bundleName = patchJson.app.bundleName;
    appQuickFix.versionCode = patchJson.app.versionCode;
    appQuickFix.versionName = patchJson.app.versionName;
    appQuickFix.deployingAppqfInfo.versionCode = patchJson.app.patchVersionCode;
    appQuickFix.deployingAppqfInfo.versionName = patchJson.app.patchVersionName;
    HqfInfo hqfInfo;
    hqfInfo.moduleName = patchJson.module.name;
    hqfInfo.hapSha256 = patchJson.module.originalModuleHash;
    appQuickFix.deployingAppqfInfo.hqfInfos.emplace_back(hqfInfo);
}

ErrCode PatchProfile::TransformTo(const std::ostringstream &source, AppQuickFix &appQuickFix)
{
    nlohmann::json jsonObject = nlohmann::json::parse(source.str(), nullptr, false);
    if (jsonObject.is_discarded()) {
        APP_LOGE("bad profile");
        return ERR_APPEXECFWK_PARSE_BAD_PROFILE;
    }
    PatchProfileReader::PatchJson patchJson = jsonObject.get<PatchProfileReader::PatchJson>();
    if (PatchProfileReader::parseResult != ERR_OK) {
        APP_LOGE("parseResult is %{public}d", PatchProfileReader::parseResult);
        int32_t ret = PatchProfileReader::parseResult;
        PatchProfileReader::parseResult = ERR_OK;
        return ret;
    }
    ToPatchInfo(patchJson, appQuickFix);
    return ERR_OK;
}
}  // namespace AppExecFwk
}  // namespace OHOS