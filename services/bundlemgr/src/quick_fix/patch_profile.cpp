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

#include "app_log_tag_wrapper.h"
#include "bundle_service_constants.h"
#include "bundle_util.h"
#include "json_util.h"
#include "parameter.h"

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
constexpr const char* BUNDLE_PATCH_TYPE_PATCH = "patch";
constexpr const char* BUNDLE_PATCH_TYPE_HOT_RELOAD = "hotreload";

int32_t g_parseResult = ERR_OK;
std::mutex g_mutex;
struct App {
    std::string bundleName;
    uint32_t versionCode = 0;
    uint32_t patchVersionCode = 0;
    std::string versionName;
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
        g_parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<uint32_t>(jsonObject,
        jsonObjectEnd,
        BUNDLE_PATCH_PROFILE_APP_KEY_VERSION_CODE,
        app.versionCode,
        JsonType::NUMBER,
        true,
        g_parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        BUNDLE_PATCH_PROFILE_APP_KEY_VERSION_NAME,
        app.versionName,
        JsonType::STRING,
        false,
        g_parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<uint32_t>(jsonObject,
        jsonObjectEnd,
        BUNDLE_PATCH_PROFILE_APP_KEY_PATCH_VERSION_CODE,
        app.patchVersionCode,
        JsonType::NUMBER,
        true,
        g_parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        BUNDLE_PATCH_PROFILE_APP_KEY_PATCH_VERSION_NAME,
        app.patchVersionName,
        JsonType::STRING,
        false,
        g_parseResult,
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
        g_parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        BUNDLE_PATCH_PROFILE_MODULE_KEY_TYPE,
        module.type,
        JsonType::STRING,
        true,
        g_parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::vector<std::string>>(jsonObject,
        jsonObjectEnd,
        BUNDLE_PATCH_PROFILE_MODULE_KEY_DEVICE_TYPES,
        module.deviceTypes,
        JsonType::ARRAY,
        false,
        g_parseResult,
        ArrayType::STRING);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        BUNDLE_PATCH_PROFILE_MODULE_KEY_ORIGINAL_MODULE_HASH,
        module.originalModuleHash,
        JsonType::STRING,
        false,
        g_parseResult,
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
        g_parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<Module>(jsonObject,
        jsonObjectEnd,
        BUNDLE_PATCH_PROFILE_KEY_MODULE,
        patchJson.module,
        JsonType::OBJECT,
        true,
        g_parseResult,
        ArrayType::NOT_ARRAY);
}

QuickFixType GetQuickFixType(const std::string &type)
{
    if (type == BUNDLE_PATCH_TYPE_PATCH) {
        return QuickFixType::PATCH;
    }
    if (type == BUNDLE_PATCH_TYPE_HOT_RELOAD) {
        return QuickFixType::HOT_RELOAD;
    }
    LOG_W(BMS_TAG_DEFAULT, "GetQuickFixType: unknow quick fix type");
    return QuickFixType::UNKNOWN;
}

bool CheckNameIsValid(const std::string &name)
{
    if (name.empty()) {
        LOG_E(BMS_TAG_DEFAULT, "CheckNameIsValid: name is empty");
        return false;
    }
    if (name.find(ServiceConstants::RELATIVE_PATH) != std::string::npos) {
        return false;
    }
    return true;
}

bool ToPatchInfo(const PatchJson &patchJson, AppQuickFix &appQuickFix)
{
    if (!CheckNameIsValid(patchJson.app.bundleName)) {
        LOG_E(BMS_TAG_DEFAULT, "bundle name is invalid");
        return false;
    }
    if (!CheckNameIsValid(patchJson.module.name)) {
        LOG_E(BMS_TAG_DEFAULT, "module name is invalid");
        return false;
    }
    appQuickFix.bundleName = patchJson.app.bundleName;
    appQuickFix.versionCode = patchJson.app.versionCode;
    appQuickFix.versionName = patchJson.app.versionName;
    appQuickFix.deployingAppqfInfo.versionCode = patchJson.app.patchVersionCode;
    appQuickFix.deployingAppqfInfo.versionName = patchJson.app.patchVersionName;
    appQuickFix.deployingAppqfInfo.type = GetQuickFixType(patchJson.module.type);
    HqfInfo hqfInfo;
    hqfInfo.moduleName = patchJson.module.name;
    hqfInfo.hapSha256 = patchJson.module.originalModuleHash;
    hqfInfo.type = GetQuickFixType(patchJson.module.type);
    appQuickFix.deployingAppqfInfo.hqfInfos.emplace_back(hqfInfo);
    return true;
}
}

bool PatchProfile::DefaultNativeSo(
    const PatchExtractor &patchExtractor, bool isSystemLib64Exist, AppqfInfo &appqfInfo)
{
    if (isSystemLib64Exist) {
        if (patchExtractor.IsDirExist(ServiceConstants::LIBS + ServiceConstants::ARM64_V8A)) {
            appqfInfo.cpuAbi = ServiceConstants::ARM64_V8A;
            auto iter = ServiceConstants::ABI_MAP.find(ServiceConstants::ARM64_V8A);
            if (iter != ServiceConstants::ABI_MAP.end()) {
                appqfInfo.nativeLibraryPath = ServiceConstants::LIBS + iter->second;
                return true;
            }
            LOG_E(BMS_TAG_DEFAULT, "Can't find ARM64_V8A in ABI_MAP");
            return false;
        }
        LOG_E(BMS_TAG_DEFAULT, " ARM64_V8A's directory doesn't exist");
        return false;
    }

    if (patchExtractor.IsDirExist(ServiceConstants::LIBS + ServiceConstants::ARM_EABI_V7A)) {
        appqfInfo.cpuAbi = ServiceConstants::ARM_EABI_V7A;
        auto iter = ServiceConstants::ABI_MAP.find(ServiceConstants::ARM_EABI_V7A);
        if (iter != ServiceConstants::ABI_MAP.end()) {
            appqfInfo.nativeLibraryPath = ServiceConstants::LIBS + iter->second;
            return true;
        }
        LOG_E(BMS_TAG_DEFAULT, "Can't find ARM_EABI_V7A in ABI_MAP");
        return false;
    }

    if (patchExtractor.IsDirExist(ServiceConstants::LIBS + ServiceConstants::ARM_EABI)) {
        appqfInfo.cpuAbi = ServiceConstants::ARM_EABI;
        auto iter = ServiceConstants::ABI_MAP.find(ServiceConstants::ARM_EABI);
        if (iter != ServiceConstants::ABI_MAP.end()) {
            appqfInfo.nativeLibraryPath = ServiceConstants::LIBS + iter->second;
            return true;
        }
        LOG_E(BMS_TAG_DEFAULT, "Can't find ARM_EABI in ABI_MAP");
        return false;
    }
    LOG_E(BMS_TAG_DEFAULT, "ARM_EABI_V7A and ARM_EABI directories do not exist");
    return false;
}

bool PatchProfile::ParseNativeSo(const PatchExtractor &patchExtractor, AppqfInfo &appqfInfo)
{
    std::string abis = GetAbiList();
    std::vector<std::string> abiList;
    SplitStr(abis, ServiceConstants::ABI_SEPARATOR, abiList, false, false);
    if (abiList.empty()) {
        LOG_E(BMS_TAG_DEFAULT, "Abi is empty");
        return false;
    }
    bool isDefault = std::find(abiList.begin(), abiList.end(), ServiceConstants::ABI_DEFAULT) != abiList.end();
    bool isSystemLib64Exist = BundleUtil::IsExistDir(ServiceConstants::SYSTEM_LIB64);
    LOG_D(BMS_TAG_DEFAULT, "abi list : %{public}s, isDefault : %{public}d, isSystemLib64Exist : %{public}d",
        abis.c_str(), isDefault, isSystemLib64Exist);
    bool soExist = patchExtractor.IsDirExist(ServiceConstants::LIBS);
    if (!soExist) {
        LOG_D(BMS_TAG_DEFAULT, "so not exist");
        if (isDefault) {
            appqfInfo.cpuAbi = isSystemLib64Exist ? ServiceConstants::ARM64_V8A : ServiceConstants::ARM_EABI_V7A;
            return true;
        }
        for (const auto &abi : abiList) {
            if (ServiceConstants::ABI_MAP.find(abi) != ServiceConstants::ABI_MAP.end()) {
                appqfInfo.cpuAbi = abi;
                return true;
            }
        }
        LOG_E(BMS_TAG_DEFAULT, "None of the abiList are in the ABI_MAP");
        return false;
    }

    LOG_D(BMS_TAG_DEFAULT, "so exist");
    if (isDefault) {
        return DefaultNativeSo(patchExtractor, isSystemLib64Exist, appqfInfo);
    }
    for (const auto &abi : abiList) {
        std::string libsPath;
        libsPath.append(ServiceConstants::LIBS).append(abi).append(ServiceConstants::PATH_SEPARATOR);
        if (ServiceConstants::ABI_MAP.find(abi) != ServiceConstants::ABI_MAP.end() &&
            patchExtractor.IsDirExist(libsPath)) {
            appqfInfo.cpuAbi = abi;
            auto iter = ServiceConstants::ABI_MAP.find(abi);
            if (iter != ServiceConstants::ABI_MAP.end()) {
                appqfInfo.nativeLibraryPath = ServiceConstants::LIBS + iter->second;
                return true;
            }
            LOG_E(BMS_TAG_DEFAULT, "Can't find %{public}s in ABI_MAP", abi.c_str());
            return false;
        }
    }
    return false;
}

ErrCode PatchProfile::TransformTo(
    const std::ostringstream &source, const PatchExtractor &patchExtractor, AppQuickFix &appQuickFix)
{
    nlohmann::json jsonObject = nlohmann::json::parse(source.str(), nullptr, false);
    if (jsonObject.is_discarded()) {
        LOG_E(BMS_TAG_DEFAULT, "bad profile");
        return ERR_APPEXECFWK_PARSE_BAD_PROFILE;
    }
    PatchProfileReader::PatchJson patchJson;
    {
        std::lock_guard<std::mutex> lock(PatchProfileReader::g_mutex);
        PatchProfileReader::g_parseResult = ERR_OK;
        patchJson = jsonObject.get<PatchProfileReader::PatchJson>();
        if (PatchProfileReader::g_parseResult != ERR_OK) {
            LOG_E(BMS_TAG_DEFAULT, "g_parseResult is %{public}d", PatchProfileReader::g_parseResult);
            int32_t ret = PatchProfileReader::g_parseResult;
            PatchProfileReader::g_parseResult = ERR_OK;
            return ret;
        }
    }
    if (!PatchProfileReader::ToPatchInfo(patchJson, appQuickFix)) {
        LOG_E(BMS_TAG_DEFAULT, "bundle or module name is invalid");
        return ERR_APPEXECFWK_PARSE_PROFILE_PROP_CHECK_ERROR;
    }
    // hot reload does not process so files
    if ((appQuickFix.deployingAppqfInfo.type == QuickFixType::PATCH) &&
        (!ParseNativeSo(patchExtractor, appQuickFix.deployingAppqfInfo))) {
        LOG_E(BMS_TAG_DEFAULT, "ParseNativeSo failed");
        return ERR_APPEXECFWK_PARSE_NATIVE_SO_FAILED;
    }
    return ERR_OK;
}
}  // namespace AppExecFwk
}  // namespace OHOS