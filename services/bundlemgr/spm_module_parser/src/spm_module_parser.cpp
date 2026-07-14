/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "spm_module_parser.h"

#include "app_log_tag_wrapper.h"
#include "nlohmann/json.hpp"

namespace OHOS {
namespace AppExecFwk {
namespace Spm {

namespace {
// JSON key constants matching module.json schema
constexpr const char* KEY_APP = "app";
constexpr const char* KEY_MODULE = "module";
// app fields
constexpr const char* KEY_APP_BUNDLE_NAME = "bundleName";
constexpr const char* KEY_APP_BUNDLE_TYPE = "bundleType";
constexpr const char* KEY_APP_TARGET_API_VERSION = "targetAPIVersion";
constexpr const char* KEY_APP_API_VERSION = "apiVersion";
// module fields
constexpr const char* KEY_MODULE_NAME = "name";
constexpr const char* KEY_MODULE_PACKAGE = "package";
constexpr const char* KEY_MODULE_SKILL_PROFILES = "skillProfiles";
constexpr const char* KEY_MODULE_REQUEST_PERMISSIONS = "requestPermissions";
constexpr const char* KEY_MODULE_REQ_PERMISSIONS = "reqPermissions";
constexpr const char* KEY_MODULE_DEFINE_PERMISSIONS = "definePermissions";
// skillProfile fields
constexpr const char* KEY_SKILL_PROFILE_NAME = "name";
// requestPermission fields
constexpr const char* KEY_REQUEST_PERM_NAME = "name";
constexpr const char* KEY_REQUEST_PERM_REASON = "reason";
constexpr const char* KEY_REQUEST_PERM_REASON_ID = "reasonId";
constexpr const char* KEY_REQUEST_PERM_MODULE_NAME = "moduleName";
constexpr const char* KEY_REQUEST_PERM_REQUIRED_FEATURE = "requiredFeature";
// apiVersion fields
constexpr const char* KEY_API_VERSION_TARGET = "target";
// definePermission fields
constexpr const char* KEY_DEFINE_PERM_NAME = "name";
constexpr const char* KEY_DEFINE_PERM_GRANT_MODE = "grantMode";
constexpr const char* KEY_DEFINE_PERM_AVAILABLE_LEVEL = "availableLevel";
constexpr const char* KEY_DEFINE_PERM_PROVISION_ENABLE = "provisionEnable";
constexpr const char* KEY_DEFINE_PERM_DISTRIBUTED_SCENE_ENABLE = "distributedSceneEnable";
constexpr const char* KEY_DEFINE_PERM_KERNEL_EFFECT = "kernelEffect";
constexpr const char* KEY_DEFINE_PERM_HAS_VALUE = "hasValue";
constexpr const char* KEY_DEFINE_PERM_LABEL = "label";
constexpr const char* KEY_DEFINE_PERM_LABEL_ID = "labelId";
constexpr const char* KEY_DEFINE_PERM_DESCRIPTION = "description";
constexpr const char* KEY_DEFINE_PERM_DESCRIPTION_ID = "descriptionId";
constexpr const char* KEY_DEFINE_PERM_AVAILABLE_TYPE = "availableType";

// bundleType string constants
constexpr const char* BUNDLE_TYPE_ATOMIC_SERVICE = "atomicService";
constexpr const char* BUNDLE_TYPE_SHARED = "shared";
constexpr const char* BUNDLE_TYPE_APP_SERVICE_FWK = "appService";
constexpr const char* BUNDLE_TYPE_PLUGIN = "appPlugin";
constexpr const char* BUNDLE_TYPE_SKILL = "skill";

// --- lightweight JSON helpers (no dependency on BMSJsonUtil) ---

inline std::string GetJsonString(const nlohmann::json &obj, const char *key)
{
    auto it = obj.find(key);
    if (it != obj.end() && it->is_string()) {
        return it->get<std::string>();
    }
    return "";
}

inline int32_t GetJsonInt32(const nlohmann::json &obj, const char *key, int32_t defaultVal = 0)
{
    auto it = obj.find(key);
    if (it != obj.end() && it->is_number()) {
        return it->get<int32_t>();
    }
    return defaultVal;
}

inline uint32_t GetJsonUint32(const nlohmann::json &obj, const char *key, uint32_t defaultVal = 0)
{
    auto it = obj.find(key);
    if (it != obj.end() && it->is_number()) {
        return it->get<uint32_t>();
    }
    return defaultVal;
}

inline bool GetJsonBool(const nlohmann::json &obj, const char *key, bool defaultVal = false)
{
    auto it = obj.find(key);
    if (it != obj.end() && it->is_boolean()) {
        return it->get<bool>();
    }
    return defaultVal;
}

BundleType ConvertBundleType(const std::string &typeStr)
{
    if (typeStr == BUNDLE_TYPE_ATOMIC_SERVICE) {
        return BundleType::ATOMIC_SERVICE;
    }
    if (typeStr == BUNDLE_TYPE_SHARED) {
        return BundleType::SHARED;
    }
    if (typeStr == BUNDLE_TYPE_APP_SERVICE_FWK) {
        return BundleType::APP_SERVICE_FWK;
    }
    if (typeStr == BUNDLE_TYPE_PLUGIN) {
        return BundleType::APP_PLUGIN;
    }
    if (typeStr == BUNDLE_TYPE_SKILL) {
        return BundleType::SKILL;
    }
    // default and "app" both map to APP
    return BundleType::APP;
}

bool ParseDefinePermissions(const nlohmann::json &moduleObj, std::vector<DefinePermission> &outPermissions)
{
    auto it = moduleObj.find(KEY_MODULE_DEFINE_PERMISSIONS);
    if (it == moduleObj.end()) {
        return true; // optional field
    }
    if (!it->is_array()) {
        return false;
    }
    for (const auto &item : *it) {
        if (!item.is_object()) {
            continue;
        }
        DefinePermission perm;
        perm.name = GetJsonString(item, KEY_DEFINE_PERM_NAME);
        perm.grantMode = GetJsonString(item, KEY_DEFINE_PERM_GRANT_MODE);
        perm.availableLevel = GetJsonString(item, KEY_DEFINE_PERM_AVAILABLE_LEVEL);
        perm.label = GetJsonString(item, KEY_DEFINE_PERM_LABEL);
        perm.description = GetJsonString(item, KEY_DEFINE_PERM_DESCRIPTION);
        perm.availableType = GetJsonString(item, KEY_DEFINE_PERM_AVAILABLE_TYPE);
        perm.labelId = GetJsonUint32(item, KEY_DEFINE_PERM_LABEL_ID);
        perm.descriptionId = GetJsonUint32(item, KEY_DEFINE_PERM_DESCRIPTION_ID);
        perm.provisionEnable = GetJsonBool(item, KEY_DEFINE_PERM_PROVISION_ENABLE, true);
        perm.distributedSceneEnable = GetJsonBool(item, KEY_DEFINE_PERM_DISTRIBUTED_SCENE_ENABLE, false);
        perm.isKernelEffect = GetJsonBool(item, KEY_DEFINE_PERM_KERNEL_EFFECT, false);
        perm.hasValue = GetJsonBool(item, KEY_DEFINE_PERM_HAS_VALUE, false);
        outPermissions.emplace_back(std::move(perm));
    }
    return true;
}

bool ParseRequestPermissions(const nlohmann::json &moduleObj, std::vector<RequestPermission> &outPermissions)
{
    auto it = moduleObj.find(KEY_MODULE_REQUEST_PERMISSIONS);
    if (it == moduleObj.end()) {
        it = moduleObj.find(KEY_MODULE_REQ_PERMISSIONS);
        if (it == moduleObj.end()) {
            return true; // optional field
        }
    }
    if (!it->is_array()) {
        return false;
    }
    for (const auto &item : *it) {
        if (!item.is_object()) {
            continue;
        }
        RequestPermission perm;
        perm.name = GetJsonString(item, KEY_REQUEST_PERM_NAME);
        perm.reason = GetJsonString(item, KEY_REQUEST_PERM_REASON);
        perm.moduleName = GetJsonString(item, KEY_REQUEST_PERM_MODULE_NAME);
        perm.requiredFeature = GetJsonString(item, KEY_REQUEST_PERM_REQUIRED_FEATURE);
        perm.reasonId = GetJsonUint32(item, KEY_REQUEST_PERM_REASON_ID);
        outPermissions.emplace_back(std::move(perm));
    }
    return true;
}

bool ParseSkillNames(const nlohmann::json &moduleObj, std::vector<std::string> &outSkillNames)
{
    auto it = moduleObj.find(KEY_MODULE_SKILL_PROFILES);
    if (it == moduleObj.end()) {
        return true; // optional field
    }
    if (!it->is_array()) {
        return false;
    }
    for (const auto &item : *it) {
        if (!item.is_object()) {
            continue;
        }
        std::string name = GetJsonString(item, KEY_SKILL_PROFILE_NAME);
        if (!name.empty()) {
            outSkillNames.emplace_back(std::move(name));
        }
    }
    return true;
}

bool ParseApiTargetVersion(const nlohmann::json &appObj, int32_t &apiTargetVersion)
{
    // Stage model
    auto it = appObj.find(KEY_APP_TARGET_API_VERSION);
    if (it != appObj.end()) {
        apiTargetVersion = GetJsonInt32(appObj, KEY_APP_TARGET_API_VERSION);
        return true;
    }
    // FA model
    auto apiIt = appObj.find(KEY_APP_API_VERSION);
    if (apiIt == appObj.end()) {
        return true; // optional field, no version info
    }
    if (apiIt->is_object()) {
        apiTargetVersion = GetJsonInt32(*apiIt, KEY_API_VERSION_TARGET);
    }
    return true;
}
} // anonymous namespace

bool ParseSpmModule(const std::string &moduleJson, InnerModuleInfoForSpm &moduleInfo)
{
    if (moduleJson.empty()) {
        LOG_NOFUNC_E(BMS_TAG_DEFAULT, "parse module json failed, input is empty");
        return false;
    }

    nlohmann::json jsonObject = nlohmann::json::parse(moduleJson, nullptr, false, true);
    if (jsonObject.is_discarded() || !jsonObject.is_object()) {
        LOG_NOFUNC_E(BMS_TAG_DEFAULT, "parse module json failed, invalid json format");
        return false;
    }

    // Parse app section
    auto appIt = jsonObject.find(KEY_APP);
    if (appIt == jsonObject.end() || !appIt->is_object()) {
        LOG_NOFUNC_E(BMS_TAG_DEFAULT, "parse module json failed, app section missing or invalid");
        return false;
    }
    const auto &appObj = *appIt;

    // bundleName (required)
    moduleInfo.bundleName = GetJsonString(appObj, KEY_APP_BUNDLE_NAME);
    if (moduleInfo.bundleName.empty()) {
        LOG_NOFUNC_E(BMS_TAG_DEFAULT, "parse module json failed, bundleName is empty");
        return false;
    }

    // bundleType (optional, defaults to APP)
    std::string bundleTypeStr = GetJsonString(appObj, KEY_APP_BUNDLE_TYPE);
    moduleInfo.bundleType = ConvertBundleType(bundleTypeStr);

    // targetAPIVersion (optional)
    (void)ParseApiTargetVersion(appObj, moduleInfo.apiTargetVersion);

    // Parse module section
    auto moduleIt = jsonObject.find(KEY_MODULE);
    if (moduleIt == jsonObject.end() || !moduleIt->is_object()) {
        LOG_NOFUNC_E(BMS_TAG_DEFAULT, "parse module json failed, module section missing or invalid");
        return false;
    }
    const auto &moduleObj = *moduleIt;

    // moduleName (required) - support both Stage model (name) and FA model (package)
    // Stage model: use "name" directly
    // FA model: use "package"; when name starts with ".", concatenate package + name
    std::string moduleName = GetJsonString(moduleObj, KEY_MODULE_NAME);
    if (moduleName.empty()) {
        moduleInfo.moduleName = GetJsonString(moduleObj, KEY_MODULE_PACKAGE);
    } else {
        if (moduleName.substr(0, 1) == ".") {
            std::string package = GetJsonString(moduleObj, KEY_MODULE_PACKAGE);
            moduleInfo.moduleName = package + moduleName;
        } else {
            moduleInfo.moduleName = moduleName;
        }
    }
    if (moduleInfo.moduleName.empty()) {
        LOG_NOFUNC_E(BMS_TAG_DEFAULT, "parse module json failed, moduleName is empty");
        return false;
    }

    // skillProfiles -> skillName (optional)
    if (!ParseSkillNames(moduleObj, moduleInfo.skillName)) {
        LOG_NOFUNC_E(BMS_TAG_DEFAULT, "parse module json failed, skillProfiles is invalid");
        return false;
    }

    // requestPermissions (optional)
    if (!ParseRequestPermissions(moduleObj, moduleInfo.requestPermission)) {
        LOG_NOFUNC_E(BMS_TAG_DEFAULT, "parse module json failed, requestPermissions is invalid");
        return false;
    }

    // definePermissions (optional)
    if (!ParseDefinePermissions(moduleObj, moduleInfo.definePermission)) {
        LOG_NOFUNC_E(BMS_TAG_DEFAULT, "parse module json failed, definePermissions is invalid");
        return false;
    }

    return true;
}

}  // namespace Spm
}  // namespace AppExecFwk
}  // namespace OHOS
