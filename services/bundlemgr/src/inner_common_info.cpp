/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "inner_common_info.h"

#include <regex>
#include <unistd.h>
#include "string_ex.h"

#include "mime_type_mgr.h"
#include "parameters.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const std::string NAME = "name";
const std::string MODULE_PACKAGE = "modulePackage";
const std::string MODULE_PATH = "modulePath";
const std::string MODULE_NAME = "moduleName";
const std::string MODULE_DESCRIPTION = "description";
const std::string MODULE_DESCRIPTION_ID = "descriptionId";
const std::string MODULE_ICON = "icon";
const std::string MODULE_ICON_ID = "iconId";
const std::string MODULE_LABEL = "label";
const std::string MODULE_LABEL_ID = "labelId";
const std::string MODULE_DESCRIPTION_INSTALLATION_FREE = "installationFree";
const std::string MODULE_IS_REMOVABLE = "isRemovable";
const std::string MODULE_UPGRADE_FLAG = "upgradeFlag";
const std::string MODULE_IS_ENTRY = "isEntry";
const std::string MODULE_METADATA = "metaData";
const std::string MODULE_COLOR_MODE = "colorMode";
const std::string MODULE_DISTRO = "distro";
const std::string MODULE_REQ_CAPABILITIES = "reqCapabilities";
const std::string MODULE_DATA_DIR = "moduleDataDir";
const std::string MODULE_RES_PATH = "moduleResPath";
const std::string MODULE_HAP_PATH = "hapPath";
const std::string MODULE_ABILITY_KEYS = "abilityKeys";
const std::string MODULE_SKILL_KEYS = "skillKeys";
const std::string MODULE_MAIN_ABILITY = "mainAbility";
const std::string MODULE_ENTRY_ABILITY_KEY = "entryAbilityKey";
const std::string MODULE_DEPENDENCIES = "dependencies";
const std::string MODULE_IS_LIB_ISOLATED = "isLibIsolated";
const std::string MODULE_NATIVE_LIBRARY_PATH = "nativeLibraryPath";
const std::string MODULE_CPU_ABI = "cpuAbi";
const std::string MODULE_SRC_PATH = "srcPath";
const std::string MODULE_HASH_VALUE = "hashValue";
const std::string PARAM_SEPARATOR = "?";
const std::string INSTALL_MARK = "installMark";
const std::string MODULE_PROCESS = "process";
const std::string MODULE_SRC_ENTRANCE = "srcEntrance";
const std::string MODULE_DEVICE_TYPES = "deviceTypes";
const std::string MODULE_VIRTUAL_MACHINE = "virtualMachine";
const std::string MODULE_UI_SYNTAX = "uiSyntax";
const std::string MODULE_PAGES = "pages";
const std::string MODULE_META_DATA = "metadata";
const std::string MODULE_HNP_PACKAGE = "hnpPackage";
const std::string MODULE_REQUEST_PERMISSIONS = "requestPermissions";
const std::string MODULE_DEFINE_PERMISSIONS = "definePermissions";
const std::string MODULE_EXTENSION_KEYS = "extensionKeys";
const std::string MODULE_EXTENSION_SKILL_KEYS = "extensionSkillKeys";
const std::string MODULE_IS_MODULE_JSON = "isModuleJson";
const std::string MODULE_IS_STAGE_BASED_MODEL = "isStageBasedModel";
const std::string MODULE_COMPILE_MODE = "compileMode";
const std::string MODULE_TARGET_MODULE_NAME = "targetModuleName";
const std::string MODULE_TARGET_PRIORITY = "targetPriority";
const std::string MODULE_OVERLAY_MODULE_INFO = "overlayModuleInfo";
const std::string MODULE_PRELOADS = "preloads";
const std::string MODULE_BUNDLE_TYPE = "bundleType";
const std::string MODULE_VERSION_CODE = "versionCode";
const std::string MODULE_VERSION_NAME = "versionName";
const std::string MODULE_PROXY_DATAS = "proxyDatas";
const std::string MODULE_BUILD_HASH = "buildHash";
const std::string MODULE_ISOLATION_MODE = "isolationMode";
const std::string MODULE_COMPRESS_NATIVE_LIBS = "compressNativeLibs";
const std::string MODULE_NATIVE_LIBRARY_FILE_NAMES = "nativeLibraryFileNames";
const std::string MODULE_AOT_COMPILE_STATUS = "aotCompileStatus";
const std::string MODULE_FILE_CONTEXT_MENU = "fileContextMenu";
const std::string MODULE_IS_ENCRYPTED = "isEncrypted";
const std::string MODULE_ROUTER_MAP = "routerMap";
const std::string STR_PHONE = "phone";
const std::string STR_DEFAULT = "default";
const std::string MODULE_QUERY_SCHEMES = "querySchemes";
const std::string MODULE_APP_ENVIRONMENTS = "appEnvironments";
const std::string MODULE_ASAN_ENABLED = "asanEnabled";
const std::string MODULE_GWP_ASAN_ENABLED = "gwpAsanEnabled";
const std::string MODULE_PACKAGE_NAME = "packageName";
const std::string MODULE_APP_STARTUP = "appStartup";
}  // namespace

void to_json(nlohmann::json &jsonObject, const Distro &distro)
{
    jsonObject = nlohmann::json {
            {ProfileReader::BUNDLE_MODULE_PROFILE_KEY_DELIVERY_WITH_INSTALL, distro.deliveryWithInstall},
            {ProfileReader::BUNDLE_MODULE_PROFILE_KEY_MODULE_NAME, distro.moduleName},
            {ProfileReader::BUNDLE_MODULE_PROFILE_KEY_MODULE_TYPE, distro.moduleType},
            {ProfileReader::BUNDLE_MODULE_PROFILE_KEY_MODULE_INSTALLATION_FREE, distro.installationFree}
    };
}

void to_json(nlohmann::json &jsonObject, const DefinePermission &definePermission)
{
    jsonObject = nlohmann::json {
        {Profile::DEFINEPERMISSION_NAME, definePermission.name},
        {Profile::DEFINEPERMISSION_GRANT_MODE, definePermission.grantMode},
        {Profile::DEFINEPERMISSION_AVAILABLE_LEVEL, definePermission.availableLevel},
        {Profile::DEFINEPERMISSION_PROVISION_ENABLE, definePermission.provisionEnable},
        {Profile::DEFINEPERMISSION_DISTRIBUTED_SCENE_ENABLE, definePermission.distributedSceneEnable},
        {Profile::LABEL, definePermission.label},
        {Profile::LABEL_ID, definePermission.labelId},
        {Profile::DESCRIPTION, definePermission.description},
        {Profile::DESCRIPTION_ID, definePermission.descriptionId},
        {Profile::DEFINEPERMISSION_AVAILABLE_TYPE, definePermission.availableType}
    };
}

void to_json(nlohmann::json &jsonObject, const Dependency &dependency)
{
    jsonObject = nlohmann::json {
        {Profile::DEPENDENCIES_MODULE_NAME, dependency.moduleName},
        {Profile::DEPENDENCIES_BUNDLE_NAME, dependency.bundleName},
        {Profile::APP_VERSION_CODE, dependency.versionCode}
    };
}

void to_json(nlohmann::json &jsonObject, const InnerModuleInfo &info)
{
    jsonObject = nlohmann::json {
        {NAME, info.name},
        {MODULE_PACKAGE, info.modulePackage},
        {MODULE_NAME, info.moduleName},
        {MODULE_PATH, info.modulePath},
        {MODULE_DATA_DIR, info.moduleDataDir},
        {MODULE_RES_PATH, info.moduleResPath},
        {MODULE_IS_ENTRY, info.isEntry},
        {MODULE_METADATA, info.metaData},
        {MODULE_COLOR_MODE, info.colorMode},
        {MODULE_DISTRO, info.distro},
        {MODULE_DESCRIPTION, info.description},
        {MODULE_DESCRIPTION_ID, info.descriptionId},
        {MODULE_ICON, info.icon},
        {MODULE_ICON_ID, info.iconId},
        {MODULE_LABEL, info.label},
        {MODULE_LABEL_ID, info.labelId},
        {MODULE_DESCRIPTION_INSTALLATION_FREE, info.installationFree},
        {MODULE_IS_REMOVABLE, info.isRemovable},
        {MODULE_UPGRADE_FLAG, info.upgradeFlag},
        {MODULE_REQ_CAPABILITIES, info.reqCapabilities},
        {MODULE_ABILITY_KEYS, info.abilityKeys},
        {MODULE_SKILL_KEYS, info.skillKeys},
        {MODULE_MAIN_ABILITY, info.mainAbility},
        {MODULE_ENTRY_ABILITY_KEY, info.entryAbilityKey},
        {MODULE_SRC_PATH, info.srcPath},
        {MODULE_HASH_VALUE, info.hashValue},
        {MODULE_PROCESS, info.process},
        {MODULE_SRC_ENTRANCE, info.srcEntrance},
        {MODULE_DEVICE_TYPES, info.deviceTypes},
        {MODULE_VIRTUAL_MACHINE, info.virtualMachine},
        {MODULE_UI_SYNTAX, info.uiSyntax},
        {MODULE_PAGES, info.pages},
        {MODULE_META_DATA, info.metadata},
        {MODULE_HNP_PACKAGE, info.hnpPackages},
        {MODULE_REQUEST_PERMISSIONS, info.requestPermissions},
        {MODULE_DEFINE_PERMISSIONS, info.definePermissions},
        {MODULE_EXTENSION_KEYS, info.extensionKeys},
        {MODULE_EXTENSION_SKILL_KEYS, info.extensionSkillKeys},
        {MODULE_IS_MODULE_JSON, info.isModuleJson},
        {MODULE_IS_STAGE_BASED_MODEL, info.isStageBasedModel},
        {MODULE_DEPENDENCIES, info.dependencies},
        {MODULE_IS_LIB_ISOLATED, info.isLibIsolated},
        {MODULE_NATIVE_LIBRARY_PATH, info.nativeLibraryPath},
        {MODULE_CPU_ABI, info.cpuAbi},
        {MODULE_HAP_PATH, info.hapPath},
        {MODULE_COMPILE_MODE, info.compileMode},
        {MODULE_TARGET_MODULE_NAME, info.targetModuleName},
        {MODULE_TARGET_PRIORITY, info.targetPriority},
        {MODULE_OVERLAY_MODULE_INFO, info.overlayModuleInfo},
        {MODULE_PRELOADS, info.preloads},
        {MODULE_BUNDLE_TYPE, info.bundleType},
        {MODULE_VERSION_CODE, info.versionCode},
        {MODULE_VERSION_NAME, info.versionName},
        {MODULE_PROXY_DATAS, info.proxyDatas},
        {MODULE_BUILD_HASH, info.buildHash},
        {MODULE_ISOLATION_MODE, info.isolationMode},
        {MODULE_COMPRESS_NATIVE_LIBS, info.compressNativeLibs},
        {MODULE_NATIVE_LIBRARY_FILE_NAMES, info.nativeLibraryFileNames},
        {MODULE_AOT_COMPILE_STATUS, info.aotCompileStatus},
        {MODULE_FILE_CONTEXT_MENU, info.fileContextMenu},
        {MODULE_IS_ENCRYPTED, info.isEncrypted},
        {MODULE_QUERY_SCHEMES, info.querySchemes},
        {MODULE_ROUTER_MAP, info.routerMap},
        {MODULE_APP_ENVIRONMENTS, info.appEnvironments},
        {MODULE_ASAN_ENABLED, info.asanEnabled},
        {MODULE_GWP_ASAN_ENABLED, info.gwpAsanEnabled},
        {MODULE_PACKAGE_NAME, info.packageName},
        {MODULE_APP_STARTUP, info.appStartup},
    };
}

void to_json(nlohmann::json &jsonObject, const InstallMark &installMark)
{
    jsonObject = nlohmann::json {
        {ProfileReader::BUNDLE_INSTALL_MARK_BUNDLE, installMark.bundleName},
        {ProfileReader::BUNDLE_INSTALL_MARK_PACKAGE, installMark.packageName},
        {ProfileReader::BUNDLE_INSTALL_MARK_STATUS, installMark.status}
    };
}

void from_json(const nlohmann::json &jsonObject, InnerModuleInfo &info)
{
    // these are not required fields.
    const auto &jsonObjectEnd = jsonObject.end();
    int32_t parseResult = ERR_OK;
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        NAME,
        info.name,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        MODULE_PACKAGE,
        info.modulePackage,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        MODULE_NAME,
        info.moduleName,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        MODULE_PATH,
        info.modulePath,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        MODULE_DATA_DIR,
        info.moduleDataDir,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        MODULE_HAP_PATH,
        info.hapPath,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        MODULE_RES_PATH,
        info.moduleResPath,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<bool>(jsonObject,
        jsonObjectEnd,
        MODULE_IS_ENTRY,
        info.isEntry,
        JsonType::BOOLEAN,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<MetaData>(jsonObject,
        jsonObjectEnd,
        MODULE_METADATA,
        info.metaData,
        JsonType::OBJECT,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<ModuleColorMode>(jsonObject,
        jsonObjectEnd,
        MODULE_COLOR_MODE,
        info.colorMode,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<Distro>(jsonObject,
        jsonObjectEnd,
        MODULE_DISTRO,
        info.distro,
        JsonType::OBJECT,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        MODULE_DESCRIPTION,
        info.description,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<int32_t>(jsonObject,
        jsonObjectEnd,
        MODULE_DESCRIPTION_ID,
        info.descriptionId,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        MODULE_ICON,
        info.icon,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<int32_t>(jsonObject,
        jsonObjectEnd,
        MODULE_ICON_ID,
        info.iconId,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        MODULE_LABEL,
        info.label,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<int32_t>(jsonObject,
        jsonObjectEnd,
        MODULE_LABEL_ID,
        info.labelId,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        MODULE_MAIN_ABILITY,
        info.mainAbility,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        MODULE_ENTRY_ABILITY_KEY,
        info.entryAbilityKey,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        MODULE_SRC_PATH,
        info.srcPath,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        MODULE_HASH_VALUE,
        info.hashValue,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<bool>(jsonObject,
        jsonObjectEnd,
        MODULE_DESCRIPTION_INSTALLATION_FREE,
        info.installationFree,
        JsonType::BOOLEAN,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::map<std::string, bool>>(jsonObject,
        jsonObjectEnd,
        MODULE_IS_REMOVABLE,
        info.isRemovable,
        JsonType::OBJECT,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<int32_t>(jsonObject,
        jsonObjectEnd,
        MODULE_UPGRADE_FLAG,
        info.upgradeFlag,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::vector<std::string>>(jsonObject,
        jsonObjectEnd,
        MODULE_REQ_CAPABILITIES,
        info.reqCapabilities,
        JsonType::ARRAY,
        false,
        parseResult,
        ArrayType::STRING);
    GetValueIfFindKey<std::vector<std::string>>(jsonObject,
        jsonObjectEnd,
        MODULE_ABILITY_KEYS,
        info.abilityKeys,
        JsonType::ARRAY,
        false,
        parseResult,
        ArrayType::STRING);
    GetValueIfFindKey<std::vector<std::string>>(jsonObject,
        jsonObjectEnd,
        MODULE_SKILL_KEYS,
        info.skillKeys,
        JsonType::ARRAY,
        false,
        parseResult,
        ArrayType::STRING);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        MODULE_PROCESS,
        info.process,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        MODULE_SRC_ENTRANCE,
        info.srcEntrance,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::vector<std::string>>(jsonObject,
        jsonObjectEnd,
        MODULE_DEVICE_TYPES,
        info.deviceTypes,
        JsonType::ARRAY,
        false,
        parseResult,
        ArrayType::STRING);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        MODULE_VIRTUAL_MACHINE,
        info.virtualMachine,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        MODULE_UI_SYNTAX,
        info.uiSyntax,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        MODULE_PAGES,
        info.pages,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::vector<Metadata>>(jsonObject,
        jsonObjectEnd,
        MODULE_META_DATA,
        info.metadata,
        JsonType::ARRAY,
        false,
        parseResult,
        ArrayType::OBJECT);
    GetValueIfFindKey<std::vector<HnpPackage>>(jsonObject,
        jsonObjectEnd,
        MODULE_HNP_PACKAGE,
        info.hnpPackages,
        JsonType::ARRAY,
        false,
        parseResult,
        ArrayType::OBJECT);
    GetValueIfFindKey<std::vector<RequestPermission>>(jsonObject,
        jsonObjectEnd,
        MODULE_REQUEST_PERMISSIONS,
        info.requestPermissions,
        JsonType::ARRAY,
        false,
        parseResult,
        ArrayType::OBJECT);
    GetValueIfFindKey<std::vector<DefinePermission>>(jsonObject,
        jsonObjectEnd,
        MODULE_DEFINE_PERMISSIONS,
        info.definePermissions,
        JsonType::ARRAY,
        false,
        parseResult,
        ArrayType::OBJECT);
    GetValueIfFindKey<std::vector<std::string>>(jsonObject,
        jsonObjectEnd,
        MODULE_EXTENSION_KEYS,
        info.extensionKeys,
        JsonType::ARRAY,
        false,
        parseResult,
        ArrayType::STRING);
    GetValueIfFindKey<std::vector<std::string>>(jsonObject,
        jsonObjectEnd,
        MODULE_EXTENSION_SKILL_KEYS,
        info.extensionSkillKeys,
        JsonType::ARRAY,
        false,
        parseResult,
        ArrayType::STRING);
    GetValueIfFindKey<bool>(jsonObject,
        jsonObjectEnd,
        MODULE_IS_MODULE_JSON,
        info.isModuleJson,
        JsonType::BOOLEAN,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<bool>(jsonObject,
        jsonObjectEnd,
        MODULE_IS_STAGE_BASED_MODEL,
        info.isStageBasedModel,
        JsonType::BOOLEAN,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::vector<Dependency>>(jsonObject,
        jsonObjectEnd,
        MODULE_DEPENDENCIES,
        info.dependencies,
        JsonType::ARRAY,
        false,
        parseResult,
        ArrayType::OBJECT);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        MODULE_COMPILE_MODE,
        info.compileMode,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<bool>(jsonObject,
        jsonObjectEnd,
        MODULE_IS_LIB_ISOLATED,
        info.isLibIsolated,
        JsonType::BOOLEAN,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        MODULE_NATIVE_LIBRARY_PATH,
        info.nativeLibraryPath,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        MODULE_CPU_ABI,
        info.cpuAbi,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        MODULE_TARGET_MODULE_NAME,
        info.targetModuleName,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<int32_t>(jsonObject,
        jsonObjectEnd,
        MODULE_TARGET_PRIORITY,
        info.targetPriority,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::vector<OverlayModuleInfo>>(jsonObject,
        jsonObjectEnd,
        MODULE_OVERLAY_MODULE_INFO,
        info.overlayModuleInfo,
        JsonType::ARRAY,
        false,
        parseResult,
        ArrayType::OBJECT);
    GetValueIfFindKey<std::vector<std::string>>(jsonObject,
        jsonObjectEnd,
        MODULE_PRELOADS,
        info.preloads,
        JsonType::ARRAY,
        false,
        parseResult,
        ArrayType::STRING);
    GetValueIfFindKey<BundleType>(jsonObject,
        jsonObjectEnd,
        MODULE_BUNDLE_TYPE,
        info.bundleType,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<uint32_t>(jsonObject,
        jsonObjectEnd,
        MODULE_VERSION_CODE,
        info.versionCode,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        MODULE_VERSION_NAME,
        info.versionName,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::vector<ProxyData>>(jsonObject,
        jsonObjectEnd,
        MODULE_PROXY_DATAS,
        info.proxyDatas,
        JsonType::ARRAY,
        false,
        parseResult,
        ArrayType::OBJECT);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        MODULE_BUILD_HASH,
        info.buildHash,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        MODULE_ISOLATION_MODE,
        info.isolationMode,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<bool>(jsonObject,
        jsonObjectEnd,
        MODULE_COMPRESS_NATIVE_LIBS,
        info.compressNativeLibs,
        JsonType::BOOLEAN,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::vector<std::string>>(jsonObject,
        jsonObjectEnd,
        MODULE_NATIVE_LIBRARY_FILE_NAMES,
        info.nativeLibraryFileNames,
        JsonType::ARRAY,
        false,
        parseResult,
        ArrayType::STRING);
    GetValueIfFindKey<AOTCompileStatus>(jsonObject,
        jsonObjectEnd,
        MODULE_AOT_COMPILE_STATUS,
        info.aotCompileStatus,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        MODULE_FILE_CONTEXT_MENU,
        info.fileContextMenu,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<bool>(jsonObject,
        jsonObjectEnd,
        MODULE_IS_ENCRYPTED,
        info.isEncrypted,
        JsonType::BOOLEAN,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::vector<std::string>>(jsonObject,
        jsonObjectEnd,
        MODULE_QUERY_SCHEMES,
        info.querySchemes,
        JsonType::ARRAY,
        false,
        parseResult,
        ArrayType::STRING);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        MODULE_ROUTER_MAP,
        info.routerMap,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::vector<AppEnvironment>>(jsonObject,
        jsonObjectEnd,
        MODULE_APP_ENVIRONMENTS,
        info.appEnvironments,
        JsonType::ARRAY,
        false,
        parseResult,
        ArrayType::OBJECT);
    GetValueIfFindKey<bool>(jsonObject,
        jsonObjectEnd,
        MODULE_ASAN_ENABLED,
        info.asanEnabled,
        JsonType::BOOLEAN,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<bool>(jsonObject,
        jsonObjectEnd,
        MODULE_GWP_ASAN_ENABLED,
        info.gwpAsanEnabled,
        JsonType::BOOLEAN,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        MODULE_PACKAGE_NAME,
        info.packageName,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        MODULE_APP_STARTUP,
        info.appStartup,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    if (parseResult != ERR_OK) {
        APP_LOGE("read InnerModuleInfo from database error code : %{public}d", parseResult);
    }
}

void from_json(const nlohmann::json &jsonObject, Distro &distro)
{
    const auto &jsonObjectEnd = jsonObject.end();
    int32_t parseResult = ERR_OK;
    GetValueIfFindKey<bool>(jsonObject,
        jsonObjectEnd,
        ProfileReader::BUNDLE_MODULE_PROFILE_KEY_DELIVERY_WITH_INSTALL,
        distro.deliveryWithInstall,
        JsonType::BOOLEAN,
        true,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        ProfileReader::BUNDLE_MODULE_PROFILE_KEY_MODULE_NAME,
        distro.moduleName,
        JsonType::STRING,
        true,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        ProfileReader::BUNDLE_MODULE_PROFILE_KEY_MODULE_TYPE,
        distro.moduleType,
        JsonType::STRING,
        true,
        parseResult,
        ArrayType::NOT_ARRAY);
    // mustFlag decide by distro.moduleType
    GetValueIfFindKey<bool>(jsonObject,
        jsonObjectEnd,
        ProfileReader::BUNDLE_MODULE_PROFILE_KEY_MODULE_INSTALLATION_FREE,
        distro.installationFree,
        JsonType::BOOLEAN,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    if (parseResult != ERR_OK) {
        APP_LOGE("Distro from_json error code : %{public}d", parseResult);
    }
}

void from_json(const nlohmann::json &jsonObject, InstallMark &installMark)
{
    const auto &jsonObjectEnd = jsonObject.end();
    int32_t parseResult = ERR_OK;
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        ProfileReader::BUNDLE_INSTALL_MARK_BUNDLE,
        installMark.bundleName,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        ProfileReader::BUNDLE_INSTALL_MARK_PACKAGE,
        installMark.packageName,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<int32_t>(jsonObject,
        jsonObjectEnd,
        ProfileReader::BUNDLE_INSTALL_MARK_STATUS,
        installMark.status,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    if (parseResult != ERR_OK) {
        APP_LOGE("InstallMark from_json error code : %{public}d", parseResult);
    }
}

void from_json(const nlohmann::json &jsonObject, DefinePermission &definePermission)
{
    const auto &jsonObjectEnd = jsonObject.end();
    int32_t parseResult = ERR_OK;
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        Profile::DEFINEPERMISSION_NAME,
        definePermission.name,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        Profile::DEFINEPERMISSION_GRANT_MODE,
        definePermission.grantMode,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        Profile::DEFINEPERMISSION_AVAILABLE_LEVEL,
        definePermission.availableLevel,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<bool>(jsonObject,
        jsonObjectEnd,
        Profile::DEFINEPERMISSION_PROVISION_ENABLE,
        definePermission.provisionEnable,
        JsonType::BOOLEAN,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<bool>(jsonObject,
        jsonObjectEnd,
        Profile::DEFINEPERMISSION_DISTRIBUTED_SCENE_ENABLE,
        definePermission.distributedSceneEnable,
        JsonType::BOOLEAN,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        Profile::LABEL,
        definePermission.label,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<int32_t>(jsonObject,
        jsonObjectEnd,
        Profile::LABEL_ID,
        definePermission.labelId,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        Profile::DESCRIPTION,
        definePermission.description,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<int32_t>(jsonObject,
        jsonObjectEnd,
        Profile::DESCRIPTION_ID,
        definePermission.descriptionId,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        Profile::DEFINEPERMISSION_AVAILABLE_TYPE,
        definePermission.availableType,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    if (parseResult != ERR_OK) {
        APP_LOGE("DefinePermission from_json error code : %{public}d", parseResult);
    }
}

void from_json(const nlohmann::json &jsonObject, Dependency &dependency)
{
    const auto &jsonObjectEnd = jsonObject.end();
    int32_t parseResult = ERR_OK;
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        Profile::DEPENDENCIES_MODULE_NAME,
        dependency.moduleName,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        Profile::DEPENDENCIES_BUNDLE_NAME,
        dependency.bundleName,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<int>(jsonObject,
        jsonObjectEnd,
        Profile::APP_VERSION_CODE,
        dependency.versionCode,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    if (parseResult != ERR_OK) {
        APP_LOGE("Dependency from_json error code : %{public}d", parseResult);
    }
}
}  // namespace AppExecFwk
}  // namespace OHOS
