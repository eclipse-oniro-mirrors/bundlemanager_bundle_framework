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

#include "inner_bundle_info.h"

#include <regex>

#ifdef BUNDLE_FRAMEWORK_APP_CONTROL
#include "app_control_constants.h"
#include "app_control_manager.h"
#endif
#include "app_log_tag_wrapper.h"
#include "bms_extension_data_mgr.h"
#include "bundle_mgr_client.h"
#include "bundle_permission_mgr.h"
#include "bundle_util.h"
#include "free_install_params.h"
#include "installd_client.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr const char* APP_TYPE = "appType";
constexpr const char* BUNDLE_STATUS = "bundleStatus";
constexpr const char* BASE_APPLICATION_INFO = "baseApplicationInfo";
constexpr const char* BASE_BUNDLE_INFO = "baseBundleInfo";
constexpr const char* BASE_ABILITY_INFO = "baseAbilityInfos";
constexpr const char* INNER_MODULE_INFO = "innerModuleInfos";
constexpr const char* SKILL_INFOS = "skillInfos";
constexpr const char* USER_ID = "userId_";
constexpr const char* APP_FEATURE = "appFeature";
constexpr const char* NAME = "name";
constexpr const char* MODULE_PACKAGE = "modulePackage";
constexpr const char* MODULE_PATH = "modulePath";
constexpr const char* MODULE_NAME = "moduleName";
constexpr const char* MODULE_DESCRIPTION = "description";
constexpr const char* MODULE_DESCRIPTION_ID = "descriptionId";
constexpr const char* MODULE_ICON = "icon";
constexpr const char* MODULE_ICON_ID = "iconId";
constexpr const char* MODULE_LABEL = "label";
constexpr const char* MODULE_LABEL_ID = "labelId";
constexpr const char* MODULE_DESCRIPTION_INSTALLATION_FREE = "installationFree";
constexpr const char* MODULE_IS_REMOVABLE = "isRemovable";
constexpr const char* MODULE_UPGRADE_FLAG = "upgradeFlag";
constexpr const char* MODULE_IS_ENTRY = "isEntry";
constexpr const char* MODULE_METADATA = "metaData";
constexpr const char* MODULE_HNP_PACKAGE = "hnpPackage";
constexpr const char* MODULE_COLOR_MODE = "colorMode";
constexpr const char* MODULE_DISTRO = "distro";
constexpr const char* MODULE_REQ_CAPABILITIES = "reqCapabilities";
constexpr const char* MODULE_DATA_DIR = "moduleDataDir";
constexpr const char* MODULE_RES_PATH = "moduleResPath";
constexpr const char* MODULE_HAP_PATH = "hapPath";
constexpr const char* MODULE_ABILITY_KEYS = "abilityKeys";
constexpr const char* MODULE_SKILL_KEYS = "skillKeys";
constexpr const char* MODULE_FORMS = "formInfos";
constexpr const char* MODULE_SHORTCUT = "shortcutInfos";
constexpr const char* MODULE_COMMON_EVENT = "commonEvents";
constexpr const char* MODULE_MAIN_ABILITY = "mainAbility";
constexpr const char* MODULE_ENTRY_ABILITY_KEY = "entryAbilityKey";
constexpr const char* MODULE_DEPENDENCIES = "dependencies";
constexpr const char* MODULE_IS_LIB_ISOLATED = "isLibIsolated";
constexpr const char* MODULE_NATIVE_LIBRARY_PATH = "nativeLibraryPath";
constexpr const char* MODULE_CPU_ABI = "cpuAbi";
constexpr const char* MODULE_SRC_PATH = "srcPath";
constexpr const char* MODULE_HASH_VALUE = "hashValue";
constexpr const char* PORT_SEPARATOR = ":";
constexpr const char* INSTALL_MARK = "installMark";
constexpr const char* INNER_BUNDLE_USER_INFOS = "innerBundleUserInfos";
constexpr const char* MODULE_PROCESS = "process";
constexpr const char* MODULE_SRC_ENTRANCE = "srcEntrance";
constexpr const char* MODULE_DEVICE_TYPES = "deviceTypes";
constexpr const char* MODULE_VIRTUAL_MACHINE = "virtualMachine";
constexpr const char* MODULE_UI_SYNTAX = "uiSyntax";
constexpr const char* MODULE_PAGES = "pages";
constexpr const char* MODULE_META_DATA = "metadata";
constexpr const char* MODULE_REQUEST_PERMISSIONS = "requestPermissions";
constexpr const char* MODULE_DEFINE_PERMISSIONS = "definePermissions";
constexpr const char* MODULE_EXTENSION_KEYS = "extensionKeys";
constexpr const char* MODULE_EXTENSION_SKILL_KEYS = "extensionSkillKeys";
constexpr const char* MODULE_IS_MODULE_JSON = "isModuleJson";
constexpr const char* MODULE_IS_STAGE_BASED_MODEL = "isStageBasedModel";
constexpr const char* BUNDLE_IS_NEW_VERSION = "isNewVersion";
constexpr const char* BUNDLE_BASE_EXTENSION_INFOS = "baseExtensionInfos";
constexpr const char* BUNDLE_EXTENSION_SKILL_INFOS = "extensionSkillInfos";
constexpr const char* BUNDLE_EXTEND_RESOURCES = "extendResources";
constexpr const char* CUR_DYNAMIC_ICON_MODULE = "curDynamicIconModule";
constexpr const char* BUNDLE_PACK_INFO = "bundlePackInfo";
constexpr const char* ALLOWED_ACLS = "allowedAcls";
constexpr const char* APP_INDEX = "appIndex";
constexpr const char* BUNDLE_IS_SANDBOX_APP = "isSandboxApp";
constexpr const char* MODULE_COMPILE_MODE = "compileMode";
constexpr const char* BUNDLE_HQF_INFOS = "hqfInfos";
constexpr const char* MODULE_TARGET_MODULE_NAME = "targetModuleName";
constexpr const char* MODULE_TARGET_PRIORITY = "targetPriority";
constexpr const char* MODULE_OVERLAY_MODULE_INFO = "overlayModuleInfo";
constexpr const char* OVERLAY_BUNDLE_INFO = "overlayBundleInfo";
constexpr const char* OVERLAY_TYPE = "overlayType";
constexpr const char* APPLY_QUICK_FIX_FREQUENCY = "applyQuickFixFrequency";
constexpr const char* MODULE_PRELOADS = "preloads";
constexpr const char* INNER_SHARED_MODULE_INFO = "innerSharedModuleInfos";
constexpr const char* MODULE_BUNDLE_TYPE = "bundleType";
constexpr const char* MODULE_VERSION_CODE = "versionCode";
constexpr const char* MODULE_VERSION_NAME = "versionName";
constexpr const char* MODULE_PROXY_DATAS = "proxyDatas";
constexpr const char* MODULE_BUILD_HASH = "buildHash";
constexpr const char* MODULE_ISOLATION_MODE = "isolationMode";
constexpr const char* MODULE_COMPRESS_NATIVE_LIBS = "compressNativeLibs";
constexpr const char* MODULE_NATIVE_LIBRARY_FILE_NAMES = "nativeLibraryFileNames";
constexpr const char* MODULE_AOT_COMPILE_STATUS = "aotCompileStatus";
constexpr const char* DATA_GROUP_INFOS = "dataGroupInfos";
constexpr const char* MODULE_FILE_CONTEXT_MENU = "fileContextMenu";
constexpr const char* MODULE_IS_ENCRYPTED = "isEncrypted";
constexpr const char* MODULE_ROUTER_MAP = "routerMap";
constexpr const char* EXT_RESOURCE_MODULE_NAME = "moduleName";
constexpr const char* EXT_RESOURCE_ICON_ID = "iconId";
constexpr const char* EXT_RESOURCE_FILE_PATH = "filePath";
constexpr const char* DEVELOPER_ID = "developerId";
constexpr const char* ODID = "odid";
constexpr const char* UNINSTALL_STATE = "uninstallState";
constexpr int8_t SINGLE_HSP_VERSION = 1;
const std::map<std::string, IsolationMode> ISOLATION_MODE_MAP = {
    {"isolationOnly", IsolationMode::ISOLATION_ONLY},
    {"nonisolationOnly", IsolationMode::NONISOLATION_ONLY},
    {"isolationFirst", IsolationMode::ISOLATION_FIRST},
};
constexpr const char* NATIVE_LIBRARY_PATH_SYMBOL = "!/";

constexpr const char* MODULE_QUERY_SCHEMES = "querySchemes";
constexpr const char* MODULE_APP_ENVIRONMENTS = "appEnvironments";
constexpr const char* MODULE_ASAN_ENABLED = "asanEnabled";
constexpr const char* MODULE_GWP_ASAN_ENABLED = "gwpAsanEnabled";
constexpr const char* MODULE_TSAN_ENABLED = "tsanEnabled";
constexpr const char* MODULE_PACKAGE_NAME = "packageName";
constexpr const char* MODULE_APP_STARTUP = "appStartup";
constexpr const char* MODULE_HWASAN_ENABLED = "hwasanEnabled";
constexpr const char* MODULE_UBSAN_ENABLED = "ubsanEnabled";
constexpr const char* MODULE_DEBUG = "debug";
constexpr uint32_t PREINSTALL_SOURCE_CLEAN_MASK = ~0B1110;
constexpr int32_t CPM_KEY_NOT_EXIST = 0x7A000005;

inline CompileMode ConvertCompileMode(const std::string& compileMode)
{
    if (compileMode == Profile::COMPILE_MODE_ES_MODULE) {
        return CompileMode::ES_MODULE;
    } else {
        return CompileMode::JS_BUNDLE;
    }
}

const std::string NameAndUserIdToKey(const std::string &bundleName, int32_t userId)
{
    return bundleName + Constants::FILE_UNDERLINE + std::to_string(userId);
}
}  // namespace

void from_json(const nlohmann::json &jsonObject, ExtendResourceInfo &extendResourceInfo)
{
    const auto &jsonObjectEnd = jsonObject.end();
    int32_t parseResult = ERR_OK;
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        EXT_RESOURCE_MODULE_NAME,
        extendResourceInfo.moduleName,
        false,
        parseResult);
    GetValueIfFindKey<int32_t>(jsonObject,
        jsonObjectEnd,
        EXT_RESOURCE_ICON_ID,
        extendResourceInfo.iconId,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        EXT_RESOURCE_FILE_PATH,
        extendResourceInfo.filePath,
        false,
        parseResult);
    if (parseResult != ERR_OK) {
        APP_LOGE("read ExtendResourceInfo from json error, error code : %{public}d", parseResult);
    }
}

void to_json(nlohmann::json &jsonObject, const ExtendResourceInfo &extendResourceInfo)
{
    jsonObject = nlohmann::json {
        {EXT_RESOURCE_MODULE_NAME, extendResourceInfo.moduleName},
        {EXT_RESOURCE_ICON_ID, extendResourceInfo.iconId},
        {EXT_RESOURCE_FILE_PATH, extendResourceInfo.filePath}
    };
}

void InnerBundleInfo::SetAOTCompileStatus(const std::string &moduleName, AOTCompileStatus aotCompileStatus)
{
    auto item = innerModuleInfos_.find(moduleName);
    if (item == innerModuleInfos_.end()) {
        APP_LOGE("moduleName %{public}s not exist", moduleName.c_str());
        return;
    }
    item->second.aotCompileStatus = aotCompileStatus;
}

AOTCompileStatus InnerBundleInfo::GetAOTCompileStatus(const std::string &moduleName) const
{
    auto item = innerModuleInfos_.find(moduleName);
    if (item == innerModuleInfos_.end()) {
        APP_LOGE("moduleName %{public}s not exist", moduleName.c_str());
        return AOTCompileStatus::NOT_COMPILED;
    }
    return item->second.aotCompileStatus;
}

void InnerBundleInfo::ResetAOTFlags()
{
    baseApplicationInfo_->arkNativeFilePath.clear();
    baseApplicationInfo_->arkNativeFileAbi.clear();
    std::for_each(innerModuleInfos_.begin(), innerModuleInfos_.end(), [](auto &item) {
        item.second.aotCompileStatus = AOTCompileStatus::NOT_COMPILED;
    });
}

ErrCode InnerBundleInfo::ResetAOTCompileStatus(const std::string &moduleName)
{
    auto item = innerModuleInfos_.find(moduleName);
    if (item == innerModuleInfos_.end()) {
        APP_LOGE("moduleName %{public}s not exist", moduleName.c_str());
        return ERR_BUNDLE_MANAGER_MODULE_NOT_EXIST;
    }
    item->second.aotCompileStatus = AOTCompileStatus::NOT_COMPILED;
    return ERR_OK;
}

void InnerBundleInfo::GetInternalDependentHspInfo(
    const std::string &moduleName, std::vector<HspInfo> &hspInfoVector) const
{
    std::vector<std::string> dependentModuleNames;
    if (!GetAllDependentModuleNames(moduleName, dependentModuleNames)) {
        return;
    }
    for (const auto &name : dependentModuleNames) {
        auto item = innerModuleInfos_.find(name);
        if (item == innerModuleInfos_.end()) {
            continue;
        }
        HspInfo hspInfo;
        hspInfo.bundleName = baseApplicationInfo_->bundleName;
        hspInfo.moduleName = item->second.moduleName;
        hspInfo.hapPath = item->second.hapPath;
        hspInfoVector.emplace_back(hspInfo);
    }
}

InnerBundleInfo::InnerBundleInfo()
{
    baseApplicationInfo_ = std::make_shared<ApplicationInfo>();
    if (baseApplicationInfo_ == nullptr) {
        APP_LOGE("baseApplicationInfo_ is nullptr, create failed");
    }
    baseBundleInfo_ = std::make_shared<BundleInfo>();
    if (baseBundleInfo_ == nullptr) {
        APP_LOGE("baseBundleInfo_ is nullptr, create failed");
    }
    bundlePackInfo_ = std::make_shared<BundlePackInfo>();
    if (bundlePackInfo_ == nullptr) {
        APP_LOGE("bundlePackInfo_ is nullptr, create failed");
    }
    APP_LOGD("inner bundle info instance is created");
}

InnerBundleInfo &InnerBundleInfo::operator=(const InnerBundleInfo &info)
{
    if (this == &info) {
        return *this;
    }
    this->appType_ = info.appType_;

    this->userId_ = info.userId_;
    this->bundleStatus_ = info.bundleStatus_;
    this->appFeature_ = info.appFeature_;
    this->allowedAcls_ = info.allowedAcls_;
    this->mark_ = info.mark_;
    this->appIndex_ = info.appIndex_;
    this->isSandboxApp_ = info.isSandboxApp_;
    this->currentPackage_ = info.currentPackage_;
    this->onlyCreateBundleUser_ = info.onlyCreateBundleUser_;
    this->innerModuleInfos_ = info.innerModuleInfos_;
    this->innerSharedModuleInfos_ = info.innerSharedModuleInfos_;
    this->formInfos_ = info.formInfos_;
    this->commonEvents_ = info.commonEvents_;
    this->shortcutInfos_ = info.shortcutInfos_;
    this->baseAbilityInfos_ = info.baseAbilityInfos_;
    this->skillInfos_ = info.skillInfos_;
    this->innerBundleUserInfos_ = info.innerBundleUserInfos_;
    this->bundlePackInfo_ = std::make_shared<BundlePackInfo>();
    if (info.bundlePackInfo_ != nullptr) {
        *(this->bundlePackInfo_) = *(info.bundlePackInfo_);
    }
    this->isNewVersion_ = info.isNewVersion_;
    this->baseExtensionInfos_= info.baseExtensionInfos_;
    this->extensionSkillInfos_ = info.extensionSkillInfos_;
    this->extendResourceInfos_ = info.extendResourceInfos_;
    this->curDynamicIconModule_ = info.curDynamicIconModule_;
    this->baseApplicationInfo_ = std::make_shared<ApplicationInfo>();
    if (info.baseApplicationInfo_ != nullptr) {
        *(this->baseApplicationInfo_) = *(info.baseApplicationInfo_);
    }
    this->baseBundleInfo_ = std::make_shared<BundleInfo>();
    if (info.baseBundleInfo_ != nullptr) {
        *(this->baseBundleInfo_) = *(info.baseBundleInfo_);
    }
    this->hqfInfos_ = info.hqfInfos_;
    this->overlayBundleInfo_ = info.overlayBundleInfo_;
    this->overlayType_ = info.overlayType_;
    this->applyQuickFixFrequency_ = info.applyQuickFixFrequency_;
    this->provisionMetadatas_ = info.provisionMetadatas_;
    this->dataGroupInfos_ = info.dataGroupInfos_;
    this->developerId_ = info.developerId_;
    this->odid_ = info.odid_;
    this->uninstallState_ = info.uninstallState_;
    return *this;
}

InnerBundleInfo::~InnerBundleInfo()
{
    APP_LOGD("inner bundle info instance is destroyed");
}

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
        {MODULE_TSAN_ENABLED, info.tsanEnabled},
        {MODULE_PACKAGE_NAME, info.packageName},
        {MODULE_APP_STARTUP, info.appStartup},
        {MODULE_HWASAN_ENABLED, static_cast<bool>(info.innerModuleInfoFlag &
            InnerBundleInfo::GetSanitizerFlag(GetInnerModuleInfoFlag::GET_INNER_MODULE_INFO_WITH_HWASANENABLED))},
        {MODULE_UBSAN_ENABLED, static_cast<bool>(info.innerModuleInfoFlag &
            InnerBundleInfo::GetSanitizerFlag(GetInnerModuleInfoFlag::GET_INNER_MODULE_INFO_WITH_UBSANENABLED))},
        {MODULE_DEBUG, info.debug},
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

void InnerBundleInfo::ToJson(nlohmann::json &jsonObject) const
{
    jsonObject[APP_TYPE] = appType_;
    jsonObject[BUNDLE_STATUS] = bundleStatus_;
    jsonObject[ALLOWED_ACLS] = allowedAcls_;
    jsonObject[BASE_APPLICATION_INFO] = *baseApplicationInfo_;
    jsonObject[BASE_BUNDLE_INFO] = *baseBundleInfo_;
    jsonObject[BASE_ABILITY_INFO] = baseAbilityInfos_;
    jsonObject[INNER_MODULE_INFO] = innerModuleInfos_;
    jsonObject[INNER_SHARED_MODULE_INFO] = innerSharedModuleInfos_;
    jsonObject[SKILL_INFOS] = skillInfos_;
    jsonObject[USER_ID] = userId_;
    jsonObject[APP_FEATURE] = appFeature_;
    jsonObject[MODULE_FORMS] = formInfos_;
    jsonObject[MODULE_SHORTCUT] = shortcutInfos_;
    jsonObject[MODULE_COMMON_EVENT] = commonEvents_;
    jsonObject[INSTALL_MARK] = mark_;
    jsonObject[INNER_BUNDLE_USER_INFOS] = innerBundleUserInfos_;
    jsonObject[BUNDLE_IS_NEW_VERSION] = isNewVersion_;
    jsonObject[BUNDLE_BASE_EXTENSION_INFOS] = baseExtensionInfos_;
    jsonObject[BUNDLE_EXTENSION_SKILL_INFOS] = extensionSkillInfos_;
    jsonObject[BUNDLE_EXTEND_RESOURCES] = extendResourceInfos_;
    jsonObject[CUR_DYNAMIC_ICON_MODULE] = curDynamicIconModule_;
    jsonObject[BUNDLE_PACK_INFO] = *bundlePackInfo_;
    jsonObject[APP_INDEX] = appIndex_;
    jsonObject[BUNDLE_IS_SANDBOX_APP] = isSandboxApp_;
    jsonObject[BUNDLE_HQF_INFOS] = hqfInfos_;
    jsonObject[OVERLAY_BUNDLE_INFO] = overlayBundleInfo_;
    jsonObject[OVERLAY_TYPE] = overlayType_;
    jsonObject[APPLY_QUICK_FIX_FREQUENCY] = applyQuickFixFrequency_;
    jsonObject[DATA_GROUP_INFOS] = dataGroupInfos_;
    jsonObject[DEVELOPER_ID] = developerId_;
    jsonObject[ODID] = odid_;
    jsonObject[UNINSTALL_STATE] = uninstallState_;
}

void from_json(const nlohmann::json &jsonObject, InnerModuleInfo &info)
{
    // these are not required fields.
    const auto &jsonObjectEnd = jsonObject.end();
    int32_t parseResult = ERR_OK;
    bool hwasanEnabled = static_cast<bool>(info.innerModuleInfoFlag &
        InnerBundleInfo::GetSanitizerFlag(GetInnerModuleInfoFlag::GET_INNER_MODULE_INFO_WITH_HWASANENABLED));
    bool ubsanEnabled = static_cast<bool>(info.innerModuleInfoFlag &
        InnerBundleInfo::GetSanitizerFlag(GetInnerModuleInfoFlag::GET_INNER_MODULE_INFO_WITH_UBSANENABLED));
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        NAME,
        info.name,
        false,
        parseResult);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        MODULE_PACKAGE,
        info.modulePackage,
        false,
        parseResult);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        MODULE_NAME,
        info.moduleName,
        false,
        parseResult);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        MODULE_PATH,
        info.modulePath,
        false,
        parseResult);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        MODULE_DATA_DIR,
        info.moduleDataDir,
        false,
        parseResult);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        MODULE_HAP_PATH,
        info.hapPath,
        false,
        parseResult);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        MODULE_RES_PATH,
        info.moduleResPath,
        false,
        parseResult);
    BMSJsonUtil::GetBoolValueIfFindKey(jsonObject,
        jsonObjectEnd,
        MODULE_IS_ENTRY,
        info.isEntry,
        false,
        parseResult);
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
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        MODULE_DESCRIPTION,
        info.description,
        false,
        parseResult);
    GetValueIfFindKey<int32_t>(jsonObject,
        jsonObjectEnd,
        MODULE_DESCRIPTION_ID,
        info.descriptionId,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        MODULE_ICON,
        info.icon,
        false,
        parseResult);
    GetValueIfFindKey<int32_t>(jsonObject,
        jsonObjectEnd,
        MODULE_ICON_ID,
        info.iconId,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        MODULE_LABEL,
        info.label,
        false,
        parseResult);
    GetValueIfFindKey<int32_t>(jsonObject,
        jsonObjectEnd,
        MODULE_LABEL_ID,
        info.labelId,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        MODULE_MAIN_ABILITY,
        info.mainAbility,
        false,
        parseResult);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        MODULE_ENTRY_ABILITY_KEY,
        info.entryAbilityKey,
        false,
        parseResult);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        MODULE_SRC_PATH,
        info.srcPath,
        false,
        parseResult);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        MODULE_HASH_VALUE,
        info.hashValue,
        false,
        parseResult);
    BMSJsonUtil::GetBoolValueIfFindKey(jsonObject,
        jsonObjectEnd,
        MODULE_DESCRIPTION_INSTALLATION_FREE,
        info.installationFree,
        false,
        parseResult);
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
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        MODULE_PROCESS,
        info.process,
        false,
        parseResult);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        MODULE_SRC_ENTRANCE,
        info.srcEntrance,
        false,
        parseResult);
    GetValueIfFindKey<std::vector<std::string>>(jsonObject,
        jsonObjectEnd,
        MODULE_DEVICE_TYPES,
        info.deviceTypes,
        JsonType::ARRAY,
        false,
        parseResult,
        ArrayType::STRING);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        MODULE_VIRTUAL_MACHINE,
        info.virtualMachine,
        false,
        parseResult);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        MODULE_UI_SYNTAX,
        info.uiSyntax,
        false,
        parseResult);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        MODULE_PAGES,
        info.pages,
        false,
        parseResult);
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
    BMSJsonUtil::GetBoolValueIfFindKey(jsonObject,
        jsonObjectEnd,
        MODULE_IS_MODULE_JSON,
        info.isModuleJson,
        false,
        parseResult);
    BMSJsonUtil::GetBoolValueIfFindKey(jsonObject,
        jsonObjectEnd,
        MODULE_IS_STAGE_BASED_MODEL,
        info.isStageBasedModel,
        false,
        parseResult);
    GetValueIfFindKey<std::vector<Dependency>>(jsonObject,
        jsonObjectEnd,
        MODULE_DEPENDENCIES,
        info.dependencies,
        JsonType::ARRAY,
        false,
        parseResult,
        ArrayType::OBJECT);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        MODULE_COMPILE_MODE,
        info.compileMode,
        false,
        parseResult);
    BMSJsonUtil::GetBoolValueIfFindKey(jsonObject,
        jsonObjectEnd,
        MODULE_IS_LIB_ISOLATED,
        info.isLibIsolated,
        false,
        parseResult);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        MODULE_NATIVE_LIBRARY_PATH,
        info.nativeLibraryPath,
        false,
        parseResult);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        MODULE_CPU_ABI,
        info.cpuAbi,
        false,
        parseResult);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        MODULE_TARGET_MODULE_NAME,
        info.targetModuleName,
        false,
        parseResult);
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
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        MODULE_VERSION_NAME,
        info.versionName,
        false,
        parseResult);
    GetValueIfFindKey<std::vector<ProxyData>>(jsonObject,
        jsonObjectEnd,
        MODULE_PROXY_DATAS,
        info.proxyDatas,
        JsonType::ARRAY,
        false,
        parseResult,
        ArrayType::OBJECT);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        MODULE_BUILD_HASH,
        info.buildHash,
        false,
        parseResult);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        MODULE_ISOLATION_MODE,
        info.isolationMode,
        false,
        parseResult);
    BMSJsonUtil::GetBoolValueIfFindKey(jsonObject,
        jsonObjectEnd,
        MODULE_COMPRESS_NATIVE_LIBS,
        info.compressNativeLibs,
        false,
        parseResult);
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
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        MODULE_FILE_CONTEXT_MENU,
        info.fileContextMenu,
        false,
        parseResult);
    BMSJsonUtil::GetBoolValueIfFindKey(jsonObject,
        jsonObjectEnd,
        MODULE_IS_ENCRYPTED,
        info.isEncrypted,
        false,
        parseResult);
    GetValueIfFindKey<std::vector<std::string>>(jsonObject,
        jsonObjectEnd,
        MODULE_QUERY_SCHEMES,
        info.querySchemes,
        JsonType::ARRAY,
        false,
        parseResult,
        ArrayType::STRING);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        MODULE_ROUTER_MAP,
        info.routerMap,
        false,
        parseResult);
    GetValueIfFindKey<std::vector<AppEnvironment>>(jsonObject,
        jsonObjectEnd,
        MODULE_APP_ENVIRONMENTS,
        info.appEnvironments,
        JsonType::ARRAY,
        false,
        parseResult,
        ArrayType::OBJECT);
    BMSJsonUtil::GetBoolValueIfFindKey(jsonObject,
        jsonObjectEnd,
        MODULE_ASAN_ENABLED,
        info.asanEnabled,
        false,
        parseResult);
    BMSJsonUtil::GetBoolValueIfFindKey(jsonObject,
        jsonObjectEnd,
        MODULE_GWP_ASAN_ENABLED,
        info.gwpAsanEnabled,
        false,
        parseResult);
    BMSJsonUtil::GetBoolValueIfFindKey(jsonObject,
        jsonObjectEnd,
        MODULE_TSAN_ENABLED,
        info.tsanEnabled,
        false,
        parseResult);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        MODULE_PACKAGE_NAME,
        info.packageName,
        false,
        parseResult);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        MODULE_APP_STARTUP,
        info.appStartup,
        false,
        parseResult);
    BMSJsonUtil::GetBoolValueIfFindKey(jsonObject,
        jsonObjectEnd,
        MODULE_HWASAN_ENABLED,
        hwasanEnabled,
        false,
        parseResult);
    BMSJsonUtil::GetBoolValueIfFindKey(jsonObject,
        jsonObjectEnd,
        MODULE_UBSAN_ENABLED,
        ubsanEnabled,
        false,
        parseResult);
    BMSJsonUtil::GetBoolValueIfFindKey(jsonObject,
        jsonObjectEnd,
        MODULE_DEBUG,
        info.debug,
        false,
        parseResult);
    if (parseResult != ERR_OK) {
        APP_LOGE("read InnerModuleInfo from database error code : %{public}d", parseResult);
    } else {
        info.innerModuleInfoFlag = hwasanEnabled ? info.innerModuleInfoFlag | InnerBundleInfo::GetSanitizerFlag(
            GetInnerModuleInfoFlag::GET_INNER_MODULE_INFO_WITH_HWASANENABLED) : info.innerModuleInfoFlag &
            (~InnerBundleInfo::GetSanitizerFlag(GetInnerModuleInfoFlag::GET_INNER_MODULE_INFO_WITH_HWASANENABLED));
        info.innerModuleInfoFlag = ubsanEnabled ? info.innerModuleInfoFlag | InnerBundleInfo::GetSanitizerFlag(
            GetInnerModuleInfoFlag::GET_INNER_MODULE_INFO_WITH_UBSANENABLED) : info.innerModuleInfoFlag &
            (~InnerBundleInfo::GetSanitizerFlag(GetInnerModuleInfoFlag::GET_INNER_MODULE_INFO_WITH_UBSANENABLED));
    }
}

void from_json(const nlohmann::json &jsonObject, Distro &distro)
{
    const auto &jsonObjectEnd = jsonObject.end();
    int32_t parseResult = ERR_OK;
    BMSJsonUtil::GetBoolValueIfFindKey(jsonObject,
        jsonObjectEnd,
        ProfileReader::BUNDLE_MODULE_PROFILE_KEY_DELIVERY_WITH_INSTALL,
        distro.deliveryWithInstall,
        true,
        parseResult);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        ProfileReader::BUNDLE_MODULE_PROFILE_KEY_MODULE_NAME,
        distro.moduleName,
        true,
        parseResult);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        ProfileReader::BUNDLE_MODULE_PROFILE_KEY_MODULE_TYPE,
        distro.moduleType,
        true,
        parseResult);
    // mustFlag decide by distro.moduleType
    BMSJsonUtil::GetBoolValueIfFindKey(jsonObject,
        jsonObjectEnd,
        ProfileReader::BUNDLE_MODULE_PROFILE_KEY_MODULE_INSTALLATION_FREE,
        distro.installationFree,
        false,
        parseResult);
    if (parseResult != ERR_OK) {
        APP_LOGE("Distro from_json error, error code : %{public}d", parseResult);
    }
}

void from_json(const nlohmann::json &jsonObject, InstallMark &installMark)
{
    const auto &jsonObjectEnd = jsonObject.end();
    int32_t parseResult = ERR_OK;
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        ProfileReader::BUNDLE_INSTALL_MARK_BUNDLE,
        installMark.bundleName,
        false,
        parseResult);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        ProfileReader::BUNDLE_INSTALL_MARK_PACKAGE,
        installMark.packageName,
        false,
        parseResult);
    GetValueIfFindKey<int32_t>(jsonObject,
        jsonObjectEnd,
        ProfileReader::BUNDLE_INSTALL_MARK_STATUS,
        installMark.status,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    if (parseResult != ERR_OK) {
        APP_LOGE("InstallMark from_json error, error code : %{public}d", parseResult);
    }
}

void from_json(const nlohmann::json &jsonObject, DefinePermission &definePermission)
{
    const auto &jsonObjectEnd = jsonObject.end();
    int32_t parseResult = ERR_OK;
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        Profile::DEFINEPERMISSION_NAME,
        definePermission.name,
        false,
        parseResult);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        Profile::DEFINEPERMISSION_GRANT_MODE,
        definePermission.grantMode,
        false,
        parseResult);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        Profile::DEFINEPERMISSION_AVAILABLE_LEVEL,
        definePermission.availableLevel,
        false,
        parseResult);
    BMSJsonUtil::GetBoolValueIfFindKey(jsonObject,
        jsonObjectEnd,
        Profile::DEFINEPERMISSION_PROVISION_ENABLE,
        definePermission.provisionEnable,
        false,
        parseResult);
    BMSJsonUtil::GetBoolValueIfFindKey(jsonObject,
        jsonObjectEnd,
        Profile::DEFINEPERMISSION_DISTRIBUTED_SCENE_ENABLE,
        definePermission.distributedSceneEnable,
        false,
        parseResult);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        Profile::LABEL,
        definePermission.label,
        false,
        parseResult);
    GetValueIfFindKey<int32_t>(jsonObject,
        jsonObjectEnd,
        Profile::LABEL_ID,
        definePermission.labelId,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        Profile::DESCRIPTION,
        definePermission.description,
        false,
        parseResult);
    GetValueIfFindKey<int32_t>(jsonObject,
        jsonObjectEnd,
        Profile::DESCRIPTION_ID,
        definePermission.descriptionId,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        Profile::DEFINEPERMISSION_AVAILABLE_TYPE,
        definePermission.availableType,
        false,
        parseResult);
    if (parseResult != ERR_OK) {
        APP_LOGE("DefinePermission from_json error, error code : %{public}d", parseResult);
    }
}

void from_json(const nlohmann::json &jsonObject, Dependency &dependency)
{
    const auto &jsonObjectEnd = jsonObject.end();
    int32_t parseResult = ERR_OK;
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        Profile::DEPENDENCIES_MODULE_NAME,
        dependency.moduleName,
        false,
        parseResult);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        Profile::DEPENDENCIES_BUNDLE_NAME,
        dependency.bundleName,
        false,
        parseResult);
    GetValueIfFindKey<int>(jsonObject,
        jsonObjectEnd,
        Profile::APP_VERSION_CODE,
        dependency.versionCode,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    if (parseResult != ERR_OK) {
        APP_LOGE("Dependency from_json error, error code : %{public}d", parseResult);
    }
}

int32_t InnerBundleInfo::FromJson(const nlohmann::json &jsonObject)
{
    const auto &jsonObjectEnd = jsonObject.end();
    int32_t parseResult = ERR_OK;
    GetValueIfFindKey<Constants::AppType>(jsonObject,
        jsonObjectEnd,
        APP_TYPE,
        appType_,
        JsonType::NUMBER,
        true,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::vector<std::string>>(jsonObject,
        jsonObjectEnd,
        ALLOWED_ACLS,
        allowedAcls_,
        JsonType::ARRAY,
        false,
        parseResult,
        ArrayType::STRING);
    GetValueIfFindKey<BundleStatus>(jsonObject,
        jsonObjectEnd,
        BUNDLE_STATUS,
        bundleStatus_,
        JsonType::NUMBER,
        true,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<BundleInfo>(jsonObject,
        jsonObjectEnd,
        BASE_BUNDLE_INFO,
        *baseBundleInfo_,
        JsonType::OBJECT,
        true,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<ApplicationInfo>(jsonObject,
        jsonObjectEnd,
        BASE_APPLICATION_INFO,
        *baseApplicationInfo_,
        JsonType::OBJECT,
        true,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::map<std::string, AbilityInfo>>(jsonObject,
        jsonObjectEnd,
        BASE_ABILITY_INFO,
        baseAbilityInfos_,
        JsonType::OBJECT,
        true,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::map<std::string, InnerModuleInfo>>(jsonObject,
        jsonObjectEnd,
        INNER_MODULE_INFO,
        innerModuleInfos_,
        JsonType::OBJECT,
        true,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::map<std::string, std::vector<InnerModuleInfo>>>(jsonObject,
        jsonObjectEnd,
        INNER_SHARED_MODULE_INFO,
        innerSharedModuleInfos_,
        JsonType::OBJECT,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::map<std::string, std::vector<Skill>>>(jsonObject,
        jsonObjectEnd,
        SKILL_INFOS,
        skillInfos_,
        JsonType::OBJECT,
        true,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<int>(jsonObject,
        jsonObjectEnd,
        USER_ID,
        userId_,
        JsonType::NUMBER,
        true,
        parseResult,
        ArrayType::NOT_ARRAY);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        APP_FEATURE,
        appFeature_,
        true,
        parseResult);
    GetValueIfFindKey<std::map<std::string, std::vector<FormInfo>>>(jsonObject,
        jsonObjectEnd,
        MODULE_FORMS,
        formInfos_,
        JsonType::OBJECT,
        true,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::map<std::string, ShortcutInfo>>(jsonObject,
        jsonObjectEnd,
        MODULE_SHORTCUT,
        shortcutInfos_,
        JsonType::OBJECT,
        true,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::map<std::string, CommonEventInfo>>(jsonObject,
        jsonObjectEnd,
        MODULE_COMMON_EVENT,
        commonEvents_,
        JsonType::OBJECT,
        true,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<InstallMark>(jsonObject,
        jsonObjectEnd,
        INSTALL_MARK,
        mark_,
        JsonType::OBJECT,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    int32_t isOldVersion = ERR_OK;
    GetValueIfFindKey<std::map<std::string, InnerBundleUserInfo>>(jsonObject,
        jsonObjectEnd,
        INNER_BUNDLE_USER_INFOS,
        innerBundleUserInfos_,
        JsonType::OBJECT,
        true,
        isOldVersion,
        ArrayType::NOT_ARRAY);
    if (parseResult == ERR_OK && isOldVersion == ERR_APPEXECFWK_PARSE_PROFILE_MISSING_PROP) {
        // To be compatible with the old database,
        // if the old data does not have bundleUserInfos,
        // the default user information needs to be constructed.
        BuildDefaultUserInfo();
    }
    BMSJsonUtil::GetBoolValueIfFindKey(jsonObject,
        jsonObjectEnd,
        BUNDLE_IS_NEW_VERSION,
        isNewVersion_,
        false,
        parseResult);
    GetValueIfFindKey<std::map<std::string, ExtensionAbilityInfo>>(jsonObject,
        jsonObjectEnd,
        BUNDLE_BASE_EXTENSION_INFOS,
        baseExtensionInfos_,
        JsonType::OBJECT,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::map<std::string, std::vector<Skill>>>(jsonObject,
        jsonObjectEnd,
        BUNDLE_EXTENSION_SKILL_INFOS,
        extensionSkillInfos_,
        JsonType::OBJECT,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::map<std::string, ExtendResourceInfo>>(jsonObject,
        jsonObjectEnd,
        BUNDLE_EXTEND_RESOURCES,
        extendResourceInfos_,
        JsonType::OBJECT,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        CUR_DYNAMIC_ICON_MODULE,
        curDynamicIconModule_,
        false,
        parseResult);
    GetValueIfFindKey<BundlePackInfo>(jsonObject,
        jsonObjectEnd,
        BUNDLE_PACK_INFO,
        *bundlePackInfo_,
        JsonType::OBJECT,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<int>(jsonObject,
        jsonObjectEnd,
        APP_INDEX,
        appIndex_,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    BMSJsonUtil::GetBoolValueIfFindKey(jsonObject,
        jsonObjectEnd,
        BUNDLE_IS_SANDBOX_APP,
        isSandboxApp_,
        false,
        parseResult);
    GetValueIfFindKey<std::vector<HqfInfo>>(jsonObject,
        jsonObjectEnd,
        BUNDLE_HQF_INFOS,
        hqfInfos_,
        JsonType::ARRAY,
        false,
        parseResult,
        ArrayType::OBJECT);
    GetValueIfFindKey<std::vector<OverlayBundleInfo>>(jsonObject,
        jsonObjectEnd,
        OVERLAY_BUNDLE_INFO,
        overlayBundleInfo_,
        JsonType::ARRAY,
        false,
        parseResult,
        ArrayType::OBJECT);
    GetValueIfFindKey<int32_t>(jsonObject,
        jsonObjectEnd,
        OVERLAY_TYPE,
        overlayType_,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<int32_t>(jsonObject,
        jsonObjectEnd,
        APPLY_QUICK_FIX_FREQUENCY,
        applyQuickFixFrequency_,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::unordered_map<std::string, std::vector<DataGroupInfo>>>(jsonObject,
        jsonObjectEnd,
        DATA_GROUP_INFOS,
        dataGroupInfos_,
        JsonType::OBJECT,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        DEVELOPER_ID,
        developerId_,
        false,
        parseResult);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        ODID,
        odid_,
        false,
        parseResult);
    BMSJsonUtil::GetBoolValueIfFindKey(jsonObject,
        jsonObjectEnd,
        UNINSTALL_STATE,
        uninstallState_,
        false,
        parseResult);
    if (parseResult != ERR_OK) {
        APP_LOGE("read InnerBundleInfo from database error code : %{public}d", parseResult);
    }
    return parseResult;
}

void InnerBundleInfo::BuildDefaultUserInfo()
{
    APP_LOGD("BuildDefaultUserInfo: bundleName: %{public}s",
        baseApplicationInfo_->bundleName.c_str());
    InnerBundleUserInfo defaultInnerBundleUserInfo;
    defaultInnerBundleUserInfo.bundleUserInfo.userId = GetUserId();
    defaultInnerBundleUserInfo.uid = Constants::INVALID_UID;
    defaultInnerBundleUserInfo.gids.emplace_back(ServiceConstants::INVALID_GID);
    defaultInnerBundleUserInfo.installTime = baseBundleInfo_->installTime;
    defaultInnerBundleUserInfo.updateTime = baseBundleInfo_->updateTime;
    defaultInnerBundleUserInfo.bundleName = baseApplicationInfo_->bundleName;
    defaultInnerBundleUserInfo.bundleUserInfo.enabled = baseApplicationInfo_->enabled;
    AddInnerBundleUserInfo(defaultInnerBundleUserInfo);
}

std::optional<HapModuleInfo> InnerBundleInfo::FindHapModuleInfo(
    const std::string &modulePackage, int32_t userId, int32_t appIndex) const
{
    auto it = innerModuleInfos_.find(modulePackage);
    if (it == innerModuleInfos_.end()) {
        APP_LOGE("not find module %{public}s", modulePackage.c_str());
        return std::nullopt;
    }
    HapModuleInfo hapInfo;
    hapInfo.name = it->second.name;
    hapInfo.package = it->second.modulePackage;
    hapInfo.moduleName = it->second.moduleName;
    hapInfo.description = it->second.description;
    hapInfo.descriptionId = it->second.descriptionId;
    hapInfo.label = it->second.label;
    hapInfo.labelId = it->second.labelId;
    hapInfo.iconPath = it->second.icon;
    hapInfo.iconId = it->second.iconId;
    hapInfo.mainAbility = it->second.mainAbility;
    hapInfo.srcPath = it->second.srcPath;
    hapInfo.hapPath = it->second.hapPath;
    hapInfo.supportedModes = baseApplicationInfo_->supportedModes;
    hapInfo.reqCapabilities = it->second.reqCapabilities;
    hapInfo.colorMode = it->second.colorMode;
    hapInfo.isRemovable = it->second.isRemovable;
    hapInfo.upgradeFlag = it->second.upgradeFlag;
    hapInfo.isLibIsolated = it->second.isLibIsolated;
    hapInfo.nativeLibraryPath = it->second.nativeLibraryPath;
    hapInfo.cpuAbi = it->second.cpuAbi;

    hapInfo.bundleName = baseApplicationInfo_->bundleName;
    hapInfo.mainElementName = it->second.mainAbility;
    hapInfo.pages = it->second.pages;
    hapInfo.process = it->second.process;
    hapInfo.resourcePath = it->second.moduleResPath;
    hapInfo.srcEntrance = it->second.srcEntrance;
    hapInfo.uiSyntax = it->second.uiSyntax;
    hapInfo.virtualMachine = it->second.virtualMachine;
    hapInfo.deliveryWithInstall = it->second.distro.deliveryWithInstall;
    hapInfo.installationFree = it->second.distro.installationFree;
    hapInfo.isModuleJson = it->second.isModuleJson;
    hapInfo.isStageBasedModel = it->second.isStageBasedModel;
    hapInfo.deviceTypes = it->second.deviceTypes;
    hapInfo.appStartup = it->second.appStartup;
    std::string moduleType = it->second.distro.moduleType;
    if (moduleType == Profile::MODULE_TYPE_ENTRY) {
        hapInfo.moduleType = ModuleType::ENTRY;
    } else if (moduleType == Profile::MODULE_TYPE_FEATURE) {
        hapInfo.moduleType = ModuleType::FEATURE;
    } else if (moduleType == Profile::MODULE_TYPE_SHARED) {
        hapInfo.moduleType = ModuleType::SHARED;
    } else {
        hapInfo.moduleType = ModuleType::UNKNOWN;
    }
    std::string key;
    key.append(".").append(modulePackage).append(".");
    for (const auto &extension : baseExtensionInfos_) {
        if ((extension.first.find(key) != std::string::npos) && (extension.second.moduleName == hapInfo.moduleName)) {
            hapInfo.extensionInfos.emplace_back(extension.second);
        }
    }
    hapInfo.metadata = it->second.metadata;
    for (auto &ability : baseAbilityInfos_) {
        if (ability.second.name == ServiceConstants::APP_DETAIL_ABILITY) {
            continue;
        }
        if ((ability.first.find(key) != std::string::npos) && (ability.second.moduleName == hapInfo.moduleName)) {
            auto &abilityInfo = hapInfo.abilityInfos.emplace_back(ability.second);
            GetApplicationInfo(ApplicationFlag::GET_APPLICATION_INFO_WITH_PERMISSION |
                ApplicationFlag::GET_APPLICATION_INFO_WITH_CERTIFICATE_FINGERPRINT, userId,
                abilityInfo.applicationInfo, appIndex);
        }
    }
    hapInfo.dependencies = it->second.dependencies;
    hapInfo.compileMode = ConvertCompileMode(it->second.compileMode);
    for (const auto &hqf : hqfInfos_) {
        if (hqf.moduleName == it->second.moduleName) {
            hapInfo.hqfInfo = hqf;
            break;
        }
    }
    for (const auto &item : it->second.preloads) {
        PreloadItem preload(item);
        hapInfo.preloads.emplace_back(preload);
    }
    for (const auto &item : it->second.proxyDatas) {
        ProxyData proxyData(item);
        hapInfo.proxyDatas.emplace_back(proxyData);
    }
    hapInfo.buildHash = it->second.buildHash;
    hapInfo.isolationMode = GetIsolationMode(it->second.isolationMode);
    hapInfo.compressNativeLibs = it->second.compressNativeLibs;
    hapInfo.nativeLibraryFileNames = it->second.nativeLibraryFileNames;
    hapInfo.aotCompileStatus = it->second.aotCompileStatus;
    hapInfo.fileContextMenu = it->second.fileContextMenu;
    hapInfo.routerMap = it->second.routerMap;
    hapInfo.appEnvironments = it->second.appEnvironments;
    hapInfo.packageName = it->second.packageName;
    return hapInfo;
}

std::optional<AbilityInfo> InnerBundleInfo::FindAbilityInfo(
    const std::string &moduleName,
    const std::string &abilityName,
    int32_t userId) const
{
    for (const auto &ability : baseAbilityInfos_) {
        auto abilityInfo = ability.second;
        if ((abilityInfo.name == abilityName) &&
            (moduleName.empty() || (abilityInfo.moduleName == moduleName))) {
            GetApplicationInfo(ApplicationFlag::GET_APPLICATION_INFO_WITH_PERMISSION |
                ApplicationFlag::GET_APPLICATION_INFO_WITH_CERTIFICATE_FINGERPRINT, userId,
                abilityInfo.applicationInfo);
            return abilityInfo;
        }
    }

    return std::nullopt;
}

std::optional<AbilityInfo> InnerBundleInfo::FindAbilityInfoV9(
    const std::string &moduleName, const std::string &abilityName) const
{
    for (const auto &ability : baseAbilityInfos_) {
        auto abilityInfo = ability.second;
        if ((abilityInfo.name == abilityName) &&
            (moduleName.empty() || (abilityInfo.moduleName == moduleName))) {
            return abilityInfo;
        }
    }
    APP_LOGE("bundleName: %{public}s not find moduleName:%{public}s, abilityName:%{public}s",
        GetBundleName().c_str(), moduleName.c_str(), abilityName.c_str());
    return std::nullopt;
}

ErrCode InnerBundleInfo::FindAbilityInfo(
    const std::string &moduleName, const std::string &abilityName, AbilityInfo &info) const
{
    bool isModuleFind = false;
    for (const auto &ability : baseAbilityInfos_) {
        auto abilityInfo = ability.second;
        if ((abilityInfo.moduleName == moduleName)) {
            isModuleFind = true;
            if (abilityInfo.name == abilityName) {
                info = abilityInfo;
                return ERR_OK;
            }
        }
    }
    APP_LOGE("bundleName: %{public}s not find moduleName:%{public}s, abilityName:%{public}s, isModuleFind:%{public}d",
        GetBundleName().c_str(), moduleName.c_str(), abilityName.c_str(), isModuleFind);
    if (isModuleFind) {
        return ERR_BUNDLE_MANAGER_ABILITY_NOT_EXIST;
    } else {
        return ERR_BUNDLE_MANAGER_MODULE_NOT_EXIST;
    }
}

std::optional<std::vector<AbilityInfo>> InnerBundleInfo::FindAbilityInfos(int32_t userId) const
{
    if (!HasInnerBundleUserInfo(userId)) {
        return std::nullopt;
    }

    std::vector<AbilityInfo> abilitys;
    for (const auto &ability : baseAbilityInfos_) {
        if (ability.second.name == ServiceConstants::APP_DETAIL_ABILITY) {
            continue;
        }
        auto abilityInfo = ability.second;
        GetApplicationInfo(ApplicationFlag::GET_APPLICATION_INFO_WITH_PERMISSION |
            ApplicationFlag::GET_APPLICATION_INFO_WITH_CERTIFICATE_FINGERPRINT, userId,
            abilityInfo.applicationInfo);
        abilitys.emplace_back(abilityInfo);
    }

    if (abilitys.empty()) {
        return std::nullopt;
    }
    return abilitys;
}

std::optional<AbilityInfo> InnerBundleInfo::FindAbilityInfo(const std::string continueType, int32_t userId) const
{
    for (const auto &ability : baseAbilityInfos_) {
        AbilityInfo abilityInfo = ability.second;
        std::vector<std::string> continueTypes = abilityInfo.continueType;
        auto item = std::find(continueTypes.begin(), continueTypes.end(), continueType);
        if (item != continueTypes.end()) {
            GetApplicationInfo(ApplicationFlag::GET_APPLICATION_INFO_WITH_PERMISSION |
                ApplicationFlag::GET_APPLICATION_INFO_WITH_CERTIFICATE_FINGERPRINT, userId,
                abilityInfo.applicationInfo);
            return abilityInfo;
        }
    }
    return std::nullopt;
}

std::optional<ExtensionAbilityInfo> InnerBundleInfo::FindExtensionInfo(
    const std::string &moduleName, const std::string &extensionName) const
{
    for (const auto &extension : baseExtensionInfos_) {
        if ((extension.second.name == extensionName) &&
            (moduleName.empty() || (extension.second.moduleName == moduleName))) {
            return extension.second;
        }
    }

    return std::nullopt;
}

std::optional<std::vector<ExtensionAbilityInfo>> InnerBundleInfo::FindExtensionInfos() const
{
    std::vector<ExtensionAbilityInfo> extensions;
    for (const auto &extension : baseExtensionInfos_) {
        extensions.emplace_back(extension.second);
    }

    if (extensions.empty()) {
        return std::nullopt;
    }

    return extensions;
}

bool InnerBundleInfo::AddModuleInfo(const InnerBundleInfo &newInfo)
{
    if (newInfo.currentPackage_.empty()) {
        APP_LOGE("current package is empty");
        return false;
    }
    if (FindModule(newInfo.currentPackage_)) {
        APP_LOGE("current package %{public}s exist", currentPackage_.c_str());
        return false;
    }
    AddInnerModuleInfo(newInfo.innerModuleInfos_);
    AddModuleAbilityInfo(newInfo.baseAbilityInfos_);
    AddModuleSkillInfo(newInfo.skillInfos_);
    AddModuleExtensionInfos(newInfo.baseExtensionInfos_);
    AddModuleExtensionSkillInfos(newInfo.extensionSkillInfos_);
    AddModuleFormInfo(newInfo.formInfos_);
    AddModuleShortcutInfo(newInfo.shortcutInfos_);
    AddModuleCommonEvent(newInfo.commonEvents_);
    UpdateIsCompressNativeLibs();
    return true;
}

void InnerBundleInfo::UpdateBaseBundleInfo(const BundleInfo &bundleInfo, bool isEntry)
{
    baseBundleInfo_->name = bundleInfo.name;

    baseBundleInfo_->versionCode = bundleInfo.versionCode;
    baseBundleInfo_->versionName = bundleInfo.versionName;
    baseBundleInfo_->minCompatibleVersionCode = bundleInfo.minCompatibleVersionCode;
    baseBundleInfo_->compatibleVersion = bundleInfo.compatibleVersion;
    baseBundleInfo_->targetVersion = bundleInfo.targetVersion;

    baseBundleInfo_->isKeepAlive = bundleInfo.isKeepAlive;
    baseBundleInfo_->singleton = bundleInfo.singleton;
    if (!baseBundleInfo_->isPreInstallApp) {
        baseBundleInfo_->isPreInstallApp = bundleInfo.isPreInstallApp;
    }

    baseBundleInfo_->vendor = bundleInfo.vendor;
    if (!baseBundleInfo_->isNativeApp) {
        baseBundleInfo_->isNativeApp = bundleInfo.isNativeApp;
    }

    if (isEntry) {
        baseBundleInfo_->mainEntry = bundleInfo.mainEntry;
        baseBundleInfo_->entryModuleName = bundleInfo.entryModuleName;
    }
}

void InnerBundleInfo::UpdateBaseApplicationInfo(const InnerBundleInfo &newInfo)
{
    const ApplicationInfo &applicationInfo = newInfo.GetBaseApplicationInfo();
    baseApplicationInfo_->name = applicationInfo.name;
    baseApplicationInfo_->bundleName = applicationInfo.bundleName;

    baseApplicationInfo_->versionCode = applicationInfo.versionCode;
    baseApplicationInfo_->versionName = applicationInfo.versionName;
    baseApplicationInfo_->minCompatibleVersionCode = applicationInfo.minCompatibleVersionCode;
    baseApplicationInfo_->apiCompatibleVersion = applicationInfo.apiCompatibleVersion;
    baseApplicationInfo_->apiTargetVersion = applicationInfo.apiTargetVersion;

    baseApplicationInfo_->iconPath = applicationInfo.iconPath;
    baseApplicationInfo_->iconId = applicationInfo.iconId;
    baseApplicationInfo_->label = applicationInfo.label;
    baseApplicationInfo_->labelId = applicationInfo.labelId;
    baseApplicationInfo_->description = applicationInfo.description;
    baseApplicationInfo_->descriptionId = applicationInfo.descriptionId;
    baseApplicationInfo_->iconResource = applicationInfo.iconResource;
    baseApplicationInfo_->labelResource = applicationInfo.labelResource;
    baseApplicationInfo_->descriptionResource = applicationInfo.descriptionResource;
    baseApplicationInfo_->singleton = applicationInfo.singleton;
    baseApplicationInfo_->userDataClearable = applicationInfo.userDataClearable;
    baseApplicationInfo_->accessible = applicationInfo.accessible;
    baseApplicationInfo_->cloudFileSyncEnabled = applicationInfo.cloudFileSyncEnabled;

    if (!baseApplicationInfo_->isSystemApp) {
        baseApplicationInfo_->isSystemApp = applicationInfo.isSystemApp;
    }
    if (!baseApplicationInfo_->isLauncherApp) {
        baseApplicationInfo_->isLauncherApp = applicationInfo.isLauncherApp;
    }

    baseApplicationInfo_->deviceId = applicationInfo.deviceId;
    baseApplicationInfo_->distributedNotificationEnabled = applicationInfo.distributedNotificationEnabled;
    baseApplicationInfo_->entityType = applicationInfo.entityType;
    baseApplicationInfo_->process = applicationInfo.process;
    baseApplicationInfo_->supportedModes = applicationInfo.supportedModes;
    baseApplicationInfo_->vendor = applicationInfo.vendor;
    baseApplicationInfo_->appDistributionType = applicationInfo.appDistributionType;
    baseApplicationInfo_->appProvisionType = applicationInfo.appProvisionType;
    baseApplicationInfo_->formVisibleNotify = applicationInfo.formVisibleNotify;
    baseApplicationInfo_->needAppDetail = applicationInfo.needAppDetail;
    baseApplicationInfo_->appDetailAbilityLibraryPath = applicationInfo.appDetailAbilityLibraryPath;
    baseApplicationInfo_->bundleType = applicationInfo.bundleType;
    baseApplicationInfo_->allowMultiProcess = applicationInfo.allowMultiProcess;
    baseApplicationInfo_->allowEnableNotification = applicationInfo.allowEnableNotification;
    UpdatePrivilegeCapability(applicationInfo);
    SetHideDesktopIcon(applicationInfo.hideDesktopIcon);
#ifdef BUNDLE_FRAMEWORK_OVERLAY_INSTALLATION
    baseApplicationInfo_->targetBundleName = applicationInfo.targetBundleName;
    baseApplicationInfo_->targetPriority = applicationInfo.targetPriority;
#endif
    UpdateDebug(newInfo);
    baseApplicationInfo_->organization = applicationInfo.organization;
    baseApplicationInfo_->multiProjects = applicationInfo.multiProjects;
    baseApplicationInfo_->appEnvironments = applicationInfo.appEnvironments;
    baseApplicationInfo_->maxChildProcess = applicationInfo.maxChildProcess;
    baseApplicationInfo_->installSource = applicationInfo.installSource;
    baseApplicationInfo_->configuration = applicationInfo.configuration;
    if (newInfo.HasEntry()) {
        baseApplicationInfo_->assetAccessGroups = applicationInfo.assetAccessGroups;
    }
}

ErrCode InnerBundleInfo::GetApplicationEnabledV9(int32_t userId, bool &isEnabled, int32_t appIndex) const
{
    InnerBundleUserInfo innerBundleUserInfo;
    if (!GetInnerBundleUserInfo(userId, innerBundleUserInfo)) {
        APP_LOGD("can not find bundleUserInfo in userId: %{public}d when GetApplicationEnabled", userId);
        return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST;
    }
    if (appIndex == 0) {
        isEnabled = innerBundleUserInfo.bundleUserInfo.enabled;
        PrintSetEnabledInfo(isEnabled, userId, appIndex, innerBundleUserInfo.bundleName,
            innerBundleUserInfo.bundleUserInfo.setEnabledCaller);
        return ERR_OK;
    } else if (appIndex > 0 && appIndex <= Constants::INITIAL_SANDBOX_APP_INDEX) {
        const std::map<std::string, InnerBundleCloneInfo> mpCloneInfos = innerBundleUserInfo.cloneInfos;
        std::string key = InnerBundleUserInfo::AppIndexToKey(appIndex);
        if (mpCloneInfos.find(key) == mpCloneInfos.end()) {
            return ERR_APPEXECFWK_CLONE_QUERY_NO_CLONE_APP;
        }
        isEnabled = mpCloneInfos.at(key).enabled;
        PrintSetEnabledInfo(isEnabled, userId, appIndex, innerBundleUserInfo.bundleName,
            mpCloneInfos.at(key).setEnabledCaller);
        return ERR_OK;
    } else {
        return ERR_APPEXECFWK_APP_INDEX_OUT_OF_RANGE;
    }
}

void InnerBundleInfo::UpdateAppDetailAbilityAttrs()
{
    if (IsExistLauncherAbility()) {
        baseApplicationInfo_->needAppDetail = false;
        baseApplicationInfo_->appDetailAbilityLibraryPath = Constants::EMPTY_STRING;
    }
    for (auto iter = baseAbilityInfos_.begin(); iter != baseAbilityInfos_.end(); ++iter) {
        if (iter->second.name == ServiceConstants::APP_DETAIL_ABILITY) {
            baseAbilityInfos_.erase(iter);
            return;
        }
    }
}

bool InnerBundleInfo::IsHideDesktopIcon() const
{
    return baseApplicationInfo_->hideDesktopIcon ? true : !IsExistLauncherAbility();
}

bool InnerBundleInfo::IsExistLauncherAbility() const
{
    bool isExistLauncherAbility = false;
    OHOS::AAFwk::Want want;
    want.SetAction(OHOS::AAFwk::Want::ACTION_HOME);
    want.AddEntity(OHOS::AAFwk::Want::ENTITY_HOME);
    for (const auto& abilityInfoPair : baseAbilityInfos_) {
        auto skillsPair = skillInfos_.find(abilityInfoPair.first);
        if (skillsPair == skillInfos_.end()) {
            continue;
        }
        for (const Skill& skill : skillsPair->second) {
            if (skill.MatchLauncher(want) && (abilityInfoPair.second.type == AbilityType::PAGE)) {
                isExistLauncherAbility = true;
                break;
            }
        }
    }
    return isExistLauncherAbility;
}

void InnerBundleInfo::UpdateNativeLibAttrs(const ApplicationInfo &applicationInfo)
{
    LOG_I(BMS_TAG_DEFAULT, "libPath:%{public}s", applicationInfo.nativeLibraryPath.c_str());
    baseApplicationInfo_->cpuAbi = applicationInfo.cpuAbi;
    baseApplicationInfo_->nativeLibraryPath = applicationInfo.nativeLibraryPath;
}

void InnerBundleInfo::UpdateArkNativeAttrs(const ApplicationInfo &applicationInfo)
{
    baseApplicationInfo_->arkNativeFileAbi = applicationInfo.arkNativeFileAbi;
    baseApplicationInfo_->arkNativeFilePath = applicationInfo.arkNativeFilePath;
}

void InnerBundleInfo::UpdatePrivilegeCapability(const ApplicationInfo &applicationInfo)
{
    // only json can be configured with the following privileges
    SetKeepAlive(applicationInfo.keepAlive);
    baseApplicationInfo_->runningResourcesApply = applicationInfo.runningResourcesApply;
    baseApplicationInfo_->associatedWakeUp = applicationInfo.associatedWakeUp;
    SetAllowCommonEvent(applicationInfo.allowCommonEvent);
    SetAllowAppRunWhenDeviceFirstLocked(applicationInfo.allowAppRunWhenDeviceFirstLocked);
    baseApplicationInfo_->resourcesApply = applicationInfo.resourcesApply;

    // both json and signature can be configured with the following privileges
    // this function is also used to update json privileges during reboot.
    if (applicationInfo.allowEnableNotification) {
        baseApplicationInfo_->allowEnableNotification = true;
    }
    if (applicationInfo.allowMultiProcess) {
        baseApplicationInfo_->allowMultiProcess = true;
    }
    if (applicationInfo.hideDesktopIcon) {
        SetHideDesktopIcon(true);
    }
    if (!applicationInfo.userDataClearable) {
        baseApplicationInfo_->userDataClearable = false; // not allow to clear data
    }
    if (applicationInfo.formVisibleNotify) {
        baseApplicationInfo_->formVisibleNotify = true;
    }
}

void InnerBundleInfo::UpdateRemovable(bool isPreInstall, bool removable)
{
#ifdef USE_PRE_BUNDLE_PROFILE
    if (!isPreInstall) {
        return;
    }
#endif

    baseApplicationInfo_->removable = removable;
}

void InnerBundleInfo::UpdateModuleInfo(const InnerBundleInfo &newInfo)
{
    if (newInfo.currentPackage_.empty()) {
        APP_LOGE("no package in new info");
        return;
    }

    RemoveModuleInfo(newInfo.currentPackage_);
    AddInnerModuleInfo(newInfo.innerModuleInfos_);
    AddModuleAbilityInfo(newInfo.baseAbilityInfos_);
    AddModuleSkillInfo(newInfo.skillInfos_);
    AddModuleExtensionInfos(newInfo.baseExtensionInfos_);
    AddModuleExtensionSkillInfos(newInfo.extensionSkillInfos_);
    AddModuleFormInfo(newInfo.formInfos_);
    AddModuleShortcutInfo(newInfo.shortcutInfos_);
    AddModuleCommonEvent(newInfo.commonEvents_);
    UpdateIsCompressNativeLibs();
}

bool InnerBundleInfo::GetMaxVerBaseSharedBundleInfo(const std::string &moduleName,
    BaseSharedBundleInfo &baseSharedBundleInfo) const
{
    auto it = innerSharedModuleInfos_.find(moduleName);
    if (it == innerSharedModuleInfos_.end()) {
        APP_LOGE("The shared module(%{public}s) infomation not exist", moduleName.c_str());
        return false;
    }
    auto sharedModuleInfoVector = it->second;
    if (sharedModuleInfoVector.empty()) {
        APP_LOGE("No version exists for the shared module(%{public}s)", moduleName.c_str());
        return false;
    }
    InnerModuleInfo innerModuleInfo = sharedModuleInfoVector.front();
    if (innerModuleInfo.bundleType != BundleType::SHARED) {
        APP_LOGE("GetMaxVerBaseSharedBundleInfo failed, bundleType is invalid");
        return false;
    }
    baseSharedBundleInfo.bundleName = baseBundleInfo_->name;
    baseSharedBundleInfo.moduleName = innerModuleInfo.moduleName;
    baseSharedBundleInfo.versionCode = innerModuleInfo.versionCode;
    baseSharedBundleInfo.nativeLibraryPath = innerModuleInfo.nativeLibraryPath;
    baseSharedBundleInfo.hapPath = innerModuleInfo.hapPath;
    baseSharedBundleInfo.compressNativeLibs = innerModuleInfo.compressNativeLibs;
    baseSharedBundleInfo.nativeLibraryFileNames = innerModuleInfo.nativeLibraryFileNames;
    return true;
}

bool InnerBundleInfo::GetBaseSharedBundleInfo(const std::string &moduleName, uint32_t versionCode,
    BaseSharedBundleInfo &baseSharedBundleInfo) const
{
    auto it = innerSharedModuleInfos_.find(moduleName);
    if (it == innerSharedModuleInfos_.end()) {
        APP_LOGE("The shared module(%{public}s) infomation not exist", moduleName.c_str());
        return false;
    }
    auto sharedModuleInfoVector = it->second;
    if (sharedModuleInfoVector.empty()) {
        APP_LOGE("No version exists for the shared module(%{public}s)", moduleName.c_str());
        return false;
    }
    for (const auto &item : sharedModuleInfoVector) {
        if (item.bundleType != BundleType::SHARED) {
            APP_LOGE("GetBaseSharedBundleInfo failed, bundleType is invalid");
            return false;
        }
        if (item.versionCode == versionCode) {
            baseSharedBundleInfo.bundleName = baseBundleInfo_->name;
            baseSharedBundleInfo.moduleName = item.moduleName;
            baseSharedBundleInfo.versionCode = item.versionCode;
            baseSharedBundleInfo.nativeLibraryPath = item.nativeLibraryPath;
            baseSharedBundleInfo.hapPath = item.hapPath;
            baseSharedBundleInfo.compressNativeLibs = item.compressNativeLibs;
            baseSharedBundleInfo.nativeLibraryFileNames = item.nativeLibraryFileNames;
            return true;
        }
    }
    APP_LOGE("GetBaseSharedBundleInfo failed, the version(%{public}d) not exists for this module(%{public}s)",
        versionCode, moduleName.c_str());
    return false;
}

void InnerBundleInfo::InsertInnerSharedModuleInfo(const std::string &moduleName,
    const InnerModuleInfo &innerModuleInfo)
{
    auto iterator = innerSharedModuleInfos_.find(moduleName);
    if (iterator != innerSharedModuleInfos_.end()) {
        auto innerModuleInfoVector = iterator->second;
        bool insertFlag = false;
        for (unsigned long i = 0; i < innerModuleInfoVector.size(); i++) {
            if (innerModuleInfo.versionCode == innerModuleInfoVector.at(i).versionCode) {
                // if the inserted versionCode same as the existing one, replace old innerModuleInfo.
                innerModuleInfoVector.at(i) = innerModuleInfo;
                insertFlag = true;
                break;
            } else if (innerModuleInfo.versionCode > innerModuleInfoVector.at(i).versionCode) {
                // if the inserted versionCode bigger then the existing one, insert the specified location.
                innerModuleInfoVector.emplace(innerModuleInfoVector.begin() + i, innerModuleInfo);
                insertFlag = true;
                break;
            } else {
                continue;
            }
        }
        if (!insertFlag) {
            // insert innerModuleInfo in last location.
            innerModuleInfoVector.emplace(innerModuleInfoVector.end(), innerModuleInfo);
        }
        innerSharedModuleInfos_[moduleName] = innerModuleInfoVector;
    } else {
        std::vector<InnerModuleInfo> newInnerModuleInfoVector;
        newInnerModuleInfoVector.emplace_back(innerModuleInfo);
        innerSharedModuleInfos_.try_emplace(moduleName, newInnerModuleInfoVector);
    }
}

void InnerBundleInfo::SetSharedModuleNativeLibraryPath(const std::string &nativeLibraryPath)
{
    auto sharedModuleInfoIterator = innerSharedModuleInfos_.find(currentPackage_);
    auto moduleInfoIterator = innerModuleInfos_.find(currentPackage_);
    if ((sharedModuleInfoIterator == innerSharedModuleInfos_.end()) ||
        (moduleInfoIterator == innerModuleInfos_.end())) {
        APP_LOGE("The shared module(%{public}s) infomation not exist", currentPackage_.c_str());
        return;
    }
    auto &innerModuleInfoVector = sharedModuleInfoIterator->second;
    for (auto iter = innerModuleInfoVector.begin(); iter != innerModuleInfoVector.end(); ++iter) {
        if (iter->versionCode == moduleInfoIterator->second.versionCode) {
            iter->nativeLibraryPath = nativeLibraryPath;
            return;
        }
    }
}

bool InnerBundleInfo::GetSharedBundleInfo(SharedBundleInfo &sharedBundleInfo) const
{
    sharedBundleInfo.name = GetBundleName();
    sharedBundleInfo.compatiblePolicy = CompatiblePolicy::BACKWARD_COMPATIBILITY;
    std::vector<SharedModuleInfo> sharedModuleInfos;
    for (const auto &infoVector : innerSharedModuleInfos_) {
        for (const auto &info : infoVector.second) {
            SharedModuleInfo sharedModuleInfo;
            sharedModuleInfo.name = info.name;
            sharedModuleInfo.versionCode = info.versionCode;
            sharedModuleInfo.versionName = info.versionName;
            sharedModuleInfo.description = info.description;
            sharedModuleInfo.descriptionId = info.descriptionId;
            sharedModuleInfo.compressNativeLibs = info.compressNativeLibs;
            sharedModuleInfo.hapPath = info.hapPath;
            sharedModuleInfo.cpuAbi = info.cpuAbi;
            sharedModuleInfo.nativeLibraryPath = info.nativeLibraryPath;
            sharedModuleInfo.nativeLibraryFileNames = info.nativeLibraryFileNames;
            sharedModuleInfos.emplace_back(sharedModuleInfo);
        }
    }
    sharedBundleInfo.sharedModuleInfos = sharedModuleInfos;
    return true;
}

bool InnerBundleInfo::GetSharedDependencies(const std::string &moduleName,
    std::vector<Dependency> &dependencies) const
{
    if (innerModuleInfos_.find(moduleName) != innerModuleInfos_.end()) {
        dependencies = innerModuleInfos_.at(moduleName).dependencies;
        return true;
    }
    APP_LOGE("GetSharedDependencies not find module %{public}s", moduleName.c_str());
    return false;
}

bool InnerBundleInfo::GetAllSharedDependencies(const std::string &moduleName,
    std::vector<Dependency> &dependencies) const
{
    if (!GetSharedDependencies(moduleName, dependencies)) {
        return false;
    }
    std::deque<Dependency> dependenciesDeque;
    std::copy(dependencies.begin(), dependencies.end(), std::back_inserter(dependenciesDeque));
    dependencies.clear();
    while (!dependenciesDeque.empty()) {
        bool isAdd = true;
        Dependency itemDependency = dependenciesDeque.front();
        dependenciesDeque.pop_front();
        for (const auto &item : dependencies) {
            if (item.bundleName == itemDependency.bundleName && item.moduleName == itemDependency.moduleName &&
                item.versionCode == itemDependency.versionCode) {
                isAdd = false;
                break;
            }
        }
        if (isAdd) {
            dependencies.push_back(itemDependency);
            std::vector<Dependency> tempDependencies;
            if (GetSharedDependencies(itemDependency.moduleName, tempDependencies)) {
                std::copy(tempDependencies.begin(), tempDependencies.end(), std::back_inserter(dependenciesDeque));
            }
        }
    }
    return true;
}

void InnerBundleInfo::RemoveModuleInfo(const std::string &modulePackage)
{
    auto it = innerModuleInfos_.find(modulePackage);
    if (it == innerModuleInfos_.end()) {
        APP_LOGE("The module(%{public}s) infomation not exist", modulePackage.c_str());
        return;
    }

    auto oldModuleInfo = it->second;
    if (oldModuleInfo.isEntry) {
        baseBundleInfo_->mainEntry.clear();
        baseBundleInfo_->entryModuleName.clear();
    }
    innerModuleInfos_.erase(it);
    std::string key;
    key.append(".").append(modulePackage).append(".");
    for (auto iter = shortcutInfos_.begin(); iter != shortcutInfos_.end();) {
        if (iter->first.find(key) != std::string::npos) {
            shortcutInfos_.erase(iter++);
        } else {
            ++iter;
        }
    }

    for (auto iter = commonEvents_.begin(); iter != commonEvents_.end();) {
        if (iter->first.find(key) != std::string::npos) {
            commonEvents_.erase(iter++);
        } else {
            ++iter;
        }
    }

    // delete old abilityInfos
    for (auto abilityKey : oldModuleInfo.abilityKeys) {
        auto abilityItem = baseAbilityInfos_.find(abilityKey);
        if (abilityItem == baseAbilityInfos_.end()) {
            continue;
        }

        baseAbilityInfos_.erase(abilityItem);
        formInfos_.erase(abilityKey);
    }

    // delete old skillInfos
    for (auto skillKey : oldModuleInfo.skillKeys) {
        auto skillItem = skillInfos_.find(skillKey);
        if (skillItem == skillInfos_.end()) {
            continue;
        }

        skillInfos_.erase(skillItem);
    }

    // delete old extensionInfos
    for (auto extensionKey : oldModuleInfo.extensionKeys) {
        auto extensionItem = baseExtensionInfos_.find(extensionKey);
        if (extensionItem == baseExtensionInfos_.end()) {
            continue;
        }

        baseExtensionInfos_.erase(extensionItem);
    }

    // delete old extensionSkillInfos
    for (auto extensionSkillKey : oldModuleInfo.extensionSkillKeys) {
        auto extensionSkillItem = extensionSkillInfos_.find(extensionSkillKey);
        if (extensionSkillItem == extensionSkillInfos_.end()) {
            continue;
        }

        extensionSkillInfos_.erase(extensionSkillItem);
    }

    // update application debug
    baseApplicationInfo_->debug = GetDebugFromModules(innerModuleInfos_);
}

std::string InnerBundleInfo::ToString() const
{
    nlohmann::json j;
    ToJson(j);
    return j.dump();
}

void InnerBundleInfo::GetApplicationInfo(int32_t flags, int32_t userId, ApplicationInfo &appInfo,
    int32_t appIndex) const
{
    InnerBundleUserInfo innerBundleUserInfo;
    if (!GetInnerBundleUserInfo(userId, innerBundleUserInfo)) {
        LOG_E(BMS_TAG_QUERY, "can not find userId %{public}d when get applicationInfo", userId);
        return;
    }

    if (baseApplicationInfo_ == nullptr) {
        LOG_E(BMS_TAG_QUERY, "baseApplicationInfo_ is nullptr");
        return;
    }
    appInfo = *baseApplicationInfo_;
    if (!GetApplicationInfoAdaptBundleClone(innerBundleUserInfo, appIndex, appInfo)) {
        return;
    }

    for (const auto &info : innerModuleInfos_) {
        bool deCompress = info.second.hapPath.empty();
        ModuleInfo moduleInfo;
        moduleInfo.moduleName = info.second.moduleName;
        if (deCompress) {
            moduleInfo.moduleSourceDir = info.second.modulePath;
            appInfo.moduleSourceDirs.emplace_back(info.second.modulePath);
        }
        if (info.second.hnpPackages.size() > 0) {
            appInfo.hnpPackages[info.second.moduleName] = info.second.hnpPackages;
        }
        moduleInfo.preloads = info.second.preloads;
        appInfo.moduleInfos.emplace_back(moduleInfo);
        if (deCompress && info.second.isEntry) {
            appInfo.entryDir = info.second.modulePath;
        }
        if ((static_cast<uint32_t>(flags) & GET_APPLICATION_INFO_WITH_PERMISSION) ==
            GET_APPLICATION_INFO_WITH_PERMISSION) {
            for (const auto &item : info.second.requestPermissions) {
                appInfo.permissions.push_back(item.name);
            }
        }
        if ((static_cast<uint32_t>(flags) & GET_APPLICATION_INFO_WITH_METADATA) == GET_APPLICATION_INFO_WITH_METADATA) {
            bool isModuleJson = info.second.isModuleJson;
            if (!isModuleJson && info.second.metaData.customizeData.size() > 0) {
                appInfo.metaData[info.second.moduleName] = info.second.metaData.customizeData;
            }
            if (isModuleJson && info.second.metadata.size() > 0) {
                appInfo.metadata[info.second.moduleName] = info.second.metadata;
            }
        }
        if ((static_cast<uint32_t>(flags) & GET_APPLICATION_INFO_WITH_CERTIFICATE_FINGERPRINT) !=
            GET_APPLICATION_INFO_WITH_CERTIFICATE_FINGERPRINT) {
            appInfo.fingerprint.clear();
        }
    }
    if (!appInfo.permissions.empty()) {
        RemoveDuplicateName(appInfo.permissions);
    }
    appInfo.appIndex = appIndex;
    // The label and icon are first used under main ability
    AdaptMainLauncherResourceInfo(appInfo);
}

ErrCode InnerBundleInfo::GetApplicationInfoV9(int32_t flags, int32_t userId, ApplicationInfo &appInfo,
    int32_t appIndex) const
{
    InnerBundleUserInfo innerBundleUserInfo;
    if (!GetInnerBundleUserInfo(userId, innerBundleUserInfo)) {
        LOG_E(BMS_TAG_QUERY, "can not find userId %{public}d when get applicationInfo", userId);
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }

    appInfo = *baseApplicationInfo_;
    if (!GetApplicationInfoAdaptBundleClone(innerBundleUserInfo, appIndex, appInfo)) {
        return ERR_APPEXECFWK_CLONE_INSTALL_INVALID_APP_INDEX;
    }

    for (const auto &info : innerModuleInfos_) {
        bool deCompress = info.second.hapPath.empty();
        ModuleInfo moduleInfo;
        moduleInfo.moduleName = info.second.moduleName;
        if (deCompress) {
            moduleInfo.moduleSourceDir = info.second.modulePath;
            appInfo.moduleSourceDirs.emplace_back(info.second.modulePath);
        }
        if (info.second.hnpPackages.size() > 0) {
            appInfo.hnpPackages[info.second.moduleName] = info.second.hnpPackages;
        }
        moduleInfo.preloads = info.second.preloads;
        appInfo.moduleInfos.emplace_back(moduleInfo);
        if (deCompress && info.second.isEntry) {
            appInfo.entryDir = info.second.modulePath;
        }
        if ((static_cast<uint32_t>(flags) &
            static_cast<uint32_t>(GetApplicationFlag::GET_APPLICATION_INFO_WITH_PERMISSION)) ==
            static_cast<uint32_t>(GetApplicationFlag::GET_APPLICATION_INFO_WITH_PERMISSION)) {
            for (const auto &item : info.second.requestPermissions) {
                appInfo.permissions.push_back(item.name);
            }
        }
        if ((static_cast<uint32_t>(flags) &
            static_cast<uint32_t>(GetApplicationFlag::GET_APPLICATION_INFO_WITH_METADATA)) ==
            static_cast<uint32_t>(GetApplicationFlag::GET_APPLICATION_INFO_WITH_METADATA)) {
            bool isModuleJson = info.second.isModuleJson;
            if (!isModuleJson && info.second.metaData.customizeData.size() > 0) {
                appInfo.metaData[info.second.moduleName] = info.second.metaData.customizeData;
            }
            if (isModuleJson && info.second.metadata.size() > 0) {
                appInfo.metadata[info.second.moduleName] = info.second.metadata;
            }
        }
    }
    if (!appInfo.permissions.empty()) {
        RemoveDuplicateName(appInfo.permissions);
    }
    // The label and icon are first used under main ability
    AdaptMainLauncherResourceInfo(appInfo);
    return ERR_OK;
}

bool InnerBundleInfo::GetBundleInfo(int32_t flags, BundleInfo &bundleInfo, int32_t userId, int32_t appIndex) const
{
    InnerBundleUserInfo innerBundleUserInfo;
    if (!GetInnerBundleUserInfo(userId, innerBundleUserInfo)) {
        LOG_E(BMS_TAG_QUERY, "can not find userId %{public}d when GetBundleInfo bundleName:%{public}s",
            userId, GetBundleName().c_str());
        return false;
    }

    bundleInfo = *baseBundleInfo_;
    if (!GetBundleInfoAdaptBundleClone(innerBundleUserInfo, appIndex, bundleInfo)) {
        LOG_E(BMS_TAG_QUERY, "userId %{public}d index %{public}d not exist", userId, appIndex);
        return false;
    }
    bundleInfo.overlayType = overlayType_;
    bundleInfo.isNewVersion = isNewVersion_;

    GetApplicationInfo(ApplicationFlag::GET_APPLICATION_INFO_WITH_CERTIFICATE_FINGERPRINT, userId,
        bundleInfo.applicationInfo, appIndex);
    for (const auto &info : innerModuleInfos_) {
        if ((static_cast<uint32_t>(flags) & GET_BUNDLE_WITH_REQUESTED_PERMISSION)
            == GET_BUNDLE_WITH_REQUESTED_PERMISSION) {
            for (const auto &item : info.second.requestPermissions) {
                bundleInfo.reqPermissions.push_back(item.name);
            }
            for (const auto &item : info.second.definePermissions) {
                bundleInfo.defPermissions.push_back(item.name);
            }
        }
        bundleInfo.hapModuleNames.emplace_back(info.second.modulePackage);
        auto hapmoduleinfo = FindHapModuleInfo(info.second.modulePackage, userId);
        if (hapmoduleinfo) {
            GetModuleWithHashValue(flags, info.second.modulePackage, *hapmoduleinfo);
            bundleInfo.hapModuleInfos.emplace_back(*hapmoduleinfo);
            bundleInfo.moduleNames.emplace_back(info.second.moduleName);
            bundleInfo.moduleDirs.emplace_back(info.second.modulePath);
            bundleInfo.modulePublicDirs.emplace_back(info.second.moduleDataDir);
            bundleInfo.moduleResPaths.emplace_back(info.second.moduleResPath);
        } else {
            LOG_E(BMS_TAG_QUERY, "can not find hapmoduleinfo %{public}s", info.second.moduleName.c_str());
        }
    }
    if ((static_cast<uint32_t>(flags) & GET_BUNDLE_WITH_REQUESTED_PERMISSION)
        == GET_BUNDLE_WITH_REQUESTED_PERMISSION) {
        if (!bundleInfo.reqPermissions.empty()) {
            RemoveDuplicateName(bundleInfo.reqPermissions);
        }
        if (!bundleInfo.defPermissions.empty()) {
            RemoveDuplicateName(bundleInfo.defPermissions);
        }
        if (!BundlePermissionMgr::GetRequestPermissionStates(bundleInfo,
            bundleInfo.applicationInfo.accessTokenId, bundleInfo.applicationInfo.deviceId)) {
            LOG_E(BMS_TAG_QUERY, "get request permission state failed");
        }
        bundleInfo.reqPermissionDetails = GetAllRequestPermissions();
    }
    GetBundleWithAbilities(flags, bundleInfo, appIndex, userId);
    GetBundleWithExtension(flags, bundleInfo, appIndex, userId);
    return true;
}

ErrCode InnerBundleInfo::GetBundleInfoV9(int32_t flags, BundleInfo &bundleInfo, int32_t userId,
    int32_t appIndex) const
{
    InnerBundleUserInfo innerBundleUserInfo;
    if (!GetInnerBundleUserInfo(userId, innerBundleUserInfo)) {
        LOG_E(BMS_TAG_QUERY, "can not find userId %{public}d when GetBundleInfo", userId);
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }

    bundleInfo = *baseBundleInfo_;
    if (!GetBundleInfoAdaptBundleClone(innerBundleUserInfo, appIndex, bundleInfo)) {
        LOG_E(BMS_TAG_QUERY, "userId %{public}d index %{public}d not exist", userId, appIndex);
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    bundleInfo.overlayType = overlayType_;
    bundleInfo.isNewVersion = isNewVersion_;

    for (const auto &info : innerModuleInfos_) {
        bundleInfo.hapModuleNames.emplace_back(info.second.modulePackage);
        bundleInfo.moduleNames.emplace_back(info.second.moduleName);
        bundleInfo.moduleDirs.emplace_back(info.second.modulePath);
        bundleInfo.modulePublicDirs.emplace_back(info.second.moduleDataDir);
        bundleInfo.moduleResPaths.emplace_back(info.second.moduleResPath);
    }
    ProcessBundleFlags(flags, userId, bundleInfo, appIndex);
    return ERR_OK;
}

bool InnerBundleInfo::GetSharedBundleInfo(int32_t flags, BundleInfo &bundleInfo) const
{
    bundleInfo = *baseBundleInfo_;
    ProcessBundleWithHapModuleInfoFlag(flags, bundleInfo, Constants::ALL_USERID);
    bundleInfo.applicationInfo = *baseApplicationInfo_;
    return true;
}

void InnerBundleInfo::ProcessBundleFlags(
    int32_t flags, int32_t userId, BundleInfo &bundleInfo, int32_t appIndex) const
{
    if ((static_cast<uint32_t>(flags) & static_cast<uint32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_APPLICATION))
        == static_cast<uint32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_APPLICATION)) {
        if ((static_cast<uint32_t>(flags) & static_cast<uint32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_METADATA))
            == static_cast<uint32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_METADATA)) {
            GetApplicationInfoV9(static_cast<int32_t>(GetApplicationFlag::GET_APPLICATION_INFO_WITH_METADATA), userId,
                bundleInfo.applicationInfo, appIndex);
        } else {
            GetApplicationInfoV9(static_cast<int32_t>(GetApplicationFlag::GET_APPLICATION_INFO_DEFAULT), userId,
                bundleInfo.applicationInfo, appIndex);
        }
    }
    bundleInfo.applicationInfo.appIndex = appIndex;
    GetBundleWithReqPermissionsV9(flags, userId, bundleInfo, appIndex);
    ProcessBundleWithHapModuleInfoFlag(flags, bundleInfo, userId, appIndex);
    if ((static_cast<uint32_t>(flags) & static_cast<uint32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_SIGNATURE_INFO))
        == static_cast<uint32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_SIGNATURE_INFO)) {
        bundleInfo.signatureInfo.appId = baseBundleInfo_->appId;
        bundleInfo.signatureInfo.fingerprint = baseApplicationInfo_->fingerprint;
        bundleInfo.signatureInfo.certificate = baseBundleInfo_->signatureInfo.certificate;
    }
}

void InnerBundleInfo::GetBundleWithReqPermissionsV9(
    int32_t flags, int32_t userId, BundleInfo &bundleInfo, int32_t appIndex) const
{
    if ((static_cast<uint32_t>(flags) &
        static_cast<uint32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_REQUESTED_PERMISSION))
        != static_cast<uint32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_REQUESTED_PERMISSION)) {
        return;
    }
    for (const auto &info : innerModuleInfos_) {
        for (const auto &item : info.second.requestPermissions) {
            bundleInfo.reqPermissions.push_back(item.name);
        }
        for (const auto &item : info.second.definePermissions) {
            bundleInfo.defPermissions.push_back(item.name);
        }
    }
    if (!bundleInfo.reqPermissions.empty()) {
        RemoveDuplicateName(bundleInfo.reqPermissions);
    }
    if (!bundleInfo.defPermissions.empty()) {
        RemoveDuplicateName(bundleInfo.defPermissions);
    }
    InnerBundleUserInfo innerBundleUserInfo;
    if (!GetInnerBundleUserInfo(userId, innerBundleUserInfo)) {
        APP_LOGE("not find userId %{public}d when get applicationInfo", userId);
        return;
    }
    uint32_t tokenId = innerBundleUserInfo.accessTokenId;
    std::string deviceId = baseApplicationInfo_->deviceId;
    if (appIndex != 0) {
        // clone app
        const std::map<std::string, InnerBundleCloneInfo> &mpCloneInfos = innerBundleUserInfo.cloneInfos;
        std::string appIndexKey = InnerBundleUserInfo::AppIndexToKey(appIndex);
        if (mpCloneInfos.find(appIndexKey) == mpCloneInfos.end()) {
            LOG_E(BMS_TAG_QUERY,
                "can not find userId %{public}d, appIndex %{public}d when get applicationInfo", userId, appIndex);
            return;
        }
        const InnerBundleCloneInfo &cloneInfo = mpCloneInfos.at(appIndexKey);
        tokenId = cloneInfo.accessTokenId;
    }
    if (!BundlePermissionMgr::GetRequestPermissionStates(bundleInfo, tokenId, deviceId)) {
        APP_LOGE("get request permission state failed");
    }
    bundleInfo.reqPermissionDetails = GetAllRequestPermissions();
}

void InnerBundleInfo::GetModuleWithHashValue(
    int32_t flags, const std::string &modulePackage, HapModuleInfo &hapModuleInfo) const
{
    if (!(static_cast<uint32_t>(flags) & GET_BUNDLE_WITH_HASH_VALUE)) {
        return;
    }

    auto it = innerModuleInfos_.find(modulePackage);
    if (it == innerModuleInfos_.end()) {
        APP_LOGE("not find module %{public}s", modulePackage.c_str());
        return;
    }

    hapModuleInfo.hashValue = it->second.hashValue;
}

void InnerBundleInfo::ProcessBundleWithHapModuleInfoFlag(
    int32_t flags, BundleInfo &bundleInfo, int32_t userId, int32_t appIndex) const
{
    if ((static_cast<uint32_t>(flags) & static_cast<uint32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_HAP_MODULE))
        != static_cast<uint32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_HAP_MODULE)) {
        bundleInfo.hapModuleInfos.clear();
        return;
    }
    for (const auto &info : innerModuleInfos_) {
        auto hapmoduleinfo = FindHapModuleInfo(info.second.modulePackage, userId, appIndex);
        if (hapmoduleinfo) {
            HapModuleInfo hapModuleInfo = *hapmoduleinfo;
            auto it = innerModuleInfos_.find(info.second.modulePackage);
            if (it == innerModuleInfos_.end()) {
                APP_LOGE("not find module %{public}s", info.second.modulePackage.c_str());
            } else {
                hapModuleInfo.hashValue = it->second.hashValue;
            }
            if (hapModuleInfo.hapPath.empty()) {
                hapModuleInfo.moduleSourceDir = info.second.modulePath;
            }
            if ((static_cast<uint32_t>(flags) & static_cast<uint32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_METADATA))
                != static_cast<uint32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_METADATA)) {
                hapModuleInfo.metadata.clear();
            }

            GetBundleWithAbilitiesV9(flags, hapModuleInfo, userId, appIndex);
            GetBundleWithExtensionAbilitiesV9(flags, hapModuleInfo, appIndex);
            bundleInfo.hapModuleInfos.emplace_back(hapModuleInfo);
        }
    }
}

void InnerBundleInfo::GetBundleWithAbilitiesV9(
    int32_t flags, HapModuleInfo &hapModuleInfo, int32_t userId, int32_t appIndex) const
{
    hapModuleInfo.abilityInfos.clear();
    if ((static_cast<uint32_t>(flags) & static_cast<uint32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_ABILITY))
        != static_cast<uint32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_ABILITY)) {
        return;
    }
    APP_LOGD("Get bundleInfo with abilities");
    for (auto &ability : baseAbilityInfos_) {
        if ((ability.second.moduleName != hapModuleInfo.moduleName) ||
            (ability.second.name == ServiceConstants::APP_DETAIL_ABILITY)) {
            continue;
        }
        bool isEnabled = IsAbilityEnabled(ability.second, userId, appIndex);
        if (!(static_cast<uint32_t>(flags) & static_cast<uint32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_DISABLE))
            && !isEnabled) {
            continue;
        }
        AbilityInfo abilityInfo = ability.second;
        abilityInfo.enabled = isEnabled;
        abilityInfo.appIndex = appIndex;

        if ((static_cast<uint32_t>(flags) & static_cast<uint32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_METADATA))
            != static_cast<uint32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_METADATA)) {
            abilityInfo.metaData.customizeData.clear();
            abilityInfo.metadata.clear();
        }
        if ((static_cast<uint32_t>(flags) & static_cast<uint32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_SKILL))
            != static_cast<uint32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_SKILL)) {
            abilityInfo.skills.clear();
        }

        hapModuleInfo.abilityInfos.emplace_back(abilityInfo);
    }
}

void InnerBundleInfo::GetBundleWithExtensionAbilitiesV9(
    int32_t flags, HapModuleInfo &hapModuleInfo, int32_t appIndex) const
{
    hapModuleInfo.extensionInfos.clear();
    if ((static_cast<uint32_t>(flags) &
        static_cast<uint32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_EXTENSION_ABILITY))
        != static_cast<uint32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_EXTENSION_ABILITY)) {
        return;
    }
    APP_LOGD("Get bundleInfo with extensionAbilities");
    for (const auto &extensionInfo : baseExtensionInfos_) {
        if (extensionInfo.second.moduleName != hapModuleInfo.moduleName || !extensionInfo.second.enabled) {
            continue;
        }
        ExtensionAbilityInfo info = extensionInfo.second;
        info.appIndex = appIndex;

        if ((static_cast<uint32_t>(flags) & static_cast<uint32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_METADATA))
            != static_cast<uint32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_METADATA)) {
            info.metadata.clear();
        }
        if ((static_cast<uint32_t>(flags) & static_cast<uint32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_SKILL))
            != static_cast<uint32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_SKILL)) {
            info.skills.clear();
        }
        hapModuleInfo.extensionInfos.emplace_back(info);
    }
}

void InnerBundleInfo::GetBundleWithAbilities(
    int32_t flags, BundleInfo &bundleInfo, int32_t appIndex, int32_t userId) const
{
    APP_LOGD("bundleName:%{public}s userid:%{public}d", bundleInfo.name.c_str(), userId);
    if (static_cast<uint32_t>(flags) & GET_BUNDLE_WITH_ABILITIES) {
        for (auto &ability : baseAbilityInfos_) {
            if (ability.second.name == ServiceConstants::APP_DETAIL_ABILITY) {
                continue;
            }
            bool isEnabled = IsAbilityEnabled(ability.second, userId);
            if (!(static_cast<uint32_t>(flags) & GET_ABILITY_INFO_WITH_DISABLE)
                && !isEnabled) {
                continue;
            }
            AbilityInfo abilityInfo = ability.second;
            abilityInfo.enabled = isEnabled;
            if ((static_cast<uint32_t>(flags) & GET_BUNDLE_WITH_SKILL) != GET_BUNDLE_WITH_SKILL) {
                abilityInfo.skills.clear();
            }
            abilityInfo.appIndex = appIndex;
            bundleInfo.abilityInfos.emplace_back(abilityInfo);
        }
    }
}

void InnerBundleInfo::GetBundleWithExtension(
    int32_t flags, BundleInfo &bundleInfo, int32_t appIndex, int32_t userId) const
{
    APP_LOGD("get bundleInfo with extensionInfo begin");
    if ((static_cast<uint32_t>(flags) & GET_BUNDLE_WITH_EXTENSION_INFO) == GET_BUNDLE_WITH_EXTENSION_INFO) {
        for (const auto &extensionInfo : baseExtensionInfos_) {
            if (!extensionInfo.second.enabled) {
                continue;
            }
            ExtensionAbilityInfo info = extensionInfo.second;
            if ((static_cast<uint32_t>(flags) & GET_BUNDLE_WITH_SKILL) != GET_BUNDLE_WITH_SKILL) {
                info.skills.clear();
            }
            info.appIndex = appIndex;
            bundleInfo.extensionInfos.emplace_back(info);
        }
    }
    APP_LOGD("get bundleInfo with extensionInfo end");
}

bool InnerBundleInfo::CheckSpecialMetaData(const std::string &metaData) const
{
    if (isNewVersion_) {
        for (const auto &moduleInfo : innerModuleInfos_) {
            for (const auto &data : moduleInfo.second.metadata) {
                if (metaData == data.name) {
                    return true;
                }
            }
        }
        return false;
    }
    // old version
    for (const auto &moduleInfo : innerModuleInfos_) {
        for (const auto &data : moduleInfo.second.metaData.customizeData) {
            if (metaData == data.name) {
                return true;
            }
        }
    }
    return false;
}

void InnerBundleInfo::GetFormsInfoByModule(const std::string &moduleName, std::vector<FormInfo> &formInfos) const
{
    for (const auto &data : formInfos_) {
        for (auto &form : data.second) {
            if (form.moduleName == moduleName) {
                formInfos.emplace_back(form);
            }
        }
    }
}

void InnerBundleInfo::GetFormsInfoByApp(std::vector<FormInfo> &formInfos) const
{
    for (const auto &data : formInfos_) {
        std::copy(data.second.begin(), data.second.end(), std::back_inserter(formInfos));
    }
}

void InnerBundleInfo::GetShortcutInfos(std::vector<ShortcutInfo> &shortcutInfos) const
{
    for (const auto &shortcut : shortcutInfos_) {
        shortcutInfos.emplace_back(shortcut.second);
    }
}

void InnerBundleInfo::GetCommonEvents(const std::string &eventKey, std::vector<CommonEventInfo> &commonEvents) const
{
    CommonEventInfo item;
    for (const auto &commonEvent : commonEvents_) {
        for (const auto &event : commonEvent.second.events) {
            if (event == eventKey) {
                item = commonEvent.second;
                item.uid = GetUid(GetUserId());
                commonEvents.emplace_back(item);
                break;
            }
        }
    }
}

std::optional<InnerModuleInfo> InnerBundleInfo::GetInnerModuleInfoByModuleName(const std::string &moduleName) const
{
    for (const auto &innerModuleInfo : innerModuleInfos_) {
        APP_LOGD("info.moduleName = %{public}s, moduleName= %{public}s",
            innerModuleInfo.second.moduleName.c_str(), moduleName.c_str());
        if (innerModuleInfo.second.moduleName == moduleName) {
            return innerModuleInfo.second;
        }
    }
    return std::nullopt;
}

std::optional<std::vector<HnpPackage>> InnerBundleInfo::GetInnerModuleInfoHnpInfo(const std::string &moduleName) const
{
    for (const auto &innerModuleInfo : innerModuleInfos_) {
        if (!(innerModuleInfo.second.hnpPackages.empty())) {
            if (innerModuleInfo.second.moduleName == moduleName) {
                return innerModuleInfo.second.hnpPackages;
            }
        }
    }
    return std::nullopt;
}

std::string InnerBundleInfo::GetInnerModuleInfoHnpPath(const std::string &moduleName) const
{
    for (const auto &innerModuleInfo : innerModuleInfos_) {
        if (!(innerModuleInfo.second.hnpPackages.empty())) {
            if (innerModuleInfo.second.moduleName == moduleName) {
                return innerModuleInfo.second.moduleHnpsPath;
            }
        }
    }
    return "";
}

void InnerBundleInfo::GetModuleNames(std::vector<std::string> &moduleNames) const
{
    for (const auto &innerModuleInfo : innerModuleInfos_) {
        moduleNames.emplace_back(innerModuleInfo.second.moduleName);
    }
}

void InnerBundleInfo::ResetBundleState(int32_t userId)
{
    if (userId == Constants::ALL_USERID) {
        for (auto& innerBundleUserInfo : innerBundleUserInfos_) {
            innerBundleUserInfo.second.bundleUserInfo.Reset();
        }

        return;
    }

    auto& key = NameAndUserIdToKey(GetBundleName(), userId);
    if (innerBundleUserInfos_.find(key) == innerBundleUserInfos_.end()) {
        APP_LOGD("no this user %{public}s", key.c_str());
        return;
    }

    innerBundleUserInfos_.at(key).bundleUserInfo.Reset();
}

void InnerBundleInfo::RemoveInnerBundleUserInfo(int32_t userId)
{
    auto& key = NameAndUserIdToKey(GetBundleName(), userId);
    auto infoItem = innerBundleUserInfos_.find(key);
    if (infoItem == innerBundleUserInfos_.end()) {
        return;
    }

    auto result = innerBundleUserInfos_.erase(key);
    if (result == 0) {
        APP_LOGE("remove userId:%{public}d key:%{public}s info failed", userId, key.c_str());
    }
    for (auto &innerModuleInfo : innerModuleInfos_) {
        DeleteModuleRemovable(innerModuleInfo.second.moduleName, userId);
    }
}

void InnerBundleInfo::AddInnerBundleUserInfo(
    const InnerBundleUserInfo& innerBundleUserInfo)
{
    auto& key = NameAndUserIdToKey(
        GetBundleName(), innerBundleUserInfo.bundleUserInfo.userId);
    auto infoItem = innerBundleUserInfos_.find(key);
    if (infoItem == innerBundleUserInfos_.end()) {
        innerBundleUserInfos_.emplace(key, innerBundleUserInfo);
        return;
    }

    innerBundleUserInfos_[key] = innerBundleUserInfo;
}

bool InnerBundleInfo::GetInnerBundleUserInfo(
    int32_t userId, InnerBundleUserInfo& innerBundleUserInfo) const
{
    if (userId == ServiceConstants::NOT_EXIST_USERID) {
        return true;
    }

    if (userId == Constants::ALL_USERID) {
        if (innerBundleUserInfos_.empty()) {
            return false;
        }

        innerBundleUserInfo = innerBundleUserInfos_.begin()->second;
        return true;
    }

    auto& key = NameAndUserIdToKey(GetBundleName(), userId);
    auto infoItem = innerBundleUserInfos_.find(key);
    if (infoItem == innerBundleUserInfos_.end()) {
        return false;
    }

    innerBundleUserInfo = infoItem->second;
    return true;
}

bool InnerBundleInfo::HasInnerBundleUserInfo(int32_t userId) const
{
    if (userId == Constants::ALL_USERID || userId == Constants::ANY_USERID) {
        return !innerBundleUserInfos_.empty();
    }

    auto& key = NameAndUserIdToKey(GetBundleName(), userId);
    auto infoItem = innerBundleUserInfos_.find(key);
    return infoItem != innerBundleUserInfos_.end();
}

void InnerBundleInfo::SetBundleInstallTime(const int64_t time, int32_t userId)
{
    auto& key = NameAndUserIdToKey(GetBundleName(), userId);
    auto infoItem = innerBundleUserInfos_.find(key);
    if (infoItem == innerBundleUserInfos_.end()) {
        return;
    }

    infoItem->second.installTime = time;
    infoItem->second.updateTime = time;
}

void InnerBundleInfo::SetAccessTokenId(uint32_t accessToken, const int32_t userId)
{
    auto& key = NameAndUserIdToKey(GetBundleName(), userId);
    auto infoItem = innerBundleUserInfos_.find(key);
    if (infoItem == innerBundleUserInfos_.end()) {
        return;
    }

    infoItem->second.accessTokenId = accessToken;
}

void InnerBundleInfo::SetAccessTokenIdEx(
    const Security::AccessToken::AccessTokenIDEx accessTokenIdEx,
    const int32_t userId)
{
    auto& key = NameAndUserIdToKey(GetBundleName(), userId);
    auto infoItem = innerBundleUserInfos_.find(key);
    if (infoItem == innerBundleUserInfos_.end()) {
        return;
    }

    infoItem->second.accessTokenId = accessTokenIdEx.tokenIdExStruct.tokenID;
    infoItem->second.accessTokenIdEx = accessTokenIdEx.tokenIDEx;
}

void InnerBundleInfo::SetAccessTokenIdExWithAppIndex(
    const Security::AccessToken::AccessTokenIDEx accessTokenIdEx,
    const int32_t userId, const int32_t appIndex)
{
    auto& key = NameAndUserIdToKey(GetBundleName(), userId);
    auto infoItem = innerBundleUserInfos_.find(key);
    if (infoItem == innerBundleUserInfos_.end()) {
        return;
    }

    auto& userInfo = infoItem->second;
    std::map<std::string, InnerBundleCloneInfo> &cloneInfos = userInfo.cloneInfos;

    auto cloneKey = InnerBundleUserInfo::AppIndexToKey(appIndex);
    auto cloneItem = cloneInfos.find(cloneKey);
    if (cloneItem == cloneInfos.end()) {
        return;
    }
    cloneItem->second.accessTokenId = accessTokenIdEx.tokenIdExStruct.tokenID;
    cloneItem->second.accessTokenIdEx = accessTokenIdEx.tokenIDEx;
}

void InnerBundleInfo::SetkeyId(const int32_t userId, const std::string &keyId, const int32_t appIndex)
{
    if (keyId.empty()) {
        APP_LOGE("SetkeyId failed, keyId is empty");
        return;
    }
    auto& key = NameAndUserIdToKey(GetBundleName(), userId);
    auto infoItem = innerBundleUserInfos_.find(key);
    if (infoItem == innerBundleUserInfos_.end()) {
        APP_LOGE("SetkeyId failed, not find userInfo for userId %{public}d", userId);
        return;
    }
    if (appIndex == 0) {
        infoItem->second.keyId = keyId;
        return;
    }
    std::map<std::string, InnerBundleCloneInfo> &mpCloneInfos = infoItem->second.cloneInfos;
    std::string appIndexKey = InnerBundleUserInfo::AppIndexToKey(appIndex);
    if (mpCloneInfos.find(appIndexKey) == mpCloneInfos.end()) {
        APP_LOGE("key:%{public}s not found", key.c_str());
        return;
    }
    mpCloneInfos.at(appIndexKey).keyId = keyId;
}

void InnerBundleInfo::SetBundleUpdateTime(const int64_t time, int32_t userId)
{
    auto& key = NameAndUserIdToKey(GetBundleName(), userId);
    auto infoItem = innerBundleUserInfos_.find(key);
    if (infoItem == innerBundleUserInfos_.end()) {
        return;
    }

    infoItem->second.updateTime = time;
}

bool InnerBundleInfo::IsAbilityEnabled(const AbilityInfo &abilityInfo, int32_t userId, int32_t appIndex) const
{
    APP_LOGD("IsAbilityEnabled bundleName:%{public}s, userId:%{public}d", abilityInfo.bundleName.c_str(), userId);
    if (userId == ServiceConstants::NOT_EXIST_USERID) {
        return true;
    }
    auto& key = NameAndUserIdToKey(abilityInfo.bundleName, userId);
    auto infoItem = innerBundleUserInfos_.find(key);
    if (infoItem == innerBundleUserInfos_.end()) {
        APP_LOGW_NOFUNC("key:%{public}s not found", key.c_str());
        return false;
    }

    if (appIndex == 0) {
        auto disabledAbilities = infoItem->second.bundleUserInfo.disabledAbilities;
        if (std::find(disabledAbilities.begin(), disabledAbilities.end(), abilityInfo.name)
            != disabledAbilities.end()) {
            APP_LOGE_NOFUNC("-n %{public}s -a %{public}s disabled",
                abilityInfo.bundleName.c_str(), abilityInfo.name.c_str());
            return false;
        } else {
            return true;
        }
    }

    const std::map<std::string, InnerBundleCloneInfo> &mpCloneInfos = infoItem->second.cloneInfos;
    std::string appIndexKey = InnerBundleUserInfo::AppIndexToKey(appIndex);
    if (mpCloneInfos.find(appIndexKey) == mpCloneInfos.end()) {
        APP_LOGW_NOFUNC("key:%{public}s not found", key.c_str());
        return false;
    }
    auto disabledAbilities = mpCloneInfos.at(appIndexKey).disabledAbilities;
    if (std::find(disabledAbilities.begin(), disabledAbilities.end(), abilityInfo.name)
        != disabledAbilities.end()) {
        APP_LOGE_NOFUNC("-n %{public}s -a %{public}s disabled",
            abilityInfo.bundleName.c_str(), abilityInfo.name.c_str());
        return false;
    } else {
        return true;
    }
}

void InnerBundleInfo::SetOverlayModuleState(const std::string &moduleName, int32_t state, int32_t userId)
{
    APP_LOGD("start to set overlay moduleInfo state of module %{public}s", moduleName.c_str());
    if (overlayType_ == NON_OVERLAY_TYPE) {
        APP_LOGW("no overlay module");
        return;
    }
    for (auto &innerUserInfo : innerBundleUserInfos_) {
        if (innerUserInfo.second.bundleUserInfo.userId != userId) {
            continue;
        }

        auto &overlayStates = innerUserInfo.second.bundleUserInfo.overlayModulesState;
        bool isSetSucc = std::any_of(overlayStates.begin(), overlayStates.end(), [&moduleName, &state](auto &item) {
            if (item.find(moduleName + Constants::FILE_UNDERLINE) != std::string::npos) {
                item = moduleName + Constants::FILE_UNDERLINE + std::to_string(state);
                return true;
            }
            return false;
        });
        if (!isSetSucc) {
            APP_LOGD("no overlay module state info under user %{public}d", userId);
            overlayStates.emplace_back(moduleName + Constants::FILE_UNDERLINE + std::to_string(state));
        }
    }
}

void InnerBundleInfo::SetOverlayModuleState(const std::string &moduleName, int32_t state)
{
    APP_LOGD("start to set overlay moduleInfo state of module %{public}s", moduleName.c_str());
    if (overlayType_ == NON_OVERLAY_TYPE) {
        APP_LOGW("no overlay module");
        return;
    }
    for (auto &innerUserInfo : innerBundleUserInfos_) {
        auto &overlayStates = innerUserInfo.second.bundleUserInfo.overlayModulesState;
        bool isSetSucc = std::any_of(overlayStates.begin(), overlayStates.end(), [&moduleName, &state](auto &item) {
            if (item.find(moduleName + Constants::FILE_UNDERLINE) != std::string::npos) {
                item = moduleName + Constants::FILE_UNDERLINE + std::to_string(state);
                return true;
            }
            return false;
        });
        if (!isSetSucc) {
            overlayStates.emplace_back(moduleName + Constants::FILE_UNDERLINE + std::to_string(state));
        }
    }
}

bool InnerBundleInfo::GetOverlayModuleState(const std::string &moduleName, int32_t userId, int32_t &state) const
{
    APP_LOGD("start to get overlay state of moduleName:%{public}s, userId:%{public}d", moduleName.c_str(), userId);
    if (userId == ServiceConstants::NOT_EXIST_USERID) {
        APP_LOGE("invalid userId %{public}d", userId);
        return false;
    }
    auto& key = NameAndUserIdToKey(GetBundleName(), userId);
    auto infoItem = innerBundleUserInfos_.find(key);
    if (infoItem == innerBundleUserInfos_.end()) {
        APP_LOGE("no userInfo under userId %{public}d", userId);
        return false;
    }

    auto overlayModulesState = infoItem->second.bundleUserInfo.overlayModulesState;
    if (overlayModulesState.empty()) {
        APP_LOGE("no overlay module installed under userId %{public}d", userId);
        return false;
    }
    for (const auto &item : overlayModulesState) {
        auto pos = item.find(moduleName + Constants::FILE_UNDERLINE);
        if (pos == std::string::npos) {
            continue;
        }
        return OHOS::StrToInt(item.substr(moduleName.length() + 1), state);
    }
    APP_LOGE("no overlay module installed under userId %{public}d", userId);
    return false;
}

void InnerBundleInfo::ClearOverlayModuleStates(const std::string &moduleName)
{
    // delete overlay module state
    for (auto &innerUserInfo : innerBundleUserInfos_) {
        auto &overlayStates = innerUserInfo.second.bundleUserInfo.overlayModulesState;
        auto iter = std::find_if(overlayStates.begin(), overlayStates.end(), [&moduleName](const auto &item) {
            if (item.find(moduleName + Constants::FILE_UNDERLINE) != std::string::npos) {
                return true;
            }
            return false;
        });
        if (iter != overlayStates.end()) {
            overlayStates.erase(iter);
        }
    }
}

ErrCode InnerBundleInfo::IsAbilityEnabledV9(const AbilityInfo &abilityInfo,
    int32_t userId, bool &isEnable, int32_t appIndex) const
{
    APP_LOGD("IsAbilityEnabled bundleName:%{public}s, userId:%{public}d", abilityInfo.bundleName.c_str(), userId);
    if (userId == ServiceConstants::NOT_EXIST_USERID) {
        isEnable = true;
        return ERR_OK;
    }
    auto& key = NameAndUserIdToKey(abilityInfo.bundleName, userId);
    auto infoItem = innerBundleUserInfos_.find(key);
    if (infoItem == innerBundleUserInfos_.end()) {
        APP_LOGW_NOFUNC("key:%{public}s not found", key.c_str());
        return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST;
    }
    if (appIndex == 0) {
        auto disabledAbilities = infoItem->second.bundleUserInfo.disabledAbilities;
        if (std::find(disabledAbilities.begin(), disabledAbilities.end(), abilityInfo.name)
            != disabledAbilities.end()) {
            APP_LOGE_NOFUNC("-n %{public}s -a %{public}s disabled",
                abilityInfo.bundleName.c_str(), abilityInfo.name.c_str());
            isEnable = false;
        } else {
            isEnable = true;
        }
        return ERR_OK;
    }
    const std::map<std::string, InnerBundleCloneInfo> &mpCloneInfos = infoItem->second.cloneInfos;
    std::string appIndexKey = InnerBundleUserInfo::AppIndexToKey(appIndex);
    if (mpCloneInfos.find(appIndexKey) == mpCloneInfos.end()) {
        APP_LOGW_NOFUNC("key:%{public}s not found", key.c_str());
        return ERR_APPEXECFWK_CLONE_QUERY_NO_CLONE_APP;
    }
    auto disabledAbilities = mpCloneInfos.at(appIndexKey).disabledAbilities;
    if (std::find(disabledAbilities.begin(), disabledAbilities.end(), abilityInfo.name)
        != disabledAbilities.end()) {
        APP_LOGE_NOFUNC("-n %{public}s -a %{public}s disabled",
            abilityInfo.bundleName.c_str(), abilityInfo.name.c_str());
        isEnable = false;
    } else {
        isEnable = true;
    }
    return ERR_OK;
}

ErrCode InnerBundleInfo::SetAbilityEnabled(
    const std::string &moduleName, const std::string &abilityName, bool isEnabled, int32_t userId)
{
    APP_LOGD("SetAbilityEnabled : %{public}s, %{public}s, %{public}d",
        moduleName.c_str(), abilityName.c_str(), userId);
    for (const auto &ability : baseAbilityInfos_) {
        if ((ability.second.name == abilityName) &&
            (moduleName.empty() || (ability.second.moduleName == moduleName))) {
            auto &key = NameAndUserIdToKey(GetBundleName(), userId);
            auto infoItem = innerBundleUserInfos_.find(key);
            if (infoItem == innerBundleUserInfos_.end()) {
                APP_LOGE("SetAbilityEnabled find innerBundleUserInfo failed");
                return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST;
            }

            auto iter = std::find(infoItem->second.bundleUserInfo.disabledAbilities.begin(),
                                  infoItem->second.bundleUserInfo.disabledAbilities.end(),
                                  abilityName);
            if (iter != infoItem->second.bundleUserInfo.disabledAbilities.end()) {
                if (isEnabled) {
                    infoItem->second.bundleUserInfo.disabledAbilities.erase(iter);
                }
            } else {
                if (!isEnabled) {
                    infoItem->second.bundleUserInfo.disabledAbilities.push_back(abilityName);
                }
            }
            return ERR_OK;
        }
    }
    APP_LOGE("SetAbilityEnabled find abilityInfo failed");
    return ERR_BUNDLE_MANAGER_ABILITY_NOT_EXIST;
}

ErrCode InnerBundleInfo::SetCloneAbilityEnabled(const std::string &moduleName, const std::string &abilityName,
    bool isEnabled, int32_t userId, int32_t appIndex)
{
    APP_LOGD("SetAbilityEnabled : %{public}s, %{public}s, %{public}d for appIndex %{public}d",
        moduleName.c_str(), abilityName.c_str(), userId, appIndex);
    for (const auto &ability : baseAbilityInfos_) {
        if ((ability.second.name == abilityName) &&
            (moduleName.empty() || (ability.second.moduleName == moduleName))) {
            auto &key = NameAndUserIdToKey(GetBundleName(), userId);
            auto infoItem = innerBundleUserInfos_.find(key);
            if (infoItem == innerBundleUserInfos_.end()) {
                APP_LOGE("SetAbilityEnabled find innerBundleUserInfo failed");
                return ERR_BUNDLE_MANAGER_INVALID_USER_ID;
            }

            auto cloneIter = infoItem->second.cloneInfos.find(std::to_string(appIndex));
            if (cloneIter == infoItem->second.cloneInfos.end()) {
                APP_LOGW("appIndex %{public}d invalid", appIndex);
                return ERR_APPEXECFWK_SANDBOX_INSTALL_INVALID_APP_INDEX;
            }

            auto iter = std::find(cloneIter->second.disabledAbilities.begin(),
                                  cloneIter->second.disabledAbilities.end(),
                                  abilityName);
            if (iter != cloneIter->second.disabledAbilities.end() && isEnabled) {
                cloneIter->second.disabledAbilities.erase(iter);
            }
            if (iter == cloneIter->second.disabledAbilities.end() && !isEnabled) {
                cloneIter->second.disabledAbilities.push_back(abilityName);
            }
            return ERR_OK;
        }
    }
    APP_LOGW("SetCloneAbilityEnabled find abilityInfo failed");
    return ERR_BUNDLE_MANAGER_ABILITY_NOT_EXIST;
}

void InnerBundleInfo::RemoveDuplicateName(std::vector<std::string> &name) const
{
    std::sort(name.begin(), name.end());
    auto iter = std::unique(name.begin(), name.end());
    name.erase(iter, name.end());
}

void InnerBundleInfo::SetInnerModuleNeedDelete(const std::string &moduleName, const bool needDelete)
{
    if (innerModuleInfos_.find(moduleName) == innerModuleInfos_.end()) {
        APP_LOGE("innerBundleInfo does not contain the module module %{public}s", moduleName.c_str());
        return;
    }
    innerModuleInfos_.at(moduleName).needDelete = needDelete;
}

bool InnerBundleInfo::GetInnerModuleNeedDelete(const std::string &moduleName)
{
    if (innerModuleInfos_.find(moduleName) == innerModuleInfos_.end()) {
        APP_LOGE("innerBundleInfo does not contain the module %{public}s", moduleName.c_str());
        return true;
    }
    return innerModuleInfos_.at(moduleName).needDelete;
}

std::vector<DefinePermission> InnerBundleInfo::GetAllDefinePermissions() const
{
    std::vector<DefinePermission> definePermissions;
    for (const auto &info : innerModuleInfos_) {
        if (info.second.needDelete) {
            continue;
        }
        std::transform(info.second.definePermissions.begin(),
            info.second.definePermissions.end(),
            std::back_inserter(definePermissions),
            [](const auto &p) { return p; });
    }
    if (!definePermissions.empty()) {
        std::sort(definePermissions.begin(), definePermissions.end(),
            [](DefinePermission defPermA, DefinePermission defPermB) {
                return defPermA.name < defPermB.name;
            });
        auto iter = std::unique(definePermissions.begin(), definePermissions.end(),
            [](DefinePermission defPermA, DefinePermission defPermB) {
                return defPermA.name == defPermB.name;
            });
        definePermissions.erase(iter, definePermissions.end());
    }
    return definePermissions;
}

std::vector<RequestPermission> InnerBundleInfo::GetAllRequestPermissions() const
{
    std::unordered_map<std::string, std::string> moduleNameMap;
    std::vector<RequestPermission> requestPermissions;
    for (const auto &info : innerModuleInfos_) {
        if (info.second.needDelete) {
            continue;
        }
        for (auto item : info.second.requestPermissions) {
            item.moduleName = info.second.moduleName;
            requestPermissions.push_back(item);
            if (moduleNameMap.find(item.moduleName) == moduleNameMap.end()) {
                moduleNameMap[item.moduleName] = info.second.distro.moduleType;
            }
        }
    }
    if (!requestPermissions.empty()) {
        InnerProcessRequestPermissions(moduleNameMap, requestPermissions);
    }
    return requestPermissions;
}

void InnerBundleInfo::InnerProcessRequestPermissions(
    const std::unordered_map<std::string, std::string> &moduleNameMap,
    std::vector<RequestPermission> &requestPermissions) const
{
    std::sort(requestPermissions.begin(), requestPermissions.end(),
        [&moduleNameMap](RequestPermission reqPermA, RequestPermission reqPermB) {
            if (reqPermA.name == reqPermB.name) {
                if ((reqPermA.reasonId == 0) || (reqPermB.reasonId == 0)) {
                    return reqPermA.reasonId > reqPermB.reasonId;
                }
                auto moduleTypeA = moduleNameMap.find(reqPermA.moduleName);
                if (moduleTypeA == moduleNameMap.end()) {
                    return reqPermA.reasonId > reqPermB.reasonId;
                }
                auto moduleTypeB = moduleNameMap.find(reqPermB.moduleName);
                if (moduleTypeB == moduleNameMap.end()) {
                    return reqPermA.reasonId > reqPermB.reasonId;
                }
                if ((moduleTypeA->second == Profile::MODULE_TYPE_ENTRY) &&
                    ((moduleTypeB->second == Profile::MODULE_TYPE_ENTRY))) {
                    return reqPermA.reasonId > reqPermB.reasonId;
                } else if (moduleTypeA->second == Profile::MODULE_TYPE_ENTRY) {
                    return true;
                } else if (moduleTypeB->second == Profile::MODULE_TYPE_ENTRY) {
                    return false;
                }
                if ((moduleTypeA->second == Profile::MODULE_TYPE_FEATURE) &&
                    ((moduleTypeB->second == Profile::MODULE_TYPE_FEATURE))) {
                    return reqPermA.reasonId > reqPermB.reasonId;
                } else if (moduleTypeA->second == Profile::MODULE_TYPE_FEATURE) {
                    return true;
                } else if (moduleTypeB->second == Profile::MODULE_TYPE_FEATURE) {
                    return false;
                }
                return reqPermA.reasonId > reqPermB.reasonId;
            }
            return reqPermA.name < reqPermB.name;
        });
    auto iter = std::unique(requestPermissions.begin(), requestPermissions.end(),
        [](RequestPermission reqPermA, RequestPermission reqPermB) {
            return reqPermA.name == reqPermB.name;
        });
    requestPermissions.erase(iter, requestPermissions.end());
}

ErrCode InnerBundleInfo::SetApplicationEnabled(bool enabled, const std::string &caller, int32_t userId)
{
    auto& key = NameAndUserIdToKey(GetBundleName(), userId);
    auto infoItem = innerBundleUserInfos_.find(key);
    if (infoItem == innerBundleUserInfos_.end()) {
        APP_LOGE("SetApplicationEnabled not find:%{public}s bundleUserInfo in userId: %{public}d",
            GetBundleName().c_str(), userId);
        return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST;
    }

    infoItem->second.bundleUserInfo.enabled = enabled;
    if (!caller.empty()) {
        infoItem->second.bundleUserInfo.setEnabledCaller = caller;
    }
    return ERR_OK;
}

ErrCode InnerBundleInfo::SetCloneApplicationEnabled(bool enabled, int32_t appIndex, const std::string &caller,
    int32_t userId)
{
    auto& key = NameAndUserIdToKey(GetBundleName(), userId);
    auto infoItem = innerBundleUserInfos_.find(key);
    if (infoItem == innerBundleUserInfos_.end()) {
        APP_LOGE_NOFUNC("SetCloneApplicationEnabled not find:%{public}s bundleUserInfo in userId:%{public}d",
            GetBundleName().c_str(), userId);
        return ERR_BUNDLE_MANAGER_INVALID_USER_ID;
    }

    auto iter = infoItem->second.cloneInfos.find(std::to_string(appIndex));
    if (iter == infoItem->second.cloneInfos.end()) {
        APP_LOGE_NOFUNC("SetCloneApplicationEnabled not find:%{public}d appIndex in userId:%{public}d",
            appIndex, userId);
        return ERR_APPEXECFWK_SANDBOX_INSTALL_INVALID_APP_INDEX;
    }
    iter->second.enabled = enabled;
    iter->second.setEnabledCaller = caller;
    return ERR_OK;
}

const std::string InnerBundleInfo::GetCurModuleName() const
{
    if (innerModuleInfos_.find(currentPackage_) != innerModuleInfos_.end()) {
        return innerModuleInfos_.at(currentPackage_).moduleName;
    }

    return Constants::EMPTY_STRING;
}

bool InnerBundleInfo::IsBundleRemovable() const
{
    if (IsPreInstallApp()) {
        APP_LOGE("PreInstallApp should not be cleaned");
        return false;
    }

    for (const auto &innerModuleInfo : innerModuleInfos_) {
        if (!innerModuleInfo.second.installationFree) {
            return false;
        }

        for (const auto &stateIter : innerModuleInfo.second.isRemovable) {
            if (!stateIter.second) {
                return false;
            }
        }
    }

    return true;
}

int64_t InnerBundleInfo::GetLastInstallationTime() const
{
    int64_t installTime = 0;
    for (const auto &innerBundleUserInfo : innerBundleUserInfos_) {
        installTime = innerBundleUserInfo.second.updateTime > installTime ?
            innerBundleUserInfo.second.updateTime : installTime;
    }

    return installTime;
}

bool InnerBundleInfo::GetRemovableModules(std::vector<std::string> &moduleToDelete) const
{
    for (const auto &innerModuleInfo : innerModuleInfos_) {
        if (!innerModuleInfo.second.installationFree) {
            continue;
        }

        bool canDelete = true;
        for (const auto &stateIter : innerModuleInfo.second.isRemovable) {
            if (!stateIter.second) {
                canDelete = false;
                break;
            }
        }

        if (canDelete) {
            moduleToDelete.emplace_back(innerModuleInfo.second.moduleName);
        }
    }

    return !moduleToDelete.empty();
}

bool InnerBundleInfo::GetFreeInstallModules(std::vector<std::string> &freeInstallModule) const
{
    for (const auto &innerModuleInfo : innerModuleInfos_) {
        if (!innerModuleInfo.second.installationFree) {
            continue;
        }

        freeInstallModule.emplace_back(innerModuleInfo.second.moduleName);
    }

    return !freeInstallModule.empty();
}

bool InnerBundleInfo::IsUserExistModule(const std::string &moduleName, int32_t userId) const
{
    APP_LOGD("userId:%{public}d moduleName:%{public}s", userId, moduleName.c_str());
    auto modInfoItem = GetInnerModuleInfoByModuleName(moduleName);
    if (!modInfoItem) {
        APP_LOGE("get InnerModuleInfo by moduleName(%{public}s) failed", moduleName.c_str());
        return false;
    }

    auto item = modInfoItem->isRemovable.find(std::to_string(userId));
    if (item == modInfoItem->isRemovable.end()) {
        APP_LOGE("-u %{public}d has not -m %{public}s", userId, moduleName.c_str());
        return false;
    }

    APP_LOGD("userId:%{public}d exist moduleName:%{public}s", userId, moduleName.c_str());
    return true;
}

ErrCode InnerBundleInfo::IsModuleRemovable(
    const std::string &moduleName, int32_t userId, bool &isRemovable) const
{
    APP_LOGD("userId:%{public}d moduleName:%{public}s", userId, moduleName.c_str());
    auto modInfoItem = GetInnerModuleInfoByModuleName(moduleName);
    if (!modInfoItem) {
        APP_LOGE("get InnerModuleInfo by moduleName(%{public}s) failed", moduleName.c_str());
        return ERR_BUNDLE_MANAGER_MODULE_NOT_EXIST;
    }

    auto item = modInfoItem->isRemovable.find(std::to_string(userId));
    if (item == modInfoItem->isRemovable.end()) {
        APP_LOGW("userId:%{public}d not moduleName:%{public}s", userId, moduleName.c_str());
        isRemovable = false;
        return ERR_OK;
    }

    isRemovable = item->second;
    APP_LOGD("userId:%{public}d, moduleName:%{public}s, isRemovable:%{public}d,",
        userId, moduleName.c_str(), isRemovable);
    return ERR_OK;
}

bool InnerBundleInfo::AddModuleRemovableInfo(
    InnerModuleInfo &info, const std::string &stringUserId, bool isEnable) const
{
    auto item = info.isRemovable.find(stringUserId);
    if (item == info.isRemovable.end()) {
        auto result = info.isRemovable.try_emplace(stringUserId, isEnable);
        if (!result.second) {
            APP_LOGE("add userId:%{public}s isRemovable:%{public}d failed", stringUserId.c_str(), isEnable);
            return false;
        }

        APP_LOGD("add userId:%{public}s isRemovable:%{public}d into map", stringUserId.c_str(), isEnable);
        return true;
    }

    item->second = isEnable;
    APP_LOGD("set userId:%{public}s isEnable:%{public}d ok", stringUserId.c_str(), isEnable);
    return true;
}

bool InnerBundleInfo::SetModuleRemovable(const std::string &moduleName, bool isEnable, int32_t userId)
{
    std::string stringUserId = std::to_string(userId);
    APP_LOGD("userId:%{public}d moduleName:%{public}s isEnable:%{public}d", userId, moduleName.c_str(), isEnable);
    for (auto &innerModuleInfo : innerModuleInfos_) {
        if (innerModuleInfo.second.moduleName == moduleName) {
            return AddModuleRemovableInfo(innerModuleInfo.second, stringUserId, isEnable);
        }
    }

    return false;
}

ErrCode InnerBundleInfo::UpdateAppEncryptedStatus(const std::string &bundleName, bool isExisted, int32_t appIndex)
{
    APP_LOGI("update encrypted key %{public}s %{public}d %{public}d", bundleName.c_str(), isExisted, appIndex);
    if (isExisted) {
        // Set the second bit to 1
        SetApplicationReservedFlag(static_cast<uint32_t>(ApplicationReservedFlag::ENCRYPTED_KEY_EXISTED));
    } else {
        // Set the second bit to 0
        ClearApplicationReservedFlag(static_cast<uint32_t>(ApplicationReservedFlag::ENCRYPTED_KEY_EXISTED));
    }
    return ERR_OK;
}

void InnerBundleInfo::DeleteModuleRemovableInfo(InnerModuleInfo &info, const std::string &stringUserId)
{
    auto item = info.isRemovable.find(stringUserId);
    if (item == info.isRemovable.end()) {
        return;
    }

    info.isRemovable.erase(stringUserId);
}

void InnerBundleInfo::DeleteModuleRemovable(const std::string &moduleName, int32_t userId)
{
    std::string stringUserId = std::to_string(userId);
    APP_LOGD("userId:%{public}d moduleName:%{public}s", userId, moduleName.c_str());
    for (auto &innerModuleInfo : innerModuleInfos_) {
        if (innerModuleInfo.second.moduleName == moduleName) {
            DeleteModuleRemovableInfo(innerModuleInfo.second, stringUserId);
            return;
        }
    }
}

ErrCode InnerBundleInfo::SetModuleUpgradeFlag(std::string moduleName, int32_t upgradeFlag)
{
    APP_LOGD("moduleName= %{public}s, upgradeFlag = %{public}d", moduleName.c_str(), upgradeFlag);
    for (auto &innerModuleInfo : innerModuleInfos_) {
        if (innerModuleInfo.second.moduleName == moduleName) {
            innerModuleInfo.second.upgradeFlag = upgradeFlag;
            return ERR_OK;
        }
    }
    return ERR_BUNDLE_MANAGER_MODULE_NOT_EXIST;
}

int32_t InnerBundleInfo::GetModuleUpgradeFlag(std::string moduleName) const
{
    auto moduleInfo = GetInnerModuleInfoByModuleName(moduleName);
    if (!moduleInfo) {
        APP_LOGE("get InnerModuleInfo by moduleName(%{public}s) failed", moduleName.c_str());
        return UpgradeFlag::NOT_UPGRADE;
    }
    APP_LOGD("innerModuleInfo.upgradeFlag : %{public}d", moduleInfo->upgradeFlag);
    return moduleInfo->upgradeFlag;
}

int32_t InnerBundleInfo::GetResponseUserId(int32_t requestUserId) const
{
    if (innerBundleUserInfos_.empty()) {
        APP_LOGD("user map is empty");
        return Constants::INVALID_USERID;
    }

    if (requestUserId == Constants::ANY_USERID) {
        return innerBundleUserInfos_.begin()->second.bundleUserInfo.userId;
    }

    if (HasInnerBundleUserInfo(requestUserId)) {
        return requestUserId;
    }

    if (requestUserId < Constants::START_USERID) {
        APP_LOGD("requestUserId(%{public}d) less than start userId", requestUserId);
        return Constants::INVALID_USERID;
    }

    int32_t responseUserId = Constants::INVALID_USERID;
    for (const auto &innerBundleUserInfo : innerBundleUserInfos_) {
        if (innerBundleUserInfo.second.bundleUserInfo.userId < Constants::START_USERID) {
            responseUserId = innerBundleUserInfo.second.bundleUserInfo.userId;
            break;
        }
    }

    APP_LOGD("requestUserId(%{public}d) and responseUserId(%{public}d)", requestUserId, responseUserId);
    return responseUserId;
}

bool InnerBundleInfo::GetDependentModuleNames(const std::string &moduleName,
    std::vector<std::string> &dependentModuleNames) const
{
    for (auto iter = innerModuleInfos_.begin(); iter != innerModuleInfos_.end(); ++iter) {
        if (iter->second.moduleName == moduleName) {
            for (const auto &dependency : iter->second.dependencies) {
                dependentModuleNames.push_back(dependency.moduleName);
            }
            return true;
        }
    }
    APP_LOGE("GetDependentModuleNames not find module %{public}s", moduleName.c_str());
    return false;
}

bool InnerBundleInfo::GetAllDependentModuleNames(const std::string &moduleName,
    std::vector<std::string> &dependentModuleNames) const
{
    if (!GetDependentModuleNames(moduleName, dependentModuleNames)) {
        return false;
    }
    std::deque<std::string> moduleDeque;
    std::copy(dependentModuleNames.begin(), dependentModuleNames.end(), std::back_inserter(moduleDeque));
    dependentModuleNames.clear();
    while (!moduleDeque.empty()) {
        std::string name = moduleDeque.front();
        moduleDeque.pop_front();
        if (std::find(dependentModuleNames.begin(), dependentModuleNames.end(), name) == dependentModuleNames.end()) {
            dependentModuleNames.push_back(name);
            std::vector<std::string> tempModuleNames;
            if (GetDependentModuleNames(name, tempModuleNames)) {
                std::copy(tempModuleNames.begin(), tempModuleNames.end(), std::back_inserter(moduleDeque));
            }
        }
    }
    return true;
}

std::string InnerBundleInfo::GetMainAbility() const
{
    AbilityInfo abilityInfo;
    GetMainAbilityInfo(abilityInfo);
    return abilityInfo.name;
}

void InnerBundleInfo::GetMainAbilityInfo(AbilityInfo &abilityInfo) const
{
    for (const auto& item : innerModuleInfos_) {
        const std::string& key = item.second.entryAbilityKey;
        if (!key.empty() && (baseAbilityInfos_.count(key) != 0)) {
            abilityInfo = baseAbilityInfos_.at(key);
            if (item.second.isEntry) {
                return;
            }
        }
    }
}

bool InnerBundleInfo::HasEntry() const
{
    return std::any_of(innerModuleInfos_.begin(), innerModuleInfos_.end(), [](const auto &item) {
            return item.second.isEntry;
        });
}

bool InnerBundleInfo::IsHsp() const
{
    if (!innerModuleInfos_.empty()) {
        return std::all_of(innerModuleInfos_.begin(), innerModuleInfos_.end(), [](const auto &item) {
            return item.second.distro.moduleType == Profile::MODULE_TYPE_SHARED;
        });
    }
    return false;
}

void InnerBundleInfo::SetAppDistributionType(const std::string &appDistributionType)
{
    baseApplicationInfo_->appDistributionType = appDistributionType;
}

std::string InnerBundleInfo::GetAppDistributionType() const
{
    return baseApplicationInfo_->appDistributionType;
}

void InnerBundleInfo::SetAppProvisionType(const std::string &appProvisionType)
{
    baseApplicationInfo_->appProvisionType = appProvisionType;
}

std::string InnerBundleInfo::GetAppProvisionType() const
{
    return baseApplicationInfo_->appProvisionType;
}

void InnerBundleInfo::SetAppCrowdtestDeadline(int64_t crowdtestDeadline)
{
    baseApplicationInfo_->crowdtestDeadline = crowdtestDeadline;
}

int64_t InnerBundleInfo::GetAppCrowdtestDeadline() const
{
    return baseApplicationInfo_->crowdtestDeadline;
}

std::vector<std::string> InnerBundleInfo::GetDistroModuleName() const
{
    std::vector<std::string> moduleVec;
    for (const auto &item : innerModuleInfos_) {
        moduleVec.push_back(item.second.moduleName);
    }
    return moduleVec;
}

std::string InnerBundleInfo::GetModuleNameByPackage(const std::string &packageName) const
{
    auto it = innerModuleInfos_.find(packageName);
    if (it == innerModuleInfos_.end()) {
        return Constants::EMPTY_STRING;
    }
    return it->second.moduleName;
}

std::string InnerBundleInfo::GetModuleTypeByPackage(const std::string &packageName) const
{
    auto it = innerModuleInfos_.find(packageName);
    if (it == innerModuleInfos_.end()) {
        return Constants::EMPTY_STRING;
    }
    return it->second.distro.moduleType;
}

AppQuickFix InnerBundleInfo::GetAppQuickFix() const
{
    return baseApplicationInfo_->appQuickFix;
}

void InnerBundleInfo::SetAppQuickFix(const AppQuickFix &appQuickFix)
{
    baseApplicationInfo_->appQuickFix = appQuickFix;
    if (appQuickFix.deployedAppqfInfo.hqfInfos.empty() && appQuickFix.deployingAppqfInfo.hqfInfos.empty()) {
        baseApplicationInfo_->appQuickFix.bundleName = Constants::EMPTY_STRING;
        baseApplicationInfo_->appQuickFix.versionCode = 0;
        baseApplicationInfo_->appQuickFix.versionName = Constants::EMPTY_STRING;
    }
    SetQuickFixHqfInfos(appQuickFix.deployedAppqfInfo.hqfInfos);
}

std::vector<HqfInfo> InnerBundleInfo::GetQuickFixHqfInfos() const
{
    return hqfInfos_;
}

void InnerBundleInfo::SetQuickFixHqfInfos(const std::vector<HqfInfo> &hqfInfos)
{
    hqfInfos_ = hqfInfos;
}

bool InnerBundleInfo::FetchNativeSoAttrs(
    const std::string &requestPackage, std::string &cpuAbi, std::string &nativeLibraryPath) const
{
    auto moduleIter = innerModuleInfos_.find(requestPackage);
    if (moduleIter == innerModuleInfos_.end()) {
        APP_LOGE("requestPackage(%{public}s) not exist", requestPackage.c_str());
        return false;
    }

    auto &moduleInfo = moduleIter->second;
    if (!moduleInfo.compressNativeLibs) {
        cpuAbi = moduleInfo.cpuAbi;
        nativeLibraryPath = moduleInfo.nativeLibraryPath;
        return !nativeLibraryPath.empty();
    }

    if (moduleInfo.isLibIsolated) {
        cpuAbi = moduleInfo.cpuAbi;
        nativeLibraryPath = moduleInfo.nativeLibraryPath;
    } else {
        cpuAbi = baseApplicationInfo_->cpuAbi;
        nativeLibraryPath = baseApplicationInfo_->nativeLibraryPath;
    }

    return !nativeLibraryPath.empty();
}

bool InnerBundleInfo::IsLibIsolated(const std::string &moduleName) const
{
    auto moduleInfo = GetInnerModuleInfoByModuleName(moduleName);
    if (!moduleInfo) {
        APP_LOGE("Get moduleInfo(%{public}s) failed", moduleName.c_str());
        return false;
    }

    return moduleInfo->isLibIsolated;
}

std::vector<std::string> InnerBundleInfo::GetDeviceType(const std::string &packageName) const
{
    auto it = innerModuleInfos_.find(packageName);
    if (it == innerModuleInfos_.end()) {
        APP_LOGW("%{public}s not existed", packageName.c_str());
        return std::vector<std::string>();
    }
    return innerModuleInfos_.at(packageName).deviceTypes;
}

void InnerBundleInfo::AddApplyQuickFixFrequency()
{
    ++applyQuickFixFrequency_;
}

int32_t InnerBundleInfo::GetApplyQuickFixFrequency() const
{
    return applyQuickFixFrequency_;
}

void InnerBundleInfo::ResetApplyQuickFixFrequency()
{
    applyQuickFixFrequency_ = 0;
}

std::vector<uint32_t> InnerBundleInfo::GetAllHspVersion() const
{
    std::vector<uint32_t> versionCodes;
    for (const auto &[moduleName, modules] : innerSharedModuleInfos_) {
        for (const auto &module : modules) {
            if (std::find(versionCodes.begin(), versionCodes.end(), module.versionCode) == versionCodes.end()) {
                versionCodes.emplace_back(module.versionCode);
            }
        }
    }
    return versionCodes;
}

void InnerBundleInfo::DeleteHspModuleByVersion(int32_t versionCode)
{
    for (auto modulesIt = innerSharedModuleInfos_.begin(); modulesIt != innerSharedModuleInfos_.end();) {
        if (modulesIt->second.size() == SINGLE_HSP_VERSION &&
            modulesIt->second.front().versionCode == static_cast<uint32_t>(versionCode)) {
            modulesIt = innerSharedModuleInfos_.erase(modulesIt);
        } else {
            modulesIt->second.erase(
                std::remove_if(modulesIt->second.begin(), modulesIt->second.end(),
                    [versionCode] (InnerModuleInfo &module) {
                        return module.versionCode == static_cast<uint32_t>(versionCode);
                    }));
            ++modulesIt;
        }
    }
}

ErrCode InnerBundleInfo::GetProxyDataInfos(
    const std::string &moduleName, std::vector<ProxyData> &proxyDatas) const
{
    if (moduleName == Constants::EMPTY_STRING) {
        GetAllProxyDataInfos(proxyDatas);
        return ERR_OK;
    }
    auto moduleIt = std::find_if(innerModuleInfos_.begin(), innerModuleInfos_.end(), [&moduleName](const auto &info) {
        return info.second.moduleName == moduleName;
    });
    if (moduleIt != innerModuleInfos_.end()) {
        proxyDatas.insert(
            proxyDatas.end(), moduleIt->second.proxyDatas.begin(), moduleIt->second.proxyDatas.end());
    } else {
        APP_LOGE("moduleName %{public}s not found", moduleName.c_str());
        return ERR_BUNDLE_MANAGER_MODULE_NOT_EXIST;
    }
    if (proxyDatas.empty()) {
        APP_LOGW("proxyDatas is empty");
    }
    return ERR_OK;
}

void InnerBundleInfo::GetAllProxyDataInfos(std::vector<ProxyData> &proxyDatas) const
{
    for (const auto &innerModuleInfo : innerModuleInfos_) {
        proxyDatas.insert(
            proxyDatas.end(), innerModuleInfo.second.proxyDatas.begin(), innerModuleInfo.second.proxyDatas.end());
    }
}

IsolationMode InnerBundleInfo::GetIsolationMode(const std::string &isolationMode) const
{
    auto isolationModeRes = ISOLATION_MODE_MAP.find(isolationMode);
    if (isolationModeRes != ISOLATION_MODE_MAP.end()) {
        return isolationModeRes->second;
    } else {
        return IsolationMode::NONISOLATION_FIRST;
    }
}

void InnerBundleInfo::SetModuleHapPath(const std::string &hapPath)
{
    if (innerModuleInfos_.count(currentPackage_) == 1) {
        innerModuleInfos_.at(currentPackage_).hapPath = hapPath;
        for (auto &abilityInfo : baseAbilityInfos_) {
            abilityInfo.second.hapPath = hapPath;
        }
        for (auto &extensionInfo : baseExtensionInfos_) {
            extensionInfo.second.hapPath = hapPath;
        }
        if (!innerModuleInfos_.at(currentPackage_).compressNativeLibs &&
            !innerModuleInfos_.at(currentPackage_).nativeLibraryPath.empty()) {
            auto pos = hapPath.rfind(ServiceConstants::PATH_SEPARATOR);
            if (pos != std::string::npos) {
                innerModuleInfos_.at(currentPackage_).nativeLibraryPath =
                    hapPath.substr(pos + 1, hapPath.length() - pos - 1) + NATIVE_LIBRARY_PATH_SYMBOL +
                    innerModuleInfos_.at(currentPackage_).nativeLibraryPath;
                return;
            }
            innerModuleInfos_.at(currentPackage_).nativeLibraryPath =
                hapPath + NATIVE_LIBRARY_PATH_SYMBOL + innerModuleInfos_.at(currentPackage_).nativeLibraryPath;
        }
    }
}

bool InnerBundleInfo::IsCompressNativeLibs(const std::string &moduleName) const
{
    auto moduleInfo = GetInnerModuleInfoByModuleName(moduleName);
    if (!moduleInfo) {
        APP_LOGE("Get moduleInfo(%{public}s) failed", moduleName.c_str());
        return true; // compressNativeLibs default true
    }

    return moduleInfo->compressNativeLibs;
}

void InnerBundleInfo::SetNativeLibraryFileNames(const std::string &moduleName,
    const std::vector<std::string> &fileNames)
{
    if (innerModuleInfos_.find(moduleName) == innerModuleInfos_.end()) {
        APP_LOGE("innerBundleInfo not contain the module: %{public}s", moduleName.c_str());
        return;
    }
    innerModuleInfos_.at(moduleName).nativeLibraryFileNames = fileNames;
}

void InnerBundleInfo::UpdateSharedModuleInfo()
{
    auto sharedModuleInfoIter = innerSharedModuleInfos_.find(currentPackage_);
    auto moduleInfoIter = innerModuleInfos_.find(currentPackage_);
    if ((sharedModuleInfoIter == innerSharedModuleInfos_.end()) ||
        (moduleInfoIter == innerModuleInfos_.end())) {
        APP_LOGE("The shared module(%{public}s) infomation not exist", currentPackage_.c_str());
        return;
    }
    auto &innerModuleInfoVector = sharedModuleInfoIter->second;
    for (auto iter = innerModuleInfoVector.begin(); iter != innerModuleInfoVector.end(); ++iter) {
        if (iter->versionCode == moduleInfoIter->second.versionCode) {
            iter->hapPath = moduleInfoIter->second.hapPath;
            iter->compressNativeLibs = moduleInfoIter->second.compressNativeLibs;
            iter->cpuAbi = moduleInfoIter->second.cpuAbi;
            iter->nativeLibraryPath = moduleInfoIter->second.nativeLibraryPath;
            iter->nativeLibraryFileNames = moduleInfoIter->second.nativeLibraryFileNames;
            return;
        }
    }
}

ErrCode InnerBundleInfo::SetExtName(
    const std::string &moduleName, const std::string &abilityName, const std::string extName)
{
    auto abilityInfoPair = baseAbilityInfos_.find(abilityName);
    if (abilityInfoPair == baseAbilityInfos_.end()) {
        APP_LOGE("ability %{public}s not exists", abilityName.c_str());
        return ERR_BUNDLE_MANAGER_ABILITY_NOT_EXIST;
    }
    if (moduleName != abilityInfoPair->second.moduleName) {
        APP_LOGE("module %{public}s not exists", moduleName.c_str());
        return ERR_BUNDLE_MANAGER_MODULE_NOT_EXIST;
    }
    auto &supportExtNames = abilityInfoPair->second.supportExtNames;
    bool duplicated = std::any_of(supportExtNames.begin(), supportExtNames.end(), [&extName](const auto &name) {
            return extName == name;
    });
    if (duplicated) {
        APP_LOGW("extName %{public}s already exist in ability %{public}s", extName.c_str(), abilityName.c_str());
        return ERR_BUNDLE_MANAGER_DUPLICATED_EXT_OR_TYPE;
    }
    supportExtNames.emplace_back(extName);
    return ERR_OK;
}

ErrCode InnerBundleInfo::SetMimeType(
    const std::string &moduleName, const std::string &abilityName, const std::string mimeType)
{
    auto abilityInfoPair = baseAbilityInfos_.find(abilityName);
    if (abilityInfoPair == baseAbilityInfos_.end()) {
        APP_LOGE("ability %{public}s not exists", abilityName.c_str());
        return ERR_BUNDLE_MANAGER_ABILITY_NOT_EXIST;
    }
    if (moduleName != abilityInfoPair->second.moduleName) {
        APP_LOGE("module %{public}s not exists", moduleName.c_str());
        return ERR_BUNDLE_MANAGER_MODULE_NOT_EXIST;
    }
    auto &supportMimeTypes = abilityInfoPair->second.supportMimeTypes;
    bool duplicated = std::any_of(supportMimeTypes.begin(), supportMimeTypes.end(), [&mimeType](const auto &type) {
            return mimeType == type;
    });
    if (duplicated) {
        APP_LOGW("MIME type %{public}s already exist in ability %{public}s", mimeType.c_str(), abilityName.c_str());
        return ERR_BUNDLE_MANAGER_DUPLICATED_EXT_OR_TYPE;
    }
    abilityInfoPair->second.supportMimeTypes.emplace_back(mimeType);
    return ERR_OK;
}

ErrCode InnerBundleInfo::DelExtName(
    const std::string &moduleName, const std::string &abilityName, const std::string extName)
{
    auto abilityInfoPair = baseAbilityInfos_.find(abilityName);
    if (abilityInfoPair == baseAbilityInfos_.end()) {
        APP_LOGE("ability %{public}s not exists", abilityName.c_str());
        return ERR_BUNDLE_MANAGER_ABILITY_NOT_EXIST;
    }
    if (moduleName != abilityInfoPair->second.moduleName) {
        APP_LOGE("module %{public}s not exists", moduleName.c_str());
        return ERR_BUNDLE_MANAGER_MODULE_NOT_EXIST;
    }
    auto &supportExtNames = abilityInfoPair->second.supportExtNames;
    supportExtNames.erase(std::remove(supportExtNames.begin(), supportExtNames.end(), extName), supportExtNames.end());
    return ERR_OK;
}

ErrCode InnerBundleInfo::DelMimeType(
    const std::string &moduleName, const std::string &abilityName, const std::string mimeType)
{
    auto abilityInfoPair = baseAbilityInfos_.find(abilityName);
    if (abilityInfoPair == baseAbilityInfos_.end()) {
        APP_LOGE("ability %{public}s not exists", abilityName.c_str());
        return ERR_BUNDLE_MANAGER_ABILITY_NOT_EXIST;
    }
    if (moduleName != abilityInfoPair->second.moduleName) {
        APP_LOGE("module %{public}s not exists", moduleName.c_str());
        return ERR_BUNDLE_MANAGER_MODULE_NOT_EXIST;
    }
    auto &supportMimeTypes = abilityInfoPair->second.supportMimeTypes;
    supportMimeTypes.erase(
        std::remove(supportMimeTypes.begin(), supportMimeTypes.end(), mimeType), supportMimeTypes.end());
    return ERR_OK;
}

ErrCode InnerBundleInfo::GetAppServiceHspInfo(BundleInfo &bundleInfo) const
{
    if (baseApplicationInfo_->bundleType != BundleType::APP_SERVICE_FWK) {
        APP_LOGW("%{public}s is not app service", GetBundleName().c_str());
        return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST;
    }
    bundleInfo = *baseBundleInfo_;
    bundleInfo.applicationInfo = *baseApplicationInfo_;
    for (const auto &info : innerModuleInfos_) {
        if (info.second.distro.moduleType == Profile::MODULE_TYPE_SHARED) {
            auto hapmoduleinfo = FindHapModuleInfo(info.second.modulePackage, Constants::ALL_USERID);
            if (hapmoduleinfo) {
                HapModuleInfo hapModuleInfo = *hapmoduleinfo;
                hapModuleInfo.moduleSourceDir = hapModuleInfo.hapPath.empty() ?
                    info.second.modulePath : hapModuleInfo.moduleSourceDir;
                bundleInfo.hapModuleInfos.emplace_back(hapModuleInfo);
            }
        }
    }
    if (bundleInfo.hapModuleInfos.empty()) {
        APP_LOGE("bundleName:%{public}s no hsp module info", baseApplicationInfo_->bundleName.c_str());
        return ERR_BUNDLE_MANAGER_MODULE_NOT_EXIST;
    }
    return ERR_OK;
}

void InnerBundleInfo::HandleOTACodeEncryption(std::vector<std::string> &withoutKeyBundles,
    std::vector<std::string> &withKeyBundles) const
{
    BundleType bundleType = GetApplicationBundleType();
    if (bundleType != BundleType::APP && bundleType != BundleType::ATOMIC_SERVICE) {
        return;
    }
    if ((GetApplicationReservedFlag() & static_cast<uint32_t>(ApplicationReservedFlag::ENCRYPTED_APPLICATION))
        != static_cast<uint32_t>(ApplicationReservedFlag::ENCRYPTED_APPLICATION)) {
        return;
    }
    if (innerBundleUserInfos_.empty()) {
        APP_LOGE("user empty");
        return;
    }
    CodeProtectBundleInfo codeProtectBundleInfo;
    codeProtectBundleInfo.bundleName = GetBundleName();
    codeProtectBundleInfo.versionCode = GetVersionCode();
    codeProtectBundleInfo.applicationReservedFlag = GetApplicationReservedFlag();
    codeProtectBundleInfo.uid = innerBundleUserInfos_.begin()->second.uid;
    codeProtectBundleInfo.appIdentifier = GetAppIdentifier();
    std::vector<CodeProtectBundleInfo> codeProtectBundleInfos { codeProtectBundleInfo };
    BmsExtensionDataMgr bmsExtensionDataMgr;
    auto res = bmsExtensionDataMgr.KeyOperation(codeProtectBundleInfos, CodeOperation::OTA_CHECK);
    if (res != ERR_OK) {
        APP_LOGE("ota check for %{public}s failed", GetBundleName().c_str());
        if (res != CPM_KEY_NOT_EXIST) {
            return;
        }
        withoutKeyBundles.emplace_back(GetBundleName());
    } else {
        withKeyBundles.emplace_back(GetBundleName());
    }
    CheckEncryptionParam checkEncryptionParam;
    checkEncryptionParam.bundleId = innerBundleUserInfos_.begin()->second.uid -
        innerBundleUserInfos_.begin()->second.bundleUserInfo.userId * Constants::BASE_USER_RANGE;
    checkEncryptionParam.appIdentifier = GetAppIdentifier();
    checkEncryptionParam.versionCode = GetVersionCode();
    APP_LOGI("start");
    for (const auto &item : innerModuleInfos_) {
        CheckHapEncryption(checkEncryptionParam, item.second);
        CheckSoEncryption(checkEncryptionParam, item.first, item.second);
    }
    APP_LOGI("end");
}

void InnerBundleInfo::CheckHapEncryption(const CheckEncryptionParam &checkEncryptionParam,
    const InnerModuleInfo &moduleInfo) const
{
    CheckEncryptionParam param { checkEncryptionParam };
    param.modulePath = moduleInfo.hapPath;
    param.isCompressNativeLibrary = moduleInfo.compressNativeLibs;
    param.installBundleType =
        moduleInfo.distro.moduleType == Profile::MODULE_TYPE_SHARED ?
        InstallBundleType::INTER_APP_HSP : InstallBundleType::HAP;
    bool isEncrypted = false;
    ErrCode result = InstalldClient::GetInstance()->CheckEncryption(param, isEncrypted);
    if (result != ERR_OK) {
        APP_LOGE("fail, error: %{public}d", result);
    }
}

void InnerBundleInfo::CheckSoEncryption(const CheckEncryptionParam &checkEncryptionParam,
    const std::string &requestPackage, const InnerModuleInfo &moduleInfo) const
{
    bool isCompressNativeLibrary = moduleInfo.compressNativeLibs;
    if (!isCompressNativeLibrary) {
        return;
    }
    std::string cpuAbi;
    std::string nativeLibraryPath;
    if (!FetchNativeSoAttrs(requestPackage, cpuAbi, nativeLibraryPath)) {
        APP_LOGE("fetch %{public}s failed", requestPackage.c_str());
        return;
    }
    std::string targetSoPath;
    targetSoPath.append(Constants::BUNDLE_CODE_DIR).append(ServiceConstants::PATH_SEPARATOR).append(GetBundleName())
        .append(ServiceConstants::PATH_SEPARATOR).append(nativeLibraryPath).append(ServiceConstants::PATH_SEPARATOR);
    CheckEncryptionParam param { checkEncryptionParam };
    param.modulePath = moduleInfo.hapPath;
    param.cpuAbi = cpuAbi;
    param.isCompressNativeLibrary = isCompressNativeLibrary;
    param.installBundleType =
        moduleInfo.distro.moduleType == Profile::MODULE_TYPE_SHARED ?
        InstallBundleType::INTER_APP_HSP : InstallBundleType::HAP;
    param.targetSoPath = targetSoPath;
    bool isEncrypted = false;
    ErrCode result = InstalldClient::GetInstance()->CheckEncryption(param, isEncrypted);
    if (result != ERR_OK) {
        APP_LOGE("fail, error: %{public}d", result);
    }
}

void InnerBundleInfo::UpdateIsCompressNativeLibs()
{
    if (innerModuleInfos_.empty()) {
        baseApplicationInfo_->isCompressNativeLibs = true;
        return;
    }
    baseApplicationInfo_->isCompressNativeLibs = false;
    for (const auto &info : innerModuleInfos_) {
        baseApplicationInfo_->isCompressNativeLibs =
            (baseApplicationInfo_->isCompressNativeLibs || info.second.compressNativeLibs) ? true : false;
    }
}

void InnerBundleInfo::SetResourcesApply(const std::vector<int32_t> &resourcesApply)
{
    baseApplicationInfo_->resourcesApply = resourcesApply;
}

void InnerBundleInfo::InnerProcessShortcut(const Shortcut &oldShortcut, ShortcutInfo &shortcutInfo) const
{
    shortcutInfo.id = oldShortcut.shortcutId;
    shortcutInfo.icon = oldShortcut.icon;
    shortcutInfo.label = oldShortcut.label;
    shortcutInfo.iconId = oldShortcut.iconId;
    if (shortcutInfo.iconId == 0) {
        auto iter = oldShortcut.icon.find(PORT_SEPARATOR);
        if (iter != std::string::npos) {
            shortcutInfo.iconId = static_cast<uint32_t>(atoi(oldShortcut.icon.substr(iter + 1).c_str()));
        }
    }
    shortcutInfo.labelId = oldShortcut.labelId;
    if (shortcutInfo.labelId == 0) {
        auto iter = oldShortcut.label.find(PORT_SEPARATOR);
        if (iter != std::string::npos) {
            shortcutInfo.labelId = static_cast<uint32_t>(atoi(oldShortcut.label.substr(iter + 1).c_str()));
        }
    }
    for (const ShortcutWant &shortcutWant : oldShortcut.wants) {
        ShortcutIntent shortcutIntent;
        shortcutIntent.targetBundle = shortcutWant.bundleName;
        shortcutIntent.targetModule = shortcutWant.moduleName;
        shortcutIntent.targetClass = shortcutWant.abilityName;
        shortcutIntent.parameters = shortcutWant.parameters;
        shortcutInfo.intents.emplace_back(shortcutIntent);
    }
}

std::string InnerBundleInfo::GetEntryModuleName() const
{
    for (const auto &item : innerModuleInfos_) {
        if (item.second.isEntry) {
            return item.second.modulePackage;
        }
    }
    return Constants::EMPTY_STRING;
}

void InnerBundleInfo::SetMoudleIsEncrpted(const std::string &packageName, bool isEncrypted)
{
    auto it = innerModuleInfos_.find(packageName);
    if (it == innerModuleInfos_.end()) {
        return;
    }
    it->second.isEncrypted = isEncrypted;
}

bool InnerBundleInfo::IsEncryptedMoudle(const std::string &packageName) const
{
    auto it = innerModuleInfos_.find(packageName);
    if (it == innerModuleInfos_.end()) {
        return false;
    }
    return it->second.isEncrypted;
}

void InnerBundleInfo::GetAllEncryptedModuleNames(std::vector<std::string> &moduleNames) const
{
    for (const auto &info : innerModuleInfos_) {
        if (info.second.isEncrypted) {
            moduleNames.emplace_back(info.second.moduleName);
        }
    }
}

bool InnerBundleInfo::IsContainEncryptedModule() const
{
    for (const auto &info : innerModuleInfos_) {
        if (info.second.isEncrypted) {
            return true;
        }
    }
    return false;
}

std::string InnerBundleInfo::GetAppIdentifier() const
{
    return baseBundleInfo_->signatureInfo.appIdentifier;
}

void InnerBundleInfo::SetAppIdentifier(const std::string &appIdentifier)
{
    baseBundleInfo_->signatureInfo.appIdentifier = appIdentifier;
}

void InnerBundleInfo::SetCertificate(const std::string &certificate)
{
    baseBundleInfo_->signatureInfo.certificate = certificate;
}

std::string InnerBundleInfo::GetCertificate() const
{
    return baseBundleInfo_->signatureInfo.certificate;
}

void InnerBundleInfo::UpdateDebug(const InnerBundleInfo &newInfo)
{
    std::string moduleName = newInfo.GetCurrentModulePackage();
    auto it = innerModuleInfos_.find(moduleName);
    if (it != innerModuleInfos_.end()) {
        it->second.debug = newInfo.GetBaseApplicationInfo().debug;
    }
    if (newInfo.HasEntry()) {
        baseApplicationInfo_->debug = newInfo.GetBaseApplicationInfo().debug;
    } else if (!HasEntry()) {
        baseApplicationInfo_->debug =
            newInfo.GetBaseApplicationInfo().debug || GetDebugFromModules(innerModuleInfos_);
    }
}

bool InnerBundleInfo::GetDebugFromModules(const std::map<std::string, InnerModuleInfo> &innerModuleInfos)
{
    bool debug = false;
    for (const auto &item : innerModuleInfos) {
        if (item.second.isEntry) {
            return item.second.debug;
        } else {
            debug = debug || item.second.debug;
        }
    }
    return debug;
}

void InnerBundleInfo::AddOldAppId(const std::string &appId)
{
    auto appIds = baseBundleInfo_->oldAppIds;
    if (std::find(appIds.begin(), appIds.end(), appId) == appIds.end()) {
        baseBundleInfo_->oldAppIds.emplace_back(appId);
    }
}

std::vector<std::string> InnerBundleInfo::GetOldAppIds() const
{
    return baseBundleInfo_->oldAppIds;
}

std::vector<std::string> InnerBundleInfo::GetQuerySchemes() const
{
    std::string entryModuleName = GetEntryModuleName();
    auto it = innerModuleInfos_.find(entryModuleName);
    if (it == innerModuleInfos_.end()) {
        return std::vector<std::string>();
    }
    std::vector<std::string> querySchemes = innerModuleInfos_.at(entryModuleName).querySchemes;
    for (size_t i = 0; i < querySchemes.size(); i++) {
        transform(querySchemes[i].begin(), querySchemes[i].end(), querySchemes[i].begin(), ::tolower);
    }
    return querySchemes;
}

void InnerBundleInfo::UpdateOdid(const std::string &developerId, const std::string &odid)
{
    developerId_ = developerId;
    odid_ = odid;
}

void InnerBundleInfo::UpdateOdidByBundleInfo(const InnerBundleInfo &info)
{
    std::string developerId;
    std::string odid;
    info.GetDeveloperidAndOdid(developerId, odid);
    developerId_ = developerId;
    odid_ = odid;
}

void InnerBundleInfo::GetDeveloperidAndOdid(std::string &developerId, std::string &odid) const
{
    developerId = developerId_;
    odid = odid_;
}

void InnerBundleInfo::GetOdid(std::string &odid) const
{
    odid = odid_;
}

void InnerBundleInfo::AddAllowedAcls(const std::vector<std::string> &allowedAcls)
{
    for (const auto &acl : allowedAcls) {
        if (!acl.empty() && (std::find(allowedAcls_.begin(), allowedAcls_.end(), acl) == allowedAcls_.end())) {
            allowedAcls_.emplace_back(acl);
        }
    }
}

bool InnerBundleInfo::IsAsanEnabled() const
{
    for (const auto &item : innerModuleInfos_) {
        if (item.second.asanEnabled) {
            return true;
        }
    }
    for (const auto &[moduleName, modules] : innerSharedModuleInfos_) {
        for (const auto &module : modules) {
            if (module.asanEnabled) {
                return true;
            }
        }
    }
    return false;
}

bool InnerBundleInfo::IsGwpAsanEnabled() const
{
    for (const auto &item : innerModuleInfos_) {
        if (item.second.gwpAsanEnabled) {
            return true;
        }
    }
    for (const auto &[moduleName, modules] : innerSharedModuleInfos_) {
        for (const auto &module : modules) {
            if (module.gwpAsanEnabled) {
                return true;
            }
        }
    }
    return false;
}

bool InnerBundleInfo::IsTsanEnabled() const
{
    for (const auto &item : innerModuleInfos_) {
        if (item.second.tsanEnabled) {
            return true;
        }
    }
    for (const auto &[moduleName, modules] : innerSharedModuleInfos_) {
        for (const auto &module : modules) {
            if (module.tsanEnabled) {
                return true;
            }
        }
    }
    return false;
}

bool InnerBundleInfo::IsHwasanEnabled() const
{
    bool hwasanEnabled = false;
    for (const auto &item : innerModuleInfos_) {
        hwasanEnabled = static_cast<bool>(item.second.innerModuleInfoFlag &
            GetSanitizerFlag(GetInnerModuleInfoFlag::GET_INNER_MODULE_INFO_WITH_HWASANENABLED));
        if (hwasanEnabled) {
            return true;
        }
    }
    for (const auto &[moduleName, modules] : innerSharedModuleInfos_) {
        for (const auto &module : modules) {
            hwasanEnabled = static_cast<bool>(module.innerModuleInfoFlag &
                GetSanitizerFlag(GetInnerModuleInfoFlag::GET_INNER_MODULE_INFO_WITH_HWASANENABLED));
            if (hwasanEnabled) {
                return true;
            }
        }
    }
    return false;
}

bool InnerBundleInfo::IsUbsanEnabled() const
{
    bool ubsanEnabled = false;
    for (const auto &item : innerModuleInfos_) {
        ubsanEnabled = static_cast<bool>(item.second.innerModuleInfoFlag &
            GetSanitizerFlag(GetInnerModuleInfoFlag::GET_INNER_MODULE_INFO_WITH_UBSANENABLED));
        if (ubsanEnabled) {
            return true;
        }
    }
    for (const auto &[moduleName, modules] : innerSharedModuleInfos_) {
        for (const auto &module : modules) {
            ubsanEnabled = static_cast<bool>(module.innerModuleInfoFlag &
                GetSanitizerFlag(GetInnerModuleInfoFlag::GET_INNER_MODULE_INFO_WITH_UBSANENABLED));
            if (ubsanEnabled) {
                return true;
            }
        }
    }
    return false;
}

bool InnerBundleInfo::GetUninstallState() const
{
    return uninstallState_;
}

void InnerBundleInfo::SetUninstallState(const bool &uninstallState)
{
    uninstallState_ = uninstallState;
}

bool InnerBundleInfo::IsNeedSendNotify() const
{
    return isNeedSendNotify_;
}

void InnerBundleInfo::SetNeedSendNotify(const bool needStatus)
{
    isNeedSendNotify_ = needStatus;
}

std::vector<std::string> InnerBundleInfo::GetAllExtensionDirsInSpecifiedModule(const std::string &moduleName) const
{
    std::vector<std::string> dirVec;
    auto extensionInfoMap = GetInnerExtensionInfos();
    for (auto item : extensionInfoMap) {
        if (item.second.moduleName != moduleName || !item.second.needCreateSandbox) {
            continue;
        }
        std::string dir = ServiceConstants::EXTENSION_DIR + item.second.moduleName +
            ServiceConstants::FILE_SEPARATOR_LINE + item.second.name +
            ServiceConstants::FILE_SEPARATOR_PLUS + item.second.bundleName;
        dirVec.emplace_back(dir);
    }
    return dirVec;
}

std::vector<std::string> InnerBundleInfo::GetAllExtensionDirs() const
{
    std::vector<std::string> dirVec;
    auto extensionInfoMap = GetInnerExtensionInfos();
    for (auto item : extensionInfoMap) {
        if (!item.second.needCreateSandbox) {
            continue;
        }
        // eg: +extension-entry-inputMethodExtAbility+com.example.myapplication
        std::string dir = ServiceConstants::EXTENSION_DIR + item.second.moduleName +
            ServiceConstants::FILE_SEPARATOR_LINE + item.second.name +
            ServiceConstants::FILE_SEPARATOR_PLUS + item.second.bundleName;
        dirVec.emplace_back(dir);
    }
    return dirVec;
}

void InnerBundleInfo::SetApplicationFlags(ApplicationInfoFlag flag)
{
    uint32_t applicationFlags = static_cast<uint32_t>(baseApplicationInfo_->applicationFlags);
    uint32_t installSourceFlag = static_cast<uint32_t>(flag);
    baseApplicationInfo_->applicationFlags =
        static_cast<int32_t>((applicationFlags & PREINSTALL_SOURCE_CLEAN_MASK) | installSourceFlag);
}

void InnerBundleInfo::UpdateExtensionSandboxInfo(const std::vector<std::string> &typeList)
{
    for (auto &extensionItem : baseExtensionInfos_) {
        extensionItem.second.needCreateSandbox = false;
        std::string typeName = extensionItem.second.extensionTypeName;
        auto it = std::find(typeList.begin(), typeList.end(), typeName);
        if (it != typeList.end()) {
            extensionItem.second.needCreateSandbox = true;
        }
    }
}

void InnerBundleInfo::UpdateExtensionDataGroupInfo(
    const std::string &key, const std::vector<std::string>& dataGroupIds)
{
    auto it = baseExtensionInfos_.find(key);
    if (it == baseExtensionInfos_.end()) {
        APP_LOGW("UpdateExtensionDataGroupInfo not find key: %{public}s", key.c_str());
        return;
    }
    it->second.validDataGroupIds = dataGroupIds;
}

void InnerBundleInfo::AddDataGroupInfo(const std::string &dataGroupId, const DataGroupInfo &info)
{
    APP_LOGD("AddDataGroupInfo, dataGroupId: %{public}s, dataGroupInfo: %{public}s",
        dataGroupId.c_str(), info.ToString().c_str());
    auto dataGroupInfosItem = dataGroupInfos_.find(dataGroupId);
    if (dataGroupInfosItem == dataGroupInfos_.end()) {
        APP_LOGD("AddDataGroupInfo add new dataGroupInfo for dataGroupId: %{public}s", dataGroupId.c_str());
        dataGroupInfos_[dataGroupId] = std::vector<DataGroupInfo> { info };
        return;
    }
    int32_t userId = info.userId;
    auto iter = std::find_if(std::begin(dataGroupInfos_[dataGroupId]), std::end(dataGroupInfos_[dataGroupId]),
        [userId](const DataGroupInfo &dataGroupinfo) { return dataGroupinfo.userId == userId; });
    if (iter != std::end(dataGroupInfos_[dataGroupId])) {
        if ((iter->uid == info.uid) && (iter->uuid == info.uuid)) {
            return;
        }
        APP_LOGW("uid or uuid not same, dataGroupId: %{public}s", dataGroupId.c_str());
        dataGroupInfos_[dataGroupId].erase(iter);
    }
    APP_LOGD("AddDataGroupInfo add new dataGroupInfo for user: %{public}d", info.userId);
    dataGroupInfos_[dataGroupId].emplace_back(info);
}

ErrCode InnerBundleInfo::AddCloneBundle(const InnerBundleCloneInfo &attr)
{
    int32_t userId = attr.userId;
    int32_t appIndex = attr.appIndex;
    const std::string key = NameAndUserIdToKey(GetBundleName(), userId);
    if (innerBundleUserInfos_.find(key) == innerBundleUserInfos_.end()) {
        APP_LOGE("Add Clone Bundle Fail, userId: %{public}d not found in bundleName: %{public}s",
            userId, GetBundleName().c_str());
        return ERR_APPEXECFWK_CLONE_INSTALL_USER_NOT_EXIST;
    }
    InnerBundleUserInfo &userInfo = innerBundleUserInfos_.find(key)->second;
    std::map<std::string, InnerBundleCloneInfo> &cloneInfos = userInfo.cloneInfos;

    if (appIndex < ServiceConstants::CLONE_APP_INDEX_MIN || appIndex > ServiceConstants::CLONE_APP_INDEX_MAX) {
        APP_LOGE("Add Clone Bundle Fail, appIndex: %{public}d not in valid range", appIndex);
        return ERR_APPEXECFWK_CLONE_INSTALL_INVALID_APP_INDEX;
    }
    std::string appIndexKey = InnerBundleUserInfo::AppIndexToKey(appIndex);
    if (cloneInfos.find(appIndexKey) != cloneInfos.end()) {
        APP_LOGE("Add Clone Bundle Fail, appIndex: %{public}d existed", appIndex);
        return ERR_APPEXECFWK_CLONE_INSTALL_APP_INDEX_EXISTED;
    }

    InnerBundleCloneInfo cloneInfo;
    cloneInfo.userId = userId;
    cloneInfo.appIndex = appIndex;
    // copy from user
    cloneInfo.enabled = userInfo.bundleUserInfo.enabled;
    cloneInfo.disabledAbilities = userInfo.bundleUserInfo.disabledAbilities;
    cloneInfo.accessTokenId = attr.accessTokenId;
    cloneInfo.accessTokenIdEx = attr.accessTokenIdEx;
    cloneInfo.uid = attr.uid;
    cloneInfo.gids = attr.gids;
    int64_t now = BundleUtil::GetCurrentTime();
    cloneInfo.installTime = now;
    cloneInfos[appIndexKey] = cloneInfo;
    APP_LOGD("Add clone app userId: %{public}d appIndex: %{public}d in bundle: %{public}s",
        userId, appIndex, GetBundleName().c_str());
    return ERR_OK;
}

ErrCode InnerBundleInfo::RemoveCloneBundle(const int32_t userId, const int32_t appIndex)
{
    const std::string key = NameAndUserIdToKey(GetBundleName(), userId);
    if (innerBundleUserInfos_.find(key) == innerBundleUserInfos_.end()) {
        APP_LOGE("Remove Clone Bundle Fail, userId: %{public}d not found in bundleName: %{public}s",
            userId, GetBundleName().c_str());
        return ERR_APPEXECFWK_CLONE_INSTALL_USER_NOT_EXIST;
    }
    InnerBundleUserInfo &userInfo = innerBundleUserInfos_.find(key)->second;
    std::map<std::string, InnerBundleCloneInfo> &cloneInfos = userInfo.cloneInfos;

    if (appIndex < ServiceConstants::CLONE_APP_INDEX_MIN || appIndex > ServiceConstants::CLONE_APP_INDEX_MAX) {
        APP_LOGE("Remove Clone Bundle Fail, appIndex: %{public}d not in valid range", appIndex);
        return ERR_APPEXECFWK_CLONE_INSTALL_INVALID_APP_INDEX;
    }
    std::string appIndexKey = InnerBundleUserInfo::AppIndexToKey(appIndex);
    if (cloneInfos.find(appIndexKey) == cloneInfos.end()) {
        APP_LOGD("appIndex: %{public}d not found", appIndex);
        return ERR_OK;
    }
    cloneInfos.erase(appIndexKey);
    APP_LOGD("Remove clone app userId: %{public}d appIndex: %{public}d in bundle: %{public}s",
        userId, appIndex, GetBundleName().c_str());
    return ERR_OK;
}

ErrCode InnerBundleInfo::GetAvailableCloneAppIndex(const int32_t userId, int32_t &appIndex)
{
    const std::string key = NameAndUserIdToKey(GetBundleName(), userId);
    if (innerBundleUserInfos_.find(key) == innerBundleUserInfos_.end()) {
        return ERR_APPEXECFWK_CLONE_INSTALL_USER_NOT_EXIST;
    }
    InnerBundleUserInfo &userInfo = innerBundleUserInfos_.find(key)->second;
    std::map<std::string, InnerBundleCloneInfo> &cloneInfos = userInfo.cloneInfos;

    int32_t candidateAppIndex = 1;
    while (cloneInfos.find(InnerBundleUserInfo::AppIndexToKey(candidateAppIndex)) != cloneInfos.end()) {
        candidateAppIndex++;
    }
    appIndex = candidateAppIndex;
    return ERR_OK;
}

ErrCode InnerBundleInfo::IsCloneAppIndexExisted(const int32_t userId, const int32_t appIndex, bool &res)
{
    const std::string key = NameAndUserIdToKey(GetBundleName(), userId);
    if (innerBundleUserInfos_.find(key) == innerBundleUserInfos_.end()) {
        return ERR_APPEXECFWK_CLONE_INSTALL_USER_NOT_EXIST;
    }
    InnerBundleUserInfo &userInfo = innerBundleUserInfos_.find(key)->second;
    std::map<std::string, InnerBundleCloneInfo> &cloneInfos = userInfo.cloneInfos;

    res = cloneInfos.find(InnerBundleUserInfo::AppIndexToKey(appIndex)) != cloneInfos.end();
    return ERR_OK;
}

bool InnerBundleInfo::GetApplicationInfoAdaptBundleClone(
    const InnerBundleUserInfo &innerBundleUserInfo,
    int32_t appIndex,
    ApplicationInfo &appInfo) const
{
    if (appIndex == 0 || appIndex > Constants::INITIAL_SANDBOX_APP_INDEX) {
        if (appInfo.removable && !innerBundleUserInfo.isRemovable) {
            appInfo.removable = false;
        }

        appInfo.accessTokenId = innerBundleUserInfo.accessTokenId;
        appInfo.accessTokenIdEx = innerBundleUserInfo.accessTokenIdEx;
        appInfo.enabled = innerBundleUserInfo.bundleUserInfo.enabled;
        appInfo.uid = innerBundleUserInfo.uid;
        return true;
    }
    APP_LOGD("start appIndex: %{public}d", appIndex);
    auto iter = innerBundleUserInfo.cloneInfos.find(std::to_string(appIndex));
    if (iter == innerBundleUserInfo.cloneInfos.end()) {
        APP_LOGE("appIndex %{public}d not exist", appIndex);
        return false;
    }
    appInfo.accessTokenId = iter->second.accessTokenId;
    appInfo.accessTokenIdEx = iter->second.accessTokenIdEx;
    appInfo.enabled = iter->second.enabled;
    appInfo.uid = iter->second.uid;
    appInfo.appIndex = iter->second.appIndex;
    return true;
}

bool InnerBundleInfo::GetBundleInfoAdaptBundleClone(
    const InnerBundleUserInfo &innerBundleUserInfo,
    int32_t appIndex,
    BundleInfo &bundleInfo) const
{
    if (appIndex == 0 || appIndex > Constants::INITIAL_SANDBOX_APP_INDEX) {
        bundleInfo.uid = innerBundleUserInfo.uid;
        if (!innerBundleUserInfo.gids.empty()) {
            bundleInfo.gid = innerBundleUserInfo.gids[0];
        }
        bundleInfo.installTime = innerBundleUserInfo.installTime;
        bundleInfo.updateTime = innerBundleUserInfo.updateTime;
        bundleInfo.appIndex = appIndex_;
        return true;
    }
    APP_LOGD("start appIndex: %{public}d", appIndex);
    auto iter = innerBundleUserInfo.cloneInfos.find(std::to_string(appIndex));
    if (iter == innerBundleUserInfo.cloneInfos.end()) {
        APP_LOGE("appIndex %{public}d not exist", appIndex);
        return false;
    }
    bundleInfo.uid = iter->second.uid;
    bundleInfo.gid = iter->second.uid; // no gids, need add
    bundleInfo.installTime = iter->second.installTime;
    bundleInfo.updateTime = innerBundleUserInfo.updateTime;
    bundleInfo.appIndex = appIndex;
    return true;
}

ErrCode InnerBundleInfo::VerifyAndAckCloneAppIndex(int32_t userId, int32_t &appIndex)
{
    auto multiAppModeData = this->baseApplicationInfo_->multiAppMode;
    if (multiAppModeData.multiAppModeType != MultiAppModeType::APP_CLONE) {
        APP_LOGE("bundleName:%{public}s is not clone app", GetBundleName().c_str());
        return ERR_APPEXECFWK_CLONE_INSTALL_APP_NOT_SUPPORTED_MULTI_TYPE;
    }

    if (appIndex < 0) {
        APP_LOGE("appIndex:%{public}d not in valid range", appIndex);
        return ERR_APPEXECFWK_CLONE_INSTALL_INVALID_APP_INDEX;
    }
    if (appIndex == 0) {
        ErrCode availableRes = GetAvailableCloneAppIndex(userId, appIndex);
        if (availableRes != ERR_OK) {
            APP_LOGE("Get Available Clone AppIndex Fail for, errCode: %{public}d", availableRes);
            return availableRes;
        }
    } else {
        bool found = false;
        ErrCode isExistedRes = IsCloneAppIndexExisted(userId, appIndex, found);
        if (isExistedRes != ERR_OK) {
            return isExistedRes;
        }
        if (found) {
            APP_LOGE("AppIndex %{public}d existed in userId %{public}d", appIndex, userId);
            return ERR_APPEXECFWK_CLONE_INSTALL_APP_INDEX_EXISTED;
        }
    }
    int32_t maxCount = std::min(multiAppModeData.maxCount, ServiceConstants::CLONE_APP_INDEX_MAX);
    if (appIndex > maxCount) {
        APP_LOGE("AppIndex %{public}d exceed max limit %{public}d in userId: %{public}d",
            appIndex, maxCount, userId);
        return ERR_APPEXECFWK_CLONE_INSTALL_APP_INDEX_EXCEED_MAX_NUMBER;
    }
    return ERR_OK;
}

void InnerBundleInfo::UpdateMultiAppMode(const InnerBundleInfo &newInfo)
{
    std::string moduleType = newInfo.GetModuleTypeByPackage(newInfo.GetCurrentModulePackage());
    if (moduleType == Profile::MODULE_TYPE_ENTRY || moduleType == Profile::MODULE_TYPE_FEATURE) {
        baseApplicationInfo_->multiAppMode = newInfo.GetBaseApplicationInfo().multiAppMode;
    }
}

void InnerBundleInfo::UpdateReleaseType(const InnerBundleInfo &newInfo)
{
    if (baseBundleInfo_->releaseType.empty() ||
        baseApplicationInfo_->apiReleaseType.empty() ||
        !newInfo.IsHsp()) {
        baseBundleInfo_->releaseType = newInfo.GetBaseBundleInfo().releaseType;
        baseApplicationInfo_->apiReleaseType = newInfo.GetBaseApplicationInfo().apiReleaseType;
    }
}

void InnerBundleInfo::AdaptMainLauncherResourceInfo(ApplicationInfo &applicationInfo) const
{
    if (ServiceConstants::ALLOW_MULTI_ICON_BUNDLE.find(GetBundleName()) !=
        ServiceConstants::ALLOW_MULTI_ICON_BUNDLE.end()) {
        return;
    }
    AbilityInfo mainAbilityInfo;
    GetMainAbilityInfo(mainAbilityInfo);
    if ((mainAbilityInfo.labelId != 0) && (mainAbilityInfo.iconId != 0)) {
        applicationInfo.labelId = mainAbilityInfo.labelId ;
        applicationInfo.labelResource.id = mainAbilityInfo.labelId;
        applicationInfo.labelResource.moduleName = mainAbilityInfo.moduleName;
        applicationInfo.labelResource.bundleName = mainAbilityInfo.bundleName;

        applicationInfo.iconId = mainAbilityInfo.iconId ;
        applicationInfo.iconResource.id = mainAbilityInfo.iconId;
        applicationInfo.iconResource.moduleName = mainAbilityInfo.moduleName;
        applicationInfo.iconResource.bundleName = mainAbilityInfo.bundleName;
    }
}

std::set<int32_t> InnerBundleInfo::GetCloneBundleAppIndexes() const
{
    std::set<int32_t> appIndexes;
    for (const auto &innerBundleUserInfo : innerBundleUserInfos_) {
        for (const auto &cloneInfo : innerBundleUserInfo.second.cloneInfos) {
            appIndexes.insert(cloneInfo.second.appIndex);
        }
    }
    return appIndexes;
}

uint8_t InnerBundleInfo::GetSanitizerFlag(GetInnerModuleInfoFlag flag)
{
    return 1 << (static_cast<uint8_t>(flag) - 1);
}

void InnerBundleInfo::PrintSetEnabledInfo(bool isEnabled, int32_t userId, int32_t appIndex,
    const std::string &bundleName, const std::string &caller) const
{
    if (!isEnabled) {
        APP_LOGW_NOFUNC("-n %{public}s -u %{public}d -i %{public}d disabled caller is %{public}s",
            bundleName.c_str(), userId, appIndex, caller.c_str());
    }
}

void InnerBundleInfo::SetDFXParamStatus()
{
    SetAsanEnabled(IsAsanEnabled());
    SetGwpAsanEnabled(IsGwpAsanEnabled());
    SetTsanEnabled(IsTsanEnabled());
    SetHwasanEnabled(IsHwasanEnabled());
    SetUbsanEnabled(IsUbsanEnabled());
}
}  // namespace AppExecFwk
}  // namespace OHOS
