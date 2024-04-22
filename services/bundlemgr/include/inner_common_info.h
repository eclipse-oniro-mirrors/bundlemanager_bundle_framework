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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_INNER_COMMON_INFO_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_INNER_COMMON_INFO_H

#include "nocopyable.h"

#include "ability_info.h"
#include "access_token.h"
#include "bundle_constants.h"
#include "bundle_info.h"
#include "common_event_info.h"
#include "common_profile.h"
#include "data_group_info.h"
#include "distributed_bundle_info.h"
#include "extension_ability_info.h"
#include "form_info.h"
#include "hap_module_info.h"
#include "json_util.h"
#include "shortcut_info.h"
#include "want.h"

namespace OHOS {
namespace AppExecFwk {
struct Distro {
    bool deliveryWithInstall = false;
    std::string moduleName;
    std::string moduleType;
    bool installationFree = false;
};

struct DefinePermission {
    std::string name;
    std::string grantMode = Profile::DEFINEPERMISSION_GRANT_MODE_SYSTEM_GRANT;
    std::string availableLevel = Profile::DEFINEPERMISSION_AVAILABLE_LEVEL_DEFAULT_VALUE;
    bool provisionEnable = true;
    bool distributedSceneEnable = false;
    std::string label;
    int32_t labelId = 0;
    std::string description;
    int32_t descriptionId = 0;
    std::string availableType;
};

struct InnerModuleInfo {
    std::string name;
    std::string modulePackage;
    std::string moduleName;
    std::string modulePath;
    std::string moduleDataDir;
    std::string moduleResPath;
    std::string label;
    std::string hapPath;
    int32_t labelId = 0;
    std::string description;
    int32_t descriptionId = 0;
    std::string icon;
    int32_t iconId = 0;
    std::string mainAbility; // config.json : mainAbility; module.json : mainElement
    std::string entryAbilityKey; // skills contains "action.system.home" and "entity.system.home"
    std::string srcPath;
    std::string hashValue;
    bool isEntry = false;
    bool installationFree = false;
    // all user's value of isRemovable
    // key:userId
    // value:isRemovable true or flase
    std::map<std::string, bool> isRemovable;
    MetaData metaData;
    ModuleColorMode colorMode = ModuleColorMode::AUTO;
    Distro distro;
    std::vector<std::string> reqCapabilities;
    std::vector<std::string> abilityKeys;
    std::vector<std::string> skillKeys;
    // new version fields
    std::string pages;
    std::string process;
    std::string srcEntrance;
    std::string uiSyntax;
    std::string virtualMachine;
    bool isModuleJson = false;
    bool isStageBasedModel = false;
    std::vector<DefinePermission> definePermissions;
    std::vector<RequestPermission> requestPermissions;
    std::vector<std::string> deviceTypes;
    std::vector<std::string> extensionKeys;
    std::vector<std::string> extensionSkillKeys;
    std::vector<Metadata> metadata;
    int32_t upgradeFlag = 0;
    std::vector<Dependency> dependencies;
    std::string compileMode;
    bool isLibIsolated = false;
    std::string nativeLibraryPath;
    std::string cpuAbi;
    std::string targetModuleName;
    int32_t targetPriority;
    std::vector<OverlayModuleInfo> overlayModuleInfo;
    std::vector<std::string> preloads;
    BundleType bundleType = BundleType::SHARED;
    uint32_t versionCode = 0;
    std::string versionName;
    std::vector<ProxyData> proxyDatas;
    std::string buildHash;
    std::string isolationMode;
    bool compressNativeLibs = true;
    std::vector<std::string> nativeLibraryFileNames;
    AOTCompileStatus aotCompileStatus = AOTCompileStatus::NOT_COMPILED;
    std::string fileContextMenu;
    bool isEncrypted = false;
    std::vector<std::string> querySchemes;
    std::string routerMap;
    std::vector<AppEnvironment> appEnvironments;
    bool asanEnabled = false;
    bool gwpAsanEnabled = false;
    std::string packageName;
    std::string appStartup;
};

struct SkillUri {
    std::string scheme;
    std::string host;
    std::string port;
    std::string path;
    std::string pathStartWith;
    std::string pathRegex;
    std::string type;
    std::string utd;
    int32_t maxFileSupported = 0;
    std::string linkFeature;
};

struct Skill {
public:
    std::vector<std::string> actions;
    std::vector<std::string> entities;
    std::vector<SkillUri> uris;
    bool domainVerify = false;
    bool Match(const OHOS::AAFwk::Want &want) const;
    bool Match(const OHOS::AAFwk::Want &want, size_t &matchUriIndex) const;
    bool MatchLauncher(const OHOS::AAFwk::Want &want) const;
    bool MatchType(const std::string &type, const std::string &skillUriType) const;
    bool MatchUtd(const std::string &utd, int32_t count) const;
private:
    bool MatchAction(const std::string &action) const;
    bool MatchEntities(const std::vector<std::string> &paramEntities) const;
    bool MatchActionAndEntities(const OHOS::AAFwk::Want &want) const;
    bool MatchUriAndType(const std::string &uriString, const std::string &type) const;
    bool MatchUriAndType(const std::string &uriString, const std::string &type, size_t &matchUriIndex) const;
    bool MatchUri(const std::string &uriString, const SkillUri &skillUri) const;
    bool StartsWith(const std::string &sourceString, const std::string &targetPrefix) const;
    bool MatchMimeType(const std::string &uriString) const;
    bool MatchMimeType(const std::string &uriString, size_t &matchUriIndex) const;
    bool MatchUtd(const OHOS::AAFwk::Want &want);
    std::string GetOptParamUri(const std::string &uriString) const;
};

enum InstallExceptionStatus : int32_t {
    INSTALL_START = 1,
    INSTALL_FINISH,
    UPDATING_EXISTED_START,
    UPDATING_NEW_START,
    UPDATING_FINISH,
    UNINSTALL_BUNDLE_START,
    UNINSTALL_PACKAGE_START,
    UNKNOWN_STATUS,
};

struct InstallMark {
    std::string bundleName;
    std::string packageName;
    int32_t status = InstallExceptionStatus::UNKNOWN_STATUS;
};

void from_json(const nlohmann::json &jsonObject, InnerModuleInfo &info);
void from_json(const nlohmann::json &jsonObject, SkillUri &uri);
void from_json(const nlohmann::json &jsonObject, Skill &skill);
void from_json(const nlohmann::json &jsonObject, Distro &distro);
void from_json(const nlohmann::json &jsonObject, InstallMark &installMark);
void from_json(const nlohmann::json &jsonObject, DefinePermission &definePermission);
void from_json(const nlohmann::json &jsonObject, Dependency &dependency);
void from_json(const nlohmann::json &jsonObject, OverlayBundleInfo &overlayBundleInfo);
void to_json(nlohmann::json &jsonObject, const Distro &distro);
void to_json(nlohmann::json &jsonObject, const DefinePermission &definePermission);
void to_json(nlohmann::json &jsonObject, const Dependency &dependency);
void to_json(nlohmann::json &jsonObject, const InnerModuleInfo &info);
void to_json(nlohmann::json &jsonObject, const SkillUri &uri);
void to_json(nlohmann::json &jsonObject, const Skill &skill);
void to_json(nlohmann::json &jsonObject, const InstallMark &installMark);
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_INNER_COMMON_INFO_H
