/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef FOUNDATION_APPEXECFWK_INTERFACES_INNERKITS_APPEXECFWK_BASE_INCLUDE_HAP_MODULE_INFO_H
#define FOUNDATION_APPEXECFWK_INTERFACES_INNERKITS_APPEXECFWK_BASE_INCLUDE_HAP_MODULE_INFO_H

#include <string>

#include "ability_info.h"
#include "extension_ability_info.h"
#include "overlay/overlay_module_info.h"
#include "parcel.h"
#include "quick_fix/hqf_info.h"

namespace OHOS {
namespace AppExecFwk {
enum class ModuleColorMode {
    AUTO = -1,
    DARK,
    LIGHT,
};

enum class ModuleType {
    UNKNOWN = 0,
    ENTRY = 1,
    FEATURE = 2,
    SHARED = 3
};

enum class AtomicServiceModuleType {
    NORMAL = 0,
    MAIN = 1,
};

enum class IsolationMode {
    NONISOLATION_FIRST = 0,
    ISOLATION_FIRST = 1,
    ISOLATION_ONLY = 2,
    NONISOLATION_ONLY = 3,
};

enum class AOTCompileStatus {
    NOT_COMPILED = 0,
    COMPILE_SUCCESS = 1,
    COMPILE_FAILED = 2,
};

struct PreloadItem : public Parcelable {
    std::string moduleName;

    PreloadItem() = default;
    explicit PreloadItem(std::string name) : moduleName(name) {}
    bool ReadFromParcel(Parcel &parcel);
    virtual bool Marshalling(Parcel &parcel) const override;
    static PreloadItem *Unmarshalling(Parcel &parcel);
};

struct Dependency : public Parcelable {
    std::string bundleName;
    std::string moduleName;
    uint32_t versionCode = 0;

    bool ReadFromParcel(Parcel &parcel);
    virtual bool Marshalling(Parcel &parcel) const override;
    static Dependency *Unmarshalling(Parcel &parcel);
};

struct ProxyData : public Parcelable {
    std::string uri;
    std::string requiredReadPermission;
    std::string requiredWritePermission;
    Metadata metadata;

    bool ReadFromParcel(Parcel &parcel);
    virtual bool Marshalling(Parcel &parcel) const override;
    static ProxyData *Unmarshalling(Parcel &parcel);
};

struct RouterItem : public Parcelable {
    std::string name;
    std::string pageSourceFile;
    std::string buildFunction;
    std::map<std::string, std::string> data;
    std::string customData;
    std::string ohmurl;
    std::string bundleName;
    std::string moduleName;

    bool ReadFromParcel(Parcel &parcel);
    virtual bool Marshalling(Parcel &parcel) const override;
    static RouterItem *Unmarshalling(Parcel &parcel);
};

struct AppEnvironment : public Parcelable {
    std::string name;
    std::string value;

    bool ReadFromParcel(Parcel &parcel);
    virtual bool Marshalling(Parcel &parcel) const override;
    static AppEnvironment *Unmarshalling(Parcel &parcel);
};

// configuration information about an module
struct HapModuleInfo : public Parcelable {
    bool compressNativeLibs = true;
    bool isLibIsolated = false;
    uint32_t descriptionId = 0;
    uint32_t iconId = 0;
    uint32_t labelId = 0;
    int supportedModes = 0;
    std::string name;        // module.name in config.json
    std::string package;
    std::string moduleName;  // module.distro.moduleName in config.json
    std::string description;
    std::string iconPath;
    std::string label;
    std::string backgroundImg;
    std::string mainAbility;
    std::string srcPath;
    std::string hashValue;
    std::string hapPath;
    std::string nativeLibraryPath;
    std::string cpuAbi;
    std::vector<std::string> nativeLibraryFileNames;

    // quick fix hqf info
    HqfInfo hqfInfo;

    // overlay module info
    std::vector<OverlayModuleInfo> overlayModuleInfos;

    std::vector<std::string> reqCapabilities;
    std::vector<std::string> deviceTypes;
    std::vector<Dependency> dependencies;
    std::vector<AbilityInfo> abilityInfos;
    ModuleColorMode colorMode = ModuleColorMode::AUTO;
    // new version fields
    std::string bundleName;
    std::string mainElementName;
    std::string pages;
    std::string process;
    std::string resourcePath;
    std::string srcEntrance;
    std::string uiSyntax;
    std::string virtualMachine;
    bool deliveryWithInstall = false;
    bool installationFree = false;
    bool isModuleJson = false;
    bool isStageBasedModel = false;
    std::map<std::string, bool> isRemovable;
    ModuleType moduleType = ModuleType::UNKNOWN;
    std::vector<ExtensionAbilityInfo> extensionInfos;
    std::vector<Metadata> metadata;
    std::vector<ProxyData> proxyDatas;
    int32_t upgradeFlag = 0;
    CompileMode compileMode = CompileMode::JS_BUNDLE;
    std::string moduleSourceDir;
    std::vector<PreloadItem> preloads;
    std::string buildHash;
    IsolationMode isolationMode = IsolationMode::NONISOLATION_FIRST;
    AOTCompileStatus aotCompileStatus = AOTCompileStatus::NOT_COMPILED;
    std::string fileContextMenu;
    std::string routerMap;
    std::vector<RouterItem> routerArray;
    std::vector<AppEnvironment> appEnvironments;
    std::string packageName;
    bool ReadFromParcel(Parcel &parcel);
    virtual bool Marshalling(Parcel &parcel) const override;
    static HapModuleInfo *Unmarshalling(Parcel &parcel);
    std::string appStartup;
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // FOUNDATION_APPEXECFWK_INTERFACES_INNERKITS_APPEXECFWK_BASE_INCLUDE_HAP_MODULE_INFO_H
