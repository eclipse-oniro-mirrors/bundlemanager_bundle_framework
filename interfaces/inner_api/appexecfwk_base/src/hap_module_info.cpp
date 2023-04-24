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

#include "hap_module_info.h"

#include "bundle_constants.h"
#include "json_util.h"
#include "message_parcel.h"
#include "nlohmann/json.hpp"
#include "parcel_macro.h"
#include "string_ex.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const std::string HAP_MODULE_INFO_NAME = "name";
const std::string HAP_MODULE_INFO_PACKAGE = "package";
const std::string HAP_MODULE_INFO_DESCRIPTION = "description";
const std::string HAP_MODULE_INFO_DESCRIPTION_ID = "descriptionId";
const std::string HAP_MODULE_INFO_ICON_PATH = "iconPath";
const std::string HAP_MODULE_INFO_ICON_ID = "iconId";
const std::string HAP_MODULE_INFO_LABEL = "label";
const std::string HAP_MODULE_INFO_LABEL_ID = "labelId";
const std::string HAP_MODULE_INFO_BACKGROUND_IMG = "backgroundImg";
const std::string HAP_MODULE_INFO_MAIN_ABILITY = "mainAbility";
const std::string HAP_MODULE_INFO_SRC_PATH = "srcPath";
const std::string HAP_MODULE_INFO_HASH_VALUE = "hashValue";
const std::string HAP_MODULE_INFO_SUPPORTED_MODES = "supportedModes";
const std::string HAP_MODULE_INFO_REQ_CAPABILITIES = "reqCapabilities";
const std::string HAP_MODULE_INFO_DEVICE_TYPES = "deviceTypes";
const std::string HAP_MODULE_INFO_ABILITY_INFOS = "abilityInfos";
const std::string HAP_MODULE_INFO_COLOR_MODE = "colorMode";
const std::string HAP_MODULE_INFO_MAIN_ELEMENTNAME = "mainElementName";
const std::string HAP_MODULE_INFO_PAGES = "pages";
const std::string HAP_MODULE_INFO_PROCESS = "process";
const std::string HAP_MODULE_INFO_RESOURCE_PATH = "resourcePath";
const std::string HAP_MODULE_INFO_SRC_ENTRANCE = "srcEntrance";
const std::string HAP_MODULE_INFO_UI_SYNTAX = "uiSyntax";
const std::string HAP_MODULE_INFO_VIRTUAL_MACHINE = "virtualMachine";
const std::string HAP_MODULE_INFO_DELIVERY_WITH_INSTALL = "deliveryWithInstall";
const std::string HAP_MODULE_INFO_INSTALLATION_FREE = "installationFree";
const std::string HAP_MODULE_INFO_IS_MODULE_JSON = "isModuleJson";
const std::string HAP_MODULE_INFO_IS_STAGE_BASED_MODEL = "isStageBasedModel";
const std::string HAP_MODULE_INFO_IS_REMOVABLE = "isRemovable";
const std::string HAP_MODULE_INFO_MODULE_TYPE = "moduleType";
const std::string HAP_MODULE_INFO_EXTENSION_INFOS = "extensionInfos";
const std::string HAP_MODULE_INFO_META_DATA = "metadata";
const std::string HAP_MODULE_INFO_DEPENDENCIES = "dependencies";
const std::string HAP_MODULE_INFO_UPGRADE_FLAG = "upgradeFlag";
const std::string HAP_MODULE_INFO_HAP_PATH = "hapPath";
const std::string HAP_MODULE_INFO_COMPILE_MODE = "compileMode";
const std::string HAP_MODULE_INFO_HQF_INFO = "hqfInfo";
const std::string HAP_MODULE_INFO_IS_LIB_ISOLATED = "isLibIsolated";
const std::string HAP_MODULE_INFO_NATIVE_LIBRARY_PATH = "nativeLibraryPath";
const std::string HAP_MODULE_INFO_CPU_ABI = "cpuAbi";
const std::string HAP_MODULE_INFO_MODULE_SOURCE_DIR = "moduleSourceDir";
const std::string HAP_MODULE_INFO_ATOMIC_SERVICE_MODULE_TYPE = "atomicServiceModuleType";
const std::string HAP_MODULE_INFO_PRELOADS = "preloads";
const std::string PRELOAD_ITEM_MODULE_NAME = "moduleName";
}

bool PreloadItem::ReadFromParcel(Parcel &parcel)
{
    moduleName = Str16ToStr8(parcel.ReadString16());
    return true;
}

bool PreloadItem::Marshalling(Parcel &parcel) const
{
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(moduleName));
    return true;
}

PreloadItem *PreloadItem::Unmarshalling(Parcel &parcel)
{
    PreloadItem *info = new (std::nothrow) PreloadItem();
    if (info && !info->ReadFromParcel(parcel)) {
        APP_LOGW("read from parcel failed");
        delete info;
        info = nullptr;
    }
    return info;
}

void to_json(nlohmann::json &jsonObject, const PreloadItem &preloadItem)
{
    jsonObject = nlohmann::json {
        {PRELOAD_ITEM_MODULE_NAME, preloadItem.moduleName}
    };
}

void from_json(const nlohmann::json &jsonObject, PreloadItem &preloadItem)
{
    const auto &jsonObjectEnd = jsonObject.end();
    int32_t parseResult = ERR_OK;
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        PRELOAD_ITEM_MODULE_NAME,
        preloadItem.moduleName,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    if (parseResult != ERR_OK) {
        APP_LOGE("read PreloadItem from database error, error code : %{public}d", parseResult);
    }
}

bool HapModuleInfo::ReadFromParcel(Parcel &parcel)
{
    name = Str16ToStr8(parcel.ReadString16());
    package = Str16ToStr8(parcel.ReadString16());
    moduleName = Str16ToStr8(parcel.ReadString16());
    description = Str16ToStr8(parcel.ReadString16());
    descriptionId = parcel.ReadInt32();
    iconPath = Str16ToStr8(parcel.ReadString16());
    iconId = parcel.ReadInt32();
    label = Str16ToStr8(parcel.ReadString16());
    labelId = parcel.ReadInt32();
    backgroundImg = Str16ToStr8(parcel.ReadString16());
    mainAbility = Str16ToStr8(parcel.ReadString16());
    srcPath = Str16ToStr8(parcel.ReadString16());
    hashValue = Str16ToStr8(parcel.ReadString16());
    hapPath = Str16ToStr8(parcel.ReadString16());
    supportedModes = parcel.ReadInt32();

    int32_t reqCapabilitiesSize;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, reqCapabilitiesSize);
    CONTAINER_SECURITY_VERIFY(parcel, reqCapabilitiesSize, &reqCapabilities);
    for (auto i = 0; i < reqCapabilitiesSize; i++) {
        reqCapabilities.emplace_back(Str16ToStr8(parcel.ReadString16()));
    }

    int32_t deviceTypesSize;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, deviceTypesSize);
    CONTAINER_SECURITY_VERIFY(parcel, deviceTypesSize, &deviceTypes);
    for (auto i = 0; i < deviceTypesSize; i++) {
        deviceTypes.emplace_back(Str16ToStr8(parcel.ReadString16()));
    }

    int32_t dependenciesSize;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, dependenciesSize);
    CONTAINER_SECURITY_VERIFY(parcel, dependenciesSize, &dependencies);
    for (auto i = 0; i < dependenciesSize; i++) {
        dependencies.emplace_back(Str16ToStr8(parcel.ReadString16()));
    }

    int32_t abilityInfosSize;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, abilityInfosSize);
    CONTAINER_SECURITY_VERIFY(parcel, abilityInfosSize, &abilityInfos);
    for (auto i = 0; i < abilityInfosSize; i++) {
        std::unique_ptr<AbilityInfo> abilityInfo(parcel.ReadParcelable<AbilityInfo>());
        if (!abilityInfo) {
            APP_LOGE("ReadParcelable<AbilityInfo> failed");
            return false;
        }
        abilityInfos.emplace_back(*abilityInfo);
    }

    colorMode = static_cast<ModuleColorMode>(parcel.ReadInt32());
    bundleName = Str16ToStr8(parcel.ReadString16());
    mainElementName = Str16ToStr8(parcel.ReadString16());
    pages = Str16ToStr8(parcel.ReadString16());
    process = Str16ToStr8(parcel.ReadString16());
    resourcePath = Str16ToStr8(parcel.ReadString16());
    srcEntrance = Str16ToStr8(parcel.ReadString16());
    uiSyntax = Str16ToStr8(parcel.ReadString16());
    virtualMachine = Str16ToStr8(parcel.ReadString16());
    deliveryWithInstall = parcel.ReadBool();
    installationFree = parcel.ReadBool();
    isModuleJson = parcel.ReadBool();
    isStageBasedModel = parcel.ReadBool();

    int32_t isRemovableSize;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, isRemovableSize);
    CONTAINER_SECURITY_VERIFY(parcel, isRemovableSize, &isRemovable);
    for (auto i = 0; i < isRemovableSize; i++) {
        std::string key = Str16ToStr8(parcel.ReadString16());
        bool isRemove = parcel.ReadBool();
        isRemovable[key] = isRemove;
    }
    moduleType = static_cast<ModuleType>(parcel.ReadInt32());

    int32_t extensionInfosSize;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, extensionInfosSize);
    CONTAINER_SECURITY_VERIFY(parcel, extensionInfosSize, &extensionInfos);
    for (auto i = 0; i < extensionInfosSize; i++) {
        std::unique_ptr<ExtensionAbilityInfo> extensionAbilityInfo(parcel.ReadParcelable<ExtensionAbilityInfo>());
        if (!extensionAbilityInfo) {
            APP_LOGE("ReadParcelable<ExtensionAbilityInfo> failed");
            return false;
        }
        extensionInfos.emplace_back(*extensionAbilityInfo);
    }

    int32_t metadataSize;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, metadataSize);
    CONTAINER_SECURITY_VERIFY(parcel, metadataSize, &metadata);
    for (int32_t i = 0; i < metadataSize; ++i) {
        std::unique_ptr<Metadata> meta(parcel.ReadParcelable<Metadata>());
        if (!meta) {
            APP_LOGE("ReadParcelable<Metadata> failed");
            return false;
        }
        metadata.emplace_back(*meta);
    }

    upgradeFlag = parcel.ReadInt32();
    compileMode = static_cast<CompileMode>(parcel.ReadInt32());
    std::unique_ptr<HqfInfo> hqfInfoPtr(parcel.ReadParcelable<HqfInfo>());
    if (hqfInfoPtr == nullptr) {
        APP_LOGE("ReadParcelable<HqfInfo> failed");
        return false;
    }
    hqfInfo = *hqfInfoPtr;
    isLibIsolated = parcel.ReadBool();
    nativeLibraryPath = Str16ToStr8(parcel.ReadString16());
    cpuAbi = Str16ToStr8(parcel.ReadString16());
    moduleSourceDir = Str16ToStr8(parcel.ReadString16());

    atomicServiceModuleType = static_cast<AtomicServiceModuleType>(parcel.ReadInt32());

    int32_t preloadsSize;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, preloadsSize);
    CONTAINER_SECURITY_VERIFY(parcel, preloadsSize, &preloads);
    for (int32_t i = 0; i < preloadsSize; ++i) {
        std::unique_ptr<PreloadItem> preload(parcel.ReadParcelable<PreloadItem>());
        if (!preload) {
            APP_LOGE("ReadParcelable<PreloadItem> failed");
            return false;
        }
        preloads.emplace_back(*preload);
    }
    return true;
}

HapModuleInfo *HapModuleInfo::Unmarshalling(Parcel &parcel)
{
    HapModuleInfo *info = new (std::nothrow) HapModuleInfo();
    if (info && !info->ReadFromParcel(parcel)) {
        APP_LOGW("read from parcel failed");
        delete info;
        info = nullptr;
    }
    return info;
}

bool HapModuleInfo::Marshalling(Parcel &parcel) const
{
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(name));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(package));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(moduleName));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(description));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, descriptionId);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(iconPath));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, iconId);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(label));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, labelId);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(backgroundImg));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(mainAbility));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(srcPath));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(hashValue));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(hapPath));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, supportedModes);

    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, reqCapabilities.size());
    for (auto &reqCapability : reqCapabilities) {
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(reqCapability));
    }

    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, deviceTypes.size());
    for (auto &deviceType : deviceTypes) {
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(deviceType));
    }

    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, dependencies.size());
    for (auto &dependency : dependencies) {
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(dependency));
    }

    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, abilityInfos.size());
    for (auto &abilityInfo : abilityInfos) {
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Parcelable, parcel, &abilityInfo);
    }

    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, static_cast<int32_t>(colorMode));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(bundleName));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(mainElementName));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(pages));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(process));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(resourcePath));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(srcEntrance));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(uiSyntax));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(virtualMachine));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Bool, parcel, deliveryWithInstall);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Bool, parcel, installationFree);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Bool, parcel, isModuleJson);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Bool, parcel, isStageBasedModel);

    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, isRemovable.size());
    for (auto &item : isRemovable) {
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(item.first));
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Bool, parcel, item.second);
    }

    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, static_cast<int32_t>(moduleType));

    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, extensionInfos.size());
    for (auto &extensionInfo : extensionInfos) {
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Parcelable, parcel, &extensionInfo);
    }

    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, metadata.size());
    for (auto &mete : metadata) {
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Parcelable, parcel, &mete);
    }

    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, upgradeFlag);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, static_cast<int32_t>(compileMode));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Parcelable, parcel, &hqfInfo);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Bool, parcel, isLibIsolated);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(nativeLibraryPath));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(cpuAbi));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(moduleSourceDir));

    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, static_cast<int32_t>(atomicServiceModuleType));

    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, preloads.size());
    for (auto &item : preloads) {
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Parcelable, parcel, &item);
    }
    return true;
}

void to_json(nlohmann::json &jsonObject, const HapModuleInfo &hapModuleInfo)
{
    jsonObject = nlohmann::json {
        {HAP_MODULE_INFO_NAME, hapModuleInfo.name},
        {HAP_MODULE_INFO_PACKAGE, hapModuleInfo.package},
        {Constants::MODULE_NAME, hapModuleInfo.moduleName},
        {HAP_MODULE_INFO_DESCRIPTION, hapModuleInfo.description},
        {HAP_MODULE_INFO_DESCRIPTION_ID, hapModuleInfo.descriptionId},
        {HAP_MODULE_INFO_ICON_PATH, hapModuleInfo.iconPath},
        {HAP_MODULE_INFO_ICON_ID, hapModuleInfo.iconId},
        {HAP_MODULE_INFO_LABEL, hapModuleInfo.label},
        {HAP_MODULE_INFO_LABEL_ID, hapModuleInfo.labelId},
        {HAP_MODULE_INFO_BACKGROUND_IMG, hapModuleInfo.backgroundImg},
        {HAP_MODULE_INFO_MAIN_ABILITY, hapModuleInfo.mainAbility},
        {HAP_MODULE_INFO_SRC_PATH, hapModuleInfo.srcPath},
        {HAP_MODULE_INFO_HASH_VALUE, hapModuleInfo.hashValue},
        {HAP_MODULE_INFO_HAP_PATH, hapModuleInfo.hapPath},
        {HAP_MODULE_INFO_SUPPORTED_MODES, hapModuleInfo.supportedModes},
        {HAP_MODULE_INFO_REQ_CAPABILITIES, hapModuleInfo.reqCapabilities},
        {HAP_MODULE_INFO_DEVICE_TYPES, hapModuleInfo.deviceTypes},
        {HAP_MODULE_INFO_ABILITY_INFOS, hapModuleInfo.abilityInfos},
        {HAP_MODULE_INFO_COLOR_MODE, hapModuleInfo.colorMode},
        {Constants::BUNDLE_NAME, hapModuleInfo.bundleName},
        {HAP_MODULE_INFO_MAIN_ELEMENTNAME, hapModuleInfo.mainElementName},
        {HAP_MODULE_INFO_PAGES, hapModuleInfo.pages},
        {HAP_MODULE_INFO_PROCESS, hapModuleInfo.process},
        {HAP_MODULE_INFO_RESOURCE_PATH, hapModuleInfo.resourcePath},
        {HAP_MODULE_INFO_SRC_ENTRANCE, hapModuleInfo.srcEntrance},
        {HAP_MODULE_INFO_UI_SYNTAX, hapModuleInfo.uiSyntax},
        {HAP_MODULE_INFO_VIRTUAL_MACHINE, hapModuleInfo.virtualMachine},
        {HAP_MODULE_INFO_DELIVERY_WITH_INSTALL, hapModuleInfo.deliveryWithInstall},
        {HAP_MODULE_INFO_INSTALLATION_FREE, hapModuleInfo.installationFree},
        {HAP_MODULE_INFO_IS_MODULE_JSON, hapModuleInfo.isModuleJson},
        {HAP_MODULE_INFO_IS_STAGE_BASED_MODEL, hapModuleInfo.isStageBasedModel},
        {HAP_MODULE_INFO_IS_REMOVABLE, hapModuleInfo.isRemovable},
        {HAP_MODULE_INFO_UPGRADE_FLAG, hapModuleInfo.upgradeFlag},
        {HAP_MODULE_INFO_MODULE_TYPE, hapModuleInfo.moduleType},
        {HAP_MODULE_INFO_EXTENSION_INFOS, hapModuleInfo.extensionInfos},
        {HAP_MODULE_INFO_META_DATA, hapModuleInfo.metadata},
        {HAP_MODULE_INFO_DEPENDENCIES, hapModuleInfo.dependencies},
        {HAP_MODULE_INFO_COMPILE_MODE, hapModuleInfo.compileMode},
        {HAP_MODULE_INFO_HQF_INFO, hapModuleInfo.hqfInfo},
        {HAP_MODULE_INFO_IS_LIB_ISOLATED, hapModuleInfo.isLibIsolated},
        {HAP_MODULE_INFO_NATIVE_LIBRARY_PATH, hapModuleInfo.nativeLibraryPath},
        {HAP_MODULE_INFO_CPU_ABI, hapModuleInfo.cpuAbi},
        {HAP_MODULE_INFO_MODULE_SOURCE_DIR, hapModuleInfo.moduleSourceDir},
        {HAP_MODULE_INFO_ATOMIC_SERVICE_MODULE_TYPE, hapModuleInfo.atomicServiceModuleType},
        {HAP_MODULE_INFO_PRELOADS, hapModuleInfo.preloads}
    };
}

void from_json(const nlohmann::json &jsonObject, HapModuleInfo &hapModuleInfo)
{
    const auto &jsonObjectEnd = jsonObject.end();
    int32_t parseResult = ERR_OK;
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        HAP_MODULE_INFO_NAME,
        hapModuleInfo.name,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        HAP_MODULE_INFO_PACKAGE,
        hapModuleInfo.package,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        Constants::MODULE_NAME,
        hapModuleInfo.moduleName,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        HAP_MODULE_INFO_DESCRIPTION,
        hapModuleInfo.description,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<int>(jsonObject,
        jsonObjectEnd,
        HAP_MODULE_INFO_DESCRIPTION_ID,
        hapModuleInfo.descriptionId,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        HAP_MODULE_INFO_ICON_PATH,
        hapModuleInfo.iconPath,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<int>(jsonObject,
        jsonObjectEnd,
        HAP_MODULE_INFO_ICON_ID,
        hapModuleInfo.iconId,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        HAP_MODULE_INFO_LABEL,
        hapModuleInfo.label,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<int>(jsonObject,
        jsonObjectEnd,
        HAP_MODULE_INFO_LABEL_ID,
        hapModuleInfo.labelId,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        HAP_MODULE_INFO_BACKGROUND_IMG,
        hapModuleInfo.backgroundImg,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        HAP_MODULE_INFO_MAIN_ABILITY,
        hapModuleInfo.mainAbility,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        HAP_MODULE_INFO_SRC_PATH,
        hapModuleInfo.srcPath,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        HAP_MODULE_INFO_HASH_VALUE,
        hapModuleInfo.hashValue,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        HAP_MODULE_INFO_HAP_PATH,
        hapModuleInfo.hapPath,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<int>(jsonObject,
        jsonObjectEnd,
        HAP_MODULE_INFO_SUPPORTED_MODES,
        hapModuleInfo.supportedModes,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::vector<std::string>>(jsonObject,
        jsonObjectEnd,
        HAP_MODULE_INFO_REQ_CAPABILITIES,
        hapModuleInfo.reqCapabilities,
        JsonType::ARRAY,
        false,
        parseResult,
        ArrayType::STRING);
    GetValueIfFindKey<std::vector<std::string>>(jsonObject,
        jsonObjectEnd,
        HAP_MODULE_INFO_DEVICE_TYPES,
        hapModuleInfo.deviceTypes,
        JsonType::ARRAY,
        false,
        parseResult,
        ArrayType::STRING);
    GetValueIfFindKey<std::vector<AbilityInfo>>(jsonObject,
        jsonObjectEnd,
        HAP_MODULE_INFO_ABILITY_INFOS,
        hapModuleInfo.abilityInfos,
        JsonType::ARRAY,
        false,
        parseResult,
        ArrayType::OBJECT);
    GetValueIfFindKey<ModuleColorMode>(jsonObject,
        jsonObjectEnd,
        HAP_MODULE_INFO_COLOR_MODE,
        hapModuleInfo.colorMode,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        Constants::BUNDLE_NAME,
        hapModuleInfo.bundleName,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        HAP_MODULE_INFO_MAIN_ELEMENTNAME,
        hapModuleInfo.mainElementName,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        HAP_MODULE_INFO_PAGES,
        hapModuleInfo.pages,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        HAP_MODULE_INFO_PROCESS,
        hapModuleInfo.process,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        HAP_MODULE_INFO_RESOURCE_PATH,
        hapModuleInfo.resourcePath,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        HAP_MODULE_INFO_SRC_ENTRANCE,
        hapModuleInfo.srcEntrance,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        HAP_MODULE_INFO_UI_SYNTAX,
        hapModuleInfo.uiSyntax,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        HAP_MODULE_INFO_VIRTUAL_MACHINE,
        hapModuleInfo.virtualMachine,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<bool>(jsonObject,
        jsonObjectEnd,
        HAP_MODULE_INFO_DELIVERY_WITH_INSTALL,
        hapModuleInfo.deliveryWithInstall,
        JsonType::BOOLEAN,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<bool>(jsonObject,
        jsonObjectEnd,
        HAP_MODULE_INFO_INSTALLATION_FREE,
        hapModuleInfo.installationFree,
        JsonType::BOOLEAN,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<bool>(jsonObject,
        jsonObjectEnd,
        HAP_MODULE_INFO_IS_MODULE_JSON,
        hapModuleInfo.isModuleJson,
        JsonType::BOOLEAN,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<bool>(jsonObject,
        jsonObjectEnd,
        HAP_MODULE_INFO_IS_STAGE_BASED_MODEL,
        hapModuleInfo.isStageBasedModel,
        JsonType::BOOLEAN,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::map<std::string, bool>>(jsonObject,
        jsonObjectEnd,
        HAP_MODULE_INFO_IS_REMOVABLE,
        hapModuleInfo.isRemovable,
        JsonType::OBJECT,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<int32_t>(jsonObject,
        jsonObjectEnd,
        HAP_MODULE_INFO_UPGRADE_FLAG,
        hapModuleInfo.upgradeFlag,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<ModuleType>(jsonObject,
        jsonObjectEnd,
        HAP_MODULE_INFO_MODULE_TYPE,
        hapModuleInfo.moduleType,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::vector<ExtensionAbilityInfo>>(jsonObject,
        jsonObjectEnd,
        HAP_MODULE_INFO_EXTENSION_INFOS,
        hapModuleInfo.extensionInfos,
        JsonType::ARRAY,
        false,
        parseResult,
        ArrayType::OBJECT);
    GetValueIfFindKey<std::vector<Metadata>>(jsonObject,
        jsonObjectEnd,
        HAP_MODULE_INFO_META_DATA,
        hapModuleInfo.metadata,
        JsonType::ARRAY,
        false,
        parseResult,
        ArrayType::OBJECT);
    GetValueIfFindKey<std::vector<std::string>>(jsonObject,
        jsonObjectEnd,
        HAP_MODULE_INFO_DEPENDENCIES,
        hapModuleInfo.dependencies,
        JsonType::ARRAY,
        false,
        parseResult,
        ArrayType::STRING);
    GetValueIfFindKey<CompileMode>(jsonObject,
        jsonObjectEnd,
        HAP_MODULE_INFO_COMPILE_MODE,
        hapModuleInfo.compileMode,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<HqfInfo>(jsonObject,
        jsonObjectEnd,
        HAP_MODULE_INFO_HQF_INFO,
        hapModuleInfo.hqfInfo,
        JsonType::OBJECT,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<bool>(jsonObject,
        jsonObjectEnd,
        HAP_MODULE_INFO_IS_LIB_ISOLATED,
        hapModuleInfo.isLibIsolated,
        JsonType::BOOLEAN,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        HAP_MODULE_INFO_NATIVE_LIBRARY_PATH,
        hapModuleInfo.nativeLibraryPath,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        HAP_MODULE_INFO_CPU_ABI,
        hapModuleInfo.cpuAbi,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        HAP_MODULE_INFO_MODULE_SOURCE_DIR,
        hapModuleInfo.moduleSourceDir,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<AtomicServiceModuleType>(jsonObject,
        jsonObjectEnd,
        HAP_MODULE_INFO_ATOMIC_SERVICE_MODULE_TYPE,
        hapModuleInfo.atomicServiceModuleType,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::vector<PreloadItem>>(jsonObject,
        jsonObjectEnd,
        HAP_MODULE_INFO_PRELOADS,
        hapModuleInfo.preloads,
        JsonType::ARRAY,
        false,
        parseResult,
        ArrayType::OBJECT);
    if (parseResult != ERR_OK) {
        APP_LOGW("HapModuleInfo from_json error, error code : %{public}d", parseResult);
    }
}
}  // namespace AppExecFwk
}  // namespace OHOS
