/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef BUNDLE_MANAGER_UTILS_H
#define BUNDLE_MANAGER_UTILS_H

#include <cstdint>

namespace OHOS {
namespace CJSystemapi {
namespace BundleManager {

    struct RetMetadata {
        char* name;
        char* value;
        char* resource;
    };

    struct CArrMetadata {
        RetMetadata* head;
        int64_t size;
    };
    
    struct ModuleMetadata {
        char* moduleName;
        CArrMetadata metadata;
    };
    
    struct CArrMoMeta {
        ModuleMetadata* head;
        int64_t size;
    };

    struct CResource {
        char* bundleName;
        char* moduleName;
        uint32_t id;
    };

    struct CArrString {
        char** head;
        int64_t size;
    };

    struct MultiAppMode {
        uint8_t multiAppModeType;
        int32_t count;
    };
    
    struct RetApplicationInfo {
        bool enabled;
        bool removable;
        bool systemApp;
        bool debug;
        bool dataUnclearable;
        bool cloudFileSyncEnabled;
        int32_t uid;
        int32_t bundleType;
        int32_t appIndex;
        uint32_t descriptionId;
        uint32_t labelId;
        uint32_t iconId;
        uint32_t accessTokenId;
        char* name;
        char* description;
        char* label;
        char* icon;
        char* process;
        char* codePath;
        char* appDistributionType;
        char* appProvisionType;
        char* nativeLibraryPath;
        char* installSource;
        char* releaseType;
        CArrString permissions;
        CArrMoMeta metadataArray;
        CResource iconResource;
        CResource labelResource;
        CResource descriptionResource;
        MultiAppMode multiAppMode;
    };

    struct CArrInt32 {
        int32_t* head;
        int64_t size;
    };

    struct RetWindowSize {
        uint32_t maxWindowWidth;
        uint32_t minWindowWidth;
        uint32_t maxWindowHeight;
        uint32_t minWindowHeight;
        double maxWindowRatio;
        double minWindowRatio;
    };

    struct RetSkillUri {
        int32_t maxFileSupported;
        char* scheme;
        char* host;
        char* port;
        char* path;
        char* pathStartWith;
        char* pathRegex;
        char* type;
        char* utd;
        char* linkFeature;
    };

    struct RetCArrSkillUri {
        RetSkillUri* head;
        int64_t size;
    };

    struct RetSkill {
        bool domainVerify;
        CArrString actions;
        CArrString entities;
        RetCArrSkillUri uris;
    };

    struct RetCArrSkill {
        RetSkill* head;
        int64_t size;
    };

    struct RetAbilityInfo {
        bool exported;
        bool enabled;
        bool excludeFromDock;
        int32_t orientation;
        int32_t launchType;
        int32_t appIndex;
        uint32_t labelId;
        uint32_t descriptionId;
        uint32_t iconId;
        char* bundleName;
        char* moduleName;
        char* name;
        char* label;
        char* description;
        char* icon;
        char* process;
        CArrString permissions;
        CArrString deviceTypes;
        CArrMetadata metadata;
        CArrInt32 supportWindowModes;
        RetApplicationInfo applicationInfo;
        RetWindowSize windowSize;
        RetCArrSkill skills;
    };

    struct CArrRetAbilityInfo {
        RetAbilityInfo* head;
        int64_t size;
    };

    struct RetExtensionAbilityInfo {
        bool exported;
        bool enabled;
        int32_t extensionAbilityType;
        int32_t appIndex;
        uint32_t labelId;
        uint32_t descriptionId;
        uint32_t iconId;
        char* bundleName;
        char* moduleName;
        char* name;
        char* readPermission;
        char* writePermission;
        char* extensionAbilityTypeName;
        CArrString permissions;
        CArrMetadata metadata;
        RetApplicationInfo applicationInfo;
        RetCArrSkill skills;
    };

    struct CArrRetExtensionAbilityInfo {
        RetExtensionAbilityInfo* head;
        int64_t size;
    };

    struct RetPreloadItem {
        char* moduleName;
    };

    struct CArrRetPreloadItem {
        RetPreloadItem* head;
        int64_t size;
    };

    struct RetDependency {
        uint32_t versionCode;
        char* bundleName;
        char* moduleName;
    };

    struct CArrRetDependency {
        RetDependency* head;
        int64_t size;
    };

    struct CDataItem {
        char* key;
        char* value;
    };

    struct CArrDataItem {
        CDataItem* head;
        int64_t size;
    };
    struct CRouterItem {
        char* name;
        char* pageSourceFile;
        char* buildFunction;
        char* customData;
        CArrDataItem data;
    };

    struct CArrRouterItem {
        CRouterItem* head;
        int64_t size;
    };

    struct RetHapModuleInfo {
        bool installationFree;
        int32_t moduleType;
        uint32_t iconId;
        uint32_t labelId;
        uint32_t descriptionId;
        char* name;
        char* icon;
        char* label;
        char* description;
        char* mainElementName;
        char* hashValue;
        char* codePath;
        char* nativeLibraryPath;
        char* fileContextMenuConfig;
        CArrRetAbilityInfo abilitiesInfo;
        CArrRetExtensionAbilityInfo extensionAbilitiesInfo;
        CArrMetadata metadata;
        CArrString deviceTypes;
        CArrRetPreloadItem preloads;
        CArrRetDependency dependencies;
        CArrRouterItem routerMap;
    };

    struct CArrHapInfo {
        RetHapModuleInfo* head;
        int64_t size;
    };

    struct RetUsedScene {
        CArrString abilities;
        char* when;
    };
    
    struct RetReqPermissionDetail {
        uint32_t reasonId;
        char* name;
        char* moduleName;
        char* reason;
        RetUsedScene usedScence;
    };

    struct CArrReqPerDetail {
        RetReqPermissionDetail* head;
        int64_t size;
    };

    struct RetSignatureInfo {
        char* appId;
        char* fingerprint;
        char* appIdentifier;
    };

    struct RetCArrString {
        int32_t code;
        CArrString value;
    };
 
    struct CRecoverableApplicationInfo {
        uint32_t labelId;
        uint32_t iconId;
        char* bundleName;
        char* moduleName;
    };
 
    struct CArrRecoverableApplicationInfo {
        CRecoverableApplicationInfo* head;
        int64_t size;
    };
 
    struct RetRecoverableApplicationInfo {
        int32_t code;
        CArrRecoverableApplicationInfo data;
    };

    struct RetBundleInfo {
        int32_t uid;
        int32_t appIndex;
        uint32_t versionCode;
        uint32_t minCompatibleVersionCode;
        uint32_t targetVersion;
        int64_t installTime;
        int64_t updateTime;
        char* name;
        char* vendor;
        char* versionName;
        RetApplicationInfo appInfo;
        CArrHapInfo hapInfo;
        CArrReqPerDetail perDetail;
        CArrInt32 state;
        RetSignatureInfo signInfo;
        CArrRouterItem routerMap;
    };

    enum BundleFlag {
        // get bundle info except abilityInfos
        GET_BUNDLE_DEFAULT = 0x00000000,
        // get bundle info include abilityInfos
        GET_BUNDLE_WITH_ABILITIES = 0x00000001,
        // get bundle info include request permissions
        GET_BUNDLE_WITH_REQUESTED_PERMISSION = 0x00000010,
        // get bundle info include extension info
        GET_BUNDLE_WITH_EXTENSION_INFO = 0x00000020,
        // get bundle info include hash value
        GET_BUNDLE_WITH_HASH_VALUE = 0x00000030,
        // get bundle info inlcude menu, only for dump usage
        GET_BUNDLE_WITH_MENU = 0x00000040,
    };

    enum class GetBundleInfoFlag {
        GET_BUNDLE_INFO_DEFAULT = 0x00000000,
        GET_BUNDLE_INFO_WITH_APPLICATION = 0x00000001,
        GET_BUNDLE_INFO_WITH_HAP_MODULE = 0x00000002,
        GET_BUNDLE_INFO_WITH_ABILITY = 0x00000004,
        GET_BUNDLE_INFO_WITH_EXTENSION_ABILITY = 0x00000008,
        GET_BUNDLE_INFO_WITH_REQUESTED_PERMISSION = 0x00000010,
        GET_BUNDLE_INFO_WITH_METADATA = 0x00000020,
        GET_BUNDLE_INFO_WITH_DISABLE = 0x00000040,
        GET_BUNDLE_INFO_WITH_SIGNATURE_INFO = 0x00000080,
        GET_BUNDLE_INFO_WITH_MENU = 0x00000100,
        GET_BUNDLE_INFO_WITH_ROUTER_MAP = 0x00000200,
        GET_BUNDLE_INFO_WITH_SKILL = 0x00000800,
    };
} // BundleManager
} // CJSystemapi
} // OHOS

#endif