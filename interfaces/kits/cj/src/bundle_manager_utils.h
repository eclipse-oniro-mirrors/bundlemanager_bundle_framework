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
    

    struct RetApplicationInfo {
        char* name;
        char* description;
        uint32_t descriptionId;
        bool enabled;
        char* label;
        uint32_t labelId;
        char* icon;
        uint32_t iconId;
        char* process;
        CArrString permissions;
        char* codePath;
        CArrMoMeta metadataArray;
        bool removable;
        uint32_t accessTokenId;
        int32_t uid;
        CResource iconResource;
        CResource labelResource;
        CResource descriptionResource;
        char* appDistributionType;
        char* appProvisionType;
        bool systemApp;
        int32_t bundleType;
        bool debug;
        bool dataUnclearable;
        bool cloudFileSyncEnabled;
    };

    struct CArrInt32 {
        int32_t* head;
        int64_t size;
    };

    struct RetWindowSize {
        double maxWindowRatio;
        double minWindowRatio;
        uint32_t maxWindowWidth;
        uint32_t minWindowWidth;
        uint32_t maxWindowHeight;
        uint32_t minWindowHeight;
    };


    struct RetAbilityInfo {
        char* bundleName;
        char* moduleName;
        char* name;
        char* label;
        uint32_t labelId;
        char* description;
        uint32_t descriptionId;
        char* icon;
        uint32_t iconId;
        char* process;
        bool exported;
        int32_t orientation;
        int32_t launchType;
        CArrString permissions;
        CArrString deviceTypes;
        RetApplicationInfo applicationInfo;
        CArrMetadata metadata;
        bool enabled;
        CArrInt32 supportWindowModes;
        RetWindowSize windowSize;
    };

    struct CArrRetAbilityInfo {
        RetAbilityInfo* head;
        int64_t size;
    };

    struct RetExtensionAbilityInfo {
        char* bundleName;
        char* moduleName;
        char* name;
        uint32_t labelId;
        uint32_t descriptionId;
        uint32_t iconId;
        bool exported;
        int32_t extensionAbilityType;
        CArrString permissions;
        RetApplicationInfo applicationInfo;
        CArrMetadata metadata;
        bool enabled;
        char* readPermission;
        char* writePermission;
        char* extensionAbilityTypeName;
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
        char* bundleName;
        char* moduleName;
        uint32_t versionCode;
    };

    struct CArrRetDependency {
        RetDependency* head;
        int64_t size;
    };

    struct RetHapModuleInfo {
        char* name;
        char* icon;
        uint32_t iconId;
        char* label;
        uint32_t labelId;
        char* description;
        uint32_t descriptionId;
        char* mainElementName;
        CArrRetAbilityInfo abilitiesInfo;
        CArrRetExtensionAbilityInfo extensionAbilitiesInfo;
        CArrMetadata metadata;
        CArrString deviceTypes;
        bool installationFree;
        char* hashValue;
        int32_t moduleType;
        CArrRetPreloadItem preloads;
        CArrRetDependency dependencies;
        char* fileContextMenuConfig;
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
        char* name;
        char* moduleName;
        char* reason;
        uint32_t reasonId;
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
        char* bundleName;
        char* moduleName;
        uint32_t labelId;
        uint32_t iconId;
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
        char* name;
        char* vendor;
        uint32_t versionCode;
        char* versionName;
        uint32_t minCompatibleVersionCode;
        uint32_t targetVersion;
        RetApplicationInfo appInfo;
        CArrHapInfo hapInfo;
        CArrReqPerDetail perDetail;
        CArrInt32 state;
        RetSignatureInfo signInfo;
        int64_t installTime;
        int64_t updateTime;
        int32_t uid;
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
    };
} // BundleManager
} // CJSystemapi
} // OHOS

#endif