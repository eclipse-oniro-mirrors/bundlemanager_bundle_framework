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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_TEST_ACCESS_TOKEN_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_TEST_ACCESS_TOKEN_H

#include <vector>
#include <string>

namespace OHOS {
namespace Security {
namespace AccessToken {
typedef unsigned int AccessTokenID;
typedef unsigned int AccessTokenAttr;
static const int DEFAULT_TOKEN_VERSION = 1;
static const int FIRSTCALLER_TOKENID_DEFAULT = 0;
static AccessTokenID INVALID_TOKENID = 0;

enum AccessTokenKitRet {
    RET_FAILED = -1,
    RET_SUCCESS = 0,
};

typedef struct {
    unsigned int tokenUniqueID : 24;
    unsigned int res : 3;
    unsigned int type : 2;
    unsigned int version : 3;
} AccessTokenIDInner;

typedef enum TypeATokenTypeEnum {
    TOKEN_INVALID = -1,
    TOKEN_HAP = 0,
    TOKEN_NATIVE,
    TOKEN_SHELL,
} ATokenTypeEnum;

typedef enum TypeATokenAplEnum {
    APL_NORMAL = 1,
    APL_SYSTEM_BASIC = 2,
    APL_SYSTEM_CORE = 3,
} ATokenAplEnum;

typedef union {
    unsigned long long tokenIDEx;
    struct {
        AccessTokenID tokenID;
        AccessTokenAttr tokenAttr;
    } tokenIdExStruct;
} AccessTokenIDEx;

typedef enum TypePermissionState {
    PERMISSION_DENIED = -1,
    PERMISSION_GRANTED = 0,
} PermissionState;

typedef enum TypeGrantMode {
    USER_GRANT = 0,
    SYSTEM_GRANT = 1,
} GrantMode;

typedef enum TypeATokenAvailableTypeEnum {
    INVALID = 0,
    NORMAL = 1,
    MDM = 2,
} ATokenAvailableTypeEnum;

typedef enum TypePermissionFlag {
    PERMISSION_DEFAULT_FLAG = 0,
    PERMISSION_USER_SET = 1 << 0,
    PERMISSION_USER_FIXED = 1 << 1,
    PERMISSION_SYSTEM_FIXED = 1 << 2,
    PERMISSION_GRANTED_BY_POLICY = 1 << 3,
} PermissionFlag;

class NativeTokenInfo final {
public:
    ATokenTypeEnum apl;
    std::string processName;
    std::vector<std::string> dcap;
    AccessTokenID tokenID;
    AccessTokenAttr tokenAttr;
    std::vector<std::string> nativeAcls;
};

class PermissionDef final {
public:
    std::string permissionName;
    std::string bundleName;
    int grantMode;
    TypeATokenAplEnum availableLevel;
    bool provisionEnable;
    bool distributedSceneEnable;
    std::string label;
    int labelId;
    std::string description;
    int descriptionId;
    ATokenAvailableTypeEnum availableType = ATokenAvailableTypeEnum::NORMAL;
};

class PermissionStateFull final {
public:
    std::string permissionName;
    bool isGeneral;
    std::vector<std::string> resDeviceID;
    std::vector<int> grantStatus;
    std::vector<int> grantFlags;
};

class HapInfoParams final {
public:
    int userID;
    std::string bundleName;
    /** instance index */
    int instIndex;
    /**
     * dlp type, for details about the valid values,
     * see the definition of HapDlpType in the access_token.h file.
     */
    int dlpType;
    std::string appIDDesc;
    /** which version of the SDK is used to develop the hap */
    int32_t apiVersion;
    /** indicates whether the hap is a system app */
    bool isSystemApp;
    /* app type */
    std::string appDistributionType;
    bool isRestore = false;
    AccessTokenID tokenID = INVALID_TOKENID;
};

/**
 * @brief Declares hap info params class
 */
class UpdateHapInfoParams final {
public:
    std::string appIDDesc;
    /** which version of the SDK is used to develop the hap */
    int32_t apiVersion;
    /** indicates whether the hap is a system app */
    bool isSystemApp;
    /* app type */
    std::string appDistributionType;
};

class PreAuthorizationInfo final {
public:
    std::string permissionName;
    /** Whether the pre-authorization is non-cancelable */
    bool userCancelable = false;
};

/**
 * @brief Whether acl check
 */
typedef enum HapPolicyCheckIgnoreType {
    /** normal */
    None = 0,
    /** ignore acl check */
    ACL_IGNORE_CHECK,
} HapPolicyCheckIgnore;

class HapPolicyParams final {
public:
    /**
     * apl level, for details about the valid values,
     * see the definition of ATokenAplEnum in the access_token.h file.
     */
    ATokenAplEnum apl;
    std::string domain;
    std::vector<PermissionDef> permList;
    std::vector<PermissionStateFull> permStateList;
    std::vector<std::string> aclRequestedList;
    std::vector<PreAuthorizationInfo> preAuthorizationInfo;
    HapPolicyCheckIgnore checkIgnore = HapPolicyCheckIgnore::None;
};

/**
 * @brief PermssionRule
 */
typedef enum TypePermissionRulesEnum {
    PERMISSION_EDM_RULE = 0,
    PERMISSION_ACL_RULE
} PermissionRulesEnum;
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_TEST_ACCESS_TOKEN_H