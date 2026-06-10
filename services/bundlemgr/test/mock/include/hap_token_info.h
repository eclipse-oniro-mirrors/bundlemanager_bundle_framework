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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_TEST_ACCESSTOKEN_HAP_TOKEN_INFO_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_TEST_ACCESSTOKEN_HAP_TOKEN_INFO_H

#include <cstdint>
#include <string>
#include <vector>

#include "access_token.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
class PermissionInfoCheckResult final {
public:
    std::string permissionName;
    PermissionRulesEnum rule;
};

class HapInfoCheckResult final {
public:
    PermissionInfoCheckResult permCheckResult;
};

struct ProfileData {
    std::string provisionRaw;
    int32_t profileBlockLength = 0;
    std::vector<uint8_t> profileBlock;
    std::string appId;
    std::string fingerprint;
    std::string organization;
    bool isOpenHarmony = false;
    bool isEnterpriseResigned = false;
};

struct TrustedBundleInfo {
    ProfileData profileData;
    std::string moduleInfo;
    std::string sharedFiles;
};

enum class ReservedType : int32_t {
    NONE = 0,
    RESERVED_IDENTITY = 1,
    RESERVED_DATA = 2,
};

struct BundlePolicy {
    std::vector<PreAuthorizationInfo> preAuthorizationInfo;
    DlpType dlpType;
    bool isDebugGrant;
};

class HapBaseInfo final {
public:
    int32_t userID;
    std::string bundleName = "";
    int32_t instIndex = 0;
};

struct Identity final {
    int32_t uid = 0;
    FullTokenID tokenId = 0;
};

struct BundleHapList {
    std::vector<std::string> hapPaths;
    bool isPreInstalled = false;
    int32_t userId = 0;
};

struct MigratedInfo final {
    std::string bundleName;
    BundleHapList pathList;
    std::vector<HapBaseInfo> hapBaseInfoList;
    std::vector<int32_t> uidList;
    std::vector<ReservedType> reservedTypeList;
};

struct BundleMigrateResult final {
    std::vector<AccessTokenIDEx> tokenIdList;
    std::vector<ReservedType> reservedTypeList;
    int32_t errcode = 0;
};

struct HapVerifyResultInfo {
    uint32_t index = 0;
    int32_t errorCode = 0;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // ACCESSTOKEN_HAP_TOKEN_INFO_H