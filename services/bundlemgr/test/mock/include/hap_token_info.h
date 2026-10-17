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

#include <map>
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

using FullTokenID = uint64_t;

// ---- SPM structures mirrored from the real hap_token_info.h (test_spm_inter) ----
enum class ReservedType : int32_t {
    NONE = 0,
    RESERVED_IDENTITY = 1,
    RESERVED_DATA = 2,
};

enum class InstallTypeEnum {
    TYPE_INSTALL = 0,
    TYPE_REPLACE = 1,
    TYPE_MERGE = 2,
};

enum SignInfoQueryFlag : uint32_t {
    QUERY_PROFILE = 1 << 0,
    QUERY_MODULE_INFO = 1 << 1,
    QUERY_SHARED_FILES = 1 << 2,
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

struct BundlePolicyInfo {
    std::vector<std::string> reqPermissions;
};

struct HapVerifyResultInfo {
    uint32_t index = 0;
    int32_t errorCode = 0;
};

class HapBaseInfo final {
public:
    int32_t userID = 0;
    std::string bundleName;
    int32_t instIndex = 0;
};

struct Identity final {
    FullTokenID tokenId = 0;
    int32_t uid = 0;
};

enum class MultipleMode : int32_t {
    DEFAULT_OR_MAIN_MODE = 0,
    SUB_MODE = 1,
};

struct BundleHapList final {
    std::vector<std::string> hapPaths;
    bool isPreInstalled = false;
    int32_t userId = 0;
    MultipleMode mode = MultipleMode::DEFAULT_OR_MAIN_MODE;
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

// Mirrors the DlpType enum of the access token SDK (see HapDlpType in
// access_token.h): consumed by BundleSpmManager::CreateBundlePolicy.
enum DlpType {
    DLP_TYPE_NONE = 0,
    DLP_TYPE_FULL_CONTROLLED = 1,
    DLP_TYPE_READ_ONLY = 2,
};

struct BundlePolicy final {
    std::vector<PreAuthorizationInfo> preAuthorizationInfo;
    int32_t dlpType = 0;
    bool isDebugGrant = false;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // ACCESSTOKEN_HAP_TOKEN_INFO_H