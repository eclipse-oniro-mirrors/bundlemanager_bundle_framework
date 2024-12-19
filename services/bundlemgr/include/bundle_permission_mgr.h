/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_BUNDLE_PERMISSION_MGR_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_BUNDLE_PERMISSION_MGR_H

#include "accesstoken_kit.h"
#include "bundle_constants.h"
#include "default_permission.h"
#include "inner_bundle_info.h"
#include "permission_define.h"

namespace OHOS {
namespace AppExecFwk {
class BundlePermissionMgr {
public:
    /**
     * @brief Initialize BundlePermissionMgr, which is only called when the system starts.
     * @return Returns true if successfully initialized BundlePermissionMgr; returns false otherwise.
     */
    static bool Init();

    static void UnInit();

    /**
     * @brief Verify whether a specified bundle has been granted a specific permission.
     * @param bundleName Indicates the name of the bundle to check.
     * @param permission Indicates the permission to check.
     * @param userId Indicates the userId of the bundle.
     * @return Returns 0 if the bundle has the permission; returns -1 otherwise.
     */
    static int32_t VerifyPermission(const std::string &bundleName, const std::string &permissionName,
        const int32_t userId);
    /**
     * @brief Obtains detailed information about a specified permission.
     * @param permissionName Indicates the name of the permission.
     * @param permissionDef Indicates the object containing detailed information about the given permission.
     * @return Returns true if the PermissionDef object is successfully obtained; returns false otherwise.
     */
    static ErrCode GetPermissionDef(const std::string &permissionName, PermissionDef &permissionDef);
    /**
     * @brief Requests a certain permission from user.
     * @param bundleName Indicates the name of the bundle.
     * @param permission Indicates the permission to request.
     * @param userId Indicates the userId of the bundle.
     * @return Returns true if the permission request successfully; returns false otherwise.
     */
    static bool RequestPermissionFromUser(
        const std::string &bundleName, const std::string &permissionName, const int32_t userId);

    static int32_t InitHapToken(const InnerBundleInfo &innerBundleInfo, const int32_t userId,
        const int32_t dlpType, Security::AccessToken::AccessTokenIDEx &tokenIdeEx,
        Security::AccessToken::HapInfoCheckResult &checkResult);

    static int32_t UpdateHapToken(Security::AccessToken::AccessTokenIDEx &tokenIdeEx,
        const InnerBundleInfo &innerBundleInfo, Security::AccessToken::HapInfoCheckResult &checkResult);

    static std::string GetCheckResultMsg(const Security::AccessToken::HapInfoCheckResult &checkResult);

    static int32_t DeleteAccessTokenId(const Security::AccessToken::AccessTokenID tokenId);

    static bool GetRequestPermissionStates(BundleInfo &bundleInfo, uint32_t tokenId, const std::string deviceId);

    static int32_t ClearUserGrantedPermissionState(const Security::AccessToken::AccessTokenID tokenId);

    static bool GetAllReqPermissionStateFull(Security::AccessToken::AccessTokenID tokenId,
        std::vector<Security::AccessToken::PermissionStateFull> &newPermissionState);

    static bool VerifySystemApp(int32_t beginApiVersion = Constants::INVALID_API_VERSION);

    static bool IsSystemApp();

    static int32_t GetHapApiVersion();

    static bool IsNativeTokenType();

    static bool IsShellTokenType();

    static bool VerifyCallingUid();

    static bool VerifyPreload(const AAFwk::Want &want);

    static bool VerifyCallingPermissionForAll(const std::string &permissionName);

    static bool VerifyCallingPermissionsForAll(const std::vector<std::string> &permissionNames);

    static bool IsSelfCalling();

    static bool VerifyUninstallPermission();

    static bool VerifyRecoverPermission();

    static void AddPermissionUsedRecord(const std::string &permission, int32_t successCount, int32_t failCount);

    static bool IsBundleSelfCalling(const std::string &bundleName);

    // for old api
    static bool VerifyCallingBundleSdkVersion(int32_t beginApiVersion = Constants::INVALID_API_VERSION);

    static bool IsCallingUidValid(int32_t uid);

private:
    static std::vector<Security::AccessToken::PermissionDef> GetPermissionDefList(
        const InnerBundleInfo &innerBundleInfo);

    static std::vector<Security::AccessToken::PermissionStateFull> GetPermissionStateFullList(
        const InnerBundleInfo &innerBundleInfo);

    static Security::AccessToken::ATokenAplEnum GetTokenApl(const std::string &apl);

    static Security::AccessToken::HapPolicyParams CreateHapPolicyParam(const InnerBundleInfo &innerBundleInfo);

    static Security::AccessToken::HapInfoParams CreateHapInfoParams(const InnerBundleInfo &innerBundleInfo,
        const int32_t userId, const int32_t dlpType);

    static void ConvertPermissionDef(const Security::AccessToken::PermissionDef &permDef,
        PermissionDef &permissionDef);
    static void ConvertPermissionDef(
        Security::AccessToken::PermissionDef &permDef, const DefinePermission &defPermission,
        const std::string &bundleName);

    static Security::AccessToken::ATokenAvailableTypeEnum GetAvailableType(const std::string &availableType);

    static bool GetDefaultPermission(const std::string &bundleName, DefaultPermission &permission);

    static bool MatchSignature(const DefaultPermission &permission, const std::vector<std::string> &signatures);

    static bool MatchSignature(const DefaultPermission &permission, const std::string &signature);

    static bool CheckPermissionInDefaultPermissions(const DefaultPermission &defaultPermission,
        const std::string &permissionName, bool &userCancellable);

    static std::map<std::string, DefaultPermission> defaultPermissions_;
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_BUNDLE_PERMISSION_MGR_H