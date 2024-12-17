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

#include "accesstoken_kit.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
#ifdef BUNDLE_PERMISSION_DEF_LIST
#ifdef BUNDLE_PERMISSION_DEF_TRUE
static constexpr int GRANT_STATUS = 100;
#endif
#endif
AccessTokenIDEx AccessTokenKit::AllocHapToken(const HapInfoParams& info, const HapPolicyParams& policy)
{
    AccessTokenIDEx token;
    token.tokenIDEx = 1;
    token.tokenIdExStruct.tokenID = 1;
    token.tokenIdExStruct.tokenAttr = 1;
    return token;
}

#ifdef BUNDLE_PERMISSION_START_FULL_FALSE
int AccessTokenKit::GetDefPermissions(AccessTokenID tokenID, std::vector<PermissionDef>& permList)
{
#ifdef BUNDLE_PERMISSION_DEF_TRUE
    PermissionDef PermissionDef;
    PermissionDef.permissionName = "testName";
    permList.push_back(PermissionDef);
    return 0;
#else
    return -1;
#endif
}
#else
int AccessTokenKit::GetDefPermissions(AccessTokenID tokenID, std::vector<PermissionDef>& permList)
{
    return 0;
}
#endif


#ifdef BUNDLE_PERMISSION_DEF_LIST
int AccessTokenKit::GetReqPermissions(AccessTokenID tokenID, std::vector<PermissionStateFull>& reqPermList,
    bool isSystemGrant)
{
    #ifdef BUNDLE_PERMISSION_DEF_TRUE
    PermissionStateFull permissionStateFull;
    permissionStateFull.permissionName = "testName";
    permissionStateFull.resDeviceID.push_back("100");
    permissionStateFull.grantStatus.push_back(GRANT_STATUS);
    reqPermList.push_back(permissionStateFull);
    return 0;
    #else
    return -1;
    #endif
}

int AccessTokenKit::GrantPermission(AccessTokenID tokenID, const std::string& permissionName, uint32_t flag)
{
    return 1;
}

int AccessTokenKit::VerifyAccessToken(AccessTokenID tokenID, const std::string& permissionName)
{
#ifdef BUNDLE_PERMISSION_DEF_TRUE
    if (permissionName == "testName") {
        return 0;
    } else {
        return -1;
    }
#else
    return -1;
#endif
}

int AccessTokenKit::GetDefPermission(const std::string& permissionName, PermissionDef& permissionDefResult)
{
    return 0;
}

ATokenTypeEnum AccessTokenKit::GetTokenTypeFlag(AccessTokenID tokenID)
{
    return TOKEN_SHELL;
}
#else
int AccessTokenKit::GetReqPermissions(AccessTokenID tokenID, std::vector<PermissionStateFull>& reqPermList,
    bool isSystemGrant)
{
    return 0;
}

int AccessTokenKit::GrantPermission(AccessTokenID tokenID, const std::string& permissionName, uint32_t flag)
{
    return 0;
}

int AccessTokenKit::VerifyAccessToken(AccessTokenID tokenID, const std::string& permissionName)
{
    return 0;
}

int AccessTokenKit::GetDefPermission(const std::string& permissionName, PermissionDef& permissionDefResult)
{
    return -1;
}

ATokenTypeEnum AccessTokenKit::GetTokenTypeFlag(AccessTokenID tokenID)
{
#ifdef BUNDLE_FRAMEWORK_SYSTEM_APP_FALSE
    return TOKEN_INVALID;
#else
    return TOKEN_NATIVE;
#endif
}
#endif

int AccessTokenKit::VerifyAccessToken(
    AccessTokenID callerTokenID, AccessTokenID firstTokenID, const std::string& permissionName)
{
    return 0;
}

int AccessTokenKit::DeleteToken(AccessTokenID tokenID)
{
    return 0;
}

int AccessTokenKit::ClearUserGrantedPermissionState(AccessTokenID tokenID)
{
    return 0;
}

AccessTokenID AccessTokenKit::GetHapTokenID(int userID, const std::string& bundleName, int instIndex)
{
    return 0;
}

AccessTokenIDEx AccessTokenKit::GetHapTokenIDEx(int userID, const std::string& bundleName, int instIndex)
{
    AccessTokenIDEx tokenIdEx;
    return tokenIdEx;
}

int AccessTokenKit::GetNativeTokenInfo(AccessTokenID tokenID, NativeTokenInfo &nativeTokenInfo)
{
    nativeTokenInfo.processName = "foundation";
    return 0;
}

int32_t AccessTokenKit::InitHapToken(const HapInfoParams& info, HapPolicyParams& policy,
    AccessTokenIDEx& fullTokenId, HapInfoCheckResult& checkResult)
{
    fullTokenId.tokenIDEx = 1;
    checkResult.permCheckResult.permissionName = "test"; // invalid Name
    return 0;
}

int32_t AccessTokenKit::UpdateHapToken(AccessTokenIDEx& tokenIdEx, const UpdateHapInfoParams& info,
    const HapPolicyParams& policy, HapInfoCheckResult& checkResult)
{
    if (info.isSystemApp) {
        tokenIdEx.tokenIdExStruct.tokenAttr = 1;
    } else {
        tokenIdEx.tokenIdExStruct.tokenAttr = 0;
    }
    checkResult.permCheckResult.permissionName = "test"; // invalid Name
    return 0;
}
}
}
}