/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

#include "account_helper.h"

#include <thread>

#include "app_log_wrapper.h"
#include "bundle_constants.h"
#include "bundle_service_constants.h"
#include "parameters.h"
#include "string_ex.h"

#ifdef ACCOUNT_ENABLE
#include "os_account_manager.h"
#endif
#include "accesstoken_kit.h"
#include "ipc_skeleton.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
    constexpr int32_t RETRY_TIMES = 20;
    constexpr int32_t RETRY_INTERVAL = 50; // 50ms
}

int32_t AccountHelper::IsOsAccountExists(const int32_t id, bool &isOsAccountExists)
{
#ifdef ACCOUNT_ENABLE
    return AccountSA::OsAccountManager::IsOsAccountCompleted(id, isOsAccountExists);
#else
    APP_LOGI("ACCOUNT_ENABLE is false");
    // ACCOUNT_ENABLE is false, do nothing and return -1.
    return -1;
#endif
}

void AccountHelper::QueryAllCreatedOsAccounts(std::set<int32_t> &userIds)
{
#ifdef ACCOUNT_ENABLE
    std::vector<AccountSA::OsAccountInfo> osAccountInfos;
    if (AccountSA::OsAccountManager::QueryAllCreatedOsAccounts(osAccountInfos) == 0) {
        for (AccountSA::OsAccountInfo acct : osAccountInfos) {
            userIds.insert(acct.GetLocalId());
        }
    }
#else
    APP_LOGI("ACCOUNT_ENABLE is false");
    // ACCOUNT_ENABLE is false, do nothing .
#endif
}

int32_t AccountHelper::GetCurrentActiveUserId()
{
#ifdef ACCOUNT_ENABLE
    int32_t localId;
    int32_t ret = AccountSA::OsAccountManager::GetForegroundOsAccountLocalId(localId);
    if (ret != 0) {
        APP_LOGE_NOFUNC("GetForegroundOsAccountLocalId failed ret:%{public}d", ret);
        return Constants::INVALID_USERID;
    }
    return localId;
#else
    APP_LOGI("ACCOUNT_ENABLE is false");
    return 0;
#endif
}

int32_t AccountHelper::GetUserIdByCallerType()
{
    auto callerToken = IPCSkeleton::GetCallingTokenID();
    auto tokenType = Security::AccessToken::AccessTokenKit::GetTokenTypeFlag(callerToken);
    if (tokenType == Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE ||
        tokenType == Security::AccessToken::ATokenTypeEnum::TOKEN_SHELL) {
        return AccountHelper::GetCurrentActiveUserId();
    }

    return AccountHelper::GetOsAccountLocalIdFromUid(IPCSkeleton::GetCallingUid());
}

bool AccountHelper::IsOsAccountVerified(const int32_t userId)
{
#ifdef ACCOUNT_ENABLE
    bool isOsAccountVerified = false;
    int32_t ret = AccountSA::OsAccountManager::IsOsAccountVerified(userId, isOsAccountVerified);
    if (ret != 0) {
        APP_LOGE("IsOsAccountVerified failed ret:%{public}d", ret);
        return false;
    }
    return isOsAccountVerified;
#else
    APP_LOGI("ACCOUNT_ENABLE is false");
    return false;
#endif
}

int32_t AccountHelper::GetOsAccountLocalIdFromUid(const int32_t callingUid)
{
    int32_t localId = callingUid < Constants::DEFAULT_USERID ? Constants::INVALID_USERID :
        callingUid / Constants::BASE_USER_RANGE;
#ifdef ACCOUNT_ENABLE
    if (localId <= Constants::DEFAULT_USERID) {
        APP_LOGW_NOFUNC("GetOsAccountLocalIdFromUid fail uid:%{public}d req from active userid", callingUid);
        return AccountHelper::GetCurrentActiveUserId();
    }
    return localId;
#else
    APP_LOGI("ACCOUNT_ENABLE is false");
    // ACCOUNT_ENABLE is false, do nothing and return -1.
    return localId;
#endif
}

int32_t AccountHelper::GetCurrentActiveUserIdWithRetry(bool isOtaInstall)
{
#ifdef ACCOUNT_ENABLE
    // Failed to obtain foreground Os Account when OTA. BMS SA is not registered.
    int32_t localId = Constants::INVALID_USERID;
    if (!isOtaInstall) {
        localId = GetCurrentActiveUserId();
        if (localId != Constants::INVALID_USERID) {
            return localId;
        }
    }
    int32_t retryCnt = 0;
    do {
        int32_t ret = AccountSA::OsAccountManager::GetDefaultActivatedOsAccount(localId);
        if (ret == 0) {
            break;
        }
        ++retryCnt;
        std::this_thread::sleep_for(std::chrono::milliseconds(RETRY_INTERVAL));
        APP_LOGW("get foregroud osAccount failed, retry count: %{public}d, ret: %{public}d", retryCnt, ret);
    } while (retryCnt < RETRY_TIMES);

    return localId;
#else
    APP_LOGI("ACCOUNT_ENABLE is false");
    return Constants::INVALID_USERID;
#endif
}

bool AccountHelper::CheckOsAccountConstraintEnabled(const int32_t userId, const std::string &constraint)
{
#ifdef ACCOUNT_ENABLE
    bool isEnabled = false;
    int32_t ret = AccountSA::OsAccountManager::CheckOsAccountConstraintEnabled(userId, constraint, isEnabled);
    if (ret != 0) {
        APP_LOGE("failed ret:%{public}d", ret);
        return false;
    }
    return isEnabled;
#else
    APP_LOGI("ACCOUNT_ENABLE is false");
    return false;
#endif
}

bool AccountHelper::CheckUserIsolation(
    const int32_t targetUserId, const std::unordered_set<int32_t> &installedUserIds)
{
    std::set<int32_t> enterpriseUserIds = GetEnterpriseUserIds();
    if (enterpriseUserIds.empty()) {
        return true;
    }

    bool inEnterpriseSpace = false;
    bool inPrivacySpace = false;
    for (int32_t installedUserId : installedUserIds) {
        if (installedUserId < Constants::START_USERID) {
            continue;
        }
        if (enterpriseUserIds.find(installedUserId) != enterpriseUserIds.end()) {
            inEnterpriseSpace = true;
        } else {
            inPrivacySpace = true;
        }
    }

    if (!inEnterpriseSpace && !inPrivacySpace) {
        return true;
    }
    if (inEnterpriseSpace && inPrivacySpace) {
        APP_LOGE("bundle is in both enterprise and privacy space");
        return false;
    }

    bool targetEnterprise = enterpriseUserIds.find(targetUserId) != enterpriseUserIds.end();
    if (inEnterpriseSpace && targetEnterprise) {
        return true;
    }
    if (inPrivacySpace && !targetEnterprise) {
        return true;
    }
    APP_LOGE("target user %{public}d is not in the same space", targetUserId);
    return false;
}

std::set<int32_t> AccountHelper::GetEnterpriseUserIds()
{
    std::string userIdListStr = OHOS::system::GetParameter(ServiceConstants::ENTERPRISE_SPACE_USER_ID_LIST, "");
    if (userIdListStr.empty()) {
        return {};
    }
    std::vector<std::string> strVector;
    OHOS::SplitStr(userIdListStr, ServiceConstants::COMMA, strVector);
    if (strVector.empty()) {
        return {};
    }
    std::set<int32_t> enterpriseUserIds;
    for (const std::string &userIdStr : strVector) {
        int32_t userId = -1;
        if (OHOS::StrToInt(userIdStr, userId)) {
            enterpriseUserIds.insert(userId);
        }
    }
    return enterpriseUserIds;
}
}  // namespace AppExecFwk
}  // namespace OHOS
