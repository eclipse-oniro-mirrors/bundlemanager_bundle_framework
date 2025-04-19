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

#include "account_helper.h"

#include <thread>

#include "app_log_wrapper.h"
#include "bundle_constants.h"

#ifdef ACCOUNT_ENABLE
#include "os_account_manager.h"
#endif

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

int32_t AccountHelper::GetCurrentActiveUserIdWithRetry()
{
#ifdef ACCOUNT_ENABLE
    int32_t localId = GetCurrentActiveUserId();
    if (localId != Constants::INVALID_USERID) {
        return localId;
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
}  // namespace AppExecFwk
}  // namespace OHOS
