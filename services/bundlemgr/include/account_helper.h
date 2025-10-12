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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_ACCOUNT_HELPER_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_ACCOUNT_HELPER_H

#include <set>
#include <string>
#include <unordered_set>

namespace OHOS {
namespace AppExecFwk {
class AccountHelper {
public:
    static int32_t IsOsAccountExists(const int32_t id, bool &isOsAccountExists);

    static int32_t GetCurrentActiveUserId();

    static int32_t GetUserIdByCallerType();

    static bool IsOsAccountVerified(const int32_t userId);

    static int32_t GetOsAccountLocalIdFromUid(const int32_t callingUid);

    static int32_t GetCurrentActiveUserIdWithRetry(bool isOtaInstall = false);

    static void QueryAllCreatedOsAccounts(std::set<int32_t> &userIds);

    static bool CheckOsAccountConstraintEnabled(const int32_t userId, const std::string &constraint);

    static bool CheckUserIsolation(const int32_t targetUserId, const std::unordered_set<int32_t> &installedUserIds);
private:
    static std::set<int32_t> GetEnterpriseUserIds();
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_ACCOUNT_HELPER_H
