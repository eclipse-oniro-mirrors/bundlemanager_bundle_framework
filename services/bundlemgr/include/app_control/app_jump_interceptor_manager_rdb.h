/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef FOUNDATION_BUNDLE_FRAMEWORK_SERVICE_INCLUDE_APP_JUMP_INTERCEPTOR_MANAGER_RDB_H
#define FOUNDATION_BUNDLE_FRAMEWORK_SERVICE_INCLUDE_APP_JUMP_INTERCEPTOR_MANAGER_RDB_H

#include "app_jump_interceptor_event_subscriber.h"
#include "app_jump_interceptor_manager_db_interface.h"

#include "rdb_data_manager.h"

namespace OHOS {
namespace AppExecFwk {
class AppJumpInterceptorManagerRdb : public IAppJumpInterceptorlManagerDb,
    public std::enable_shared_from_this<AppJumpInterceptorManagerRdb> {
public:
    AppJumpInterceptorManagerRdb();
    ~AppJumpInterceptorManagerRdb();

    virtual ErrCode ConfirmAppJumpControlRule(const std::string &callerBundleName,
        const std::string &targetBundleName, int32_t userId) override;
    virtual ErrCode AddAppJumpControlRule(const std::vector<AppJumpControlRule> &controlRules, int32_t userId) override;
    virtual ErrCode DeleteAppJumpControlRule(const std::vector<AppJumpControlRule> &controlRules,
        int32_t userId) override;
    virtual ErrCode DeleteRuleByCallerBundleName(const std::string &callerBundleName, int32_t userId) override;
    virtual ErrCode DeleteRuleByTargetBundleName(const std::string &targetBundleName, int32_t userId) override;
    virtual ErrCode GetAppJumpControlRule(const std::string &callerBundleName, const std::string &targetBundleName,
        int32_t userId, AppJumpControlRule &controlRule) override;
    virtual bool SubscribeCommonEvent() override;
private:
    std::shared_ptr<RdbDataManager> rdbDataManager_;
    sptr<AppJumpInterceptorEventSubscriber> eventSubscriber_;
};
} // namespace AppExecFwk
} // namespace OHOS
#endif // FOUNDATION_BUNDLE_FRAMEWORK_SERVICE_INCLUDE_APP_JUMP_INTERCEPTOR_MANAGER_RDB_H