/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#ifdef BMS_USER_AUTH_FRAMEWORK_ENABLED
#include "migrate_data_user_auth_callback.h"

#include <chrono>

#include "appexecfwk_errors.h"

namespace OHOS {
namespace AppExecFwk {
static constexpr int32_t WAIT_TIME = 5;
using namespace OHOS::UserIam::UserAuth;
MigrateDataUserAuthCallback::MigrateDataUserAuthCallback()
    : result_(ERR_BUNDLE_MANAGER_MIGRATE_DATA_USER_AUTHENTICATION_TIME_OUT)
{}
MigrateDataUserAuthCallback::~MigrateDataUserAuthCallback() {}
void MigrateDataUserAuthCallback::OnAcquireInfo(int32_t module, uint32_t acquireInfo, const Attributes &extraInfo) {}

void MigrateDataUserAuthCallback::OnResult(int32_t result, const Attributes &extraInfo)
{
    if (isComplete_.load()) {
        return;
    }
    isComplete_.store(true);
    result_ = result;
    resultPromise_.set_value(result);
}

int32_t MigrateDataUserAuthCallback::GetUserAuthResult()
{
    if (isComplete_.load()) {
        return result_;
    }
    // timeout waiting for five minutes
    auto future = resultPromise_.get_future();
    if (future.wait_for(std::chrono::minutes(WAIT_TIME)) == std::future_status::ready) {
        return future.get();
    }
    return result_;
}
} // namespace AppExecFwk
} // namespace OHOS
#endif // BMS_USER_AUTH_FRAMEWORK_ENABLED