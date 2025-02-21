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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_MIGRATE_DATA_USER_AUTH_CALLBACK_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_MIGRATE_DATA_USER_AUTH_CALLBACK_H

#ifdef BMS_USER_AUTH_FRAMEWORK_ENABLED
#include <atomic>
#include <future>

#include "user_auth_client_callback.h"

namespace OHOS {
namespace AppExecFwk {
using namespace OHOS::UserIam::UserAuth;
class MigrateDataUserAuthCallback final : public AuthenticationCallback {
public:
    MigrateDataUserAuthCallback();
    ~MigrateDataUserAuthCallback();
    void OnAcquireInfo(int32_t module, uint32_t acquireInfo, const Attributes &extraInfo) override;
    void OnResult(int32_t result, const Attributes &extraInfo) override;
    int32_t GetUserAuthResult();

private:
    std::atomic<bool> isComplete_{ false };
    std::promise<int32_t> resultPromise_;
    std::shared_future<int32_t> future_ = resultPromise_.get_future().share();
    int32_t result_{ 0 };
};
} // namespace AppExecFwk
} // namespace OHOS
#endif // BMS_USER_AUTH_FRAMEWORK_ENABLED
#endif // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_MIGRATE_DATA_USER_AUTH_CALLBACK_H