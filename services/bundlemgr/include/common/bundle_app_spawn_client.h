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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_COMMON_BUNDLE_APP_SPAWN_CLIENT_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_COMMON_BUNDLE_APP_SPAWN_CLIENT_H

#include <mutex>
#include <string>

#include "appexecfwk_errors.h"
#include "appspawn.h"
#include "nocopyable.h"

namespace OHOS {
namespace AppExecFwk {
enum class SpawnConnectionState { STATE_NOT_CONNECT, STATE_CONNECTED, STATE_CONNECT_FAILED };
struct AppSpawnRemoveSandboxDirMsg {
    std::string bundleName;
    int32_t uid = 0;
    int32_t code = 0;
    int32_t bundleIndex = 0;
    AppFlagsIndex flags = AppFlagsIndex::APP_FLAGS_COLD_BOOT;
};

class BundleAppSpawnClient {
public:
    static BundleAppSpawnClient& GetInstance();
    int32_t RemoveSandboxDir(const AppSpawnRemoveSandboxDirMsg &removeSandboxDirMsg);
private:
    DISALLOW_COPY_AND_MOVE(BundleAppSpawnClient);
    BundleAppSpawnClient();
    ~BundleAppSpawnClient();
    void CloseConnection();
    int32_t OpenConnection();
    int32_t AppspawnCreateDefaultMsg(const AppSpawnRemoveSandboxDirMsg &removeSandboxDirMsg,
        AppSpawnReqMsgHandle reqHandle);
    bool VerifyMsg(const AppSpawnRemoveSandboxDirMsg &removeSandboxDirMsg);
private:
    std::string serviceName_;
    AppSpawnClientHandle handle_;
    SpawnConnectionState state_;
    std::mutex mutex_;
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_COMMON_BUNDLE_APP_SPAWN_CLIENT_H