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

#ifndef FOUNDATION_APPEXECFWK_INTERFACES_INNERKITS_APPEXECFWK_CORE_INCLUDE_VERIFY_MANAGER_CLIENT_H
#define FOUNDATION_APPEXECFWK_INTERFACES_INNERKITS_APPEXECFWK_CORE_INCLUDE_VERIFY_MANAGER_CLIENT_H

#include <mutex>

#include "appexecfwk_errors.h"
#include "bundle_info.h"
#include "bundle_mgr_interface.h"
#include "iverify_manager.h"

namespace OHOS {
namespace AppExecFwk {
class VerifyManagerClient {
public:
    static VerifyManagerClient &GetInstance();

    ErrCode Verify(const std::vector<std::string>& abcPaths);
    ErrCode RemoveFiles(const std::vector<std::string>& abcPaths);
    ErrCode DeleteAbc(const std::string& path);

private:
    VerifyManagerClient();
    ~VerifyManagerClient();
    DISALLOW_COPY_AND_MOVE(VerifyManagerClient);

    class VerifyManagerDeathRecipient : public IRemoteObject::DeathRecipient {
    public:
        VerifyManagerDeathRecipient() = default;
        ~VerifyManagerDeathRecipient() override = default;
        void OnRemoteDied(const wptr<IRemoteObject>& remote) override;

    private:
        DISALLOW_COPY_AND_MOVE(VerifyManagerDeathRecipient);
    };
    void ResetVerifyManagerProxy(const wptr<IRemoteObject>& remote);
    sptr<IVerifyManager> GetVerifyManagerProxy();

    std::mutex mutex_;
    sptr<IRemoteObject::DeathRecipient> deathRecipient_;
    sptr<IVerifyManager> verifyManager_;
};
}
}
#endif // FOUNDATION_APPEXECFWK_INTERFACES_INNERKITS_APPEXECFWK_CORE_INCLUDE_VERIFY_MANAGER_CLIENT_H
