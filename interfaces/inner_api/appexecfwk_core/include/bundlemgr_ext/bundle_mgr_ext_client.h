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

#ifndef FOUNDATION_APPEXECFWK_INTERFACES_INNERKITS_APPEXECFWK_CORE_INCLUDE_BUNDLEMGR_BUNDLE_MGR_EXT_CLIENT_H
#define FOUNDATION_APPEXECFWK_INTERFACES_INNERKITS_APPEXECFWK_CORE_INCLUDE_BUNDLEMGR_BUNDLE_MGR_EXT_CLIENT_H

#include <mutex>

#include "appexecfwk_errors.h"
#include "bundle_constants.h"
#include "bundle_mgr_interface.h"

namespace OHOS {
namespace AppExecFwk {

class BundleMgrExtClient {
public:
    static BundleMgrExtClient &GetInstance();
    ErrCode GetBundleNamesForUidExt(const int32_t uid, std::vector<std::string> &bundleNames);

private:
    BundleMgrExtClient() = default;
    ~BundleMgrExtClient() = default;
    DISALLOW_COPY_AND_MOVE(BundleMgrExtClient);
private:
    class BundleMgrExtDeathRecipient : public IRemoteObject::DeathRecipient {
    public:
        BundleMgrExtDeathRecipient() = default;
        ~BundleMgrExtDeathRecipient() override = default;
        void OnRemoteDied(const wptr<IRemoteObject>& remote) override;

    private:
        DISALLOW_COPY_AND_MOVE(BundleMgrExtDeathRecipient);
    };
    sptr<IBundleMgrExt> GetBundleMgrExtProxy();
    void ResetBundleMgrExtProxy(const wptr<IRemoteObject> &remote);

private:
    std::mutex mutex_;
    sptr<IBundleMgrExt> bundleMgrExtProxy_;
    sptr<IRemoteObject::DeathRecipient> deathRecipient_ = nullptr;
};
} // namespace AppExecFwk
} // namespace OHOS
#endif // FOUNDATION_APPEXECFWK_INTERFACES_INNERKITS_APPEXECFWK_CORE_INCLUDE_BUNDLEMGR_BUNDLE_MGR_EXT_CLIENT_H