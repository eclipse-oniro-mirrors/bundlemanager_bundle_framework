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
#ifndef FOUNDATION_APPEXECFWK_INTERFACES_INNERAPI_APPEXECFWK_CORE_INCLUDE_OVERLAY_MANAGER_CLIENT_H
#define FOUNDATION_APPEXECFWK_INTERFACES_INNERAPI_APPEXECFWK_CORE_INCLUDE_OVERLAY_MANAGER_CLIENT_H

#include <mutex>

#include "bundle_constants.h"
#include "ioverlay_manager.h"
#include "overlay/overlay_bundle_info.h"
#include "overlay/overlay_module_info.h"

namespace OHOS {
namespace AppExecFwk {
class OverlayManagerClient {
public:
    static OverlayManagerClient &GetInstance();

    ErrCode GetAllOverlayModuleInfo(const std::string &bundleName,
        std::vector<OverlayModuleInfo> &overlayModuleInfos, int32_t userId = Constants::UNSPECIFIED_USERID);

    ErrCode GetOverlayModuleInfo(const std::string &bundleName, const std::string &moduleName,
        OverlayModuleInfo &overlayModuleInfo, int32_t userId = Constants::UNSPECIFIED_USERID);

    ErrCode GetOverlayModuleInfo(const std::string &moduleName, OverlayModuleInfo &overlayModuleInfo,
        int32_t userId = Constants::UNSPECIFIED_USERID);

    ErrCode GetTargetOverlayModuleInfo(const std::string &targetModuleName,
        std::vector<OverlayModuleInfo> &overlayModuleInfos, int32_t userId = Constants::UNSPECIFIED_USERID);

    ErrCode GetOverlayModuleInfoByBundleName(const std::string &bundleName, const std::string &moduleName,
        std::vector<OverlayModuleInfo> &overlayModuleInfos, int32_t userId = Constants::UNSPECIFIED_USERID);

    ErrCode GetOverlayBundleInfoForTarget(const std::string &targetBundleName,
        std::vector<OverlayBundleInfo> &overlayBundleInfos, int32_t userId = Constants::UNSPECIFIED_USERID);

    ErrCode GetOverlayModuleInfoForTarget(const std::string &targetBundleName,
        const std::string &targetModuleName, std::vector<OverlayModuleInfo> &overlayModuleInfos,
        int32_t userId = Constants::UNSPECIFIED_USERID);

    ErrCode SetOverlayEnabled(const std::string &bundleName, const std::string &moduleName,
        bool isEnabled, int32_t userId = Constants::UNSPECIFIED_USERID);

    ErrCode SetOverlayEnabledForSelf(const std::string &moduleName, bool isEnabled,
        int32_t userId = Constants::UNSPECIFIED_USERID);

private:
    OverlayManagerClient() = default;
    ~OverlayManagerClient() = default;
    DISALLOW_COPY_AND_MOVE(OverlayManagerClient);
    sptr<IOverlayManager> GetOverlayManagerProxy();
    void ResetOverlayManagerProxy(const wptr<IRemoteObject>& remote);
    class OverlayManagerDeathRecipient : public IRemoteObject::DeathRecipient {
    public:
        OverlayManagerDeathRecipient() = default;
        ~OverlayManagerDeathRecipient() override = default;
        void OnRemoteDied(const wptr<IRemoteObject>& remote) override;

    private:
        DISALLOW_COPY_AND_MOVE(OverlayManagerDeathRecipient);
    };
    std::mutex mutex_;
    sptr<IOverlayManager> overlayManagerProxy_;
    sptr<IRemoteObject::DeathRecipient> deathRecipient_;
};
} // AppExecFwk
} // OHOS
#endif // FOUNDATION_APPEXECFWK_INTERFACES_INNERAPI_APPEXECFWK_CORE_INCLUDE_OVERLAY_MANAGER_CLIENT_H