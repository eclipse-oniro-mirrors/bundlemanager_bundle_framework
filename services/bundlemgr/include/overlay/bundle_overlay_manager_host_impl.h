/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

#ifndef FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_SERVICE_BUNDLEMGR_INCLUDE_OVERLAY_MANAGER_HOST_IMPL_H
#define FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_SERVICE_BUNDLEMGR_INCLUDE_OVERLAY_MANAGER_HOST_IMPL_H

#include <atomic>

#include "overlay_manager_stub.h"

namespace OHOS {
namespace AppExecFwk {
class OverlayManagerHostImpl : public OverlayManagerStub {
public:
    OverlayManagerHostImpl();
    virtual ~OverlayManagerHostImpl();

    virtual ErrCode GetAllOverlayModuleInfo(const std::string &bundleName, int32_t userId,
        std::vector<OverlayModuleInfo> &overlayModuleInfo, int32_t &funcResult) override;
    virtual ErrCode GetOverlayModuleInfo(const std::string &bundleName, const std::string &moduleName, int32_t userId,
        OverlayModuleInfo &overlayModuleInfo, int32_t &funcResult) override;
    virtual ErrCode GetOverlayModuleInfo(const std::string &moduleName, int32_t userId,
        OverlayModuleInfo &overlayModuleInfo, int32_t &funcResult) override;
    virtual ErrCode GetTargetOverlayModuleInfo(const std::string &targetModuleName, int32_t userId,
        std::vector<OverlayModuleInfo> &overlayModuleInfos, int32_t &funcResult) override;
    virtual ErrCode GetOverlayModuleInfoByBundleName(const std::string &bundleName, const std::string &moduleName,
        int32_t userId, std::vector<OverlayModuleInfo> &overlayModuleInfos, int32_t &funcResult) override;
    virtual ErrCode GetOverlayBundleInfoForTarget(const std::string &targetBundleName, int32_t userId,
        std::vector<OverlayBundleInfo> &overlayBundleInfo, int32_t &funcResult) override;
    virtual ErrCode GetOverlayModuleInfoForTarget(const std::string &targetBundleName,
        const std::string &targetModuleName, int32_t userId, std::vector<OverlayModuleInfo> &overlayModuleInfo,
        int32_t& funcResult) override;
    virtual ErrCode SetOverlayEnabledForSelf(const std::string &moduleName, bool isEnabled, int32_t userId,
        int32_t& funcResult) override;
    virtual ErrCode SetOverlayEnabled(const std::string &bundleName, const std::string &moduleName, bool isEnabled,
        int32_t userId, int32_t &funcResult) override;
    virtual int32_t CallbackEnter([[maybe_unused]] uint32_t code) override;
    virtual int32_t CallbackExit([[maybe_unused]] uint32_t code, [[maybe_unused]] int32_t result) override;
};
} // AppExecFwk
} // OHOS
#endif // FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_SERVICE_BUNDLEMGR_INCLUDE_OVERLAY_MANAGER_HOST_IMPL_H