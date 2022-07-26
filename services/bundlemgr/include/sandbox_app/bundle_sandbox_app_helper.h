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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_BUNDLE_SANDBOX_APP_HELPER_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_BUNDLE_SANDBOX_APP_HELPER_H

#include <map>
#include <string>

#include "appexecfwk_errors.h"
#include "bundle_data_storage_interface.h"
#include "bundle_constants.h"
#include "inner_bundle_info.h"
#include "singleton.h"

#ifdef BUNDLE_FRAMEWORK_SANDBOX_APP
#include "bundle_sandbox_data_mgr.h"
#endif

namespace OHOS {
namespace AppExecFwk {
class BundleSandboxAppHelper : public DelayedSingleton<BundleSandboxAppHelper> {
public:
    // BundleSandboxDataMgr interface
    void SaveSandboxAppInfo(const InnerBundleInfo &info, const int32_t &appIndex);
    void DeleteSandboxAppInfo(const std::string &bundleName, const int32_t &appIndex);
    ErrCode GetSandboxAppBundleInfo(
        const std::string &bundleName, const int32_t &appIndex, const int32_t &userId, BundleInfo &info) const;
    int32_t GenerateSandboxAppIndex(const std::string &bundleName);
    bool DeleteSandboxAppIndex(const std::string &bundleName, int32_t appIndex);
    std::unordered_map<std::string, InnerBundleInfo> GetSandboxAppInfoMap() const;
    ErrCode GetSandboxAppInfo(
        const std::string &bundleName, const int32_t &appIndex, int32_t &userId, InnerBundleInfo &info) const;
    ErrCode GetSandboxHapModuleInfo(const AbilityInfo &abilityInfo, int32_t appIndex, int32_t userId,
        HapModuleInfo &hapModuleInfo) const;
    ErrCode GetInnerBundleInfoByUid(const int32_t &uid, InnerBundleInfo &innerBundleInfo) const;

    // BundleSandboxExceptionHandler interface
    void RemoveSandboxApp(const std::shared_ptr<IBundleDataStorage> &dataStorage, InnerBundleInfo &info);

    // BundleSandboxInstaller interface
    ErrCode InstallSandboxApp(const std::string &bundleName, const int32_t &dlpType, const int32_t &userId,
        int32_t &appIndex);

    ErrCode UninstallSandboxApp(const std::string &bundleName, const int32_t &appIndex, const int32_t &userId);

    ErrCode UninstallAllSandboxApps(const std::string &bundleName, int32_t userId = Constants::INVALID_USERID);

#ifdef BUNDLE_FRAMEWORK_SANDBOX_APP
    std::shared_ptr<BundleSandboxDataMgr> GetSandboxDataMgr() const
    {
        return sandboxDataMgr_;
    }
#endif

#ifdef BUNDLE_FRAMEWORK_SANDBOX_APP
private:
    std::shared_ptr<BundleSandboxDataMgr> sandboxDataMgr_ = std::make_shared<BundleSandboxDataMgr>();
#endif
};
} // AppExecFwk
} // OHOS

#endif // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_BUNDLE_SANDBOX_APP_HELPER_H