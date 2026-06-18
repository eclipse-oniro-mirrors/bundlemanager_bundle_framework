/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_BUNDLE_CLI_SANDBOX_INSTALLER_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_BUNDLE_CLI_SANDBOX_INSTALLER_H

#include <string>

#include "bundle_data_mgr.h"
#include "event_report.h"
#include "inner_bundle_info.h"
#include "inner_cli_sandbox_info.h"

namespace OHOS {
namespace AppExecFwk {
class BundleCliSandboxInstaller final {
public:
    BundleCliSandboxInstaller();
    ~BundleCliSandboxInstaller();

    /**
     * @brief Create CLI sandbox application.
     * @param callerBundleName Indicates the caller package name.
     * @param bundleName Indicates the bundle name of the application.
     * @param userId Indicates the user id.
     * @param appIndex Indicates the appIndex of the created sandbox.
     * @return Returns ERR_OK if created successfully; returns error code otherwise.
     */
    ErrCode CreateCliSandboxApp(const std::string &callerBundleName,
        const std::string &bundleName, int32_t userId, int32_t &appIndex);

    /**
     * @brief Destroy CLI sandbox application.
     * @param callerBundleName Indicates the caller bundle name.
     * @param envCallerBundleName Indicates the env caller bundle name.
     * @param bundleName Indicates the bundle name of the application.
     * @param userId Indicates the user id.
     * @param appIndex Indicates the appIndex of the sandbox to destroy.
     * @return Returns ERR_OK if destroyed successfully; returns error code otherwise.
     */
    ErrCode DestroyCliSandboxApp(const std::string &creatorBundleName,
        const std::string &envCallerBundleName, const std::string &bundleName,
        int32_t userId, int32_t appIndex, bool skipCallerCheck);

    /**
     * @brief Destroy all CLI sandbox applications for a specific bundle under a specific user.
     * @param bundleName Indicates the bundle name of the application.
     * @param userId Indicates the user id.
     * @return Returns ERR_OK if all destroyed successfully; returns error code otherwise.
     */
    ErrCode DestroyAllCliSandboxApps(const std::string &bundleName, int32_t userId);

private:
    ErrCode ProcessDestroyCliSandbox(const std::string &creatorBundleName,
        const std::string &envCallerBundleName, const std::string &bundleName,
        int32_t userId, int32_t appIndex, bool skipCallerCheck);
    void UninstallDebugAppSandbox(const std::string &bundleName, const int32_t uid,
        int32_t appIndex, const InnerBundleInfo& innerBundleInfo);

    ErrCode ProcessCreateCliSandbox(const std::string &callerBundleName,
        const std::string &bundleName, int32_t userId, int32_t &appIndex);
    ErrCode CreateSandboxDataDir(InnerBundleInfo &info, int32_t userId,
        int32_t uid, int32_t appIndex) const;
    ErrCode RemoveSandboxDataDir(const std::string &bundleName, int32_t userId, int32_t appIndex, bool sync) const;
    ErrCode GetDataMgr();
    std::string GetActualCreatorBundleName(const std::string &creatorBundleName,
        const std::string &envCallerBundleName, int32_t userId);

    void CreateEl5Dir(InnerBundleInfo &info, const int32_t userId,
        const int32_t uid, const int32_t appIndex);
    void RemoveEl5Dir(const std::string &bundleName, int32_t userId, const int32_t appIndex);
    void ResetInstallProperties();

    std::shared_ptr<BundleDataMgr> dataMgr_ = nullptr;
    int32_t uid_ = 0;
    uint32_t accessTokenId_ = 0;
    std::string appId_;
    std::string appIdentifier_;
    int64_t versionCode_ = 0;
    bool isBundleCrossAppSharedConfig_ = false;
    std::string appDistributionType_;
    int32_t sessionId_ = 0;
    bool sessionCommitted_ = false;
    int64_t startTime_ = 0;
};
} // namespace AppExecFwk
} // namespace OHOS
#endif // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_BUNDLE_CLI_SANDBOX_INSTALLER_H
