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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_BUNDLE_MULTIUSER_INSTALLER_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_BUNDLE_MULTIUSER_INSTALLER_H

#include <string>

#include "bundle_data_mgr.h"

namespace OHOS {
namespace AppExecFwk {
class BundleMultiUserInstaller final {
public:
    BundleMultiUserInstaller();
    ~BundleMultiUserInstaller();

    /**
     * @brief The main function for existed app installing.
     * @param bundleName Indicates the bundleName of the application to install.
     * @param userId Indicates the app will be installed under which user id.
     * @return Returns ERR_OK if the app install successfully; returns error code otherwise.
     */
    ErrCode InstallExistedApp(const std::string &bundleName, const int32_t userId);

    ErrCode ProcessBundleInstall(const std::string &bundleName, const int32_t userId);

    void ResetInstallProperties();
private:
    ErrCode CreateDataDir(
        InnerBundleInfo &info, const int32_t userId, const int32_t &uid) const;
    void CreateEl5Dir(InnerBundleInfo &info, const int32_t userId, const int32_t &uid);
    ErrCode RemoveDataDir(const std::string bundleName, int32_t userId);
    ErrCode GetDataMgr();

    std::shared_ptr<BundleDataMgr> dataMgr_ = nullptr;
    int32_t uid_ = 0;
    uint32_t accessTokenId_ = 0;
};
} // AppExecFwk
} // OHOS

#endif // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_BUNDLE_MULTIUSER_INSTALLER_H