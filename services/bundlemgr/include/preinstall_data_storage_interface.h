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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_IPRE_INSTALL_DATA_STORAGE_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_IPRE_INSTALL_DATA_STORAGE_H

#include "pre_install_bundle_info.h"

namespace OHOS {
namespace AppExecFwk {
class IPreInstallDataStorage {
public:
    IPreInstallDataStorage() = default;
    virtual ~IPreInstallDataStorage() = default;
    /**
     * @brief Save the preInstall bundle data corresponding to the device Id of the bundle name to KvStore.
     * @param preInstallBundleInfo Indicates the PreInstallBundleInfo object to be save.
     * @return Returns true if the data is successfully saved; returns false otherwise.
     */
    virtual bool SavePreInstallStorageBundleInfo(const PreInstallBundleInfo &preInstallBundleInfo) = 0;
    /**
     * @brief Obtains the PreInstallBundleInfo objects provided by bundleName.
     * @param preInstallBundleInfos Indicates information about the PreInstallBundleInfo.
     * @return Returns true if this function is successfully called; returns false otherwise.
     */
    virtual bool LoadAllPreInstallBundleInfos(std::vector<PreInstallBundleInfo> &preInstallBundleInfos) = 0;
    /**
     * @brief Delete the bundle data corresponding to the device Id of the bundle name to KvStore.
     * @param innerBundleInfo Indicates the InnerBundleInfo object to be Delete.
     * @return Returns true if the data is successfully deleted; returns false otherwise.
     */
    virtual bool DeletePreInstallStorageBundleInfo(const PreInstallBundleInfo &preInstallBundleInfo) = 0;
};
} // namespace AppExecFwk
} // namespace OHOS
#endif // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_IPRE_INSTALL_DATA_STORAGE_H
