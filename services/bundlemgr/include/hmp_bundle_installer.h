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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_HMP_BUNDLE_INSTALLER_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_HMP_BUNDLE_INSTALLER_H

#include "base_bundle_installer.h"

namespace OHOS {
namespace AppExecFwk {
class HmpBundleInstaller : public BaseBundleInstaller {
public:
    HmpBundleInstaller();
    virtual ~HmpBundleInstaller() override;
    /**
     * @brief Install hmp bundle.
     * @param filePath Indicates the filePath.
     * @return Returns ERR_OK if this function called successfully; returns error code otherwise.
     */
    ErrCode InstallHmpBundle(const std::string &filePath, bool isNeedRollback);

    ErrCode InstallSystemHspInHmp(const std::string &bundleDir) const;

    ErrCode InstallNormalAppInHmp(const std::string &bundleDir);

    std::set<int32_t> GetRequiredUserIds(std::string bundleName) const;

    std::set<std::string> GetRollbackHapList(std::set<std::string> hapList) const;

    void RollbackHmpBundle(const std::set<std::string> &systemHspList,
        const std::set<std::string> &hapList);

    void UpdateBundleInfo(const std::string &bundleName, const std::string &bundleDir, const std::string &hspDir);

private:
    std::set<std::string> GetHmpBundleList(const std::string &path) const;

    void UpdateInnerBundleInfo(const std::string &bundleName,
        const std::unordered_map<std::string, InnerBundleInfo> &infos);

    void ParseInfos(const std::string &bundleDir, const std::string &hspDir,
        std::unordered_map<std::string, InnerBundleInfo> &infos);

    bool ParseHapFiles(const std::string &hapFilePath, std::unordered_map<std::string, InnerBundleInfo> &infos);

    bool UninstallSystemBundle(const std::string &bundleName, const std::string &modulePackage);

    void CheckUninstallSystemHsp(const std::string &bundleName);

    void UpdatePreInfoInDb(
        const std::string &bundleName, const std::unordered_map<std::string, InnerBundleInfo> &infos);

    void UpdateBundleInfoForHmp(const std::string &filePath, std::set<std::string> hapList,
        std::set<std::string> systemHspList);

    DISALLOW_COPY_AND_MOVE(HmpBundleInstaller);
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_HMP_BUNDLE_INSTALLER_H
