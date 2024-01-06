/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_SHARED_BUNDLE_INSTALLER_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_SHARED_BUNDLE_INSTALLER_H

#include <memory>
#include <string>
#include <unordered_map>

#include "event_report.h"
#include "inner_shared_bundle_installer.h"
#include "install_param.h"
#include "inner_bundle_info.h"
#include "nocopyable.h"

namespace OHOS {
namespace AppExecFwk {
class SharedBundleInstaller {
public:
    /**
     * @brief Cross-app shared bundle installer.
     * @param installParam Indicates the install param.
     * @param appType Indicates the type of the application.
     */
    SharedBundleInstaller(const InstallParam &installParam, const Constants::AppType appType);
    virtual ~SharedBundleInstaller();

    /**
     * @brief Parse cross-app hsp files.
     * @return Returns ERR_OK if the files are parsed successfully; returns error code otherwise.
     */
    ErrCode ParseFiles();

    /**
     * @brief Checks whether to install cross-app shared bundles.
     * @return Returns true if the files need to be installed; returns false otherwise.
     */
    inline bool NeedToInstall() const
    {
        return !innerInstallers_.empty();
    }

    /**
     * @brief Checks whether the dependencies of a bundle are satisfied in installing or installed shared bundles.
     * @param innerBundleInfo Indicates the InnerBundleInfo object to be checked.
     * @return Returns true if the dependencies are satisfied; returns false otherwise.
     */
    bool CheckDependency(const InnerBundleInfo &innerBundleInfo) const;

    /**
     * @brief Install cross-app shared bundles.
     * @param eventTemplate Indicates the template of EventInfo to send after installation.
     * @return Returns ERR_OK if the files are installed successfully; returns error code otherwise.
     */
    ErrCode Install(const EventInfo &eventTemplate);

private:
    bool FindDependencyInInstalledBundles(const Dependency &dependency) const;
    void SendBundleSystemEvent(const EventInfo &eventTemplate, ErrCode errCode);
    void GetCallingEventInfo(EventInfo &eventInfo);

    InstallParam installParam_;
    const Constants::AppType appType_;
    // the key is the bundle name of cross-app shared bundle to be installed
    std::unordered_map<std::string, std::shared_ptr<InnerSharedBundleInstaller>> innerInstallers_;

    DISALLOW_COPY_AND_MOVE(SharedBundleInstaller);

#define CHECK_RESULT(errcode, errmsg)                                              \
    do {                                                                           \
        if ((errcode) != ERR_OK) {                                                   \
            APP_LOGE(errmsg, errcode);                                             \
            return errcode;                                                        \
        }                                                                          \
    } while (0)
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_SHARED_BUNDLE_INSTALLER_H