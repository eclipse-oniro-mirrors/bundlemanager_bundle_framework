/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_BUNDLE_USER_MGR_HOST_IMPL_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_BUNDLE_USER_MGR_HOST_IMPL_H

#include "bundle_data_mgr.h"
#include "bundle_installer_host.h"
#include "bundle_user_mgr_host.h"

namespace OHOS {
namespace AppExecFwk {
class BundleUserMgrHostImpl : public BundleUserMgrHost {
public:
    /**
     * @brief Create new user.
     * @param userId Indicates the userId.
     * @param bundleUserStatus Indicates the bundleUserStatus.
     * @param disallowList Pass in the provisioned disallowList.
     */
    ErrCode CreateNewUser(int32_t userId, const std::vector<std::string> &disallowList = {}) override;
    /**
     * @brief Remove user.
     * @param userId Indicates the userId.
     * @param bundleUserStatus Indicates the bundleUserStatus.
     */
    virtual ErrCode RemoveUser(int32_t userId) override;

    void AddNotifyBundleEvents(const NotifyBundleEvents &notifyBundleEvents);

private:
    const std::shared_ptr<BundleDataMgr> GetDataMgrFromService();
    const sptr<IBundleInstaller> GetBundleInstaller();
    void InnerUninstallBundle(int32_t userId, const std::vector<BundleInfo> &bundleInfos);
    ErrCode CheckInitialUser();
    void BeforeCreateNewUser(int32_t userId);
    void OnCreateNewUser(int32_t userId, const std::vector<std::string> &disallowList = {});
    void AfterCreateNewUser(int32_t userId);
    void RemoveArkProfile(int32_t userId);
    void RemoveAsanLogDirectory(int32_t userId);
    void HandleSceneBoard(int32_t userId) const;
    void HandleNotifyBundleEventsAsync();
    void HandleNotifyBundleEvents();
    void ClearBundleEvents();
    bool GetAllPreInstallBundleInfos(
        const std::vector<std::string> &disallowList,
        int32_t userId,
        std::set<PreInstallBundleInfo> &preInstallBundleInfos);
    void UninstallBackupUninstallList(int32_t userId);

    ErrCode InnerRemoveUser(int32_t userId, bool needLock);

    ErrCode ProcessRemoveUser(int32_t userId);

    std::mutex bundleUserMgrMutex_;

    std::mutex bundleEventMutex_;
    std::vector<NotifyBundleEvents> bundleEvents_;
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_BUNDLE_USER_MGR_HOST_IMPL_H
