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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_OOBE_PRELOAD_UNINSTALL_MGR_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_OOBE_PRELOAD_UNINSTALL_MGR_H

#include <map>
#include <mutex>
#include <set>
#include <string>
#include <vector>

namespace OHOS {
namespace AppExecFwk {
class OobePreloadUninstallMgr {
public:
    using PendingBundleUserIds = std::map<std::string, std::set<int32_t>>;

    OobePreloadUninstallMgr();
    ~OobePreloadUninstallMgr();

    PendingBundleUserIds GetPendingBundles();
    bool AddPendingBundle(const std::string &bundleName, int32_t userId);
    bool RemovePendingBundle(const std::string &bundleName, int32_t userId);
    void RecoverPendingBundles(int32_t userId);

private:
    bool LoadPendingBundlesLocked(PendingBundleUserIds &pendingBundles);
    bool SavePendingBundlesLocked(const PendingBundleUserIds &pendingBundles);

private:
    std::mutex mutex_;
};
} // namespace AppExecFwk
} // namespace OHOS
#endif // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_OOBE_PRELOAD_UNINSTALL_MGR_H
