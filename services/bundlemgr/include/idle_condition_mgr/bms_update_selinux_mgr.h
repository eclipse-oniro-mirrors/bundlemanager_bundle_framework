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
#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_IDLE_CONDITION_MGR_BMS_UPDATE_SELINUX_MGR_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_IDLE_CONDITION_MGR_BMS_UPDATE_SELINUX_MGR_H

#include <atomic>
#include <mutex>
#include <vector>

#include "bundle_option.h"
#include "ipc/create_dir_param.h"
#include "idle_manager_rdb.h"
#include "singleton.h"

namespace OHOS {
namespace AppExecFwk {
class BmsUpdateSelinuxMgr : public DelayedSingleton<BmsUpdateSelinuxMgr> {
public:
    BmsUpdateSelinuxMgr();
    ~BmsUpdateSelinuxMgr();
    ErrCode StartUpdateSelinuxLabel(const int32_t userId);
    ErrCode StopUpdateSelinuxLabel(const int32_t reason);
    ErrCode AddBundles(const std::vector<BundleOptionInfo> &bundleOptionInfos);
    ErrCode DeleteBundle(const std::string &bundleName, int32_t userId, int32_t appIndex);

private:
    std::vector<std::string> GetBundleDataPath(const std::string &bundleName,
        const int32_t userId, const int32_t appIndex, const bool isContainsEl5Dir);
    std::atomic<bool> needStop_{false};
    std::mutex createDirParamMutex_;
    CreateDirParam createDirParam_;
    std::shared_ptr<IdleManagerRdb> idleManagerRdb_;
};
} // namespace AppExecFwk
} // namespace OHOS
#endif  // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_IDLE_CONDITION_MGR_BMS_UPDATE_SELINUX_MGR_H