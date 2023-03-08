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

#include "sr_samgr_helper.h"

#include "app_log_wrapper.h"
#include "bundle_constants.h"
#include "bundle_mgr_proxy.h"
#include "if_system_ability_manager.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#ifdef ACCOUNT_ENABLE
#include "os_account_manager.h"
#endif
#include "system_ability_definition.h"

namespace OHOS {
namespace AppExecFwk {
SrSamgrHelper::SrSamgrHelper()
{}

SrSamgrHelper::~SrSamgrHelper()
{}

sptr<IBundleMgr> SrSamgrHelper::GetBundleMgr()
{
    APP_LOGI("GetBundleMgr called.");
    std::lock_guard<std::mutex> lock(bundleMgrMutex_);
    if (iBundleMgr_ == nullptr) {
        sptr<ISystemAbilityManager> saManager =
            SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
        auto remoteObj = saManager->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
        if (remoteObj == nullptr) {
            APP_LOGE("%{public}s error, failed to get bms remoteObj.", __func__);
            return nullptr;
        }

        iBundleMgr_ = iface_cast<IBundleMgr>(remoteObj);
        if (iBundleMgr_ == nullptr) {
            APP_LOGE("%{public}s error, failed to get bms", __func__);
            return nullptr;
        }
    }
    return iBundleMgr_;
}

int32_t SrSamgrHelper::GetCurrentActiveUserId()
{
#ifdef ACCOUNT_ENABLE
    std::vector<int32_t> activeIds;
    int ret = AccountSA::OsAccountManager::QueryActiveOsAccountIds(activeIds);
    if (ret != 0) {
        APP_LOGE("QueryActiveOsAccountIds failed ret:%{public}d", ret);
        return Constants::INVALID_USERID;
    }
    if (activeIds.empty()) {
        APP_LOGE("QueryActiveOsAccountIds activeIds empty");
        return Constants::INVALID_USERID;
    }
    APP_LOGE("QueryActiveOsAccountIds activeIds ret:%{public}d", activeIds[0]);
    return activeIds[0];
#else
    APP_LOGI("ACCOUNT_ENABLE is false");
    return 0;
#endif
}
} // namespace AppExecFwk
} // namespace OHOS
