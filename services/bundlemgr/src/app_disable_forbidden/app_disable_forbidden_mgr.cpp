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

#include "app_disable_forbidden_mgr.h"

#include "app_log_wrapper.h"
#include "bundle_mgr_service.h"

namespace OHOS {
namespace AppExecFwk {
AppDisableForbiddenMgr::AppDisableForbiddenMgr()
{
    disableForbiddenDb_ = std::make_shared<DisableForbiddenRdb>();
}

AppDisableForbiddenMgr::~AppDisableForbiddenMgr()
{}

ErrCode AppDisableForbiddenMgr::IsApplicationDisableForbidden(const std::string &bundleName, int32_t userId,
    int32_t appIndex, bool &forbidden) const
{
    std::shared_ptr<BundleDataMgr> dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        APP_LOGE_NOFUNC("DataMgr is nullptr");
        return ERR_APPEXECFWK_NULL_PTR;
    }
    auto ret = dataMgr->CheckBundleExist(bundleName, userId, appIndex);
    if (ret != ERR_OK) {
        APP_LOGE_NOFUNC("CheckBundleExist failed");
        return ret;
    }

    if (disableForbiddenDb_ == nullptr) {
        APP_LOGE_NOFUNC("disableForbiddenDb_ is null");
        return ERR_APPEXECFWK_NULL_PTR;
    }
    if (!disableForbiddenDb_->IsApplicationDisableForbidden(bundleName, userId, appIndex, forbidden)) {
        APP_LOGE_NOFUNC("DisableForbiddenRdb get data failed");
        return ERR_APPEXECFWK_DB_GET_DATA_ERROR;
    }
    return ERR_OK;
}

ErrCode AppDisableForbiddenMgr::SetApplicationDisableForbidden(const std::string &bundleName, int32_t userId,
    int32_t appIndex, bool forbidden)
{
    if (disableForbiddenDb_ == nullptr) {
        APP_LOGE_NOFUNC("disableForbiddenDb_ is null");
        return ERR_APPEXECFWK_NULL_PTR;
    }
    if (bundleName.empty()) {
        APP_LOGE_NOFUNC("bundleName is empty");
        return ERR_BUNDLE_MANAGER_BUNDLE_NAME_IS_EMPTY;
    }
    if (userId < 0) {
        APP_LOGE_NOFUNC("userId less than 0");
        return ERR_BUNDLE_MANAGER_INVALID_USER_ID;
    }
    if (appIndex < 0 || appIndex > ServiceConstants::CLONE_APP_INDEX_MAX) {
        APP_LOGE_NOFUNC("appindex out of range");
        return ERR_APPEXECFWK_APP_INDEX_OUT_OF_RANGE;
    }
    if (forbidden) {
        if (!disableForbiddenDb_->AddDisableForbiddenData(bundleName, userId, appIndex)) {
            APP_LOGE_NOFUNC("DisableForbiddenRdb insert data failed");
            return ERR_APPEXECFWK_DB_INSERT_ERROR;
        }
    } else {
        if (!disableForbiddenDb_->DeleteDisableForbiddenData(bundleName, userId, appIndex)) {
            APP_LOGE_NOFUNC("DisableForbiddenRdb delete data failed");
            return ERR_APPEXECFWK_DB_DELETE_ERROR;
        }
    }
    return ERR_OK;
}

ErrCode AppDisableForbiddenMgr::IsApplicationDisableForbiddenNoCheck(const std::string &bundleName, int32_t userId,
    int32_t appIndex, bool &forbidden) const
{
    if (disableForbiddenDb_ == nullptr) {
        APP_LOGE_NOFUNC("disableForbiddenDb_ is null");
        return ERR_APPEXECFWK_NULL_PTR;
    }
    if (!disableForbiddenDb_->IsApplicationDisableForbidden(bundleName, userId, appIndex, forbidden)) {
        APP_LOGE_NOFUNC("DisableForbiddenRdb get data failed");
        return ERR_APPEXECFWK_DB_GET_DATA_ERROR;
    }
    return ERR_OK;
}

}  // namespace AppExecFwk
}  // namespace OHOS
