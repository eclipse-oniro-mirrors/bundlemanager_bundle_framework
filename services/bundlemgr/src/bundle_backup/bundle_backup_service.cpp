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

#include "bundle_backup_service.h"

#include "app_log_wrapper.h"
#include "bundle_mgr_service.h"
#include "shortcut_data_storage_rdb.h"

namespace OHOS {
namespace AppExecFwk {

BundleBackupService::BundleBackupService()
{
    shortcutStorage_ = std::make_shared<ShortcutDataStorageRdb>();
    dataMgr_ = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
}

BundleBackupService::~BundleBackupService() {}

ErrCode BundleBackupService::OnBackup(nlohmann::json &jsonObject)
{
    if (!shortcutStorage_->GetAllTableDataToJson(jsonObject)) {
        APP_LOGE("Failed to get shortcuts from storage");
        return ERR_APPEXECFWK_DB_GET_DATA_ERROR;
    }
    return ERR_OK;
}

ErrCode BundleBackupService::OnRestore(nlohmann::json &jsonObject)
{
    if (dataMgr_ == nullptr) {
        return ERR_APPEXECFWK_NULL_PTR;
    }
    dataMgr_->CheckIfShortcutBundleExist(jsonObject);
    if (!shortcutStorage_->UpdateAllShortcuts(jsonObject)) {
        APP_LOGE("Failed to clear shortcut table");
        return ERR_APPEXECFWK_DB_UPDATE_ERROR;
    }
    return ERR_OK;
}
}  // namespace AppExecFwk
}  // namespace OHOS