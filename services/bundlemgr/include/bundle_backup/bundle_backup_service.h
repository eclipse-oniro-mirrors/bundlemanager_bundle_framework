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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_BUNDLE_BACKUP_SERVICE_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_BUNDLE_BACKUP_SERVICE_H

#include "appexecfwk_errors.h"
#include "bundle_data_mgr.h"
#include "nlohmann/json.hpp"
#include "shortcut_data_storage_interface.h"

namespace OHOS {
namespace AppExecFwk {

class BundleBackupService {
public:
    BundleBackupService();
    ~BundleBackupService();
    static BundleBackupService &GetInstance();
    ErrCode OnBackup(nlohmann::json &jsonObject);
    ErrCode OnRestore(nlohmann::json &jsonObject);

private:
    std::shared_ptr<IShortcutDataStorage> shortcutStorage_;
    std::shared_ptr<BundleDataMgr> dataMgr_;
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_BUNDLE_BACKUP_SERVICE_H