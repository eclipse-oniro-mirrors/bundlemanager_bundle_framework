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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_SHORTCUT_DATA_STORAGE_RDB_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_SHORTCUT_DATA_STORAGE_RDB_H

#include "bundle_constants.h"
#include "rdb_data_manager.h"
#include "shortcut_data_storage_interface.h"

namespace OHOS {
namespace AppExecFwk {
class ShortcutDataStorageRdb :
    public IShortcutDataStorage, public std::enable_shared_from_this<ShortcutDataStorageRdb>  {
public:
    ShortcutDataStorageRdb();
    ~ShortcutDataStorageRdb();
    bool AddDesktopShortcutInfo(const ShortcutInfo &shortcutInfo, int32_t userId, bool &isIdIllegal);
    bool DeleteDesktopShortcutInfo(const ShortcutInfo &shortcutInfo, int32_t userId);
    void GetAllDesktopShortcutInfo(int32_t userId, std::vector<ShortcutInfo> &shortcutInfos);
    bool DeleteDesktopShortcutInfo(const std::string &bundleName);
    bool DeleteDesktopShortcutInfo(const std::string &bundleName, int32_t userId, int32_t appIndex);

private:
    bool ShortcutIdVerification(const ShortcutInfo &shortcutInfo, int32_t userId);
    void GetDesktopShortcutInfosByDefaultUserId(std::vector<ShortcutInfo> &shortcutInfos);
    std::shared_ptr<RdbDataManager> rdbDataManager_ = nullptr;
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_SHORTCUT_DATA_STORAGE_RDB_H