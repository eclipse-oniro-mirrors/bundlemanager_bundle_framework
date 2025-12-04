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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_SHORTCUT_ENABLED_DATA_STORAGE_RDB_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_SHORTCUT_ENABLED_DATA_STORAGE_RDB_H

#include "bundle_constants.h"
#include "rdb_data_manager.h"
#include "shortcut_info.h"

namespace OHOS {
namespace AppExecFwk {
class ShortcutEnabledDataStorageRdb {
public:
    ShortcutEnabledDataStorageRdb();
    ~ShortcutEnabledDataStorageRdb();

    bool SaveStorageShortcutEnabledInfos(const std::vector<ShortcutInfo> shortcutInfos, bool isEnabled);
    bool DeleteShortcutEnabledInfo(const std::string &bundleName);
    bool DeleteShortcutEnabledInfo(const std::string &bundleName, const std::vector<std::string> &shortcutIdList);
    void FilterShortcutInfosEnabled(const std::string &bundleName, std::vector<ShortcutInfo> &shortcutInfos) const;
    ErrCode GetShortcutEnabledStatus(const std::string &bundleName, const std::string &shortcutId,
        bool &isEnabled) const;
    bool UpdateShortcutEnabledInfo(const std::string &bundleName, const std::vector<ShortcutInfo> &shortcutInfos);

private:
    std::shared_ptr<RdbDataManager> rdbDataManager_ = nullptr;
};

}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_SHORTCUT_ENABLED_DATA_STORAGE_RDB_H