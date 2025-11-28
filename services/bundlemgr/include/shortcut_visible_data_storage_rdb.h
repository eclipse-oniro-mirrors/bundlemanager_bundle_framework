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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_SHORTCUT_VISIBLE_DATA_STORAGE_RDB_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_SHORTCUT_VISIBLE_DATA_STORAGE_RDB_H

#include "bundle_constants.h"
#include "rdb_data_manager.h"
#include "shortcut_info.h"

namespace OHOS {
namespace AppExecFwk {
class ShortcutVisibleDataStorageRdb {
public:
    ShortcutVisibleDataStorageRdb();
    ~ShortcutVisibleDataStorageRdb();

    bool IsShortcutVisibleInfoExist(
        const std::string &bundleName, const std::string &shortcutId, int32_t appIndex, int32_t userId, bool visible);
    bool SaveStorageShortcutVisibleInfo(
        const std::string &bundleName, const std::string &shortcutId, int32_t appIndex, int32_t userId, bool visible);
    bool DeleteShortcutVisibleInfo(const std::string &bundleName, int32_t userId, int32_t appIndex);

    bool AddDynamicShortcutInfos(const std::vector<ShortcutInfo> &shortcutInfos, int32_t userId);
    bool DeleteDynamicShortcutInfos(const std::string &bundleName, const int32_t appIndex, const int32_t userId,
        const std::vector<std::string> &ids);

    void GetStorageShortcutInfos(const std::string &bundleName, const int32_t appIndex, const int32_t userId,
        std::vector<ShortcutInfo> &shortcutInfos, const bool onlyDynamic = false);
private:
    void ProcessStaticShortcutInfos(const NativeRdb::AbsRdbPredicates &absRdbPredicatesConst,
        std::vector<ShortcutInfo> &shortcutInfos);

    std::shared_ptr<RdbDataManager> rdbDataManager_ = nullptr;
};

}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_SHORTCUT_VISIBLE_DATA_STORAGE_RDB_H
