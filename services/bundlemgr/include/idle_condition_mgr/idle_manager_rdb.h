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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_IDLE_MANAGER_RDB_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_IDLE_MANAGER_RDB_H

#include <vector>

#include "bundle_option.h"
#include "rdb_data_manager.h"

namespace OHOS {
namespace AppExecFwk {
class IdleManagerRdb : public std::enable_shared_from_this<IdleManagerRdb> {
public:
    IdleManagerRdb();
    ~IdleManagerRdb();
    ErrCode AddBundles(const std::vector<BundleOptionInfo> &bundleOptionInfos);
    ErrCode AddBundle(const BundleOptionInfo &bundleOptionInfo);
    ErrCode DeleteBundle(const BundleOptionInfo &bundleOptionInfo);
    ErrCode GetAllBundle(int32_t userId, std::vector<BundleOptionInfo> &bundleOptionInfos);
private:
    bool ConvertToBundleOptionInfo(const std::shared_ptr<NativeRdb::ResultSet> &absSharedResultSet,
        BundleOptionInfo &bundleOptionInfo);
    std::shared_ptr<RdbDataManager> rdbDataManager_ = nullptr;

#define CHECK_RDB_RESULT_RETURN_IF_FAIL(errcode, errmsg)                           \
    do {                                                                           \
        if ((errcode) != NativeRdb::E_OK) {                                          \
            APP_LOGE(errmsg, errcode);                                             \
            return false;                                                          \
        }                                                                          \
    } while (0)
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_IDLE_MANAGER_RDB_H