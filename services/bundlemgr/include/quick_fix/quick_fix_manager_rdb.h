/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef FOUNDATION_BUNDLE_FRAMEWORK_SERVICE_INCLUDE_QUICK_FIX_QUICK_FIX_MANAGER_RDB_H
#define FOUNDATION_BUNDLE_FRAMEWORK_SERVICE_INCLUDE_QUICK_FIX_QUICK_FIX_MANAGER_RDB_H

#include "quick_fix_manager_db_interface.h"
#include "rdb_data_manager.h"

namespace OHOS {
namespace AppExecFwk {
class QuickFixManagerRdb final :
    public IQuickFixManagerDb,
    public std::enable_shared_from_this<QuickFixManagerRdb> {
public:
    QuickFixManagerRdb();
    ~QuickFixManagerRdb();

    bool QueryAllInnerAppQuickFix(std::map<std::string, InnerAppQuickFix> &innerAppQuickFixes) override;
    bool QueryInnerAppQuickFix(const std::string &bundleName, InnerAppQuickFix &innerAppQuickFix) override;
    bool SaveInnerAppQuickFix(const InnerAppQuickFix &innerAppQuickFix) override;
    bool DeleteInnerAppQuickFix(const std::string &bundleName) override;

private:
    bool GetAllDataFromDb(std::map<std::string, InnerAppQuickFix> &innerAppQuickFixes);
    bool GetDataFromDb(const std::string &bundleName, InnerAppQuickFix &innerAppQuickFix);
    bool SaveDataToDb(const InnerAppQuickFix &innerAppQuickFix);
    bool DeleteDataFromDb(const std::string &bundleName);

    std::shared_ptr<RdbDataManager> rdbDataManager_;
};
} // namespace AppExecFwk
} // namespace OHOS
#endif // FOUNDATION_BUNDLE_FRAMEWORK_SERVICE_INCLUDE_QUICK_FIX_QUICK_FIX_MANAGER_RDB_H
