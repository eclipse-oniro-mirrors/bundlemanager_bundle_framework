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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_INSTALL_EXCEPTION_MGR_RDB_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_INSTALL_EXCEPTION_MGR_RDB_H

#include <map>
#include <string>

#include "rdb_data_manager.h"
#include "single_delayed_task_mgr.h"

namespace OHOS {
namespace AppExecFwk {

enum class InstallRenameExceptionStatus : uint8_t {
    UNKOWN_STATUS = 0,
    RENAME_RELA_TO_OLD_PATH = 1,
    RENAME_NEW_TO_RELA_PATH = 2,
    DELETE_OLD_PATH = 3,
};

struct InstallExceptionInfo {
    InstallRenameExceptionStatus status = InstallRenameExceptionStatus::UNKOWN_STATUS;
    uint32_t versionCode = 0;
    bool FromString(const std::string &installExceptionInfoStr);
    std::string ToString() const;
};

class InstallExceptionMgrRdb : public std::enable_shared_from_this<InstallExceptionMgrRdb> {
public:
    InstallExceptionMgrRdb();
    ~InstallExceptionMgrRdb();
    ErrCode SaveBundleExceptionInfo(const std::string &bundleName, const InstallExceptionInfo &installExceptionInfo);
    ErrCode DeleteBundleExceptionInfo(const std::string &bundleName);
    void GetAllBundleExceptionInfo(std::map<std::string, InstallExceptionInfo> &bundleExceptionInfos);

private:
    std::shared_ptr<RdbDataManager> rdbDataManager_ = nullptr;
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_INSTALL_EXCEPTION_MGR_RDB_H
