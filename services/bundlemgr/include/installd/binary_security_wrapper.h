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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_INSTALLD_BINARY_SECURITY_WRAPPER_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_INSTALLD_BINARY_SECURITY_WRAPPER_H

#include <shared_mutex>
#include <string>
#include <vector>

#include "appexecfwk_errors.h"
#include "single_delayed_task_mgr.h"

namespace OHOS {
namespace AppExecFwk {

struct BinFileInfo {
    std::string path;
};

class BinarySecurityWrapper {
public:
    static BinarySecurityWrapper& GetInstance();

    ErrCode ProcessHapBinInstall(const std::string &bundleName,
        const std::string &appIdentifier, int32_t userId,
        const std::vector<BinFileInfo> &binFileInfos);

private:
    BinarySecurityWrapper();
    ~BinarySecurityWrapper() = default;

    BinarySecurityWrapper(const BinarySecurityWrapper&) = delete;
    BinarySecurityWrapper& operator=(const BinarySecurityWrapper&) = delete;
    BinarySecurityWrapper(BinarySecurityWrapper&&) = delete;
    BinarySecurityWrapper& operator=(BinarySecurityWrapper&&) = delete;

    bool LoadLibraryNoLock();
    void UnloadLibrary();
    void ScheduleUnload();

    using ProcessHapBinInstallFunc = int32_t(*)(const std::string&, const std::string&,
        int32_t, const std::vector<BinFileInfo>&);

    mutable std::shared_mutex mutex_;
    void* handle_ = nullptr;
    ProcessHapBinInstallFunc processHapBinInstallFunc_ = nullptr;
    std::shared_ptr<SingleDelayedTaskMgr> delayedTaskMgr_ = nullptr;
};

}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_INSTALLD_BINARY_SECURITY_WRAPPER_H
