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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_BUNDLE_BACKUP_MGR_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_BUNDLE_BACKUP_MGR_H

#include "iremote_stub.h"
#include "nlohmann/json.hpp"
#include "singleton.h"

namespace OHOS {
namespace AppExecFwk {

class BundleBackupMgr : public DelayedSingleton<BundleBackupMgr> {
public:
    BundleBackupMgr();
    ~BundleBackupMgr();
    
    ErrCode OnBackup(MessageParcel& data, MessageParcel& reply);
    ErrCode OnRestore(MessageParcel& data, MessageParcel& reply);

private:

    ErrCode SaveToFile(const std::string& config);
    ErrCode LoadFromFile(int32_t fd, std::string& config);

    const char* BACKUP_FILE_PATH = "/data/service/el1/public/bms/bundle_manager_service/backup_config.conf";
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_BUNDLE_BACKUP_MGR_H