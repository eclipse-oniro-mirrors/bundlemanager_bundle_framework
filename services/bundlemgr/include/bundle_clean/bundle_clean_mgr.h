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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_BUNDLE_CLEAN_MGR_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_BUNDLE_CLEAN_MGR_H

#include <memory>
#include <string>

#include "iremote_stub.h"
#include "singleton.h"

namespace OHOS {
namespace AppExecFwk {

class RdbDataManager;

// Selective BMS data cleanup in cleanup mode.
// Deletes the bms_param fingerprint row and writes the bmsCleanRecovery flag on the mirror bmsdb.
class BundleCleanMgr : public DelayedSingleton<BundleCleanMgr> {
public:
    BundleCleanMgr();
    ~BundleCleanMgr();

    // SA clean callback entry. Returns ERR_OK(0) on success.
    ErrCode OnClean();

private:
    // Delete the bms_param KEY='fingerprint' row on the mirror bmsdb.
    ErrCode CleanFingerprint();

    // Write KEY='bmsCleanRecovery' VALUE='true' to the bms_param table on the mirror bmsdb.
    ErrCode SetCleanupRecoveryFlag();

    // Build an isolated RdbDataManager instance on the mirror dbPath; tableName selects bms_param.
    std::shared_ptr<RdbDataManager> CreateMirrorRdbDataManager(const std::string &tableName);
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_BUNDLE_CLEAN_MGR_H
