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

#ifndef FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_INTERFACES_KITS_BUNDLE_RESOURCE_BUNDLE_RESOURCE_RDB_CALLBACK_H
#define FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_INTERFACES_KITS_BUNDLE_RESOURCE_BUNDLE_RESOURCE_RDB_CALLBACK_H

#include "rdb_errno.h"
#include "rdb_open_callback.h"

namespace OHOS {
namespace AppExecFwk {
class BundleResourceRdbCallback : public NativeRdb::RdbOpenCallback {
public:
    BundleResourceRdbCallback();
    ~BundleResourceRdbCallback();
    int32_t OnCreate(NativeRdb::RdbStore &rdbStore) override;
    int32_t OnUpgrade(NativeRdb::RdbStore &rdbStore, int currentVersion, int targetVersion) override;
    int32_t OnDowngrade(NativeRdb::RdbStore &rdbStore, int currentVersion, int targetVersion) override;
    int32_t OnOpen(NativeRdb::RdbStore &rdbStore) override;
    int32_t onCorruption(std::string databaseFile) override;
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_INTERFACES_KITS_BUNDLE_RESOURCE_BUNDLE_RESOURCE_RDB_CALLBACK_H
