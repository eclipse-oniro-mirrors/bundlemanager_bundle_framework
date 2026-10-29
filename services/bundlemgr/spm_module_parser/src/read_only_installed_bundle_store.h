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

#ifndef FOUNDATION_BUNDLE_FRAMEWORK_READ_ONLY_INSTALLED_BUNDLE_STORE_H
#define FOUNDATION_BUNDLE_FRAMEWORK_READ_ONLY_INSTALLED_BUNDLE_STORE_H

#include <map>
#include <memory>
#include <string>

#include "bundle_service_constants.h"

namespace OHOS::NativeRdb {
class RdbStore;
class ResultSet;
}

namespace OHOS::AppExecFwk::AtmRecovery {
class __attribute__((visibility("hidden"))) ReadOnlyInstalledBundleStore final {
public:
    explicit ReadOnlyInstalledBundleStore(const std::string &path =
        std::string(ServiceConstants::BUNDLE_MANAGER_SERVICE_PATH) + ServiceConstants::BUNDLE_RDB_NAME);
    ~ReadOnlyInstalledBundleStore();
    ReadOnlyInstalledBundleStore(const ReadOnlyInstalledBundleStore &) = delete;
    ReadOnlyInstalledBundleStore &operator=(const ReadOnlyInstalledBundleStore &) = delete;
    bool Open();
    bool QueryAllData(std::map<std::string, std::string> &data);
    bool QueryAllUninstallData(std::map<std::string, std::string> &data);
private:
    static bool ReadAllRows(NativeRdb::ResultSet &rows, std::map<std::string, std::string> &data);
    std::string path_;
    std::shared_ptr<NativeRdb::RdbStore> db_;
    std::shared_ptr<NativeRdb::ResultSet> rows_;
};
} // namespace OHOS::AppExecFwk::AtmRecovery
#endif
