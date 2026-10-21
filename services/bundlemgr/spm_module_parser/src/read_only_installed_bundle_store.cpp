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

#include "read_only_installed_bundle_store.h"

#include <sys/stat.h>
#include "rdb_errno.h"
#include "rdb_helper.h"
#include "rdb_open_callback.h"
#include "rdb_store.h"
#include "rdb_store_config.h"
#include "result_set.h"

namespace OHOS::AppExecFwk::AtmRecovery {
namespace {
constexpr int SQLITE_HEADER_BYTES = 100;
constexpr int SKIP_VERSION_CHECK = -1;

class ReadOnlyOpenCallback final : public NativeRdb::RdbOpenCallback {
public:
    int OnCreate(NativeRdb::RdbStore &) override
    {
        return NativeRdb::E_NOT_SUPPORT;
    }
    int OnUpgrade(NativeRdb::RdbStore &, int, int) override
    {
        return NativeRdb::E_NOT_SUPPORT;
    }
};
}

ReadOnlyInstalledBundleStore::ReadOnlyInstalledBundleStore(const std::string &path) : path_(path) {}

ReadOnlyInstalledBundleStore::~ReadOnlyInstalledBundleStore()
{
    if (rows_ != nullptr) {
        rows_->Close();
    }
}

bool ReadOnlyInstalledBundleStore::Open()
{
    struct stat status = {};
    if (db_ != nullptr || lstat(path_.c_str(), &status) != 0 || !S_ISREG(status.st_mode) ||
        status.st_size < SQLITE_HEADER_BYTES) {
        return false;
    }
    NativeRdb::RdbStoreConfig config(path_);
    config.SetReadOnly(true);
    config.SetCreateNecessary(false);
    config.SetAllowRebuild(false);
    config.SetHaMode(NativeRdb::HAMode::SINGLE);
    // VISITOR skips owner configuration such as chmod and database initialization.
    config.SetRoleType(NativeRdb::VISITOR);
    config.SetVisitorDir(path_);
    ReadOnlyOpenCallback callback;
    int error = NativeRdb::E_OK;
    db_ = NativeRdb::RdbHelper::GetRdbStore(config, SKIP_VERSION_CHECK, callback, error);
    return error == NativeRdb::E_OK && db_ != nullptr && db_->IsReadOnly();
}

bool ReadOnlyInstalledBundleStore::QueryAllData(std::map<std::string, std::string> &data)
{
    data.clear();
    if (db_ == nullptr || rows_ != nullptr) {
        return false;
    }
    rows_ = db_->QueryByStep("SELECT KEY, VALUE FROM installed_bundle", {}, false);
    if (rows_ == nullptr) {
        return false;
    }
    bool valid = ReadAllRows(*rows_, data);
    int result = rows_->Close();
    rows_.reset();
    db_.reset();
    if (!valid || result != NativeRdb::E_OK) {
        data.clear();
        return false;
    }
    return true;
}

bool ReadOnlyInstalledBundleStore::ReadAllRows(NativeRdb::ResultSet &rows,
    std::map<std::string, std::string> &data)
{
    data.clear();
    int step = rows.GoToFirstRow();
    bool hasRows = step == NativeRdb::E_OK;
    bool hasReadableRows = false;
    for (; step == NativeRdb::E_OK; step = rows.GoToNextRow()) {
        std::string key;
        std::string value;
        if (rows.GetString(0, key) != NativeRdb::E_OK) {
            continue;
        }
        if (rows.GetString(1, value) != NativeRdb::E_OK) {
            continue;
        }
        data.emplace(std::move(key), std::move(value));
        hasReadableRows = true;
    }
    if (step != NativeRdb::E_ROW_OUT_RANGE || (hasRows && !hasReadableRows)) {
        data.clear();
        return false;
    }
    return true;
}
} // namespace OHOS::AppExecFwk::AtmRecovery
