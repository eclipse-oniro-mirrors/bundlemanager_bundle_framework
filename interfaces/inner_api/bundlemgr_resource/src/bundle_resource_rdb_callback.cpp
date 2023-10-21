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

#include "bundle_resource_rdb_callback.h"

#include "app_log_wrapper.h"

namespace OHOS {
namespace AppExecFwk {
BundleResourceRdbCallback::BundleResourceRdbCallback()
{
}

BundleResourceRdbCallback::~BundleResourceRdbCallback()
{
}

int32_t BundleResourceRdbCallback::OnCreate(NativeRdb::RdbStore &rdbStore)
{
    return NativeRdb::E_OK;
}

int32_t BundleResourceRdbCallback::OnUpgrade(
    NativeRdb::RdbStore &rdbStore, int currentVersion, int targetVersion)
{
    return NativeRdb::E_OK;
}

int32_t BundleResourceRdbCallback::OnDowngrade(
    NativeRdb::RdbStore &rdbStore, int currentVersion, int targetVersion)
{
    return NativeRdb::E_OK;
}

int32_t BundleResourceRdbCallback::OnOpen(NativeRdb::RdbStore &rdbStore)
{
    return NativeRdb::E_OK;
}

int32_t BundleResourceRdbCallback::onCorruption(std::string databaseFile)
{
    return NativeRdb::E_OK;
}
}  // namespace AppExecFwk
}  // namespace OHOS
