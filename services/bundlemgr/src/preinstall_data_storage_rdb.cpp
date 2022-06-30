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

#include "preinstall_data_storage_rdb.h"

#include "app_log_wrapper.h"

namespace OHOS {
namespace AppExecFwk {
PreInstallDataStorageRdb::PreInstallDataStorageRdb()
{
    APP_LOGI("instance:%{private}p is created", this);
}

PreInstallDataStorageRdb::~PreInstallDataStorageRdb()
{
    APP_LOGI("instance:%{private}p is destroyed", this);
}

bool PreInstallDataStorageRdb::LoadAllPreInstallBundleInfos(
    std::vector<PreInstallBundleInfo> &preInstallBundleInfos)
{
    return true;
}

bool PreInstallDataStorageRdb::SavePreInstallStorageBundleInfo(
    const PreInstallBundleInfo &preInstallBundleInfo)
{
    return true;
}

bool PreInstallDataStorageRdb::DeletePreInstallStorageBundleInfo(
    const PreInstallBundleInfo &preInstallBundleInfo)
{
    return true;
}
}  // namespace AppExecFwk
}  // namespace OHOS