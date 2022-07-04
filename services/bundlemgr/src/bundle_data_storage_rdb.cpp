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

#include "bundle_data_storage_rdb.h"

#include "app_log_wrapper.h"

namespace OHOS {
namespace AppExecFwk {
BundleDataStorageRdb::BundleDataStorageRdb()
{
    APP_LOGI("instance:%{private}p is created", this);
}

BundleDataStorageRdb::~BundleDataStorageRdb()
{
    APP_LOGI("instance:%{private}p is destroyed", this);
}

bool BundleDataStorageRdb::LoadAllData(std::map<std::string, InnerBundleInfo> &infos)
{
    return true;
}

bool BundleDataStorageRdb::SaveStorageBundleInfo(const InnerBundleInfo &innerBundleInfo)
{
    return true;
}

bool BundleDataStorageRdb::DeleteStorageBundleInfo(const InnerBundleInfo &innerBundleInfo)
{
    return true;
}

bool BundleDataStorageRdb::ResetKvStore()
{
    return true;
}
}  // namespace AppExecFwk
}  // namespace OHOS