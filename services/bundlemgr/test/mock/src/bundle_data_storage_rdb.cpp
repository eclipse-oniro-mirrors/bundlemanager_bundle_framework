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
#include "bundle_exception_handler.h"
#include "bundle_sandbox_app_helper.h"

namespace OHOS {
namespace AppExecFwk {
static std::map<std::string, InnerBundleInfo> INNER_BUNDLE_INFOS;

BundleDataStorageRdb::BundleDataStorageRdb()
{
    INNER_BUNDLE_INFOS.emplace("test.placeholder", InnerBundleInfo());
}

BundleDataStorageRdb::~BundleDataStorageRdb()
{}

bool BundleDataStorageRdb::LoadAllData(std::map<std::string, InnerBundleInfo> &infos)
{
    infos = INNER_BUNDLE_INFOS;
    return true;
}

bool BundleDataStorageRdb::SaveStorageBundleInfo(const InnerBundleInfo &innerBundleInfo)
{
    INNER_BUNDLE_INFOS[innerBundleInfo.GetBundleName()] = innerBundleInfo;
    return true;
}

bool BundleDataStorageRdb::DeleteStorageBundleInfo(const InnerBundleInfo &innerBundleInfo)
{
    auto ret = INNER_BUNDLE_INFOS.erase(innerBundleInfo.GetBundleName());
    if (ret == 0) {
        return false;
    }
    return true;
}

bool BundleDataStorageRdb::ResetKvStore()
{
    return true;
}

void BundleDataStorageRdb::TransformStrToInfo(
    const std::map<std::string, std::string> &datas,
    std::map<std::string, InnerBundleInfo> &infos)
{}

void BundleDataStorageRdb::UpdateDataBase(std::map<std::string, InnerBundleInfo> &infos)
{}
}  // namespace AppExecFwk
}  // namespace OHOS