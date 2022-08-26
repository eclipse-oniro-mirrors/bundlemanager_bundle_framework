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

#include "bundle_data_storage_database.h"

#include "app_log_wrapper.h"
#include "bundle_exception_handler.h"
#include "bundle_sandbox_app_helper.h"

#include "kvstore_death_recipient_callback.h"

using namespace OHOS::DistributedKv;

namespace OHOS {
static std::map<std::string, InnerBundleInfo> INNER_BUNDLE_INFOS;
namespace AppExecFwk {
BundleDataStorageDatabase::BundleDataStorageDatabase()
{
    INNER_BUNDLE_INFOS.emplace("test.placeholder", InnerBundleInfo());
}

BundleDataStorageDatabase::~BundleDataStorageDatabase()
{}

bool BundleDataStorageDatabase::LoadAllData(std::map<std::string, InnerBundleInfo> &infos)
{
    infos = INNER_BUNDLE_INFOS;
    return true;
}

bool BundleDataStorageDatabase::SaveStorageBundleInfo(const InnerBundleInfo &innerBundleInfo)
{
    INNER_BUNDLE_INFOS.emplace(innerBundleInfo.GetBundleName(), innerBundleInfo);
    return true;
}

bool BundleDataStorageDatabase::DeleteStorageBundleInfo(const InnerBundleInfo &innerBundleInfo)
{
    auto iter = INNER_BUNDLE_INFOS.find(innerBundleInfo.GetBundleName());
    if (iter != INNER_BUNDLE_INFOS.end()) {
        INNER_BUNDLE_INFOS.erase(iter);
    }
    return true;
}

void BundleDataStorageDatabase::RegisterKvStoreDeathListener()
{}

bool BundleDataStorageDatabase::ResetKvStore()
{
    return true;
}

void BundleDataStorageDatabase::SaveEntries(const std::vector<DistributedKv::Entry> &allEntries,
    std::map<std::string, InnerBundleInfo> &infos)
{}

DistributedKv::Status BundleDataStorageDatabase::GetEntries(std::vector<DistributedKv::Entry> &allEntries) const
{
    return Status::SUCCESS;
}
void BundleDataStorageDatabase::TryTwice(const std::function<DistributedKv::Status()> &func) const
{}

bool BundleDataStorageDatabase::CheckKvStore()
{
    return true;
}

DistributedKv::Status BundleDataStorageDatabase::GetKvStore()
{
    return Status::SUCCESS;
}

void BundleDataStorageDatabase::UpdateDataBase(std::map<std::string, InnerBundleInfo>& infos)
{}

void BundleDataStorageDatabase::DeleteOldBundleInfo(const std::string& oldKey)
{}
}  // namespace AppExecFwk
}  // namespace OHOS