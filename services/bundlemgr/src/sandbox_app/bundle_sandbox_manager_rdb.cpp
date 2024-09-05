/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "bundle_sandbox_manager_rdb.h"

#include "app_log_wrapper.h"
#include "appexecfwk_errors.h"
#include "json_serializer.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr const char* SAND_BOX_RDB_TABLE_NAME = "sandbox";
}
SandboxManagerRdb::SandboxManagerRdb()
{
    APP_LOGI("create SandboxManagerRdb");
    BmsRdbConfig bmsRdbConfig;
    bmsRdbConfig.dbName = ServiceConstants::BUNDLE_RDB_NAME;
    bmsRdbConfig.tableName = SAND_BOX_RDB_TABLE_NAME;
    rdbDataManager_ = std::make_shared<RdbDataManager>(bmsRdbConfig);
    rdbDataManager_->CreateTable();
}

SandboxManagerRdb::~SandboxManagerRdb()
{
    APP_LOGI("destroy SandboxManagerRdb");
}

bool SandboxManagerRdb::QueryAllSandboxInnerBundleInfo(
    std::unordered_map<std::string, InnerBundleInfo> &innerBundleInfos)
{
    APP_LOGI("begin to QueryAllSandboxInnerBundleInfo");
    bool ret = GetAllDataFromDb(innerBundleInfos);
    if (!ret) {
        APP_LOGE("GetAllDataFromDb failed");
        return false;
    }
    return true;
}

bool SandboxManagerRdb::QuerySandboxInnerBundleInfo(const std::string &bundleName, InnerBundleInfo &innerBundleInfos)
{
    APP_LOGI("begin to QuerySandboxInnerBundleInfo");
    bool ret = GetDataFromDb(bundleName, innerBundleInfos);
    if (!ret) {
        APP_LOGE("GetDataFromDb failed");
        return false;
    }
    return true;
}

bool SandboxManagerRdb::SaveSandboxInnerBundleInfo(const std::string &bundleName,
    const InnerBundleInfo &innerBundleInfos)
{
    APP_LOGI("begin to SaveSandboxInnerBundleInfo");
    bool ret = SaveDataToDb(bundleName, innerBundleInfos);
    if (!ret) {
        APP_LOGE("SaveDataToDb failed");
        return false;
    }
    return true;
}

bool SandboxManagerRdb::DeleteSandboxInnerBundleInfo(const std::string &bundleName)
{
    APP_LOGI("begin to DeleteSandboxInnerBundleInfo");
    bool ret = DeleteDataFromDb(bundleName);
    if (!ret) {
        APP_LOGE("DeleteDataFromDb failed");
        return false;
    }
    return true;
}

bool SandboxManagerRdb::GetAllDataFromDb(std::unordered_map<std::string, InnerBundleInfo> &innerBundleInfos)
{
    if (rdbDataManager_ == nullptr) {
        APP_LOGE("rdbDataManager is null");
        return false;
    }

    std::map<std::string, std::string> values;
    bool result = rdbDataManager_->QueryAllData(values);
    if (!result) {
        APP_LOGE("QueryAllData failed");
        return false;
    }
    for (auto iter = values.begin(); iter != values.end(); ++iter) {
        nlohmann::json jsonObject = nlohmann::json::parse(iter->second, nullptr, false);
        InnerBundleInfo innerBundleInfo;
        if (jsonObject.is_discarded() || (innerBundleInfo.FromJson(jsonObject) != ERR_OK)) {
            APP_LOGE("error key : %{public}s", iter->first.c_str());
            rdbDataManager_->DeleteData(iter->first);
            continue;
        }
        if (innerBundleInfos.find(iter->first) == innerBundleInfos.end()) {
            innerBundleInfos.emplace(iter->first, innerBundleInfo);
        } else {
            innerBundleInfos.at(iter->first) = innerBundleInfo;
        }
    }
    return true;
}

bool SandboxManagerRdb::GetDataFromDb(const std::string &bundleName, InnerBundleInfo &innerBundleInfo)
{
    if (rdbDataManager_ == nullptr) {
        APP_LOGE("rdbDataManager is null");
        return false;
    }

    std::string value;
    bool result = rdbDataManager_->QueryData(bundleName, value);
    if (!result) {
        APP_LOGE("QueryData failed by bundleName %{public}s", bundleName.c_str());
        return false;
    }

    nlohmann::json jsonObject = nlohmann::json::parse(value, nullptr, false);
    if (jsonObject.is_discarded() || (innerBundleInfo.FromJson(jsonObject) != ERR_OK)) {
        APP_LOGE("error key : %{public}s", bundleName.c_str());
        rdbDataManager_->DeleteData(bundleName);
        return false;
    }
    return true;
}

bool SandboxManagerRdb::SaveDataToDb(const std::string &bundleName, const InnerBundleInfo &innerBundleInfo)
{
    if (rdbDataManager_ == nullptr) {
        APP_LOGE("rdbDataManager is null");
        return false;
    }

    return rdbDataManager_->InsertData(bundleName, innerBundleInfo.ToString());
}

bool SandboxManagerRdb::DeleteDataFromDb(const std::string &bundleName)
{
    if (rdbDataManager_ == nullptr) {
        APP_LOGE("rdbDataManager is null");
        return false;
    }

    return rdbDataManager_->DeleteData(bundleName);
}
} // namespace AppExecFwk
} // namespace OHOS
