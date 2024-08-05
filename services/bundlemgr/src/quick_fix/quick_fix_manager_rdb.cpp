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

#include "quick_fix_manager_rdb.h"

#include "app_log_tag_wrapper.h"
#include "json_serializer.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr const char* QUICK_FIX_RDB_TABLE_NAME = "quick_fix";
}
QuickFixManagerRdb::QuickFixManagerRdb()
{
    LOG_I(BMS_TAG_DEFAULT, "create QuickFixManagerRdb");
    BmsRdbConfig bmsRdbConfig;
    bmsRdbConfig.dbName = ServiceConstants::BUNDLE_RDB_NAME;
    bmsRdbConfig.tableName = QUICK_FIX_RDB_TABLE_NAME;
    rdbDataManager_ = std::make_shared<RdbDataManager>(bmsRdbConfig);
    rdbDataManager_->CreateTable();
}

QuickFixManagerRdb::~QuickFixManagerRdb()
{
    LOG_I(BMS_TAG_DEFAULT, "destroy QuickFixManagerRdb");
}

bool QuickFixManagerRdb::QueryAllInnerAppQuickFix(std::map<std::string, InnerAppQuickFix> &innerAppQuickFixes)
{
    LOG_I(BMS_TAG_DEFAULT, "begin to QueryAllInnerAppQuickFix");
    bool ret = GetAllDataFromDb(innerAppQuickFixes);
    if (!ret) {
        LOG_E(BMS_TAG_DEFAULT, "GetAllDataFromDb failed");
        return false;
    }
    return true;
}

bool QuickFixManagerRdb::QueryInnerAppQuickFix(const std::string &bundleName, InnerAppQuickFix &innerAppQuickFix)
{
    LOG_I(BMS_TAG_DEFAULT, "begin to QueryAppQuickFix");
    bool ret = GetDataFromDb(bundleName, innerAppQuickFix);
    if (!ret) {
        LOG_E(BMS_TAG_DEFAULT, "GetDataFromDb failed");
        return false;
    }
    return true;
}

bool QuickFixManagerRdb::SaveInnerAppQuickFix(const InnerAppQuickFix &innerAppQuickFix)
{
    LOG_I(BMS_TAG_DEFAULT, "begin to SaveInnerAppQuickFix");
    bool ret = SaveDataToDb(innerAppQuickFix);
    if (!ret) {
        LOG_E(BMS_TAG_DEFAULT, "SaveDataToDb failed");
        return false;
    }
    return true;
}

bool QuickFixManagerRdb::DeleteInnerAppQuickFix(const std::string &bundleName)
{
    LOG_I(BMS_TAG_DEFAULT, "begin to DeleteInnerAppQuickFix");
    bool ret = DeleteDataFromDb(bundleName);
    if (!ret) {
        LOG_E(BMS_TAG_DEFAULT, "DeleteDataFromDb failed");
        return false;
    }
    return true;
}

bool QuickFixManagerRdb::GetAllDataFromDb(std::map<std::string, InnerAppQuickFix> &innerAppQuickFixes)
{
    if (rdbDataManager_ == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "rdbDataManager is null");
        return false;
    }

    std::map<std::string, std::string> values;
    bool result = rdbDataManager_->QueryAllData(values);
    if (!result) {
        LOG_E(BMS_TAG_DEFAULT, "QueryAllData failed");
        return false;
    }
    for (auto iter = values.begin(); iter != values.end(); ++iter) {
        nlohmann::json jsonObject = nlohmann::json::parse(iter->second, nullptr, false);
        InnerAppQuickFix appQuickFix;
        if (jsonObject.is_discarded() || (appQuickFix.FromJson(jsonObject) != ERR_OK)) {
            LOG_E(BMS_TAG_DEFAULT, "error key : %{public}s", iter->first.c_str());
            rdbDataManager_->DeleteData(iter->first);
            continue;
        }
        innerAppQuickFixes.insert({ iter->first, appQuickFix });
    }
    return true;
}

bool QuickFixManagerRdb::GetDataFromDb(const std::string &bundleName, InnerAppQuickFix &innerAppQuickFix)
{
    if (rdbDataManager_ == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "rdbDataManager is null");
        return false;
    }

    std::string value;
    bool result = rdbDataManager_->QueryData(bundleName, value);
    if (!result) {
        LOG_E(BMS_TAG_DEFAULT, "QueryData failed by bundleName %{public}s", bundleName.c_str());
        return false;
    }

    nlohmann::json jsonObject = nlohmann::json::parse(value, nullptr, false);
    if (jsonObject.is_discarded() || (innerAppQuickFix.FromJson(jsonObject) != ERR_OK)) {
        LOG_E(BMS_TAG_DEFAULT, "error key : %{public}s", bundleName.c_str());
        rdbDataManager_->DeleteData(bundleName);
        return false;
    }
    return true;
}

bool QuickFixManagerRdb::SaveDataToDb(const InnerAppQuickFix &innerAppQuickFix)
{
    if (rdbDataManager_ == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "rdbDataManager is null");
        return false;
    }

    return rdbDataManager_->InsertData(innerAppQuickFix.GetAppQuickFix().bundleName, innerAppQuickFix.ToString());
}

bool QuickFixManagerRdb::DeleteDataFromDb(const std::string &bundleName)
{
    if (rdbDataManager_ == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "rdbDataManager is null");
        return false;
    }

    return rdbDataManager_->DeleteData(bundleName);
}
} // namespace AppExecFwk
} // namespace OHOS
