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

#include "app_log_wrapper.h"
#include "appexecfwk_errors.h"
#include "json_serializer.h"

namespace OHOS {
namespace AppExecFwk {
QuickFixManagerRdb::QuickFixManagerRdb()
{
    APP_LOGI("create QuickFixManagerRdb.");
    BmsRdbConfig bmsRdbConfig;
    bmsRdbConfig.dbName = Constants::BUNDLE_RDB_NAME;
    bmsRdbConfig.tableName = Constants::QUICK_FIX_RDB_TABLE_NAME;
    rdbDataManager_ = std::make_shared<RdbDataManager>(bmsRdbConfig);
    rdbDataManager_->CreateTable();
}

QuickFixManagerRdb::~QuickFixManagerRdb()
{
    APP_LOGI("destroy QuickFixManagerRdb.");
}

bool QuickFixManagerRdb::QueryAllInnerAppQuickFix(std::map<std::string, InnerAppQuickFix> &innerAppQuickFixes)
{
    APP_LOGI("begin to QueryAllInnerAppQuickFix");
    bool ret = GetAllDataFromDb(innerAppQuickFixes);
    if (!ret) {
        APP_LOGE("GetAllDataFromDb failed.");
        return false;
    }
    return true;
}

bool QuickFixManagerRdb::QueryInnerAppQuickFix(const std::string &bundleName, InnerAppQuickFix &innerAppQuickFix)
{
    APP_LOGI("begin to QueryAppQuickFix");
    bool ret = GetDataFromDb(bundleName, innerAppQuickFix);
    if (!ret) {
        APP_LOGE("GetDataFromDb failed.");
        return false;
    }
    return true;
}

bool QuickFixManagerRdb::SaveInnerAppQuickFix(const InnerAppQuickFix &innerAppQuickFix)
{
    APP_LOGI("begin to SaveInnerAppQuickFix");
    bool ret = SaveDataToDb(innerAppQuickFix);
    if (!ret) {
        APP_LOGE("SaveDataToDb failed.");
        return false;
    }
    return true;
}

bool QuickFixManagerRdb::DeleteInnerAppQuickFix(const std::string &bundleName)
{
    APP_LOGI("begin to DeleteInnerAppQuickFix");
    bool ret = DeleteDataFromDb(bundleName);
    if (!ret) {
        APP_LOGE("DeleteDataFromDb failed.");
        return false;
    }
    return true;
}

bool QuickFixManagerRdb::GetAllDataFromDb(std::map<std::string, InnerAppQuickFix> &innerAppQuickFixes)
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
        InnerAppQuickFix appQuickFix;
        if (jsonObject.is_discarded() || (appQuickFix.FromJson(jsonObject) != ERR_OK)) {
            APP_LOGE("error key : %{public}s", iter->first.c_str());
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
    if (jsonObject.is_discarded() || (innerAppQuickFix.FromJson(jsonObject) != ERR_OK)) {
        APP_LOGE("error key : %{public}s", bundleName.c_str());
        rdbDataManager_->DeleteData(bundleName);
        return false;
    }
    return true;
}

bool QuickFixManagerRdb::SaveDataToDb(const InnerAppQuickFix &innerAppQuickFix)
{
    if (rdbDataManager_ == nullptr) {
        APP_LOGE("rdbDataManager is null");
        return false;
    }

    return rdbDataManager_->InsertData(innerAppQuickFix.GetAppQuickFix().bundleName, innerAppQuickFix.ToString());
}

bool QuickFixManagerRdb::DeleteDataFromDb(const std::string &bundleName)
{
    if (rdbDataManager_ == nullptr) {
        APP_LOGE("rdbDataManager is null");
        return false;
    }

    return rdbDataManager_->DeleteData(bundleName);
}
} // namespace AppExecFwk
} // namespace OHOS
