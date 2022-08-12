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

#include "app_control_manager_rdb.h"

#include "app_log_wrapper.h"
#include "appexecfwk_errors.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
    const std::string APP_CONTROL_RDB_TABLE_NAME = "app_control";
    const std::string CALLING_NAME = "CALLING_NAME";
    const std::string APP_CONTROL_LIST = "APP_CONTROL_LIST";
    const std::string USER_ID = "USER_ID";
    const std::string APP_ID = "APP_ID";
    const int32_t APP_ID_INDEX = 4;
}
AppControlManagerRdb::AppControlManagerRdb()
{
    APP_LOGD("create AppControlManagerRdb.");
    BmsRdbConfig bmsRdbConfig;
    bmsRdbConfig.dbName = Constants::BUNDLE_RDB_NAME;
    bmsRdbConfig.tableName = APP_CONTROL_RDB_TABLE_NAME;
    bmsRdbConfig.createTableSql = std::string(
        "CREATE TABLE IF NOT EXISTS "
        + APP_CONTROL_RDB_TABLE_NAME
        + "(ID INTEGER PRIMARY KEY AUTOINCREMENT, CALLING_NAME TEXT NOT NULL, "
        + "APP_CONTROL_LIST TEXT, USER_ID INTEGER, APP_ID TEXT);");
    rdbDataManager_ = std::make_shared<RdbDataManager>(bmsRdbConfig);
}

AppControlManagerRdb::~AppControlManagerRdb()
{
    APP_LOGD("destroy AppControlManagerRdb.");
}

ErrCode AppControlManagerRdb::AddAppInstallControlRule(const std::string &callingName,
    const std::vector<std::string> &appIds, const std::string &controlRuleType, int32_t userId)
{
    ErrCode code = DeleteAppInstallControlRule(callingName, controlRuleType, userId);
    if (code != ERR_OK) {
        APP_LOGW("DeleteAppInstallControlRule failed.");
        return ERR_APPEXECFWK_APP_CONTROL_INTERNAL_ERROR;
    }
    std::vector<NativeRdb::ValuesBucket> valuesBuckets;
    for (auto appid : appIds) {
        NativeRdb::ValuesBucket valuesBucket;
        valuesBucket.PutString(CALLING_NAME, callingName);
        valuesBucket.PutString(APP_CONTROL_LIST, controlRuleType);
        valuesBucket.PutInt(USER_ID, static_cast<int>(userId));
        valuesBucket.PutString(APP_ID, appid);
        valuesBuckets.emplace_back(valuesBucket);
    }
    int64_t insertNum = 0;
    bool ret = rdbDataManager_->BatchInsert(insertNum, valuesBuckets);
    if (!ret) {
        APP_LOGE("BatchInsert failed.");
        return ERR_APPEXECFWK_APP_CONTROL_INTERNAL_ERROR;
    }
    APP_LOGD("BatchInsert num:%{public}lld.", insertNum);
    return ERR_OK;
}

ErrCode AppControlManagerRdb::DeleteAppInstallControlRule(const std::string &callingName,
    const std::vector<std::string> &appIds, int32_t userId)
{
    for (auto appid : appIds) {
        NativeRdb::AbsRdbPredicates absRdbPredicates(APP_CONTROL_RDB_TABLE_NAME);
        absRdbPredicates.EqualTo(CALLING_NAME, callingName);
        absRdbPredicates.EqualTo(USER_ID, std::to_string(userId));
        absRdbPredicates.EqualTo(APP_ID, appid);
        bool ret = rdbDataManager_->DeleteData(absRdbPredicates);
        if (!ret) {
            APP_LOGE("DeleteAppInstallControlRule callingName:%{public}s appid:%{public}s userId:%{public}d failed.",
                callingName.c_str(), appid.c_str(), userId);
            return ERR_APPEXECFWK_APP_CONTROL_INTERNAL_ERROR;
        }
    }
    return ERR_OK;
}

ErrCode AppControlManagerRdb::DeleteAppInstallControlRule(const std::string &callingName,
    const std::string &controlRuleType, int32_t userId)
{
    NativeRdb::AbsRdbPredicates absRdbPredicates(APP_CONTROL_RDB_TABLE_NAME);
    absRdbPredicates.EqualTo(CALLING_NAME, callingName);
    absRdbPredicates.EqualTo(APP_CONTROL_LIST, controlRuleType);
    absRdbPredicates.EqualTo(USER_ID, std::to_string(userId));
    bool ret = rdbDataManager_->DeleteData(absRdbPredicates);
    if (!ret) {
        APP_LOGE("DeleteData callingName:%{public}s controlRuleType:%{public}s failed.",
            callingName.c_str(), controlRuleType.c_str());
        return ERR_APPEXECFWK_APP_CONTROL_INTERNAL_ERROR;
    }
    return ERR_OK;
}

ErrCode AppControlManagerRdb::GetAppInstallControlRule(const std::string &callingName,
    const std::string &controlRuleType, int32_t userId, std::vector<std::string> &appIds)
{
    NativeRdb::AbsRdbPredicates absRdbPredicates(APP_CONTROL_RDB_TABLE_NAME);
    absRdbPredicates.EqualTo(CALLING_NAME, callingName);
    absRdbPredicates.EqualTo(APP_CONTROL_LIST, controlRuleType);
    absRdbPredicates.EqualTo(USER_ID, std::to_string(userId));
    auto absSharedResultSet = rdbDataManager_->QueryData(absRdbPredicates);
    if (absSharedResultSet == nullptr) {
        APP_LOGE("GetAppInstallControlRule failed.");
        return ERR_APPEXECFWK_APP_CONTROL_INTERNAL_ERROR;
    }
    
    auto ret = absSharedResultSet->GoToFirstRow();
    if (ret != NativeRdb::E_OK) {
        APP_LOGE("GoToFirstRow failed, ret: %{public}d", ret);
        return ERR_APPEXECFWK_APP_CONTROL_INTERNAL_ERROR;
    }
    do {
        std::string appId;
        ret = absSharedResultSet->GetString(APP_ID_INDEX, appId);
        if (ret != NativeRdb::E_OK) {
            APP_LOGE("GetString appId failed, ret: %{public}d", ret);
            return ERR_APPEXECFWK_APP_CONTROL_INTERNAL_ERROR;
        }
        appIds.push_back(appId);
    } while (absSharedResultSet->GoToNextRow() == NativeRdb::E_OK);
    return ERR_OK;
}
}
}